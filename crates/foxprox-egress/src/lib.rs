//! Concrete host-socket egress implementations for foxprox alpha harnesses.
//!
//! This crate stays outside `foxprox-core` so the core policy/audit contracts do
//! not depend on host socket APIs. Runtime code can plug these implementations
//! into the core TCP/UDP forwarding harnesses after policy/audit allow evidence
//! has been recorded.

#![forbid(unsafe_code)]

use foxprox_core::{
    DnsQueryMetadata, DnsUpstream, DnsUpstreamError, NetworkEndpoint, TcpEgress, TcpEgressError,
    UdpEgress, UdpEgressError,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct BlockingTcpEgress {
    connect_timeout: Duration,
    io_timeout: Duration,
    max_response_bytes: usize,
}

impl BlockingTcpEgress {
    pub fn new(connect_timeout: Duration, io_timeout: Duration, max_response_bytes: usize) -> Self {
        Self {
            connect_timeout,
            io_timeout,
            max_response_bytes,
        }
    }
}

impl Default for BlockingTcpEgress {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(5), 64 * 1024)
    }
}

impl TcpEgress for BlockingTcpEgress {
    fn connect_and_exchange(
        &mut self,
        destination: NetworkEndpoint,
        from_sandbox: &[u8],
    ) -> Result<Vec<u8>, TcpEgressError> {
        let destination = socket_addr(destination).ok_or(TcpEgressError::ConnectFailed)?;
        let mut stream = TcpStream::connect_timeout(&destination, self.connect_timeout)
            .map_err(|_| TcpEgressError::ConnectFailed)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        stream
            .write_all(from_sandbox)
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        let _ = stream.shutdown(std::net::Shutdown::Write);

        let mut response = Vec::new();
        let mut limited = stream.take(self.max_response_bytes as u64);
        limited
            .read_to_end(&mut response)
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        Ok(response)
    }
}

#[derive(Clone, Debug)]
pub struct BlockingDnsUpstream {
    upstream: SocketAddr,
    bind_addr: SocketAddr,
    timeout: Duration,
    max_response_bytes: usize,
}

impl BlockingDnsUpstream {
    pub fn new(
        upstream: SocketAddr,
        bind_addr: SocketAddr,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            upstream,
            bind_addr,
            timeout,
            max_response_bytes,
        }
    }
}

impl DnsUpstream for BlockingDnsUpstream {
    fn exchange(
        &mut self,
        _query: &DnsQueryMetadata,
        packet: &[u8],
    ) -> Result<Vec<u8>, DnsUpstreamError> {
        let socket = UdpSocket::bind(self.bind_addr).map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .send_to(packet, self.upstream)
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        let mut response = vec![0u8; self.max_response_bytes.max(1)];
        let (len, peer) = socket
            .recv_from(&mut response)
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        if peer != self.upstream {
            return Err(DnsUpstreamError::Unavailable);
        }
        response.truncate(len);
        Ok(response)
    }
}

#[derive(Clone, Debug)]
pub struct BlockingUdpEgress {
    bind_addr: SocketAddr,
}

impl BlockingUdpEgress {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }
}

impl Default for BlockingUdpEgress {
    fn default() -> Self {
        Self::new("0.0.0.0:0".parse().expect("valid default UDP bind address"))
    }
}

impl UdpEgress for BlockingUdpEgress {
    fn send_datagram(
        &mut self,
        destination: NetworkEndpoint,
        payload: &[u8],
    ) -> Result<(), UdpEgressError> {
        let destination = socket_addr(destination).ok_or(UdpEgressError::SendFailed)?;
        let socket = UdpSocket::bind(self.bind_addr).map_err(|_| UdpEgressError::SendFailed)?;
        socket
            .send_to(payload, destination)
            .map_err(|_| UdpEgressError::SendFailed)?;
        Ok(())
    }
}

fn socket_addr(endpoint: NetworkEndpoint) -> Option<SocketAddr> {
    Some(SocketAddr::new(endpoint.ip?, endpoint.port?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        BrokerCore, Cidr, Decision, DnsBrokerHandler, FlowKey, PolicyConfig, PolicyEngine,
        PolicyRule, Protocol, TcpForwarder, UdpForwarder, UdpTimeoutConfig,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    #[test]
    fn blocking_tcp_egress_connects_and_exchanges_bytes_through_forwarder() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-loopback")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("127.0.0.0".parse().unwrap(), 8))
                .destination_port(addr.port()),
        );
        let key = FlowKey::tcp("10.0.2.15".parse().unwrap(), 40000, addr.ip(), addr.port());
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            BlockingTcpEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        );

        let result = forwarder
            .connect_and_bridge(key, b"ping", 1_000, 1_010)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.byte_counts.from_sandbox, 4);
        assert_eq!(result.byte_counts.to_sandbox, 4);
        server.join().unwrap();
    }

    #[test]
    fn blocking_udp_egress_sends_datagram_through_forwarder() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let addr = receiver.local_addr().unwrap();

        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp("10.0.2.15".parse().unwrap(), 40000, addr.ip(), addr.port());
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            BlockingUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, b"hello", 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let mut buf = [0u8; 16];
        let (len, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[test]
    fn blocking_dns_upstream_exchanges_query_through_dns_handler() {
        let resolver = UdpSocket::bind("127.0.0.1:0").unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let query = dns_query(0x4242, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let expected_query = query.clone();
        let expected_response = response.clone();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = resolver.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], expected_query.as_slice());
            resolver.send_to(&expected_response, peer).unwrap();
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let upstream = BlockingDnsUpstream::new(
            resolver_addr,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            512,
        );
        let mut handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::Allow);
        assert_eq!(result.response.as_deref(), Some(response.as_slice()));
        assert_eq!(
            result.observed_addresses,
            vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
        );
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        server.join().unwrap();
    }

    #[test]
    fn blocking_dns_upstream_rejects_wrong_source_response() {
        let resolver = UdpSocket::bind("127.0.0.1:0").unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let wrong_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let query = dns_query(0x4545, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let expected_query = query.clone();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = resolver.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], expected_query.as_slice());
            wrong_sender.send_to(&response, peer).unwrap();
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let upstream = BlockingDnsUpstream::new(
            resolver_addr,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            512,
        );
        let mut handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(result.observed_addresses.is_empty());
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records[1].details["dns_upstream_error"], "unavailable");
        server.join().unwrap();
    }

    #[test]
    fn blocking_dns_upstream_unavailable_maps_to_handler_fail_closed() {
        let query = dns_query(0x4343, "Example.COM", 1);
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable = closed.local_addr().unwrap();
        drop(closed);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let upstream = BlockingDnsUpstream::new(
            unreachable,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_millis(10),
            512,
        );
        let mut handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records[1].details["dns_upstream_error"], "unavailable");
    }

    #[test]
    fn missing_endpoint_maps_to_egress_errors() {
        let mut tcp = BlockingTcpEgress::default();
        assert_eq!(
            tcp.connect_and_exchange(NetworkEndpoint::default(), b"x")
                .unwrap_err(),
            TcpEgressError::ConnectFailed
        );
        let mut udp = BlockingUdpEgress::default();
        assert_eq!(
            udp.send_datagram(NetworkEndpoint::default(), b"x")
                .unwrap_err(),
            UdpEgressError::SendFailed
        );
    }

    fn dns_query(transaction_id: u16, hostname: &str, query_type: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&query_type.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn dns_a_response(query: &[u8], address: [u8; 4], ttl_seconds: u32) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }
}
