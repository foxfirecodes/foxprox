//! Concrete host-socket egress implementations for foxprox alpha harnesses.
//!
//! This crate stays outside `foxprox-core` so the core policy/audit contracts do
//! not depend on host socket APIs. Runtime code can plug these implementations
//! into the core TCP/UDP forwarding harnesses after policy/audit allow evidence
//! has been recorded.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditKind, AuditRecord, BrokerRuntimeConfig, Decision, DenialReason, DnsBrokerHandler,
    DnsHandlerResult, DnsQueryMetadata, DnsUpstream, DnsUpstreamError, ExplicitProxyEgress,
    ExplicitProxyFrontend, Frontend, NetworkEndpoint, PolicyRequest, Protocol, ProxyEgressError,
    TcpEgress, TcpEgressError, UdpEgress, UdpEgressError,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
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

    pub fn from_runtime_config(
        config: &BrokerRuntimeConfig,
        bind_addr: SocketAddr,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self::new(config.dns_upstream, bind_addr, timeout, max_response_bytes)
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
            return Err(DnsUpstreamError::SourceMismatch);
        }
        response.truncate(len);
        Ok(response)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsBrokerStepResult {
    pub client: SocketAddr,
    pub query_len: usize,
    pub response_len: usize,
    pub sent_response: bool,
    pub send_status: String,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
}

#[derive(Debug)]
pub struct BlockingDnsBrokerServer<U> {
    socket: UdpSocket,
    handler: DnsBrokerHandler<U>,
    max_query_bytes: usize,
}

impl<U: DnsUpstream> BlockingDnsBrokerServer<U> {
    pub fn bind(
        bind_addr: SocketAddr,
        handler: DnsBrokerHandler<U>,
        timeout: Duration,
        max_query_bytes: usize,
    ) -> Result<Self, DnsUpstreamError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        Ok(Self {
            socket,
            handler,
            max_query_bytes,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, DnsUpstreamError> {
        self.socket
            .local_addr()
            .map_err(|_| DnsUpstreamError::Unavailable)
    }

    pub fn handle_one(
        &mut self,
        sandbox_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<DnsBrokerStepResult, DnsUpstreamError> {
        let sandbox_id = sandbox_id.into();
        let mut query = vec![0u8; self.max_query_bytes.max(1)];
        let (query_len, client) = self
            .socket
            .recv_from(&mut query)
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        query.truncate(query_len);
        let result = self
            .handler
            .handle_query(sandbox_id.clone(), &query, now_ms);
        let response_len = result.response.as_ref().map_or(0, Vec::len);
        let mut sent_response = false;
        let mut send_status = "not_sent".to_string();
        if let Some(response) = result.response.as_ref() {
            match self.socket.send_to(response, client) {
                Ok(_) => {
                    sent_response = true;
                    send_status = "sent".to_string();
                }
                Err(_) => {
                    self.record_client_send_failure(
                        &sandbox_id,
                        client,
                        query_len,
                        response_len,
                        &result,
                        now_ms,
                    );
                    return Ok(DnsBrokerStepResult {
                        client,
                        query_len,
                        response_len,
                        sent_response: false,
                        send_status: "send_failed".to_string(),
                        decision: Decision::FailClosed,
                        reason: Some(DenialReason::ResourceLimit),
                    });
                }
            }
        }
        Ok(DnsBrokerStepResult {
            client,
            query_len,
            response_len,
            sent_response,
            send_status,
            decision: result.decision.decision,
            reason: result.decision.reason,
        })
    }

    pub fn handler(&self) -> &DnsBrokerHandler<U> {
        &self.handler
    }

    fn record_client_send_failure(
        &mut self,
        sandbox_id: &str,
        client: SocketAddr,
        query_len: usize,
        response_len: usize,
        result: &DnsHandlerResult,
        now_ms: u64,
    ) {
        if let Some(observation) = result.observation.as_ref() {
            self.handler.rollback_observation(observation);
        }
        let request = PolicyRequest::unsupported(
            sandbox_id.to_string(),
            Frontend::Tun,
            DenialReason::ResourceLimit,
        );
        let audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            sandbox_id.to_string(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Dns)
        .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
        .with_detail("dns_client", client.to_string())
        .with_detail("query_len", query_len.to_string())
        .with_detail("response_len", response_len.to_string())
        .with_detail("send_status", "send_failed")
        .with_detail("error", "dns_client_send_failed");
        let _ = self.handler.broker_mut().append_audit_for(&request, audit);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpProxyListenerStepResult {
    pub client: SocketAddr,
    pub request_len: usize,
    pub response_len: usize,
    pub sent_response: bool,
    pub send_status: String,
    pub status_code: u16,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub forwarded: bool,
}

#[derive(Debug)]
pub struct BlockingHttpProxyServer<E> {
    listener: TcpListener,
    frontend: ExplicitProxyFrontend<E>,
    io_timeout: Duration,
    max_request_bytes: usize,
}

impl<E: ExplicitProxyEgress> BlockingHttpProxyServer<E> {
    pub fn bind(
        bind_addr: SocketAddr,
        frontend: ExplicitProxyFrontend<E>,
        io_timeout: Duration,
        max_request_bytes: usize,
    ) -> Result<Self, ProxyEgressError> {
        let listener = TcpListener::bind(bind_addr).map_err(|_| ProxyEgressError::SendFailed)?;
        listener
            .set_nonblocking(false)
            .map_err(|_| ProxyEgressError::SendFailed)?;
        Ok(Self {
            listener,
            frontend,
            io_timeout,
            max_request_bytes,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProxyEgressError> {
        self.listener
            .local_addr()
            .map_err(|_| ProxyEgressError::SendFailed)
    }

    pub fn handle_one(
        &mut self,
        now_ms: u64,
    ) -> Result<HttpProxyListenerStepResult, ProxyEgressError> {
        let (mut stream, client) = self
            .listener
            .accept()
            .map_err(|_| ProxyEgressError::SendFailed)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        let request = read_http_proxy_request(&mut stream, self.max_request_bytes)?;
        let request_len = request.len();
        let result = self.frontend.handle_http_proxy_bytes(&request)?;
        let (status_code, response) = http_proxy_response_for(&request, result.decision);
        match stream.write_all(response.as_bytes()) {
            Ok(()) => Ok(HttpProxyListenerStepResult {
                client,
                request_len,
                response_len: response.len(),
                sent_response: true,
                send_status: "sent".to_string(),
                status_code,
                decision: result.decision,
                reason: result.reason,
                forwarded: result.forwarded,
            }),
            Err(_) => {
                let audit =
                    AuditRecord::new_at(AuditKind::BrokerError, "proxy-listener", now_ms as u128)
                        .with_frontend(Frontend::HttpProxy)
                        .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                        .with_detail("client", client.to_string())
                        .with_detail("request_len", request_len.to_string())
                        .with_detail("response_len", response.len().to_string())
                        .with_detail("send_status", "send_failed")
                        .with_detail("error", "http_proxy_client_send_failed");
                let request = PolicyRequest::unsupported(
                    "proxy-listener".to_string(),
                    Frontend::HttpProxy,
                    DenialReason::ResourceLimit,
                );
                let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
                Ok(HttpProxyListenerStepResult {
                    client,
                    request_len,
                    response_len: response.len(),
                    sent_response: false,
                    send_status: "send_failed".to_string(),
                    status_code,
                    decision: Decision::FailClosed,
                    reason: Some(DenialReason::ResourceLimit),
                    forwarded: result.forwarded,
                })
            }
        }
    }

    pub fn frontend(&self) -> &ExplicitProxyFrontend<E> {
        &self.frontend
    }
}

fn read_http_proxy_request(
    stream: &mut TcpStream,
    max_request_bytes: usize,
) -> Result<Vec<u8>, ProxyEgressError> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 256];
    while request.len() < max_request_bytes.max(1) {
        let remaining = max_request_bytes.max(1).saturating_sub(request.len());
        let read_len = remaining.min(chunk.len());
        let len = stream
            .read(&mut chunk[..read_len])
            .map_err(|_| ProxyEgressError::SendFailed)?;
        if len == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..len]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(request)
}

fn http_proxy_response_for(request: &[u8], decision: Decision) -> (u16, &'static str) {
    if decision.is_allow() {
        if request.starts_with(b"CONNECT ") {
            (200, "HTTP/1.1 200 Connection Established\r\n\r\n")
        } else {
            (200, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        }
    } else if matches!(decision, Decision::FailClosed) {
        (400, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    } else {
        (403, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
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
        BrokerCore, Cidr, Decision, DnsBrokerHandler, ExplicitProxyFrontend, FlowKey,
        InMemoryExplicitProxyEgress, PolicyConfig, PolicyEngine, PolicyRule, Protocol,
        TcpForwarder, UdpForwarder, UdpTimeoutConfig,
    };
    use std::collections::VecDeque;
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
    fn blocking_http_proxy_server_handles_allowed_request() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        let step = server.handle_one(1_000).unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.status_code, 200);
        assert_eq!(step.send_status, "sent");
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
    }

    #[test]
    fn blocking_http_proxy_server_denies_without_forwarding() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();

        let step = server.handle_one(1_000).unwrap();
        assert_eq!(step.decision, Decision::DenyDrop);
        assert!(!step.forwarded);
        assert_eq!(step.status_code, 403);
        assert_eq!(step.send_status, "sent");
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, Some(Decision::DenyDrop));
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
        let mut runtime_config = BrokerRuntimeConfig::alpha_default("s1");
        runtime_config.dns_upstream = resolver_addr;
        let upstream = BlockingDnsUpstream::from_runtime_config(
            &runtime_config,
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
        assert_eq!(records[1].details["dns_upstream_error"], "source_mismatch");
        server.join().unwrap();
    }

    #[test]
    fn blocking_dns_broker_server_handles_one_allowed_query() {
        let resolver = UdpSocket::bind("127.0.0.1:0").unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let query = dns_query(0x4646, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let expected_response = response.clone();
        let resolver_thread = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (_, peer) = resolver.recv_from(&mut buf).unwrap();
            resolver.send_to(&expected_response, peer).unwrap();
        });
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let upstream = BlockingDnsUpstream::new(
            resolver_addr,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            512,
        );
        let handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap();
        assert_eq!(step.query_len, query.len());
        assert_eq!(step.response_len, response.len());
        assert!(step.sent_response);
        assert_eq!(step.send_status, "sent");
        assert_eq!(step.decision, Decision::Allow);
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], response.as_slice());
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        resolver_thread.join().unwrap();
    }

    #[test]
    fn blocking_dns_broker_server_sends_refused_for_denied_query() {
        let query = dns_query(0x4747, "blocked.test", 1);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let upstream = BlockingDnsUpstream::new(
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_millis(10),
            512,
        );
        let handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap();
        assert_eq!(step.decision, Decision::DenyDrop);
        assert!(step.sent_response);
        assert_eq!(step.send_status, "sent");
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(buf[3] & 0x0f, 5);
        assert_eq!(step.response_len, len);
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, Some(Decision::DenyDrop));
    }

    #[test]
    fn blocking_dns_broker_server_audits_send_failure_and_rolls_back_cache() {
        let query = dns_query(0x4848, "Example.COM", 1);
        let mut huge_response = dns_a_response(&query, [93, 184, 216, 34], 30);
        huge_response.resize(70_000, 0);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let handler = DnsBrokerHandler::new(
            broker,
            StaticDnsUpstream {
                response: huge_response,
            },
            "10.0.2.3".parse().unwrap(),
        );
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap();
        assert!(!step.sent_response);
        assert_eq!(step.send_status, "send_failed");
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ResourceLimit));
        assert!(server
            .handler()
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        assert_eq!(records[2].kind, AuditKind::BrokerError);
        assert_eq!(records[2].details["send_status"], "send_failed");
        assert_eq!(records[2].details["error"], "dns_client_send_failed");
    }

    #[test]
    fn blocking_dns_send_failure_rolls_back_only_latest_duplicate_observation() {
        let query = dns_query(0x4949, "Example.COM", 1);
        let small_response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let mut huge_response = small_response.clone();
        huge_response.resize(70_000, 0);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 12);
        let handler = DnsBrokerHandler::new(
            broker,
            SequenceDnsUpstream {
                responses: VecDeque::from([small_response.clone(), huge_response]),
            },
            "10.0.2.3".parse().unwrap(),
        );
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();
        let delivered = server.handle_one("s1", 1_000).unwrap();
        assert_eq!(delivered.send_status, "sent");
        let mut buf = [0u8; 512];
        let _ = client.recv_from(&mut buf).unwrap();

        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();
        let failed = server.handle_one("s1", 1_000).unwrap();
        assert_eq!(failed.send_status, "send_failed");
        assert!(server
            .handler()
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_some());
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(
            records.last().unwrap().details["error"],
            "dns_client_send_failed"
        );
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

    #[derive(Clone, Debug)]
    struct StaticDnsUpstream {
        response: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct SequenceDnsUpstream {
        responses: VecDeque<Vec<u8>>,
    }

    impl DnsUpstream for SequenceDnsUpstream {
        fn exchange(
            &mut self,
            _query: &DnsQueryMetadata,
            _packet: &[u8],
        ) -> Result<Vec<u8>, DnsUpstreamError> {
            self.responses
                .pop_front()
                .ok_or(DnsUpstreamError::Unavailable)
        }
    }

    impl DnsUpstream for StaticDnsUpstream {
        fn exchange(
            &mut self,
            _query: &DnsQueryMetadata,
            _packet: &[u8],
        ) -> Result<Vec<u8>, DnsUpstreamError> {
            Ok(self.response.clone())
        }
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
