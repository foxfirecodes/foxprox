//! Standard-library host egress adapters for foxprox proof runtimes.
//!
//! This crate consumes dependency-free request/context types from
//! `foxprox-core` and owns concrete `std::net` socket opening. Callers remain
//! responsible for policy evaluation and audit ordering before constructing
//! requests; the adapter still fails closed unless the attached decision allows
//! egress.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use foxprox_core::{
    DnsEgressRequest, EgressError, EgressErrorKind, Hostname, TcpEgress, TcpEgressRequest,
    UdpEgressRequest,
};
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Configuration for the standard-library host egress adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdHostEgressConfig {
    /// Maximum UDP payload bytes read for generic one-shot UDP forwarding.
    pub udp_response_limit: usize,
    /// Maximum DNS response bytes read from the upstream resolver.
    pub dns_response_limit: usize,
}

impl Default for StdHostEgressConfig {
    fn default() -> Self {
        Self {
            udp_response_limit: 65_535,
            dns_response_limit: 4096,
        }
    }
}

/// Standard-library implementation of host egress operations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StdHostEgress {
    config: StdHostEgressConfig,
}

impl StdHostEgress {
    /// Creates an adapter with default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an adapter with explicit limits.
    pub const fn with_config(config: StdHostEgressConfig) -> Self {
        Self { config }
    }

    /// Opens a TCP stream and marks it nonblocking after a successful connect.
    pub fn connect_tcp_nonblocking(
        &mut self,
        request: TcpEgressRequest,
    ) -> Result<TcpStream, EgressError> {
        let stream = self.connect_tcp(request)?;
        stream
            .set_nonblocking(true)
            .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))?;
        Ok(stream)
    }

    /// Sends one UDP datagram and waits for at most one response.
    pub fn forward_udp_once(
        &mut self,
        request: UdpEgressRequest,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, EgressError> {
        ensure_allowed(request.context.is_allowed())?;
        let destination = SocketAddr::new(request.destination.ip, request.destination.port);
        let socket = bind_unspecified_for(destination)?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))?;
        socket
            .send_to(payload, destination)
            .map_err(|error| egress_io_error(EgressErrorKind::WriteFailed, error))?;
        let mut response = vec![0_u8; self.config.udp_response_limit];
        match socket.recv(&mut response) {
            Ok(len) => {
                response.truncate(len);
                Ok(Some(response))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(egress_io_error(EgressErrorKind::ReadFailed, error)),
        }
    }

    /// Sends a raw DNS query payload to the configured upstream resolver.
    pub fn query_dns_raw(
        &mut self,
        request: DnsEgressRequest,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, EgressError> {
        ensure_allowed(request.context.is_allowed())?;
        let upstream = SocketAddr::new(request.upstream.ip, request.upstream.port);
        let socket = bind_unspecified_for(upstream)?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))?;
        socket
            .send_to(payload, upstream)
            .map_err(|error| egress_io_error(EgressErrorKind::WriteFailed, error))?;
        let mut response = vec![0_u8; self.config.dns_response_limit];
        let len = socket
            .recv(&mut response)
            .map_err(|error| egress_io_error(EgressErrorKind::ReadFailed, error))?;
        response.truncate(len);
        Ok(response)
    }
}

impl TcpEgress for StdHostEgress {
    type Stream = TcpStream;

    fn connect_tcp(&mut self, request: TcpEgressRequest) -> Result<Self::Stream, EgressError> {
        ensure_allowed(request.context.is_allowed())?;
        let destination = SocketAddr::new(request.destination.ip, request.destination.port);
        let stream = if let Some(timeout) = request.connect_timeout {
            TcpStream::connect_timeout(&destination, timeout)
        } else {
            TcpStream::connect(destination)
        }
        .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))?;
        Ok(stream)
    }
}

/// Resolves a hostname and port using the process resolver, preferring IPv4.
///
/// This preserves the current proof-runtime behavior. Name resolution is not
/// timeout-bound by this helper.
pub fn resolve_host_port(host: &Hostname, port: u16) -> io::Result<SocketAddr> {
    let mut addrs: Vec<_> = (host.as_str(), port).to_socket_addrs()?.collect();
    addrs.sort_by_key(|addr| !addr.is_ipv4());
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "host did not resolve"))
}

/// Converts a core egress error into an `io::Error` for proof runtimes.
pub fn egress_error_to_io(error: EgressError) -> io::Error {
    let kind = match error.kind {
        EgressErrorKind::PolicyDenied => io::ErrorKind::PermissionDenied,
        EgressErrorKind::ConnectFailed => io::ErrorKind::ConnectionRefused,
        EgressErrorKind::ReadFailed => io::ErrorKind::UnexpectedEof,
        EgressErrorKind::WriteFailed => io::ErrorKind::BrokenPipe,
        EgressErrorKind::Timeout => io::ErrorKind::TimedOut,
        EgressErrorKind::ResourceLimit => io::ErrorKind::WouldBlock,
        EgressErrorKind::Unsupported => io::ErrorKind::Unsupported,
    };
    io::Error::new(kind, error.to_string())
}

fn ensure_allowed(allowed: bool) -> Result<(), EgressError> {
    if allowed {
        Ok(())
    } else {
        Err(EgressError::new(
            EgressErrorKind::PolicyDenied,
            "policy denied host egress",
        ))
    }
}

fn bind_unspecified_for(destination: SocketAddr) -> Result<UdpSocket, EgressError> {
    let bind_addr = if destination.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    UdpSocket::bind(bind_addr)
        .map_err(|error| egress_io_error(EgressErrorKind::ConnectFailed, error))
}

fn egress_io_error(kind: EgressErrorKind, error: io::Error) -> EgressError {
    EgressError::new(kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        Attribution, Decision, EgressContext, FlowTimeoutClass, Frontend, SandboxId,
        TransportEndpoint,
    };
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::thread;

    fn context(decision: Decision) -> EgressContext {
        EgressContext {
            sandbox_id: SandboxId::new("egress-test").unwrap(),
            frontend: Frontend::Tun,
            decision,
            attribution: Attribution::ip_only(),
        }
    }

    fn tcp_request(decision: Decision, destination: SocketAddr) -> TcpEgressRequest {
        TcpEgressRequest {
            context: context(decision),
            source: None,
            destination: TransportEndpoint::from(destination),
            connect_timeout: Some(Duration::from_secs(1)),
        }
    }

    #[test]
    fn denied_tcp_request_fails_before_socket_io() {
        let destination = SocketAddr::from(([203, 0, 113, 1], 9));
        let error = StdHostEgress::new()
            .connect_tcp(tcp_request(
                Decision::default_deny(foxprox_core::DecisionAction::DenyDrop),
                destination,
            ))
            .unwrap_err();
        assert_eq!(error.kind, EgressErrorKind::PolicyDenied);
    }

    #[test]
    fn allowed_tcp_request_connects_to_loopback() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).unwrap();
            stream.write_all(&byte).unwrap();
        });

        let mut stream = StdHostEgress::new()
            .connect_tcp(tcp_request(Decision::allow("allow-loopback"), addr))
            .unwrap();
        stream.write_all(b"x").unwrap();
        let mut response = [0_u8; 1];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"x");
        server.join().unwrap();
    }

    #[test]
    fn denied_udp_request_fails_before_socket_io() {
        let request = UdpEgressRequest {
            context: context(Decision::default_deny(
                foxprox_core::DecisionAction::DenyDrop,
            )),
            source: TransportEndpoint::new(IpAddr::from([10, 255, 0, 2]), 44444),
            destination: TransportEndpoint::new(IpAddr::from([203, 0, 113, 1]), 53),
            timeout_class: FlowTimeoutClass::GenericUdp,
        };
        let error = StdHostEgress::new()
            .forward_udp_once(request, b"hello", Duration::from_millis(1))
            .unwrap_err();
        assert_eq!(error.kind, EgressErrorKind::PolicyDenied);
    }

    #[test]
    fn allowed_udp_request_round_trips_loopback() {
        let server = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut buf = [0_u8; 32];
            let (len, peer) = server.recv_from(&mut buf).unwrap();
            server.send_to(&buf[..len], peer).unwrap();
        });
        let request = UdpEgressRequest {
            context: context(Decision::allow("allow-udp")),
            source: TransportEndpoint::new(IpAddr::from([10, 255, 0, 2]), 44444),
            destination: TransportEndpoint::from(addr),
            timeout_class: FlowTimeoutClass::GenericUdp,
        };
        let response = StdHostEgress::new()
            .forward_udp_once(request, b"hello", Duration::from_secs(1))
            .unwrap();
        assert_eq!(response.as_deref(), Some(&b"hello"[..]));
        thread.join().unwrap();
    }

    #[test]
    fn denied_dns_request_fails_before_socket_io() {
        let request = DnsEgressRequest {
            context: context(Decision::default_deny(
                foxprox_core::DecisionAction::DenyDrop,
            )),
            hostname: Hostname::parse("example.com").unwrap(),
            query_type: "A".to_string(),
            upstream: TransportEndpoint::new(IpAddr::from([203, 0, 113, 1]), 53),
        };
        let error = StdHostEgress::new()
            .query_dns_raw(request, b"\0", Duration::from_millis(1))
            .unwrap_err();
        assert_eq!(error.kind, EgressErrorKind::PolicyDenied);
    }

    #[test]
    fn allowed_dns_request_round_trips_loopback_payload() {
        let server = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut buf = [0_u8; 32];
            let (len, peer) = server.recv_from(&mut buf).unwrap();
            server.send_to(&buf[..len], peer).unwrap();
        });
        let request = DnsEgressRequest {
            context: context(Decision::allow("allow-dns")),
            hostname: Hostname::parse("example.com").unwrap(),
            query_type: "A".to_string(),
            upstream: TransportEndpoint::from(addr),
        };
        let response = StdHostEgress::new()
            .query_dns_raw(request, b"dns", Duration::from_secs(1))
            .unwrap();
        assert_eq!(response, b"dns");
        thread.join().unwrap();
    }

    #[test]
    fn resolve_host_port_prefers_ipv4_loopback() {
        let addr = resolve_host_port(&Hostname::parse("localhost").unwrap(), 80).unwrap();
        assert!(addr.is_ipv4() || addr.is_ipv6());
        assert_eq!(addr.port(), 80);
    }
}
