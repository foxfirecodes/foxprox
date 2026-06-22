//! Shared host egress contract for transparent and explicit proxy paths.
//!
//! The egress crate accepts normalized policy events and never receives raw TUN
//! packets, HTTP parser internals, SOCKS parser internals, or sandbox sockets.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};

use foxprox_core::{
    DestinationHost, DnsQuery, HttpMethod, HttpRequest, HttpScheme, HttpsConnect, NormalizedEvent,
    SocksConnect, TcpConnectAttempt, UdpFlowAttempt,
};

/// Shared host-side egress backend used by all frontends after policy allows an
/// event. Production implementations open host sockets; tests can use mocks.
pub trait HostEgress {
    type TcpStream: HostTcpStream;
    type UdpHandle;
    type HttpResponse;

    fn connect_tcp(&mut self, event: &TcpConnectAttempt) -> Result<Self::TcpStream, EgressError>;

    fn open_udp_flow(&mut self, event: &UdpFlowAttempt) -> Result<Self::UdpHandle, EgressError>;

    fn proxy_http_request(
        &mut self,
        event: &HttpRequest,
    ) -> Result<Self::HttpResponse, EgressError>;

    fn proxy_connect(&mut self, event: &HttpsConnect) -> Result<Self::TcpStream, EgressError>;

    fn socks_connect(&mut self, event: &SocksConnect) -> Result<Self::TcpStream, EgressError>;

    fn resolve_dns(&mut self, event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError>;
}

/// Shared host TCP stream contract used by transparent and proxy bridge code.
pub trait HostTcpStream {
    fn write_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError>;
    fn read_to_sandbox(&mut self, max_bytes: usize) -> Result<Vec<u8>, EgressError>;
}

impl HostTcpStream for TcpStream {
    fn write_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
        self.write(bytes)
            .map_err(|error| EgressError::StreamIo(error.to_string()))
    }

    fn read_to_sandbox(&mut self, max_bytes: usize) -> Result<Vec<u8>, EgressError> {
        let mut buffer = vec![0_u8; max_bytes];
        let len = self
            .read(&mut buffer)
            .map_err(|error| EgressError::StreamIo(error.to_string()))?;
        buffer.truncate(len);
        Ok(buffer)
    }
}

/// Records allowed events and returns inert handles. Useful for contract tests.
#[derive(Clone, Debug, Default)]
pub struct MockEgress {
    pub tcp_connects: Vec<TcpConnectAttempt>,
    pub udp_flows: Vec<UdpFlowAttempt>,
    pub http_requests: Vec<HttpRequest>,
    pub proxy_connects: Vec<HttpsConnect>,
    pub socks_connects: Vec<SocksConnect>,
    pub dns_queries: Vec<DnsQuery>,
    pub dns_results: Vec<SocketAddr>,
}

impl HostEgress for MockEgress {
    type TcpStream = MockTcpStream;
    type UdpHandle = MockUdpHandle;
    type HttpResponse = MockHttpResponse;

    fn connect_tcp(&mut self, event: &TcpConnectAttempt) -> Result<Self::TcpStream, EgressError> {
        self.tcp_connects.push(event.clone());
        Ok(MockTcpStream)
    }

    fn open_udp_flow(&mut self, event: &UdpFlowAttempt) -> Result<Self::UdpHandle, EgressError> {
        self.udp_flows.push(event.clone());
        Ok(MockUdpHandle)
    }

    fn proxy_http_request(
        &mut self,
        event: &HttpRequest,
    ) -> Result<Self::HttpResponse, EgressError> {
        self.http_requests.push(event.clone());
        Ok(MockHttpResponse)
    }

    fn proxy_connect(&mut self, event: &HttpsConnect) -> Result<Self::TcpStream, EgressError> {
        self.proxy_connects.push(event.clone());
        Ok(MockTcpStream)
    }

    fn socks_connect(&mut self, event: &SocksConnect) -> Result<Self::TcpStream, EgressError> {
        self.socks_connects.push(event.clone());
        Ok(MockTcpStream)
    }

    fn resolve_dns(&mut self, event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError> {
        self.dns_queries.push(event.clone());
        Ok(self.dns_results.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockTcpStream;

impl HostTcpStream for MockTcpStream {
    fn write_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
        Ok(bytes.len())
    }

    fn read_to_sandbox(&mut self, _max_bytes: usize) -> Result<Vec<u8>, EgressError> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockUdpHandle;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockHttpResponse;

/// Standard-library host egress backend.
///
/// This implementation centralizes host socket opening behind the shared egress
/// trait. It is intentionally blocking and minimal; async backpressure and
/// streaming adapters can wrap the same normalized contract later.
#[derive(Clone, Debug, Default)]
pub struct StdHostEgress;

impl HostEgress for StdHostEgress {
    type TcpStream = TcpStream;
    type UdpHandle = UdpSocket;
    type HttpResponse = StdHttpResponse;

    fn connect_tcp(&mut self, event: &TcpConnectAttempt) -> Result<Self::TcpStream, EgressError> {
        TcpStream::connect(event.destination)
            .map_err(|error| EgressError::ConnectFailed(error.to_string()))
    }

    fn open_udp_flow(&mut self, event: &UdpFlowAttempt) -> Result<Self::UdpHandle, EgressError> {
        let bind_addr = match event.destination.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|error| EgressError::ConnectFailed(error.to_string()))?;
        socket
            .connect(event.destination)
            .map_err(|error| EgressError::ConnectFailed(error.to_string()))?;
        Ok(socket)
    }

    fn proxy_http_request(
        &mut self,
        event: &HttpRequest,
    ) -> Result<Self::HttpResponse, EgressError> {
        if event.scheme != HttpScheme::Http {
            return Err(EgressError::UnsupportedAllowedEvent);
        }
        let mut stream = connect_destination(&event.host, event.port)?;
        let host = destination_host_to_string(&event.host);
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            http_method_as_str(&event.method),
            event.path_query,
            format_http_host_header(&event.host, event.port)
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| EgressError::ConnectFailed(error.to_string()))?;
        Ok(StdHttpResponse { stream, host })
    }

    fn proxy_connect(&mut self, event: &HttpsConnect) -> Result<Self::TcpStream, EgressError> {
        connect_destination(&event.host, event.port)
    }

    fn socks_connect(&mut self, event: &SocksConnect) -> Result<Self::TcpStream, EgressError> {
        connect_destination(&event.destination, event.port)
    }

    fn resolve_dns(&mut self, event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError> {
        (event.hostname.as_str(), 0)
            .to_socket_addrs()
            .map(|addrs| addrs.collect())
            .map_err(|error| EgressError::DnsFailed(error.to_string()))
    }
}

#[derive(Debug)]
pub struct StdHttpResponse {
    pub stream: TcpStream,
    pub host: String,
}

fn connect_destination(host: &DestinationHost, port: u16) -> Result<TcpStream, EgressError> {
    match host {
        DestinationHost::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, port))
            .map_err(|error| EgressError::ConnectFailed(error.to_string())),
        DestinationHost::Hostname(hostname) => (hostname.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| EgressError::ConnectFailed(error.to_string()))?
            .next()
            .ok_or_else(|| EgressError::ConnectFailed("destination did not resolve".into()))
            .and_then(|addr| {
                TcpStream::connect(addr)
                    .map_err(|error| EgressError::ConnectFailed(error.to_string()))
            }),
    }
}

fn http_method_as_str(method: &HttpMethod) -> &str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Connect => "CONNECT",
        HttpMethod::Other(method) => method.as_str(),
    }
}

fn format_http_host_header(host: &DestinationHost, port: u16) -> String {
    match host {
        DestinationHost::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        DestinationHost::Ip(ip) => format!("{ip}:{port}"),
        DestinationHost::Hostname(hostname) => format!("{hostname}:{port}"),
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EgressError {
    ConnectFailed(String),
    DnsFailed(String),
    StreamIo(String),
    UnsupportedAllowedEvent,
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectFailed(reason) => write!(f, "host connect failed: {reason}"),
            Self::DnsFailed(reason) => write!(f, "DNS failed: {reason}"),
            Self::StreamIo(reason) => write!(f, "host stream IO failed: {reason}"),
            Self::UnsupportedAllowedEvent => f.write_str("allowed event has no egress operation"),
        }
    }
}

impl std::error::Error for EgressError {}

pub type DispatchOutcome<E> = EgressOutcome<
    <E as HostEgress>::TcpStream,
    <E as HostEgress>::UdpHandle,
    <E as HostEgress>::HttpResponse,
>;

/// Dispatch a normalized allowed event through the shared egress backend.
pub fn dispatch_allowed_event<E: HostEgress>(
    egress: &mut E,
    event: &NormalizedEvent,
) -> Result<DispatchOutcome<E>, EgressError> {
    match event {
        NormalizedEvent::TcpConnectAttempt(event) => {
            egress.connect_tcp(event).map(EgressOutcome::TcpConnected)
        }
        NormalizedEvent::UdpFlowAttempt(event) => {
            egress.open_udp_flow(event).map(EgressOutcome::UdpOpened)
        }
        NormalizedEvent::DnsQuery(event) => {
            egress.resolve_dns(event).map(EgressOutcome::DnsResolved)
        }
        NormalizedEvent::HttpRequest(event) => egress
            .proxy_http_request(event)
            .map(EgressOutcome::HttpForwarded),
        NormalizedEvent::HttpsConnect(event) => {
            egress.proxy_connect(event).map(EgressOutcome::TcpConnected)
        }
        NormalizedEvent::SocksConnect(event) => {
            egress.socks_connect(event).map(EgressOutcome::TcpConnected)
        }
        NormalizedEvent::TlsClientHello(_)
        | NormalizedEvent::IcmpMessage(_)
        | NormalizedEvent::UnsupportedNetworkEvent(_) => Err(EgressError::UnsupportedAllowedEvent),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressOutcome<TcpStream, UdpHandle, HttpResponse> {
    TcpConnected(TcpStream),
    UdpOpened(UdpHandle),
    HttpForwarded(HttpResponse),
    DnsResolved(Vec<SocketAddr>),
}

pub fn destination_host_to_string(host: &DestinationHost) -> String {
    match host {
        DestinationHost::Hostname(hostname) => hostname.as_str().to_string(),
        DestinationHost::Ip(ip) => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{FrontendKind, SandboxId, UdpClassification};

    #[test]
    fn transparent_and_proxy_paths_use_same_egress_trait() {
        let mut egress = MockEgress::default();
        let tcp = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "203.0.113.10:80".parse().unwrap(),
            hostname: None,
        });
        let proxy = NormalizedEvent::HttpsConnect(HttpsConnect {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::HttpProxy,
            host: DestinationHost::Hostname(foxprox_core::Hostname::new("example.com").unwrap()),
            port: 443,
        });
        let http = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::HttpProxy,
            method: foxprox_core::HttpMethod::Get,
            scheme: foxprox_core::HttpScheme::Http,
            host: DestinationHost::Hostname(foxprox_core::Hostname::new("example.com").unwrap()),
            port: 80,
            path_query: "/index.html".to_string(),
        });

        dispatch_allowed_event(&mut egress, &tcp).unwrap();
        dispatch_allowed_event(&mut egress, &proxy).unwrap();
        dispatch_allowed_event(&mut egress, &http).unwrap();

        assert_eq!(egress.tcp_connects.len(), 1);
        assert_eq!(egress.proxy_connects.len(), 1);
        assert_eq!(egress.http_requests.len(), 1);
    }

    #[test]
    fn std_egress_formats_normalized_destinations_without_frontend_types() {
        let ipv6 = DestinationHost::Ip("2001:db8::1".parse().unwrap());
        assert_eq!(format_http_host_header(&ipv6, 8080), "[2001:db8::1]:8080");
        let hostname =
            DestinationHost::Hostname(foxprox_core::Hostname::new("Example.COM").unwrap());
        assert_eq!(destination_host_to_string(&hostname), "example.com");
        assert_eq!(http_method_as_str(&foxprox_core::HttpMethod::Post), "POST");
    }

    #[test]
    fn tcp_stream_contract_is_shared_for_bridge_code() {
        let mut stream = MockTcpStream;
        assert_eq!(stream.write_from_sandbox(b"hello").unwrap(), 5);
        assert_eq!(stream.read_to_sandbox(1024).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn udp_egress_receives_normalized_classification() {
        let mut egress = MockEgress::default();
        let udp = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: None,
            classification: UdpClassification::QuicCandidate,
        });

        dispatch_allowed_event(&mut egress, &udp).unwrap();
        assert_eq!(
            egress.udp_flows[0].classification,
            UdpClassification::QuicCandidate
        );
    }
}
