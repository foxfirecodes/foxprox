//! Shared host egress contract for transparent and explicit proxy paths.
//!
//! The egress crate accepts normalized policy events and never receives raw TUN
//! packets, HTTP parser internals, SOCKS parser internals, or sandbox sockets.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;

use foxprox_core::{
    DestinationHost, DnsQuery, HttpsConnect, NormalizedEvent, SocksConnect, TcpConnectAttempt,
    UdpFlowAttempt,
};

/// Shared host-side egress backend used by all frontends after policy allows an
/// event. Production implementations open host sockets; tests can use mocks.
pub trait HostEgress {
    type TcpStream;
    type UdpHandle;

    fn connect_tcp(&mut self, event: &TcpConnectAttempt) -> Result<Self::TcpStream, EgressError>;

    fn open_udp_flow(&mut self, event: &UdpFlowAttempt) -> Result<Self::UdpHandle, EgressError>;

    fn proxy_connect(&mut self, event: &HttpsConnect) -> Result<Self::TcpStream, EgressError>;

    fn socks_connect(&mut self, event: &SocksConnect) -> Result<Self::TcpStream, EgressError>;

    fn resolve_dns(&mut self, event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError>;
}

/// Records allowed events and returns inert handles. Useful for contract tests.
#[derive(Clone, Debug, Default)]
pub struct MockEgress {
    pub tcp_connects: Vec<TcpConnectAttempt>,
    pub udp_flows: Vec<UdpFlowAttempt>,
    pub proxy_connects: Vec<HttpsConnect>,
    pub socks_connects: Vec<SocksConnect>,
    pub dns_queries: Vec<DnsQuery>,
}

impl HostEgress for MockEgress {
    type TcpStream = MockTcpStream;
    type UdpHandle = MockUdpHandle;

    fn connect_tcp(&mut self, event: &TcpConnectAttempt) -> Result<Self::TcpStream, EgressError> {
        self.tcp_connects.push(event.clone());
        Ok(MockTcpStream)
    }

    fn open_udp_flow(&mut self, event: &UdpFlowAttempt) -> Result<Self::UdpHandle, EgressError> {
        self.udp_flows.push(event.clone());
        Ok(MockUdpHandle)
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
        Ok(Vec::new())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockTcpStream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockUdpHandle;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EgressError {
    ConnectFailed(String),
    DnsFailed(String),
    UnsupportedAllowedEvent,
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectFailed(reason) => write!(f, "host connect failed: {reason}"),
            Self::DnsFailed(reason) => write!(f, "DNS failed: {reason}"),
            Self::UnsupportedAllowedEvent => f.write_str("allowed event has no egress operation"),
        }
    }
}

impl std::error::Error for EgressError {}

/// Dispatch a normalized allowed event through the shared egress backend.
pub fn dispatch_allowed_event<E: HostEgress>(
    egress: &mut E,
    event: &NormalizedEvent,
) -> Result<EgressOutcome<E::TcpStream, E::UdpHandle>, EgressError> {
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
        NormalizedEvent::HttpsConnect(event) => {
            egress.proxy_connect(event).map(EgressOutcome::TcpConnected)
        }
        NormalizedEvent::SocksConnect(event) => {
            egress.socks_connect(event).map(EgressOutcome::TcpConnected)
        }
        NormalizedEvent::HttpRequest(_)
        | NormalizedEvent::TlsClientHello(_)
        | NormalizedEvent::IcmpMessage(_)
        | NormalizedEvent::UnsupportedNetworkEvent(_) => Err(EgressError::UnsupportedAllowedEvent),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressOutcome<TcpStream, UdpHandle> {
    TcpConnected(TcpStream),
    UdpOpened(UdpHandle),
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

        dispatch_allowed_event(&mut egress, &tcp).unwrap();
        dispatch_allowed_event(&mut egress, &proxy).unwrap();

        assert_eq!(egress.tcp_connects.len(), 1);
        assert_eq!(egress.proxy_connects.len(), 1);
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
