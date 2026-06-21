//! Normalized network event model shared by transparent and proxy frontends.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

/// Stable sandbox/session identifier used in policy and audit events.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SandboxId(String);

impl SandboxId {
    /// Creates a new sandbox identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentifierError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SandboxId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Identifier validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// Identifiers must not be empty or whitespace-only.
    Empty,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("identifier must not be empty"),
        }
    }
}

impl std::error::Error for IdentifierError {}

/// Normalized hostname used by rules, DNS observations, SNI, and proxy requests.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Hostname(String);

impl Hostname {
    /// Parses and normalizes a hostname.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, HostnameError> {
        let trimmed = value.as_ref().trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(HostnameError::Empty);
        }
        if trimmed.len() > 253 {
            return Err(HostnameError::TooLong);
        }
        if trimmed
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63 || !is_valid_label(label))
        {
            return Err(HostnameError::InvalidLabel);
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    /// Returns the normalized hostname.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true when this hostname is exactly `domain` or is a subdomain of it.
    pub fn matches_domain_suffix(&self, domain: &Hostname) -> bool {
        self.0 == domain.0
            || self
                .0
                .strip_suffix(domain.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Hostname {
    type Err = HostnameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn is_valid_label(label: &str) -> bool {
    label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Hostname validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostnameError {
    /// Hostnames must not be empty.
    Empty,
    /// Hostnames must fit the DNS wire-format length limit.
    TooLong,
    /// At least one DNS label is invalid.
    InvalidLabel,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("hostname must not be empty"),
            Self::TooLong => f.write_str("hostname is too long"),
            Self::InvalidLabel => f.write_str("hostname contains an invalid label"),
        }
    }
}

impl std::error::Error for HostnameError {}

/// Frontend that produced a normalized event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Frontend {
    /// Transparent TUN frontend.
    Tun,
    /// Explicit HTTP proxy frontend.
    HttpProxy,
    /// Explicit SOCKS5 frontend.
    Socks5,
    /// Broker-controlled DNS frontend.
    Dns,
    /// Integration/setup subsystem.
    Setup,
}

/// Network protocol or semantic policy class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Domain Name System.
    Dns,
    /// Internet Control Message Protocol.
    Icmp,
    /// Plaintext HTTP request.
    Http,
    /// HTTPS proxy CONNECT request.
    HttpsConnect,
    /// TLS ClientHello metadata.
    Tls,
    /// SOCKS TCP connect request.
    Socks,
    /// QUIC candidate over UDP.
    Quic,
    /// Unsupported or malformed input.
    Unsupported,
}

/// IP/port tuple for normalized transport events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TransportEndpoint {
    /// IP address.
    pub ip: IpAddr,
    /// Transport port.
    pub port: u16,
}

impl TransportEndpoint {
    /// Creates a transport endpoint from an address and port.
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

impl From<SocketAddr> for TransportEndpoint {
    fn from(value: SocketAddr) -> Self {
        Self::new(value.ip(), value.port())
    }
}

/// Source of hostname attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AttributionSource {
    /// Explicit proxy destination host.
    ExplicitProxy,
    /// Plaintext HTTP Host header.
    HttpHostHeader,
    /// TLS ClientHello SNI.
    TlsSni,
    /// Broker-controlled DNS cache correlation.
    DnsCache,
    /// IP-only fallback with no hostname.
    IpOnly,
    /// QUIC visible metadata.
    QuicMetadata,
}

/// Confidence level for hostname attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AttributionConfidence {
    /// No attribution or only raw IP information.
    Low,
    /// DNS cache correlation or other reusable but shared-IP-prone evidence.
    Medium,
    /// Direct request metadata such as proxy host, HTTP Host, or TLS SNI.
    High,
}

/// Hostname attribution attached to a flow or request.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Attribution {
    /// Hostname if one is known.
    pub hostname: Option<Hostname>,
    /// Source of the attribution.
    pub source: AttributionSource,
    /// Confidence in the attribution.
    pub confidence: AttributionConfidence,
}

impl Attribution {
    /// Creates high-confidence attribution from an explicit proxy host.
    pub fn explicit_proxy(hostname: Hostname) -> Self {
        Self {
            hostname: Some(hostname),
            source: AttributionSource::ExplicitProxy,
            confidence: AttributionConfidence::High,
        }
    }

    /// Creates IP-only low-confidence attribution.
    pub const fn ip_only() -> Self {
        Self {
            hostname: None,
            source: AttributionSource::IpOnly,
            confidence: AttributionConfidence::Low,
        }
    }
}

/// Parsed origin tuple used by HTTP policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Origin {
    /// URL scheme, usually `http` or `https`.
    pub scheme: String,
    /// Origin host.
    pub host: Hostname,
    /// Origin port.
    pub port: u16,
}

/// SOCKS TCP CONNECT destination.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SocksDestination {
    /// Hostname destination requested by the client.
    Host {
        /// Destination host.
        host: Hostname,
        /// Destination port.
        port: u16,
    },
    /// IP destination requested by the client or after resolution.
    Ip(TransportEndpoint),
}

impl SocksDestination {
    /// Returns the requested destination port.
    pub const fn port(&self) -> u16 {
        match self {
            Self::Host { port, .. } => *port,
            Self::Ip(endpoint) => endpoint.port,
        }
    }

    /// Returns the requested destination host, when the client supplied one.
    pub const fn host(&self) -> Option<&Hostname> {
        match self {
            Self::Host { host, .. } => Some(host),
            Self::Ip(_) => None,
        }
    }

    /// Returns the requested IP endpoint, when available.
    pub const fn endpoint(&self) -> Option<TransportEndpoint> {
        match self {
            Self::Host { .. } => None,
            Self::Ip(endpoint) => Some(*endpoint),
        }
    }
}

/// HTTP method carried by normalized events.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HttpMethod(String);

impl HttpMethod {
    /// Parses and normalizes an HTTP method token.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, HttpMethodError> {
        let value = value.as_ref().trim();
        if value.is_empty() {
            return Err(HttpMethodError::Empty);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(HttpMethodError::InvalidToken);
        }
        Ok(Self(value.to_ascii_uppercase()))
    }

    /// Returns the normalized method token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// HTTP method validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpMethodError {
    /// Methods must not be empty.
    Empty,
    /// Method is not an HTTP token.
    InvalidToken,
}

impl fmt::Display for HttpMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("HTTP method must not be empty"),
            Self::InvalidToken => f.write_str("HTTP method is not a valid token"),
        }
    }
}

impl std::error::Error for HttpMethodError {}

/// Reason an input could not safely be handled and must fail closed.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum UnsupportedReason {
    /// Packet or request was malformed.
    Malformed(String),
    /// IP protocol number is not supported.
    UnsupportedIpProtocol(u8),
    /// Fragmentation case is unsupported by the current implementation.
    UnsupportedFragmentation,
    /// Direct DNS bypass attempt.
    DirectDnsBypass,
    /// Multicast or broadcast traffic is denied by default.
    MulticastOrBroadcast,
    /// ICMP type/code is not supported.
    UnsupportedIcmp {
        /// ICMP type.
        ty: u8,
        /// ICMP code.
        code: u8,
    },
    /// Missing hostname attribution for a hostname-required rule path.
    MissingRequiredAttribution,
    /// Generic setup or integration failure.
    SetupFailure(String),
}

/// Normalized event emitted by frontend, inspection, DNS, setup, or stack code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkEvent {
    /// Broker or sandbox network session started.
    SessionStarted {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Frontend or backend source.
        frontend: Frontend,
    },
    /// TUN interface was configured.
    TunConfigured {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Sandbox-side address.
        address: IpAddr,
        /// MTU in bytes.
        mtu: u16,
    },
    /// TCP connection attempt.
    TcpConnectAttempt {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Source frontend.
        frontend: Frontend,
        /// Sandbox-side source endpoint.
        source: Option<TransportEndpoint>,
        /// Destination endpoint.
        destination: TransportEndpoint,
        /// Hostname attribution.
        attribution: Attribution,
    },
    /// UDP flow or datagram attempt.
    UdpFlowAttempt {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Source frontend.
        frontend: Frontend,
        /// Sandbox-side source endpoint.
        source: TransportEndpoint,
        /// Destination endpoint.
        destination: TransportEndpoint,
        /// Hostname attribution.
        attribution: Attribution,
        /// Protocol classification.
        classification: Protocol,
    },
    /// DNS query observed by the broker.
    DnsQuery {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Query hostname.
        hostname: Hostname,
        /// Query type, e.g. `A` or `AAAA`.
        query_type: String,
        /// Source frontend.
        frontend: Frontend,
    },
    /// Plaintext HTTP request metadata.
    HttpRequest {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Source frontend.
        frontend: Frontend,
        /// HTTP method.
        method: HttpMethod,
        /// Request origin.
        origin: Origin,
        /// Path and optional query string.
        path_and_query: String,
    },
    /// HTTPS CONNECT request metadata.
    HttpsConnect {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Source frontend.
        frontend: Frontend,
        /// Destination host.
        host: Hostname,
        /// Destination port.
        port: u16,
    },
    /// TLS ClientHello metadata.
    TlsClientHello {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Source frontend.
        frontend: Frontend,
        /// Destination endpoint.
        destination: TransportEndpoint,
        /// SNI when visible.
        sni: Option<Hostname>,
        /// DNS-correlated hostname when available.
        dns_hostname: Option<Hostname>,
        /// Whether SNI and DNS attribution disagree.
        mismatch: bool,
    },
    /// SOCKS TCP CONNECT request metadata.
    SocksConnect {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Requested SOCKS destination.
        target: SocksDestination,
    },
    /// ICMP message.
    IcmpMessage {
        /// Sandbox/session identifier.
        sandbox_id: SandboxId,
        /// Source endpoint address.
        source: IpAddr,
        /// Destination endpoint address.
        destination: IpAddr,
        /// ICMP type.
        ty: u8,
        /// ICMP code.
        code: u8,
    },
    /// Unsupported or malformed packet/request that must fail closed.
    Unsupported {
        /// Sandbox/session identifier when known.
        sandbox_id: Option<SandboxId>,
        /// Source frontend.
        frontend: Frontend,
        /// Fail-closed reason.
        reason: UnsupportedReason,
    },
}

impl NetworkEvent {
    /// Returns the sandbox identifier for events that have one.
    pub fn sandbox_id(&self) -> Option<&SandboxId> {
        match self {
            Self::SessionStarted { sandbox_id, .. }
            | Self::TunConfigured { sandbox_id, .. }
            | Self::TcpConnectAttempt { sandbox_id, .. }
            | Self::UdpFlowAttempt { sandbox_id, .. }
            | Self::DnsQuery { sandbox_id, .. }
            | Self::HttpRequest { sandbox_id, .. }
            | Self::HttpsConnect { sandbox_id, .. }
            | Self::TlsClientHello { sandbox_id, .. }
            | Self::SocksConnect { sandbox_id, .. }
            | Self::IcmpMessage { sandbox_id, .. } => Some(sandbox_id),
            Self::Unsupported { sandbox_id, .. } => sandbox_id.as_ref(),
        }
    }

    /// Returns the semantic protocol for policy and audit routing.
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::SessionStarted { .. } | Self::TunConfigured { .. } => Protocol::Unsupported,
            Self::TcpConnectAttempt { .. } => Protocol::Tcp,
            Self::UdpFlowAttempt { classification, .. } => *classification,
            Self::DnsQuery { .. } => Protocol::Dns,
            Self::HttpRequest { .. } => Protocol::Http,
            Self::HttpsConnect { .. } => Protocol::HttpsConnect,
            Self::TlsClientHello { .. } => Protocol::Tls,
            Self::SocksConnect { .. } => Protocol::Socks,
            Self::IcmpMessage { .. } => Protocol::Icmp,
            Self::Unsupported { .. } => Protocol::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_normalizes_and_matches_suffix() {
        let host = Hostname::parse("WWW.Example.COM.").unwrap();
        let domain = Hostname::parse("example.com").unwrap();
        assert_eq!(host.as_str(), "www.example.com");
        assert!(host.matches_domain_suffix(&domain));
        assert!(domain.matches_domain_suffix(&domain));
    }

    #[test]
    fn hostname_rejects_bad_labels() {
        assert!(Hostname::parse("-bad.example").is_err());
        assert!(Hostname::parse("bad..example").is_err());
    }

    #[test]
    fn event_protocol_reflects_semantic_classification() {
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: SandboxId::new("alpha").unwrap(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new("10.0.0.2".parse().unwrap(), 44_444),
            destination: TransportEndpoint::new("93.184.216.34".parse().unwrap(), 443),
            attribution: Attribution::ip_only(),
            classification: Protocol::Quic,
        };
        assert_eq!(event.protocol(), Protocol::Quic);
    }
}
