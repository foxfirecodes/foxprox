use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// Stable identifier for the sandbox/session whose traffic is being mediated.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SandboxId(String);

impl SandboxId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SandboxId {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Broker frontend that observed a policy event.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Frontend {
    Tun,
    HttpProxy,
    Socks5,
    SetupHelper,
}

/// Normalized protocol or policy class.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Http,
    HttpsConnect,
    TlsSni,
    Socks,
    QuicCandidate,
    Unsupported(u8),
}

/// IP/port tuple when both are meaningful for the policy event.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: impl Into<Option<u16>>) -> Self {
        Self {
            ip,
            port: port.into(),
        }
    }

    pub fn tcp(ip: IpAddr, port: u16) -> Self {
        Self::new(ip, Some(port))
    }

    pub fn udp(ip: IpAddr, port: u16) -> Self {
        Self::new(ip, Some(port))
    }

    pub fn is_limited_broadcast(&self) -> bool {
        self.ip == IpAddr::V4(Ipv4Addr::BROADCAST)
    }

    pub fn is_multicast(&self) -> bool {
        self.ip.is_multicast()
    }
}

/// Source of a hostname attached to a policy event.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HostnameSource {
    None,
    IpOnly,
    DnsCache,
    PlaintextHttpHost,
    TlsSni,
    QuicTls,
    ExplicitProxy,
}

/// Confidence for applying domain-based policy rules.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HostnameConfidence {
    None,
    Low,
    Medium,
    High,
}

/// Normalized ICMP policy input. The handler decides which type/code pairs are
/// essential and which are denied unless configured otherwise.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct IcmpMessage {
    pub version: IpVersion,
    pub type_: u8,
    pub code: u8,
}

impl IcmpMessage {
    pub fn ipv4(type_: u8, code: u8) -> Self {
        Self {
            version: IpVersion::V4,
            type_,
            code,
        }
    }

    pub fn ipv6(type_: u8, code: u8) -> Self {
        Self {
            version: IpVersion::V6,
            type_,
            code,
        }
    }

    pub fn is_echo_request(&self) -> bool {
        matches!(
            (self.version, self.type_),
            (IpVersion::V4, 8) | (IpVersion::V6, 128)
        )
    }

    pub fn is_essential_error(&self) -> bool {
        matches!(
            (self.version, self.type_),
            (IpVersion::V4, 3 | 11 | 12) | (IpVersion::V6, 1..=4)
        )
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum IpVersion {
    V4,
    V6,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => f.write_str("tcp"),
            Protocol::Udp => f.write_str("udp"),
            Protocol::Dns => f.write_str("dns"),
            Protocol::Icmp => f.write_str("icmp"),
            Protocol::Http => f.write_str("http"),
            Protocol::HttpsConnect => f.write_str("https_connect"),
            Protocol::TlsSni => f.write_str("tls_sni"),
            Protocol::Socks => f.write_str("socks"),
            Protocol::QuicCandidate => f.write_str("quic_candidate"),
            Protocol::Unsupported(number) => write!(f, "unsupported:{number}"),
        }
    }
}
