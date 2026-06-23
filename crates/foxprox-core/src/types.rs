use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frontend {
    Tun,
    HttpProxy,
    Socks5Proxy,
    Setup,
    Core,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Quic,
    Http,
    Https,
    Socks,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    DenyDrop,
    DenyReset,
    DenyIcmpUnreachable,
    RequireBrokerDns,
    FailClosed,
}

impl Decision {
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_deny(self) -> bool {
        !self.is_allow()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConfidence {
    None,
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionSource {
    None,
    IpOnly,
    BrokerDns,
    PlaintextHttpHost,
    TlsSni,
    QuicTlsMetadata,
    ExplicitProxyHost,
    SocksDestination,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostnameAttribution {
    pub hostname: String,
    pub source: AttributionSource,
    pub confidence: AttributionConfidence,
}

impl HostnameAttribution {
    pub fn new(
        hostname: impl Into<String>,
        source: AttributionSource,
        confidence: AttributionConfidence,
    ) -> Self {
        Self {
            hostname: normalize_hostname(&hostname.into()),
            source,
            confidence,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    NetworkSessionStart,
    BrokerStarted,
    TunConfigured,
    ProxyListenerConfigured,
    RuntimeReadiness,
    ProxyDestinationResolved,
    PacketObserved,
    PacketMalformedDenied,
    HttpRequestDecision,
    HttpsConnectDecision,
    TransparentHttpDecision,
    TlsClientHelloObserved,
    SniDnsMismatchDenied,
    HiddenSniDenied,
    SocksConnectDecision,
    DnsQueryDecision,
    TcpConnectDecision,
    TcpFlowClosed,
    UdpFlowCreated,
    UdpPacketDecision,
    UdpFlowExpired,
    QuicCandidateFlowCreated,
    IcmpDecision,
    UnsupportedDenied,
    PolicyReload,
    BrokerError,
    NetworkSessionExit,
    AuditBackpressure,
    SetupPlanCreated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    DefaultDeny,
    RuleDenied,
    DirectDnsBypass,
    DnsDenied,
    MulticastDenied,
    BroadcastDenied,
    UnsupportedProtocol,
    UnsupportedFragmentation,
    MalformedPacket,
    IcmpUnsupported,
    SniDnsMismatch,
    HiddenSni,
    HostnameAttributionRequired,
    QuicDisabled,
    ProxyMalformed,
    ResourceLimit,
    AuditBackpressure,
    SetupFailed,
    RuntimeState,
    PolicyConfig,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
}

impl NetworkEndpoint {
    pub fn ip(ip: IpAddr) -> Self {
        Self {
            ip: Some(ip),
            port: None,
        }
    }

    pub fn socket(ip: IpAddr, port: u16) -> Self {
        Self {
            ip: Some(ip),
            port: Some(port),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn new(scheme: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme: scheme.into().to_ascii_lowercase(),
            host: normalize_hostname(&host.into()),
            port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxIdentity {
    pub session_id: String,
    pub profile: Option<String>,
    pub process_id: Option<u32>,
}

impl SandboxIdentity {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            profile: None,
            process_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteCounts {
    pub from_sandbox: u64,
    pub to_sandbox: u64,
}

impl ByteCounts {
    pub const ZERO: Self = Self {
        from_sandbox: 0,
        to_sandbox: 0,
    };
}

pub fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}
