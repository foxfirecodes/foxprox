//! Core, platform-independent contracts for foxprox.
//!
//! This crate defines the narrow data model shared by frontends, transparent
//! inspection, policy, audit, egress, and integration layers. It intentionally
//! contains no Linux, TUN, bwrap, smoltcp, HTTP parser, SOCKS parser, or socket
//! implementation types.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// Stable crate marker used by scaffold tests and downstream workspace checks.
pub const CRATE_NAME: &str = "foxprox-core";

/// Opaque sandbox/session identity used in normalized events and audit output.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SandboxId(String);

impl SandboxId {
    /// Creates a sandbox id after rejecting empty or whitespace-only values.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ContractError::EmptySandboxId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalized hostname. Construction lowercases and trims a trailing dot.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hostname(String);

impl Hostname {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let mut value = value
            .into()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if value.is_empty() {
            return Err(ContractError::EmptyHostname);
        }
        if value.len() > 253
            || value
                .split('.')
                .any(|label| label.is_empty() || label.len() > 63)
        {
            return Err(ContractError::InvalidHostname(value));
        }
        if value.ends_with('.') {
            value.pop();
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_subdomain_of(&self, suffix: &DomainSuffix) -> bool {
        self.0 == suffix.as_str()
            || self
                .0
                .strip_suffix(suffix.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalized domain suffix used by policy rules.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainSuffix(Hostname);

impl DomainSuffix {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        let value = value.trim().trim_start_matches('.').to_string();
        Ok(Self(Hostname::new(value)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// IP network matcher that does not leak an external CIDR crate into contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, ContractError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(ContractError::InvalidCidrPrefix { prefix_len, max });
        }
        Ok(Self {
            network: mask_ip(network, prefix_len),
            prefix_len,
        })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = ipv4_mask(self.prefix_len);
                u32::from(network) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = ipv6_mask(self.prefix_len);
                u128::from(network) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or_else(|| ContractError::InvalidCidr(value.to_string()))?;
        let ip: IpAddr = ip
            .parse()
            .map_err(|_| ContractError::InvalidCidr(value.to_string()))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| ContractError::InvalidCidr(value.to_string()))?;
        Self::new(ip, prefix_len)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

fn mask_ip(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & ipv4_mask(prefix_len))),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & ipv6_mask(prefix_len))),
    }
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

/// Frontend kind is normalized and intentionally independent from frontend crate
/// implementation structs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FrontendKind {
    Tun,
    HttpProxy,
    Socks5,
    SetupHelper,
    ExternalNamespace,
}

/// Protocol class as seen by policy. Parser-specific protocol objects must not
/// cross into this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Http,
    HttpsConnect,
    TlsClientHello,
    SocksConnect,
    QuicCandidate,
    Unsupported,
}

/// Source of hostname attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostnameAttributionSource {
    BrokerDns,
    HttpHostHeader,
    TlsSni,
    QuicTlsMetadata,
    ExplicitProxyDestination,
    IpOnly,
}

/// Confidence assigned to hostname attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HostnameConfidence {
    Unknown,
    Low,
    Medium,
    High,
}

/// Hostname plus attribution metadata used by policy and audit.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HostnameAttribution {
    hostname: Hostname,
    source: HostnameAttributionSource,
    confidence: HostnameConfidence,
}

impl HostnameAttribution {
    pub fn new(
        hostname: Hostname,
        source: HostnameAttributionSource,
        confidence: HostnameConfidence,
    ) -> Self {
        Self {
            hostname,
            source,
            confidence,
        }
    }

    pub fn hostname(&self) -> &Hostname {
        &self.hostname
    }

    pub fn source(&self) -> HostnameAttributionSource {
        self.source
    }

    pub fn confidence(&self) -> HostnameConfidence {
        self.confidence
    }
}

/// SNI/DNS mismatch state for transparent HTTPS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostnameMismatch {
    Matches,
    Mismatch,
    Unavailable,
    NotChecked,
}

/// Host or IP destination used by explicit proxy and SOCKS contracts.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DestinationHost {
    Hostname(Hostname),
    Ip(IpAddr),
}

impl DestinationHost {
    pub fn hostname(&self) -> Option<&Hostname> {
        match self {
            Self::Hostname(hostname) => Some(hostname),
            Self::Ip(_) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Hostname(_) => None,
        }
    }
}

/// Byte counters for flow lifecycle audit records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct ByteCounts {
    pub ingress: u64,
    pub egress: u64,
}

impl ByteCounts {
    pub fn new(ingress: u64, egress: u64) -> Self {
        Self { ingress, egress }
    }
}

/// UDP semantic classification used for timeout and policy decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UdpClassification {
    Dns,
    QuicCandidate,
    NtpLike,
    MulticastOrBroadcast,
    Generic,
}

/// DNS query type represented without leaking a parser crate.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Other(u16),
}

/// Normalized TCP connect attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConnectAttempt {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub hostname: Option<HostnameAttribution>,
}

/// Normalized UDP flow or datagram attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowAttempt {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub hostname: Option<HostnameAttribution>,
    pub classification: UdpClassification,
}

/// DNS query normalized before policy/audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub hostname: Hostname,
    pub query_type: DnsQueryType,
    pub direct_external: bool,
}

/// Plaintext HTTP request metadata visible to policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub method: HttpMethod,
    pub scheme: HttpScheme,
    pub host: DestinationHost,
    pub port: u16,
    pub path_query: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HttpScheme {
    Http,
    Https,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Other(String),
}

impl HttpMethod {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            other => Self::Other(other.to_string()),
        }
    }
}

/// HTTPS CONNECT destination metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsConnect {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub host: DestinationHost,
    pub port: u16,
}

/// Transparent TLS ClientHello metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsClientHello {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub destination: SocketAddr,
    pub sni: Option<Hostname>,
    pub dns_hostname: Option<HostnameAttribution>,
    pub mismatch: HostnameMismatch,
}

/// SOCKS5 TCP CONNECT destination metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksConnect {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub destination: DestinationHost,
    pub port: u16,
}

/// ICMP message metadata visible to policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpMessage {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub source: IpAddr,
    pub destination: IpAddr,
}

/// Fail-closed unsupported event, emitted after a packet/request is normalized as
/// unsupported. Safe metadata must remain non-sensitive and frontend independent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedNetworkEvent {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub reason: UnsupportedReason,
    pub safe_metadata: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum UnsupportedReason {
    MalformedPacket,
    MalformedProxyRequest,
    UnsupportedIpProtocol(u8),
    UnsupportedFragmentation,
    UnsupportedIcmpType { icmp_type: u8, icmp_code: u8 },
    UnknownLayer2,
    ParserLimitExceeded,
    HiddenSniOrEch,
    Other(String),
}

/// Normalized policy event produced by any frontend or inspection path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedEvent {
    TcpConnectAttempt(TcpConnectAttempt),
    UdpFlowAttempt(UdpFlowAttempt),
    DnsQuery(DnsQuery),
    HttpRequest(HttpRequest),
    HttpsConnect(HttpsConnect),
    TlsClientHello(TlsClientHello),
    SocksConnect(SocksConnect),
    IcmpMessage(IcmpMessage),
    UnsupportedNetworkEvent(UnsupportedNetworkEvent),
}

impl NormalizedEvent {
    pub fn sandbox_id(&self) -> &SandboxId {
        match self {
            Self::TcpConnectAttempt(event) => &event.sandbox_id,
            Self::UdpFlowAttempt(event) => &event.sandbox_id,
            Self::DnsQuery(event) => &event.sandbox_id,
            Self::HttpRequest(event) => &event.sandbox_id,
            Self::HttpsConnect(event) => &event.sandbox_id,
            Self::TlsClientHello(event) => &event.sandbox_id,
            Self::SocksConnect(event) => &event.sandbox_id,
            Self::IcmpMessage(event) => &event.sandbox_id,
            Self::UnsupportedNetworkEvent(event) => &event.sandbox_id,
        }
    }

    pub fn frontend(&self) -> FrontendKind {
        match self {
            Self::TcpConnectAttempt(event) => event.frontend,
            Self::UdpFlowAttempt(event) => event.frontend,
            Self::DnsQuery(event) => event.frontend,
            Self::HttpRequest(event) => event.frontend,
            Self::HttpsConnect(event) => event.frontend,
            Self::TlsClientHello(event) => event.frontend,
            Self::SocksConnect(event) => event.frontend,
            Self::IcmpMessage(event) => event.frontend,
            Self::UnsupportedNetworkEvent(event) => event.frontend,
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            Self::TcpConnectAttempt(_) => Protocol::Tcp,
            Self::UdpFlowAttempt(event) => match event.classification {
                UdpClassification::Dns => Protocol::Dns,
                UdpClassification::QuicCandidate => Protocol::QuicCandidate,
                _ => Protocol::Udp,
            },
            Self::DnsQuery(_) => Protocol::Dns,
            Self::HttpRequest(_) => Protocol::Http,
            Self::HttpsConnect(_) => Protocol::HttpsConnect,
            Self::TlsClientHello(_) => Protocol::TlsClientHello,
            Self::SocksConnect(_) => Protocol::SocksConnect,
            Self::IcmpMessage(_) => Protocol::Icmp,
            Self::UnsupportedNetworkEvent(_) => Protocol::Unsupported,
        }
    }

    pub fn hostname_attribution(&self) -> Option<&HostnameAttribution> {
        match self {
            Self::TcpConnectAttempt(event) => event.hostname.as_ref(),
            Self::UdpFlowAttempt(event) => event.hostname.as_ref(),
            Self::DnsQuery(_) => None,
            Self::HttpRequest(_) => None,
            Self::HttpsConnect(_) => None,
            Self::TlsClientHello(event) => event.dns_hostname.as_ref(),
            Self::SocksConnect(_) => None,
            Self::IcmpMessage(_) => None,
            Self::UnsupportedNetworkEvent(_) => None,
        }
    }

    pub fn destination_ip(&self) -> Option<IpAddr> {
        match self {
            Self::TcpConnectAttempt(event) => Some(event.destination.ip()),
            Self::UdpFlowAttempt(event) => Some(event.destination.ip()),
            Self::DnsQuery(event) => Some(event.destination.ip()),
            Self::TlsClientHello(event) => Some(event.destination.ip()),
            Self::IcmpMessage(event) => Some(event.destination),
            Self::HttpsConnect(event) => event.host.ip(),
            Self::SocksConnect(event) => event.destination.ip(),
            Self::HttpRequest(event) => event.host.ip(),
            Self::UnsupportedNetworkEvent(_) => None,
        }
    }

    pub fn destination_port(&self) -> Option<u16> {
        match self {
            Self::TcpConnectAttempt(event) => Some(event.destination.port()),
            Self::UdpFlowAttempt(event) => Some(event.destination.port()),
            Self::DnsQuery(event) => Some(event.destination.port()),
            Self::HttpRequest(event) => Some(event.port),
            Self::HttpsConnect(event) => Some(event.port),
            Self::TlsClientHello(event) => Some(event.destination.port()),
            Self::SocksConnect(event) => Some(event.port),
            Self::IcmpMessage(_) | Self::UnsupportedNetworkEvent(_) => None,
        }
    }

    pub fn explicit_hostname(&self) -> Option<&Hostname> {
        match self {
            Self::DnsQuery(event) => Some(&event.hostname),
            Self::HttpRequest(event) => event.host.hostname(),
            Self::HttpsConnect(event) => event.host.hostname(),
            Self::TlsClientHello(event) => event.sni.as_ref(),
            Self::SocksConnect(event) => event.destination.hostname(),
            Self::TcpConnectAttempt(event) => {
                event.hostname.as_ref().map(HostnameAttribution::hostname)
            }
            Self::UdpFlowAttempt(event) => {
                event.hostname.as_ref().map(HostnameAttribution::hostname)
            }
            Self::IcmpMessage(_) | Self::UnsupportedNetworkEvent(_) => None,
        }
    }
}

/// Policy decision action. Exhaustive by design so denial behavior is explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow(AllowDecision),
    Deny(DenyDecision),
    RequireBrokerDns { reason: DecisionReason },
    FailClosed { reason: DecisionReason },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }

    pub fn reason(&self) -> Option<&DecisionReason> {
        match self {
            Self::Allow(decision) => decision.reason.as_ref(),
            Self::Deny(decision) => Some(&decision.reason),
            Self::RequireBrokerDns { reason } | Self::FailClosed { reason } => Some(reason),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowDecision {
    pub rule_id: Option<RuleId>,
    pub timeout_override: Option<Duration>,
    pub reason: Option<DecisionReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyDecision {
    pub action: DenialAction,
    pub rule_id: Option<RuleId>,
    pub reason: DecisionReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DenialAction {
    Drop,
    Reset,
    IcmpUnreachable,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DecisionReason(String);

impl DecisionReason {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for DecisionReason {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for DecisionReason {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RuleId(String);

impl RuleId {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ContractError::EmptyRuleId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Minimal normalized runtime configuration for alpha policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub default_policy: DefaultPolicy,
    pub direct_dns_policy: DirectDnsPolicy,
    pub allow_ping: bool,
    pub quic_policy: QuicPolicy,
    pub broker_dns_addrs: Vec<IpAddr>,
    pub udp_timeouts: UdpTimeouts,
    pub resource_limits: ResourceLimits,
    pub rules: Vec<PolicyRule>,
}

impl RuntimeConfig {
    pub fn deny_by_default() -> Self {
        Self {
            default_policy: DefaultPolicy::Deny,
            direct_dns_policy: DirectDnsPolicy::DenyExternal,
            allow_ping: false,
            quic_policy: QuicPolicy::DenyByDefault,
            broker_dns_addrs: Vec::new(),
            udp_timeouts: UdpTimeouts::default(),
            resource_limits: ResourceLimits::default(),
            rules: Vec::new(),
        }
    }

    pub fn allow_by_default() -> Self {
        Self {
            default_policy: DefaultPolicy::Allow,
            ..Self::deny_by_default()
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::deny_by_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DefaultPolicy {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DirectDnsPolicy {
    DenyExternal,
    AllowExternal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum QuicPolicy {
    DenyByDefault,
    AllowCandidates,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTimeouts {
    pub dns: Duration,
    pub generic: Duration,
    pub quic: Duration,
    pub ntp_like: Duration,
}

impl Default for UdpTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(10),
            generic: Duration::from_secs(60),
            quic: Duration::from_secs(180),
            ntp_like: Duration::from_secs(10),
        }
    }
}

/// Runtime resource limits enforced by broker subsystems.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ResourceLimits {
    pub max_flows: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self { max_flows: 4096 }
    }
}

/// Classify UDP destinations using only normalized socket metadata.
///
/// Packet, flow, and policy-adjacent code share this helper so QUIC/DNS/NTP and
/// multicast semantics do not drift across parser and network-adapter crates.
pub fn classify_udp_destination(destination: SocketAddr) -> UdpClassification {
    if is_multicast_or_broadcast(destination.ip()) {
        UdpClassification::MulticastOrBroadcast
    } else if destination.port() == 53 {
        UdpClassification::Dns
    } else if destination.port() == 443 {
        UdpClassification::QuicCandidate
    } else if destination.port() == 123 {
        UdpClassification::NtpLike
    } else {
        UdpClassification::Generic
    }
}

fn is_multicast_or_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_multicast() || ip.octets() == [255, 255, 255, 255],
        IpAddr::V6(ip) => ip.is_multicast(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub id: RuleId,
    pub action: RuleAction,
    pub protocol: ProtocolMatcher,
    pub destination: DestinationMatcher,
    pub port: PortMatcher,
    pub http_scheme: HttpSchemeMatcher,
    pub http_method: HttpMethodMatcher,
    pub http_path: HttpPathMatcher,
    pub minimum_hostname_confidence: HostnameConfidence,
    pub timeout_override: Option<Duration>,
}

impl PolicyRule {
    pub fn allow(id: RuleId) -> Self {
        Self {
            id,
            action: RuleAction::Allow,
            protocol: ProtocolMatcher::Any,
            destination: DestinationMatcher::Any,
            port: PortMatcher::Any,
            http_scheme: HttpSchemeMatcher::Any,
            http_method: HttpMethodMatcher::Any,
            http_path: HttpPathMatcher::Any,
            minimum_hostname_confidence: HostnameConfidence::Unknown,
            timeout_override: None,
        }
    }

    pub fn deny(id: RuleId, action: DenialAction) -> Self {
        Self {
            action: RuleAction::Deny(action),
            ..Self::allow(id)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RuleAction {
    Allow,
    Deny(DenialAction),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProtocolMatcher {
    Any,
    Exact(Protocol),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationMatcher {
    Any,
    Ip(IpAddr),
    Cidr(IpCidr),
    Hostname(Hostname),
    DomainSuffix(DomainSuffix),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PortMatcher {
    Any,
    Exact(u16),
    Range { start: u16, end: u16 },
}

/// HTTP scheme matcher for origin-aware HTTP policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HttpSchemeMatcher {
    Any,
    Exact(HttpScheme),
}

/// HTTP method matcher for plaintext HTTP policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HttpMethodMatcher {
    Any,
    Exact(HttpMethod),
}

/// HTTP path/query matcher for plaintext HTTP policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HttpPathMatcher {
    Any,
    Exact(String),
    Prefix(String),
}

impl PortMatcher {
    pub fn matches(self, port: Option<u16>) -> bool {
        match (self, port) {
            (Self::Any, _) => true,
            (Self::Exact(expected), Some(actual)) => expected == actual,
            (Self::Range { start, end }, Some(actual)) => (start..=end).contains(&actual),
            (_, None) => false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ContractError {
    EmptySandboxId,
    EmptyHostname,
    InvalidHostname(String),
    InvalidCidr(String),
    InvalidCidrPrefix { prefix_len: u8, max: u8 },
    EmptyRuleId,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySandboxId => f.write_str("sandbox id must not be empty"),
            Self::EmptyHostname => f.write_str("hostname must not be empty"),
            Self::InvalidHostname(hostname) => write!(f, "invalid hostname: {hostname}"),
            Self::InvalidCidr(cidr) => write!(f, "invalid CIDR: {cidr}"),
            Self::InvalidCidrPrefix { prefix_len, max } => {
                write!(f, "invalid CIDR prefix {prefix_len}; max is {max}")
            }
            Self::EmptyRuleId => f.write_str("rule id must not be empty"),
        }
    }
}

impl std::error::Error for ContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_core_crate_marker() {
        assert_eq!(CRATE_NAME, "foxprox-core");
    }

    #[test]
    fn normalizes_hostname_for_policy_matching() {
        let hostname = Hostname::new("Example.COM.").unwrap();
        let suffix = DomainSuffix::new(".example.com").unwrap();
        let child = Hostname::new("www.example.com").unwrap();

        assert_eq!(hostname.as_str(), "example.com");
        assert!(hostname.is_subdomain_of(&suffix));
        assert!(child.is_subdomain_of(&suffix));
    }

    #[test]
    fn cidr_matcher_masks_network() {
        let cidr: IpCidr = "192.0.2.99/24".parse().unwrap();
        assert_eq!(cidr.to_string(), "192.0.2.0/24");
        assert!(cidr.contains("192.0.2.1".parse().unwrap()));
        assert!(!cidr.contains("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn normalized_event_protocol_hides_frontend_details() {
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: SandboxId::new("sandbox-a").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:40000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: None,
            classification: UdpClassification::QuicCandidate,
        });

        assert_eq!(event.protocol(), Protocol::QuicCandidate);
        assert_eq!(event.frontend(), FrontendKind::Tun);
    }

    #[test]
    fn shared_udp_destination_classification_covers_alpha_defaults() {
        assert_eq!(
            classify_udp_destination("203.0.113.10:53".parse().unwrap()),
            UdpClassification::Dns
        );
        assert_eq!(
            classify_udp_destination("203.0.113.10:443".parse().unwrap()),
            UdpClassification::QuicCandidate
        );
        assert_eq!(
            classify_udp_destination("224.0.0.1:9999".parse().unwrap()),
            UdpClassification::MulticastOrBroadcast
        );
    }
}
