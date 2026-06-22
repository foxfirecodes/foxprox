//! Platform-independent core types for foxprox.
//!
//! This crate owns the normalized event, policy, and audit boundary. It must not
//! depend on Linux, TUN, bwrap, smoltcp, or any concrete frontend/backend
//! implementation.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

/// Stable crate marker used by scaffold tests and downstream workspace checks.
pub const CRATE_NAME: &str = "foxprox-core";

/// Stable identity for one sandbox/network session.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SandboxId(String);

impl SandboxId {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(CoreError::InvalidSandboxId);
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

/// Core validation errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    InvalidSandboxId,
    InvalidCidrPrefix { addr: IpAddr, prefix: u8 },
    InvalidPortRange { start: u16, end: u16 },
    EmptyRuleId,
    EmptyHostnamePattern,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidSandboxId => f.write_str("sandbox id must not be empty"),
            CoreError::InvalidCidrPrefix { addr, prefix } => {
                write!(f, "invalid CIDR prefix {prefix} for address {addr}")
            }
            CoreError::InvalidPortRange { start, end } => {
                write!(f, "invalid port range {start}..={end}")
            }
            CoreError::EmptyRuleId => f.write_str("policy rule id must not be empty"),
            CoreError::EmptyHostnamePattern => f.write_str("hostname pattern must not be empty"),
        }
    }
}

impl std::error::Error for CoreError {}

/// Frontend that produced a normalized event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FrontendKind {
    Tun,
    HttpProxy,
    Socks5,
    Setup,
    External,
}

/// Network protocol or policy class visible at the core boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Http,
    HttpsConnect,
    TlsClientHello,
    Socks,
    QuicCandidate,
    Unsupported,
}

/// IP endpoint with an optional port for non-port protocols such as ICMP.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

impl Endpoint {
    pub const fn new(ip: IpAddr, port: Option<u16>) -> Self {
        Self { ip, port }
    }

    pub const fn tcp(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port: Some(port),
        }
    }

    pub const fn udp(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port: Some(port),
        }
    }
}

/// Source that supplied a hostname attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AttributionSource {
    ExplicitProxyHost,
    HttpHostHeader,
    TlsSni,
    DnsCache,
    QuicMetadata,
    IpOnly,
}

/// Confidence level for hostname attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AttributionConfidence {
    Low,
    Medium,
    High,
}

/// Hostname and confidence attached to a flow or request.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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
            hostname: normalize_hostname(hostname),
            source,
            confidence,
        }
    }
}

/// Classification for UDP pseudo-flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UdpClassification {
    Dns,
    QuicCandidate,
    Generic,
}

/// Normalized network event emitted by frontends/inspection before policy.
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
    Unsupported(UnsupportedNetworkEvent),
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
            Self::Unsupported(event) => &event.sandbox_id,
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
            Self::Unsupported(event) => event.frontend,
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            Self::TcpConnectAttempt(_) => Protocol::Tcp,
            Self::UdpFlowAttempt(event) => match event.classification {
                UdpClassification::Dns => Protocol::Dns,
                UdpClassification::QuicCandidate => Protocol::QuicCandidate,
                UdpClassification::Generic => Protocol::Udp,
            },
            Self::DnsQuery(_) => Protocol::Dns,
            Self::HttpRequest(_) => Protocol::Http,
            Self::HttpsConnect(_) => Protocol::HttpsConnect,
            Self::TlsClientHello(_) => Protocol::TlsClientHello,
            Self::SocksConnect(_) => Protocol::Socks,
            Self::IcmpMessage(_) => Protocol::Icmp,
            Self::Unsupported(_) => Protocol::Unsupported,
        }
    }

    pub fn source(&self) -> Option<Endpoint> {
        match self {
            Self::TcpConnectAttempt(event) => Some(event.source),
            Self::UdpFlowAttempt(event) => Some(event.source),
            Self::DnsQuery(event) => event.source,
            Self::HttpRequest(event) => event.source,
            Self::HttpsConnect(event) => event.source,
            Self::TlsClientHello(event) => event.source,
            Self::SocksConnect(_) => None,
            Self::IcmpMessage(event) => Some(event.source),
            Self::Unsupported(event) => event.source,
        }
    }

    pub fn destination(&self) -> Option<Endpoint> {
        match self {
            Self::TcpConnectAttempt(event) => Some(event.destination),
            Self::UdpFlowAttempt(event) => Some(event.destination),
            Self::DnsQuery(event) => Some(event.resolver),
            Self::HttpRequest(event) => event.destination,
            Self::HttpsConnect(event) => event.destination,
            Self::TlsClientHello(event) => Some(event.destination),
            Self::SocksConnect(event) => {
                event.destination_ip.map(|ip| Endpoint::tcp(ip, event.port))
            }
            Self::IcmpMessage(event) => Some(event.destination),
            Self::Unsupported(event) => event.destination,
        }
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::TcpConnectAttempt(event) => event
                .attribution
                .as_ref()
                .map(|value| value.hostname.as_str()),
            Self::UdpFlowAttempt(event) => event
                .attribution
                .as_ref()
                .map(|value| value.hostname.as_str()),
            Self::DnsQuery(event) => Some(event.hostname.as_str()),
            Self::HttpRequest(event) => Some(event.host.as_str()),
            Self::HttpsConnect(event) => Some(event.host.as_str()),
            Self::TlsClientHello(event) => event.sni.as_deref(),
            Self::SocksConnect(event) => Some(event.host.as_str()),
            Self::IcmpMessage(_) | Self::Unsupported(_) => None,
        }
    }

    pub fn destination_port(&self) -> Option<u16> {
        match self {
            Self::HttpRequest(event) => Some(event.port),
            Self::HttpsConnect(event) => Some(event.port),
            Self::SocksConnect(event) => Some(event.port),
            _ => self.destination().and_then(|destination| destination.port),
        }
    }

    pub fn attribution_confidence(&self) -> Option<AttributionConfidence> {
        match self {
            Self::TcpConnectAttempt(event) => {
                event.attribution.as_ref().map(|value| value.confidence)
            }
            Self::UdpFlowAttempt(event) => event.attribution.as_ref().map(|value| value.confidence),
            Self::DnsQuery(_)
            | Self::HttpRequest(_)
            | Self::HttpsConnect(_)
            | Self::SocksConnect(_) => Some(AttributionConfidence::High),
            Self::TlsClientHello(event) => event.sni.as_ref().map(|_| AttributionConfidence::High),
            Self::IcmpMessage(_) | Self::Unsupported(_) => None,
        }
    }

    pub fn http_method(&self) -> Option<&str> {
        match self {
            Self::HttpRequest(event) => Some(event.method.as_str()),
            _ => None,
        }
    }

    pub fn http_scheme(&self) -> Option<&str> {
        match self {
            Self::HttpRequest(event) => Some(event.scheme.as_str()),
            _ => None,
        }
    }

    pub fn http_path_query(&self) -> Option<&str> {
        match self {
            Self::HttpRequest(event) => Some(event.path_query.as_str()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConnectAttempt {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub attribution: Option<HostnameAttribution>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowAttempt {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub classification: UdpClassification,
    pub attribution: Option<HostnameAttribution>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Option<Endpoint>,
    pub resolver: Endpoint,
    pub hostname: String,
    pub query_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_query: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsConnect {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsClientHello {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub sni: Option<String>,
    pub dns_attribution: Option<HostnameAttribution>,
    pub mismatch: SniDnsMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SniDnsMismatch {
    NotChecked,
    Match,
    Mismatch,
    MissingSni,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksConnect {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub host: String,
    pub destination_ip: Option<IpAddr>,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpMessage {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub icmp_type: u8,
    pub icmp_code: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedNetworkEvent {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub reason: String,
}

/// Policy action after a rule match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleAction {
    Allow,
    Deny(DenyReason),
}

/// Denial behavior visible to frontends/forwarders.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DenialBehavior {
    Drop,
    Reset,
    IcmpUnreachable,
}

/// Reason attached to a denied/fail-closed decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyReason {
    pub behavior: DenialBehavior,
    pub message: String,
}

impl DenyReason {
    pub fn drop(message: impl Into<String>) -> Self {
        Self {
            behavior: DenialBehavior::Drop,
            message: message.into(),
        }
    }

    pub fn reset(message: impl Into<String>) -> Self {
        Self {
            behavior: DenialBehavior::Reset,
            message: message.into(),
        }
    }

    pub fn icmp_unreachable(message: impl Into<String>) -> Self {
        Self {
            behavior: DenialBehavior::IcmpUnreachable,
            message: message.into(),
        }
    }
}

/// Policy decision returned by the core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow {
        rule_id: Option<String>,
    },
    Deny {
        behavior: DenialBehavior,
        reason: String,
        rule_id: Option<String>,
    },
    FailClosed {
        reason: String,
    },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

/// CIDR matcher without dependency-specific types leaking across boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, CoreError> {
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(CoreError::InvalidCidrPrefix { addr, prefix });
        }
        Ok(Self { addr, prefix })
    }

    pub fn single(addr: IpAddr) -> Self {
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { addr, prefix }
    }

    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.addr, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                prefix_contains(u32::from(network), u32::from(candidate), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                prefix_contains(u128::from(network), u128::from(candidate), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_contains<T>(network: T, candidate: T, prefix: u8) -> bool
where
    T: Copy
        + From<u8>
        + std::ops::Not<Output = T>
        + std::ops::Shl<u32, Output = T>
        + std::ops::BitAnd<Output = T>
        + PartialEq,
{
    let bits = (std::mem::size_of::<T>() * 8) as u8;
    if prefix == 0 {
        return true;
    }
    let mask = !T::from(0) << u32::from(bits - prefix);
    (network & mask) == (candidate & mask)
}

/// Inclusive port matcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Result<Self, CoreError> {
        if start > end {
            return Err(CoreError::InvalidPortRange { start, end });
        }
        Ok(Self { start, end })
    }

    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// Host/domain matcher. `example.com` matches exactly; `.example.com` matches a
/// domain suffix including the apex and subdomains.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HostnamePattern(String);

impl HostnamePattern {
    pub fn new(pattern: impl Into<String>) -> Result<Self, CoreError> {
        let pattern = normalize_hostname(pattern);
        if pattern.is_empty() || pattern == "." {
            return Err(CoreError::EmptyHostnamePattern);
        }
        Ok(Self(pattern))
    }

    pub fn matches(&self, hostname: &str) -> bool {
        let hostname = normalize_hostname(hostname);
        if let Some(suffix) = self.0.strip_prefix('.') {
            hostname == suffix || hostname.ends_with(&format!(".{suffix}"))
        } else {
            hostname == self.0
        }
    }
}

/// Rule-level protocol matcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProtocolMatcher {
    Any,
    One(Protocol),
}

impl ProtocolMatcher {
    fn matches(self, protocol: Protocol) -> bool {
        match self {
            Self::Any => true,
            Self::One(expected) => expected == protocol,
        }
    }
}

/// One deterministic policy rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub id: String,
    pub action: RuleAction,
    pub protocol: ProtocolMatcher,
    pub destination_cidrs: Vec<IpCidr>,
    pub destination_ports: Vec<PortRange>,
    pub hostnames: Vec<HostnamePattern>,
    pub minimum_hostname_confidence: AttributionConfidence,
    pub http_methods: Vec<String>,
    pub http_path_prefixes: Vec<String>,
}

impl PolicyRule {
    pub fn new(id: impl Into<String>, action: RuleAction) -> Result<Self, CoreError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(CoreError::EmptyRuleId);
        }
        Ok(Self {
            id,
            action,
            protocol: ProtocolMatcher::Any,
            destination_cidrs: Vec::new(),
            destination_ports: Vec::new(),
            hostnames: Vec::new(),
            minimum_hostname_confidence: AttributionConfidence::Medium,
            http_methods: Vec::new(),
            http_path_prefixes: Vec::new(),
        })
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = ProtocolMatcher::One(protocol);
        self
    }

    pub fn with_destination_cidr(mut self, cidr: IpCidr) -> Self {
        self.destination_cidrs.push(cidr);
        self
    }

    pub fn with_destination_port(mut self, port: u16) -> Self {
        self.destination_ports.push(PortRange::single(port));
        self
    }

    pub fn with_hostname(mut self, hostname: HostnamePattern) -> Self {
        self.hostnames.push(hostname);
        self
    }

    pub fn with_minimum_hostname_confidence(mut self, confidence: AttributionConfidence) -> Self {
        self.minimum_hostname_confidence = confidence;
        self
    }

    pub fn with_http_method(mut self, method: impl Into<String>) -> Self {
        self.http_methods.push(method.into().to_ascii_uppercase());
        self
    }

    pub fn with_http_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.http_path_prefixes.push(prefix.into());
        self
    }

    fn matches(&self, event: &NormalizedEvent) -> bool {
        if !self.protocol.matches(event.protocol()) {
            return false;
        }

        if !self.destination_cidrs.is_empty() {
            let Some(destination) = event.destination() else {
                return false;
            };
            if !self
                .destination_cidrs
                .iter()
                .any(|cidr| cidr.contains(destination.ip))
            {
                return false;
            }
        }

        if !self.destination_ports.is_empty() {
            let Some(port) = event.destination_port() else {
                return false;
            };
            if !self
                .destination_ports
                .iter()
                .any(|range| range.contains(port))
            {
                return false;
            }
        }

        if !self.hostnames.is_empty() {
            let Some(hostname) = event.hostname() else {
                return false;
            };
            let Some(confidence) = event.attribution_confidence() else {
                return false;
            };
            if confidence < self.minimum_hostname_confidence {
                return false;
            }
            if !self
                .hostnames
                .iter()
                .any(|pattern| pattern.matches(hostname))
            {
                return false;
            }
        }

        if !self.http_methods.is_empty() {
            let Some(method) = event.http_method() else {
                return false;
            };
            if !self
                .http_methods
                .iter()
                .any(|expected| expected == &method.to_ascii_uppercase())
            {
                return false;
            }
        }

        if !self.http_path_prefixes.is_empty() {
            let Some(path_query) = event.http_path_query() else {
                return false;
            };
            if !self
                .http_path_prefixes
                .iter()
                .any(|prefix| path_query.starts_with(prefix))
            {
                return false;
            }
        }

        true
    }
}

/// DNS-specific fail-closed defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPolicy {
    pub broker_resolvers: Vec<Endpoint>,
    pub deny_direct_external_dns: bool,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            broker_resolvers: Vec::new(),
            deny_direct_external_dns: true,
        }
    }
}

/// ICMP defaults applied after explicit rules and before global defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpPolicy {
    pub allow_echo: bool,
    pub allow_essential_errors: bool,
}

impl Default for IcmpPolicy {
    fn default() -> Self {
        Self {
            allow_echo: false,
            allow_essential_errors: true,
        }
    }
}

/// Default policy when no rule matches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DefaultPolicy {
    Allow,
    Deny(DenyReason),
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::Deny(DenyReason::drop("default-deny"))
    }
}

/// Platform-independent policy configuration.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct PolicyConfig {
    pub default_policy: DefaultPolicy,
    pub dns: DnsPolicy,
    pub icmp: IcmpPolicy,
    pub rules: Vec<PolicyRule>,
}

/// Deterministic policy engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn decide(&self, event: &NormalizedEvent) -> PolicyDecision {
        if let NormalizedEvent::Unsupported(event) = event {
            return PolicyDecision::FailClosed {
                reason: format!("unsupported-network-event: {}", event.reason),
            };
        }

        if matches!(event.protocol(), Protocol::Unsupported) {
            return PolicyDecision::FailClosed {
                reason: "unsupported-protocol".to_owned(),
            };
        }

        if self.is_direct_dns_bypass(event) {
            return PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "direct-external-dns-denied".to_owned(),
                rule_id: None,
            };
        }

        if let NormalizedEvent::TlsClientHello(event) = event {
            match event.mismatch {
                SniDnsMismatch::Mismatch => {
                    return PolicyDecision::Deny {
                        behavior: DenialBehavior::Reset,
                        reason: "tls-sni-dns-mismatch".to_owned(),
                        rule_id: None,
                    };
                }
                SniDnsMismatch::MissingSni => {
                    return PolicyDecision::Deny {
                        behavior: DenialBehavior::Reset,
                        reason: "tls-sni-missing".to_owned(),
                        rule_id: None,
                    };
                }
                SniDnsMismatch::NotChecked | SniDnsMismatch::Match => {}
            }
        }

        for rule in &self.config.rules {
            if rule.matches(event) {
                return match &rule.action {
                    RuleAction::Allow => PolicyDecision::Allow {
                        rule_id: Some(rule.id.clone()),
                    },
                    RuleAction::Deny(reason) => PolicyDecision::Deny {
                        behavior: reason.behavior,
                        reason: reason.message.clone(),
                        rule_id: Some(rule.id.clone()),
                    },
                };
            }
        }

        if self.is_default_denied_udp_discovery(event) {
            return PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "udp-multicast-broadcast-denied".to_owned(),
                rule_id: None,
            };
        }

        if let Some(decision) = self.default_icmp_decision(event) {
            return decision;
        }

        match &self.config.default_policy {
            DefaultPolicy::Allow => PolicyDecision::Allow { rule_id: None },
            DefaultPolicy::Deny(reason) => PolicyDecision::Deny {
                behavior: reason.behavior,
                reason: reason.message.clone(),
                rule_id: None,
            },
        }
    }

    pub fn evaluate(&self, event: &NormalizedEvent) -> PolicyEvaluation {
        let decision = self.decide(event);
        let audit = AuditRecord::from_decision(event, &decision);
        PolicyEvaluation { decision, audit }
    }

    fn is_direct_dns_bypass(&self, event: &NormalizedEvent) -> bool {
        if !self.config.dns.deny_direct_external_dns || event.protocol() != Protocol::Dns {
            return false;
        }

        let Some(destination) = event.destination() else {
            return false;
        };
        if destination.port != Some(53) {
            return false;
        }
        !self
            .config
            .dns
            .broker_resolvers
            .iter()
            .any(|resolver| resolver == &destination)
    }

    fn is_default_denied_udp_discovery(&self, event: &NormalizedEvent) -> bool {
        if !matches!(
            event.protocol(),
            Protocol::Udp | Protocol::Dns | Protocol::QuicCandidate
        ) {
            return false;
        }
        event
            .destination()
            .map(|destination| is_multicast_or_broadcast(destination.ip))
            .unwrap_or(false)
    }

    fn default_icmp_decision(&self, event: &NormalizedEvent) -> Option<PolicyDecision> {
        let NormalizedEvent::IcmpMessage(message) = event else {
            return None;
        };
        if self.config.icmp.allow_essential_errors && is_essential_icmp_error(message) {
            return Some(PolicyDecision::Allow { rule_id: None });
        }
        if self.config.icmp.allow_echo && is_icmp_echo_request(message) {
            return Some(PolicyDecision::Allow { rule_id: None });
        }
        Some(PolicyDecision::Deny {
            behavior: DenialBehavior::Drop,
            reason: "icmp-default-deny".to_owned(),
            rule_id: None,
        })
    }
}

fn is_essential_icmp_error(message: &IcmpMessage) -> bool {
    if is_ipv6_icmp(message) {
        matches!(message.icmp_type, 1..=4)
    } else {
        matches!(message.icmp_type, 3 | 11 | 12)
    }
}

fn is_icmp_echo_request(message: &IcmpMessage) -> bool {
    message.icmp_code == 0
        && if is_ipv6_icmp(message) {
            message.icmp_type == 128
        } else {
            message.icmp_type == 8
        }
}

fn is_ipv6_icmp(message: &IcmpMessage) -> bool {
    message.source.ip.is_ipv6() || message.destination.ip.is_ipv6()
}

fn is_multicast_or_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_multicast() || addr.octets() == [255, 255, 255, 255],
        IpAddr::V6(addr) => addr.is_multicast(),
    }
}

/// Decision and audit record produced from one policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub audit: AuditRecord,
}

/// Audit event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuditKind {
    TcpConnect,
    UdpFlow,
    UdpFlowExpired,
    DnsQuery,
    HttpRequest,
    HttpsConnect,
    TlsClientHello,
    SocksConnect,
    IcmpMessage,
    UnsupportedNetworkEvent,
}

/// Decision represented in audit output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuditDecision {
    Allowed,
    Denied,
    FailClosed,
    Observed,
}

/// Structured audit record emitted by the policy boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub timestamp: SystemTime,
    pub kind: AuditKind,
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub protocol: Protocol,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub hostname: Option<String>,
    pub hostname_confidence: Option<AttributionConfidence>,
    pub http_method: Option<String>,
    pub http_scheme: Option<String>,
    pub http_path_query: Option<String>,
    pub decision: AuditDecision,
    pub denial_behavior: Option<DenialBehavior>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub byte_count: Option<u64>,
}

impl AuditRecord {
    pub fn from_decision(event: &NormalizedEvent, decision: &PolicyDecision) -> Self {
        let (audit_decision, denial_behavior, rule_id, reason) = match decision {
            PolicyDecision::Allow { rule_id } => {
                (AuditDecision::Allowed, None, rule_id.clone(), None)
            }
            PolicyDecision::Deny {
                behavior,
                reason,
                rule_id,
            } => (
                AuditDecision::Denied,
                Some(*behavior),
                rule_id.clone(),
                Some(reason.clone()),
            ),
            PolicyDecision::FailClosed { reason } => {
                (AuditDecision::FailClosed, None, None, Some(reason.clone()))
            }
        };

        Self {
            timestamp: SystemTime::now(),
            kind: AuditKind::from(event),
            sandbox_id: event.sandbox_id().clone(),
            frontend: event.frontend(),
            protocol: event.protocol(),
            source: event.source(),
            destination: event.destination(),
            hostname: event.hostname().map(ToOwned::to_owned),
            hostname_confidence: event.attribution_confidence(),
            http_method: event.http_method().map(ToOwned::to_owned),
            http_scheme: event.http_scheme().map(ToOwned::to_owned),
            http_path_query: event.http_path_query().map(ToOwned::to_owned),
            decision: audit_decision,
            denial_behavior,
            rule_id,
            reason,
            byte_count: None,
        }
    }
}

impl From<&NormalizedEvent> for AuditKind {
    fn from(value: &NormalizedEvent) -> Self {
        match value {
            NormalizedEvent::TcpConnectAttempt(_) => Self::TcpConnect,
            NormalizedEvent::UdpFlowAttempt(_) => Self::UdpFlow,
            NormalizedEvent::DnsQuery(_) => Self::DnsQuery,
            NormalizedEvent::HttpRequest(_) => Self::HttpRequest,
            NormalizedEvent::HttpsConnect(_) => Self::HttpsConnect,
            NormalizedEvent::TlsClientHello(_) => Self::TlsClientHello,
            NormalizedEvent::SocksConnect(_) => Self::SocksConnect,
            NormalizedEvent::IcmpMessage(_) => Self::IcmpMessage,
            NormalizedEvent::Unsupported(_) => Self::UnsupportedNetworkEvent,
        }
    }
}

fn normalize_hostname(value: impl Into<String>) -> String {
    value
        .into()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sandbox_id() -> SandboxId {
        SandboxId::new("alpha-test").expect("valid sandbox id")
    }

    fn tcp_event(destination: Ipv4Addr, port: u16) -> NormalizedEvent {
        NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152),
            destination: Endpoint::tcp(destination.into(), port),
            attribution: None,
        })
    }

    #[test]
    fn exposes_core_crate_marker() {
        assert_eq!(CRATE_NAME, "foxprox-core");
    }

    #[test]
    fn default_policy_denies_tcp_and_emits_structured_audit() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let event = tcp_event(Ipv4Addr::new(198, 51, 100, 10), 80);

        let evaluation = engine.evaluate(&event);

        assert_eq!(
            evaluation.decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );
        assert_eq!(evaluation.audit.kind, AuditKind::TcpConnect);
        assert_eq!(evaluation.audit.frontend, FrontendKind::Tun);
        assert_eq!(evaluation.audit.protocol, Protocol::Tcp);
        assert_eq!(evaluation.audit.decision, AuditDecision::Denied);
        assert_eq!(evaluation.audit.reason.as_deref(), Some("default-deny"));
        assert_eq!(
            evaluation.audit.destination,
            Some(Endpoint::tcp(Ipv4Addr::new(198, 51, 100, 10).into(), 80))
        );
    }

    #[test]
    fn ip_port_allow_rule_permits_matching_tcp_flow() {
        let cidr = IpCidr::new(Ipv4Addr::new(203, 0, 113, 0).into(), 24).unwrap();
        let rule = PolicyRule::new("allow-doc-http", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Tcp)
            .with_destination_cidr(cidr)
            .with_destination_port(80);
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let event = tcp_event(Ipv4Addr::new(203, 0, 113, 7), 80);

        let evaluation = engine.evaluate(&event);

        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-doc-http".to_owned())
            }
        );
        assert_eq!(evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(evaluation.audit.rule_id.as_deref(), Some("allow-doc-http"));
    }

    #[test]
    fn domain_rule_requires_sufficient_hostname_attribution() {
        let rule = PolicyRule::new("allow-example", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Tcp)
            .with_hostname(HostnamePattern::new(".example.com").unwrap())
            .with_destination_port(443);
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let low_confidence = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152),
            destination: Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            attribution: Some(HostnameAttribution::new(
                "www.example.com",
                AttributionSource::IpOnly,
                AttributionConfidence::Low,
            )),
        });
        let medium_confidence = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152),
            destination: Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            attribution: Some(HostnameAttribution::new(
                "WWW.EXAMPLE.COM.",
                AttributionSource::DnsCache,
                AttributionConfidence::Medium,
            )),
        });

        assert_eq!(
            engine.evaluate(&low_confidence).decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );
        assert_eq!(
            engine.evaluate(&medium_confidence).decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-example".to_owned())
            }
        );
    }

    #[test]
    fn direct_external_dns_bypass_is_denied_before_default_allow() {
        let broker_resolver = Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53);
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            dns: DnsPolicy {
                broker_resolvers: vec![broker_resolver],
                deny_direct_external_dns: true,
            },
            icmp: IcmpPolicy::default(),
            rules: Vec::new(),
        });
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::udp(Ipv4Addr::new(10, 0, 0, 2).into(), 50000),
            destination: Endpoint::udp(Ipv4Addr::new(8, 8, 8, 8).into(), 53),
            classification: UdpClassification::Dns,
            attribution: None,
        });

        let evaluation = engine.evaluate(&event);

        assert_eq!(
            evaluation.decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "direct-external-dns-denied".to_owned(),
                rule_id: None,
            }
        );
        assert_eq!(evaluation.audit.kind, AuditKind::UdpFlow);
        assert_eq!(evaluation.audit.protocol, Protocol::Dns);
    }

    #[test]
    fn broker_dns_resolver_can_be_allowed_by_default_policy() {
        let broker_resolver = Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53);
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            dns: DnsPolicy {
                broker_resolvers: vec![broker_resolver],
                deny_direct_external_dns: true,
            },
            icmp: IcmpPolicy::default(),
            rules: Vec::new(),
        });
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::udp(Ipv4Addr::new(10, 0, 0, 2).into(), 50000),
            destination: broker_resolver,
            classification: UdpClassification::Dns,
            attribution: None,
        });

        assert_eq!(
            engine.evaluate(&event).decision,
            PolicyDecision::Allow { rule_id: None }
        );
    }

    #[test]
    fn icmp_defaults_allow_essential_errors_but_not_echo_or_unusual_types() {
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        });
        let destination_unreachable = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), None),
            destination: Endpoint::new(Ipv4Addr::new(203, 0, 113, 10).into(), None),
            icmp_type: 3,
            icmp_code: 0,
        });
        let echo = NormalizedEvent::IcmpMessage(IcmpMessage {
            icmp_type: 8,
            icmp_code: 0,
            ..match destination_unreachable.clone() {
                NormalizedEvent::IcmpMessage(event) => event,
                _ => unreachable!(),
            }
        });
        let timestamp = NormalizedEvent::IcmpMessage(IcmpMessage {
            icmp_type: 13,
            icmp_code: 0,
            ..match destination_unreachable.clone() {
                NormalizedEvent::IcmpMessage(event) => event,
                _ => unreachable!(),
            }
        });

        assert_eq!(
            engine.evaluate(&destination_unreachable).decision,
            PolicyDecision::Allow { rule_id: None }
        );
        for event in [echo, timestamp] {
            assert_eq!(
                engine.evaluate(&event).decision,
                PolicyDecision::Deny {
                    behavior: DenialBehavior::Drop,
                    reason: "icmp-default-deny".to_owned(),
                    rule_id: None,
                }
            );
        }
    }

    #[test]
    fn configured_icmp_echo_allows_ping_without_broad_icmp_allow() {
        let engine = PolicyEngine::new(PolicyConfig {
            icmp: IcmpPolicy {
                allow_echo: true,
                allow_essential_errors: true,
            },
            ..PolicyConfig::default()
        });
        let echo = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), None),
            destination: Endpoint::new(Ipv4Addr::new(203, 0, 113, 10).into(), None),
            icmp_type: 8,
            icmp_code: 0,
        });

        assert_eq!(
            engine.evaluate(&echo).decision,
            PolicyDecision::Allow { rule_id: None }
        );
    }

    #[test]
    fn icmpv6_defaults_allow_essential_errors_but_not_echo_or_neighbor_discovery() {
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        });
        let destination_unreachable = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(Ipv6Addr::LOCALHOST.into(), None),
            destination: Endpoint::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), None),
            icmp_type: 1,
            icmp_code: 0,
        });
        let packet_too_big = NormalizedEvent::IcmpMessage(IcmpMessage {
            icmp_type: 2,
            icmp_code: 0,
            ..match destination_unreachable.clone() {
                NormalizedEvent::IcmpMessage(event) => event,
                _ => unreachable!(),
            }
        });
        let echo = NormalizedEvent::IcmpMessage(IcmpMessage {
            icmp_type: 128,
            icmp_code: 0,
            ..match destination_unreachable.clone() {
                NormalizedEvent::IcmpMessage(event) => event,
                _ => unreachable!(),
            }
        });
        let neighbor_solicitation = NormalizedEvent::IcmpMessage(IcmpMessage {
            icmp_type: 135,
            icmp_code: 0,
            ..match destination_unreachable.clone() {
                NormalizedEvent::IcmpMessage(event) => event,
                _ => unreachable!(),
            }
        });

        for event in [destination_unreachable, packet_too_big] {
            assert_eq!(
                engine.evaluate(&event).decision,
                PolicyDecision::Allow { rule_id: None }
            );
        }
        for event in [echo, neighbor_solicitation] {
            assert_eq!(
                engine.evaluate(&event).decision,
                PolicyDecision::Deny {
                    behavior: DenialBehavior::Drop,
                    reason: "icmp-default-deny".to_owned(),
                    rule_id: None,
                }
            );
        }
    }

    #[test]
    fn configured_icmp_echo_allows_icmpv6_echo_request() {
        let engine = PolicyEngine::new(PolicyConfig {
            icmp: IcmpPolicy {
                allow_echo: true,
                allow_essential_errors: true,
            },
            ..PolicyConfig::default()
        });
        let echo = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(Ipv6Addr::LOCALHOST.into(), None),
            destination: Endpoint::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), None),
            icmp_type: 128,
            icmp_code: 0,
        });

        assert_eq!(
            engine.evaluate(&echo).decision,
            PolicyDecision::Allow { rule_id: None }
        );
    }

    #[test]
    fn udp_multicast_and_broadcast_are_denied_before_default_allow() {
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            dns: DnsPolicy {
                broker_resolvers: vec![Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53)],
                deny_direct_external_dns: true,
            },
            icmp: IcmpPolicy::default(),
            rules: Vec::new(),
        });
        let multicast = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::udp(Ipv4Addr::new(10, 0, 0, 2).into(), 53530),
            destination: Endpoint::udp(Ipv4Addr::new(224, 0, 0, 251).into(), 5353),
            classification: UdpClassification::Generic,
            attribution: None,
        });
        let broadcast = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            destination: Endpoint::udp(Ipv4Addr::new(255, 255, 255, 255).into(), 1900),
            ..match multicast.clone() {
                NormalizedEvent::UdpFlowAttempt(event) => event,
                _ => unreachable!(),
            }
        });

        for event in [multicast, broadcast] {
            assert_eq!(
                engine.evaluate(&event).decision,
                PolicyDecision::Deny {
                    behavior: DenialBehavior::Drop,
                    reason: "udp-multicast-broadcast-denied".to_owned(),
                    rule_id: None,
                }
            );
        }
    }

    #[test]
    fn explicit_rule_can_allow_udp_multicast_destination() {
        let rule = PolicyRule::new("allow-mdns", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Udp)
            .with_destination_cidr(IpCidr::single(Ipv4Addr::new(224, 0, 0, 251).into()))
            .with_destination_port(5353);
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::udp(Ipv4Addr::new(10, 0, 0, 2).into(), 53530),
            destination: Endpoint::udp(Ipv4Addr::new(224, 0, 0, 251).into(), 5353),
            classification: UdpClassification::Generic,
            attribution: None,
        });

        assert_eq!(
            engine.evaluate(&event).decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-mdns".to_owned())
            }
        );
    }

    #[test]
    fn unsupported_event_fails_closed_and_is_audited() {
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: None,
            reason: "ipv4-fragmentation-not-supported".to_owned(),
        });

        let evaluation = engine.evaluate(&event);

        assert_eq!(
            evaluation.decision,
            PolicyDecision::FailClosed {
                reason: "unsupported-network-event: ipv4-fragmentation-not-supported".to_owned()
            }
        );
        assert_eq!(evaluation.audit.kind, AuditKind::UnsupportedNetworkEvent);
        assert_eq!(evaluation.audit.decision, AuditDecision::FailClosed);
    }

    #[test]
    fn tls_sni_dns_mismatch_denies_before_allow_rules() {
        let rule = PolicyRule::new("allow-all-tls", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::TlsClientHello);
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::TlsClientHello(TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)),
            destination: Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            sni: Some("evil.example".to_owned()),
            dns_attribution: Some(HostnameAttribution::new(
                "example.com",
                AttributionSource::DnsCache,
                AttributionConfidence::Medium,
            )),
            mismatch: SniDnsMismatch::Mismatch,
        });

        assert_eq!(
            engine.evaluate(&event).decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Reset,
                reason: "tls-sni-dns-mismatch".to_owned(),
                rule_id: None,
            }
        );
    }

    #[test]
    fn http_rule_matches_method_host_port_and_path_prefix() {
        let rule = PolicyRule::new("allow-http-api", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Http)
            .with_hostname(HostnamePattern::new("example.com").unwrap())
            .with_destination_port(80)
            .with_http_method("GET")
            .with_http_path_prefix("/api/");
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let allowed = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)),
            destination: Some(Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 80)),
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.com".to_owned(),
            port: 80,
            path_query: "/api/items?limit=1".to_owned(),
        });
        let wrong_path = NormalizedEvent::HttpRequest(HttpRequest {
            path_query: "/admin".to_owned(),
            ..match allowed.clone() {
                NormalizedEvent::HttpRequest(event) => event,
                _ => unreachable!(),
            }
        });

        let evaluation = engine.evaluate(&allowed);

        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-http-api".to_owned())
            }
        );
        assert_eq!(evaluation.audit.kind, AuditKind::HttpRequest);
        assert_eq!(evaluation.audit.http_method.as_deref(), Some("GET"));
        assert_eq!(
            evaluation.audit.http_path_query.as_deref(),
            Some("/api/items?limit=1")
        );
        assert_eq!(
            engine.evaluate(&wrong_path).decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );
    }

    #[test]
    fn cidr_matching_supports_ipv6() {
        let cidr = IpCidr::new(Ipv6Addr::LOCALHOST.into(), 128).unwrap();

        assert!(cidr.contains(Ipv6Addr::LOCALHOST.into()));
        assert!(!cidr.contains(Ipv6Addr::UNSPECIFIED.into()));
    }
}
