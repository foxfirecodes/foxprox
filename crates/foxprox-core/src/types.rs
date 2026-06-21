use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SandboxId(String);

impl SandboxId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ValidationError::EmptySandboxId);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrontendKind {
    Tun,
    HttpProxy,
    Socks5,
    Setup,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Http,
    HttpsConnect,
    Tls,
    Socks,
    Quic,
    Unsupported(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecisionAction {
    Allow,
    DenyDrop,
    DenyReset,
    DenyIcmpUnreachable,
    FailClosed,
    RequireBrokerDns,
}

impl DecisionAction {
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_denial(self) -> bool {
        !self.is_allow()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: DecisionAction,
    pub reason: DecisionReason,
    pub rule_id: Option<String>,
    pub timeout_override: Option<Duration>,
}

impl Decision {
    pub fn allow(rule_id: impl Into<Option<String>>) -> Self {
        Self {
            action: DecisionAction::Allow,
            reason: DecisionReason::RuleAllowed,
            rule_id: rule_id.into(),
            timeout_override: None,
        }
    }

    pub fn denied(action: DecisionAction, reason: DecisionReason) -> Self {
        debug_assert!(action.is_denial());
        Self {
            action,
            reason,
            rule_id: None,
            timeout_override: None,
        }
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_override = Some(timeout);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionReason {
    RuleAllowed,
    RuleDenied,
    DefaultDeny,
    DefaultAllow,
    MalformedInput,
    UnsupportedProtocol,
    UnsupportedFragmentation,
    DirectDnsBypass,
    MulticastOrBroadcast,
    HostnameAttributionRequired,
    SniDnsMismatch,
    HiddenSniOrEch,
    QuicDisabled,
    InvalidConfig,
    AuditBackpressure,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn is_dns_port(&self) -> bool {
        self.port == 53
    }

    pub fn is_tls_dns_port(&self) -> bool {
        self.port == 853
    }

    pub fn is_quic_port(&self) -> bool {
        self.port == 443
    }

    pub fn is_multicast_or_broadcast(&self) -> bool {
        match self.ip {
            IpAddr::V4(ip) => ip.is_multicast() || ip.octets() == [255, 255, 255, 255],
            IpAddr::V6(ip) => ip.is_multicast(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: Protocol,
    pub source: Endpoint,
    pub destination: Endpoint,
}

impl FlowKey {
    pub fn new(protocol: Protocol, source: Endpoint, destination: Endpoint) -> Self {
        Self {
            protocol,
            source,
            destination,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    pub fn normalize(input: &str) -> Result<Self, ValidationError> {
        let trimmed = input.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.is_empty() {
            return Err(ValidationError::EmptyHostname);
        }
        if trimmed.len() > 253 {
            return Err(ValidationError::HostnameTooLong);
        }
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(ValidationError::InvalidHostnameLabel);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ValidationError::InvalidHostnameLabel);
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(ValidationError::InvalidHostnameLabel);
            }
        }
        Ok(Self(trimmed))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches_domain_suffix(&self, suffix: &Hostname) -> bool {
        self.0 == suffix.0
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttributionConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttributionSource {
    IpOnly,
    BrokerDns,
    HttpHost,
    TlsSni,
    QuicTls,
    ExplicitProxy,
    SocksDestination,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostnameAttribution {
    pub hostname: Hostname,
    pub source: AttributionSource,
    pub confidence: AttributionConfidence,
}

impl HostnameAttribution {
    pub fn new(
        hostname: Hostname,
        source: AttributionSource,
        confidence: AttributionConfidence,
    ) -> Self {
        Self {
            hostname,
            source,
            confidence,
        }
    }

    pub fn broker_dns(hostname: Hostname) -> Self {
        Self::new(
            hostname,
            AttributionSource::BrokerDns,
            AttributionConfidence::Medium,
        )
    }

    pub fn explicit_proxy(hostname: Hostname) -> Self {
        Self::new(
            hostname,
            AttributionSource::ExplicitProxy,
            AttributionConfidence::High,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
    Socks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub scheme: Scheme,
    pub host: Hostname,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestMetadata {
    pub method: String,
    pub host: Hostname,
    pub port: u16,
    pub path_query: String,
    pub scheme: Scheme,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SniStatus {
    Present,
    Missing,
    HiddenOrEncrypted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsSniMatch {
    NotApplicable,
    Match,
    Mismatch,
    UnknownDnsAttribution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QuicStatus {
    NotQuic,
    Candidate,
    VisibleMetadata,
    UnsupportedVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    EmptySandboxId,
    EmptyHostname,
    HostnameTooLong,
    InvalidHostnameLabel,
}
