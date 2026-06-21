use crate::types::{
    AttributionConfidence, AttributionSource, Decision, DecisionAction, DecisionReason, Endpoint,
    FrontendKind, Hostname, HostnameAttribution, HttpRequestMetadata, Protocol, QuicStatus,
    SandboxId, SniStatus,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub default_action: DecisionAction,
    pub broker_dns: Vec<IpAddr>,
    pub rules: RuleSet,
    pub allow_ping: bool,
    pub quic_enabled: bool,
    pub require_hostname_for_domain_rules: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: DecisionAction::DenyDrop,
            broker_dns: Vec::new(),
            rules: RuleSet::default(),
            allow_ping: false,
            quic_enabled: true,
            require_hostname_for_domain_rules: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<PolicyRule>,
}

impl RuleSet {
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    pub fn push(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    pub fn iter(&self) -> impl Iterator<Item = &PolicyRule> {
        self.rules.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub action: DecisionAction,
    pub protocol: Option<Protocol>,
    pub frontend: Option<FrontendKind>,
    pub destination_ip: Option<IpMatcher>,
    pub destination_port: Option<PortMatcher>,
    pub hostname: Option<Hostname>,
    pub domain_suffix: Option<Hostname>,
    pub minimum_confidence: Option<AttributionConfidence>,
    pub http_method: Option<String>,
    pub http_path_prefix: Option<String>,
    pub quic_status: Option<QuicStatus>,
    pub timeout_override: Option<Duration>,
}

impl PolicyRule {
    pub fn new(id: impl Into<String>, action: DecisionAction) -> Self {
        Self {
            id: id.into(),
            action,
            protocol: None,
            frontend: None,
            destination_ip: None,
            destination_port: None,
            hostname: None,
            domain_suffix: None,
            minimum_confidence: None,
            http_method: None,
            http_path_prefix: None,
            quic_status: None,
            timeout_override: None,
        }
    }

    pub fn allow(id: impl Into<String>) -> Self {
        Self::new(id, DecisionAction::Allow)
    }

    pub fn deny_drop(id: impl Into<String>) -> Self {
        Self::new(id, DecisionAction::DenyDrop)
    }

    fn matches(&self, input: &PolicyInput) -> bool {
        if self
            .protocol
            .is_some_and(|protocol| protocol != input.protocol)
        {
            return false;
        }
        if self
            .frontend
            .is_some_and(|frontend| frontend != input.frontend)
        {
            return false;
        }
        if let Some(matcher) = &self.destination_ip {
            let Some(destination) = &input.destination else {
                return false;
            };
            if !matcher.matches(destination.ip) {
                return false;
            }
        }
        if let Some(matcher) = &self.destination_port {
            let Some(destination) = &input.destination else {
                return false;
            };
            if !matcher.matches(destination.port) {
                return false;
            }
        }
        if let Some(expected) = &self.hostname {
            let Some(attribution) = &input.hostname else {
                return false;
            };
            if &attribution.hostname != expected {
                return false;
            }
        }
        if let Some(suffix) = &self.domain_suffix {
            let Some(attribution) = &input.hostname else {
                return false;
            };
            if !attribution.hostname.matches_domain_suffix(suffix) {
                return false;
            }
        }
        if let Some(minimum_confidence) = self.minimum_confidence {
            let Some(attribution) = &input.hostname else {
                return false;
            };
            if attribution.confidence < minimum_confidence {
                return false;
            }
        }
        if let Some(method) = &self.http_method {
            let Some(http) = &input.http else {
                return false;
            };
            if !http.method.eq_ignore_ascii_case(method) {
                return false;
            }
        }
        if let Some(prefix) = &self.http_path_prefix {
            let Some(http) = &input.http else {
                return false;
            };
            if !http.path_query.starts_with(prefix) {
                return false;
            }
        }
        if self
            .quic_status
            .is_some_and(|status| status != input.quic_status)
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpMatcher {
    Exact(IpAddr),
    Cidr(IpCidr),
}

impl IpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Exact(expected) => *expected == ip,
            Self::Cidr(cidr) => cidr.contains(ip),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, CidrError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(CidrError::PrefixTooLong { prefix_len, max });
        }
        Ok(Self {
            network: mask_ip(network, prefix_len),
            prefix_len,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
            (network, ip) => mask_ip(ip, self.prefix_len) == network,
        }
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CidrError {
    PrefixTooLong { prefix_len: u8, max: u8 },
}

fn mask_ip(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(mask_bits(u32::from(ip), prefix_len))),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(mask_bits(u128::from(ip), prefix_len))),
    }
}

fn mask_bits<T>(value: T, prefix_len: u8) -> T
where
    T: From<u8>
        + Copy
        + std::ops::Not<Output = T>
        + std::ops::Shl<u8, Output = T>
        + std::ops::BitAnd<Output = T>,
{
    let zero = T::from(0);
    if prefix_len == 0 {
        zero
    } else {
        let width = (std::mem::size_of::<T>() * 8) as u8;
        value & (!zero << (width - prefix_len))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortMatcher {
    Exact(u16),
    Range { start: u16, end: u16 },
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Exact(expected) => *expected == port,
            Self::Range { start, end } => (*start..=*end).contains(&port),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyInput {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub protocol: Protocol,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub hostname: Option<HostnameAttribution>,
    pub http: Option<HttpRequestMetadata>,
    pub sni_status: SniStatus,
    pub sni_dns_mismatch: bool,
    pub quic_status: QuicStatus,
    pub malformed: bool,
    pub unsupported: bool,
    pub unsupported_fragmentation: bool,
}

impl PolicyInput {
    pub fn new(sandbox_id: SandboxId, frontend: FrontendKind, protocol: Protocol) -> Self {
        Self {
            sandbox_id,
            frontend,
            protocol,
            source: None,
            destination: None,
            hostname: None,
            http: None,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
            quic_status: QuicStatus::NotQuic,
            malformed: false,
            unsupported: false,
            unsupported_fragmentation: false,
        }
    }

    pub fn with_endpoints(mut self, source: Endpoint, destination: Endpoint) -> Self {
        self.source = Some(source);
        self.destination = Some(destination);
        self
    }

    pub fn with_hostname(mut self, hostname: HostnameAttribution) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn with_http(mut self, http: HttpRequestMetadata) -> Self {
        self.hostname = Some(HostnameAttribution::new(
            http.host.clone(),
            AttributionSource::HttpHost,
            AttributionConfidence::High,
        ));
        self.http = Some(http);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn evaluate(&self, input: &PolicyInput) -> Decision {
        if input.malformed {
            return Decision::denied(DecisionAction::FailClosed, DecisionReason::MalformedInput);
        }
        if input.unsupported || matches!(input.protocol, Protocol::Unsupported(_)) {
            return Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::UnsupportedProtocol,
            );
        }
        if input.unsupported_fragmentation {
            return Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::UnsupportedFragmentation,
            );
        }
        if let Some(destination) = &input.destination {
            if destination.is_multicast_or_broadcast() {
                return Decision::denied(
                    DecisionAction::FailClosed,
                    DecisionReason::MulticastOrBroadcast,
                );
            }
            if input.protocol == Protocol::Dns && !self.config.broker_dns.contains(&destination.ip)
            {
                return Decision::denied(
                    DecisionAction::RequireBrokerDns,
                    DecisionReason::DirectDnsBypass,
                );
            }
            if destination.is_tls_dns_port() {
                return Decision::denied(
                    DecisionAction::FailClosed,
                    DecisionReason::DirectDnsBypass,
                );
            }
        }
        if input.sni_dns_mismatch {
            return Decision::denied(DecisionAction::FailClosed, DecisionReason::SniDnsMismatch);
        }
        if input.sni_status == SniStatus::HiddenOrEncrypted {
            return Decision::denied(DecisionAction::FailClosed, DecisionReason::HiddenSniOrEch);
        }
        if input.quic_status != QuicStatus::NotQuic && !self.config.quic_enabled {
            return Decision::denied(DecisionAction::DenyDrop, DecisionReason::QuicDisabled);
        }
        if input.protocol == Protocol::Icmp && self.config.allow_ping {
            return Decision {
                action: DecisionAction::Allow,
                reason: DecisionReason::DefaultAllow,
                rule_id: None,
                timeout_override: None,
            };
        }

        for rule in self.config.rules.iter() {
            if rule.matches(input) {
                let reason = if rule.action == DecisionAction::Allow {
                    DecisionReason::RuleAllowed
                } else {
                    DecisionReason::RuleDenied
                };
                let mut decision = Decision {
                    action: rule.action,
                    reason,
                    rule_id: Some(rule.id.clone()),
                    timeout_override: None,
                };
                if let Some(timeout) = rule.timeout_override {
                    decision = decision.with_timeout(timeout);
                }
                return decision;
            }
        }

        match self.config.default_action {
            DecisionAction::Allow => Decision {
                action: DecisionAction::Allow,
                reason: DecisionReason::DefaultAllow,
                rule_id: None,
                timeout_override: None,
            },
            action => Decision::denied(action, DecisionReason::DefaultDeny),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn sandbox() -> SandboxId {
        SandboxId::new("test").unwrap()
    }

    #[test]
    fn default_policy_denies() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let decision = engine.evaluate(&PolicyInput::new(
            sandbox(),
            FrontendKind::Tun,
            Protocol::Tcp,
        ));
        assert_eq!(decision.action, DecisionAction::DenyDrop);
        assert_eq!(decision.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn ping_can_be_enabled_by_default_config() {
        let input = PolicyInput::new(
            SandboxId::new("policy-test").unwrap(),
            FrontendKind::Tun,
            Protocol::Icmp,
        );
        let denied = PolicyEngine::new(PolicyConfig::default()).evaluate(&input);
        assert_eq!(denied.action, DecisionAction::DenyDrop);

        let allowed = PolicyEngine::new(PolicyConfig {
            allow_ping: true,
            ..PolicyConfig::default()
        })
        .evaluate(&input);
        assert_eq!(allowed.action, DecisionAction::Allow);
        assert_eq!(allowed.reason, DecisionReason::DefaultAllow);
    }

    #[test]
    fn direct_dns_to_non_broker_requires_broker_dns() {
        let engine = PolicyEngine::new(PolicyConfig {
            broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            ..PolicyConfig::default()
        });
        let input = PolicyInput::new(sandbox(), FrontendKind::Tun, Protocol::Dns).with_endpoints(
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000),
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        );
        let decision = engine.evaluate(&input);
        assert_eq!(decision.action, DecisionAction::RequireBrokerDns);
        assert_eq!(decision.reason, DecisionReason::DirectDnsBypass);
    }

    #[test]
    fn domain_rule_requires_matching_attribution() {
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-example");
        rule.protocol = Some(Protocol::Tcp);
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::Medium);
        rules.push(rule);
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        });
        let input = PolicyInput::new(sandbox(), FrontendKind::Tun, Protocol::Tcp).with_hostname(
            HostnameAttribution::broker_dns(Hostname::normalize("www.example.com").unwrap()),
        );
        let decision = engine.evaluate(&input);
        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("allow-example"));
    }

    #[test]
    fn malformed_input_fails_closed_before_allow_rule() {
        let mut rules = RuleSet::default();
        rules.push(PolicyRule::allow("allow-all"));
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        });
        let mut input = PolicyInput::new(sandbox(), FrontendKind::Tun, Protocol::Tcp);
        input.malformed = true;
        let decision = engine.evaluate(&input);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, DecisionReason::MalformedInput);
    }

    #[test]
    fn cidr_matches_only_inside_network() {
        let cidr = IpCidr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)), 24).unwrap();
        assert_eq!(cidr.network(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
    }
}
