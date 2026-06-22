use std::net::IpAddr;

use crate::audit::{AttributionConfidence, Decision, Frontend, Protocol};

/// Normalized request evaluated by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub sandbox_id: String,
    pub frontend: Frontend,
    pub protocol: Protocol,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<u16>,
    pub hostname: Option<String>,
    pub attribution_confidence: AttributionConfidence,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub is_direct_dns: bool,
    pub is_multicast_or_broadcast: bool,
    pub is_malformed: bool,
    pub is_unsupported: bool,
    pub sni_dns_mismatch: bool,
    pub hidden_sni: bool,
    pub quic_candidate: bool,
}

impl PolicyRequest {
    pub fn new(sandbox_id: impl Into<String>, frontend: Frontend, protocol: Protocol) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            frontend,
            protocol,
            source_ip: None,
            source_port: None,
            destination_ip: None,
            destination_port: None,
            hostname: None,
            attribution_confidence: AttributionConfidence::None,
            http_method: None,
            http_path: None,
            is_direct_dns: false,
            is_multicast_or_broadcast: false,
            is_malformed: false,
            is_unsupported: false,
            sni_dns_mismatch: false,
            hidden_sni: false,
            quic_candidate: false,
        }
    }

    pub fn with_destination(mut self, ip: IpAddr, port: u16) -> Self {
        self.destination_ip = Some(ip);
        self.destination_port = Some(port);
        self
    }

    pub fn with_source(mut self, ip: IpAddr, port: u16) -> Self {
        self.source_ip = Some(ip);
        self.source_port = Some(port);
        self
    }

    pub fn with_hostname(
        mut self,
        hostname: impl Into<String>,
        confidence: AttributionConfidence,
    ) -> Self {
        self.hostname = Some(hostname.into().to_ascii_lowercase());
        self.attribution_confidence = confidence;
        self
    }

    pub fn with_http(mut self, method: impl Into<String>, path: impl Into<String>) -> Self {
        self.http_method = Some(method.into());
        self.http_path = Some(path.into());
        self
    }
}

/// Policy evaluation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub decision: Decision,
    pub reason: String,
    pub rule_id: Option<String>,
}

impl PolicyOutcome {
    pub fn allow(reason: impl Into<String>, rule_id: Option<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
            rule_id,
        }
    }

    pub fn deny(decision: Decision, reason: impl Into<String>, rule_id: Option<String>) -> Self {
        Self {
            decision,
            reason: reason.into(),
            rule_id,
        }
    }
}

/// Default policy posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Allow,
    Deny,
}

/// Rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    DenyDrop,
    DenyReset,
    DenyIcmpUnreachable,
}

impl RuleAction {
    fn decision(self) -> Decision {
        match self {
            Self::Allow => Decision::Allow,
            Self::DenyDrop => Decision::DenyDrop,
            Self::DenyReset => Decision::DenyReset,
            Self::DenyIcmpUnreachable => Decision::DenyIcmpUnreachable,
        }
    }
}

/// A small deterministic policy rule sufficient for the alpha harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub action: RuleAction,
    pub protocol: Option<Protocol>,
    pub destination: Option<Cidr>,
    pub port: Option<u16>,
    pub hostname: Option<String>,
    pub domain_suffix: Option<String>,
    pub http_method: Option<String>,
    pub http_path_prefix: Option<String>,
    pub require_hostname_attribution: bool,
}

impl PolicyRule {
    pub fn new(id: impl Into<String>, action: RuleAction) -> Self {
        Self {
            id: id.into(),
            action,
            protocol: None,
            destination: None,
            port: None,
            hostname: None,
            domain_suffix: None,
            http_method: None,
            http_path_prefix: None,
            require_hostname_attribution: false,
        }
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn destination(mut self, cidr: Cidr) -> Self {
        self.destination = Some(cidr);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into().to_ascii_lowercase());
        self
    }

    pub fn domain_suffix(mut self, suffix: impl Into<String>) -> Self {
        let suffix = suffix.into().trim_start_matches('.').to_ascii_lowercase();
        self.domain_suffix = Some(suffix);
        self
    }

    pub fn http_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.http_path_prefix = Some(prefix.into());
        self
    }

    pub fn require_hostname_attribution(mut self) -> Self {
        self.require_hostname_attribution = true;
        self
    }

    fn matches(&self, request: &PolicyRequest) -> bool {
        if let Some(protocol) = self.protocol {
            if request.protocol != protocol {
                return false;
            }
        }
        if let Some(destination) = &self.destination {
            let Some(ip) = request.destination_ip else {
                return false;
            };
            if !destination.contains(ip) {
                return false;
            }
        }
        if let Some(port) = self.port {
            if request.destination_port != Some(port) {
                return false;
            }
        }
        if let Some(hostname) = &self.hostname {
            if request.hostname.as_deref() != Some(hostname.as_str()) {
                return false;
            }
        }
        if let Some(suffix) = &self.domain_suffix {
            let Some(hostname) = request.hostname.as_deref() else {
                return false;
            };
            if hostname != suffix && !hostname.ends_with(&format!(".{suffix}")) {
                return false;
            }
        }
        if let Some(method) = &self.http_method {
            if request.http_method.as_deref() != Some(method.as_str()) {
                return false;
            }
        }
        if let Some(prefix) = &self.http_path_prefix {
            let Some(path) = request.http_path.as_deref() else {
                return false;
            };
            if !path.starts_with(prefix) {
                return false;
            }
        }
        if self.require_hostname_attribution
            && !has_hostname_attribution(request.attribution_confidence)
        {
            return false;
        }
        true
    }
}

/// Complete policy configuration for deterministic harness checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    pub default_action: DefaultAction,
    pub direct_dns_broker_ip: Option<IpAddr>,
    pub allow_ping: bool,
    pub allow_quic: bool,
    pub rules: Vec<PolicyRule>,
}

impl PolicyConfig {
    pub fn deny_by_default() -> Self {
        Self {
            default_action: DefaultAction::Deny,
            direct_dns_broker_ip: None,
            allow_ping: false,
            allow_quic: false,
            rules: Vec::new(),
        }
    }

    pub fn allow_by_default() -> Self {
        Self {
            default_action: DefaultAction::Allow,
            ..Self::deny_by_default()
        }
    }

    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn broker_dns(mut self, ip: IpAddr) -> Self {
        self.direct_dns_broker_ip = Some(ip);
        self
    }

    pub fn allow_quic(mut self, allow: bool) -> Self {
        self.allow_quic = allow;
        self
    }

    pub fn allow_ping(mut self, allow: bool) -> Self {
        self.allow_ping = allow;
        self
    }
}

/// Stateless deterministic policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyOutcome {
        if request.is_malformed {
            return PolicyOutcome::deny(Decision::FailClosed, "malformed input fails closed", None);
        }
        if request.is_unsupported {
            return PolicyOutcome::deny(
                Decision::FailClosed,
                "unsupported network event fails closed",
                None,
            );
        }
        if request.is_multicast_or_broadcast {
            return PolicyOutcome::deny(
                Decision::DenyDrop,
                "multicast/broadcast denied by default",
                None,
            );
        }
        if request.is_direct_dns {
            if request.destination_ip != self.config.direct_dns_broker_ip {
                return PolicyOutcome::deny(Decision::DenyDrop, "direct external DNS denied", None);
            }
        }
        if request.sni_dns_mismatch {
            return PolicyOutcome::deny(Decision::FailClosed, "SNI/DNS attribution mismatch", None);
        }
        if request.hidden_sni {
            let explicit_ip_allow = self.config.rules.iter().any(|rule| {
                rule.action == RuleAction::Allow
                    && rule.hostname.is_none()
                    && rule.domain_suffix.is_none()
                    && rule.destination.is_some()
                    && rule.matches(request)
            });
            if !explicit_ip_allow {
                return PolicyOutcome::deny(
                    Decision::FailClosed,
                    "hidden SNI requires explicit IP allow",
                    None,
                );
            }
        }
        if request.quic_candidate && !self.config.allow_quic {
            return PolicyOutcome::deny(
                Decision::DenyDrop,
                "QUIC candidate denied by configuration",
                None,
            );
        }
        if request.protocol == Protocol::Icmp && self.config.allow_ping {
            return PolicyOutcome::allow("ICMP ping allowed by configuration", None);
        }

        for rule in &self.config.rules {
            if rule.matches(request) {
                let reason = match rule.action {
                    RuleAction::Allow => "matched allow rule",
                    RuleAction::DenyDrop
                    | RuleAction::DenyReset
                    | RuleAction::DenyIcmpUnreachable => "matched deny rule",
                };
                return PolicyOutcome {
                    decision: rule.action.decision(),
                    reason: reason.to_string(),
                    rule_id: Some(rule.id.clone()),
                };
            }
        }

        match self.config.default_action {
            DefaultAction::Allow => PolicyOutcome::allow("default allow", None),
            DefaultAction::Deny => PolicyOutcome::deny(
                default_deny_decision(request.protocol),
                "default deny",
                None,
            ),
        }
    }
}

fn default_deny_decision(protocol: Protocol) -> Decision {
    match protocol {
        Protocol::Tcp
        | Protocol::Http
        | Protocol::HttpsConnect
        | Protocol::Tls
        | Protocol::Socks => Decision::DenyReset,
        Protocol::Udp | Protocol::Dns | Protocol::Quic => Decision::DenyDrop,
        Protocol::Icmp => Decision::DenyIcmpUnreachable,
        Protocol::Unsupported => Decision::FailClosed,
    }
}

fn has_hostname_attribution(confidence: AttributionConfidence) -> bool {
    matches!(
        confidence,
        AttributionConfidence::High | AttributionConfidence::Medium
    )
}

/// IP network match used by policy rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, String> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("prefix {prefix} exceeds max {max}"));
        }
        Ok(Self { network, prefix })
    }

    pub fn host(ip: IpAddr) -> Self {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self {
            network: ip,
            prefix,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let network = u32::from(network);
                let ip = u32::from(ip);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (network & mask) == (ip & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let network = u128::from(network);
                let ip = u128::from(ip);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (network & mask) == (ip & mask)
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip, prefix)) = s.split_once('/') {
            let ip = ip
                .parse::<IpAddr>()
                .map_err(|err| format!("invalid CIDR IP: {err}"))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|err| format!("invalid CIDR prefix: {err}"))?;
            Self::new(ip, prefix)
        } else {
            let ip = s
                .parse::<IpAddr>()
                .map_err(|err| format!("invalid IP: {err}"))?;
            Ok(Self::host(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn cidr_matches_ipv4_network() {
        let cidr = "10.0.0.0/24".parse::<Cidr>().unwrap();
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))));
        assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
    }

    #[test]
    fn default_deny_resets_tcp_and_drops_udp() {
        let engine = PolicyEngine::new(PolicyConfig::deny_by_default());
        let tcp = PolicyRequest::new("s", Frontend::Tun, Protocol::Tcp);
        let udp = PolicyRequest::new("s", Frontend::Tun, Protocol::Udp);
        assert_eq!(engine.evaluate(&tcp).decision, Decision::DenyReset);
        assert_eq!(engine.evaluate(&udp).decision, Decision::DenyDrop);
    }

    #[test]
    fn direct_dns_must_target_broker_resolver() {
        let broker_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
        let engine = PolicyEngine::new(PolicyConfig::deny_by_default().broker_dns(broker_ip));
        let mut req = PolicyRequest::new("s", Frontend::Tun, Protocol::Dns)
            .with_destination(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        req.is_direct_dns = true;
        assert_eq!(engine.evaluate(&req).reason, "direct external DNS denied");
    }

    #[test]
    fn domain_rule_requires_attribution_when_requested() {
        let engine = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-example", RuleAction::Allow)
                    .protocol(Protocol::Tcp)
                    .domain_suffix("example.com")
                    .port(443)
                    .require_hostname_attribution(),
            ),
        );
        let req = PolicyRequest::new("s", Frontend::Tun, Protocol::Tcp)
            .with_destination(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)
            .with_hostname("www.example.com", AttributionConfidence::Medium);
        assert_eq!(engine.evaluate(&req).decision, Decision::Allow);
    }

    #[test]
    fn hidden_sni_fails_closed_without_explicit_ip_allow() {
        let engine = PolicyEngine::new(PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-domain", RuleAction::Allow).domain_suffix("example.com"),
        ));
        let mut req = PolicyRequest::new("s", Frontend::Tun, Protocol::Tls)
            .with_destination(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)
            .with_hostname("example.com", AttributionConfidence::Medium);
        req.hidden_sni = true;
        assert_eq!(engine.evaluate(&req).decision, Decision::FailClosed);
    }
}
