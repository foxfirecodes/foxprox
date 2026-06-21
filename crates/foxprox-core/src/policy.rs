use std::net::IpAddr;

use crate::attribution::{HostAttribution, Hostname};
use crate::config::{DestinationMatcher, PolicyConfig, PolicyRule, RuleAction};
use crate::types::{Endpoint, Frontend, IcmpMessage, Protocol, SandboxId};

/// Exhaustive policy outcome. Callers must handle allow, denial, and fail-closed
/// decisions distinctly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow {
        rule_id: Option<String>,
    },
    Deny {
        behavior: DenyBehavior,
        reason: DenialReason,
        rule_id: Option<String>,
    },
    FailClosed {
        reason: DenialReason,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    pub fn reason(&self) -> Option<DenialReason> {
        match self {
            Decision::Allow { .. } => None,
            Decision::Deny { reason, .. } | Decision::FailClosed { reason } => Some(*reason),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DenyBehavior {
    Drop,
    Reset,
    IcmpUnreachable,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DenialReason {
    DefaultDeny,
    RuleDeny,
    MalformedInput,
    UnsupportedProtocol,
    DirectDnsBypass,
    MulticastOrBroadcast,
    AttributionRequired,
    AttributionMismatch,
    HiddenSni,
    IcmpTypeDenied,
    InvalidConfig,
}

/// Normalized policy input shared by transparent and explicit frontends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRequest {
    pub sandbox_id: SandboxId,
    pub frontend: Frontend,
    pub protocol: Protocol,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub attribution: HostAttribution,
    pub dns_attribution: Option<Hostname>,
    pub presented_hostname: Option<Hostname>,
    pub icmp: Option<IcmpMessage>,
    pub malformed: bool,
    pub hidden_sni: bool,
}

impl PolicyRequest {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            sandbox_id: SandboxId::default(),
            frontend: Frontend::Tun,
            protocol,
            source: None,
            destination: None,
            attribution: HostAttribution::none(),
            dns_attribution: None,
            presented_hostname: None,
            icmp: None,
            malformed: false,
            hidden_sni: false,
        }
    }

    pub fn with_destination(mut self, destination: Endpoint) -> Self {
        self.destination = Some(destination);
        self
    }

    pub fn with_attribution(mut self, attribution: HostAttribution) -> Self {
        self.attribution = attribution;
        self
    }

    pub fn with_dns_attribution(mut self, hostname: Hostname) -> Self {
        self.dns_attribution = Some(hostname);
        self
    }

    pub fn with_presented_hostname(mut self, hostname: Hostname) -> Self {
        self.presented_hostname = Some(hostname);
        self
    }

    pub fn malformed(protocol: Protocol) -> Self {
        Self {
            malformed: true,
            ..Self::new(protocol)
        }
    }
}

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn decide(config: &PolicyConfig, request: &PolicyRequest) -> Decision {
        if config.validate().is_err() {
            return Decision::FailClosed {
                reason: DenialReason::InvalidConfig,
            };
        }

        if request.malformed {
            return Decision::FailClosed {
                reason: DenialReason::MalformedInput,
            };
        }

        if matches!(request.protocol, Protocol::Unsupported(_)) {
            return Decision::FailClosed {
                reason: DenialReason::UnsupportedProtocol,
            };
        }

        if is_multicast_or_broadcast(request.destination) && !config.allow_multicast_broadcast {
            return Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::MulticastOrBroadcast,
                rule_id: None,
            };
        }

        if is_direct_dns_bypass(config, request) {
            return Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::DirectDnsBypass,
                rule_id: None,
            };
        }

        if let Some(decision) = decide_icmp(config, request) {
            return decision;
        }

        if config.deny_attribution_mismatch && has_attribution_mismatch(request) {
            return Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::AttributionMismatch,
                rule_id: None,
            };
        }

        if let Some(decision) = decide_hidden_sni(config, request) {
            return decision;
        }

        if let Some(decision) = first_matching_rule(config, request) {
            return decision;
        }

        if matches!(request.protocol, Protocol::QuicCandidate) {
            return action_to_decision(config.quic_default, None, DenialReason::DefaultDeny);
        }

        action_to_decision(config.default_action, None, DenialReason::DefaultDeny)
    }
}

fn first_matching_rule(config: &PolicyConfig, request: &PolicyRequest) -> Option<Decision> {
    config
        .rules
        .iter()
        .find(|rule| rule.matches_protocol(request.protocol) && destination_matches(rule, request))
        .map(|rule| action_to_decision(rule.action, Some(rule.id.clone()), DenialReason::RuleDeny))
}

fn destination_matches(rule: &PolicyRule, request: &PolicyRequest) -> bool {
    match &rule.destination {
        DestinationMatcher::Any => true,
        DestinationMatcher::Ip { cidr, port } => request.destination.is_some_and(|destination| {
            cidr.contains(destination.ip) && port_matches(*port, destination.port)
        }),
        DestinationMatcher::Host { host, port } => {
            request.attribution.is_sufficient_for_domain_rules()
                && request
                    .destination
                    .map_or(true, |destination| port_matches(*port, destination.port))
                && request
                    .attribution
                    .hostname
                    .as_ref()
                    .is_some_and(|hostname| host.matches(hostname))
        }
    }
}

fn port_matches(expected: Option<u16>, actual: Option<u16>) -> bool {
    expected.is_none() || expected == actual
}

fn action_to_decision(
    action: RuleAction,
    rule_id: Option<String>,
    deny_reason: DenialReason,
) -> Decision {
    match action {
        RuleAction::Allow => Decision::Allow { rule_id },
        RuleAction::Deny(behavior) => Decision::Deny {
            behavior,
            reason: deny_reason,
            rule_id,
        },
    }
}

fn is_multicast_or_broadcast(destination: Option<Endpoint>) -> bool {
    destination.is_some_and(|destination| {
        destination.is_multicast()
            || destination.is_limited_broadcast()
            || is_ipv4_subnet_broadcast(destination.ip)
    })
}

fn is_ipv4_subnet_broadcast(ip: IpAddr) -> bool {
    // Without interface prefix context, only the limited broadcast and all-ones
    // host portions in common private /24 discovery ranges can be classified
    // safely here. Interface-specific directed broadcast checks belong in the
    // device layer once route context exists.
    match ip {
        IpAddr::V4(ip) => ip.octets()[3] == 255,
        IpAddr::V6(_) => false,
    }
}

fn is_direct_dns_bypass(config: &PolicyConfig, request: &PolicyRequest) -> bool {
    if config.allow_direct_dns {
        return false;
    }

    let Some(destination) = request.destination else {
        return request.protocol == Protocol::Dns;
    };

    match (request.protocol, destination.port) {
        (Protocol::Dns, Some(53)) => !config.broker_dns_servers.contains(&destination.ip),
        (Protocol::Dns, _) => true,
        (Protocol::Tcp | Protocol::Udp, Some(53 | 853)) => {
            !config.broker_dns_servers.contains(&destination.ip)
        }
        _ => false,
    }
}

fn decide_hidden_sni(config: &PolicyConfig, request: &PolicyRequest) -> Option<Decision> {
    if !request.hidden_sni {
        return None;
    }

    for rule in &config.rules {
        if !rule.matches_protocol(request.protocol) || !destination_matches(rule, request) {
            continue;
        }

        match (&rule.action, &rule.destination) {
            (RuleAction::Deny(_), _) => {
                return Some(action_to_decision(
                    rule.action,
                    Some(rule.id.clone()),
                    DenialReason::RuleDeny,
                ));
            }
            (RuleAction::Allow, DestinationMatcher::Ip { .. }) => {
                return Some(Decision::Allow {
                    rule_id: Some(rule.id.clone()),
                });
            }
            (RuleAction::Allow, DestinationMatcher::Any | DestinationMatcher::Host { .. }) => {}
        }
    }

    Some(Decision::Deny {
        behavior: DenyBehavior::Drop,
        reason: DenialReason::HiddenSni,
        rule_id: None,
    })
}

fn decide_icmp(config: &PolicyConfig, request: &PolicyRequest) -> Option<Decision> {
    if request.protocol != Protocol::Icmp {
        return None;
    }
    let Some(icmp) = request.icmp else {
        return Some(Decision::FailClosed {
            reason: DenialReason::MalformedInput,
        });
    };
    if icmp.is_essential_error() || (config.allow_ping && icmp.is_echo_request()) {
        return Some(Decision::Allow { rule_id: None });
    }
    Some(Decision::Deny {
        behavior: DenyBehavior::Drop,
        reason: DenialReason::IcmpTypeDenied,
        rule_id: None,
    })
}

fn has_attribution_mismatch(request: &PolicyRequest) -> bool {
    match (&request.dns_attribution, &request.presented_hostname) {
        (Some(dns), Some(presented)) => dns != presented,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::attribution::{HostAttribution, Hostname};
    use crate::config::{Cidr, HostMatcher, PolicyRule};
    use crate::types::{HostnameConfidence, HostnameSource};

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    #[test]
    fn default_policy_denies_tcp_without_matching_rule() {
        let request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(Endpoint::tcp(ip([93, 184, 216, 34]), 80));

        assert_eq!(
            PolicyEngine::decide(&PolicyConfig::default(), &request),
            Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::DefaultDeny,
                rule_id: None,
            }
        );
    }

    #[test]
    fn malformed_and_unsupported_inputs_fail_closed_before_rules() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-all-v4",
            "0.0.0.0/0".parse().unwrap(),
            None,
        ));

        assert_eq!(
            PolicyEngine::decide(&config, &PolicyRequest::malformed(Protocol::Tcp)),
            Decision::FailClosed {
                reason: DenialReason::MalformedInput,
            }
        );
        assert_eq!(
            PolicyEngine::decide(&config, &PolicyRequest::new(Protocol::Unsupported(99))),
            Decision::FailClosed {
                reason: DenialReason::UnsupportedProtocol,
            }
        );
    }

    #[test]
    fn direct_dns_to_non_broker_resolver_is_denied() {
        let mut config = PolicyConfig::default();
        config.broker_dns_servers.push(ip([10, 0, 2, 3]));
        config.rules.push(PolicyRule::allow_ip(
            "allow-all-v4",
            "0.0.0.0/0".parse().unwrap(),
            None,
        ));

        for (protocol, destination) in [
            (Protocol::Dns, Endpoint::udp(ip([8, 8, 8, 8]), 53)),
            (Protocol::Udp, Endpoint::udp(ip([8, 8, 8, 8]), 53)),
            (Protocol::Tcp, Endpoint::tcp(ip([8, 8, 8, 8]), 53)),
            (Protocol::Tcp, Endpoint::tcp(ip([1, 1, 1, 1]), 853)),
        ] {
            let bypass = PolicyRequest::new(protocol).with_destination(destination);
            assert_eq!(
                PolicyEngine::decide(&config, &bypass).reason(),
                Some(DenialReason::DirectDnsBypass)
            );
        }

        let broker = PolicyRequest::new(Protocol::Dns)
            .with_destination(Endpoint::udp(ip([10, 0, 2, 3]), 53));
        assert!(PolicyEngine::decide(&config, &broker).is_allow());
    }

    #[test]
    fn multicast_and_broadcast_are_denied_before_allow_rules() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-all-v4",
            "0.0.0.0/0".parse().unwrap(),
            None,
        ));

        for addr in [
            ip([224, 0, 0, 1]),
            ip([255, 255, 255, 255]),
            ip([192, 168, 1, 255]),
        ] {
            let request =
                PolicyRequest::new(Protocol::Udp).with_destination(Endpoint::udp(addr, 1900));
            assert_eq!(
                PolicyEngine::decide(&config, &request).reason(),
                Some(DenialReason::MulticastOrBroadcast)
            );
        }
    }

    #[test]
    fn domain_rules_require_medium_or_high_confidence_attribution() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-example",
            HostMatcher::suffix("example.com").unwrap(),
            Some(443),
        ));
        let destination = Endpoint::tcp(ip([93, 184, 216, 34]), 443);
        let low = HostAttribution::new(
            Hostname::parse("www.example.com").unwrap(),
            HostnameSource::IpOnly,
            HostnameConfidence::Low,
        );
        let medium = HostAttribution::dns(Hostname::parse("www.example.com").unwrap());

        assert_eq!(
            PolicyEngine::decide(
                &config,
                &PolicyRequest::new(Protocol::Tcp)
                    .with_destination(destination)
                    .with_attribution(low)
            )
            .reason(),
            Some(DenialReason::DefaultDeny)
        );
        assert!(PolicyEngine::decide(
            &config,
            &PolicyRequest::new(Protocol::Tcp)
                .with_destination(destination)
                .with_attribution(medium)
        )
        .is_allow());
    }

    #[test]
    fn attribution_mismatch_is_denied_even_when_ip_rule_would_allow() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-ip",
            Cidr::host(ip([93, 184, 216, 34])),
            Some(443),
        ));
        let request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(Endpoint::tcp(ip([93, 184, 216, 34]), 443))
            .with_dns_attribution(Hostname::parse("example.com").unwrap())
            .with_presented_hostname(Hostname::parse("evil.example").unwrap());

        assert_eq!(
            PolicyEngine::decide(&config, &request).reason(),
            Some(DenialReason::AttributionMismatch)
        );
    }

    #[test]
    fn hidden_sni_is_denied_unless_explicit_ip_rule_matches() {
        let destination = Endpoint::tcp(ip([93, 184, 216, 34]), 443);
        let hidden = PolicyRequest {
            hidden_sni: true,
            destination: Some(destination),
            ..PolicyRequest::new(Protocol::Tcp)
        };

        assert_eq!(
            PolicyEngine::decide(&PolicyConfig::default(), &hidden).reason(),
            Some(DenialReason::HiddenSni)
        );

        let mut domain_config = PolicyConfig::default();
        domain_config.rules.push(PolicyRule::allow_domain(
            "domain-is-not-enough",
            HostMatcher::suffix("example.com").unwrap(),
            Some(443),
        ));
        let hidden_with_domain = PolicyRequest {
            hidden_sni: true,
            destination: Some(destination),
            attribution: HostAttribution::dns(Hostname::parse("www.example.com").unwrap()),
            ..PolicyRequest::new(Protocol::Tcp)
        };
        assert_eq!(
            PolicyEngine::decide(&domain_config, &hidden_with_domain).reason(),
            Some(DenialReason::HiddenSni)
        );

        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "explicit-ip",
            Cidr::host(ip([93, 184, 216, 34])),
            Some(443),
        ));
        assert!(PolicyEngine::decide(&config, &hidden).is_allow());
    }

    #[test]
    fn unusual_icmp_is_denied_and_ping_is_configurable() {
        let ping = PolicyRequest {
            protocol: Protocol::Icmp,
            icmp: Some(IcmpMessage::ipv4(8, 0)),
            ..PolicyRequest::new(Protocol::Icmp)
        };
        assert_eq!(
            PolicyEngine::decide(&PolicyConfig::default(), &ping).reason(),
            Some(DenialReason::IcmpTypeDenied)
        );

        let config = PolicyConfig {
            allow_ping: true,
            ..PolicyConfig::default()
        };
        assert!(PolicyEngine::decide(&config, &ping).is_allow());

        let error = PolicyRequest {
            protocol: Protocol::Icmp,
            icmp: Some(IcmpMessage::ipv4(3, 1)),
            ..PolicyRequest::new(Protocol::Icmp)
        };
        assert!(PolicyEngine::decide(&PolicyConfig::default(), &error).is_allow());
    }

    #[test]
    fn first_matching_rule_order_is_deterministic() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule {
            id: "deny-first".into(),
            action: RuleAction::Deny(DenyBehavior::Reset),
            protocol: crate::config::ProtocolMatcher::Any,
            destination: DestinationMatcher::Any,
        });
        config.rules.push(PolicyRule::allow_ip(
            "allow-second",
            "0.0.0.0/0".parse().unwrap(),
            None,
        ));
        let request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(Endpoint::tcp(ip([1, 1, 1, 1]), 443));

        assert_eq!(
            PolicyEngine::decide(&config, &request),
            Decision::Deny {
                behavior: DenyBehavior::Reset,
                reason: DenialReason::RuleDeny,
                rule_id: Some("deny-first".into()),
            }
        );
    }
}
