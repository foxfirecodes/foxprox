//! Deterministic policy evaluation over normalized foxprox events.
//!
//! This crate deliberately depends only on `foxprox-core`. It must not import
//! frontend, Linux, bwrap, parser, network-stack, audit, or egress crates.

#![forbid(unsafe_code)]

use foxprox_core::{
    AllowDecision, DefaultPolicy, DenialAction, DenyDecision, DestinationMatcher, DirectDnsPolicy,
    HostnameConfidence, HostnameMismatch, NormalizedEvent, PolicyDecision, PolicyRule, Protocol,
    ProtocolMatcher, QuicPolicy, RuleAction, RuntimeConfig, UdpClassification,
};

/// Policy engine with a typed, normalized runtime configuration.
#[derive(Clone, Debug)]
pub struct PolicyEngine {
    config: RuntimeConfig,
}

impl PolicyEngine {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Evaluate a normalized event. Unsupported and malformed paths fail closed
    /// before configurable default allow rules are considered.
    pub fn decide(&self, event: &NormalizedEvent) -> PolicyDecision {
        if event.protocol() == Protocol::Unsupported {
            return fail_closed("unsupported network event");
        }

        if let NormalizedEvent::DnsQuery(dns) = event {
            if dns.direct_external && self.config.direct_dns_policy == DirectDnsPolicy::DenyExternal
            {
                return PolicyDecision::RequireBrokerDns {
                    reason: "direct external DNS is denied; broker resolver is required".into(),
                };
            }
        }

        if let NormalizedEvent::UdpFlowAttempt(udp) = event {
            if udp.classification == UdpClassification::MulticastOrBroadcast {
                return deny(
                    DenialAction::Drop,
                    None,
                    "multicast and broadcast UDP are denied by default",
                );
            }
            if udp.classification == UdpClassification::QuicCandidate
                && self.config.quic_policy == QuicPolicy::DenyByDefault
            {
                if let Some(decision) = self.match_configured_rule(event) {
                    return decision;
                }
                return deny(DenialAction::Drop, None, "QUIC candidate denied by default");
            }
        }

        if let NormalizedEvent::IcmpMessage(icmp) = event {
            let is_echo = icmp.icmp_type == 8 || icmp.icmp_type == 128;
            if is_echo && !self.config.allow_ping {
                return deny(DenialAction::Drop, None, "ICMP echo is disabled by policy");
            }
        }

        if let NormalizedEvent::TlsClientHello(tls) = event {
            if tls.mismatch == HostnameMismatch::Mismatch {
                return deny(
                    DenialAction::Reset,
                    None,
                    "TLS SNI does not match DNS attribution",
                );
            }
        }

        if let Some(decision) = self.match_configured_rule(event) {
            return decision;
        }

        match self.config.default_policy {
            DefaultPolicy::Allow => PolicyDecision::Allow(AllowDecision {
                rule_id: None,
                timeout_override: None,
                reason: Some("default allow policy".into()),
            }),
            DefaultPolicy::Deny => deny(DenialAction::Drop, None, "default deny policy"),
        }
    }

    fn match_configured_rule(&self, event: &NormalizedEvent) -> Option<PolicyDecision> {
        self.config
            .rules
            .iter()
            .find(|rule| rule_matches(rule, event))
            .map(|rule| match rule.action {
                RuleAction::Allow => PolicyDecision::Allow(AllowDecision {
                    rule_id: Some(rule.id.clone()),
                    timeout_override: None,
                    reason: Some("matched allow rule".into()),
                }),
                RuleAction::Deny(action) => {
                    deny(action, Some(rule.id.clone()), "matched deny rule")
                }
            })
    }
}

fn rule_matches(rule: &PolicyRule, event: &NormalizedEvent) -> bool {
    protocol_matches(rule.protocol, event.protocol())
        && destination_matches(rule, event)
        && rule.port.matches(event.destination_port())
}

fn protocol_matches(matcher: ProtocolMatcher, protocol: Protocol) -> bool {
    matches!(matcher, ProtocolMatcher::Any) || matcher == ProtocolMatcher::Exact(protocol)
}

fn destination_matches(rule: &PolicyRule, event: &NormalizedEvent) -> bool {
    match &rule.destination {
        DestinationMatcher::Any => true,
        DestinationMatcher::Ip(expected) => {
            event.destination_ip().is_some_and(|ip| ip == *expected)
        }
        DestinationMatcher::Cidr(cidr) => {
            event.destination_ip().is_some_and(|ip| cidr.contains(ip))
        }
        DestinationMatcher::Hostname(expected) => {
            hostname_matches(event, rule.minimum_hostname_confidence)
                .is_some_and(|hostname| hostname == expected)
        }
        DestinationMatcher::DomainSuffix(suffix) => {
            hostname_matches(event, rule.minimum_hostname_confidence)
                .is_some_and(|hostname| hostname.is_subdomain_of(suffix))
        }
    }
}

fn hostname_matches(
    event: &NormalizedEvent,
    minimum_confidence: HostnameConfidence,
) -> Option<&foxprox_core::Hostname> {
    if let Some(attribution) = event.hostname_attribution() {
        if attribution.confidence() >= minimum_confidence {
            return Some(attribution.hostname());
        }
        return None;
    }

    if minimum_confidence <= HostnameConfidence::High {
        match event {
            NormalizedEvent::DnsQuery(_)
            | NormalizedEvent::HttpRequest(_)
            | NormalizedEvent::HttpsConnect(_)
            | NormalizedEvent::TlsClientHello(_)
            | NormalizedEvent::SocksConnect(_) => event.explicit_hostname(),
            _ => None,
        }
    } else {
        None
    }
}

fn deny(
    action: DenialAction,
    rule_id: Option<foxprox_core::RuleId>,
    reason: &'static str,
) -> PolicyDecision {
    PolicyDecision::Deny(DenyDecision {
        action,
        rule_id,
        reason: reason.into(),
    })
}

fn fail_closed(reason: &'static str) -> PolicyDecision {
    PolicyDecision::FailClosed {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        DestinationHost, DnsQuery, DnsQueryType, DomainSuffix, FrontendKind, Hostname,
        HostnameAttribution, HostnameAttributionSource, HttpMethod, HttpRequest, HttpScheme,
        IpCidr, RuleId, SandboxId, TcpConnectAttempt, UdpFlowAttempt, UnsupportedNetworkEvent,
        UnsupportedReason,
    };

    fn sandbox() -> SandboxId {
        SandboxId::new("test-sandbox").unwrap()
    }

    #[test]
    fn direct_external_dns_requires_broker_resolver() {
        let event = NormalizedEvent::DnsQuery(DnsQuery {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:40000".parse().unwrap(),
            destination: "8.8.8.8:53".parse().unwrap(),
            hostname: Hostname::new("example.com").unwrap(),
            query_type: DnsQueryType::A,
            direct_external: true,
        });

        let decision = PolicyEngine::new(RuntimeConfig::deny_by_default()).decide(&event);
        assert!(matches!(decision, PolicyDecision::RequireBrokerDns { .. }));
    }

    #[test]
    fn unsupported_events_fail_closed_even_when_default_allows() {
        let event = NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            reason: UnsupportedReason::UnsupportedIpProtocol(99),
            safe_metadata: None,
        });

        let decision = PolicyEngine::new(RuntimeConfig::allow_by_default()).decide(&event);
        assert!(matches!(decision, PolicyDecision::FailClosed { .. }));
    }

    #[test]
    fn policy_allows_tcp_by_cidr_without_frontend_specific_data() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("allow-doc-net").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.destination = DestinationMatcher::Cidr("203.0.113.0/24".parse::<IpCidr>().unwrap());
        rule.port = foxprox_core::PortMatcher::Exact(443);
        config.rules.push(rule);

        let event = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: None,
        });

        let decision = PolicyEngine::new(config).decide(&event);
        assert!(decision.is_allowed());
    }

    #[test]
    fn domain_rule_requires_configured_attribution_confidence() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("domain").unwrap());
        rule.destination =
            DestinationMatcher::DomainSuffix(DomainSuffix::new("example.com").unwrap());
        rule.minimum_hostname_confidence = HostnameConfidence::Medium;
        config.rules.push(rule);

        let event = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: Some(HostnameAttribution::new(
                Hostname::new("www.example.com").unwrap(),
                HostnameAttributionSource::BrokerDns,
                HostnameConfidence::Medium,
            )),
        });

        assert!(PolicyEngine::new(config).decide(&event).is_allowed());
    }

    #[test]
    fn transparent_http_can_use_host_method_path_without_raw_parser_type() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("http-domain").unwrap());
        rule.destination =
            DestinationMatcher::DomainSuffix(DomainSuffix::new("example.com").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Http);
        config.rules.push(rule);

        let event = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            method: HttpMethod::Get,
            scheme: HttpScheme::Http,
            host: Hostname::new("www.example.com").unwrap(),
            port: 80,
            path_query: "/index.html".to_string(),
        });

        assert!(PolicyEngine::new(config).decide(&event).is_allowed());
    }

    #[test]
    fn explicit_proxy_destination_is_normalized() {
        let event = NormalizedEvent::HttpsConnect(foxprox_core::HttpsConnect {
            sandbox_id: sandbox(),
            frontend: FrontendKind::HttpProxy,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 443,
        });

        assert_eq!(event.protocol(), Protocol::HttpsConnect);
        assert_eq!(event.explicit_hostname().unwrap().as_str(), "example.com");
    }

    #[test]
    fn quic_denies_by_default() {
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: None,
            classification: UdpClassification::QuicCandidate,
        });

        let decision = PolicyEngine::new(RuntimeConfig::deny_by_default()).decide(&event);
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }
}
