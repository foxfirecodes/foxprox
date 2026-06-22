//! Deterministic policy evaluation over normalized foxprox events.
//!
//! This crate deliberately depends only on `foxprox-core`. It must not import
//! frontend, Linux, bwrap, parser, network-stack, audit, or egress crates.

#![forbid(unsafe_code)]

use foxprox_core::{
    AllowDecision, DefaultPolicy, DenialAction, DenyDecision, DestinationMatcher, DirectDnsPolicy,
    HostnameConfidence, HostnameMismatch, HttpMethodMatcher, HttpPathMatcher, HttpSchemeMatcher,
    NormalizedEvent, PolicyDecision, PolicyRule, Protocol, ProtocolMatcher, QuicPolicy, RuleAction,
    RuntimeConfig, UdpClassification,
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

        if self.is_direct_encrypted_dns_candidate(event) {
            if let Some(decision) = self.match_configured_rule(event) {
                return decision;
            }
            return deny(
                DenialAction::Reset,
                None,
                "direct DNS-over-TLS candidate denied by default",
            );
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
            if is_echo {
                if self.config.allow_ping {
                    return PolicyDecision::Allow(AllowDecision {
                        rule_id: None,
                        timeout_override: None,
                        reason: Some("ICMP echo enabled by policy".into()),
                    });
                }
                return deny(DenialAction::Drop, None, "ICMP echo is disabled by policy");
            }
            if is_essential_icmp(icmp) {
                return PolicyDecision::Allow(AllowDecision {
                    rule_id: None,
                    timeout_override: None,
                    reason: Some("essential ICMP error allowed by default".into()),
                });
            }
            return deny(
                DenialAction::Drop,
                None,
                "unsupported ICMP type denied by default",
            );
        }

        if let NormalizedEvent::TlsClientHello(tls) = event {
            if tls.mismatch == HostnameMismatch::Mismatch {
                return deny(
                    DenialAction::Reset,
                    None,
                    "TLS SNI does not match DNS attribution",
                );
            }
            if tls.sni.is_none() {
                if let Some(decision) = self.match_configured_rule(event) {
                    return decision;
                }
                return deny(
                    DenialAction::Reset,
                    None,
                    "TLS SNI is unavailable; explicit IP/port allow rule required",
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
                    timeout_override: rule.timeout_override,
                    reason: Some("matched allow rule".into()),
                }),
                RuleAction::Deny(action) => {
                    deny(action, Some(rule.id.clone()), "matched deny rule")
                }
            })
    }

    fn is_direct_encrypted_dns_candidate(&self, event: &NormalizedEvent) -> bool {
        if event.protocol() != Protocol::Tcp || event.destination_port() != Some(853) {
            return false;
        }
        event.destination_ip().is_some_and(|ip| {
            !self.config.broker_dns_addrs.contains(&ip)
                && self.config.direct_dns_policy == DirectDnsPolicy::DenyExternal
        })
    }
}

fn rule_matches(rule: &PolicyRule, event: &NormalizedEvent) -> bool {
    protocol_matches(rule.protocol, event.protocol())
        && destination_matches(rule, event)
        && rule.port.matches(event.destination_port())
        && request_metadata_matches(rule, event)
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

fn request_metadata_matches(rule: &PolicyRule, event: &NormalizedEvent) -> bool {
    let scheme_matches = match rule.http_scheme {
        HttpSchemeMatcher::Any => true,
        HttpSchemeMatcher::Exact(expected) => match event {
            NormalizedEvent::HttpRequest(request) => request.scheme == expected,
            _ => false,
        },
    };
    let method_matches = match &rule.http_method {
        HttpMethodMatcher::Any => true,
        HttpMethodMatcher::Exact(expected) => match event {
            NormalizedEvent::HttpRequest(request) => &request.method == expected,
            _ => false,
        },
    };
    let path_matches = match &rule.http_path {
        HttpPathMatcher::Any => true,
        HttpPathMatcher::Exact(expected) => match event {
            NormalizedEvent::HttpRequest(request) => &request.path_query == expected,
            _ => false,
        },
        HttpPathMatcher::Prefix(prefix) => match event {
            NormalizedEvent::HttpRequest(request) => request.path_query.starts_with(prefix),
            _ => false,
        },
    };
    scheme_matches && method_matches && path_matches
}

fn is_essential_icmp(icmp: &foxprox_core::IcmpMessage) -> bool {
    if icmp.source.is_ipv4() && icmp.destination.is_ipv4() {
        matches!(icmp.icmp_type, 3 | 11 | 12)
    } else if icmp.source.is_ipv6() && icmp.destination.is_ipv6() {
        matches!(icmp.icmp_type, 1..=4)
    } else {
        false
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
        HttpSchemeMatcher, IcmpMessage, IpCidr, RuleId, SandboxId, TcpConnectAttempt,
        TlsClientHello, UdpFlowAttempt, UnsupportedNetworkEvent, UnsupportedReason,
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
    fn allow_rule_can_set_timeout_override() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("quic-timeout").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::QuicCandidate);
        rule.timeout_override = Some(std::time::Duration::from_secs(240));
        config.quic_policy = QuicPolicy::AllowCandidates;
        config.rules.push(rule);
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: None,
            classification: UdpClassification::QuicCandidate,
        });

        let decision = PolicyEngine::new(config).decide(&event);
        let PolicyDecision::Allow(allow) = decision else {
            panic!("expected allow");
        };
        assert_eq!(
            allow.timeout_override,
            Some(std::time::Duration::from_secs(240))
        );
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
            host: DestinationHost::Hostname(Hostname::new("www.example.com").unwrap()),
            port: 80,
            path_query: "/index.html".to_string(),
        });

        assert!(PolicyEngine::new(config).decide(&event).is_allowed());
    }

    #[test]
    fn http_scheme_method_and_path_matchers_are_enforced() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("http-api").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Http);
        rule.http_scheme = HttpSchemeMatcher::Exact(HttpScheme::Http);
        rule.http_method = HttpMethodMatcher::Exact(HttpMethod::Get);
        rule.http_path = HttpPathMatcher::Prefix("/api/".to_string());
        config.rules.push(rule);

        let allowed = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            method: HttpMethod::Get,
            scheme: HttpScheme::Http,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 80,
            path_query: "/api/items".to_string(),
        });
        let wrong_scheme = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: sandbox(),
            frontend: FrontendKind::HttpProxy,
            method: HttpMethod::Get,
            scheme: HttpScheme::Https,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 443,
            path_query: "/api/items".to_string(),
        });
        let denied = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            method: HttpMethod::Post,
            scheme: HttpScheme::Http,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 80,
            path_query: "/api/items".to_string(),
        });
        let engine = PolicyEngine::new(config);

        assert!(engine.decide(&allowed).is_allowed());
        assert!(!engine.decide(&wrong_scheme).is_allowed());
        assert!(!engine.decide(&denied).is_allowed());
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
    fn icmp_defaults_allow_essential_errors_and_gate_ping() {
        let essential = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            icmp_type: 3,
            icmp_code: 1,
            source: "203.0.113.10".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
        });
        assert!(PolicyEngine::new(RuntimeConfig::deny_by_default())
            .decide(&essential)
            .is_allowed());

        let ping = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            icmp_type: 8,
            icmp_code: 0,
            source: "10.0.0.2".parse().unwrap(),
            destination: "203.0.113.10".parse().unwrap(),
        });
        assert!(!PolicyEngine::new(RuntimeConfig::allow_by_default())
            .decide(&ping)
            .is_allowed());
        let mut config = RuntimeConfig::deny_by_default();
        config.allow_ping = true;
        assert!(PolicyEngine::new(config).decide(&ping).is_allowed());

        let unusual = NormalizedEvent::IcmpMessage(IcmpMessage {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            icmp_type: 13,
            icmp_code: 0,
            source: "10.0.0.2".parse().unwrap(),
            destination: "203.0.113.10".parse().unwrap(),
        });
        assert!(!PolicyEngine::new(RuntimeConfig::allow_by_default())
            .decide(&unusual)
            .is_allowed());
    }

    #[test]
    fn tls_without_sni_requires_explicit_ip_allow_even_when_default_allows() {
        let event = NormalizedEvent::TlsClientHello(TlsClientHello {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            destination: "203.0.113.10:443".parse().unwrap(),
            sni: None,
            dns_hostname: None,
            mismatch: HostnameMismatch::Unavailable,
        });

        let denied = PolicyEngine::new(RuntimeConfig::allow_by_default()).decide(&event);
        assert!(matches!(denied, PolicyDecision::Deny(_)));

        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("ip-https").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::TlsClientHello);
        rule.destination = DestinationMatcher::Ip("203.0.113.10".parse().unwrap());
        rule.port = foxprox_core::PortMatcher::Exact(443);
        config.rules.push(rule);

        assert!(PolicyEngine::new(config).decide(&event).is_allowed());
    }

    #[test]
    fn direct_dot_candidate_is_denied_before_default_allow() {
        let event = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "203.0.113.53:853".parse().unwrap(),
            hostname: None,
        });

        let decision = PolicyEngine::new(RuntimeConfig::allow_by_default()).decide(&event);
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn explicit_rule_can_allow_dot_candidate() {
        let event = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "203.0.113.53:853".parse().unwrap(),
            hostname: None,
        });
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("allow-dot-lab").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.destination = DestinationMatcher::Ip("203.0.113.53".parse().unwrap());
        rule.port = foxprox_core::PortMatcher::Exact(853);
        config.rules.push(rule);

        assert!(PolicyEngine::new(config).decide(&event).is_allowed());
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
