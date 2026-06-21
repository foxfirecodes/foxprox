use crate::audit::{AuditEvent, AuditEventKind};
use crate::policy::PolicyInput;
use crate::types::{
    AttributionConfidence, AttributionSource, Endpoint, FrontendKind, HostnameAttribution,
    HttpRequestMetadata, Protocol, QuicStatus, SandboxId, SniStatus,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizedEvent {
    TcpConnectAttempt {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        source: Option<Endpoint>,
        destination: Endpoint,
        hostname: Option<HostnameAttribution>,
        sni_status: SniStatus,
        sni_dns_mismatch: bool,
    },
    UdpFlowAttempt {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        source: Endpoint,
        destination: Endpoint,
        hostname: Option<HostnameAttribution>,
        quic_status: QuicStatus,
    },
    DnsQuery {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        source: Endpoint,
        destination: Endpoint,
        query: HostnameAttribution,
    },
    HttpRequest {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        source: Option<Endpoint>,
        destination: Option<Endpoint>,
        metadata: HttpRequestMetadata,
    },
    HttpsConnect {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        hostname: HostnameAttribution,
        port: u16,
    },
    SocksConnect {
        sandbox_id: SandboxId,
        hostname: Option<HostnameAttribution>,
        destination: Option<Endpoint>,
        port: u16,
    },
    IcmpMessage {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        source: Endpoint,
        destination: Endpoint,
    },
    UnsupportedNetworkEvent {
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        protocol: Protocol,
    },
}

impl NormalizedEvent {
    pub fn to_policy_input(&self) -> PolicyInput {
        match self {
            Self::TcpConnectAttempt {
                sandbox_id,
                frontend,
                source,
                destination,
                hostname,
                sni_status,
                sni_dns_mismatch,
            } => {
                let mut input = PolicyInput::new(sandbox_id.clone(), *frontend, Protocol::Tcp);
                input.source = source.clone();
                input.destination = Some(destination.clone());
                input.hostname = hostname.clone();
                input.sni_status = *sni_status;
                input.sni_dns_mismatch = *sni_dns_mismatch;
                input
            }
            Self::UdpFlowAttempt {
                sandbox_id,
                frontend,
                source,
                destination,
                hostname,
                quic_status,
            } => {
                let mut input = PolicyInput::new(sandbox_id.clone(), *frontend, Protocol::Udp);
                input.source = Some(source.clone());
                input.destination = Some(destination.clone());
                input.hostname = hostname.clone();
                input.quic_status = *quic_status;
                input
            }
            Self::DnsQuery {
                sandbox_id,
                frontend,
                source,
                destination,
                query,
            } => {
                let mut input = PolicyInput::new(sandbox_id.clone(), *frontend, Protocol::Dns);
                input.source = Some(source.clone());
                input.destination = Some(destination.clone());
                input.hostname = Some(query.clone());
                input
            }
            Self::HttpRequest {
                sandbox_id,
                frontend,
                source,
                destination,
                metadata,
            } => {
                let mut input = PolicyInput::new(sandbox_id.clone(), *frontend, Protocol::Http)
                    .with_http(metadata.clone());
                input.source = source.clone();
                input.destination = destination.clone();
                input
            }
            Self::HttpsConnect {
                sandbox_id,
                frontend,
                hostname,
                port,
            } => {
                let mut input =
                    PolicyInput::new(sandbox_id.clone(), *frontend, Protocol::HttpsConnect);
                input.hostname = Some(hostname.clone());
                input.destination = Some(Endpoint::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    *port,
                ));
                input
            }
            Self::SocksConnect {
                sandbox_id,
                hostname,
                destination,
                ..
            } => {
                let mut input =
                    PolicyInput::new(sandbox_id.clone(), FrontendKind::Socks5, Protocol::Socks);
                input.hostname = hostname.clone();
                input.destination = destination.clone();
                input
            }
            Self::IcmpMessage {
                sandbox_id,
                frontend,
                source,
                destination,
            } => PolicyInput::new(sandbox_id.clone(), *frontend, Protocol::Icmp)
                .with_endpoints(source.clone(), destination.clone()),
            Self::UnsupportedNetworkEvent {
                sandbox_id,
                frontend,
                protocol,
            } => {
                let mut input = PolicyInput::new(sandbox_id.clone(), *frontend, *protocol);
                input.unsupported = true;
                input
            }
        }
    }

    pub fn to_audit_event(&self, timestamp_millis: u128) -> AuditEvent {
        match self {
            Self::TcpConnectAttempt {
                sandbox_id,
                frontend,
                source,
                destination,
                hostname,
                ..
            } => event_base(
                timestamp_millis,
                AuditEventKind::TcpConnect,
                sandbox_id,
                *frontend,
            )
            .with_protocol(Protocol::Tcp)
            .with_optional_endpoints(source.clone(), Some(destination.clone()))
            .with_optional_hostname(hostname.clone()),
            Self::UdpFlowAttempt {
                sandbox_id,
                frontend,
                source,
                destination,
                hostname,
                quic_status,
            } => {
                let kind = if *quic_status == QuicStatus::Candidate {
                    AuditEventKind::QuicCandidateFlowCreated
                } else {
                    AuditEventKind::UdpFlowCreated
                };
                event_base(timestamp_millis, kind, sandbox_id, *frontend)
                    .with_protocol(Protocol::Udp)
                    .with_endpoints(source.clone(), destination.clone())
                    .with_optional_hostname(hostname.clone())
            }
            Self::DnsQuery {
                sandbox_id,
                frontend,
                source,
                destination,
                query,
            } => event_base(
                timestamp_millis,
                AuditEventKind::DnsQuery,
                sandbox_id,
                *frontend,
            )
            .with_protocol(Protocol::Dns)
            .with_endpoints(source.clone(), destination.clone())
            .with_hostname(query.hostname.clone(), query.confidence),
            Self::HttpRequest {
                sandbox_id,
                frontend,
                source,
                destination,
                metadata,
            } => event_base(
                timestamp_millis,
                AuditEventKind::HttpRequest,
                sandbox_id,
                *frontend,
            )
            .with_protocol(Protocol::Http)
            .with_optional_endpoints(source.clone(), destination.clone())
            .with_hostname(metadata.host.clone(), AttributionConfidence::High),
            Self::HttpsConnect {
                sandbox_id,
                frontend,
                hostname,
                ..
            } => event_base(
                timestamp_millis,
                AuditEventKind::HttpsConnect,
                sandbox_id,
                *frontend,
            )
            .with_protocol(Protocol::HttpsConnect)
            .with_hostname(hostname.hostname.clone(), hostname.confidence),
            Self::SocksConnect {
                sandbox_id,
                hostname,
                destination,
                ..
            } => event_base(
                timestamp_millis,
                AuditEventKind::SocksConnect,
                sandbox_id,
                FrontendKind::Socks5,
            )
            .with_protocol(Protocol::Socks)
            .with_optional_endpoints(None, destination.clone())
            .with_optional_hostname(hostname.clone()),
            Self::IcmpMessage {
                sandbox_id,
                frontend,
                source,
                destination,
            } => event_base(
                timestamp_millis,
                AuditEventKind::IcmpMessage,
                sandbox_id,
                *frontend,
            )
            .with_protocol(Protocol::Icmp)
            .with_endpoints(source.clone(), destination.clone()),
            Self::UnsupportedNetworkEvent {
                sandbox_id,
                frontend,
                protocol,
            } => event_base(
                timestamp_millis,
                AuditEventKind::UnsupportedNetworkEvent,
                sandbox_id,
                *frontend,
            )
            .with_protocol(*protocol),
        }
    }
}

fn event_base(
    timestamp_millis: u128,
    kind: AuditEventKind,
    sandbox_id: &SandboxId,
    frontend: FrontendKind,
) -> AuditEvent {
    AuditEvent::new(timestamp_millis, kind, sandbox_id.clone(), frontend)
}

trait AuditEventExt {
    fn with_optional_endpoints(
        self,
        source: Option<Endpoint>,
        destination: Option<Endpoint>,
    ) -> Self;
    fn with_optional_hostname(self, hostname: Option<HostnameAttribution>) -> Self;
}

impl AuditEventExt for AuditEvent {
    fn with_optional_endpoints(
        mut self,
        source: Option<Endpoint>,
        destination: Option<Endpoint>,
    ) -> Self {
        self.source = source;
        self.destination = destination;
        self
    }

    fn with_optional_hostname(mut self, hostname: Option<HostnameAttribution>) -> Self {
        if let Some(hostname) = hostname {
            self.hostname = Some(hostname.hostname);
            self.hostname_confidence = Some(hostname.confidence);
        }
        self
    }
}

pub fn explicit_proxy_attribution(hostname: crate::types::Hostname) -> HostnameAttribution {
    HostnameAttribution::new(
        hostname,
        AttributionSource::ExplicitProxy,
        AttributionConfidence::High,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyConfig, PolicyEngine, PolicyRule, PortMatcher, RuleSet};
    use crate::types::{DecisionAction, Hostname, Scheme};
    use std::net::{IpAddr, Ipv4Addr};

    fn sandbox() -> SandboxId {
        SandboxId::new("scenario").unwrap()
    }

    #[test]
    fn transparent_http_event_uses_host_metadata_for_policy() {
        let mut rule = PolicyRule::allow("allow-http-path");
        rule.protocol = Some(Protocol::Http);
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::High);
        rule.http_method = Some("GET".to_string());
        rule.http_path_prefix = Some("/allowed".to_string());
        let mut rules = RuleSet::default();
        rules.push(rule);
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::HttpRequest {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                80,
            )),
            metadata: HttpRequestMetadata {
                method: "GET".to_string(),
                host: Hostname::normalize("www.example.com").unwrap(),
                port: 80,
                path_query: "/allowed/page".to_string(),
                scheme: Scheme::Http,
            },
        };
        let decision = engine.evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("allow-http-path"));
    }

    #[test]
    fn tls_sni_mismatch_event_fails_closed_before_rules() {
        let mut rules = RuleSet::default();
        rules.push(PolicyRule::allow("allow-all"));
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::TcpConnectAttempt {
            sandbox_id: sandbox(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443),
            hostname: Some(HostnameAttribution::broker_dns(
                Hostname::normalize("example.com").unwrap(),
            )),
            sni_status: SniStatus::Present,
            sni_dns_mismatch: true,
        };
        let decision = engine.evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::FailClosed);
    }

    #[test]
    fn socks_event_can_share_domain_policy() {
        let mut rule = PolicyRule::allow("allow-socks-domain");
        rule.protocol = Some(Protocol::Socks);
        rule.destination_port = Some(PortMatcher::Exact(443));
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::High);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::SocksConnect {
            sandbox_id: sandbox(),
            hostname: Some(explicit_proxy_attribution(
                Hostname::normalize("api.example.com").unwrap(),
            )),
            destination: Some(Endpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443)),
            port: 443,
        };
        let decision = engine.evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::Allow);
    }
}
