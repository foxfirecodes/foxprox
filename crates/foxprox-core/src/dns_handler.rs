use crate::audit::{AuditDecision, AuditEvent, AuditEventKind};
use crate::dns::{
    build_dns_empty_response, parse_dns_query, DnsBuildError, DnsQueryMetadata, DnsResponseCode,
};
use crate::policy::{Decision, DenialReason, PolicyEngine, PolicyRequest};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDnsQueryContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub frontend: Frontend,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub max_query_bytes: usize,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerDnsQueryOutcome {
    Forward {
        query: DnsQueryMetadata,
        audit: AuditEvent,
    },
    Respond {
        query: DnsQueryMetadata,
        response: Vec<u8>,
        audit: AuditEvent,
    },
    Drop {
        audit: AuditEvent,
        response_error: Option<DnsBuildError>,
    },
}

pub fn handle_broker_dns_query(
    wire: &[u8],
    config: &PolicyConfig,
    context: BrokerDnsQueryContext,
) -> BrokerDnsQueryOutcome {
    let query = match parse_dns_query(wire, context.max_query_bytes) {
        Ok(query) => query,
        Err(_) => {
            return BrokerDnsQueryOutcome::Drop {
                audit: dns_parse_failure_audit(&context),
                response_error: None,
            };
        }
    };

    let request = PolicyRequest::from_dns_query_metadata(
        context.frontend,
        context.source,
        context.destination,
        query.clone(),
    );
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_dns_query_metadata(
        context.timestamp_millis,
        context.sandbox_id,
        context.frontend,
        context.source,
        context.destination,
        &query,
        &decision,
    );

    if decision.is_allow() {
        return BrokerDnsQueryOutcome::Forward { query, audit };
    }

    match build_dns_empty_response(
        &query,
        denial_response_code(&decision),
        context.max_response_bytes,
    ) {
        Ok(response) => BrokerDnsQueryOutcome::Respond {
            query,
            response,
            audit,
        },
        Err(error) => BrokerDnsQueryOutcome::Drop {
            audit,
            response_error: Some(error),
        },
    }
}

fn denial_response_code(decision: &Decision) -> DnsResponseCode {
    match decision {
        Decision::Allow { .. } => DnsResponseCode::NoError,
        Decision::Deny { .. } => DnsResponseCode::Refused,
        Decision::FailClosed { .. } => DnsResponseCode::ServFail,
    }
}

fn dns_parse_failure_audit(context: &BrokerDnsQueryContext) -> AuditEvent {
    AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind: AuditEventKind::DnsQuery,
        frontend: Some(context.frontend),
        protocol: Some(Protocol::Dns),
        source: context.source,
        destination: context.destination,
        requested_port: context.destination.and_then(|endpoint| endpoint.port),
        hostname: None,
        hostname_source: HostnameSource::None,
        hostname_confidence: HostnameConfidence::None,
        dns_query_type: None,
        dns_response_code: None,
        dns_answer_count: None,
        dns_min_ttl_seconds: None,
        decision: Some(AuditDecision::FailClosed),
        rule_id: None,
        reason: Some(DenialReason::MalformedInput),
        http_method: None,
        http_path_query: None,
        byte_count: None,
        flow_duration_millis: None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::config::{HostMatcher, PolicyRule, RuleAction};
    use crate::dns::{parse_dns_address_response, DnsParseError, DnsQueryType};
    use crate::policy::DenyBehavior;

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn endpoint(value: [u8; 4], port: u16) -> Endpoint {
        Endpoint::udp(ip(value), port)
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&qtype.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes
    }

    fn context() -> BrokerDnsQueryContext {
        BrokerDnsQueryContext {
            timestamp_millis: 123,
            sandbox_id: SandboxId::new("sandbox-dns"),
            frontend: Frontend::Tun,
            source: Some(endpoint([10, 0, 0, 2], 40000)),
            destination: Some(endpoint([10, 0, 2, 3], 53)),
            max_query_bytes: 512,
            max_response_bytes: 512,
        }
    }

    fn broker_config_with_rule(rule: PolicyRule) -> PolicyConfig {
        PolicyConfig {
            broker_dns_servers: vec![ip([10, 0, 2, 3])],
            rules: vec![rule],
            ..PolicyConfig::default()
        }
    }

    #[test]
    fn allowed_broker_dns_queries_return_forward_outcome_with_audit() {
        let config = broker_config_with_rule(PolicyRule::allow_domain(
            "allow-example-dns",
            HostMatcher::exact("example.com").unwrap(),
            Some(53),
        ));

        let outcome = handle_broker_dns_query(&query("example.com", 1), &config, context());
        let BrokerDnsQueryOutcome::Forward { query, audit } = outcome else {
            panic!("expected forward outcome");
        };

        assert_eq!(query.hostname.as_str(), "example.com");
        assert_eq!(query.query_type, DnsQueryType::A);
        assert_eq!(audit.kind, AuditEventKind::DnsQuery);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-example-dns"));
        assert_eq!(audit.dns_query_type, Some(DnsQueryType::A));
        assert_eq!(audit.requested_port, Some(53));
    }

    #[test]
    fn denied_broker_dns_queries_return_refused_response_and_audit() {
        let config = broker_config_with_rule(PolicyRule {
            id: "deny-example-dns".into(),
            action: RuleAction::Deny(DenyBehavior::Drop),
            protocol: crate::config::ProtocolMatcher::Exact(Protocol::Dns),
            destination: crate::config::DestinationMatcher::Any,
            request: crate::config::RequestMatcher::default(),
        });

        let outcome = handle_broker_dns_query(&query("example.com", 28), &config, context());
        let BrokerDnsQueryOutcome::Respond {
            query,
            response,
            audit,
        } = outcome
        else {
            panic!("expected refused response");
        };

        let parsed = parse_dns_address_response(&response, 512, 8).unwrap();
        assert_eq!(query.query_type, DnsQueryType::Aaaa);
        assert_eq!(parsed.hostname.as_str(), "example.com");
        assert_eq!(parsed.response_code, DnsResponseCode::Refused);
        assert!(parsed.addresses.is_empty());
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::RuleDeny));
        assert_eq!(audit.rule_id.as_deref(), Some("deny-example-dns"));
    }

    #[test]
    fn malformed_broker_dns_queries_fail_closed_without_response() {
        let config = broker_config_with_rule(PolicyRule::allow_domain(
            "allow-example-dns",
            HostMatcher::exact("example.com").unwrap(),
            Some(53),
        ));
        let outcome = handle_broker_dns_query(&[0u8; 4], &config, context());
        let BrokerDnsQueryOutcome::Drop {
            audit,
            response_error,
        } = outcome
        else {
            panic!("expected drop outcome");
        };

        assert_eq!(response_error, None);
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
        assert_eq!(audit.dns_query_type, None);
    }

    #[test]
    fn denial_response_synthesis_failure_drops_with_audited_decision() {
        let config = broker_config_with_rule(PolicyRule {
            id: "deny-example-dns".into(),
            action: RuleAction::Deny(DenyBehavior::Drop),
            protocol: crate::config::ProtocolMatcher::Exact(Protocol::Dns),
            destination: crate::config::DestinationMatcher::Any,
            request: crate::config::RequestMatcher::default(),
        });
        let mut too_small = context();
        too_small.max_response_bytes = 8;

        let outcome = handle_broker_dns_query(&query("example.com", 1), &config, too_small);
        let BrokerDnsQueryOutcome::Drop {
            audit,
            response_error,
        } = outcome
        else {
            panic!("expected drop outcome");
        };

        assert_eq!(response_error, Some(DnsBuildError::MessageTooLarge));
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::RuleDeny));
        assert_eq!(audit.dns_query_type, Some(DnsQueryType::A));
    }

    #[test]
    fn malformed_dns_query_still_matches_strict_parser_error() {
        assert_eq!(
            parse_dns_query(&[0u8; 4], 512),
            Err(DnsParseError::Truncated)
        );
    }
}
