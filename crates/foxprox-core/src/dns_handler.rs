use crate::audit::{AuditDecision, AuditEvent, AuditEventKind};
use crate::dns::{
    build_dns_empty_response, parse_dns_address_response, parse_dns_query,
    DnsAddressResponseMetadata, DnsAttributionCache, DnsBuildError, DnsParseError,
    DnsQueryMetadata, DnsResponseCode, DnsResponseObserveOutcome, DnsTransactionError,
    PendingDnsObserveOutcome, PendingDnsQueryTable,
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
        wire: Vec<u8>,
        audit: AuditEvent,
        pending: Option<PendingDnsObserveOutcome>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDnsResponseContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub frontend: Frontend,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub max_response_bytes: usize,
    pub max_answers: usize,
    pub now_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerDnsResponseOutcome {
    Forward {
        response: DnsAddressResponseMetadata,
        wire: Vec<u8>,
        cache: DnsResponseObserveOutcome,
        audit: AuditEvent,
    },
    Drop {
        audit: AuditEvent,
        parse_error: Option<DnsParseError>,
        transaction_error: Option<DnsTransactionError>,
    },
}

pub fn handle_broker_dns_query(
    wire: &[u8],
    config: &PolicyConfig,
    context: BrokerDnsQueryContext,
) -> BrokerDnsQueryOutcome {
    handle_broker_dns_query_inner(wire, config, context, None)
}

pub fn handle_broker_dns_query_with_pending(
    wire: &[u8],
    config: &PolicyConfig,
    context: BrokerDnsQueryContext,
    pending_queries: &mut PendingDnsQueryTable,
    upstream: Endpoint,
    now_millis: u64,
) -> BrokerDnsQueryOutcome {
    handle_broker_dns_query_inner(
        wire,
        config,
        context,
        Some((pending_queries, upstream, now_millis)),
    )
}

fn handle_broker_dns_query_inner(
    wire: &[u8],
    config: &PolicyConfig,
    context: BrokerDnsQueryContext,
    pending: Option<(&mut PendingDnsQueryTable, Endpoint, u64)>,
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
        let pending = pending.and_then(|(pending_queries, upstream, now_millis)| {
            context
                .source
                .map(|client| pending_queries.observe_query(client, upstream, &query, now_millis))
        });
        return BrokerDnsQueryOutcome::Forward {
            query,
            wire: wire.to_vec(),
            audit,
            pending,
        };
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

pub fn handle_broker_dns_response(
    wire: &[u8],
    pending_queries: &mut PendingDnsQueryTable,
    cache: &mut DnsAttributionCache,
    context: BrokerDnsResponseContext,
) -> BrokerDnsResponseOutcome {
    let response =
        match parse_dns_address_response(wire, context.max_response_bytes, context.max_answers) {
            Ok(response) => response,
            Err(error) => {
                return BrokerDnsResponseOutcome::Drop {
                    audit: dns_response_parse_failure_audit(&context),
                    parse_error: Some(error),
                    transaction_error: None,
                };
            }
        };

    let (Some(client), Some(upstream)) = (context.destination, context.source) else {
        return BrokerDnsResponseOutcome::Drop {
            audit: dns_response_parse_failure_audit(&context),
            parse_error: None,
            transaction_error: None,
        };
    };

    match pending_queries.validate_response_and_observe(
        cache,
        client,
        upstream,
        &response,
        context.now_millis,
    ) {
        Ok(cache_outcome) => {
            let audit = AuditEvent::from_dns_response_metadata(
                context.timestamp_millis,
                context.sandbox_id,
                context.frontend,
                context.source,
                context.destination,
                &response,
                &Decision::Allow { rule_id: None },
            );
            BrokerDnsResponseOutcome::Forward {
                response,
                wire: wire.to_vec(),
                cache: cache_outcome,
                audit,
            }
        }
        Err(error) => {
            let audit = AuditEvent::from_dns_response_metadata(
                context.timestamp_millis,
                context.sandbox_id,
                context.frontend,
                context.source,
                context.destination,
                &response,
                &Decision::FailClosed {
                    reason: DenialReason::AttributionMismatch,
                },
            );
            BrokerDnsResponseOutcome::Drop {
                audit,
                parse_error: None,
                transaction_error: Some(error),
            }
        }
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
        presented_hostname: None,
        dns_attribution: None,
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

fn dns_response_parse_failure_audit(context: &BrokerDnsResponseContext) -> AuditEvent {
    AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind: AuditEventKind::DnsResponse,
        frontend: Some(context.frontend),
        protocol: Some(Protocol::Dns),
        source: context.source,
        destination: context.destination,
        requested_port: context.destination.and_then(|endpoint| endpoint.port),
        hostname: None,
        presented_hostname: None,
        dns_attribution: None,
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

    fn response_context() -> BrokerDnsResponseContext {
        BrokerDnsResponseContext {
            timestamp_millis: 124,
            sandbox_id: SandboxId::new("sandbox-dns"),
            frontend: Frontend::Tun,
            source: Some(endpoint([8, 8, 8, 8], 53)),
            destination: Some(endpoint([10, 0, 0, 2], 40000)),
            max_response_bytes: 512,
            max_answers: 8,
            now_millis: 1_100,
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

        let query_wire = query("example.com", 1);
        let outcome = handle_broker_dns_query(&query_wire, &config, context());
        let BrokerDnsQueryOutcome::Forward {
            query,
            wire,
            audit,
            pending,
        } = outcome
        else {
            panic!("expected forward outcome");
        };

        assert_eq!(query.hostname.as_str(), "example.com");
        assert_eq!(query.query_type, DnsQueryType::A);
        assert_eq!(wire, query_wire);
        assert_eq!(audit.kind, AuditEventKind::DnsQuery);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-example-dns"));
        assert_eq!(audit.dns_query_type, Some(DnsQueryType::A));
        assert_eq!(audit.requested_port, Some(53));
        assert_eq!(pending, None);
    }

    #[test]
    fn allowed_broker_dns_queries_can_store_bounded_pending_transactions() {
        let config = broker_config_with_rule(PolicyRule::allow_domain(
            "allow-example-dns",
            HostMatcher::exact("example.com").unwrap(),
            Some(53),
        ));
        let mut pending_queries = PendingDnsQueryTable::new(4, 5_000);
        let upstream = endpoint([8, 8, 8, 8], 53);

        let outcome = handle_broker_dns_query_with_pending(
            &query("example.com", 1),
            &config,
            context(),
            &mut pending_queries,
            upstream,
            1_000,
        );
        let BrokerDnsQueryOutcome::Forward {
            query,
            wire: _,
            audit: _,
            pending,
        } = outcome
        else {
            panic!("expected forward outcome");
        };

        let pending = pending.expect("allowed query should be observed");
        assert_eq!(pending.status, crate::dns::PendingDnsObserveStatus::Stored);
        assert_eq!(pending_queries.len(), 1);

        let response = crate::dns::parse_dns_address_response(
            &crate::dns::build_dns_address_response(
                &query,
                [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
                512,
                8,
            )
            .unwrap(),
            512,
            8,
        )
        .unwrap();
        assert!(pending_queries
            .validate_response(endpoint([10, 0, 0, 2], 40000), upstream, &response, 1_100)
            .is_ok());
    }

    #[test]
    fn correlated_dns_responses_forward_and_update_cache_with_audit() {
        let config = broker_config_with_rule(PolicyRule::allow_domain(
            "allow-example-dns",
            HostMatcher::exact("example.com").unwrap(),
            Some(53),
        ));
        let mut pending_queries = PendingDnsQueryTable::new(4, 5_000);
        let upstream = endpoint([8, 8, 8, 8], 53);
        let BrokerDnsQueryOutcome::Forward { query, .. } = handle_broker_dns_query_with_pending(
            &query("example.com", 1),
            &config,
            context(),
            &mut pending_queries,
            upstream,
            1_000,
        ) else {
            panic!("expected query forward");
        };
        let wire_response = crate::dns::build_dns_address_response(
            &query,
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            60,
            512,
            8,
        )
        .unwrap();
        let mut cache = DnsAttributionCache::new(8, 60_000);

        let outcome = handle_broker_dns_response(
            &wire_response,
            &mut pending_queries,
            &mut cache,
            response_context(),
        );
        let BrokerDnsResponseOutcome::Forward {
            response,
            wire,
            cache: cache_outcome,
            audit,
        } = outcome
        else {
            panic!("expected response forward");
        };

        assert_eq!(response.hostname.as_str(), "example.com");
        assert_eq!(wire, wire_response);
        assert_eq!(cache_outcome.cache.stored, 1);
        assert_eq!(pending_queries.len(), 0);
        assert_eq!(
            cache
                .lookup(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 1_200)
                .len(),
            1
        );
        assert_eq!(audit.kind, AuditEventKind::DnsResponse);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.hostname_confidence, HostnameConfidence::Medium);
        assert_eq!(audit.dns_answer_count, Some(1));
        assert_eq!(audit.dns_min_ttl_seconds, Some(60));
    }

    #[test]
    fn dns_response_replay_or_malformed_input_drops_without_cache_update() {
        let config = broker_config_with_rule(PolicyRule::allow_domain(
            "allow-example-dns",
            HostMatcher::exact("example.com").unwrap(),
            Some(53),
        ));
        let mut pending_queries = PendingDnsQueryTable::new(4, 5_000);
        let upstream = endpoint([8, 8, 8, 8], 53);
        let BrokerDnsQueryOutcome::Forward { query, .. } = handle_broker_dns_query_with_pending(
            &query("example.com", 1),
            &config,
            context(),
            &mut pending_queries,
            upstream,
            1_000,
        ) else {
            panic!("expected query forward");
        };
        let wire_response = crate::dns::build_dns_address_response(
            &query,
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            60,
            512,
            8,
        )
        .unwrap();
        let mut cache = DnsAttributionCache::new(8, 60_000);

        assert!(matches!(
            handle_broker_dns_response(
                &wire_response,
                &mut pending_queries,
                &mut cache,
                response_context(),
            ),
            BrokerDnsResponseOutcome::Forward { .. }
        ));
        let replay = handle_broker_dns_response(
            &wire_response,
            &mut pending_queries,
            &mut cache,
            response_context(),
        );
        let BrokerDnsResponseOutcome::Drop {
            audit,
            parse_error,
            transaction_error,
        } = replay
        else {
            panic!("expected replay drop");
        };
        assert_eq!(parse_error, None);
        assert_eq!(
            transaction_error,
            Some(DnsTransactionError::UnmatchedResponse)
        );
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::AttributionMismatch));

        let malformed = handle_broker_dns_response(
            &[0u8; 4],
            &mut pending_queries,
            &mut cache,
            response_context(),
        );
        let BrokerDnsResponseOutcome::Drop {
            audit,
            parse_error,
            transaction_error,
        } = malformed
        else {
            panic!("expected malformed drop");
        };
        assert_eq!(parse_error, Some(DnsParseError::Truncated));
        assert_eq!(transaction_error, None);
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
        assert_eq!(
            cache
                .lookup(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 1_200)
                .len(),
            0
        );
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
    fn denied_queries_do_not_store_pending_transactions() {
        let config = broker_config_with_rule(PolicyRule {
            id: "deny-example-dns".into(),
            action: RuleAction::Deny(DenyBehavior::Drop),
            protocol: crate::config::ProtocolMatcher::Exact(Protocol::Dns),
            destination: crate::config::DestinationMatcher::Any,
            request: crate::config::RequestMatcher::default(),
        });
        let mut pending_queries = PendingDnsQueryTable::new(4, 5_000);

        let outcome = handle_broker_dns_query_with_pending(
            &query("example.com", 1),
            &config,
            context(),
            &mut pending_queries,
            endpoint([8, 8, 8, 8], 53),
            1_000,
        );

        assert!(matches!(outcome, BrokerDnsQueryOutcome::Respond { .. }));
        assert!(pending_queries.is_empty());
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
