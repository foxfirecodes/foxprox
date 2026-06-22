use crate::audit::{AuditDecision, AuditEvent, AuditEventKind, AuditPolicyContext};
use crate::egress::{EgressPermit, EgressPermitError};
use crate::http::{parse_http_request_head, HttpParseError, HttpRequestMetadata};
use crate::policy::{Decision, DenialReason, PolicyEngine, PolicyRequest};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentHttpContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub max_header_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransparentHttpOutcome {
    Allow {
        metadata: HttpRequestMetadata,
        permit: EgressPermit,
        audit: Box<AuditEvent>,
    },
    Drop {
        metadata: Option<HttpRequestMetadata>,
        parse_error: Option<HttpParseError>,
        permit_error: Option<EgressPermitError>,
        decision: Decision,
        audit: Box<AuditEvent>,
    },
}

pub fn handle_transparent_http_request(
    wire: &[u8],
    config: &PolicyConfig,
    context: TransparentHttpContext,
) -> TransparentHttpOutcome {
    let metadata = match parse_http_request_head(wire, context.max_header_bytes) {
        Ok(metadata) => metadata,
        Err(error) => {
            let audit = malformed_http_audit(&context);
            return TransparentHttpOutcome::Drop {
                metadata: None,
                parse_error: Some(error),
                permit_error: None,
                decision: Decision::FailClosed {
                    reason: DenialReason::MalformedInput,
                },
                audit: Box::new(audit),
            };
        }
    };

    let mut request = PolicyRequest::from_http_request_metadata(
        Frontend::Tun,
        metadata.clone(),
        Some(context.destination),
    );
    request.sandbox_id = context.sandbox_id.clone();
    request.source = context.source;
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_policy_decision(
        AuditPolicyContext::from_request(
            context.timestamp_millis,
            AuditEventKind::HttpRequest,
            &request,
        ),
        &decision,
    );

    if decision.is_allow() {
        match EgressPermit::from_policy_decision(&request, &decision) {
            Ok(permit) => TransparentHttpOutcome::Allow {
                metadata,
                permit,
                audit: Box::new(audit),
            },
            Err(error) => TransparentHttpOutcome::Drop {
                metadata: Some(metadata),
                parse_error: None,
                permit_error: Some(error),
                decision,
                audit: Box::new(audit),
            },
        }
    } else {
        TransparentHttpOutcome::Drop {
            metadata: Some(metadata),
            parse_error: None,
            permit_error: None,
            decision,
            audit: Box::new(audit),
        }
    }
}

fn malformed_http_audit(context: &TransparentHttpContext) -> AuditEvent {
    AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind: AuditEventKind::HttpRequest,
        frontend: Some(Frontend::Tun),
        protocol: Some(Protocol::Http),
        source: context.source,
        destination: Some(context.destination),
        requested_port: context.destination.port,
        hostname: None,
        presented_hostname: None,
        dns_attribution: None,
        hidden_sni: false,
        quic_header_form: None,
        quic_long_packet_type: None,
        quic_version: None,
        quic_version_supported: None,
        quic_destination_connection_id_len: None,
        quic_source_connection_id_len: None,
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

    use crate::config::{HostMatcher, PolicyRule};
    use crate::egress::EgressDestination;
    use crate::policy::DenyBehavior;

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn context() -> TransparentHttpContext {
        TransparentHttpContext {
            timestamp_millis: 500,
            sandbox_id: SandboxId::new("sandbox-http"),
            source: Some(Endpoint::tcp(ip([10, 0, 0, 2]), 40000)),
            destination: Endpoint::tcp(ip([203, 0, 113, 10]), 80),
            max_header_bytes: 1024,
        }
    }

    #[test]
    fn path_scoped_transparent_http_allows_with_egress_permit_and_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow_domain(
                "allow-api",
                HostMatcher::exact("api.example.com").unwrap(),
                Some(80),
            )
            .with_http_method("GET")
            .with_http_path_prefix("/v1/"),
        );
        let wire = b"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let outcome = handle_transparent_http_request(wire, &config, context());
        let TransparentHttpOutcome::Allow {
            metadata,
            permit,
            audit,
        } = outcome
        else {
            panic!("expected transparent HTTP allow");
        };

        assert_eq!(metadata.host.as_str(), "api.example.com");
        assert_eq!(metadata.path_query, "/v1/users");
        assert_eq!(
            permit.destination,
            EgressDestination::Ip(Endpoint::tcp(ip([203, 0, 113, 10]), 80))
        );
        assert_eq!(audit.frontend, Some(Frontend::Tun));
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-api"));
        assert_eq!(audit.http_method.as_deref(), Some("GET"));
        assert_eq!(audit.http_path_query.as_deref(), Some("/v1/users"));
    }

    #[test]
    fn transparent_http_path_mismatch_denies_before_egress() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow_domain(
                "allow-api",
                HostMatcher::exact("api.example.com").unwrap(),
                Some(80),
            )
            .with_http_path_prefix("/v1/"),
        );
        let wire = b"GET /admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let outcome = handle_transparent_http_request(wire, &config, context());
        let TransparentHttpOutcome::Drop {
            metadata,
            decision,
            audit,
            ..
        } = outcome
        else {
            panic!("expected HTTP deny");
        };

        assert!(metadata.is_some());
        assert_eq!(decision.reason(), Some(DenialReason::DefaultDeny));
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.hostname.as_ref().unwrap().as_str(), "api.example.com");
        assert_eq!(audit.http_path_query.as_deref(), Some("/admin"));
    }

    #[test]
    fn malformed_transparent_http_fails_closed_before_policy_or_egress() {
        let wire = b"GET / HTTP/1.1\r\n\r\n";

        let outcome = handle_transparent_http_request(wire, &PolicyConfig::default(), context());
        let TransparentHttpOutcome::Drop {
            metadata,
            parse_error,
            permit_error,
            decision,
            audit,
        } = outcome
        else {
            panic!("expected malformed HTTP drop");
        };

        assert_eq!(metadata, None);
        assert_eq!(parse_error, Some(HttpParseError::MissingHost));
        assert_eq!(permit_error, None);
        assert_eq!(decision.reason(), Some(DenialReason::MalformedInput));
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
        assert_eq!(audit.hostname, None);
    }
}
