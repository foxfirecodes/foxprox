use crate::audit::{AuditDecision, AuditEvent, AuditEventKind, AuditPolicyContext};
use crate::http::{parse_http_request_head, parse_https_connect_head};
use crate::policy::{Decision, DenialReason, PolicyEngine, PolicyRequest};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProxyRequestContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub source: Option<Endpoint>,
    pub max_header_bytes: usize,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpProxyRequestOutcome {
    ForwardHttp {
        request: PolicyRequest,
        wire: Vec<u8>,
        audit: AuditEvent,
    },
    EstablishConnect {
        request: PolicyRequest,
        wire: Vec<u8>,
        audit: AuditEvent,
    },
    Respond {
        response: Vec<u8>,
        audit: AuditEvent,
    },
    Drop {
        audit: AuditEvent,
        response_error: Option<HttpProxyResponseError>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HttpProxyResponseError {
    ResponseTooLarge,
}

pub fn handle_http_proxy_request(
    wire: &[u8],
    config: &PolicyConfig,
    context: HttpProxyRequestContext,
) -> HttpProxyRequestOutcome {
    if starts_with_connect(wire) {
        handle_connect_request(wire, config, context)
    } else {
        handle_plain_http_request(wire, config, context)
    }
}

fn handle_plain_http_request(
    wire: &[u8],
    config: &PolicyConfig,
    context: HttpProxyRequestContext,
) -> HttpProxyRequestOutcome {
    let metadata = match parse_http_request_head(wire, context.max_header_bytes) {
        Ok(metadata) => metadata,
        Err(_) => return malformed_proxy_outcome(&context, AuditEventKind::HttpRequest),
    };
    let mut request =
        PolicyRequest::from_http_request_metadata(Frontend::HttpProxy, metadata, None);
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
        HttpProxyRequestOutcome::ForwardHttp {
            request,
            wire: wire.to_vec(),
            audit,
        }
    } else {
        denied_proxy_response(
            decision_response_status(&decision),
            audit,
            context.max_response_bytes,
        )
    }
}

fn handle_connect_request(
    wire: &[u8],
    config: &PolicyConfig,
    context: HttpProxyRequestContext,
) -> HttpProxyRequestOutcome {
    let metadata = match parse_https_connect_head(wire, context.max_header_bytes) {
        Ok(metadata) => metadata,
        Err(_) => return malformed_proxy_outcome(&context, AuditEventKind::HttpsConnect),
    };
    let mut request = PolicyRequest::from_https_connect_metadata(metadata);
    request.sandbox_id = context.sandbox_id.clone();
    request.source = context.source;
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_policy_decision(
        AuditPolicyContext::from_request(
            context.timestamp_millis,
            AuditEventKind::HttpsConnect,
            &request,
        ),
        &decision,
    );

    if decision.is_allow() {
        HttpProxyRequestOutcome::EstablishConnect {
            request,
            wire: wire.to_vec(),
            audit,
        }
    } else {
        denied_proxy_response(
            decision_response_status(&decision),
            audit,
            context.max_response_bytes,
        )
    }
}

fn malformed_proxy_outcome(
    context: &HttpProxyRequestContext,
    kind: AuditEventKind,
) -> HttpProxyRequestOutcome {
    let audit = AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind,
        frontend: Some(Frontend::HttpProxy),
        protocol: Some(match kind {
            AuditEventKind::HttpsConnect => Protocol::HttpsConnect,
            _ => Protocol::Http,
        }),
        source: context.source,
        destination: None,
        requested_port: None,
        hostname: None,
        presented_hostname: None,
        dns_attribution: None,
        hidden_sni: false,
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
    };
    denied_proxy_response(400, audit, context.max_response_bytes)
}

fn denied_proxy_response(
    status: u16,
    audit: AuditEvent,
    max_response_bytes: usize,
) -> HttpProxyRequestOutcome {
    match build_proxy_response(status, max_response_bytes) {
        Ok(response) => HttpProxyRequestOutcome::Respond { response, audit },
        Err(error) => HttpProxyRequestOutcome::Drop {
            audit,
            response_error: Some(error),
        },
    }
}

fn decision_response_status(decision: &Decision) -> u16 {
    match decision {
        Decision::Allow { .. } => 200,
        Decision::Deny { .. } => 403,
        Decision::FailClosed { .. } => 502,
    }
}

fn build_proxy_response(
    status: u16,
    max_response_bytes: usize,
) -> Result<Vec<u8>, HttpProxyResponseError> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        _ => "Proxy Response",
    };
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes();
    if response.len() > max_response_bytes {
        return Err(HttpProxyResponseError::ResponseTooLarge);
    }
    Ok(response)
}

fn starts_with_connect(wire: &[u8]) -> bool {
    wire.get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"CONNECT "))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::attribution::Hostname;
    use crate::config::{HostMatcher, PolicyRule, RuleAction};
    use crate::http::HttpParseError;
    use crate::policy::DenyBehavior;

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn context() -> HttpProxyRequestContext {
        HttpProxyRequestContext {
            timestamp_millis: 77,
            sandbox_id: SandboxId::new("sandbox-proxy"),
            source: Some(Endpoint::tcp(ip([10, 0, 0, 2]), 40000)),
            max_header_bytes: 1024,
            max_response_bytes: 256,
        }
    }

    #[test]
    fn allowed_http_proxy_requests_forward_with_policy_and_audit_metadata() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow_domain(
                "allow-http-api",
                HostMatcher::exact("api.example.com").unwrap(),
                Some(80),
            )
            .with_http_method("GET")
            .with_http_path_prefix("/v1/"),
        );
        let wire = b"GET http://api.example.com/v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let outcome = handle_http_proxy_request(wire, &config, context());
        let HttpProxyRequestOutcome::ForwardHttp {
            request,
            wire: forwarded,
            audit,
        } = outcome
        else {
            panic!("expected HTTP forward");
        };

        assert_eq!(forwarded, wire);
        assert_eq!(request.protocol, Protocol::Http);
        assert_eq!(request.frontend, Frontend::HttpProxy);
        assert_eq!(request.requested_port, Some(80));
        assert_eq!(request.http_method.as_deref(), Some("GET"));
        assert_eq!(request.http_path_query.as_deref(), Some("/v1/users"));
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-http-api"));
        assert_eq!(audit.http_method.as_deref(), Some("GET"));
    }

    #[test]
    fn denied_http_proxy_requests_return_forbidden_with_audit() {
        let config = PolicyConfig::default();
        let wire = b"GET http://api.example.com/admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let outcome = handle_http_proxy_request(wire, &config, context());
        let HttpProxyRequestOutcome::Respond { response, audit } = outcome else {
            panic!("expected deny response");
        };

        assert!(std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 403 Forbidden"));
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DefaultDeny));
        assert_eq!(audit.hostname.as_ref().unwrap().as_str(), "api.example.com");
        assert_eq!(audit.requested_port, Some(80));
    }

    #[test]
    fn allowed_connect_requests_establish_tunnel_with_authority_metadata() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-connect",
            HostMatcher::exact("secure.example.com").unwrap(),
            Some(443),
        ));
        let wire =
            b"CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n";

        let outcome = handle_http_proxy_request(wire, &config, context());
        let HttpProxyRequestOutcome::EstablishConnect {
            request,
            wire: forwarded,
            audit,
        } = outcome
        else {
            panic!("expected CONNECT tunnel");
        };

        assert_eq!(forwarded, wire);
        assert_eq!(request.protocol, Protocol::HttpsConnect);
        assert_eq!(request.frontend, Frontend::HttpProxy);
        assert_eq!(request.requested_port, Some(443));
        assert_eq!(
            request.attribution.hostname,
            Some(Hostname::parse("secure.example.com").unwrap())
        );
        assert_eq!(audit.kind, AuditEventKind::HttpsConnect);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-connect"));
    }

    #[test]
    fn malformed_connect_requests_fail_closed_with_bounded_response() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-connect",
            HostMatcher::exact("secure.example.com").unwrap(),
            Some(443),
        ));
        let wire = b"CONNECT secure.example.com HTTP/1.1\r\n\r\n";

        let outcome = handle_http_proxy_request(wire, &config, context());
        let HttpProxyRequestOutcome::Respond { response, audit } = outcome else {
            panic!("expected fail-closed response");
        };

        assert!(std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 400 Bad Request"));
        assert_eq!(audit.kind, AuditEventKind::HttpsConnect);
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
        assert_eq!(audit.hostname, None);
    }

    #[test]
    fn proxy_response_size_bounds_drop_instead_of_allocating_unbounded() {
        let config = PolicyConfig {
            default_action: RuleAction::Deny(DenyBehavior::Drop),
            ..PolicyConfig::default()
        };
        let mut tiny_context = context();
        tiny_context.max_response_bytes = 8;
        let wire = b"GET http://api.example.com/admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let outcome = handle_http_proxy_request(wire, &config, tiny_context);
        let HttpProxyRequestOutcome::Drop {
            audit,
            response_error,
        } = outcome
        else {
            panic!("expected bounded drop");
        };

        assert_eq!(
            response_error,
            Some(HttpProxyResponseError::ResponseTooLarge)
        );
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DefaultDeny));
    }

    #[test]
    fn unsupported_proxy_request_shape_fails_closed() {
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/1.1\r\n\r\n", 1024),
            Err(HttpParseError::MissingHost)
        );
        let outcome = handle_http_proxy_request(
            b"GET / HTTP/1.1\r\n\r\n",
            &PolicyConfig::default(),
            context(),
        );
        assert!(matches!(outcome, HttpProxyRequestOutcome::Respond { .. }));
    }
}
