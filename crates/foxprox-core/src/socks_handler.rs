use crate::audit::{AuditDecision, AuditEvent, AuditEventKind, AuditPolicyContext};
use crate::policy::{Decision, DenialReason, PolicyEngine, PolicyRequest};
use crate::socks::{parse_socks5_connect_request, parse_socks5_greeting, Socks5Greeting};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Context {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub source: Option<Endpoint>,
    pub max_message_bytes: usize,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5GreetingOutcome {
    Accept {
        greeting: Socks5Greeting,
        response: Vec<u8>,
    },
    Reject {
        response: Vec<u8>,
    },
    Drop {
        response_error: Option<Socks5ResponseError>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5ConnectOutcome {
    Connect {
        request: Box<PolicyRequest>,
        wire: Vec<u8>,
        audit: Box<AuditEvent>,
    },
    Respond {
        response: Vec<u8>,
        audit: Box<AuditEvent>,
    },
    Drop {
        audit: Box<AuditEvent>,
        response_error: Option<Socks5ResponseError>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Socks5ResponseError {
    ResponseTooLarge,
}

pub fn handle_socks5_greeting(wire: &[u8], context: &Socks5Context) -> Socks5GreetingOutcome {
    match parse_socks5_greeting(wire, context.max_message_bytes) {
        Ok(greeting) => match build_socks5_method_response(0x00, context.max_response_bytes) {
            Ok(response) => Socks5GreetingOutcome::Accept { greeting, response },
            Err(error) => Socks5GreetingOutcome::Drop {
                response_error: Some(error),
            },
        },
        Err(_) => match build_socks5_method_response(0xff, context.max_response_bytes) {
            Ok(response) => Socks5GreetingOutcome::Reject { response },
            Err(error) => Socks5GreetingOutcome::Drop {
                response_error: Some(error),
            },
        },
    }
}

pub fn handle_socks5_connect(
    wire: &[u8],
    config: &PolicyConfig,
    context: Socks5Context,
) -> Socks5ConnectOutcome {
    let metadata = match parse_socks5_connect_request(wire, context.max_message_bytes) {
        Ok(metadata) => metadata,
        Err(_) => return malformed_socks_connect(&context),
    };
    let mut request = PolicyRequest::from_socks5_connect_metadata(metadata);
    request.sandbox_id = context.sandbox_id.clone();
    request.source = context.source;
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_policy_decision(
        AuditPolicyContext::from_request(
            context.timestamp_millis,
            AuditEventKind::SocksConnect,
            &request,
        ),
        &decision,
    );

    if decision.is_allow() {
        Socks5ConnectOutcome::Connect {
            request: Box::new(request),
            wire: wire.to_vec(),
            audit: Box::new(audit),
        }
    } else {
        socks_connect_response(
            decision_reply_code(&decision),
            audit,
            context.max_response_bytes,
        )
    }
}

fn malformed_socks_connect(context: &Socks5Context) -> Socks5ConnectOutcome {
    let audit = AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind: AuditEventKind::SocksConnect,
        frontend: Some(Frontend::Socks5),
        protocol: Some(Protocol::Socks),
        source: context.source,
        destination: None,
        requested_port: None,
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
    };
    socks_connect_response(0x01, audit, context.max_response_bytes)
}

fn socks_connect_response(
    reply_code: u8,
    audit: AuditEvent,
    max_response_bytes: usize,
) -> Socks5ConnectOutcome {
    match build_socks5_connect_response(reply_code, max_response_bytes) {
        Ok(response) => Socks5ConnectOutcome::Respond {
            response,
            audit: Box::new(audit),
        },
        Err(error) => Socks5ConnectOutcome::Drop {
            audit: Box::new(audit),
            response_error: Some(error),
        },
    }
}

fn decision_reply_code(decision: &Decision) -> u8 {
    match decision {
        Decision::Allow { .. } => 0x00,
        Decision::Deny { .. } => 0x02,
        Decision::FailClosed { .. } => 0x01,
    }
}

fn build_socks5_method_response(
    method: u8,
    max_response_bytes: usize,
) -> Result<Vec<u8>, Socks5ResponseError> {
    bounded_response(vec![0x05, method], max_response_bytes)
}

fn build_socks5_connect_response(
    reply_code: u8,
    max_response_bytes: usize,
) -> Result<Vec<u8>, Socks5ResponseError> {
    bounded_response(
        vec![
            0x05, reply_code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        max_response_bytes,
    )
}

fn bounded_response(
    response: Vec<u8>,
    max_response_bytes: usize,
) -> Result<Vec<u8>, Socks5ResponseError> {
    if response.len() > max_response_bytes {
        return Err(Socks5ResponseError::ResponseTooLarge);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::attribution::Hostname;
    use crate::config::{Cidr, HostMatcher, PolicyRule, RuleAction};
    use crate::policy::DenyBehavior;

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn context() -> Socks5Context {
        Socks5Context {
            timestamp_millis: 88,
            sandbox_id: SandboxId::new("sandbox-socks"),
            source: Some(Endpoint::tcp(ip([10, 0, 0, 2]), 41000)),
            max_message_bytes: 512,
            max_response_bytes: 64,
        }
    }

    fn domain_connect(host: &str, port: u16) -> Vec<u8> {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        bytes.extend_from_slice(host.as_bytes());
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes
    }

    #[test]
    fn socks5_greeting_selects_no_auth_or_rejects_without_unbounded_response() {
        let accepted = handle_socks5_greeting(&[0x05, 0x01, 0x00], &context());
        assert_eq!(
            accepted,
            Socks5GreetingOutcome::Accept {
                greeting: Socks5Greeting {
                    selected_method: crate::socks::Socks5AuthMethod::NoAuthentication
                },
                response: vec![0x05, 0x00]
            }
        );

        let rejected = handle_socks5_greeting(&[0x05, 0x01, 0x02], &context());
        assert_eq!(
            rejected,
            Socks5GreetingOutcome::Reject {
                response: vec![0x05, 0xff]
            }
        );

        let mut tiny = context();
        tiny.max_response_bytes = 1;
        assert_eq!(
            handle_socks5_greeting(&[0x05, 0x01, 0x00], &tiny),
            Socks5GreetingOutcome::Drop {
                response_error: Some(Socks5ResponseError::ResponseTooLarge)
            }
        );
    }

    #[test]
    fn allowed_socks_domain_connect_uses_shared_policy_and_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-socks-domain",
            HostMatcher::exact("example.com").unwrap(),
            Some(443),
        ));
        let wire = domain_connect("example.com", 443);

        let outcome = handle_socks5_connect(&wire, &config, context());
        let Socks5ConnectOutcome::Connect {
            request,
            wire: forwarded,
            audit,
        } = outcome
        else {
            panic!("expected socks connect");
        };

        assert_eq!(forwarded, wire);
        assert_eq!(request.protocol, Protocol::Socks);
        assert_eq!(request.frontend, Frontend::Socks5);
        assert_eq!(request.requested_port, Some(443));
        assert_eq!(
            request.attribution.hostname,
            Some(Hostname::parse("example.com").unwrap())
        );
        assert_eq!(audit.kind, AuditEventKind::SocksConnect);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-socks-domain"));
    }

    #[test]
    fn denied_socks_ip_connect_returns_failure_with_ip_only_audit() {
        let config = PolicyConfig::default();
        let wire = [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 10, 0x01, 0xbb];

        let outcome = handle_socks5_connect(&wire, &config, context());
        let Socks5ConnectOutcome::Respond { response, audit } = outcome else {
            panic!("expected socks deny response");
        };

        assert_eq!(response[1], 0x02);
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DefaultDeny));
        assert_eq!(
            audit.destination,
            Some(Endpoint::tcp(ip([203, 0, 113, 10]), 443))
        );
        assert_eq!(audit.hostname_source, HostnameSource::IpOnly);
        assert_eq!(audit.hostname_confidence, HostnameConfidence::Low);
    }

    #[test]
    fn malformed_or_unsupported_socks_connect_fails_closed() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-all",
            Cidr::new(ip([0, 0, 0, 0]), 0).unwrap(),
            None,
        ));
        let bind_request = [0x05, 0x02, 0x00, 0x01, 203, 0, 113, 10, 0x01, 0xbb];

        let outcome = handle_socks5_connect(&bind_request, &config, context());
        let Socks5ConnectOutcome::Respond { response, audit } = outcome else {
            panic!("expected fail-closed response");
        };

        assert_eq!(response[1], 0x01);
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
        assert_eq!(audit.destination, None);
    }

    #[test]
    fn socks_connect_response_size_bounds_drop_with_audit() {
        let config = PolicyConfig {
            default_action: RuleAction::Deny(DenyBehavior::Drop),
            ..PolicyConfig::default()
        };
        let mut tiny = context();
        tiny.max_response_bytes = 4;
        let wire = domain_connect("example.com", 443);

        let outcome = handle_socks5_connect(&wire, &config, tiny);
        let Socks5ConnectOutcome::Drop {
            audit,
            response_error,
        } = outcome
        else {
            panic!("expected bounded drop");
        };

        assert_eq!(response_error, Some(Socks5ResponseError::ResponseTooLarge));
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DefaultDeny));
    }
}
