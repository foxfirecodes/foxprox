use crate::attribution::Hostname;
use crate::audit::{AuditDecision, AuditEvent, AuditPolicyContext};
use crate::egress::{EgressPermit, EgressPermitError};
use crate::policy::{Decision, DenialReason, PolicyEngine, PolicyRequest};
use crate::quic::{parse_quic_candidate, QuicPacketMetadata, QuicParseError};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicInspectionContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub frontend: Frontend,
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub dns_attribution: Option<Hostname>,
    pub max_packet_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicInspectionOutcome {
    Allow {
        metadata: QuicPacketMetadata,
        permit: EgressPermit,
        audit: Box<AuditEvent>,
    },
    Drop {
        metadata: Option<QuicPacketMetadata>,
        parse_error: Option<QuicParseError>,
        permit_error: Option<EgressPermitError>,
        decision: Decision,
        audit: Box<AuditEvent>,
    },
}

pub fn handle_quic_candidate(
    payload: &[u8],
    config: &PolicyConfig,
    context: QuicInspectionContext,
) -> QuicInspectionOutcome {
    let metadata = match parse_quic_candidate(payload, context.max_packet_bytes) {
        Ok(metadata) => metadata,
        Err(error) => {
            let audit = malformed_quic_audit(&context);
            return QuicInspectionOutcome::Drop {
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

    let mut request = PolicyRequest::from_quic_candidate_metadata(
        context.frontend,
        context.destination,
        metadata.clone(),
        context.dns_attribution.clone(),
    );
    request.sandbox_id = context.sandbox_id.clone();
    request.source = context.source;
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_quic_candidate_metadata(
        AuditPolicyContext::from_request(
            context.timestamp_millis,
            crate::audit::AuditEventKind::QuicCandidateFlowCreated,
            &request,
        ),
        &metadata,
        &decision,
    );

    if decision.is_allow() {
        match EgressPermit::from_policy_decision(&request, &decision) {
            Ok(permit) => QuicInspectionOutcome::Allow {
                metadata,
                permit,
                audit: Box::new(audit),
            },
            Err(error) => QuicInspectionOutcome::Drop {
                metadata: Some(metadata),
                parse_error: None,
                permit_error: Some(error),
                decision,
                audit: Box::new(audit),
            },
        }
    } else {
        QuicInspectionOutcome::Drop {
            metadata: Some(metadata),
            parse_error: None,
            permit_error: None,
            decision,
            audit: Box::new(audit),
        }
    }
}

fn malformed_quic_audit(context: &QuicInspectionContext) -> AuditEvent {
    AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind: crate::audit::AuditEventKind::QuicCandidateFlowCreated,
        frontend: Some(context.frontend),
        protocol: Some(Protocol::QuicCandidate),
        source: context.source,
        destination: Some(context.destination),
        requested_port: context.destination.port,
        hostname: None,
        presented_hostname: None,
        dns_attribution: context.dns_attribution.clone(),
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

    use crate::audit::AuditEventKind;
    use crate::config::{Cidr, HostMatcher, PolicyRule};
    use crate::egress::EgressDestination;
    use crate::quic::{QuicHeaderForm, QuicLongPacketType};

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn context(dns_attribution: Option<&str>) -> QuicInspectionContext {
        QuicInspectionContext {
            timestamp_millis: 400,
            sandbox_id: SandboxId::new("sandbox-quic"),
            frontend: Frontend::Tun,
            source: Some(Endpoint::udp(ip([10, 0, 0, 2]), 40000)),
            destination: Endpoint::udp(ip([203, 0, 113, 10]), 443),
            dns_attribution: dns_attribution.map(|host| Hostname::parse(host).unwrap()),
            max_packet_bytes: 1200,
        }
    }

    fn quic_initial() -> Vec<u8> {
        vec![
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x04, 9, 10, 11, 12, 0,
        ]
    }

    #[test]
    fn dns_attributed_quic_domain_policy_allows_without_inventing_hostname_from_header() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-quic-domain",
            HostMatcher::exact("video.example.com").unwrap(),
            Some(443),
        ));

        let outcome =
            handle_quic_candidate(&quic_initial(), &config, context(Some("video.example.com")));
        let QuicInspectionOutcome::Allow {
            metadata,
            permit,
            audit,
        } = outcome
        else {
            panic!("expected QUIC allow");
        };

        assert_eq!(metadata.header_form, QuicHeaderForm::Long);
        assert_eq!(metadata.long_packet_type, Some(QuicLongPacketType::Initial));
        assert_eq!(
            permit.destination,
            EgressDestination::Ip(Endpoint::udp(ip([203, 0, 113, 10]), 443))
        );
        assert_eq!(audit.kind, AuditEventKind::QuicCandidateFlowCreated);
        assert_eq!(audit.hostname, None);
        assert_eq!(
            audit.dns_attribution.as_ref().unwrap().as_str(),
            "video.example.com"
        );
        assert_eq!(audit.quic_version, Some(1));
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
    }

    #[test]
    fn quic_domain_rules_default_deny_without_dns_attribution() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-quic-domain",
            HostMatcher::exact("video.example.com").unwrap(),
            Some(443),
        ));

        let outcome = handle_quic_candidate(&quic_initial(), &config, context(None));
        let QuicInspectionOutcome::Drop {
            decision, audit, ..
        } = outcome
        else {
            panic!("expected QUIC deny");
        };

        assert_eq!(decision.reason(), Some(DenialReason::DefaultDeny));
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: crate::policy::DenyBehavior::Drop
            })
        );
        assert_eq!(audit.quic_header_form, Some(QuicHeaderForm::Long));
    }

    #[test]
    fn explicit_ip_rules_can_allow_unattributed_quic_candidates() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-quic-ip",
            Cidr::host(ip([203, 0, 113, 10])),
            Some(443),
        ));

        let outcome = handle_quic_candidate(&quic_initial(), &config, context(None));
        let QuicInspectionOutcome::Allow { audit, .. } = outcome else {
            panic!("expected QUIC IP allow");
        };
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-quic-ip"));
        assert_eq!(audit.hostname, None);
    }

    #[test]
    fn malformed_quic_candidates_fail_closed_before_policy_or_egress() {
        let outcome = handle_quic_candidate(&[0x00], &PolicyConfig::default(), context(None));
        let QuicInspectionOutcome::Drop {
            metadata,
            parse_error,
            permit_error,
            decision,
            audit,
        } = outcome
        else {
            panic!("expected malformed QUIC drop");
        };

        assert_eq!(metadata, None);
        assert_eq!(parse_error, Some(QuicParseError::MissingFixedBit));
        assert_eq!(permit_error, None);
        assert_eq!(decision.reason(), Some(DenialReason::MalformedInput));
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
        assert_eq!(audit.quic_header_form, None);
    }
}
