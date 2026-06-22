use crate::attribution::Hostname;
use crate::audit::{AuditDecision, AuditEvent, AuditEventKind, AuditPolicyContext};
use crate::egress::{EgressPermit, EgressPermitError};
use crate::policy::{Decision, DenialReason, PolicyEngine, PolicyRequest};
use crate::tls::{parse_tls_client_hello, TlsClientHelloMetadata, TlsParseError};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsInspectionContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub frontend: Frontend,
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub dns_attribution: Option<Hostname>,
    pub max_client_hello_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsInspectionOutcome {
    Allow {
        metadata: TlsClientHelloMetadata,
        permit: EgressPermit,
        audit: Box<AuditEvent>,
    },
    Drop {
        metadata: Option<TlsClientHelloMetadata>,
        parse_error: Option<TlsParseError>,
        permit_error: Option<EgressPermitError>,
        decision: Decision,
        audit: Box<AuditEvent>,
    },
}

pub fn handle_tls_client_hello(
    wire: &[u8],
    config: &PolicyConfig,
    context: TlsInspectionContext,
) -> TlsInspectionOutcome {
    let metadata = match parse_tls_client_hello(wire, context.max_client_hello_bytes) {
        Ok(metadata) => metadata,
        Err(error) => {
            let audit = malformed_tls_audit(&context);
            return TlsInspectionOutcome::Drop {
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

    let mut request = PolicyRequest::from_tls_client_hello_metadata(
        context.frontend,
        context.destination,
        metadata.clone(),
        context.dns_attribution.clone(),
    );
    request.sandbox_id = context.sandbox_id.clone();
    request.source = context.source;
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_policy_decision(
        AuditPolicyContext::from_request(
            context.timestamp_millis,
            AuditEventKind::TlsClientHello,
            &request,
        ),
        &decision,
    );

    if decision.is_allow() {
        match EgressPermit::from_policy_decision(&request, &decision) {
            Ok(permit) => TlsInspectionOutcome::Allow {
                metadata,
                permit,
                audit: Box::new(audit),
            },
            Err(error) => TlsInspectionOutcome::Drop {
                metadata: Some(metadata),
                parse_error: None,
                permit_error: Some(error),
                decision,
                audit: Box::new(audit),
            },
        }
    } else {
        TlsInspectionOutcome::Drop {
            metadata: Some(metadata),
            parse_error: None,
            permit_error: None,
            decision,
            audit: Box::new(audit),
        }
    }
}

fn malformed_tls_audit(context: &TlsInspectionContext) -> AuditEvent {
    AuditEvent {
        timestamp_millis: context.timestamp_millis,
        sandbox_id: context.sandbox_id.clone(),
        kind: AuditEventKind::TlsClientHello,
        frontend: Some(context.frontend),
        protocol: Some(Protocol::TlsSni),
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

    use crate::config::{Cidr, HostMatcher, PolicyRule};
    use crate::egress::EgressDestination;

    use super::*;

    const EXT_SERVER_NAME: u16 = 0;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn context(dns_attribution: Option<&str>) -> TlsInspectionContext {
        TlsInspectionContext {
            timestamp_millis: 300,
            sandbox_id: SandboxId::new("sandbox-tls"),
            frontend: Frontend::Tun,
            source: Some(Endpoint::tcp(ip([10, 0, 0, 2]), 40000)),
            destination: Endpoint::tcp(ip([203, 0, 113, 10]), 443),
            dns_attribution: dns_attribution.map(|host| Hostname::parse(host).unwrap()),
            max_client_hello_bytes: 4096,
        }
    }

    #[test]
    fn visible_sni_allows_with_shared_policy_audit_and_egress_permit() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_domain(
            "allow-tls-sni",
            HostMatcher::exact("secure.example.com").unwrap(),
            Some(443),
        ));
        let wire = client_hello(&[sni_extension("secure.example.com")]);

        let outcome = handle_tls_client_hello(&wire, &config, context(None));
        let TlsInspectionOutcome::Allow {
            metadata,
            permit,
            audit,
        } = outcome
        else {
            panic!("expected TLS allow");
        };

        assert_eq!(metadata.sni.unwrap().as_str(), "secure.example.com");
        assert_eq!(
            permit.destination,
            EgressDestination::Ip(Endpoint::tcp(ip([203, 0, 113, 10]), 443))
        );
        assert_eq!(audit.kind, AuditEventKind::TlsClientHello);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(
            audit.hostname.as_ref().unwrap().as_str(),
            "secure.example.com"
        );
        assert_eq!(
            audit.presented_hostname.as_ref().unwrap().as_str(),
            "secure.example.com"
        );
        assert!(!audit.hidden_sni);
    }

    #[test]
    fn sni_dns_mismatch_denies_with_both_names_in_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-ip-would-match",
            Cidr::host(ip([203, 0, 113, 10])),
            Some(443),
        ));
        let wire = client_hello(&[sni_extension("evil.example")]);

        let outcome = handle_tls_client_hello(&wire, &config, context(Some("good.example")));
        let TlsInspectionOutcome::Drop {
            decision, audit, ..
        } = outcome
        else {
            panic!("expected mismatch drop");
        };

        assert_eq!(decision.reason(), Some(DenialReason::AttributionMismatch));
        assert_eq!(
            audit.presented_hostname.as_ref().unwrap().as_str(),
            "evil.example"
        );
        assert_eq!(
            audit.dns_attribution.as_ref().unwrap().as_str(),
            "good.example"
        );
        assert_eq!(audit.reason, Some(DenialReason::AttributionMismatch));
    }

    #[test]
    fn hidden_sni_denies_unless_explicit_ip_rule_allows() {
        let wire = client_hello(&[]);
        let denied = handle_tls_client_hello(&wire, &PolicyConfig::default(), context(None));
        let TlsInspectionOutcome::Drop {
            decision, audit, ..
        } = denied
        else {
            panic!("expected hidden SNI denial");
        };
        assert_eq!(decision.reason(), Some(DenialReason::HiddenSni));
        assert!(audit.hidden_sni);

        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-hidden-ip",
            Cidr::host(ip([203, 0, 113, 10])),
            Some(443),
        ));
        let allowed = handle_tls_client_hello(&wire, &config, context(None));
        let TlsInspectionOutcome::Allow { audit, .. } = allowed else {
            panic!("expected hidden SNI IP allow");
        };
        assert!(audit.hidden_sni);
        assert_eq!(audit.rule_id.as_deref(), Some("allow-hidden-ip"));
    }

    #[test]
    fn malformed_clienthello_fails_closed_before_policy_or_egress() {
        let outcome = handle_tls_client_hello(&[22, 3], &PolicyConfig::default(), context(None));
        let TlsInspectionOutcome::Drop {
            metadata,
            parse_error,
            permit_error,
            decision,
            audit,
        } = outcome
        else {
            panic!("expected malformed TLS drop");
        };

        assert_eq!(metadata, None);
        assert_eq!(parse_error, Some(TlsParseError::Incomplete));
        assert_eq!(permit_error, None);
        assert_eq!(decision.reason(), Some(DenialReason::MalformedInput));
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
    }

    fn sni_extension(hostname: &str) -> Vec<u8> {
        let host = hostname.as_bytes();
        let mut list = Vec::new();
        list.push(0);
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);

        let mut data = Vec::new();
        data.extend_from_slice(&(list.len() as u16).to_be_bytes());
        data.extend_from_slice(&list);
        extension(EXT_SERVER_NAME, &data)
    }

    fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&extension_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x002fu16.to_be_bytes());
        body.push(1);
        body.push(0);

        let extensions_len: usize = extensions.iter().map(Vec::len).sum();
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        for extension in extensions {
            body.extend_from_slice(extension);
        }

        let mut handshake = vec![
            1,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
