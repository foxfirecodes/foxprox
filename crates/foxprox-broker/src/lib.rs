//! Minimal broker orchestration that connects packet input to policy/audit and
//! packet output.
//!
//! This crate intentionally remains platform-independent. A Linux TUN frontend
//! can feed bytes into this handler later, but raw packet bytes do not cross into
//! policy code.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditDecision, IcmpMessage, NormalizedEvent, PolicyEngine, PolicyEvaluation, Protocol,
};
use foxprox_packet::{
    parse_ipv4_packet, parse_ipv4_packet_fail_closed, synthesize_icmp_echo_reply, PacketContext,
};

/// Result of processing one inbound IPv4 packet from a frontend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketProcessingResult {
    pub evaluation: PolicyEvaluation,
    pub outbound_packets: Vec<Vec<u8>>,
    pub reply_error: Option<String>,
}

/// Platform-independent packet broker for one sandbox/session policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4PacketBroker {
    policy: PolicyEngine,
}

impl Ipv4PacketBroker {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    /// Process a single IPv4 packet and return audit plus any synthesized
    /// outbound packet(s).
    pub fn process_packet(&self, context: &PacketContext, packet: &[u8]) -> PacketProcessingResult {
        let event = match parse_ipv4_packet(context, packet) {
            Ok(event) => event,
            Err(_) => parse_ipv4_packet_fail_closed(context, packet),
        };
        let evaluation = self.policy.evaluate(&event);

        let mut outbound_packets = Vec::new();
        let mut reply_error = None;
        if should_synthesize_echo_reply(&event, &evaluation) {
            match synthesize_icmp_echo_reply(packet) {
                Ok(reply) => outbound_packets.push(reply),
                Err(error) => reply_error = Some(error.to_string()),
            }
        }

        PacketProcessingResult {
            evaluation,
            outbound_packets,
            reply_error,
        }
    }
}

fn should_synthesize_echo_reply(event: &NormalizedEvent, evaluation: &PolicyEvaluation) -> bool {
    if evaluation.audit.decision != AuditDecision::Allowed || event.protocol() != Protocol::Icmp {
        return false;
    }
    matches!(
        event,
        NormalizedEvent::IcmpMessage(IcmpMessage {
            icmp_type: 8,
            icmp_code: 0,
            ..
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        AuditDecision, DenialBehavior, Endpoint, FrontendKind, PolicyConfig, PolicyDecision,
        PolicyRule, RuleAction, SandboxId,
    };
    use foxprox_packet::parse_ipv4_packet;
    use std::net::Ipv4Addr;

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("broker-test").unwrap(), FrontendKind::Tun)
    }

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_length = 20 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn echo_request_packet() -> Vec<u8> {
        ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            b"\x08\x00\x00\x00\xab\xcd\x00\x01payload",
        )
    }

    fn allow_icmp_broker() -> Ipv4PacketBroker {
        let rule = PolicyRule::new("allow-icmp", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Icmp);
        Ipv4PacketBroker::new(PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        }))
    }

    #[test]
    fn allowed_icmp_echo_request_emits_audit_and_reply_packet() {
        let broker = allow_icmp_broker();
        let request = echo_request_packet();

        let result = broker.process_packet(&context(), &request);

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-icmp".to_owned())
            }
        );
        assert_eq!(result.evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(result.evaluation.audit.protocol, Protocol::Icmp);
        assert_eq!(result.outbound_packets.len(), 1);
        assert_eq!(result.reply_error, None);

        let reply_event = parse_ipv4_packet(&context(), &result.outbound_packets[0]).unwrap();
        assert_eq!(reply_event.protocol(), Protocol::Icmp);
        assert_eq!(
            reply_event.source(),
            Some(Endpoint::new(Ipv4Addr::new(203, 0, 113, 10).into(), None))
        );
        assert_eq!(
            reply_event.destination(),
            Some(Endpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), None))
        );
        match reply_event {
            NormalizedEvent::IcmpMessage(message) => {
                assert_eq!(message.icmp_type, 0);
                assert_eq!(message.icmp_code, 0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn denied_icmp_echo_request_is_audited_without_reply() {
        let broker = Ipv4PacketBroker::new(PolicyEngine::new(PolicyConfig::default()));

        let result = broker.process_packet(&context(), &echo_request_packet());

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "icmp-default-deny".to_owned(),
                rule_id: None,
            }
        );
        assert_eq!(result.evaluation.audit.decision, AuditDecision::Denied);
        assert!(result.outbound_packets.is_empty());
        assert_eq!(result.reply_error, None);
    }

    #[test]
    fn malformed_packet_is_audited_fail_closed_without_reply() {
        let broker = allow_icmp_broker();

        let result = broker.process_packet(&context(), &[0x45, 0, 0, 20]);

        assert_eq!(result.evaluation.audit.decision, AuditDecision::FailClosed);
        assert_eq!(result.evaluation.audit.protocol, Protocol::Unsupported);
        assert!(result.outbound_packets.is_empty());
    }

    #[test]
    fn non_echo_icmp_is_allowed_but_does_not_synthesize_reply() {
        let broker = allow_icmp_broker();
        let destination_unreachable = ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &[3, 0, 0, 0, 0, 0, 0, 0],
        );

        let result = broker.process_packet(&context(), &destination_unreachable);

        assert_eq!(result.evaluation.audit.decision, AuditDecision::Allowed);
        assert!(result.outbound_packets.is_empty());
        assert_eq!(result.reply_error, None);
    }
}
