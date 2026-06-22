//! Minimal broker orchestration that connects packet input to policy/audit and
//! packet output.
//!
//! This crate intentionally remains platform-independent. A Linux TUN frontend
//! can feed bytes into this handler later, but raw packet bytes do not cross into
//! policy code.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditDecision, IcmpMessage, NormalizedEvent, PolicyEngine, PolicyEvaluation, Protocol,
    UnsupportedNetworkEvent,
};
use foxprox_packet::{
    parse_ipv4_packet, parse_ipv4_packet_fail_closed, parse_ipv6_packet,
    parse_ipv6_packet_fail_closed, synthesize_icmp_echo_reply, PacketContext,
};

/// Result of processing one inbound IP packet from a frontend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketProcessingResult {
    pub evaluation: PolicyEvaluation,
    pub outbound_packets: Vec<Vec<u8>>,
    pub reply_error: Option<String>,
}

/// Platform-independent packet broker for one sandbox/session policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPacketBroker {
    policy: PolicyEngine,
}

impl IpPacketBroker {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    /// Process a single IPv4 or IPv6 packet and return audit plus any
    /// synthesized outbound packet(s).
    pub fn process_packet(&self, context: &PacketContext, packet: &[u8]) -> PacketProcessingResult {
        let event = parse_ip_packet_fail_closed(context, packet);
        let evaluation = self.policy.evaluate(&event);

        let mut outbound_packets = Vec::new();
        let mut reply_error = None;
        if should_synthesize_ipv4_echo_reply(&event, &evaluation) {
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

/// Compatibility wrapper for callers that have already constrained input to
/// IPv4. New runtime code should prefer [`IpPacketBroker`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4PacketBroker {
    inner: IpPacketBroker,
}

impl Ipv4PacketBroker {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            inner: IpPacketBroker::new(policy),
        }
    }

    /// Process a single IPv4 packet and return audit plus any synthesized
    /// outbound packet(s).
    pub fn process_packet(&self, context: &PacketContext, packet: &[u8]) -> PacketProcessingResult {
        self.inner.process_packet(context, packet)
    }
}

fn parse_ip_packet_fail_closed(context: &PacketContext, packet: &[u8]) -> NormalizedEvent {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => match parse_ipv4_packet(context, packet) {
            Ok(event) => event,
            Err(_) => parse_ipv4_packet_fail_closed(context, packet),
        },
        Some(6) => match parse_ipv6_packet(context, packet) {
            Ok(event) => event,
            Err(_) => parse_ipv6_packet_fail_closed(context, packet),
        },
        Some(version) => NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
            sandbox_id: context.sandbox_id.clone(),
            frontend: context.frontend,
            source: None,
            destination: None,
            reason: format!("unsupported-ip-version: {version}"),
        }),
        None => NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
            sandbox_id: context.sandbox_id.clone(),
            frontend: context.frontend,
            source: None,
            destination: None,
            reason: "ip-packet-too-short: actual=0 minimum=1".to_owned(),
        }),
    }
}

fn should_synthesize_ipv4_echo_reply(
    event: &NormalizedEvent,
    evaluation: &PolicyEvaluation,
) -> bool {
    if evaluation.audit.decision != AuditDecision::Allowed || event.protocol() != Protocol::Icmp {
        return false;
    }
    matches!(
        event,
        NormalizedEvent::IcmpMessage(IcmpMessage {
            source,
            destination,
            icmp_type: 8,
            icmp_code: 0,
            ..
        }) if source.ip.is_ipv4() && destination.ip.is_ipv4()
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    fn ipv6_packet(
        next_header: u8,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0_u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn icmpv6_destination_unreachable_packet() -> Vec<u8> {
        ipv6_packet(
            58,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            &[1, 0, 0, 0, 0, 0, 0, 0],
        )
    }

    fn icmpv6_echo_request_packet() -> Vec<u8> {
        ipv6_packet(
            58,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            &[128, 0, 0, 0, 0xab, 0xcd, 0, 1],
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

    #[test]
    fn ip_broker_dispatches_ipv6_icmpv6_without_ipv4_reply_synthesis() {
        let broker = IpPacketBroker::new(PolicyEngine::new(PolicyConfig::default()));

        let result = broker.process_packet(&context(), &icmpv6_destination_unreachable_packet());

        assert_eq!(result.evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(result.evaluation.audit.protocol, Protocol::Icmp);
        assert!(result.outbound_packets.is_empty());
        assert_eq!(result.reply_error, None);
    }

    #[test]
    fn ip_broker_does_not_synthesize_ipv4_echo_reply_for_icmpv6_echo() {
        let broker = IpPacketBroker::new(PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule::new("allow-icmp", RuleAction::Allow)
                .unwrap()
                .with_protocol(Protocol::Icmp)],
            ..PolicyConfig::default()
        }));

        let result = broker.process_packet(&context(), &icmpv6_echo_request_packet());

        assert_eq!(result.evaluation.audit.decision, AuditDecision::Allowed);
        assert!(result.outbound_packets.is_empty());
        assert_eq!(result.reply_error, None);
    }

    #[test]
    fn ip_broker_fails_closed_on_unknown_or_empty_ip_version() {
        let broker = IpPacketBroker::new(PolicyEngine::new(PolicyConfig::default()));

        for packet in [&[][..], &[0xf0][..]] {
            let result = broker.process_packet(&context(), packet);
            assert_eq!(result.evaluation.audit.decision, AuditDecision::FailClosed);
            assert_eq!(result.evaluation.audit.protocol, Protocol::Unsupported);
            assert!(result.outbound_packets.is_empty());
        }
    }
}
