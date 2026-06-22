use crate::audit::{AuditEvent, AuditEventKind, AuditPolicyContext};
use crate::packet::{parse_ip_packet, PacketParseError, PacketSummary};
use crate::policy::{Decision, PolicyEngine};
use crate::types::{Frontend, SandboxId};
use crate::PolicyConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunPacketContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunPacketOutcome {
    Forward {
        summary: PacketSummary,
        wire: Vec<u8>,
        decision: Decision,
        audit: Box<AuditEvent>,
    },
    Drop {
        summary: Option<PacketSummary>,
        parse_error: Option<PacketParseError>,
        decision: Decision,
        audit: Box<AuditEvent>,
    },
}

pub fn handle_tun_packet(
    wire: &[u8],
    config: &PolicyConfig,
    context: TunPacketContext,
) -> TunPacketOutcome {
    let summary = match parse_ip_packet(wire) {
        Ok(summary) => summary,
        Err(error) => {
            return TunPacketOutcome::Drop {
                summary: None,
                parse_error: Some(error),
                decision: Decision::FailClosed {
                    reason: crate::policy::DenialReason::MalformedInput,
                },
                audit: Box::new(AuditEvent::from_packet_parse_error(
                    context.timestamp_millis,
                    context.sandbox_id,
                    Frontend::Tun,
                    error,
                )),
            };
        }
    };

    let mut request = summary.to_policy_request();
    request.sandbox_id = context.sandbox_id.clone();
    request.frontend = Frontend::Tun;
    let decision = PolicyEngine::decide(config, &request);
    let audit = AuditEvent::from_policy_decision(
        AuditPolicyContext::from_request(
            context.timestamp_millis,
            AuditEventKind::from_protocol_for_packet(summary.protocol),
            &request,
        ),
        &decision,
    );

    if decision.is_allow() {
        TunPacketOutcome::Forward {
            summary,
            wire: wire.to_vec(),
            decision,
            audit: Box::new(audit),
        }
    } else {
        TunPacketOutcome::Drop {
            summary: Some(summary),
            parse_error: None,
            decision,
            audit: Box::new(audit),
        }
    }
}

trait PacketAuditKind {
    fn from_protocol_for_packet(protocol: crate::types::Protocol) -> Self;
}

impl PacketAuditKind for AuditEventKind {
    fn from_protocol_for_packet(protocol: crate::types::Protocol) -> Self {
        match protocol {
            crate::types::Protocol::Tcp | crate::types::Protocol::TlsSni => Self::TcpConnect,
            crate::types::Protocol::Udp | crate::types::Protocol::QuicCandidate => {
                Self::UdpFlowCreated
            }
            crate::types::Protocol::Dns => Self::DnsQuery,
            crate::types::Protocol::Icmp => Self::IcmpMessage,
            crate::types::Protocol::Http => Self::HttpRequest,
            crate::types::Protocol::Unsupported(_) => Self::UnsupportedNetworkEvent,
            crate::types::Protocol::HttpsConnect | crate::types::Protocol::Socks => {
                Self::UnsupportedNetworkEvent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::audit::AuditDecision;
    use crate::config::{Cidr, PolicyRule};
    use crate::policy::{DenialReason, DenyBehavior};
    use crate::types::{Endpoint, Protocol};

    use super::*;

    fn context() -> TunPacketContext {
        TunPacketContext {
            timestamp_millis: 200,
            sandbox_id: SandboxId::new("sandbox-tun"),
        }
    }

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    #[test]
    fn allowed_tun_tcp_packets_forward_with_audited_metadata() {
        let packet = ipv4_packet(6, &tcp_header(49152, 443));
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-web-ip",
            Cidr::host(ip([93, 184, 216, 34])),
            Some(443),
        ));

        let outcome = handle_tun_packet(&packet, &config, context());
        let TunPacketOutcome::Forward {
            summary,
            wire,
            decision,
            audit,
        } = outcome
        else {
            panic!("expected packet forward");
        };

        assert_eq!(wire, packet);
        assert_eq!(summary.protocol, Protocol::Tcp);
        assert_eq!(summary.destination_port, Some(443));
        assert!(decision.is_allow());
        assert_eq!(audit.kind, AuditEventKind::TcpConnect);
        assert_eq!(audit.decision, Some(AuditDecision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-web-ip"));
        assert_eq!(
            audit.destination,
            Some(Endpoint::tcp(ip([93, 184, 216, 34]), 443))
        );
    }

    #[test]
    fn direct_dns_bypass_packets_drop_before_allow_rules() {
        let packet = ipv4_packet(17, &udp_header(49152, 53));
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "allow-all",
            Cidr::new(ip([0, 0, 0, 0]), 0).unwrap(),
            None,
        ));

        let outcome = handle_tun_packet(&packet, &config, context());
        let TunPacketOutcome::Drop {
            summary,
            parse_error,
            decision,
            audit,
        } = outcome
        else {
            panic!("expected packet drop");
        };

        assert_eq!(summary.unwrap().protocol, Protocol::Dns);
        assert_eq!(parse_error, None);
        assert_eq!(decision.reason(), Some(DenialReason::DirectDnsBypass));
        assert_eq!(audit.kind, AuditEventKind::DnsQuery);
        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Drop
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DirectDnsBypass));
    }

    #[test]
    fn malformed_tun_packets_fail_closed_without_summary() {
        let mut packet = ipv4_packet(6, &tcp_header(49152, 443));
        packet[10] ^= 0xff;

        let outcome = handle_tun_packet(&packet, &PolicyConfig::default(), context());
        let TunPacketOutcome::Drop {
            summary,
            parse_error,
            decision,
            audit,
        } = outcome
        else {
            panic!("expected fail-closed drop");
        };

        assert_eq!(summary, None);
        assert_eq!(
            parse_error,
            Some(PacketParseError::InvalidIpv4HeaderChecksum)
        );
        assert_eq!(decision.reason(), Some(DenialReason::MalformedInput));
        assert_eq!(audit.kind, AuditEventKind::UnsupportedNetworkEvent);
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::MalformedInput));
    }

    #[test]
    fn unsupported_tun_protocol_packets_fail_closed_with_protocol_evidence() {
        let packet = ipv4_packet(99, &[]);
        let outcome = handle_tun_packet(&packet, &PolicyConfig::default(), context());
        let TunPacketOutcome::Drop {
            parse_error, audit, ..
        } = outcome
        else {
            panic!("expected unsupported drop");
        };

        assert_eq!(parse_error, Some(PacketParseError::UnsupportedProtocol(99)));
        assert_eq!(audit.protocol, Some(Protocol::Unsupported(99)));
        assert_eq!(audit.decision, Some(AuditDecision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::UnsupportedProtocol));
    }

    fn ipv4_packet(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total_len = 20 + transport.len();
        let mut packet = vec![
            0x45,
            0x00,
            ((total_len >> 8) & 0xff) as u8,
            (total_len & 0xff) as u8,
            0x12,
            0x34,
            0x00,
            0x00,
            64,
            protocol,
            0x00,
            0x00,
            10,
            0,
            0,
            2,
            93,
            184,
            216,
            34,
        ];
        let checksum = internet_checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(transport);
        match protocol {
            6 => set_tcp_checksum(&mut packet),
            17 => set_udp_checksum(&mut packet),
            _ => {}
        }
        packet
    }

    fn tcp_header(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut header = vec![0_u8; 20];
        header[0..2].copy_from_slice(&source_port.to_be_bytes());
        header[2..4].copy_from_slice(&destination_port.to_be_bytes());
        header[12] = 5 << 4;
        header[13] = 0x02;
        header
    }

    fn udp_header(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut header = vec![0_u8; 8];
        header[0..2].copy_from_slice(&source_port.to_be_bytes());
        header[2..4].copy_from_slice(&destination_port.to_be_bytes());
        header[4..6].copy_from_slice(&8_u16.to_be_bytes());
        header
    }

    fn set_tcp_checksum(packet: &mut [u8]) {
        let checksum = transport_checksum(packet, 6, 20);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    }

    fn set_udp_checksum(packet: &mut [u8]) {
        let checksum = transport_checksum(packet, 17, 20);
        packet[26..28].copy_from_slice(&checksum.to_be_bytes());
    }

    fn transport_checksum(packet: &[u8], protocol: u8, transport_offset: usize) -> u16 {
        let transport = &packet[transport_offset..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..16]);
        pseudo.extend_from_slice(&packet[16..20]);
        pseudo.push(0);
        pseudo.push(protocol);
        pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(transport);
        internet_checksum(&pseudo)
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from(chunk[0]) << 8
            };
            sum += u32::from(word);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
        }
        !(sum as u16)
    }
}
