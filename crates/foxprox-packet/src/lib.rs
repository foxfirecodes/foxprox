//! Platform-independent packet parsing for foxprox.
//!
//! This crate owns raw packet buffers only long enough to normalize them into
//! `foxprox-core` events. Policy code should consume the normalized events, not
//! packet bytes or parser-specific objects.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::Ipv4Addr;

use foxprox_core::{
    Endpoint, FrontendKind, IcmpMessage, NormalizedEvent, SandboxId, TcpConnectAttempt,
    UdpClassification, UdpFlowAttempt, UnsupportedNetworkEvent,
};

/// Context supplied by the frontend before packet bytes enter the parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketContext {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
}

impl PacketContext {
    pub const fn new(sandbox_id: SandboxId, frontend: FrontendKind) -> Self {
        Self {
            sandbox_id,
            frontend,
        }
    }
}

/// Packet parse/validation failure that must be handled fail-closed by callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketParseError {
    TooShort {
        actual: usize,
        minimum: usize,
    },
    NotIpv4 {
        version: u8,
    },
    InvalidHeaderLength {
        ihl_words: u8,
    },
    InvalidTotalLength {
        total_length: usize,
        header_length: usize,
    },
    TruncatedPacket {
        total_length: usize,
        actual: usize,
    },
    FragmentedIpv4 {
        flags_fragment_offset: u16,
    },
    TcpHeaderTooShort {
        actual: usize,
    },
    UdpHeaderTooShort {
        actual: usize,
    },
    IcmpHeaderTooShort {
        actual: usize,
    },
}

impl PacketParseError {
    pub fn fail_closed_reason(&self) -> String {
        match self {
            Self::TooShort { actual, minimum } => {
                format!("ipv4-packet-too-short: actual={actual} minimum={minimum}")
            }
            Self::NotIpv4 { version } => format!("not-ipv4: version={version}"),
            Self::InvalidHeaderLength { ihl_words } => {
                format!("invalid-ipv4-header-length: ihl_words={ihl_words}")
            }
            Self::InvalidTotalLength {
                total_length,
                header_length,
            } => format!(
                "invalid-ipv4-total-length: total_length={total_length} header_length={header_length}"
            ),
            Self::TruncatedPacket {
                total_length,
                actual,
            } => format!("truncated-ipv4-packet: total_length={total_length} actual={actual}"),
            Self::FragmentedIpv4 {
                flags_fragment_offset,
            } => format!(
                "unsupported-ipv4-fragmentation: flags_fragment_offset=0x{flags_fragment_offset:04x}"
            ),
            Self::TcpHeaderTooShort { actual } => {
                format!("tcp-header-too-short: actual={actual}")
            }
            Self::UdpHeaderTooShort { actual } => {
                format!("udp-header-too-short: actual={actual}")
            }
            Self::IcmpHeaderTooShort { actual } => {
                format!("icmp-header-too-short: actual={actual}")
            }
        }
    }
}

impl fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fail_closed_reason())
    }
}

impl std::error::Error for PacketParseError {}

/// Parse one IPv4 packet into a normalized event.
///
/// Unsupported protocol numbers and non-connect TCP packets become explicit
/// `UnsupportedNetworkEvent`s. Malformed or fragmented packets return a
/// `PacketParseError`, which callers can turn into an unsupported/fail-closed
/// event with [`parse_ipv4_packet_fail_closed`].
pub fn parse_ipv4_packet(
    context: &PacketContext,
    packet: &[u8],
) -> Result<NormalizedEvent, PacketParseError> {
    let header = Ipv4Header::parse(packet)?;
    let payload = &packet[header.header_length..header.total_length];

    match header.protocol {
        1 => parse_icmp(context, header, payload),
        6 => parse_tcp(context, header, payload),
        17 => parse_udp(context, header, payload),
        protocol => Ok(unsupported_event(
            context,
            Some(header.source_endpoint(None)),
            Some(header.destination_endpoint(None)),
            format!("unsupported-ipv4-protocol: {protocol}"),
        )),
    }
}

/// Parse an IPv4 packet and convert malformed input into an unsupported event
/// suitable for policy fail-closed evaluation.
pub fn parse_ipv4_packet_fail_closed(context: &PacketContext, packet: &[u8]) -> NormalizedEvent {
    match parse_ipv4_packet(context, packet) {
        Ok(event) => event,
        Err(error) => unsupported_event(context, None, None, error.fail_closed_reason()),
    }
}

fn parse_tcp(
    context: &PacketContext,
    header: Ipv4Header,
    payload: &[u8],
) -> Result<NormalizedEvent, PacketParseError> {
    if payload.len() < 20 {
        return Err(PacketParseError::TcpHeaderTooShort {
            actual: payload.len(),
        });
    }

    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let flags = payload[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;

    if !syn || ack {
        return Ok(unsupported_event(
            context,
            Some(header.source_endpoint(Some(source_port))),
            Some(header.destination_endpoint(Some(destination_port))),
            "tcp-packet-is-not-connect-attempt",
        ));
    }

    Ok(NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
        sandbox_id: context.sandbox_id.clone(),
        frontend: context.frontend,
        source: header.source_endpoint(Some(source_port)),
        destination: header.destination_endpoint(Some(destination_port)),
        attribution: None,
    }))
}

fn parse_udp(
    context: &PacketContext,
    header: Ipv4Header,
    payload: &[u8],
) -> Result<NormalizedEvent, PacketParseError> {
    if payload.len() < 8 {
        return Err(PacketParseError::UdpHeaderTooShort {
            actual: payload.len(),
        });
    }

    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let classification = match destination_port {
        53 => UdpClassification::Dns,
        443 => UdpClassification::QuicCandidate,
        _ => UdpClassification::Generic,
    };

    Ok(NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
        sandbox_id: context.sandbox_id.clone(),
        frontend: context.frontend,
        source: header.source_endpoint(Some(source_port)),
        destination: header.destination_endpoint(Some(destination_port)),
        classification,
        attribution: None,
    }))
}

fn parse_icmp(
    context: &PacketContext,
    header: Ipv4Header,
    payload: &[u8],
) -> Result<NormalizedEvent, PacketParseError> {
    if payload.len() < 2 {
        return Err(PacketParseError::IcmpHeaderTooShort {
            actual: payload.len(),
        });
    }

    Ok(NormalizedEvent::IcmpMessage(IcmpMessage {
        sandbox_id: context.sandbox_id.clone(),
        frontend: context.frontend,
        source: header.source_endpoint(None),
        destination: header.destination_endpoint(None),
        icmp_type: payload[0],
        icmp_code: payload[1],
    }))
}

fn unsupported_event(
    context: &PacketContext,
    source: Option<Endpoint>,
    destination: Option<Endpoint>,
    reason: impl Into<String>,
) -> NormalizedEvent {
    NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
        sandbox_id: context.sandbox_id.clone(),
        frontend: context.frontend,
        source,
        destination,
        reason: reason.into(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv4Header {
    header_length: usize,
    total_length: usize,
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

impl Ipv4Header {
    fn parse(packet: &[u8]) -> Result<Self, PacketParseError> {
        if packet.len() < 20 {
            return Err(PacketParseError::TooShort {
                actual: packet.len(),
                minimum: 20,
            });
        }

        let version = packet[0] >> 4;
        if version != 4 {
            return Err(PacketParseError::NotIpv4 { version });
        }

        let ihl_words = packet[0] & 0x0f;
        if ihl_words < 5 {
            return Err(PacketParseError::InvalidHeaderLength { ihl_words });
        }
        let header_length = usize::from(ihl_words) * 4;
        let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));

        if total_length < header_length {
            return Err(PacketParseError::InvalidTotalLength {
                total_length,
                header_length,
            });
        }
        if packet.len() < total_length {
            return Err(PacketParseError::TruncatedPacket {
                total_length,
                actual: packet.len(),
            });
        }
        if packet.len() < header_length {
            return Err(PacketParseError::TooShort {
                actual: packet.len(),
                minimum: header_length,
            });
        }

        let flags_fragment_offset = u16::from_be_bytes([packet[6], packet[7]]);
        let more_fragments = flags_fragment_offset & 0x2000 != 0;
        let fragment_offset = flags_fragment_offset & 0x1fff;
        if more_fragments || fragment_offset != 0 {
            return Err(PacketParseError::FragmentedIpv4 {
                flags_fragment_offset,
            });
        }

        Ok(Self {
            header_length,
            total_length,
            protocol: packet[9],
            source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        })
    }

    fn source_endpoint(self, port: Option<u16>) -> Endpoint {
        Endpoint::new(self.source.into(), port)
    }

    fn destination_endpoint(self, port: Option<u16>) -> Endpoint {
        Endpoint::new(self.destination.into(), port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        AuditDecision, AuditKind, DefaultPolicy, DenialBehavior, DnsPolicy, PolicyConfig,
        PolicyDecision, PolicyEngine, Protocol,
    };

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("packet-test").unwrap(), FrontendKind::Tun)
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

    fn tcp_syn_payload(source_port: u16, destination_port: u16) -> [u8; 20] {
        let mut payload = [0_u8; 20];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[12] = 5 << 4;
        payload[13] = 0x02;
        payload
    }

    fn udp_payload(source_port: u16, destination_port: u16) -> [u8; 8] {
        let mut payload = [0_u8; 8];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[4..6].copy_from_slice(&(8_u16).to_be_bytes());
        payload
    }

    #[test]
    fn parses_ipv4_tcp_syn_into_connect_attempt() {
        let packet = ipv4_packet(
            6,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &tcp_syn_payload(49152, 443),
        );

        let event = parse_ipv4_packet(&context(), &packet).unwrap();

        assert_eq!(event.protocol(), Protocol::Tcp);
        assert_eq!(
            event.source(),
            Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152))
        );
        assert_eq!(
            event.destination(),
            Some(Endpoint::tcp(Ipv4Addr::new(203, 0, 113, 10).into(), 443))
        );
    }

    #[test]
    fn parses_udp_dns_packet_and_policy_denies_direct_external_dns() {
        let packet = ipv4_packet(17, [10, 0, 0, 2], [8, 8, 8, 8], &udp_payload(53000, 53));
        let event = parse_ipv4_packet(&context(), &packet).unwrap();
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            dns: DnsPolicy {
                broker_resolvers: vec![Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53)],
                deny_direct_external_dns: true,
            },
            rules: Vec::new(),
        });

        let evaluation = engine.evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Dns);
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "direct-external-dns-denied".to_owned(),
                rule_id: None,
            }
        );
        assert_eq!(evaluation.audit.kind, AuditKind::UdpFlow);
        assert_eq!(evaluation.audit.decision, AuditDecision::Denied);
    }

    #[test]
    fn parses_udp_443_as_quic_candidate() {
        let packet = ipv4_packet(
            17,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &udp_payload(53000, 443),
        );

        let event = parse_ipv4_packet(&context(), &packet).unwrap();

        assert_eq!(event.protocol(), Protocol::QuicCandidate);
    }

    #[test]
    fn parses_icmp_message() {
        let packet = ipv4_packet(1, [10, 0, 0, 2], [203, 0, 113, 10], &[8, 0, 0, 0]);

        let event = parse_ipv4_packet(&context(), &packet).unwrap();

        assert_eq!(event.protocol(), Protocol::Icmp);
        match event {
            NormalizedEvent::IcmpMessage(message) => {
                assert_eq!(message.icmp_type, 8);
                assert_eq!(message.icmp_code, 0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn unsupported_ipv4_protocol_becomes_fail_closed_policy_event() {
        let packet = ipv4_packet(99, [10, 0, 0, 2], [203, 0, 113, 10], &[1, 2, 3, 4]);
        let event = parse_ipv4_packet(&context(), &packet).unwrap();
        let evaluation = PolicyEngine::new(PolicyConfig::default()).evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Unsupported);
        assert_eq!(
            evaluation.decision,
            PolicyDecision::FailClosed {
                reason: "unsupported-network-event: unsupported-ipv4-protocol: 99".to_owned()
            }
        );
        assert_eq!(evaluation.audit.decision, AuditDecision::FailClosed);
    }

    #[test]
    fn malformed_packet_can_be_converted_to_fail_closed_event() {
        let event = parse_ipv4_packet_fail_closed(&context(), &[0x45, 0, 0, 20]);
        let evaluation = PolicyEngine::new(PolicyConfig::default()).evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Unsupported);
        assert_eq!(evaluation.audit.kind, AuditKind::UnsupportedNetworkEvent);
        assert_eq!(evaluation.audit.decision, AuditDecision::FailClosed);
        assert_eq!(
            evaluation.decision,
            PolicyDecision::FailClosed {
                reason: "unsupported-network-event: ipv4-packet-too-short: actual=4 minimum=20"
                    .to_owned()
            }
        );
    }

    #[test]
    fn ipv4_fragmentation_is_rejected_before_normalization() {
        let mut packet = ipv4_packet(
            17,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &udp_payload(53000, 443),
        );
        packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());

        assert_eq!(
            parse_ipv4_packet(&context(), &packet),
            Err(PacketParseError::FragmentedIpv4 {
                flags_fragment_offset: 0x2000
            })
        );
        let event = parse_ipv4_packet_fail_closed(&context(), &packet);
        assert_eq!(event.protocol(), Protocol::Unsupported);
    }
}
