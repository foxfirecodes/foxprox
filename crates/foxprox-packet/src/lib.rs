//! Minimal packet parser/synthesizer for alpha write-back proofs.
//!
//! Raw packet buffers terminate in this crate. Policy and audit receive only
//! normalized `foxprox-core` events, and outbound packets remain opaque bytes.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use foxprox_core::{
    classify_udp_destination, DenialAction, FrontendKind, IcmpMessage, NormalizedEvent,
    PolicyDecision, SandboxId, TcpConnectAttempt, UdpFlowAttempt, UnsupportedNetworkEvent,
    UnsupportedReason,
};

/// Result of inspecting one inbound IP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketInspection {
    pub event: NormalizedEvent,
    pub synthetic_reply: Option<SyntheticIpPacket>,
    pub udp_payload: Option<Vec<u8>>,
}

/// Opaque synthetic IP packet to write back to the device frontend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticIpPacket {
    bytes: Vec<u8>,
}

impl SyntheticIpPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv4Header {
    ihl: usize,
    total_len: usize,
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv6Header {
    payload_len: usize,
    next_header: u8,
    source: Ipv6Addr,
    destination: Ipv6Addr,
}

/// Inspect an IPv4 packet and normalize the policy-relevant alpha metadata.
///
/// The packet boundary exposes TCP connect attempts, UDP flow attempts, ICMP
/// message metadata, and fail-closed unsupported events. It does not expose raw
/// headers or parser-specific structs to policy/audit layers.
pub fn inspect_ipv4_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> PacketInspection {
    match inspect_ipv4_packet_inner(sandbox_id.clone(), frontend, bytes) {
        Ok(inspection) => inspection,
        Err(error) => PacketInspection {
            event: NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
                sandbox_id,
                frontend,
                reason: error.reason,
                safe_metadata: error.safe_metadata,
            }),
            synthetic_reply: None,
            udp_payload: None,
        },
    }
}

fn inspect_ipv4_packet_inner(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> Result<PacketInspection, PacketError> {
    let header = parse_ipv4_header(bytes)?;
    match header.protocol {
        1 => inspect_icmp_packet(sandbox_id, frontend, bytes, header),
        6 => inspect_tcp_packet(sandbox_id, frontend, bytes, header),
        17 => inspect_udp_packet(sandbox_id, frontend, bytes, header),
        protocol => Err(PacketError {
            reason: UnsupportedReason::UnsupportedIpProtocol(protocol),
            safe_metadata: Some(format!("ipv4 protocol {protocol}")),
        }),
    }
}

/// Inspect an IPv6 packet and normalize the policy-relevant alpha metadata.
///
/// Extension headers are intentionally fail-closed in alpha; support can be
/// widened inside this packet boundary without changing policy/audit contracts.
pub fn inspect_ipv6_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> PacketInspection {
    match inspect_ipv6_packet_inner(sandbox_id.clone(), frontend, bytes) {
        Ok(inspection) => inspection,
        Err(error) => PacketInspection {
            event: NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
                sandbox_id,
                frontend,
                reason: error.reason,
                safe_metadata: error.safe_metadata,
            }),
            synthetic_reply: None,
            udp_payload: None,
        },
    }
}

fn inspect_ipv6_packet_inner(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> Result<PacketInspection, PacketError> {
    let header = parse_ipv6_header(bytes)?;
    match header.next_header {
        6 => inspect_tcp_ipv6_packet(sandbox_id, frontend, bytes, header),
        17 => inspect_udp_ipv6_packet(sandbox_id, frontend, bytes, header),
        58 => inspect_icmpv6_packet(sandbox_id, frontend, bytes, header),
        next_header => Err(PacketError {
            reason: UnsupportedReason::UnsupportedIpProtocol(next_header),
            safe_metadata: Some(format!("ipv6 next_header {next_header}")),
        }),
    }
}

fn parse_ipv4_header(bytes: &[u8]) -> Result<Ipv4Header, PacketError> {
    if bytes.len() < 20 {
        return Err(PacketError::malformed("short IPv4 header"));
    }
    let version = bytes[0] >> 4;
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if version != 4 || ihl < 20 || bytes.len() < ihl {
        return Err(PacketError::malformed("invalid IPv4 header"));
    }
    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < ihl || total_len > bytes.len() {
        return Err(PacketError::malformed("invalid IPv4 total length"));
    }
    let flags_fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    if flags_fragment & 0x3fff != 0 {
        return Err(PacketError {
            reason: UnsupportedReason::UnsupportedFragmentation,
            safe_metadata: Some(format!("flags_fragment=0x{flags_fragment:04x}")),
        });
    }

    Ok(Ipv4Header {
        ihl,
        total_len,
        protocol: bytes[9],
        source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
    })
}

fn parse_ipv6_header(bytes: &[u8]) -> Result<Ipv6Header, PacketError> {
    if bytes.len() < 40 {
        return Err(PacketError::malformed("short IPv6 header"));
    }
    if bytes[0] >> 4 != 6 {
        return Err(PacketError::malformed("invalid IPv6 header"));
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if bytes.len() < 40 + payload_len {
        return Err(PacketError::malformed("invalid IPv6 payload length"));
    }
    let next_header = bytes[6];
    if matches!(next_header, 0 | 43 | 44 | 50 | 51 | 60) {
        return Err(PacketError {
            reason: if next_header == 44 {
                UnsupportedReason::UnsupportedFragmentation
            } else {
                UnsupportedReason::UnsupportedIpProtocol(next_header)
            },
            safe_metadata: Some(format!("ipv6 extension header {next_header}")),
        });
    }

    Ok(Ipv6Header {
        payload_len,
        next_header,
        source: Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap()),
        destination: Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap()),
    })
}

fn inspect_icmp_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    header: Ipv4Header,
) -> Result<PacketInspection, PacketError> {
    let icmp = &bytes[header.ihl..header.total_len];
    if icmp.len() < 8 {
        return Err(PacketError::malformed("short ICMP message"));
    }

    let icmp_type = icmp[0];
    let icmp_code = icmp[1];
    let event = NormalizedEvent::IcmpMessage(IcmpMessage {
        sandbox_id,
        frontend,
        icmp_type,
        icmp_code,
        source: IpAddr::V4(header.source),
        destination: IpAddr::V4(header.destination),
    });

    let synthetic_reply = if icmp_type == 8 && icmp_code == 0 {
        Some(SyntheticIpPacket {
            bytes: synthesize_echo_reply(bytes, header),
        })
    } else {
        None
    };

    Ok(PacketInspection {
        event,
        synthetic_reply,
        udp_payload: None,
    })
}

fn inspect_tcp_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    header: Ipv4Header,
) -> Result<PacketInspection, PacketError> {
    let tcp = &bytes[header.ihl..header.total_len];
    if tcp.len() < 20 {
        return Err(PacketError::malformed("short TCP header"));
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return Err(PacketError::malformed("invalid TCP data offset"));
    }
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if !syn || ack {
        return Err(PacketError {
            reason: UnsupportedReason::Other(
                "tcp packet requires stack adapter flow handling".into(),
            ),
            safe_metadata: Some(format!("tcp flags=0x{flags:02x}")),
        });
    }

    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Ok(PacketInspection {
        event: NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id,
            frontend,
            source: SocketAddr::new(IpAddr::V4(header.source), source_port),
            destination: SocketAddr::new(IpAddr::V4(header.destination), destination_port),
            hostname: None,
        }),
        synthetic_reply: None,
        udp_payload: None,
    })
}

fn inspect_udp_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    header: Ipv4Header,
) -> Result<PacketInspection, PacketError> {
    let udp = &bytes[header.ihl..header.total_len];
    if udp.len() < 8 {
        return Err(PacketError::malformed("short UDP header"));
    }
    inspect_udp_segment(
        sandbox_id,
        frontend,
        SocketAddr::new(
            IpAddr::V4(header.source),
            u16::from_be_bytes([udp[0], udp[1]]),
        ),
        SocketAddr::new(
            IpAddr::V4(header.destination),
            u16::from_be_bytes([udp[2], udp[3]]),
        ),
        udp,
    )
}

fn inspect_icmpv6_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    header: Ipv6Header,
) -> Result<PacketInspection, PacketError> {
    let icmp = &bytes[40..40 + header.payload_len];
    if icmp.len() < 8 {
        return Err(PacketError::malformed("short ICMPv6 message"));
    }
    let icmp_type = icmp[0];
    let icmp_code = icmp[1];
    let event = NormalizedEvent::IcmpMessage(IcmpMessage {
        sandbox_id,
        frontend,
        icmp_type,
        icmp_code,
        source: IpAddr::V6(header.source),
        destination: IpAddr::V6(header.destination),
    });
    let synthetic_reply = if icmp_type == 128 && icmp_code == 0 {
        Some(SyntheticIpPacket {
            bytes: synthesize_icmpv6_echo_reply(bytes, header),
        })
    } else {
        None
    };
    Ok(PacketInspection {
        event,
        synthetic_reply,
        udp_payload: None,
    })
}

fn inspect_tcp_ipv6_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    header: Ipv6Header,
) -> Result<PacketInspection, PacketError> {
    let tcp = &bytes[40..40 + header.payload_len];
    if tcp.len() < 20 {
        return Err(PacketError::malformed("short TCP header"));
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return Err(PacketError::malformed("invalid TCP data offset"));
    }
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if !syn || ack {
        return Err(PacketError {
            reason: UnsupportedReason::Other(
                "tcp packet requires stack adapter flow handling".into(),
            ),
            safe_metadata: Some(format!("tcp flags=0x{flags:02x}")),
        });
    }
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Ok(PacketInspection {
        event: NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id,
            frontend,
            source: SocketAddr::new(IpAddr::V6(header.source), source_port),
            destination: SocketAddr::new(IpAddr::V6(header.destination), destination_port),
            hostname: None,
        }),
        synthetic_reply: None,
        udp_payload: None,
    })
}

fn inspect_udp_ipv6_packet(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    header: Ipv6Header,
) -> Result<PacketInspection, PacketError> {
    let udp = &bytes[40..40 + header.payload_len];
    if udp.len() < 8 {
        return Err(PacketError::malformed("short UDP header"));
    }
    inspect_udp_segment(
        sandbox_id,
        frontend,
        SocketAddr::new(
            IpAddr::V6(header.source),
            u16::from_be_bytes([udp[0], udp[1]]),
        ),
        SocketAddr::new(
            IpAddr::V6(header.destination),
            u16::from_be_bytes([udp[2], udp[3]]),
        ),
        udp,
    )
}

fn inspect_udp_segment(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    source: SocketAddr,
    destination: SocketAddr,
    udp: &[u8],
) -> Result<PacketInspection, PacketError> {
    if udp.len() < 8 {
        return Err(PacketError::malformed("short UDP header"));
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp_len > udp.len() {
        return Err(PacketError::malformed("invalid UDP length"));
    }
    Ok(PacketInspection {
        event: NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id,
            frontend,
            source,
            destination,
            hostname: None,
            classification: classify_udp_destination(destination),
        }),
        synthetic_reply: None,
        udp_payload: Some(udp[8..udp_len].to_vec()),
    })
}

/// Synthesize an IPv4 UDP packet carrying host response bytes back to the
/// original sandbox source. The caller supplies the normalized original UDP flow
/// endpoints; raw IPv4/UDP formatting stays in the packet boundary.
pub fn synthesize_udp_ipv4_response(
    original_source: SocketAddr,
    original_destination: SocketAddr,
    payload: &[u8],
) -> Result<SyntheticIpPacket, PacketError> {
    let (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) =
        (original_source.ip(), original_destination.ip())
    else {
        return Err(PacketError::malformed(
            "UDP IPv4 response requires IPv4 endpoints",
        ));
    };
    let total_len = 28 + payload.len();
    if total_len > u16::MAX as usize {
        return Err(PacketError::malformed(
            "UDP IPv4 response exceeds IPv4 length",
        ));
    }
    let udp_len = 8 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&destination_ip.octets());
    packet[16..20].copy_from_slice(&source_ip.octets());
    packet[20..22].copy_from_slice(&original_destination.port().to_be_bytes());
    packet[22..24].copy_from_slice(&original_source.port().to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let udp_checksum = udp_checksum_ipv4(destination_ip, source_ip, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    Ok(SyntheticIpPacket { bytes: packet })
}

/// Synthesize an IPv4 ICMP port-unreachable response for a failed UDP flow.
///
/// Runtime callers provide only the normalized UDP flow key. Packet code owns
/// the minimal quoted IPv4/UDP packet bytes required by ICMP.
pub fn synthesize_udp_ipv4_unreachable_from_flow(
    original_source: SocketAddr,
    original_destination: SocketAddr,
    code: u8,
) -> Result<SyntheticIpPacket, PacketError> {
    let (source_ip, destination_ip) = match (original_source.ip(), original_destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => (source, destination),
        _ => {
            return Err(PacketError::unsupported(
                "udp ipv4 unreachable requires IPv4 socket addresses",
            ));
        }
    };
    let mut original = vec![0_u8; 28];
    original[0] = 0x45;
    original[2..4].copy_from_slice(&28_u16.to_be_bytes());
    original[8] = 64;
    original[9] = 17;
    original[12..16].copy_from_slice(&source_ip.octets());
    original[16..20].copy_from_slice(&destination_ip.octets());
    original[20..22].copy_from_slice(&original_source.port().to_be_bytes());
    original[22..24].copy_from_slice(&original_destination.port().to_be_bytes());
    original[24..26].copy_from_slice(&8_u16.to_be_bytes());
    let udp_checksum = udp_checksum_ipv4(source_ip, destination_ip, &original[20..]);
    original[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    let ip_checksum = internet_checksum(&original[..20]);
    original[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    synthesize_ipv4_icmp_unreachable(&original, code)
}

/// Synthesize an IPv6 UDP response packet for a host reply to an original
/// sandbox UDP flow. The returned packet swaps the original flow endpoints.
pub fn synthesize_udp_ipv6_response(
    original_source: SocketAddr,
    original_destination: SocketAddr,
    payload: &[u8],
) -> Result<SyntheticIpPacket, PacketError> {
    let (source_ip, destination_ip) = match (original_source.ip(), original_destination.ip()) {
        (IpAddr::V6(source), IpAddr::V6(destination)) => (source, destination),
        _ => {
            return Err(PacketError::unsupported(
                "udp ipv6 response requires IPv6 socket addresses",
            ));
        }
    };
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or_else(|| PacketError::malformed("udp payload length overflow"))?;
    if udp_len > u16::MAX as usize {
        return Err(PacketError::malformed("udp payload too large"));
    }
    let total_len = 40 + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&destination_ip.octets());
    packet[24..40].copy_from_slice(&source_ip.octets());
    packet[40..42].copy_from_slice(&original_destination.port().to_be_bytes());
    packet[42..44].copy_from_slice(&original_source.port().to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    let udp_checksum = udp_checksum_ipv6(destination_ip, source_ip, &packet[40..]);
    packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(SyntheticIpPacket { bytes: packet })
}

/// Synthesize an IPv6 ICMPv6 destination-unreachable response for a failed UDP
/// flow using only normalized flow endpoints.
pub fn synthesize_udp_ipv6_unreachable_from_flow(
    original_source: SocketAddr,
    original_destination: SocketAddr,
    code: u8,
) -> Result<SyntheticIpPacket, PacketError> {
    let (source_ip, destination_ip) = match (original_source.ip(), original_destination.ip()) {
        (IpAddr::V6(source), IpAddr::V6(destination)) => (source, destination),
        _ => {
            return Err(PacketError::unsupported(
                "udp ipv6 unreachable requires IPv6 socket addresses",
            ));
        }
    };
    let mut original = vec![0_u8; 48];
    original[0] = 0x60;
    original[4..6].copy_from_slice(&8_u16.to_be_bytes());
    original[6] = 17;
    original[7] = 64;
    original[8..24].copy_from_slice(&source_ip.octets());
    original[24..40].copy_from_slice(&destination_ip.octets());
    original[40..42].copy_from_slice(&original_source.port().to_be_bytes());
    original[42..44].copy_from_slice(&original_destination.port().to_be_bytes());
    original[44..46].copy_from_slice(&8_u16.to_be_bytes());
    let udp_checksum = udp_checksum_ipv6(source_ip, destination_ip, &original[40..]);
    original[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    synthesize_ipv6_icmp_unreachable(&original, code)
}

/// Synthesize an ICMPv6 destination-unreachable response for denied traffic.
pub fn synthesize_ipv6_icmp_unreachable(
    original_packet: &[u8],
    code: u8,
) -> Result<SyntheticIpPacket, PacketError> {
    let header = parse_ipv6_header(original_packet)?;
    let original_len = (40 + header.payload_len).min(1232);
    let icmp_len = 8 + original_len;
    let total_len = 40 + icmp_len;
    if icmp_len > u16::MAX as usize {
        return Err(PacketError::malformed("ICMPv6 error too large"));
    }
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&header.destination.octets());
    packet[24..40].copy_from_slice(&header.source.octets());
    packet[40] = 1;
    packet[41] = code;
    packet[48..].copy_from_slice(&original_packet[..original_len]);
    let checksum = icmpv6_checksum(header.destination, header.source, &packet[40..]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    Ok(SyntheticIpPacket { bytes: packet })
}

/// Synthesize a packet-level IPv6 denial response when policy requests an ICMP
/// unreachable. Drop/reset decisions intentionally produce no packet here.
pub fn synthesize_ipv6_denial_response(
    original_packet: &[u8],
    decision: &PolicyDecision,
) -> Result<Option<SyntheticIpPacket>, PacketError> {
    match decision {
        PolicyDecision::Deny(deny) if deny.action == DenialAction::IcmpUnreachable => {
            synthesize_ipv6_icmp_unreachable(original_packet, 1).map(Some)
        }
        _ => Ok(None),
    }
}

fn udp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    if pseudo.len() % 2 == 1 {
        pseudo.push(0);
    }
    let checksum = internet_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn udp_checksum_ipv6(source: Ipv6Addr, destination: Ipv6Addr, udp_segment: &[u8]) -> u16 {
    checksum_ipv6_next_header(source, destination, 17, udp_segment)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp_segment: &[u8]) -> u16 {
    checksum_ipv6_next_header(source, destination, 58, icmp_segment)
}

fn checksum_ipv6_next_header(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(segment);
    if pseudo.len() % 2 == 1 {
        pseudo.push(0);
    }
    let checksum = internet_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn synthesize_echo_reply(bytes: &[u8], header: Ipv4Header) -> Vec<u8> {
    let mut reply = bytes[..header.total_len].to_vec();

    // Swap IPv4 source/destination and normalize TTL for the broker reply.
    reply[12..16].copy_from_slice(&header.destination.octets());
    reply[16..20].copy_from_slice(&header.source.octets());
    reply[8] = 64;

    // ICMP echo request -> echo reply.
    reply[header.ihl] = 0;
    reply[header.ihl + 2] = 0;
    reply[header.ihl + 3] = 0;
    let icmp_checksum = internet_checksum(&reply[header.ihl..header.total_len]);
    reply[header.ihl + 2..header.ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    // Recompute IPv4 header checksum after address/TTL changes.
    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = internet_checksum(&reply[..header.ihl]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    reply
}

fn synthesize_icmpv6_echo_reply(bytes: &[u8], header: Ipv6Header) -> Vec<u8> {
    let total_len = 40 + header.payload_len;
    let mut reply = bytes[..total_len].to_vec();
    reply[7] = 64;
    reply[8..24].copy_from_slice(&header.destination.octets());
    reply[24..40].copy_from_slice(&header.source.octets());
    reply[40] = 129;
    reply[42] = 0;
    reply[43] = 0;
    let checksum = icmpv6_checksum(header.destination, header.source, &reply[40..total_len]);
    reply[42..44].copy_from_slice(&checksum.to_be_bytes());
    reply
}

/// Synthesize a packet-level denial response when the normalized policy decision
/// requests one.
///
/// Policy chooses the denial action; packet code owns the raw IPv4/ICMP bytes.
/// Drop/reset decisions intentionally produce no packet response here.
pub fn synthesize_ipv4_denial_response(
    original_packet: &[u8],
    decision: &PolicyDecision,
) -> Result<Option<SyntheticIpPacket>, PacketError> {
    match decision {
        PolicyDecision::Deny(deny) if deny.action == DenialAction::IcmpUnreachable => {
            synthesize_ipv4_icmp_unreachable(original_packet, 13).map(Some)
        }
        _ => Ok(None),
    }
}

/// Synthesize an IPv4 ICMP destination-unreachable response for denied traffic.
///
/// Callers choose the ICMP code (for example, 3 for port unreachable or 13 for
/// administratively prohibited). The original packet remains opaque to policy;
/// this function only returns bytes suitable for TUN write-back.
pub fn synthesize_ipv4_icmp_unreachable(
    original_packet: &[u8],
    code: u8,
) -> Result<SyntheticIpPacket, PacketError> {
    let header = parse_ipv4_header(original_packet)?;
    let original_prefix_len = (header.ihl + 8).min(header.total_len);
    if original_prefix_len < header.ihl {
        return Err(PacketError::malformed(
            "short original packet for ICMP error",
        ));
    }
    let total_len = 20 + 8 + original_prefix_len;
    let mut packet = vec![0_u8; total_len];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&header.destination.octets());
    packet[16..20].copy_from_slice(&header.source.octets());

    let icmp_offset = 20;
    packet[icmp_offset] = 3;
    packet[icmp_offset + 1] = code;
    packet[icmp_offset + 8..].copy_from_slice(&original_packet[..original_prefix_len]);
    let icmp_checksum = internet_checksum(&packet[icmp_offset..]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    Ok(SyntheticIpPacket { bytes: packet })
}

/// Internet checksum used by IPv4 and ICMP.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PacketError {
    reason: UnsupportedReason,
    safe_metadata: Option<String>,
}

impl PacketError {
    fn malformed(metadata: impl Into<String>) -> Self {
        Self {
            reason: UnsupportedReason::MalformedPacket,
            safe_metadata: Some(metadata.into()),
        }
    }

    pub fn unsupported(metadata: impl Into<String>) -> Self {
        Self {
            reason: UnsupportedReason::UnsupportedIpProtocol(0),
            safe_metadata: Some(metadata.into()),
        }
    }
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.reason)
    }
}

impl std::error::Error for PacketError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{Protocol, UdpClassification, UnsupportedReason};

    fn sandbox() -> SandboxId {
        SandboxId::new("s1").unwrap()
    }

    #[test]
    fn malformed_ipv4_corpus_fails_closed_without_panics() {
        let corpus: &[&[u8]] = &[
            b"",
            &[0x45],
            &[0x45, 0, 0, 1],
            &[
                0x65, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
            ],
            &[
                0x45, 0, 0, 20, 0, 0, 0x20, 1, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
            ],
        ];

        for bytes in corpus {
            let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, bytes);
            assert!(matches!(
                inspection.event,
                NormalizedEvent::UnsupportedNetworkEvent(_)
            ));
            assert!(inspection.synthetic_reply.is_none());
        }
    }

    #[test]
    fn icmp_echo_request_returns_normalized_event_and_synthetic_reply() {
        let request = echo_request_packet();
        let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, &request);

        let NormalizedEvent::IcmpMessage(event) = inspection.event else {
            panic!("expected ICMP event");
        };
        assert_eq!(event.icmp_type, 8);
        assert_eq!(event.source, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(event.destination, "10.0.0.1".parse::<IpAddr>().unwrap());

        let reply = inspection.synthetic_reply.unwrap();
        assert_eq!(&reply.bytes()[12..16], &[10, 0, 0, 1]);
        assert_eq!(&reply.bytes()[16..20], &[10, 0, 0, 2]);
        assert_eq!(reply.bytes()[20], 0);
        assert_eq!(internet_checksum(&reply.bytes()[..20]), 0);
        assert_eq!(internet_checksum(&reply.bytes()[20..]), 0);
    }

    #[test]
    fn tcp_syn_returns_connect_attempt_without_exposing_tcp_header() {
        let packet = tcp_syn_packet();
        let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, &packet);
        let NormalizedEvent::TcpConnectAttempt(event) = inspection.event else {
            panic!("expected TCP connect attempt");
        };
        assert_eq!(event.source, "10.0.0.2:49152".parse().unwrap());
        assert_eq!(event.destination, "203.0.113.10:443".parse().unwrap());
        assert!(event.hostname.is_none());
        assert!(inspection.synthetic_reply.is_none());
    }

    #[test]
    fn non_syn_tcp_stays_behind_stack_adapter_boundary() {
        let mut packet = tcp_syn_packet();
        packet[20 + 13] = 0x10;
        packet[10] = 0;
        packet[11] = 0;
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, &packet);
        assert_eq!(inspection.event.protocol(), Protocol::Unsupported);
        let NormalizedEvent::UnsupportedNetworkEvent(event) = inspection.event else {
            panic!("expected unsupported event");
        };
        assert_eq!(
            event.reason,
            UnsupportedReason::Other("tcp packet requires stack adapter flow handling".into())
        );
    }

    #[test]
    fn udp_packet_returns_classified_flow_attempt() {
        let packet = udp_packet(53000, 443, &[1, 2, 3, 4]);
        let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, &packet);
        let NormalizedEvent::UdpFlowAttempt(event) = inspection.event else {
            panic!("expected UDP flow attempt");
        };
        assert_eq!(event.source, "10.0.0.2:53000".parse().unwrap());
        assert_eq!(event.destination, "203.0.113.10:443".parse().unwrap());
        assert_eq!(event.classification, UdpClassification::QuicCandidate);
    }

    #[test]
    fn unsupported_protocol_becomes_fail_closed_event() {
        let mut packet = echo_request_packet();
        packet[9] = 99;
        packet[10] = 0;
        packet[11] = 0;
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, &packet);
        assert_eq!(inspection.event.protocol(), Protocol::Unsupported);
        let NormalizedEvent::UnsupportedNetworkEvent(event) = inspection.event else {
            panic!("expected unsupported event");
        };
        assert_eq!(event.reason, UnsupportedReason::UnsupportedIpProtocol(99));
        assert!(inspection.synthetic_reply.is_none());
    }

    #[test]
    fn fragmented_packet_is_unsupported() {
        let mut packet = echo_request_packet();
        packet[6] = 0x20; // more fragments flag
        packet[10] = 0;
        packet[11] = 0;
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let inspection = inspect_ipv4_packet(sandbox(), FrontendKind::Tun, &packet);
        let NormalizedEvent::UnsupportedNetworkEvent(event) = inspection.event else {
            panic!("expected unsupported");
        };
        assert_eq!(event.reason, UnsupportedReason::UnsupportedFragmentation);
    }

    #[test]
    fn udp_ipv4_response_synthesis_swaps_original_flow_endpoints() {
        let packet = synthesize_udp_ipv4_response(
            "10.0.0.2:53000".parse().unwrap(),
            "203.0.113.10:12345".parse().unwrap(),
            b"pong",
        )
        .unwrap();
        let bytes = packet.bytes();

        assert_eq!(bytes[9], 17);
        assert_eq!(&bytes[12..16], &[203, 0, 113, 10]);
        assert_eq!(&bytes[16..20], &[10, 0, 0, 2]);
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 12345);
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 53000);
        assert_ne!(u16::from_be_bytes([bytes[26], bytes[27]]), 0);
        assert_eq!(&bytes[28..], b"pong");
    }

    #[test]
    fn udp_ipv4_unreachable_from_flow_quotes_minimal_udp_packet() {
        let packet = synthesize_udp_ipv4_unreachable_from_flow(
            "10.0.0.2:53000".parse().unwrap(),
            "203.0.113.10:12345".parse().unwrap(),
            3,
        )
        .unwrap();
        let bytes = packet.bytes();

        assert_eq!(bytes[9], 1);
        assert_eq!(&bytes[12..16], &[203, 0, 113, 10]);
        assert_eq!(&bytes[16..20], &[10, 0, 0, 2]);
        assert_eq!(bytes[20], 3);
        assert_eq!(bytes[21], 3);
        assert_eq!(u16::from_be_bytes([bytes[48], bytes[49]]), 53000);
        assert_eq!(u16::from_be_bytes([bytes[50], bytes[51]]), 12345);
        assert_eq!(internet_checksum(&bytes[..20]), 0);
        assert_eq!(internet_checksum(&bytes[20..]), 0);
    }

    #[test]
    fn ipv6_udp_packet_returns_classified_flow_attempt() {
        let packet = udp_ipv6_packet(53000, 443, &[1, 2, 3, 4]);
        let inspection = inspect_ipv6_packet(sandbox(), FrontendKind::Tun, &packet);
        let NormalizedEvent::UdpFlowAttempt(event) = inspection.event else {
            panic!("expected UDP flow attempt");
        };
        assert_eq!(event.source, "[2001:db8::2]:53000".parse().unwrap());
        assert_eq!(event.destination, "[2001:db8::10]:443".parse().unwrap());
        assert_eq!(event.classification, UdpClassification::QuicCandidate);
        assert_eq!(
            inspection.udp_payload.as_deref(),
            Some([1, 2, 3, 4].as_slice())
        );
    }

    #[test]
    fn icmpv6_echo_request_returns_normalized_event_and_synthetic_reply() {
        let request = icmpv6_echo_request_packet();
        let inspection = inspect_ipv6_packet(sandbox(), FrontendKind::Tun, &request);
        let NormalizedEvent::IcmpMessage(event) = inspection.event else {
            panic!("expected ICMPv6 event");
        };
        assert_eq!(event.icmp_type, 128);
        assert_eq!(event.source, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!(event.destination, "2001:db8::1".parse::<IpAddr>().unwrap());

        let reply = inspection.synthetic_reply.unwrap();
        assert_eq!(reply.bytes()[6], 58);
        assert_eq!(reply.bytes()[40], 129);
        assert_eq!(reply.bytes()[41], 0);
        assert_eq!(
            &reply.bytes()[8..24],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &reply.bytes()[24..40],
            &"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            icmpv6_checksum(
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                &reply.bytes()[40..]
            ),
            0xffff
        );
    }

    #[test]
    fn udp_ipv6_unreachable_from_flow_quotes_minimal_udp_packet() {
        let packet = synthesize_udp_ipv6_unreachable_from_flow(
            "[2001:db8::2]:53000".parse().unwrap(),
            "[2001:db8::10]:12345".parse().unwrap(),
            4,
        )
        .unwrap();
        let bytes = packet.bytes();

        assert_eq!(bytes[6], 58);
        assert_eq!(bytes[40], 1);
        assert_eq!(bytes[41], 4);
        assert_eq!(u16::from_be_bytes([bytes[88], bytes[89]]), 53000);
        assert_eq!(u16::from_be_bytes([bytes[90], bytes[91]]), 12345);
    }

    #[test]
    fn udp_ipv6_response_synthesis_swaps_original_flow_endpoints() {
        let packet = synthesize_udp_ipv6_response(
            "[2001:db8::2]:53000".parse().unwrap(),
            "[2001:db8::10]:12345".parse().unwrap(),
            b"pong",
        )
        .unwrap();
        let bytes = packet.bytes();

        assert_eq!(bytes[0] >> 4, 6);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 12);
        assert_eq!(bytes[6], 17);
        assert_eq!(bytes[7], 64);
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &bytes[24..40],
            &"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(u16::from_be_bytes([bytes[40], bytes[41]]), 12345);
        assert_eq!(u16::from_be_bytes([bytes[42], bytes[43]]), 53000);
        assert_ne!(u16::from_be_bytes([bytes[46], bytes[47]]), 0);
        assert_eq!(&bytes[48..], b"pong");
    }

    #[test]
    fn policy_icmp_unreachable_decision_synthesizes_denial_response() {
        let denied = udp_packet(53000, 12345, &[1, 2, 3, 4]);
        let decision = PolicyDecision::Deny(foxprox_core::DenyDecision {
            action: DenialAction::IcmpUnreachable,
            rule_id: None,
            reason: "blocked".into(),
        });

        let response = synthesize_ipv4_denial_response(&denied, &decision)
            .unwrap()
            .unwrap();
        assert_eq!(response.bytes()[20], 3);
        assert_eq!(response.bytes()[21], 13);

        let drop = PolicyDecision::Deny(foxprox_core::DenyDecision {
            action: DenialAction::Drop,
            rule_id: None,
            reason: "blocked".into(),
        });
        assert!(synthesize_ipv4_denial_response(&denied, &drop)
            .unwrap()
            .is_none());
    }

    #[test]
    fn synthesizes_icmp_unreachable_for_denied_ipv4_packet() {
        let denied = udp_packet(53000, 12345, &[1, 2, 3, 4]);
        let response = synthesize_ipv4_icmp_unreachable(&denied, 13).unwrap();

        assert_eq!(&response.bytes()[12..16], &[203, 0, 113, 10]);
        assert_eq!(&response.bytes()[16..20], &[10, 0, 0, 2]);
        assert_eq!(response.bytes()[20], 3);
        assert_eq!(response.bytes()[21], 13);
        assert_eq!(internet_checksum(&response.bytes()[..20]), 0);
        assert_eq!(internet_checksum(&response.bytes()[20..]), 0);
        assert_eq!(&response.bytes()[28..48], &denied[..20]);
    }

    fn echo_request_packet() -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 28, // version/IHL, DSCP, total length
            0x12, 0x34, 0, 0, // id, flags/fragment
            64, 1, 0, 0, // ttl, protocol=icmp, checksum
            10, 0, 0, 2, // source
            10, 0, 0, 1, // destination
            8, 0, 0, 0, // echo request, checksum
            0xab, 0xcd, 0, 1, // identifier, sequence
        ];
        let icmp_checksum = internet_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        finish_ipv4_checksum(&mut packet);
        packet
    }

    fn tcp_syn_packet() -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 40, // version/IHL, total length
            0x12, 0x34, 0, 0, // id, flags/fragment
            64, 6, 0, 0, // ttl, protocol=tcp, checksum
            10, 0, 0, 2, // source
            203, 0, 113, 10, // destination
            0xc0, 0x00, 0x01, 0xbb, // ports 49152 -> 443
            0, 0, 0, 1, // seq
            0, 0, 0, 0, // ack
            0x50, 0x02, 0x72, 0x10, // data offset, SYN, window
            0, 0, 0, 0, // checksum, urgent
        ];
        finish_ipv4_checksum(&mut packet);
        packet
    }

    fn udp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0x12,
            0x34,
            0,
            0,
            64,
            17,
            0,
            0,
            10,
            0,
            0,
            2,
            203,
            0,
            113,
            10,
            (source_port >> 8) as u8,
            source_port as u8,
            (destination_port >> 8) as u8,
            destination_port as u8,
            (udp_len >> 8) as u8,
            udp_len as u8,
            0,
            0,
        ];
        packet.extend_from_slice(payload);
        finish_ipv4_checksum(&mut packet);
        packet
    }

    fn udp_ipv6_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8::10".parse::<Ipv6Addr>().unwrap();
        let udp_len = 8 + payload.len();
        let mut packet = vec![0_u8; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let checksum = udp_checksum_ipv6(source, destination, &packet[40..]);
        packet[46..48].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn icmpv6_echo_request_packet() -> Vec<u8> {
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = 128;
        packet[42..44].copy_from_slice(&0xabcd_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&1_u16.to_be_bytes());
        packet[46..48].copy_from_slice(&2_u16.to_be_bytes());
        let checksum = icmpv6_checksum(source, destination, &packet[40..]);
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn finish_ipv4_checksum(packet: &mut [u8]) {
        packet[10] = 0;
        packet[11] = 0;
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        let checksum = internet_checksum(&packet[..ihl]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
}
