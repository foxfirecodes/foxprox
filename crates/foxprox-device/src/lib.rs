//! Device-facing packet helpers for foxprox.
//!
//! This crate owns packet-buffer mechanics that are below policy decisions but
//! above concrete Linux TUN setup. The initial Milestone 1 proof path supports a
//! narrow, fail-closed IPv4 ICMP echo-reply synthesizer.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use foxprox_core::{Frontend, NetworkEvent, SandboxId, TransportEndpoint};
use std::net::{IpAddr, Ipv4Addr};

/// IPv4 protocol number for ICMPv4.
pub const IPPROTO_ICMP: u8 = 1;

/// ICMPv4 echo request type.
pub const ICMPV4_ECHO_REQUEST: u8 = 8;

/// ICMPv4 echo reply type.
pub const ICMPV4_ECHO_REPLY: u8 = 0;

/// Minimal parsed IPv4 metadata useful for packet logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Ipv4PacketMetadata {
    /// Total IPv4 packet length from the header.
    pub total_len: usize,
    /// IPv4 header length in bytes.
    pub header_len: usize,
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// IP protocol number.
    pub protocol: u8,
    /// Time-to-live value.
    pub ttl: u8,
}

/// Minimal parsed ICMPv4 metadata useful for packet logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Icmpv4Metadata {
    /// ICMP type.
    pub ty: u8,
    /// ICMP code.
    pub code: u8,
    /// Echo identifier, when the packet is echo-shaped.
    pub identifier: Option<u16>,
    /// Echo sequence number, when the packet is echo-shaped.
    pub sequence: Option<u16>,
}

/// Reasons a packet is dropped by the proof packet path.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PacketDropReason {
    /// Packet is too short for the advertised header.
    Malformed(&'static str),
    /// Packet is not IPv4.
    UnsupportedIpVersion(u8),
    /// IPv4 header options are not supported by the proof path.
    UnsupportedIpv4Options,
    /// IPv4 fragmentation is not supported by the proof path.
    UnsupportedFragmentation,
    /// IPv4 header checksum is invalid.
    InvalidIpv4Checksum,
    /// ICMPv4 checksum is invalid.
    InvalidIcmpv4Checksum,
    /// IP protocol is not supported by the proof path.
    UnsupportedIpProtocol(u8),
    /// ICMP type/code is not supported by the proof path.
    UnsupportedIcmp {
        /// ICMP type.
        ty: u8,
        /// ICMP code.
        code: u8,
    },
    /// Echo request was not addressed to this broker/gateway address.
    NotForLocalAddress {
        /// Actual destination address.
        destination: Ipv4Addr,
        /// Expected local address.
        local: Ipv4Addr,
    },
}

/// Parses IPv4 metadata and applies fail-closed packet validation for the proof path.
pub fn parse_ipv4_metadata(packet: &[u8]) -> Result<Ipv4PacketMetadata, PacketDropReason> {
    if packet.len() < 20 {
        return Err(PacketDropReason::Malformed(
            "IPv4 packet shorter than base header",
        ));
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return Err(PacketDropReason::UnsupportedIpVersion(version));
    }

    let ihl_words = packet[0] & 0x0f;
    if ihl_words < 5 {
        return Err(PacketDropReason::Malformed(
            "IPv4 IHL shorter than base header",
        ));
    }
    if ihl_words != 5 {
        return Err(PacketDropReason::UnsupportedIpv4Options);
    }
    let header_len = usize::from(ihl_words) * 4;
    if packet.len() < header_len {
        return Err(PacketDropReason::Malformed(
            "buffer shorter than IPv4 header length",
        ));
    }

    let total_len = usize::from(read_u16(&packet[2..4]));
    if total_len < header_len {
        return Err(PacketDropReason::Malformed(
            "IPv4 total length shorter than header",
        ));
    }
    if total_len > packet.len() {
        return Err(PacketDropReason::Malformed(
            "buffer shorter than IPv4 total length",
        ));
    }

    let flags_fragment = read_u16(&packet[6..8]);
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = flags_fragment & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return Err(PacketDropReason::UnsupportedFragmentation);
    }

    if checksum16(&packet[..header_len]) != 0 {
        return Err(PacketDropReason::InvalidIpv4Checksum);
    }

    Ok(Ipv4PacketMetadata {
        total_len,
        header_len,
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        ttl: packet[8],
    })
}

/// Parses ICMPv4 metadata from a previously validated IPv4 packet.
pub fn parse_icmpv4_metadata(
    packet: &[u8],
    ipv4: Ipv4PacketMetadata,
) -> Result<Icmpv4Metadata, PacketDropReason> {
    if ipv4.protocol != IPPROTO_ICMP {
        return Err(PacketDropReason::UnsupportedIpProtocol(ipv4.protocol));
    }
    let icmp = &packet[ipv4.header_len..ipv4.total_len];
    if icmp.len() < 8 {
        return Err(PacketDropReason::Malformed(
            "ICMPv4 message shorter than base header",
        ));
    }
    Ok(Icmpv4Metadata {
        ty: icmp[0],
        code: icmp[1],
        identifier: Some(read_u16(&icmp[4..6])),
        sequence: Some(read_u16(&icmp[6..8])),
    })
}

/// Builds a synthetic ICMPv4 echo reply for a valid echo request addressed to `local_ip`.
///
/// Unsupported or malformed packets return a structured drop reason. The returned packet
/// is an owned IPv4 packet ready to write back to an `IFF_TUN | IFF_NO_PI` device.
pub fn synthesize_icmpv4_echo_reply(
    request: &[u8],
    local_ip: Ipv4Addr,
) -> Result<Vec<u8>, PacketDropReason> {
    let ipv4 = parse_ipv4_metadata(request)?;
    if ipv4.protocol != IPPROTO_ICMP {
        return Err(PacketDropReason::UnsupportedIpProtocol(ipv4.protocol));
    }
    if ipv4.destination != local_ip {
        return Err(PacketDropReason::NotForLocalAddress {
            destination: ipv4.destination,
            local: local_ip,
        });
    }

    let icmp_offset = ipv4.header_len;
    let icmp_len = ipv4.total_len - icmp_offset;
    if icmp_len < 8 {
        return Err(PacketDropReason::Malformed(
            "ICMPv4 message shorter than base header",
        ));
    }
    if checksum16(&request[icmp_offset..ipv4.total_len]) != 0 {
        return Err(PacketDropReason::InvalidIcmpv4Checksum);
    }
    if request[icmp_offset] != ICMPV4_ECHO_REQUEST || request[icmp_offset + 1] != 0 {
        return Err(PacketDropReason::UnsupportedIcmp {
            ty: request[icmp_offset],
            code: request[icmp_offset + 1],
        });
    }

    let mut reply = request[..ipv4.total_len].to_vec();
    reply[8] = 64;
    reply[10] = 0;
    reply[11] = 0;
    reply[12..16].copy_from_slice(&ipv4.destination.octets());
    reply[16..20].copy_from_slice(&ipv4.source.octets());
    let ip_checksum = checksum16(&reply[..ipv4.header_len]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    reply[icmp_offset] = ICMPV4_ECHO_REPLY;
    reply[icmp_offset + 1] = 0;
    reply[icmp_offset + 2] = 0;
    reply[icmp_offset + 3] = 0;
    let icmp_checksum = checksum16(&reply[icmp_offset..ipv4.total_len]);
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    Ok(reply)
}

/// Converts parsed ICMP metadata into a normalized core event for audit/policy plumbing.
pub fn icmp_event(
    sandbox_id: SandboxId,
    ipv4: Ipv4PacketMetadata,
    icmp: Icmpv4Metadata,
) -> NetworkEvent {
    NetworkEvent::IcmpMessage {
        sandbox_id,
        source: IpAddr::V4(ipv4.source),
        destination: IpAddr::V4(ipv4.destination),
        ty: icmp.ty,
        code: icmp.code,
    }
}

/// Converts an IPv4 packet endpoint pair to transport endpoints for log helpers.
pub fn transport_endpoints_for_ip_packet(
    ipv4: Ipv4PacketMetadata,
) -> (TransportEndpoint, TransportEndpoint) {
    (
        TransportEndpoint::new(IpAddr::V4(ipv4.source), 0),
        TransportEndpoint::new(IpAddr::V4(ipv4.destination), 0),
    )
}

/// Returns a normalized unsupported event for a packet drop reason.
pub fn unsupported_event_for_drop(
    sandbox_id: Option<SandboxId>,
    reason: PacketDropReason,
) -> NetworkEvent {
    use foxprox_core::UnsupportedReason;

    let reason = match reason {
        PacketDropReason::Malformed(reason) => UnsupportedReason::Malformed(reason.to_string()),
        PacketDropReason::UnsupportedIpVersion(version) => {
            UnsupportedReason::Malformed(format!("unsupported IP version {version}"))
        }
        PacketDropReason::UnsupportedIpv4Options => {
            UnsupportedReason::Malformed("IPv4 options are unsupported".to_string())
        }
        PacketDropReason::UnsupportedFragmentation => UnsupportedReason::UnsupportedFragmentation,
        PacketDropReason::InvalidIpv4Checksum => {
            UnsupportedReason::Malformed("invalid IPv4 checksum".to_string())
        }
        PacketDropReason::InvalidIcmpv4Checksum => {
            UnsupportedReason::Malformed("invalid ICMPv4 checksum".to_string())
        }
        PacketDropReason::UnsupportedIpProtocol(protocol) => {
            UnsupportedReason::UnsupportedIpProtocol(protocol)
        }
        PacketDropReason::UnsupportedIcmp { ty, code } => {
            UnsupportedReason::UnsupportedIcmp { ty, code }
        }
        PacketDropReason::NotForLocalAddress { destination, local } => {
            UnsupportedReason::Malformed(format!(
                "ICMP echo request destination {destination} did not match local {local}"
            ))
        }
    };

    NetworkEvent::Unsupported {
        sandbox_id,
        frontend: Frontend::Tun,
        reason,
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn checksum16(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(read_u16(chunk));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_request() -> Vec<u8> {
        let mut packet = vec![
            0x45,
            0,
            0,
            32,
            0x12,
            0x34,
            0,
            0,
            64,
            IPPROTO_ICMP,
            0,
            0,
            10,
            255,
            0,
            2,
            10,
            255,
            0,
            1,
            ICMPV4_ECHO_REQUEST,
            0,
            0,
            0,
            0xab,
            0xcd,
            0,
            7,
            b'p',
            b'i',
            b'n',
            b'g',
        ];
        let ip_checksum = checksum16(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        let icmp_checksum = checksum16(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn parses_ipv4_and_icmp_metadata() {
        let packet = echo_request();
        let ipv4 = parse_ipv4_metadata(&packet).unwrap();
        assert_eq!(ipv4.source, Ipv4Addr::new(10, 255, 0, 2));
        assert_eq!(ipv4.destination, Ipv4Addr::new(10, 255, 0, 1));
        assert_eq!(ipv4.protocol, IPPROTO_ICMP);
        let icmp = parse_icmpv4_metadata(&packet, ipv4).unwrap();
        assert_eq!(icmp.ty, ICMPV4_ECHO_REQUEST);
        assert_eq!(icmp.identifier, Some(0xabcd));
        assert_eq!(icmp.sequence, Some(7));
    }

    #[test]
    fn synthesizes_echo_reply_with_swapped_addresses_and_valid_checksums() {
        let packet = echo_request();
        let reply = synthesize_icmpv4_echo_reply(&packet, Ipv4Addr::new(10, 255, 0, 1)).unwrap();
        let ipv4 = parse_ipv4_metadata(&reply).unwrap();
        assert_eq!(ipv4.source, Ipv4Addr::new(10, 255, 0, 1));
        assert_eq!(ipv4.destination, Ipv4Addr::new(10, 255, 0, 2));
        assert_eq!(reply[20], ICMPV4_ECHO_REPLY);
        assert_eq!(&reply[24..], &packet[24..]);
        assert_eq!(checksum16(&reply[20..]), 0);
    }

    #[test]
    fn drops_fragmented_packets() {
        let mut packet = echo_request();
        packet[6] = 0x20;
        packet[10] = 0;
        packet[11] = 0;
        let ip_checksum = checksum16(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        assert_eq!(
            synthesize_icmpv4_echo_reply(&packet, Ipv4Addr::new(10, 255, 0, 1)),
            Err(PacketDropReason::UnsupportedFragmentation)
        );
    }

    #[test]
    fn drops_unsupported_protocols() {
        let mut packet = echo_request();
        packet[9] = 6;
        packet[10] = 0;
        packet[11] = 0;
        let ip_checksum = checksum16(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        assert_eq!(
            synthesize_icmpv4_echo_reply(&packet, Ipv4Addr::new(10, 255, 0, 1)),
            Err(PacketDropReason::UnsupportedIpProtocol(6))
        );
    }

    #[test]
    fn drops_invalid_icmp_checksum() {
        let mut packet = echo_request();
        packet[31] ^= 0xff;
        assert_eq!(
            synthesize_icmpv4_echo_reply(&packet, Ipv4Addr::new(10, 255, 0, 1)),
            Err(PacketDropReason::InvalidIcmpv4Checksum)
        );
    }

    #[test]
    fn drops_non_echo_icmp() {
        let mut packet = echo_request();
        packet[20] = 3;
        packet[22] = 0;
        packet[23] = 0;
        let icmp_checksum = checksum16(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        assert_eq!(
            synthesize_icmpv4_echo_reply(&packet, Ipv4Addr::new(10, 255, 0, 1)),
            Err(PacketDropReason::UnsupportedIcmp { ty: 3, code: 0 })
        );
    }

    #[test]
    fn drops_malformed_packets() {
        assert!(matches!(
            synthesize_icmpv4_echo_reply(&[0; 4], Ipv4Addr::new(10, 255, 0, 1)),
            Err(PacketDropReason::Malformed(_))
        ));
    }

    #[test]
    fn fuzz_smoke_packet_parsers_are_total() {
        let seeds = [Vec::new(), vec![0; 4], echo_request()];
        for seed in seeds {
            for input in mutated_inputs(&seed) {
                let ipv4 = parse_ipv4_metadata(&input);
                if let Ok(metadata) = ipv4 {
                    let _ = parse_icmpv4_metadata(&input, metadata);
                }
                let _ = synthesize_icmpv4_echo_reply(&input, Ipv4Addr::new(10, 255, 0, 1));
            }
        }
    }

    fn mutated_inputs(seed: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        out.push(seed.to_vec());
        for len in 0..=seed.len().min(16) {
            out.push(seed[..len].to_vec());
        }
        for index in 0..seed.len().min(32) {
            let mut mutated = seed.to_vec();
            mutated[index] ^= 0xaa;
            out.push(mutated);
        }
        let mut generated = Vec::new();
        let mut state = seed.len() as u32 ^ 0x1020_3040;
        for _ in 0..96 {
            state = state.wrapping_mul(22_695_477).wrapping_add(1);
            generated.push((state >> 24) as u8);
        }
        out.push(generated);
        out
    }

    #[test]
    fn maps_drop_reason_to_unsupported_event() {
        let event = unsupported_event_for_drop(None, PacketDropReason::UnsupportedIpProtocol(99));
        assert_eq!(event.protocol(), foxprox_core::Protocol::Unsupported);
    }
}
