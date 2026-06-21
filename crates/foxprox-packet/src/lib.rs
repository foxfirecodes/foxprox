//! Minimal packet parser/synthesizer for alpha write-back proofs.
//!
//! Raw packet buffers terminate in this crate. Policy and audit receive only
//! normalized `foxprox-core` events, and outbound packets remain opaque bytes.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use foxprox_core::{
    FrontendKind, IcmpMessage, NormalizedEvent, SandboxId, UnsupportedNetworkEvent,
    UnsupportedReason,
};

/// Result of inspecting one inbound IP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketInspection {
    pub event: NormalizedEvent,
    pub synthetic_reply: Option<SyntheticIpPacket>,
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

/// Inspect an IPv4 packet and synthesize an ICMP echo reply when possible.
/// Malformed and unsupported cases produce fail-closed normalized events.
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
        },
    }
}

fn inspect_ipv4_packet_inner(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> Result<PacketInspection, PacketError> {
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

    let protocol = bytes[9];
    if protocol != 1 {
        return Err(PacketError {
            reason: UnsupportedReason::UnsupportedIpProtocol(protocol),
            safe_metadata: Some(format!("ipv4 protocol {protocol}")),
        });
    }

    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let icmp = &bytes[ihl..total_len];
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
        source: IpAddr::V4(source),
        destination: IpAddr::V4(destination),
    });

    let synthetic_reply = if icmp_type == 8 && icmp_code == 0 {
        Some(SyntheticIpPacket {
            bytes: synthesize_echo_reply(bytes, ihl, total_len),
        })
    } else {
        None
    };

    Ok(PacketInspection {
        event,
        synthetic_reply,
    })
}

fn synthesize_echo_reply(bytes: &[u8], ihl: usize, total_len: usize) -> Vec<u8> {
    let mut reply = bytes[..total_len].to_vec();

    // Swap IPv4 source/destination and normalize TTL for the broker reply.
    let original_source = [reply[12], reply[13], reply[14], reply[15]];
    let original_destination = [reply[16], reply[17], reply[18], reply[19]];
    reply[12..16].copy_from_slice(&original_destination);
    reply[16..20].copy_from_slice(&original_source);
    reply[8] = 64;

    // ICMP echo request -> echo reply.
    reply[ihl] = 0;
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_checksum = internet_checksum(&reply[ihl..total_len]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    // Recompute IPv4 header checksum after address/TTL changes.
    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = internet_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    reply
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
    use foxprox_core::{Protocol, UnsupportedReason};

    fn sandbox() -> SandboxId {
        SandboxId::new("s1").unwrap()
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
            panic!("expected unsupported event");
        };
        assert_eq!(event.reason, UnsupportedReason::UnsupportedFragmentation);
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
        let ip_checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }
}
