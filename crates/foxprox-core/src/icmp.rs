use crate::packet::{parse_ip_packet, PacketParseError};
use crate::types::Protocol;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IcmpSynthesisError {
    Packet(PacketParseError),
    UnsupportedPacket,
    NotEchoRequest,
}

pub fn synthesize_icmpv4_echo_reply(packet: &[u8]) -> Result<Vec<u8>, IcmpSynthesisError> {
    let summary = parse_ip_packet(packet).map_err(IcmpSynthesisError::Packet)?;
    if summary.protocol != Protocol::Icmp {
        return Err(IcmpSynthesisError::UnsupportedPacket);
    }
    let Some(icmp) = summary.icmp else {
        return Err(IcmpSynthesisError::UnsupportedPacket);
    };
    if !icmp.is_echo_request() || packet.len() < 28 || packet[0] >> 4 != 4 {
        return Err(IcmpSynthesisError::NotEchoRequest);
    }

    let ihl_bytes = usize::from(packet[0] & 0x0f) * 4;
    if packet.len() < ihl_bytes + 8 {
        return Err(IcmpSynthesisError::Packet(
            PacketParseError::TruncatedTransportHeader,
        ));
    }

    let mut reply = packet.to_vec();
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = internet_checksum(&reply[..ihl_bytes]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    reply[ihl_bytes] = 0;
    reply[ihl_bytes + 2] = 0;
    reply[ihl_bytes + 3] = 0;
    let icmp_checksum = internet_checksum(&reply[ihl_bytes..]);
    reply[ihl_bytes + 2..ihl_bytes + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(reply)
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::packet::parse_ip_packet;
    use crate::types::IcmpMessage;

    use super::*;

    #[test]
    fn synthesizes_icmpv4_echo_replies_with_reversed_endpoints_and_checksums() {
        let request = ipv4_icmp_packet(8, 0, &[0x12, 0x34, 0x00, 0x01, b'p', b'i', b'n', b'g']);
        let reply = synthesize_icmpv4_echo_reply(&request).unwrap();

        let parsed = parse_ip_packet(&reply).unwrap();
        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(parsed.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(parsed.icmp, Some(IcmpMessage::ipv4(0, 0)));
        assert_eq!(&reply[24..], &request[24..]);
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }

    #[test]
    fn refuses_to_synthesize_unusual_icmp_or_non_icmp_packets() {
        let destination_unreachable = ipv4_icmp_packet(3, 0, &[0, 0, 0, 0]);
        assert_eq!(
            synthesize_icmpv4_echo_reply(&destination_unreachable),
            Err(IcmpSynthesisError::NotEchoRequest)
        );

        let tcp = ipv4_packet(6, &[0_u8; 20]);
        assert_eq!(
            synthesize_icmpv4_echo_reply(&tcp),
            Err(IcmpSynthesisError::Packet(
                PacketParseError::InvalidTransportChecksum
            ))
        );
    }

    #[test]
    fn malformed_echo_requests_fail_closed_before_synthesis() {
        let mut request = ipv4_icmp_packet(8, 0, &[0x12, 0x34, 0x00, 0x01]);
        request[22] ^= 0xff;
        assert_eq!(
            synthesize_icmpv4_echo_reply(&request),
            Err(IcmpSynthesisError::Packet(
                PacketParseError::InvalidTransportChecksum
            ))
        );
    }

    fn ipv4_icmp_packet(type_: u8, code: u8, rest: &[u8]) -> Vec<u8> {
        let mut icmp = vec![type_, code, 0, 0];
        icmp.extend_from_slice(rest);
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        ipv4_packet(1, &icmp)
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
        packet
    }
}
