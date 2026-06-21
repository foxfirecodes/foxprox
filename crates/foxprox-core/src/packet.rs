use std::net::{IpAddr, Ipv4Addr};

use crate::audit::Protocol;
use crate::flow::{FlowKey, UdpClass};
use crate::origin::classify_quic_candidate;

/// Parsed IPv4 packet metadata used by the harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol_number: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn protocol(&self) -> Protocol {
        match self.protocol_number {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Unsupported,
        }
    }
}

/// Parse IPv4 and reject malformed packets, options, and fragmentation for alpha fail-closed behavior.
pub fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Packet<'_>, String> {
    if packet.len() < 20 {
        return Err("IPv4 packet too short".to_string());
    }
    let version = packet[0] >> 4;
    let ihl_words = packet[0] & 0x0f;
    if version != 4 {
        return Err("not an IPv4 packet".to_string());
    }
    if ihl_words < 5 {
        return Err("IPv4 IHL is too small".to_string());
    }
    let header_len = ihl_words as usize * 4;
    if header_len != 20 {
        return Err("IPv4 options are unsupported in alpha".to_string());
    }
    if packet.len() < header_len {
        return Err("IPv4 header truncated".to_string());
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return Err("IPv4 total length is invalid".to_string());
    }
    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = flags_fragment & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return Err("IPv4 fragmentation is unsupported in alpha".to_string());
    }
    if checksum(&packet[..header_len]) != 0 {
        return Err("IPv4 header checksum invalid".to_string());
    }
    Ok(Ipv4Packet {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol_number: packet[9],
        ttl: packet[8],
        payload: &packet[header_len..total_len],
    })
}

/// Parsed TCP header subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
}

pub fn parse_tcp(payload: &[u8]) -> Result<TcpSegment<'_>, String> {
    if payload.len() < 20 {
        return Err("TCP segment too short".to_string());
    }
    let data_offset = (payload[12] >> 4) as usize * 4;
    if data_offset < 20 || payload.len() < data_offset {
        return Err("TCP data offset invalid".to_string());
    }
    let flags = payload[13];
    Ok(TcpSegment {
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        syn: flags & 0x02 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        payload: &payload[data_offset..],
    })
}

/// Parsed UDP datagram subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
    pub class: UdpClass,
}

pub fn parse_udp(payload: &[u8]) -> Result<UdpDatagram<'_>, String> {
    if payload.len() < 8 {
        return Err("UDP datagram too short".to_string());
    }
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < 8 || length > payload.len() {
        return Err("UDP length invalid".to_string());
    }
    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let data = &payload[8..length];
    let class = classify_udp(destination_port, data);
    Ok(UdpDatagram {
        source_port,
        destination_port,
        payload: data,
        class,
    })
}

pub fn classify_udp(destination_port: u16, payload: &[u8]) -> UdpClass {
    match destination_port {
        53 => UdpClass::Dns,
        123 => UdpClass::NtpLike,
        443 if classify_quic_candidate(443, payload) => UdpClass::QuicCandidate,
        _ => UdpClass::Generic,
    }
}

/// ICMP echo metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpEcho<'a> {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

pub fn parse_icmp_echo_request(payload: &[u8]) -> Result<IcmpEcho<'_>, String> {
    if payload.len() < 8 {
        return Err("ICMP packet too short".to_string());
    }
    if payload[0] != 8 || payload[1] != 0 {
        return Err("ICMP packet is not echo request".to_string());
    }
    if checksum(payload) != 0 {
        return Err("ICMP checksum invalid".to_string());
    }
    Ok(IcmpEcho {
        identifier: u16::from_be_bytes([payload[4], payload[5]]),
        sequence: u16::from_be_bytes([payload[6], payload[7]]),
        payload: &payload[8..],
    })
}

/// Synthesize an IPv4 ICMP echo reply by reversing source/destination and recalculating checksums.
pub fn synthesize_icmp_echo_reply(request_packet: &[u8]) -> Result<Vec<u8>, String> {
    let parsed = parse_ipv4(request_packet)?;
    if parsed.protocol_number != 1 {
        return Err("not ICMP".to_string());
    }
    let echo = parse_icmp_echo_request(parsed.payload)?;
    let icmp_len = 8 + echo.payload.len();
    let total_len = 20 + icmp_len;
    let mut out = vec![0u8; total_len];
    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[4..6].copy_from_slice(&request_packet[4..6]);
    out[6..8].copy_from_slice(&[0, 0]);
    out[8] = 64;
    out[9] = 1;
    out[12..16].copy_from_slice(&parsed.destination.octets());
    out[16..20].copy_from_slice(&parsed.source.octets());
    let header_sum = checksum(&out[..20]);
    out[10..12].copy_from_slice(&header_sum.to_be_bytes());

    let icmp = &mut out[20..];
    icmp[0] = 0; // echo reply
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&echo.identifier.to_be_bytes());
    icmp[6..8].copy_from_slice(&echo.sequence.to_be_bytes());
    icmp[8..].copy_from_slice(echo.payload);
    let icmp_sum = checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_sum.to_be_bytes());
    Ok(out)
}

pub fn flow_key_from_tcp(packet: &Ipv4Packet<'_>, tcp: &TcpSegment<'_>) -> FlowKey {
    FlowKey::new(
        IpAddr::V4(packet.source),
        tcp.source_port,
        IpAddr::V4(packet.destination),
        tcp.destination_port,
        Protocol::Tcp,
    )
}

pub fn flow_key_from_udp(packet: &Ipv4Packet<'_>, udp: &UdpDatagram<'_>) -> FlowKey {
    FlowKey::new(
        IpAddr::V4(packet.source),
        udp.source_port,
        IpAddr::V4(packet.destination),
        udp.destination_port,
        Protocol::Udp,
    )
}

/// Internet checksum. Returned value is what should be written to a zeroed checksum field.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp_and_classifies_dns() {
        let packet = ipv4_packet(17, &[0xc3, 0x50, 0x00, 0x35, 0x00, 0x0c, 0, 0, 1, 2, 3, 4]);
        let ipv4 = parse_ipv4(&packet).unwrap();
        assert_eq!(ipv4.source, Ipv4Addr::new(10, 0, 2, 2));
        let udp = parse_udp(ipv4.payload).unwrap();
        assert_eq!(udp.destination_port, 53);
        assert_eq!(udp.class, UdpClass::Dns);
    }

    #[test]
    fn rejects_ipv4_fragments_fail_closed() {
        let mut packet = ipv4_packet(17, &[0u8; 8]);
        packet[6] = 0x20;
        packet[10] = 0;
        packet[11] = 0;
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        assert!(parse_ipv4(&packet).unwrap_err().contains("fragmentation"));
    }

    #[test]
    fn synthesizes_valid_icmp_echo_reply() {
        let request = icmp_echo_request_packet();
        let reply = synthesize_icmp_echo_reply(&request).unwrap();
        let ipv4 = parse_ipv4(&reply).unwrap();
        assert_eq!(ipv4.source, Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(ipv4.destination, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(ipv4.payload[0], 0);
        assert_eq!(checksum(ipv4.payload), 0);
    }

    pub(crate) fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 2, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 2, 1]);
        packet[20..].copy_from_slice(payload);
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn icmp_echo_request_packet() -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'];
        let sum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        ipv4_packet(1, &icmp)
    }
}
