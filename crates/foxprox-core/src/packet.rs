use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketError {
    Empty,
    UnsupportedIpVersion {
        version: u8,
    },
    TruncatedIpv4Header,
    InvalidIpv4HeaderLength {
        ihl_bytes: usize,
    },
    TruncatedIpv4Packet {
        total_len: usize,
        actual_len: usize,
    },
    UnsupportedIpv4Options,
    UnsupportedFragmentation,
    InvalidChecksum,
    TruncatedIcmp,
    UnsupportedIcmpType {
        type_: u8,
        code: u8,
    },
    TruncatedUdp,
    InvalidUdpLength {
        udp_len: usize,
        actual_len: usize,
    },
    TruncatedTcp,
    InvalidTcpHeaderLength {
        data_offset_bytes: usize,
    },
    TruncatedTcpOptions {
        header_len: usize,
        actual_len: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedIpPacket<'a> {
    Icmpv4EchoRequest(Icmpv4EchoRequest<'a>),
    Tcpv4Segment(Tcpv4Segment<'a>),
    Udpv4Packet(Udpv4Packet<'a>),
    UnsupportedIpv4Protocol(UnsupportedIpv4Protocol<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedIpv4Protocol<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv4EchoRequest<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Udpv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tcpv4Segment<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
    pub payload: &'a [u8],
}

impl Tcpv4Segment<'_> {
    pub fn is_connect_attempt(&self) -> bool {
        self.syn && !self.ack && !self.rst
    }
}

pub fn parse_ip_packet(bytes: &[u8]) -> Result<ParsedIpPacket<'_>, PacketError> {
    let first = *bytes.first().ok_or(PacketError::Empty)?;
    let version = first >> 4;
    match version {
        4 => parse_ipv4_packet(bytes),
        other => Err(PacketError::UnsupportedIpVersion { version: other }),
    }
}

fn parse_ipv4_packet(bytes: &[u8]) -> Result<ParsedIpPacket<'_>, PacketError> {
    if bytes.len() < 20 {
        return Err(PacketError::TruncatedIpv4Header);
    }
    let ihl_bytes = ((bytes[0] & 0x0f) as usize) * 4;
    if ihl_bytes < 20 {
        return Err(PacketError::InvalidIpv4HeaderLength { ihl_bytes });
    }
    if bytes.len() < ihl_bytes {
        return Err(PacketError::TruncatedIpv4Header);
    }
    if ihl_bytes != 20 {
        return Err(PacketError::UnsupportedIpv4Options);
    }
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if bytes.len() < total_len {
        return Err(PacketError::TruncatedIpv4Packet {
            total_len,
            actual_len: bytes.len(),
        });
    }
    if checksum(&bytes[..ihl_bytes]) != 0 {
        return Err(PacketError::InvalidChecksum);
    }
    let flags_fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    let more_fragments = (flags_fragment & 0x2000) != 0;
    let fragment_offset = flags_fragment & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return Err(PacketError::UnsupportedFragmentation);
    }
    let protocol = bytes[9];
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let payload = &bytes[ihl_bytes..total_len];
    match protocol {
        1 => parse_icmpv4(source, destination, payload),
        6 => parse_tcpv4(source, destination, payload),
        17 => parse_udpv4(source, destination, payload),
        other => Ok(ParsedIpPacket::UnsupportedIpv4Protocol(
            UnsupportedIpv4Protocol {
                source,
                destination,
                protocol: other,
                payload,
            },
        )),
    }
}

fn parse_icmpv4<'a>(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &'a [u8],
) -> Result<ParsedIpPacket<'a>, PacketError> {
    if payload.len() < 8 {
        return Err(PacketError::TruncatedIcmp);
    }
    if checksum(payload) != 0 {
        return Err(PacketError::InvalidChecksum);
    }
    let type_ = payload[0];
    let code = payload[1];
    match (type_, code) {
        (8, 0) => Ok(ParsedIpPacket::Icmpv4EchoRequest(Icmpv4EchoRequest {
            source,
            destination,
            identifier: u16::from_be_bytes([payload[4], payload[5]]),
            sequence: u16::from_be_bytes([payload[6], payload[7]]),
            payload: &payload[8..],
        })),
        _ => Err(PacketError::UnsupportedIcmpType { type_, code }),
    }
}

fn parse_tcpv4<'a>(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &'a [u8],
) -> Result<ParsedIpPacket<'a>, PacketError> {
    if payload.len() < 20 {
        return Err(PacketError::TruncatedTcp);
    }
    let data_offset_bytes = ((payload[12] >> 4) as usize) * 4;
    if data_offset_bytes < 20 {
        return Err(PacketError::InvalidTcpHeaderLength { data_offset_bytes });
    }
    if payload.len() < data_offset_bytes {
        return Err(PacketError::TruncatedTcpOptions {
            header_len: data_offset_bytes,
            actual_len: payload.len(),
        });
    }
    if ipv4_pseudo_checksum(source, destination, 6, payload) != 0 {
        return Err(PacketError::InvalidChecksum);
    }
    let flags = payload[13];
    Ok(ParsedIpPacket::Tcpv4Segment(Tcpv4Segment {
        source,
        destination,
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        sequence: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        acknowledgement: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        syn: (flags & 0x02) != 0,
        ack: (flags & 0x10) != 0,
        rst: (flags & 0x04) != 0,
        fin: (flags & 0x01) != 0,
        payload: &payload[data_offset_bytes..],
    }))
}

fn parse_udpv4<'a>(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &'a [u8],
) -> Result<ParsedIpPacket<'a>, PacketError> {
    if payload.len() < 8 {
        return Err(PacketError::TruncatedUdp);
    }
    let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if udp_len < 8 || udp_len > payload.len() {
        return Err(PacketError::InvalidUdpLength {
            udp_len,
            actual_len: payload.len(),
        });
    }
    let udp_payload = &payload[..udp_len];
    let udp_checksum = u16::from_be_bytes([payload[6], payload[7]]);
    if udp_checksum != 0 && ipv4_pseudo_checksum(source, destination, 17, udp_payload) != 0 {
        return Err(PacketError::InvalidChecksum);
    }
    Ok(ParsedIpPacket::Udpv4Packet(Udpv4Packet {
        source,
        destination,
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        payload: &payload[8..udp_len],
    }))
}

pub fn synthesize_udpv4_response(request: &Udpv4Packet<'_>, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&request.destination.octets());
    packet[16..20].copy_from_slice(&request.source.octets());
    let ip_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&request.destination_port.to_be_bytes());
    udp[2..4].copy_from_slice(&request.source_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let udp_checksum = ipv4_pseudo_checksum(request.destination, request.source, 17, udp);
    udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());
    packet
}

pub fn synthesize_icmpv4_echo_reply(request: &Icmpv4EchoRequest<'_>) -> Vec<u8> {
    let icmp_len = 8 + request.payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&request.destination.octets());
    packet[16..20].copy_from_slice(&request.source.octets());
    let ip_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp = &mut packet[20..];
    icmp[0] = 0;
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&request.identifier.to_be_bytes());
    icmp[6..8].copy_from_slice(&request.sequence.to_be_bytes());
    icmp[8..].copy_from_slice(request.payload);
    let icmp_checksum = checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

pub fn packet_addrs(packet: &ParsedIpPacket<'_>) -> (IpAddr, IpAddr) {
    match packet {
        ParsedIpPacket::Icmpv4EchoRequest(echo) => {
            (IpAddr::V4(echo.source), IpAddr::V4(echo.destination))
        }
        ParsedIpPacket::Tcpv4Segment(segment) => {
            (IpAddr::V4(segment.source), IpAddr::V4(segment.destination))
        }
        ParsedIpPacket::Udpv4Packet(packet) => {
            (IpAddr::V4(packet.source), IpAddr::V4(packet.destination))
        }
        ParsedIpPacket::UnsupportedIpv4Protocol(packet) => {
            (IpAddr::V4(packet.source), IpAddr::V4(packet.destination))
        }
    }
}

fn ipv4_pseudo_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let mut sum = 0u32;
    sum = add_checksum_bytes(sum, &source.octets());
    sum = add_checksum_bytes(sum, &destination.octets());
    sum = add_checksum_bytes(sum, &[0, protocol]);
    sum = add_checksum_bytes(sum, &(payload.len() as u16).to_be_bytes());
    sum = add_checksum_bytes(sum, payload);
    finish_checksum(sum)
}

fn checksum(bytes: &[u8]) -> u16 {
    finish_checksum(add_checksum_bytes(0, bytes))
}

fn add_checksum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&remaining) = chunks.remainder().first() {
        sum += (remaining as u32) << 8;
    }
    sum
}

fn finish_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_icmp_echo_and_synthesizes_reversed_reply() {
        let request = build_echo_request(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        let parsed = parse_ip_packet(&request).unwrap();
        let ParsedIpPacket::Icmpv4EchoRequest(echo) = parsed else {
            panic!("expected echo request");
        };
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence, 7);
        assert_eq!(echo.payload, b"hello");

        let reply = synthesize_icmpv4_echo_reply(&echo);
        let reply_echo = parse_echo_reply(&reply);
        assert_eq!(reply_echo.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(reply_echo.destination, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(reply_echo.identifier, 0x1234);
        assert_eq!(reply_echo.sequence, 7);
        assert_eq!(reply_echo.payload, b"hello");
    }

    #[test]
    fn parses_udp_packet_ports_and_payload() {
        let packet = build_udp_packet(b"dns?");
        let parsed = parse_ip_packet(&packet).unwrap();
        let ParsedIpPacket::Udpv4Packet(udp) = parsed else {
            panic!("expected udp packet");
        };
        assert_eq!(udp.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(udp.destination, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(udp.source_port, 53000);
        assert_eq!(udp.destination_port, 53);
        assert_eq!(udp.payload, b"dns?");
    }

    #[test]
    fn parses_tcp_syn_as_connect_attempt() {
        let packet = build_tcp_packet(0x02, &[]);
        let parsed = parse_ip_packet(&packet).unwrap();
        let ParsedIpPacket::Tcpv4Segment(tcp) = parsed else {
            panic!("expected tcp segment");
        };
        assert_eq!(tcp.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(tcp.destination, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(tcp.source_port, 53000);
        assert_eq!(tcp.destination_port, 80);
        assert_eq!(tcp.sequence, 0x01020304);
        assert!(tcp.is_connect_attempt());
    }

    #[test]
    fn tcp_checksum_is_mandatory_and_validated() {
        let mut packet = build_tcp_packet(0x02, &[]);
        packet[36] = 0x12;
        packet[37] = 0x34;

        assert_eq!(parse_ip_packet(&packet), Err(PacketError::InvalidChecksum));
    }

    #[test]
    fn invalid_tcp_header_length_fails_closed() {
        let mut packet = build_tcp_packet(0x02, &[]);
        packet[32] = 0x40;
        packet[10] = 0;
        packet[11] = 0;
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        assert_eq!(
            parse_ip_packet(&packet),
            Err(PacketError::InvalidTcpHeaderLength {
                data_offset_bytes: 16,
            })
        );
    }

    #[test]
    fn synthesizes_reversed_udp_response_with_checksum() {
        let packet = build_udp_packet(b"query");
        let ParsedIpPacket::Udpv4Packet(request) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected udp packet");
        };

        let response = synthesize_udpv4_response(&request, b"answer");
        let ParsedIpPacket::Udpv4Packet(parsed) = parse_ip_packet(&response).unwrap() else {
            panic!("expected udp response");
        };

        assert_eq!(parsed.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.destination, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 53000);
        assert_eq!(parsed.payload, b"answer");
        assert_ne!(u16::from_be_bytes([response[26], response[27]]), 0);
    }

    #[test]
    fn invalid_udp_length_fails_closed() {
        let mut packet = build_udp_packet(b"dns?");
        packet[24] = 0;
        packet[25] = 7;
        packet[10] = 0;
        packet[11] = 0;
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());

        assert_eq!(
            parse_ip_packet(&packet),
            Err(PacketError::InvalidUdpLength {
                udp_len: 7,
                actual_len: 12,
            })
        );
    }

    #[test]
    fn invalid_udp_checksum_fails_closed_when_present() {
        let mut packet = build_udp_packet(b"dns?");
        packet[26] = 0x12;
        packet[27] = 0x34;

        assert_eq!(parse_ip_packet(&packet), Err(PacketError::InvalidChecksum));
    }

    #[test]
    fn unsupported_fragmentation_fails_closed() {
        let mut packet = build_echo_request(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        packet[6] = 0x20;
        packet[10] = 0;
        packet[11] = 0;
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(
            parse_ip_packet(&packet),
            Err(PacketError::UnsupportedFragmentation)
        );
    }

    #[test]
    fn invalid_checksum_is_rejected() {
        let mut packet = build_echo_request(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        packet[12] = 192;
        assert_eq!(parse_ip_packet(&packet), Err(PacketError::InvalidChecksum));
    }

    struct EchoReply {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    }

    fn parse_echo_reply(packet: &[u8]) -> EchoReply {
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(packet[9], 1);
        let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let icmp = &packet[20..];
        assert_eq!(checksum(icmp), 0);
        assert_eq!(icmp[0], 0);
        EchoReply {
            source,
            destination,
            identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
            sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
            payload: icmp[8..].to_vec(),
        }
    }

    fn build_udp_packet(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[26..28].copy_from_slice(&0u16.to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn build_tcp_packet(flags: u8, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let total_len = 20 + tcp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());
        packet[24..28].copy_from_slice(&0x01020304u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&4096u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let tcp_checksum = ipv4_pseudo_checksum(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            6,
            &packet[20..],
        );
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn build_echo_request(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let payload = b"hello";
        let total_len = 20 + 8 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let icmp = &mut packet[20..];
        icmp[0] = 8;
        icmp[1] = 0;
        icmp[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&7u16.to_be_bytes());
        icmp[8..].copy_from_slice(payload);
        let icmp_checksum = checksum(icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        packet
    }
}
