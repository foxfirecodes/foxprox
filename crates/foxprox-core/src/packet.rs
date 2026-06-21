use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::PolicyRequest;
use crate::types::{Endpoint, IcmpMessage, Protocol};

/// Validated, normalized metadata extracted from an inbound IP packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PacketSummary {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Protocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub icmp: Option<IcmpMessage>,
}

impl PacketSummary {
    pub fn destination_endpoint(&self) -> Endpoint {
        Endpoint::new(self.destination, self.destination_port)
    }

    pub fn source_endpoint(&self) -> Endpoint {
        Endpoint::new(self.source, self.source_port)
    }

    pub fn to_policy_request(&self) -> PolicyRequest {
        PolicyRequest {
            protocol: self.protocol,
            source: Some(self.source_endpoint()),
            destination: Some(self.destination_endpoint()),
            requested_port: self.destination_port,
            icmp: self.icmp,
            ..PolicyRequest::new(self.protocol)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PacketParseError {
    Empty,
    UnsupportedIpVersion(u8),
    TruncatedIpHeader,
    InvalidIpv4HeaderLength,
    InvalidIpv4TotalLength,
    UnsupportedIpv4Fragmentation,
    UnsupportedIpv6ExtensionHeader(u8),
    UnsupportedProtocol(u8),
    TruncatedTransportHeader,
    InvalidTcpHeaderLength,
    InvalidUdpLength,
}

pub fn parse_ip_packet(packet: &[u8]) -> Result<PacketSummary, PacketParseError> {
    let Some(first) = packet.first() else {
        return Err(PacketParseError::Empty);
    };

    match first >> 4 {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        version => Err(PacketParseError::UnsupportedIpVersion(version)),
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Result<PacketSummary, PacketParseError> {
    if packet.len() < 20 {
        return Err(PacketParseError::TruncatedIpHeader);
    }

    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 {
        return Err(PacketParseError::InvalidIpv4HeaderLength);
    }
    if packet.len() < ihl {
        return Err(PacketParseError::TruncatedIpHeader);
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl {
        return Err(PacketParseError::InvalidIpv4TotalLength);
    }
    if packet.len() < total_len {
        return Err(PacketParseError::TruncatedIpHeader);
    }

    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = flags_fragment & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return Err(PacketParseError::UnsupportedIpv4Fragmentation);
    }

    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    parse_transport(packet[9], source, destination, &packet[ihl..total_len])
}

fn parse_ipv6_packet(packet: &[u8]) -> Result<PacketSummary, PacketParseError> {
    if packet.len() < 40 {
        return Err(PacketParseError::TruncatedIpHeader);
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = 40 + payload_len;
    if packet.len() < total_len {
        return Err(PacketParseError::TruncatedIpHeader);
    }

    let next_header = packet[6];
    if is_ipv6_extension_header(next_header) {
        return Err(PacketParseError::UnsupportedIpv6ExtensionHeader(
            next_header,
        ));
    }

    let source = IpAddr::V6(Ipv6Addr::from(read_16_bytes(packet, 8)));
    let destination = IpAddr::V6(Ipv6Addr::from(read_16_bytes(packet, 24)));
    parse_transport(next_header, source, destination, &packet[40..total_len])
}

fn parse_transport(
    protocol_number: u8,
    source: IpAddr,
    destination: IpAddr,
    payload: &[u8],
) -> Result<PacketSummary, PacketParseError> {
    match protocol_number {
        1 => parse_icmp(source, destination, payload, false),
        6 => parse_tcp(source, destination, payload),
        17 => parse_udp(source, destination, payload),
        58 => parse_icmp(source, destination, payload, true),
        other => Err(PacketParseError::UnsupportedProtocol(other)),
    }
}

fn parse_tcp(
    source: IpAddr,
    destination: IpAddr,
    payload: &[u8],
) -> Result<PacketSummary, PacketParseError> {
    if payload.len() < 20 {
        return Err(PacketParseError::TruncatedTransportHeader);
    }
    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if data_offset < 20 || data_offset > payload.len() {
        return Err(PacketParseError::InvalidTcpHeaderLength);
    }

    Ok(PacketSummary {
        source,
        destination,
        protocol: classify_ports(Protocol::Tcp, source_port, destination_port),
        source_port: Some(source_port),
        destination_port: Some(destination_port),
        icmp: None,
    })
}

fn parse_udp(
    source: IpAddr,
    destination: IpAddr,
    payload: &[u8],
) -> Result<PacketSummary, PacketParseError> {
    if payload.len() < 8 {
        return Err(PacketParseError::TruncatedTransportHeader);
    }
    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let udp_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if udp_len < 8 || udp_len > payload.len() {
        return Err(PacketParseError::InvalidUdpLength);
    }

    Ok(PacketSummary {
        source,
        destination,
        protocol: classify_ports(Protocol::Udp, source_port, destination_port),
        source_port: Some(source_port),
        destination_port: Some(destination_port),
        icmp: None,
    })
}

fn parse_icmp(
    source: IpAddr,
    destination: IpAddr,
    payload: &[u8],
    ipv6: bool,
) -> Result<PacketSummary, PacketParseError> {
    if payload.len() < 4 {
        return Err(PacketParseError::TruncatedTransportHeader);
    }

    let icmp = if ipv6 {
        IcmpMessage::ipv6(payload[0], payload[1])
    } else {
        IcmpMessage::ipv4(payload[0], payload[1])
    };

    Ok(PacketSummary {
        source,
        destination,
        protocol: Protocol::Icmp,
        source_port: None,
        destination_port: None,
        icmp: Some(icmp),
    })
}

fn classify_ports(default: Protocol, source_port: u16, destination_port: u16) -> Protocol {
    if source_port == 53 || destination_port == 53 {
        Protocol::Dns
    } else if default == Protocol::Udp && destination_port == 443 {
        Protocol::QuicCandidate
    } else {
        default
    }
}

fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140)
}

fn read_16_bytes(packet: &[u8], start: usize) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&packet[start..start + 16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet.extend_from_slice(payload);
        packet
    }

    fn tcp_header(source_port: u16, destination_port: u16) -> [u8; 20] {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp
    }

    fn udp_header(source_port: u16, destination_port: u16) -> [u8; 8] {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        udp
    }

    #[test]
    fn extracts_ipv4_tcp_metadata() {
        let summary = parse_ip_packet(&ipv4_packet(6, &tcp_header(49152, 80))).unwrap();
        assert_eq!(summary.protocol, Protocol::Tcp);
        assert_eq!(summary.source, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            summary.destination,
            "93.184.216.34".parse::<IpAddr>().unwrap()
        );
        assert_eq!(summary.source_port, Some(49152));
        assert_eq!(summary.destination_port, Some(80));
    }

    #[test]
    fn classifies_dns_and_quic_candidate_udp() {
        let dns = parse_ip_packet(&ipv4_packet(17, &udp_header(49152, 53))).unwrap();
        assert_eq!(dns.protocol, Protocol::Dns);

        let quic = parse_ip_packet(&ipv4_packet(17, &udp_header(49152, 443))).unwrap();
        assert_eq!(quic.protocol, Protocol::QuicCandidate);
    }

    #[test]
    fn extracts_ipv6_icmp_metadata() {
        let summary = parse_ip_packet(&ipv6_packet(58, &[128, 0, 0, 0])).unwrap();
        assert_eq!(summary.protocol, Protocol::Icmp);
        assert_eq!(summary.icmp, Some(IcmpMessage::ipv6(128, 0)));
        assert_eq!(summary.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            summary.destination,
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn malformed_packet_lengths_fail_closed() {
        assert_eq!(parse_ip_packet(&[]), Err(PacketParseError::Empty));
        assert_eq!(
            parse_ip_packet(&[0x45; 10]),
            Err(PacketParseError::TruncatedIpHeader)
        );

        let mut bad_total = ipv4_packet(6, &tcp_header(1, 2));
        bad_total[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(
            parse_ip_packet(&bad_total),
            Err(PacketParseError::InvalidIpv4TotalLength)
        );

        let mut bad_tcp = tcp_header(1, 2);
        bad_tcp[12] = 4 << 4;
        assert_eq!(
            parse_ip_packet(&ipv4_packet(6, &bad_tcp)),
            Err(PacketParseError::InvalidTcpHeaderLength)
        );

        let mut bad_udp = udp_header(1, 2);
        bad_udp[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            parse_ip_packet(&ipv4_packet(17, &bad_udp)),
            Err(PacketParseError::InvalidUdpLength)
        );
    }

    #[test]
    fn unsupported_protocols_and_fragmentation_fail_closed() {
        assert_eq!(
            parse_ip_packet(&ipv4_packet(99, &[])),
            Err(PacketParseError::UnsupportedProtocol(99))
        );

        let mut fragment = ipv4_packet(17, &udp_header(1, 2));
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert_eq!(
            parse_ip_packet(&fragment),
            Err(PacketParseError::UnsupportedIpv4Fragmentation)
        );

        assert_eq!(
            parse_ip_packet(&ipv6_packet(0, &[])),
            Err(PacketParseError::UnsupportedIpv6ExtensionHeader(0))
        );
    }

    #[test]
    fn parsed_summary_builds_policy_request() {
        let summary = parse_ip_packet(&ipv4_packet(17, &udp_header(49152, 53))).unwrap();
        let request = summary.to_policy_request();
        assert_eq!(request.protocol, Protocol::Dns);
        assert_eq!(request.destination, Some(summary.destination_endpoint()));
        assert_eq!(request.source, Some(summary.source_endpoint()));
    }
}
