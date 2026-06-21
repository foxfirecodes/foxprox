use crate::audit::AuditRecord;
use crate::types::{AuditKind, Decision, DenialReason, Frontend, NetworkEndpoint, Protocol};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedIpPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Protocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub payload_len: usize,
}

impl ParsedIpPacket {
    pub fn parse_ipv4(packet: &[u8]) -> Result<Self, IpParseError> {
        if packet.len() < 20 {
            return Err(IpParseError::MalformedPacket("short_ipv4_header"));
        }
        let version = packet[0] >> 4;
        let ihl = (packet[0] & 0x0f) as usize * 4;
        if version != 4 || ihl < 20 || packet.len() < ihl {
            return Err(IpParseError::MalformedPacket("invalid_ipv4_header"));
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total_len < ihl || packet.len() < total_len {
            return Err(IpParseError::MalformedPacket("invalid_ipv4_total_length"));
        }
        let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
        let more_fragments = flags_fragment & 0x2000 != 0;
        let fragment_offset = flags_fragment & 0x1fff;
        if more_fragments || fragment_offset != 0 {
            return Err(IpParseError::UnsupportedFragmentation);
        }
        let source = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let destination = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        let payload = &packet[ihl..total_len];
        let (protocol, source_port, destination_port, icmp_type, icmp_code) = match packet[9] {
            1 => {
                if payload.len() < 4 {
                    return Err(IpParseError::MalformedPacket("short_icmp_header"));
                }
                (
                    Protocol::Icmp,
                    None,
                    None,
                    Some(payload[0]),
                    Some(payload[1]),
                )
            }
            6 => {
                if payload.len() < 20 {
                    return Err(IpParseError::MalformedPacket("short_tcp_header"));
                }
                (
                    Protocol::Tcp,
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                    None,
                    None,
                )
            }
            17 => {
                if payload.len() < 8 {
                    return Err(IpParseError::MalformedPacket("short_udp_header"));
                }
                (
                    Protocol::Udp,
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                    None,
                    None,
                )
            }
            other => return Err(IpParseError::UnsupportedProtocol(other)),
        };
        Ok(Self {
            source,
            destination,
            protocol,
            source_port,
            destination_port,
            icmp_type,
            icmp_code,
            payload_len: payload.len(),
        })
    }

    pub fn source_endpoint(&self) -> NetworkEndpoint {
        NetworkEndpoint {
            ip: Some(self.source),
            port: self.source_port,
        }
    }

    pub fn destination_endpoint(&self) -> NetworkEndpoint {
        NetworkEndpoint {
            ip: Some(self.destination),
            port: self.destination_port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpParseError {
    MalformedPacket(&'static str),
    UnsupportedFragmentation,
    UnsupportedProtocol(u8),
}

impl IpParseError {
    pub fn denial_reason(&self) -> DenialReason {
        match self {
            Self::MalformedPacket(_) => DenialReason::MalformedPacket,
            Self::UnsupportedFragmentation => DenialReason::UnsupportedFragmentation,
            Self::UnsupportedProtocol(_) => DenialReason::UnsupportedProtocol,
        }
    }

    pub fn audit_record(&self, sandbox_id: impl Into<String>) -> AuditRecord {
        let mut audit = AuditRecord::new(AuditKind::PacketMalformedDenied, sandbox_id)
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Unsupported)
            .with_decision(Decision::FailClosed, Some(self.denial_reason()));
        match self {
            Self::MalformedPacket(reason) => {
                audit = audit.with_detail("parse_error", *reason);
            }
            Self::UnsupportedFragmentation => {
                audit = audit.with_detail("parse_error", "unsupported_fragmentation");
            }
            Self::UnsupportedProtocol(protocol) => {
                audit = audit.with_detail("unsupported_ip_protocol", protocol.to_string());
            }
        }
        audit
    }
}

pub fn synthesize_icmpv4_echo_reply(packet: &[u8]) -> Result<Vec<u8>, IpParseError> {
    let parsed = ParsedIpPacket::parse_ipv4(packet)?;
    if parsed.protocol != Protocol::Icmp || parsed.icmp_type != Some(8) {
        return Err(IpParseError::MalformedPacket("not_icmp_echo_request"));
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len.saturating_sub(ihl) < 8 {
        return Err(IpParseError::MalformedPacket("short_icmp_echo_header"));
    }
    let mut reply = packet[..total_len].to_vec();

    // Swap IPv4 source/destination.
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // ICMP echo reply type; keep code/id/sequence/payload.
    reply[ihl] = 0;
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_checksum = checksum(&reply[ihl..total_len]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(reply)
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_ipv4_udp_packet_with_ports() {
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x00, 0x35, 0, 8, 0, 0]);
        let parsed = ParsedIpPacket::parse_ipv4(&packet).unwrap();
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.source_port, Some(0x1234));
        assert_eq!(parsed.destination_port, Some(53));
        assert_eq!(parsed.source, "10.0.2.15".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.destination, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn short_tcp_udp_and_icmp_headers_fail_closed() {
        let tcp = ipv4_packet(6, 0, &[0x12, 0x34, 0x00, 0x50]);
        assert_eq!(
            ParsedIpPacket::parse_ipv4(&tcp).unwrap_err(),
            IpParseError::MalformedPacket("short_tcp_header")
        );

        let udp = ipv4_packet(17, 0, &[0x12, 0x34, 0x00, 0x35]);
        assert_eq!(
            ParsedIpPacket::parse_ipv4(&udp).unwrap_err(),
            IpParseError::MalformedPacket("short_udp_header")
        );

        let icmp = ipv4_packet(1, 0, &[8, 0]);
        assert_eq!(
            synthesize_icmpv4_echo_reply(&icmp).unwrap_err(),
            IpParseError::MalformedPacket("short_icmp_header")
        );
    }

    #[test]
    fn fragmented_ipv4_fails_closed_with_structured_audit() {
        let packet = ipv4_packet(17, 0x2000, &[0, 1, 0, 2, 0, 8, 0, 0]);
        let error = ParsedIpPacket::parse_ipv4(&packet).unwrap_err();
        assert_eq!(error, IpParseError::UnsupportedFragmentation);
        let audit = error.audit_record("s1");
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::UnsupportedFragmentation));
        assert_eq!(audit.details["parse_error"], "unsupported_fragmentation");
    }

    #[test]
    fn unsupported_ip_protocol_fails_closed_with_protocol_number() {
        let packet = ipv4_packet(132, 0, &[0, 1, 2, 3]);
        let error = ParsedIpPacket::parse_ipv4(&packet).unwrap_err();
        let audit = error.audit_record("s1");
        assert_eq!(audit.reason, Some(DenialReason::UnsupportedProtocol));
        assert_eq!(audit.details["unsupported_ip_protocol"], "132");
    }

    #[test]
    fn icmp_echo_reply_swaps_addresses_and_recomputes_checksums() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i'];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, 0, &icmp);
        let reply = synthesize_icmpv4_echo_reply(&packet).unwrap();
        assert_eq!(&reply[12..16], &[8, 8, 8, 8]);
        assert_eq!(&reply[16..20], &[10, 0, 2, 15]);
        assert_eq!(reply[20], 0);
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!(checksum(&reply[20..]), 0);
    }

    fn ipv4_packet(protocol: u8, flags_fragment: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 2, 15]);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        packet[20..].copy_from_slice(payload);
        let csum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&csum.to_be_bytes());
        packet
    }
}
