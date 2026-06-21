//! DNS subsystem boundary for alpha query normalization.
//!
//! DNS wire data is parsed here into normalized `foxprox-core` events. Policy and
//! audit do not consume DNS packet parser structs.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use foxprox_core::{
    DnsQuery, DnsQueryType, FrontendKind, Hostname, NormalizedEvent, SandboxId,
    UnsupportedNetworkEvent, UnsupportedReason,
};

/// Parse the first DNS question into a normalized event. Malformed packets become
/// unsupported normalized events so callers can fail closed and audit safely.
pub fn parse_dns_query_event(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    source: SocketAddr,
    destination: SocketAddr,
    broker_dns_addrs: &[IpAddr],
    packet: &[u8],
) -> NormalizedEvent {
    match parse_dns_query_inner(
        sandbox_id.clone(),
        frontend,
        source,
        destination,
        broker_dns_addrs,
        packet,
    ) {
        Ok(query) => NormalizedEvent::DnsQuery(query),
        Err(error) => NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id,
            frontend,
            reason: UnsupportedReason::MalformedPacket,
            safe_metadata: Some(error.to_string()),
        }),
    }
}

fn parse_dns_query_inner(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    source: SocketAddr,
    destination: SocketAddr,
    broker_dns_addrs: &[IpAddr],
    packet: &[u8],
) -> Result<DnsQuery, DnsError> {
    let parsed = parse_wire_query(packet)?;
    Ok(DnsQuery {
        sandbox_id,
        frontend,
        source,
        destination,
        hostname: parsed.hostname,
        query_type: parsed.query_type,
        direct_external: destination.port() == 53 && !broker_dns_addrs.contains(&destination.ip()),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedWireQuery {
    pub id: u16,
    pub hostname: Hostname,
    pub query_type: DnsQueryType,
    question_end: usize,
}

/// Parse one DNS wire query. Only the first question is exposed to alpha policy.
pub fn parse_wire_query(packet: &[u8]) -> Result<ParsedWireQuery, DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::Malformed("short DNS header"));
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if flags & 0x8000 != 0 {
        return Err(DnsError::Malformed("DNS message is a response"));
    }
    if qdcount == 0 {
        return Err(DnsError::Malformed("DNS query has no questions"));
    }

    let (hostname, after_name) = parse_qname(packet, 12)?;
    if packet.len() < after_name + 4 {
        return Err(DnsError::Malformed("short DNS question"));
    }
    let qtype = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
    let _qclass = u16::from_be_bytes([packet[after_name + 2], packet[after_name + 3]]);
    Ok(ParsedWireQuery {
        id,
        hostname,
        query_type: map_qtype(qtype),
        question_end: after_name + 4,
    })
}

fn parse_qname(packet: &[u8], mut offset: usize) -> Result<(Hostname, usize), DnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;
    let mut seen = 0_usize;
    loop {
        if offset >= packet.len() {
            return Err(DnsError::Malformed("QNAME overruns packet"));
        }
        seen += 1;
        if seen > 128 {
            return Err(DnsError::Malformed("QNAME compression loop"));
        }
        let len = packet[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError::Malformed("short QNAME pointer"));
            }
            let pointer = usize::from(u16::from_be_bytes([len & 0x3f, packet[offset + 1]]));
            if !jumped {
                end_offset = offset + 2;
            }
            jumped = true;
            offset = pointer;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(DnsError::Malformed("invalid QNAME label"));
        }
        offset += 1;
        if len == 0 {
            if !jumped {
                end_offset = offset;
            }
            break;
        }
        let label_len = usize::from(len);
        if offset + label_len > packet.len() {
            return Err(DnsError::Malformed("QNAME label overruns packet"));
        }
        let label = std::str::from_utf8(&packet[offset..offset + label_len])
            .map_err(|_| DnsError::Malformed("QNAME label utf8"))?;
        labels.push(label.to_string());
        offset += label_len;
    }
    if labels.is_empty() {
        return Err(DnsError::Malformed("root QNAME unsupported"));
    }
    let hostname =
        Hostname::new(labels.join(".")).map_err(|_| DnsError::Malformed("invalid hostname"))?;
    Ok((hostname, end_offset))
}

fn map_qtype(qtype: u16) -> DnsQueryType {
    match qtype {
        1 => DnsQueryType::A,
        5 => DnsQueryType::Cname,
        15 => DnsQueryType::Mx,
        16 => DnsQueryType::Txt,
        28 => DnsQueryType::Aaaa,
        33 => DnsQueryType::Srv,
        other => DnsQueryType::Other(other),
    }
}

/// Build a DNS REFUSED response that echoes the original first question.
pub fn build_refused_response(packet: &[u8]) -> Result<Vec<u8>, DnsError> {
    let parsed = parse_wire_query(packet)?;
    let mut response = Vec::with_capacity(parsed.question_end);
    response.extend_from_slice(&packet[..parsed.question_end]);
    // QR=1, RD copied, RA=0, RCODE=5 (refused). Preserve opcode from request.
    let request_flags = u16::from_be_bytes([packet[2], packet[3]]);
    let opcode = request_flags & 0x7800;
    let rd = request_flags & 0x0100;
    let response_flags = 0x8000 | opcode | rd | 0x0005;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[4..6].copy_from_slice(&1_u16.to_be_bytes()); // qdcount
    response[6..8].copy_from_slice(&0_u16.to_be_bytes()); // ancount
    response[8..10].copy_from_slice(&0_u16.to_be_bytes()); // nscount
    response[10..12].copy_from_slice(&0_u16.to_be_bytes()); // arcount
    Ok(response)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DnsError {
    Malformed(&'static str),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed DNS packet: {reason}"),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{Protocol, UnsupportedReason};

    fn sandbox() -> SandboxId {
        SandboxId::new("s1").unwrap()
    }

    #[test]
    fn parses_dns_query_to_normalized_event() {
        let packet = dns_query_packet(0x1234, "Example.COM", 1);
        let event = parse_dns_query_event(
            sandbox(),
            FrontendKind::Tun,
            "10.0.0.2:40000".parse().unwrap(),
            "10.255.0.1:53".parse().unwrap(),
            &["10.255.0.1".parse().unwrap()],
            &packet,
        );
        let NormalizedEvent::DnsQuery(query) = event else {
            panic!("expected DNS query");
        };
        assert_eq!(query.hostname.as_str(), "example.com");
        assert_eq!(query.query_type, DnsQueryType::A);
        assert!(!query.direct_external);
    }

    #[test]
    fn marks_direct_external_dns_bypass() {
        let packet = dns_query_packet(0x1234, "example.com", 28);
        let event = parse_dns_query_event(
            sandbox(),
            FrontendKind::Tun,
            "10.0.0.2:40000".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            &["10.255.0.1".parse().unwrap()],
            &packet,
        );
        let NormalizedEvent::DnsQuery(query) = event else {
            panic!("expected DNS query");
        };
        assert_eq!(query.query_type, DnsQueryType::Aaaa);
        assert!(query.direct_external);
    }

    #[test]
    fn malformed_dns_fails_closed() {
        let event = parse_dns_query_event(
            sandbox(),
            FrontendKind::Tun,
            "10.0.0.2:40000".parse().unwrap(),
            "10.255.0.1:53".parse().unwrap(),
            &["10.255.0.1".parse().unwrap()],
            &[0, 1, 2],
        );
        assert_eq!(event.protocol(), Protocol::Unsupported);
        let NormalizedEvent::UnsupportedNetworkEvent(unsupported) = event else {
            panic!("expected unsupported");
        };
        assert_eq!(unsupported.reason, UnsupportedReason::MalformedPacket);
    }

    #[test]
    fn builds_refused_response_with_original_question() {
        let packet = dns_query_packet(0xabcd, "example.com", 1);
        let response = build_refused_response(&packet).unwrap();
        assert_eq!(&response[0..2], &[0xab, 0xcd]);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x800f,
            0x8005
        );
        assert_eq!(&response[12..], &packet[12..]);
    }

    fn dns_query_packet(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        for label in hostname.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes()); // IN
        packet
    }
}
