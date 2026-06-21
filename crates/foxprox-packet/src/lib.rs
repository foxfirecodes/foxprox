//! Platform-independent packet parsing for foxprox.
//!
//! This crate owns raw packet buffers only long enough to normalize them into
//! `foxprox-core` events. Policy code should consume the normalized events, not
//! packet bytes or parser-specific objects.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::Ipv4Addr;

use foxprox_core::{
    DnsQuery, Endpoint, FrontendKind, IcmpMessage, NormalizedEvent, SandboxId, TcpConnectAttempt,
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
    InvalidUdpLength {
        udp_length: usize,
        actual: usize,
    },
    DnsHeaderTooShort {
        actual: usize,
    },
    DnsQuestionCountZero,
    DnsNameTooLong,
    DnsNameTruncated,
    DnsCompressionPointerUnsupported,
    DnsQuestionTooShort {
        remaining: usize,
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
            Self::InvalidUdpLength { udp_length, actual } => {
                format!("invalid-udp-length: udp_length={udp_length} actual={actual}")
            }
            Self::DnsHeaderTooShort { actual } => {
                format!("dns-header-too-short: actual={actual}")
            }
            Self::DnsQuestionCountZero => "dns-question-count-zero".to_owned(),
            Self::DnsNameTooLong => "dns-name-too-long".to_owned(),
            Self::DnsNameTruncated => "dns-name-truncated".to_owned(),
            Self::DnsCompressionPointerUnsupported => {
                "dns-compression-pointer-unsupported".to_owned()
            }
            Self::DnsQuestionTooShort { remaining } => {
                format!("dns-question-too-short: remaining={remaining}")
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

/// Packet synthesis failure for reply/write-back paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketBuildError {
    Parse(PacketParseError),
    NotIcmp { protocol: u8 },
    IcmpEchoTooShort { actual: usize },
    NotEchoRequest { icmp_type: u8, icmp_code: u8 },
    ReplyTooLarge { total_length: usize },
}

impl fmt::Display for PacketBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "cannot-parse-request: {error}"),
            Self::NotIcmp { protocol } => write!(f, "not-icmp: protocol={protocol}"),
            Self::IcmpEchoTooShort { actual } => write!(f, "icmp-echo-too-short: actual={actual}"),
            Self::NotEchoRequest {
                icmp_type,
                icmp_code,
            } => write!(
                f,
                "not-icmp-echo-request: type={icmp_type} code={icmp_code}"
            ),
            Self::ReplyTooLarge { total_length } => {
                write!(f, "icmp-echo-reply-too-large: total_length={total_length}")
            }
        }
    }
}

impl std::error::Error for PacketBuildError {}

impl From<PacketParseError> for PacketBuildError {
    fn from(value: PacketParseError) -> Self {
        Self::Parse(value)
    }
}

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
    let udp_length = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if udp_length < 8 || udp_length > payload.len() {
        return Err(PacketParseError::InvalidUdpLength {
            udp_length,
            actual: payload.len(),
        });
    }
    let udp_body = &payload[8..udp_length];

    if destination_port == 53 {
        let query = parse_dns_question(udp_body)?;
        return Ok(NormalizedEvent::DnsQuery(DnsQuery {
            sandbox_id: context.sandbox_id.clone(),
            frontend: context.frontend,
            source: Some(header.source_endpoint(Some(source_port))),
            resolver: header.destination_endpoint(Some(destination_port)),
            hostname: query.hostname,
            query_type: query.query_type,
        }));
    }

    let classification = match destination_port {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedDnsQuestion {
    hostname: String,
    query_type: String,
}

fn parse_dns_question(payload: &[u8]) -> Result<ParsedDnsQuestion, PacketParseError> {
    if payload.len() < 12 {
        return Err(PacketParseError::DnsHeaderTooShort {
            actual: payload.len(),
        });
    }

    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    if question_count == 0 {
        return Err(PacketParseError::DnsQuestionCountZero);
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        if offset >= payload.len() {
            return Err(PacketParseError::DnsNameTruncated);
        }
        let length = payload[offset];
        offset += 1;

        if length & 0xc0 != 0 {
            return Err(PacketParseError::DnsCompressionPointerUnsupported);
        }
        if length == 0 {
            break;
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(PacketParseError::DnsNameTooLong);
        }
        if offset + length > payload.len() {
            return Err(PacketParseError::DnsNameTruncated);
        }
        let label = std::str::from_utf8(&payload[offset..offset + length])
            .map_err(|_| PacketParseError::DnsNameTruncated)?;
        labels.push(label.to_ascii_lowercase());
        offset += length;
    }

    if payload.len() - offset < 4 {
        return Err(PacketParseError::DnsQuestionTooShort {
            remaining: payload.len() - offset,
        });
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);

    Ok(ParsedDnsQuestion {
        hostname: labels.join("."),
        query_type: dns_query_type(qtype).to_owned(),
    })
}

fn dns_query_type(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        65 => "HTTPS",
        _ => "UNKNOWN",
    }
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

/// Synthesize an IPv4 ICMP echo reply from an IPv4 ICMP echo request.
///
/// This is the minimal packet write-back proof path. It reverses IPv4
/// source/destination addresses, converts ICMP type 8 to type 0, and recomputes
/// IPv4 and ICMP checksums.
pub fn synthesize_icmp_echo_reply(request_packet: &[u8]) -> Result<Vec<u8>, PacketBuildError> {
    let request_header = Ipv4Header::parse(request_packet)?;
    if request_header.protocol != 1 {
        return Err(PacketBuildError::NotIcmp {
            protocol: request_header.protocol,
        });
    }

    let request_icmp = &request_packet[request_header.header_length..request_header.total_length];
    if request_icmp.len() < 8 {
        return Err(PacketBuildError::IcmpEchoTooShort {
            actual: request_icmp.len(),
        });
    }
    if request_icmp[0] != 8 || request_icmp[1] != 0 {
        return Err(PacketBuildError::NotEchoRequest {
            icmp_type: request_icmp[0],
            icmp_code: request_icmp[1],
        });
    }

    let total_length = 20 + request_icmp.len();
    if total_length > usize::from(u16::MAX) {
        return Err(PacketBuildError::ReplyTooLarge { total_length });
    }

    let mut reply = vec![0_u8; total_length];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    reply[8] = 64;
    reply[9] = 1;
    reply[12..16].copy_from_slice(&request_header.destination.octets());
    reply[16..20].copy_from_slice(&request_header.source.octets());

    reply[20..].copy_from_slice(request_icmp);
    reply[20] = 0;
    reply[21] = 0;
    reply[22] = 0;
    reply[23] = 0;
    let icmp_checksum = internet_checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());

    let ipv4_checksum = internet_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

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

    fn udp_payload_with_body(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
        let udp_length = 8 + body.len();
        let mut payload = vec![0_u8; udp_length];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
        payload[8..].copy_from_slice(body);
        payload
    }

    fn dns_query_body(hostname: &str, qtype: u16) -> Vec<u8> {
        let mut body = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // standard recursive query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        for label in hostname.split('.') {
            body.push(label.len() as u8);
            body.extend_from_slice(label.as_bytes());
        }
        body.push(0);
        body.extend_from_slice(&qtype.to_be_bytes());
        body.extend_from_slice(&1_u16.to_be_bytes()); // IN
        body
    }

    fn icmp_echo_request_payload() -> Vec<u8> {
        let mut payload = b"\x08\x00\x00\x00\x12\x34\x00\x01foxprox".to_vec();
        let checksum = internet_checksum(&payload);
        payload[2..4].copy_from_slice(&checksum.to_be_bytes());
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
    fn parses_udp_dns_query_packet_and_policy_denies_direct_external_dns() {
        let packet = ipv4_packet(
            17,
            [10, 0, 0, 2],
            [8, 8, 8, 8],
            &udp_payload_with_body(53000, 53, &dns_query_body("Example.COM", 1)),
        );
        let event = parse_ipv4_packet(&context(), &packet).unwrap();
        let engine = PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            dns: DnsPolicy {
                broker_resolvers: vec![Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53)],
                deny_direct_external_dns: true,
            },
            rules: Vec::new(),
            ..PolicyConfig::default()
        });

        let evaluation = engine.evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Dns);
        assert_eq!(event.hostname(), Some("example.com"));
        match &event {
            NormalizedEvent::DnsQuery(query) => assert_eq!(query.query_type, "A"),
            other => panic!("unexpected event: {other:?}"),
        }
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Deny {
                behavior: DenialBehavior::Drop,
                reason: "direct-external-dns-denied".to_owned(),
                rule_id: None,
            }
        );
        assert_eq!(evaluation.audit.kind, AuditKind::DnsQuery);
        assert_eq!(evaluation.audit.hostname.as_deref(), Some("example.com"));
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
    fn synthesizes_icmp_echo_reply_with_reversed_addresses_and_checksums() {
        let request = ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &icmp_echo_request_payload(),
        );

        let reply = synthesize_icmp_echo_reply(&request).unwrap();
        let event = parse_ipv4_packet(&context(), &reply).unwrap();

        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
        assert_eq!(
            event.source(),
            Some(Endpoint::new(Ipv4Addr::new(203, 0, 113, 10).into(), None))
        );
        assert_eq!(
            event.destination(),
            Some(Endpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), None))
        );
        match event {
            NormalizedEvent::IcmpMessage(message) => {
                assert_eq!(message.icmp_type, 0);
                assert_eq!(message.icmp_code, 0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn refuses_to_synthesize_icmp_reply_from_non_echo_request() {
        let packet = ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &[3, 0, 0, 0, 0, 0, 0, 0],
        );

        assert_eq!(
            synthesize_icmp_echo_reply(&packet),
            Err(PacketBuildError::NotEchoRequest {
                icmp_type: 3,
                icmp_code: 0,
            })
        );
    }

    #[test]
    fn malformed_dns_query_can_be_converted_to_fail_closed_event() {
        let packet = ipv4_packet(
            17,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &udp_payload_with_body(53000, 53, &[0x12, 0x34]),
        );

        assert_eq!(
            parse_ipv4_packet(&context(), &packet),
            Err(PacketParseError::DnsHeaderTooShort { actual: 2 })
        );
        let event = parse_ipv4_packet_fail_closed(&context(), &packet);
        let evaluation = PolicyEngine::new(PolicyConfig::default()).evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Unsupported);
        assert_eq!(evaluation.audit.decision, AuditDecision::FailClosed);
        assert_eq!(
            evaluation.decision,
            PolicyDecision::FailClosed {
                reason: "unsupported-network-event: dns-header-too-short: actual=2".to_owned()
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
