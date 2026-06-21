use crate::types::{Hostname, HostnameAttribution};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsObservation {
    pub hostname: Hostname,
    pub addresses: Vec<IpAddr>,
    pub observed_at_millis: u128,
    pub ttl_millis: u128,
}

impl DnsObservation {
    pub fn new(
        hostname: Hostname,
        addresses: Vec<IpAddr>,
        observed_at_millis: u128,
        ttl_millis: u128,
    ) -> Self {
        Self {
            hostname,
            addresses,
            observed_at_millis,
            ttl_millis,
        }
    }

    pub fn expires_at_millis(&self) -> u128 {
        self.observed_at_millis.saturating_add(self.ttl_millis)
    }

    pub fn is_live_at(&self, now_millis: u128) -> bool {
        now_millis <= self.expires_at_millis()
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsCache {
    observations: Vec<DnsObservation>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, observation: DnsObservation) {
        self.observations.push(observation);
    }

    pub fn record_response(
        &mut self,
        packet: &[u8],
        observed_at_millis: u128,
    ) -> Result<Option<DnsObservation>, DnsParseError> {
        let observation = parse_dns_response_observation(packet, observed_at_millis)?;
        if let Some(observation) = observation.clone() {
            self.record(observation);
        }
        Ok(observation)
    }

    pub fn expire(&mut self, now_millis: u128) {
        self.observations
            .retain(|observation| observation.is_live_at(now_millis));
    }

    pub fn lookup_ip(&self, ip: IpAddr, now_millis: u128) -> Option<HostnameAttribution> {
        self.observations
            .iter()
            .rev()
            .find(|observation| {
                observation.is_live_at(now_millis) && observation.addresses.contains(&ip)
            })
            .map(|observation| HostnameAttribution::broker_dns(observation.hostname.clone()))
    }

    pub fn observations(&self) -> &[DnsObservation] {
        &self.observations
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Other(u16),
}

impl DnsRecordType {
    fn from_wire(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::Aaaa,
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub hostname: Hostname,
    pub record_type: DnsRecordType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerDnsResponse {
    pub packet: Vec<u8>,
    pub observation: Option<DnsObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticDnsRecord {
    pub hostname: Hostname,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticDnsResolver {
    ttl_secs: u32,
    records: Vec<StaticDnsRecord>,
}

impl StaticDnsResolver {
    pub fn new(ttl_secs: u32) -> Self {
        Self {
            ttl_secs,
            records: Vec::new(),
        }
    }

    pub fn insert(&mut self, hostname: Hostname, addresses: Vec<IpAddr>) {
        self.records.push(StaticDnsRecord {
            hostname,
            addresses,
        });
    }

    pub fn resolve_query_packet(
        &self,
        query_packet: &[u8],
        observed_at_millis: u128,
    ) -> Result<BrokerDnsResponse, DnsParseError> {
        let question = parse_dns_query(query_packet)?;
        let addresses = self
            .records
            .iter()
            .find(|record| record.hostname == question.hostname)
            .map(|record| record.addresses.as_slice())
            .unwrap_or(&[]);
        let packet = synthesize_dns_response(query_packet, addresses, self.ttl_secs)?;
        let observation = parse_dns_response_observation(&packet, observed_at_millis)?;
        Ok(BrokerDnsResponse {
            packet,
            observation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsParseError {
    TruncatedHeader,
    TruncatedName,
    TruncatedQuestion,
    TruncatedRecord,
    InvalidLabelLength { len: u8 },
    InvalidCompressionPointer,
    CompressionLoop,
    InvalidHostname,
    UnsupportedOpcode { opcode: u8 },
    NotAQuery,
    NotAResponse,
    QuestionCountNotOne { count: u16 },
    UnsupportedClass { class: u16 },
    MalformedRecordData,
}

pub fn parse_dns_query(packet: &[u8]) -> Result<DnsQuestion, DnsParseError> {
    parse_dns_query_with_question_end(packet).map(|(question, _)| question)
}

pub fn synthesize_dns_response(
    query_packet: &[u8],
    addresses: &[IpAddr],
    ttl_secs: u32,
) -> Result<Vec<u8>, DnsParseError> {
    let (question, question_end) = parse_dns_query_with_question_end(query_packet)?;
    let matching_addresses: Vec<IpAddr> = addresses
        .iter()
        .copied()
        .filter(|address| {
            matches!(
                (question.record_type, address),
                (DnsRecordType::A, IpAddr::V4(_)) | (DnsRecordType::Aaaa, IpAddr::V6(_))
            )
        })
        .collect();

    let mut response = Vec::with_capacity(question_end + 16 * matching_addresses.len());
    response.extend_from_slice(&query_packet[..2]);
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(matching_addresses.len() as u16).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&query_packet[12..question_end]);

    for address in matching_addresses {
        response.extend_from_slice(&[0xc0, 0x0c]);
        match address {
            IpAddr::V4(ip) => {
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.extend_from_slice(&28u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&ip.octets());
            }
        }
    }

    Ok(response)
}

fn parse_dns_query_with_question_end(packet: &[u8]) -> Result<(DnsQuestion, usize), DnsParseError> {
    let header = DnsHeader::parse(packet)?;
    if header.is_response {
        return Err(DnsParseError::NotAQuery);
    }
    if header.opcode != 0 {
        return Err(DnsParseError::UnsupportedOpcode {
            opcode: header.opcode,
        });
    }
    if header.qdcount != 1 {
        return Err(DnsParseError::QuestionCountNotOne {
            count: header.qdcount,
        });
    }
    let (hostname, offset) = parse_name(packet, 12)?;
    parse_question_tail(packet, offset).map(|(record_type, end)| {
        (
            DnsQuestion {
                hostname,
                record_type,
            },
            end,
        )
    })
}

pub fn parse_dns_response_observation(
    packet: &[u8],
    observed_at_millis: u128,
) -> Result<Option<DnsObservation>, DnsParseError> {
    let header = DnsHeader::parse(packet)?;
    if !header.is_response {
        return Err(DnsParseError::NotAResponse);
    }
    if header.opcode != 0 {
        return Err(DnsParseError::UnsupportedOpcode {
            opcode: header.opcode,
        });
    }
    if header.qdcount != 1 {
        return Err(DnsParseError::QuestionCountNotOne {
            count: header.qdcount,
        });
    }
    let (hostname, question_end) = parse_name(packet, 12)?;
    let (_, mut offset) = parse_question_tail(packet, question_end)?;
    let mut addresses = Vec::new();
    let mut min_ttl_millis = None::<u128>;

    for _ in 0..header.ancount {
        let (_answer_name, after_name) = parse_name(packet, offset)?;
        if packet.len() < after_name + 10 {
            return Err(DnsParseError::TruncatedRecord);
        }
        let record_type = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
        let class = u16::from_be_bytes([packet[after_name + 2], packet[after_name + 3]]);
        let ttl = u32::from_be_bytes([
            packet[after_name + 4],
            packet[after_name + 5],
            packet[after_name + 6],
            packet[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[after_name + 8], packet[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start + rdlen;
        if packet.len() < rdata_end {
            return Err(DnsParseError::TruncatedRecord);
        }
        if class == 1 {
            match (
                DnsRecordType::from_wire(record_type),
                &packet[rdata_start..rdata_end],
            ) {
                (DnsRecordType::A, [a, b, c, d]) => {
                    addresses.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
                    min_ttl_millis = Some(min_ttl_millis.map_or(ttl as u128 * 1000, |current| {
                        current.min(ttl as u128 * 1000)
                    }));
                }
                (DnsRecordType::Aaaa, data) if data.len() == 16 => {
                    let segments = [
                        u16::from_be_bytes([data[0], data[1]]),
                        u16::from_be_bytes([data[2], data[3]]),
                        u16::from_be_bytes([data[4], data[5]]),
                        u16::from_be_bytes([data[6], data[7]]),
                        u16::from_be_bytes([data[8], data[9]]),
                        u16::from_be_bytes([data[10], data[11]]),
                        u16::from_be_bytes([data[12], data[13]]),
                        u16::from_be_bytes([data[14], data[15]]),
                    ];
                    addresses.push(IpAddr::V6(Ipv6Addr::from(segments)));
                    min_ttl_millis = Some(min_ttl_millis.map_or(ttl as u128 * 1000, |current| {
                        current.min(ttl as u128 * 1000)
                    }));
                }
                (DnsRecordType::A | DnsRecordType::Aaaa, _) => {
                    return Err(DnsParseError::MalformedRecordData);
                }
                (DnsRecordType::Other(_), _) => {}
            }
        }
        offset = rdata_end;
    }

    if addresses.is_empty() {
        return Ok(None);
    }
    Ok(Some(DnsObservation::new(
        hostname,
        addresses,
        observed_at_millis,
        min_ttl_millis.unwrap_or(0),
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DnsHeader {
    is_response: bool,
    opcode: u8,
    qdcount: u16,
    ancount: u16,
}

impl DnsHeader {
    fn parse(packet: &[u8]) -> Result<Self, DnsParseError> {
        if packet.len() < 12 {
            return Err(DnsParseError::TruncatedHeader);
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        Ok(Self {
            is_response: (flags & 0x8000) != 0,
            opcode: ((flags >> 11) & 0x0f) as u8,
            qdcount: u16::from_be_bytes([packet[4], packet[5]]),
            ancount: u16::from_be_bytes([packet[6], packet[7]]),
        })
    }
}

fn parse_question_tail(
    packet: &[u8],
    offset: usize,
) -> Result<(DnsRecordType, usize), DnsParseError> {
    if packet.len() < offset + 4 {
        return Err(DnsParseError::TruncatedQuestion);
    }
    let record_type =
        DnsRecordType::from_wire(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
    let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    if class != 1 {
        return Err(DnsParseError::UnsupportedClass { class });
    }
    Ok((record_type, offset + 4))
}

fn parse_name(packet: &[u8], offset: usize) -> Result<(Hostname, usize), DnsParseError> {
    let (labels, next_offset) = parse_name_labels(packet, offset, 0)?;
    Hostname::normalize(&labels.join("."))
        .map(|hostname| (hostname, next_offset))
        .map_err(|_| DnsParseError::InvalidHostname)
}

fn parse_name_labels(
    packet: &[u8],
    mut offset: usize,
    depth: usize,
) -> Result<(Vec<String>, usize), DnsParseError> {
    if depth > 8 {
        return Err(DnsParseError::CompressionLoop);
    }
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(offset).ok_or(DnsParseError::TruncatedName)?;
        match len & 0xc0 {
            0x00 => {
                offset += 1;
                if len == 0 {
                    return Ok((labels, offset));
                }
                if len > 63 {
                    return Err(DnsParseError::InvalidLabelLength { len });
                }
                let end = offset + len as usize;
                let label = packet
                    .get(offset..end)
                    .ok_or(DnsParseError::TruncatedName)?;
                let label =
                    std::str::from_utf8(label).map_err(|_| DnsParseError::InvalidHostname)?;
                labels.push(label.to_string());
                offset = end;
            }
            0xc0 => {
                let second = *packet.get(offset + 1).ok_or(DnsParseError::TruncatedName)?;
                let pointer = (((len & 0x3f) as usize) << 8) | second as usize;
                if pointer >= packet.len() {
                    return Err(DnsParseError::InvalidCompressionPointer);
                }
                let (mut pointed_labels, _) = parse_name_labels(packet, pointer, depth + 1)?;
                labels.append(&mut pointed_labels);
                return Ok((labels, offset + 2));
            }
            _ => return Err(DnsParseError::InvalidLabelLength { len }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn dns_cache_returns_live_medium_confidence_attribution() {
        let host = Hostname::normalize("Example.COM.").unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let mut cache = DnsCache::new();
        cache.record(DnsObservation::new(host.clone(), vec![ip], 1000, 5000));
        let attribution = cache.lookup_ip(ip, 2000).unwrap();
        assert_eq!(attribution.hostname, host);
    }

    #[test]
    fn dns_cache_does_not_return_expired_attribution() {
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let mut cache = DnsCache::new();
        cache.record(DnsObservation::new(
            Hostname::normalize("example.com").unwrap(),
            vec![ip],
            1000,
            500,
        ));
        assert!(cache.lookup_ip(ip, 2000).is_none());
    }

    #[test]
    fn parses_one_question_dns_query() {
        let query = build_query(0x0100, 1);
        let question = parse_dns_query(&query).unwrap();
        assert_eq!(question.hostname.as_str(), "example.com");
        assert_eq!(question.record_type, DnsRecordType::A);
    }

    #[test]
    fn dns_query_rejects_responses_and_multiple_questions() {
        assert_eq!(
            parse_dns_query(&build_query(0x8180, 1)),
            Err(DnsParseError::NotAQuery)
        );
        assert_eq!(
            parse_dns_query(&build_query(0x0100, 2)),
            Err(DnsParseError::QuestionCountNotOne { count: 2 })
        );
    }

    #[test]
    fn static_dns_resolver_returns_synthesized_response_and_observation() {
        let query = build_query(0x0100, 1);
        let mut resolver = StaticDnsResolver::new(30);
        resolver.insert(
            Hostname::normalize("example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );

        let response = resolver.resolve_query_packet(&query, 100).unwrap();

        assert_eq!(response.packet[0..2], query[0..2]);
        let observation = response.observation.unwrap();
        assert_eq!(observation.hostname.as_str(), "example.com");
        assert_eq!(observation.ttl_millis, 30_000);
        assert_eq!(
            observation.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn static_dns_resolver_returns_empty_response_for_unknown_host() {
        let query = build_query(0x0100, 1);
        let resolver = StaticDnsResolver::new(30);

        let response = resolver.resolve_query_packet(&query, 100).unwrap();

        assert_eq!(&response.packet[6..8], &0u16.to_be_bytes());
        assert!(response.observation.is_none());
    }

    #[test]
    fn synthesizes_dns_response_for_matching_query_type() {
        let query = build_query(0x0100, 1);
        let response = synthesize_dns_response(
            &query,
            &[
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            60,
        )
        .unwrap();
        let observation = parse_dns_response_observation(&response, 100)
            .unwrap()
            .unwrap();

        assert_eq!(observation.hostname.as_str(), "example.com");
        assert_eq!(
            observation.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert_eq!(observation.ttl_millis, 60_000);
    }

    #[test]
    fn synthesizes_empty_dns_response_when_no_record_type_matches() {
        let query = build_query(0x0100, 1);
        let response =
            synthesize_dns_response(&query, &[IpAddr::V6(Ipv6Addr::LOCALHOST)], 60).unwrap();
        assert_eq!(&response[6..8], &0u16.to_be_bytes());
        assert!(parse_dns_response_observation(&response, 100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn dns_response_records_a_and_aaaa_with_min_ttl() {
        let response = build_response_with_answers();
        let observation = parse_dns_response_observation(&response, 10)
            .unwrap()
            .unwrap();
        assert_eq!(observation.hostname.as_str(), "example.com");
        assert_eq!(observation.ttl_millis, 5000);
        assert_eq!(
            observation.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 1)),
            ]
        );
    }

    #[test]
    fn dns_cache_records_valid_response_for_later_attribution() {
        let mut cache = DnsCache::new();
        let observation = cache
            .record_response(&build_response_with_answers(), 10)
            .unwrap()
            .unwrap();
        assert_eq!(observation.hostname.as_str(), "example.com");
        let attribution = cache
            .lookup_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 20)
            .unwrap();
        assert_eq!(attribution.hostname.as_str(), "example.com");
    }

    #[test]
    fn malformed_dns_response_fails_closed() {
        let mut response = build_response_with_answers();
        response.pop();
        assert_eq!(
            parse_dns_response_observation(&response, 10),
            Err(DnsParseError::TruncatedRecord)
        );
    }

    fn build_query(flags: u16, qdcount: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34];
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&qdcount.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn build_response_with_answers() -> Vec<u8> {
        let mut packet = build_query(0x8180, 1);
        packet[6..8].copy_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&30u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[93, 184, 216, 34]);
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&28u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&5u32.to_be_bytes());
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&[
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        packet
    }
}
