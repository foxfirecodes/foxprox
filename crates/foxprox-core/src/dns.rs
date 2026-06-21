use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::attribution::{HostAttribution, Hostname, HostnameError};
use crate::types::Endpoint;

/// Bounded DNS observation cache for transparent hostname attribution.
///
/// DNS-derived attribution is always medium confidence because IPs may be shared,
/// reused, or raced by unrelated traffic.
#[derive(Clone, Debug)]
pub struct DnsAttributionCache {
    max_entries: usize,
    max_ttl_millis: u64,
    entries: VecDeque<DnsAttributionEntry>,
}

impl DnsAttributionCache {
    pub fn new(max_entries: usize, max_ttl_millis: u64) -> Self {
        Self {
            max_entries,
            max_ttl_millis,
            entries: VecDeque::with_capacity(max_entries),
        }
    }

    pub fn observe<I>(
        &mut self,
        hostname: &str,
        addresses: I,
        now_millis: u64,
        ttl_seconds: u32,
    ) -> Result<ObserveOutcome, HostnameError>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        let hostname = Hostname::parse(hostname)?;
        self.purge_expired(now_millis);

        if self.max_entries == 0 || self.max_ttl_millis == 0 || ttl_seconds == 0 {
            return Ok(ObserveOutcome {
                stored: 0,
                evicted: 0,
            });
        }

        let ttl_millis = u64::from(ttl_seconds)
            .saturating_mul(1000)
            .min(self.max_ttl_millis);
        let expires_at_millis = now_millis.saturating_add(ttl_millis);
        let mut stored = 0;
        let mut evicted = 0;

        for address in addresses {
            self.remove_exact(address, &hostname);
            while self.entries.len() >= self.max_entries {
                self.entries.pop_front();
                evicted += 1;
            }
            self.entries.push_back(DnsAttributionEntry {
                address,
                hostname: hostname.clone(),
                observed_at_millis: now_millis,
                expires_at_millis,
            });
            stored += 1;
        }

        Ok(ObserveOutcome { stored, evicted })
    }

    pub fn lookup(&mut self, address: IpAddr, now_millis: u64) -> Vec<HostAttribution> {
        self.purge_expired(now_millis);
        self.entries
            .iter()
            .filter(|entry| entry.address == address)
            .map(|entry| HostAttribution::dns(entry.hostname.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    fn purge_expired(&mut self, now_millis: u64) {
        self.entries
            .retain(|entry| entry.expires_at_millis > now_millis);
    }

    fn remove_exact(&mut self, address: IpAddr, hostname: &Hostname) {
        self.entries
            .retain(|entry| entry.address != address || &entry.hostname != hostname);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAttributionEntry {
    pub address: IpAddr,
    pub hostname: Hostname,
    pub observed_at_millis: u64,
    pub expires_at_millis: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ObserveOutcome {
    pub stored: usize,
    pub evicted: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQueryMetadata {
    pub transaction_id: u16,
    pub hostname: Hostname,
    pub query_type: DnsQueryType,
    pub recursion_desired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAddressResponseMetadata {
    pub transaction_id: u16,
    pub hostname: Hostname,
    pub query_type: DnsQueryType,
    pub addresses: Vec<IpAddr>,
    pub min_ttl_seconds: Option<u32>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Ptr,
    Other(u16),
}

impl DnsQueryType {
    fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            5 => Self::Cname,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            other => Self::Other(other),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DnsParseError {
    MessageTooLarge,
    Truncated,
    NotQuery,
    UnsupportedOpcode,
    QuestionCountUnsupported,
    UnexpectedResourceRecords,
    CompressionUnsupported,
    InvalidLabelLength,
    InvalidHostname,
    UnsupportedClass,
    TrailingBytes,
    TooManyAnswers,
    OwnerNameMismatch,
    UnsupportedAnswerType,
    InvalidRecordLength,
}

#[derive(Clone, Debug)]
pub struct PendingDnsQueryTable {
    max_entries: usize,
    timeout_millis: u64,
    entries: VecDeque<PendingDnsQuery>,
}

impl PendingDnsQueryTable {
    pub fn new(max_entries: usize, timeout_millis: u64) -> Self {
        Self {
            max_entries,
            timeout_millis,
            entries: VecDeque::with_capacity(max_entries),
        }
    }

    pub fn observe_query(
        &mut self,
        client: Endpoint,
        upstream: Endpoint,
        query: &DnsQueryMetadata,
        now_millis: u64,
    ) -> PendingDnsObserveOutcome {
        let expired = self.expire(now_millis);
        let replaced = self.remove_exact(client, upstream, query.transaction_id) > 0;

        if self.max_entries == 0 || self.timeout_millis == 0 {
            return PendingDnsObserveOutcome {
                status: PendingDnsObserveStatus::RejectedNoCapacity,
                evicted: 0,
                expired,
                replaced,
            };
        }

        let mut evicted = 0;
        while self.entries.len() >= self.max_entries {
            self.entries.pop_front();
            evicted += 1;
        }

        self.entries.push_back(PendingDnsQuery {
            client,
            upstream,
            transaction_id: query.transaction_id,
            hostname: query.hostname.clone(),
            query_type: query.query_type,
            observed_at_millis: now_millis,
            expires_at_millis: now_millis.saturating_add(self.timeout_millis),
        });

        PendingDnsObserveOutcome {
            status: PendingDnsObserveStatus::Stored,
            evicted,
            expired,
            replaced,
        }
    }

    pub fn validate_response(
        &mut self,
        client: Endpoint,
        upstream: Endpoint,
        response: &DnsAddressResponseMetadata,
        now_millis: u64,
    ) -> Result<PendingDnsQuery, DnsTransactionError> {
        self.expire(now_millis);
        let Some(index) = self.entries.iter().position(|entry| {
            entry.client == client
                && entry.upstream == upstream
                && entry.transaction_id == response.transaction_id
        }) else {
            return Err(DnsTransactionError::UnmatchedResponse);
        };
        let pending = self
            .entries
            .remove(index)
            .expect("position came from entries");

        if pending.hostname != response.hostname {
            return Err(DnsTransactionError::HostnameMismatch);
        }
        if pending.query_type != response.query_type {
            return Err(DnsTransactionError::QueryTypeMismatch);
        }

        Ok(pending)
    }

    pub fn expire(&mut self, now_millis: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|entry| entry.expires_at_millis > now_millis);
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    fn remove_exact(&mut self, client: Endpoint, upstream: Endpoint, transaction_id: u16) -> usize {
        let before = self.entries.len();
        self.entries.retain(|entry| {
            entry.client != client
                || entry.upstream != upstream
                || entry.transaction_id != transaction_id
        });
        before - self.entries.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDnsQuery {
    pub client: Endpoint,
    pub upstream: Endpoint,
    pub transaction_id: u16,
    pub hostname: Hostname,
    pub query_type: DnsQueryType,
    pub observed_at_millis: u64,
    pub expires_at_millis: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PendingDnsObserveStatus {
    Stored,
    RejectedNoCapacity,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PendingDnsObserveOutcome {
    pub status: PendingDnsObserveStatus,
    pub evicted: usize,
    pub expired: usize,
    pub replaced: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DnsTransactionError {
    UnmatchedResponse,
    HostnameMismatch,
    QueryTypeMismatch,
}

pub fn parse_dns_query(
    bytes: &[u8],
    max_message_bytes: usize,
) -> Result<DnsQueryMetadata, DnsParseError> {
    let header = parse_dns_header(bytes, max_message_bytes)?;
    if header.is_response {
        return Err(DnsParseError::NotQuery);
    }
    if header.answer_count != 0 || header.authority_count != 0 || header.additional_count != 0 {
        return Err(DnsParseError::UnexpectedResourceRecords);
    }

    let (hostname, offset, qtype) = parse_single_question(bytes)?;
    if bytes.len() != offset {
        return Err(DnsParseError::TrailingBytes);
    }

    Ok(DnsQueryMetadata {
        transaction_id: header.transaction_id,
        hostname,
        query_type: DnsQueryType::from_code(qtype),
        recursion_desired: header.flags & 0x0100 != 0,
    })
}

pub fn parse_dns_address_response(
    bytes: &[u8],
    max_message_bytes: usize,
    max_answers: usize,
) -> Result<DnsAddressResponseMetadata, DnsParseError> {
    let header = parse_dns_header(bytes, max_message_bytes)?;
    if !header.is_response {
        return Err(DnsParseError::NotQuery);
    }
    if header.authority_count != 0 || header.additional_count != 0 {
        return Err(DnsParseError::UnexpectedResourceRecords);
    }
    if usize::from(header.answer_count) > max_answers {
        return Err(DnsParseError::TooManyAnswers);
    }

    let (hostname, mut offset, qtype) = parse_single_question(bytes)?;
    if header.flags & 0x000f != 0 {
        if header.answer_count == 0 && bytes.len() == offset {
            return Ok(DnsAddressResponseMetadata {
                transaction_id: header.transaction_id,
                hostname,
                query_type: DnsQueryType::from_code(qtype),
                addresses: Vec::new(),
                min_ttl_seconds: None,
            });
        }
        return Err(DnsParseError::UnexpectedResourceRecords);
    }

    let mut addresses = Vec::new();
    let mut min_ttl_seconds = None;
    for _ in 0..header.answer_count {
        let (owner, next_offset) = parse_response_name(bytes, offset, &hostname)?;
        if owner != hostname {
            return Err(DnsParseError::OwnerNameMismatch);
        }
        offset = next_offset;
        let answer_type = read_u16(bytes, offset)?;
        let answer_class = read_u16(bytes, offset + 2)?;
        let ttl = read_u32(bytes, offset + 4)?;
        let rdlength = usize::from(read_u16(bytes, offset + 8)?);
        offset += 10;
        let rdata_end = offset + rdlength;
        let rdata = bytes
            .get(offset..rdata_end)
            .ok_or(DnsParseError::Truncated)?;
        offset = rdata_end;

        if answer_class != 1 {
            return Err(DnsParseError::UnsupportedClass);
        }

        let address = match (answer_type, rdlength) {
            (1, 4) => IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (28, 16) => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(rdata);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            (1 | 28, _) => return Err(DnsParseError::InvalidRecordLength),
            _ => return Err(DnsParseError::UnsupportedAnswerType),
        };
        addresses.push(address);
        min_ttl_seconds = Some(min_ttl_seconds.map_or(ttl, |current: u32| current.min(ttl)));
    }

    if bytes.len() != offset {
        return Err(DnsParseError::TrailingBytes);
    }

    Ok(DnsAddressResponseMetadata {
        transaction_id: header.transaction_id,
        hostname,
        query_type: DnsQueryType::from_code(qtype),
        addresses,
        min_ttl_seconds,
    })
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct DnsHeader {
    transaction_id: u16,
    flags: u16,
    is_response: bool,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

fn parse_dns_header(bytes: &[u8], max_message_bytes: usize) -> Result<DnsHeader, DnsParseError> {
    if bytes.len() > max_message_bytes {
        return Err(DnsParseError::MessageTooLarge);
    }
    if bytes.len() < 12 {
        return Err(DnsParseError::Truncated);
    }

    let transaction_id = read_u16(bytes, 0)?;
    let flags = read_u16(bytes, 2)?;
    if flags & 0x7800 != 0 {
        return Err(DnsParseError::UnsupportedOpcode);
    }

    let qdcount = read_u16(bytes, 4)?;
    if qdcount != 1 {
        return Err(DnsParseError::QuestionCountUnsupported);
    }

    Ok(DnsHeader {
        transaction_id,
        flags,
        is_response: flags & 0x8000 != 0,
        answer_count: read_u16(bytes, 6)?,
        authority_count: read_u16(bytes, 8)?,
        additional_count: read_u16(bytes, 10)?,
    })
}

fn parse_single_question(bytes: &[u8]) -> Result<(Hostname, usize, u16), DnsParseError> {
    let (hostname, offset) = parse_qname(bytes, 12)?;
    let qtype = read_u16(bytes, offset)?;
    let qclass = read_u16(bytes, offset + 2)?;
    if qclass != 1 {
        return Err(DnsParseError::UnsupportedClass);
    }
    Ok((hostname, offset + 4, qtype))
}

fn parse_qname(bytes: &[u8], mut offset: usize) -> Result<(Hostname, usize), DnsParseError> {
    let mut name = String::new();
    let mut total_len = 0_usize;

    loop {
        let length = *bytes.get(offset).ok_or(DnsParseError::Truncated)?;
        offset += 1;

        if length == 0 {
            if name.is_empty() {
                return Err(DnsParseError::InvalidHostname);
            }
            let hostname = Hostname::parse(&name).map_err(|_| DnsParseError::InvalidHostname)?;
            return Ok((hostname, offset));
        }

        if length & 0b1100_0000 != 0 {
            return Err(DnsParseError::CompressionUnsupported);
        }
        if length > 63 {
            return Err(DnsParseError::InvalidLabelLength);
        }

        let label_len = usize::from(length);
        let label_end = offset + label_len;
        let label = bytes
            .get(offset..label_end)
            .ok_or(DnsParseError::Truncated)?;
        let label = std::str::from_utf8(label).map_err(|_| DnsParseError::InvalidHostname)?;
        if !label.is_ascii() {
            return Err(DnsParseError::InvalidHostname);
        }

        if !name.is_empty() {
            name.push('.');
            total_len += 1;
        }
        total_len += label.len();
        if total_len > 253 {
            return Err(DnsParseError::InvalidHostname);
        }
        name.push_str(label);
        offset = label_end;
    }
}

fn parse_response_name(
    bytes: &[u8],
    offset: usize,
    question_hostname: &Hostname,
) -> Result<(Hostname, usize), DnsParseError> {
    let first = *bytes.get(offset).ok_or(DnsParseError::Truncated)?;
    if first & 0b1100_0000 == 0b1100_0000 {
        let second = *bytes.get(offset + 1).ok_or(DnsParseError::Truncated)?;
        let pointer = (usize::from(first & 0b0011_1111) << 8) | usize::from(second);
        if pointer != 12 {
            return Err(DnsParseError::CompressionUnsupported);
        }
        return Ok((question_hostname.clone(), offset + 2));
    }
    if first & 0b1100_0000 != 0 {
        return Err(DnsParseError::CompressionUnsupported);
    }
    parse_qname(bytes, offset)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsParseError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(DnsParseError::Truncated)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DnsParseError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(DnsParseError::Truncated)?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::types::{Endpoint, HostnameConfidence, HostnameSource};

    use super::*;

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn udp_endpoint(octets: [u8; 4], port: u16) -> Endpoint {
        Endpoint::udp(ip(octets), port)
    }

    #[test]
    fn dns_observations_are_normalized_medium_confidence_attribution() {
        let mut cache = DnsAttributionCache::new(8, 60_000);
        assert_eq!(
            cache.observe("Example.COM.", [ip([93, 184, 216, 34])], 1_000, 30),
            Ok(ObserveOutcome {
                stored: 1,
                evicted: 0
            })
        );

        let attributions = cache.lookup(ip([93, 184, 216, 34]), 2_000);
        assert_eq!(attributions.len(), 1);
        assert_eq!(
            attributions[0].hostname.as_ref().unwrap().as_str(),
            "example.com"
        );
        assert_eq!(attributions[0].source, HostnameSource::DnsCache);
        assert_eq!(attributions[0].confidence, HostnameConfidence::Medium);
    }

    #[test]
    fn invalid_dns_hostnames_are_rejected() {
        let mut cache = DnsAttributionCache::new(8, 60_000);
        assert!(cache
            .observe("bad_host.example", [ip([127, 0, 0, 1])], 0, 60)
            .is_err());
        assert!(cache.is_empty());
    }

    #[test]
    fn dns_attribution_expires_by_ttl_and_max_ttl() {
        let mut cache = DnsAttributionCache::new(8, 5_000);
        cache
            .observe("short.example", [ip([192, 0, 2, 1])], 1_000, 2)
            .unwrap();
        cache
            .observe("clamped.example", [ip([192, 0, 2, 2])], 1_000, 60)
            .unwrap();

        assert_eq!(cache.lookup(ip([192, 0, 2, 1]), 2_999).len(), 1);
        assert!(cache.lookup(ip([192, 0, 2, 1]), 3_000).is_empty());
        assert_eq!(cache.lookup(ip([192, 0, 2, 2]), 5_999).len(), 1);
        assert!(cache.lookup(ip([192, 0, 2, 2]), 6_000).is_empty());
    }

    #[test]
    fn dns_cache_is_capacity_bounded_and_evicts_oldest() {
        let mut cache = DnsAttributionCache::new(2, 60_000);
        cache
            .observe("one.example", [ip([192, 0, 2, 1])], 0, 60)
            .unwrap();
        cache
            .observe("two.example", [ip([192, 0, 2, 2])], 0, 60)
            .unwrap();
        let outcome = cache
            .observe("three.example", [ip([192, 0, 2, 3])], 0, 60)
            .unwrap();

        assert_eq!(
            outcome,
            ObserveOutcome {
                stored: 1,
                evicted: 1
            }
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(ip([192, 0, 2, 1]), 1).is_empty());
        assert_eq!(cache.lookup(ip([192, 0, 2, 2]), 1).len(), 1);
        assert_eq!(cache.lookup(ip([192, 0, 2, 3]), 1).len(), 1);
    }

    #[test]
    fn shared_ips_return_multiple_medium_confidence_hostnames() {
        let mut cache = DnsAttributionCache::new(8, 60_000);
        cache
            .observe("a.example", [ip([203, 0, 113, 10])], 0, 60)
            .unwrap();
        cache
            .observe("b.example", [ip([203, 0, 113, 10])], 0, 60)
            .unwrap();

        let attributions = cache.lookup(ip([203, 0, 113, 10]), 1);
        let names: Vec<_> = attributions
            .iter()
            .map(|attribution| attribution.hostname.as_ref().unwrap().as_str())
            .collect();
        assert_eq!(names, vec!["a.example", "b.example"]);
        assert!(attributions
            .iter()
            .all(|attribution| attribution.confidence == HostnameConfidence::Medium));
    }

    #[test]
    fn zero_capacity_or_zero_ttl_stores_nothing() {
        let mut no_capacity = DnsAttributionCache::new(0, 60_000);
        assert_eq!(
            no_capacity.observe("example.com", [ip([192, 0, 2, 1])], 0, 60),
            Ok(ObserveOutcome {
                stored: 0,
                evicted: 0
            })
        );
        assert!(no_capacity.is_empty());

        let mut cache = DnsAttributionCache::new(8, 60_000);
        cache
            .observe("example.com", [ip([192, 0, 2, 1])], 0, 0)
            .unwrap();
        assert!(cache.is_empty());
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, // transaction id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        for label in name.split('.') {
            bytes.push(label.len().try_into().unwrap());
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&qtype.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_valid_dns_queries_with_normalized_hostname_and_type() {
        let parsed = parse_dns_query(&dns_query("Example.COM", 1), 512).unwrap();
        assert_eq!(parsed.transaction_id, 0x1234);
        assert_eq!(parsed.hostname.as_str(), "example.com");
        assert_eq!(parsed.query_type, DnsQueryType::A);
        assert!(parsed.recursion_desired);

        let parsed = parse_dns_query(&dns_query("ipv6.example", 28), 512).unwrap();
        assert_eq!(parsed.hostname.as_str(), "ipv6.example");
        assert_eq!(parsed.query_type, DnsQueryType::Aaaa);

        let parsed = parse_dns_query(&dns_query("unknown.example", 65), 512).unwrap();
        assert_eq!(parsed.query_type, DnsQueryType::Other(65));
    }

    #[test]
    fn rejects_malformed_or_unsupported_dns_message_shapes() {
        assert_eq!(parse_dns_query(&[], 512), Err(DnsParseError::Truncated));

        let mut response = dns_query("example.com", 1);
        response[2] = 0x81;
        assert_eq!(
            parse_dns_query(&response, 512),
            Err(DnsParseError::NotQuery)
        );

        let mut inverse_query = dns_query("example.com", 1);
        inverse_query[2] = 0x09;
        assert_eq!(
            parse_dns_query(&inverse_query, 512),
            Err(DnsParseError::UnsupportedOpcode)
        );

        let mut two_questions = dns_query("example.com", 1);
        two_questions[5] = 0x02;
        assert_eq!(
            parse_dns_query(&two_questions, 512),
            Err(DnsParseError::QuestionCountUnsupported)
        );

        let mut additional = dns_query("example.com", 1);
        additional[11] = 0x01;
        assert_eq!(
            parse_dns_query(&additional, 512),
            Err(DnsParseError::UnexpectedResourceRecords)
        );
    }

    #[test]
    fn rejects_ambiguous_or_invalid_dns_question_names() {
        let mut compressed = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(
            parse_dns_query(&compressed, 512),
            Err(DnsParseError::CompressionUnsupported)
        );

        let root_query = dns_query("", 1);
        assert_eq!(
            parse_dns_query(&root_query, 512),
            Err(DnsParseError::InvalidHostname)
        );

        let invalid_host = dns_query("bad_host.example", 1);
        assert_eq!(
            parse_dns_query(&invalid_host, 512),
            Err(DnsParseError::InvalidHostname)
        );

        compressed[12] = 64;
        assert_eq!(
            parse_dns_query(&compressed, 512),
            Err(DnsParseError::CompressionUnsupported)
        );
    }

    #[test]
    fn rejects_dns_query_truncation_class_trailing_and_size_issues() {
        let mut truncated = dns_query("example.com", 1);
        truncated.pop();
        assert_eq!(
            parse_dns_query(&truncated, 512),
            Err(DnsParseError::Truncated)
        );

        let mut class_chaos = dns_query("example.com", 1);
        let last = class_chaos.len() - 1;
        class_chaos[last] = 3;
        assert_eq!(
            parse_dns_query(&class_chaos, 512),
            Err(DnsParseError::UnsupportedClass)
        );

        let mut trailing = dns_query("example.com", 1);
        trailing.push(0);
        assert_eq!(
            parse_dns_query(&trailing, 512),
            Err(DnsParseError::TrailingBytes)
        );

        assert_eq!(
            parse_dns_query(&dns_query("example.com", 1), 8),
            Err(DnsParseError::MessageTooLarge)
        );
    }

    fn dns_response(name: &str, qtype: u16, answers: &[(&str, u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = dns_query(name, qtype);
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        let answer_count: u16 = answers.len().try_into().unwrap();
        bytes[6..8].copy_from_slice(&answer_count.to_be_bytes());

        for (owner, answer_type, ttl, rdata) in answers {
            if *owner == "@" {
                bytes.extend_from_slice(&[0xc0, 0x0c]);
            } else {
                for label in owner.split('.') {
                    bytes.push(label.len().try_into().unwrap());
                    bytes.extend_from_slice(label.as_bytes());
                }
                bytes.push(0);
            }
            bytes.extend_from_slice(&answer_type.to_be_bytes());
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&ttl.to_be_bytes());
            let rdlength: u16 = rdata.len().try_into().unwrap();
            bytes.extend_from_slice(&rdlength.to_be_bytes());
            bytes.extend_from_slice(rdata);
        }

        bytes
    }

    #[test]
    fn parses_dns_address_responses_with_ttl_bounds() {
        let response = dns_response(
            "example.com",
            1,
            &[
                ("@", 1, 60, vec![93, 184, 216, 34]),
                (
                    "example.com",
                    28,
                    30,
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
                        .octets()
                        .to_vec(),
                ),
            ],
        );

        let parsed = parse_dns_address_response(&response, 512, 8).unwrap();
        assert_eq!(parsed.transaction_id, 0x1234);
        assert_eq!(parsed.hostname.as_str(), "example.com");
        assert_eq!(parsed.query_type, DnsQueryType::A);
        assert_eq!(
            parsed.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ]
        );
        assert_eq!(parsed.min_ttl_seconds, Some(30));
    }

    #[test]
    fn parses_empty_error_dns_response_without_attribution_addresses() {
        let mut response = dns_query("missing.example", 1);
        response[2] = 0x81;
        response[3] = 0x83;

        let parsed = parse_dns_address_response(&response, 512, 8).unwrap();
        assert_eq!(parsed.hostname.as_str(), "missing.example");
        assert!(parsed.addresses.is_empty());
        assert_eq!(parsed.min_ttl_seconds, None);
    }

    #[test]
    fn rejects_dns_response_answer_bounds_and_owner_mismatch() {
        let response = dns_response("example.com", 1, &[("@", 1, 60, vec![127, 0, 0, 1])]);
        assert_eq!(
            parse_dns_address_response(&response, 512, 0),
            Err(DnsParseError::TooManyAnswers)
        );

        let mismatch = dns_response(
            "example.com",
            1,
            &[("evil.example", 1, 60, vec![127, 0, 0, 1])],
        );
        assert_eq!(
            parse_dns_address_response(&mismatch, 512, 8),
            Err(DnsParseError::OwnerNameMismatch)
        );

        let mut bad_pointer = response.clone();
        let question_end = dns_query("example.com", 1).len();
        bad_pointer[question_end + 1] = 0x00;
        assert_eq!(
            parse_dns_address_response(&bad_pointer, 512, 8),
            Err(DnsParseError::CompressionUnsupported)
        );
    }

    #[test]
    fn rejects_dns_response_unsupported_records_and_malformed_lengths() {
        let unsupported = dns_response("example.com", 1, &[("@", 5, 60, vec![0])]);
        assert_eq!(
            parse_dns_address_response(&unsupported, 512, 8),
            Err(DnsParseError::UnsupportedAnswerType)
        );

        let bad_length = dns_response("example.com", 1, &[("@", 1, 60, vec![127, 0, 0])]);
        assert_eq!(
            parse_dns_address_response(&bad_length, 512, 8),
            Err(DnsParseError::InvalidRecordLength)
        );

        let mut bad_class = dns_response("example.com", 1, &[("@", 1, 60, vec![127, 0, 0, 1])]);
        let question_end = dns_query("example.com", 1).len();
        bad_class[question_end + 4] = 0;
        bad_class[question_end + 5] = 3;
        assert_eq!(
            parse_dns_address_response(&bad_class, 512, 8),
            Err(DnsParseError::UnsupportedClass)
        );

        let mut trailing = dns_response("example.com", 1, &[("@", 1, 60, vec![127, 0, 0, 1])]);
        trailing.push(0);
        assert_eq!(
            parse_dns_address_response(&trailing, 512, 8),
            Err(DnsParseError::TrailingBytes)
        );
    }

    #[test]
    fn pending_dns_transactions_match_and_are_removed() {
        let client = udp_endpoint([10, 0, 0, 2], 40000);
        let upstream = udp_endpoint([8, 8, 8, 8], 53);
        let query = parse_dns_query(&dns_query("example.com", 1), 512).unwrap();
        let response = parse_dns_address_response(
            &dns_response("example.com", 1, &[("@", 1, 60, vec![93, 184, 216, 34])]),
            512,
            8,
        )
        .unwrap();
        let mut pending = PendingDnsQueryTable::new(8, 5_000);

        let outcome = pending.observe_query(client, upstream, &query, 1_000);
        assert_eq!(outcome.status, PendingDnsObserveStatus::Stored);
        assert_eq!(pending.len(), 1);

        let matched = pending
            .validate_response(client, upstream, &response, 1_100)
            .unwrap();
        assert_eq!(matched.hostname.as_str(), "example.com");
        assert_eq!(matched.query_type, DnsQueryType::A);
        assert!(pending.is_empty());
        assert_eq!(
            pending.validate_response(client, upstream, &response, 1_101),
            Err(DnsTransactionError::UnmatchedResponse)
        );
    }

    #[test]
    fn pending_dns_transactions_reject_mismatched_responses() {
        let client = udp_endpoint([10, 0, 0, 2], 40000);
        let other_client = udp_endpoint([10, 0, 0, 3], 40000);
        let upstream = udp_endpoint([8, 8, 8, 8], 53);
        let other_upstream = udp_endpoint([1, 1, 1, 1], 53);
        let query = parse_dns_query(&dns_query("example.com", 1), 512).unwrap();
        let matching_response = parse_dns_address_response(
            &dns_response("example.com", 1, &[("@", 1, 60, vec![93, 184, 216, 34])]),
            512,
            8,
        )
        .unwrap();

        let mut pending = PendingDnsQueryTable::new(8, 5_000);
        pending.observe_query(client, upstream, &query, 0);
        assert_eq!(
            pending.validate_response(other_client, upstream, &matching_response, 1),
            Err(DnsTransactionError::UnmatchedResponse)
        );
        assert_eq!(
            pending.validate_response(client, other_upstream, &matching_response, 1),
            Err(DnsTransactionError::UnmatchedResponse)
        );

        let wrong_name = parse_dns_address_response(
            &dns_response("evil.example", 1, &[("@", 1, 60, vec![127, 0, 0, 1])]),
            512,
            8,
        )
        .unwrap();
        assert_eq!(
            pending.validate_response(client, upstream, &wrong_name, 1),
            Err(DnsTransactionError::HostnameMismatch)
        );
        assert!(pending.is_empty());

        pending.observe_query(client, upstream, &query, 2);
        let wrong_type =
            parse_dns_address_response(&dns_response("example.com", 28, &[]), 512, 8).unwrap();
        assert_eq!(
            pending.validate_response(client, upstream, &wrong_type, 3),
            Err(DnsTransactionError::QueryTypeMismatch)
        );
    }

    #[test]
    fn pending_dns_transactions_are_ttl_and_capacity_bounded() {
        let client = udp_endpoint([10, 0, 0, 2], 40000);
        let upstream = udp_endpoint([8, 8, 8, 8], 53);
        let first = parse_dns_query(&dns_query("one.example", 1), 512).unwrap();
        let mut second_wire = dns_query("two.example", 1);
        second_wire[1] = 0x35;
        let second = parse_dns_query(&second_wire, 512).unwrap();
        let mut pending = PendingDnsQueryTable::new(1, 10);

        pending.observe_query(client, upstream, &first, 0);
        let outcome = pending.observe_query(client, upstream, &second, 1);
        assert_eq!(outcome.evicted, 1);
        assert_eq!(pending.len(), 1);

        assert_eq!(pending.expire(10), 0);
        assert_eq!(pending.expire(11), 1);
        assert!(pending.is_empty());

        let mut none = PendingDnsQueryTable::new(0, 10);
        let outcome = none.observe_query(client, upstream, &first, 0);
        assert_eq!(outcome.status, PendingDnsObserveStatus::RejectedNoCapacity);
        assert!(none.is_empty());

        let mut zero_ttl = PendingDnsQueryTable::new(8, 0);
        let outcome = zero_ttl.observe_query(client, upstream, &first, 0);
        assert_eq!(outcome.status, PendingDnsObserveStatus::RejectedNoCapacity);
        assert!(zero_ttl.is_empty());
    }

    #[test]
    fn pending_dns_transactions_replace_reused_ids_for_same_path() {
        let client = udp_endpoint([10, 0, 0, 2], 40000);
        let upstream = udp_endpoint([8, 8, 8, 8], 53);
        let first = parse_dns_query(&dns_query("one.example", 1), 512).unwrap();
        let mut second = dns_query("two.example", 1);
        second[0] = 0x12;
        second[1] = 0x34;
        let second = parse_dns_query(&second, 512).unwrap();
        let mut pending = PendingDnsQueryTable::new(8, 5_000);

        pending.observe_query(client, upstream, &first, 0);
        let outcome = pending.observe_query(client, upstream, &second, 1);
        assert!(outcome.replaced);
        assert_eq!(pending.len(), 1);
    }
}
