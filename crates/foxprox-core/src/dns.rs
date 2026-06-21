use std::collections::VecDeque;
use std::net::IpAddr;

use crate::attribution::{HostAttribution, Hostname, HostnameError};

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
}

pub fn parse_dns_query(
    bytes: &[u8],
    max_message_bytes: usize,
) -> Result<DnsQueryMetadata, DnsParseError> {
    if bytes.len() > max_message_bytes {
        return Err(DnsParseError::MessageTooLarge);
    }
    if bytes.len() < 12 {
        return Err(DnsParseError::Truncated);
    }

    let transaction_id = read_u16(bytes, 0)?;
    let flags = read_u16(bytes, 2)?;
    if flags & 0x8000 != 0 {
        return Err(DnsParseError::NotQuery);
    }
    if flags & 0x7800 != 0 {
        return Err(DnsParseError::UnsupportedOpcode);
    }

    let qdcount = read_u16(bytes, 4)?;
    let ancount = read_u16(bytes, 6)?;
    let nscount = read_u16(bytes, 8)?;
    let arcount = read_u16(bytes, 10)?;
    if qdcount != 1 {
        return Err(DnsParseError::QuestionCountUnsupported);
    }
    if ancount != 0 || nscount != 0 || arcount != 0 {
        return Err(DnsParseError::UnexpectedResourceRecords);
    }

    let (hostname, offset) = parse_qname(bytes, 12)?;
    let qtype = read_u16(bytes, offset)?;
    let qclass = read_u16(bytes, offset + 2)?;
    if qclass != 1 {
        return Err(DnsParseError::UnsupportedClass);
    }
    if bytes.len() != offset + 4 {
        return Err(DnsParseError::TrailingBytes);
    }

    Ok(DnsQueryMetadata {
        transaction_id,
        hostname,
        query_type: DnsQueryType::from_code(qtype),
        recursion_desired: flags & 0x0100 != 0,
    })
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

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsParseError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(DnsParseError::Truncated)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::types::{HostnameConfidence, HostnameSource};

    use super::*;

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
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
}
