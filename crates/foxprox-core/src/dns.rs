//! DNS observation, wire parsing, and cache types for transparent attribution.
//!
//! This module stays dependency-free and socket-free. Runtime crates own UDP I/O
//! and upstream resolver access; core owns bounded DNS wire parsing, normalized
//! observations, and cache semantics shared by policy/audit code.

use crate::event::{Attribution, AttributionConfidence, AttributionSource, Hostname, SandboxId};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

const DNS_HEADER_LEN: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const MAX_DNS_POINTER_JUMPS: usize = 16;

/// DNS query type observed by the broker.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DnsQueryType {
    /// IPv4 address lookup.
    A,
    /// IPv6 address lookup.
    Aaaa,
    /// Other query type by numeric DNS RR type code.
    Other(u16),
}

impl DnsQueryType {
    /// Parses a DNS query type label or numeric code.
    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_uppercase();
        if normalized.is_empty() {
            return None;
        }
        Some(match normalized.as_str() {
            "A" => Self::A,
            "AAAA" => Self::Aaaa,
            _ => Self::Other(normalized.parse().ok()?),
        })
    }

    /// Converts a numeric DNS RR type code to a query type.
    pub const fn from_code(code: u16) -> Self {
        match code {
            DNS_TYPE_A => Self::A,
            DNS_TYPE_AAAA => Self::Aaaa,
            other => Self::Other(other),
        }
    }

    /// Returns the numeric DNS RR type code.
    pub const fn code(&self) -> u16 {
        match self {
            Self::A => DNS_TYPE_A,
            Self::Aaaa => DNS_TYPE_AAAA,
            Self::Other(code) => *code,
        }
    }

    /// Returns the query type as a presentation string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Other(_) => "OTHER",
        }
    }
}

/// Parsed DNS question from a UDP DNS query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    /// DNS transaction identifier.
    pub transaction_id: u16,
    /// Queried hostname.
    pub hostname: Hostname,
    /// Query type.
    pub query_type: DnsQueryType,
    /// Query class code.
    pub query_class: u16,
    /// Whether recursion was requested.
    pub recursion_desired: bool,
}

/// Parsed address answer from a DNS response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAddressRecord {
    /// Answer hostname.
    pub hostname: Hostname,
    /// Answer IP address.
    pub address: IpAddr,
    /// Record TTL.
    pub ttl: Duration,
}

/// Parsed DNS response observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResponseObservation {
    /// DNS transaction identifier.
    pub transaction_id: u16,
    /// Queried hostname when known or present in the response question.
    pub hostname: Option<Hostname>,
    /// Query type when known or present in the response question.
    pub query_type: Option<DnsQueryType>,
    /// DNS response code.
    pub rcode: u8,
    /// Whether the response was truncated.
    pub truncated: bool,
    /// A/AAAA address answers extracted from the response.
    pub answers: Vec<DnsAddressRecord>,
}

/// DNS parse failure category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsParseError {
    /// Packet ended before a required field.
    Truncated,
    /// DNS name was malformed.
    MalformedName,
    /// DNS compression pointer was malformed or cyclic.
    BadCompressionPointer,
    /// The query/response shape is unsupported by this alpha parser.
    Unsupported(String),
}

/// Parses a single-question UDP DNS query.
pub fn parse_dns_query(packet: &[u8]) -> Result<DnsQuestion, DnsParseError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsParseError::Truncated);
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 != 0 {
        return Err(DnsParseError::Unsupported("expected DNS query".to_string()));
    }
    if read_u16(packet, 4)? != 1 {
        return Err(DnsParseError::Unsupported(
            "expected exactly one DNS question".to_string(),
        ));
    }
    let (hostname, offset) = parse_name(packet, DNS_HEADER_LEN)?;
    let query_type = DnsQueryType::from_code(read_u16(packet, offset)?);
    let query_class = read_u16(packet, offset + 2)?;
    Ok(DnsQuestion {
        transaction_id: read_u16(packet, 0)?,
        hostname,
        query_type,
        query_class,
        recursion_desired: flags & 0x0100 != 0,
    })
}

/// Parses a UDP DNS response and extracts A/AAAA address answers.
pub fn parse_dns_response(
    packet: &[u8],
    expected_question: Option<&DnsQuestion>,
) -> Result<DnsResponseObservation, DnsParseError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsParseError::Truncated);
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsParseError::Unsupported(
            "expected DNS response".to_string(),
        ));
    }

    let qdcount = read_u16(packet, 4)? as usize;
    let ancount = read_u16(packet, 6)? as usize;
    let mut offset = DNS_HEADER_LEN;
    let mut question = expected_question.cloned();
    for index in 0..qdcount {
        let (hostname, next) = parse_name(packet, offset)?;
        let query_type = DnsQueryType::from_code(read_u16(packet, next)?);
        let query_class = read_u16(packet, next + 2)?;
        offset = next + 4;
        if index == 0 && question.is_none() {
            question = Some(DnsQuestion {
                transaction_id: read_u16(packet, 0)?,
                hostname,
                query_type,
                query_class,
                recursion_desired: flags & 0x0100 != 0,
            });
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (hostname, next) = parse_name(packet, offset)?;
        let rr_type = read_u16(packet, next)?;
        let rr_class = read_u16(packet, next + 2)?;
        let ttl_secs = read_u32(packet, next + 4)?;
        let rdlen = read_u16(packet, next + 8)? as usize;
        let data_offset = next + 10;
        let data_end = data_offset
            .checked_add(rdlen)
            .ok_or(DnsParseError::Truncated)?;
        if data_end > packet.len() {
            return Err(DnsParseError::Truncated);
        }
        if rr_class == DNS_CLASS_IN && rr_type == DNS_TYPE_A && rdlen == 4 {
            answers.push(DnsAddressRecord {
                hostname,
                address: IpAddr::V4(Ipv4Addr::new(
                    packet[data_offset],
                    packet[data_offset + 1],
                    packet[data_offset + 2],
                    packet[data_offset + 3],
                )),
                ttl: Duration::from_secs(u64::from(ttl_secs)),
            });
        } else if rr_class == DNS_CLASS_IN && rr_type == DNS_TYPE_AAAA && rdlen == 16 {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[data_offset..data_end]);
            answers.push(DnsAddressRecord {
                hostname,
                address: IpAddr::V6(Ipv6Addr::from(octets)),
                ttl: Duration::from_secs(u64::from(ttl_secs)),
            });
        }
        offset = data_end;
    }

    Ok(DnsResponseObservation {
        transaction_id: read_u16(packet, 0)?,
        hostname: question.as_ref().map(|question| question.hostname.clone()),
        query_type: question.map(|question| question.query_type),
        rcode: (flags & 0x000f) as u8,
        truncated: flags & 0x0200 != 0,
        answers,
    })
}

/// A broker-observed DNS query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsObservation {
    /// Sandbox/session identifier.
    pub sandbox_id: SandboxId,
    /// Queried hostname.
    pub hostname: Hostname,
    /// Query type.
    pub query_type: DnsQueryType,
    /// Time the query was observed.
    pub observed_at: SystemTime,
    /// Whether this query used the broker DNS path.
    pub broker_controlled: bool,
}

/// DNS cache entry suitable for later hostname attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCacheEntry {
    /// Sandbox/session identifier.
    pub sandbox_id: SandboxId,
    /// Hostname associated with the returned addresses.
    pub hostname: Hostname,
    /// Addresses returned by the DNS response.
    pub addresses: Vec<IpAddr>,
    /// Query type that produced this entry.
    pub query_type: DnsQueryType,
    /// Time the response was observed.
    pub observed_at: SystemTime,
    /// Time when this cache entry expires.
    pub expires_at: SystemTime,
    /// Whether this answer came from the broker-controlled resolver path.
    pub broker_controlled: bool,
}

impl DnsCacheEntry {
    /// Creates a DNS cache entry from response data and TTL.
    pub fn new(observation: DnsObservation, addresses: Vec<IpAddr>, ttl: Duration) -> Option<Self> {
        if addresses.is_empty() {
            return None;
        }
        let expires_at = observation.observed_at.checked_add(ttl)?;
        Some(Self {
            sandbox_id: observation.sandbox_id,
            hostname: observation.hostname,
            addresses,
            query_type: observation.query_type,
            observed_at: observation.observed_at,
            expires_at,
            broker_controlled: observation.broker_controlled,
        })
    }

    /// Creates cache entries from parsed DNS response address answers.
    pub fn from_response(
        sandbox_id: SandboxId,
        response: &DnsResponseObservation,
        observed_at: SystemTime,
        broker_controlled: bool,
    ) -> Vec<Self> {
        let Some(hostname) = response.hostname.clone() else {
            return Vec::new();
        };
        let Some(query_type) = response.query_type.clone() else {
            return Vec::new();
        };
        let mut addresses = Vec::new();
        let mut min_ttl = None;
        for answer in &response.answers {
            addresses.push(answer.address);
            min_ttl = Some(min_ttl.map_or(answer.ttl, |current: Duration| current.min(answer.ttl)));
        }
        let Some(ttl) = min_ttl else {
            return Vec::new();
        };
        let observation = DnsObservation {
            sandbox_id,
            hostname,
            query_type,
            observed_at,
            broker_controlled,
        };
        Self::new(observation, addresses, ttl).into_iter().collect()
    }

    /// Returns true when this entry is expired at `now`.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// Builds medium-confidence DNS-cache attribution for this entry.
    pub fn attribution(&self) -> Attribution {
        Attribution {
            hostname: Some(self.hostname.clone()),
            source: AttributionSource::DnsCache,
            confidence: AttributionConfidence::Medium,
        }
    }
}

/// Per-sandbox DNS cache keyed for hostname and reverse IP attribution lookup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsCache {
    entries: HashMap<(SandboxId, Hostname), DnsCacheEntry>,
}

impl DnsCache {
    /// Inserts or replaces a DNS cache entry.
    pub fn insert(&mut self, entry: DnsCacheEntry) {
        self.entries
            .insert((entry.sandbox_id.clone(), entry.hostname.clone()), entry);
    }

    /// Looks up a hostname entry, returning `None` after expiry.
    pub fn lookup_hostname(
        &self,
        sandbox_id: &SandboxId,
        hostname: &Hostname,
        now: SystemTime,
    ) -> Option<&DnsCacheEntry> {
        self.entries
            .get(&(sandbox_id.clone(), hostname.clone()))
            .filter(|entry| !entry.is_expired(now))
    }

    /// Finds the freshest unexpired entry that contains `address`.
    pub fn lookup_address(
        &self,
        sandbox_id: &SandboxId,
        address: IpAddr,
        now: SystemTime,
    ) -> Option<&DnsCacheEntry> {
        self.entries
            .values()
            .filter(|entry| {
                &entry.sandbox_id == sandbox_id
                    && !entry.is_expired(now)
                    && entry.addresses.contains(&address)
            })
            .max_by_key(|entry| entry.observed_at)
    }

    /// Removes expired entries and returns the number removed.
    pub fn expire(&mut self, now: SystemTime) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired(now));
        before - self.entries.len()
    }

    /// Returns the number of cached hostnames.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn parse_name(packet: &[u8], mut offset: usize) -> Result<(Hostname, usize), DnsParseError> {
    let mut labels = Vec::new();
    let mut consumed_offset = None;
    let mut jumps = 0;
    let mut name_len = 0;

    loop {
        let length = *packet.get(offset).ok_or(DnsParseError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(offset + 1).ok_or(DnsParseError::Truncated)?;
            let pointer = (((length & 0x3f) as usize) << 8) | next as usize;
            if pointer >= packet.len() || jumps >= MAX_DNS_POINTER_JUMPS {
                return Err(DnsParseError::BadCompressionPointer);
            }
            consumed_offset.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsParseError::MalformedName);
        }
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return Err(DnsParseError::MalformedName);
        }
        let end = offset
            .checked_add(length as usize)
            .ok_or(DnsParseError::Truncated)?;
        let label = packet.get(offset..end).ok_or(DnsParseError::Truncated)?;
        let label_str = std::str::from_utf8(label).map_err(|_| DnsParseError::MalformedName)?;
        name_len += label_str.len() + usize::from(!labels.is_empty());
        if name_len > 253 {
            return Err(DnsParseError::MalformedName);
        }
        labels.push(label_str.to_string());
        offset = end;
    }

    if labels.is_empty() {
        return Err(DnsParseError::MalformedName);
    }
    let hostname = Hostname::parse(labels.join(".")).map_err(|_| DnsParseError::MalformedName)?;
    Ok((hostname, consumed_offset.unwrap_or(offset)))
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsParseError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(DnsParseError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, DnsParseError> {
    let bytes = packet
        .get(offset..offset + 4)
        .ok_or(DnsParseError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(now: SystemTime) -> DnsObservation {
        DnsObservation {
            sandbox_id: SandboxId::new("alpha").unwrap(),
            hostname: Hostname::parse("Example.COM").unwrap(),
            query_type: DnsQueryType::parse("a").unwrap(),
            observed_at: now,
            broker_controlled: true,
        }
    }

    fn example_query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn query_type_normalizes_common_values() {
        assert_eq!(DnsQueryType::parse("a").unwrap(), DnsQueryType::A);
        assert_eq!(DnsQueryType::parse("AAAA").unwrap().as_str(), "AAAA");
        assert_eq!(DnsQueryType::parse("16").unwrap(), DnsQueryType::Other(16));
        assert!(DnsQueryType::parse("txt").is_none());
        assert!(DnsQueryType::parse("   ").is_none());
    }

    #[test]
    fn parses_single_question_query() {
        let question = parse_dns_query(&example_query()).unwrap();
        assert_eq!(question.transaction_id, 0x1234);
        assert_eq!(question.hostname.as_str(), "example.com");
        assert_eq!(question.query_type, DnsQueryType::A);
        assert_eq!(question.query_class, DNS_CLASS_IN);
        assert!(question.recursion_desired);
    }

    #[test]
    fn parses_compressed_address_response() {
        let mut response = example_query();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 0x01;
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        let question = parse_dns_query(&example_query()).unwrap();
        let parsed = parse_dns_response(&response, Some(&question)).unwrap();
        assert_eq!(parsed.transaction_id, 0x1234);
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0].address,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(parsed.answers[0].ttl, Duration::from_secs(60));
    }

    #[test]
    fn rejects_malformed_dns_packets() {
        assert_eq!(parse_dns_query(&[0; 4]), Err(DnsParseError::Truncated));
        let mut loop_pointer = example_query();
        let name_offset = DNS_HEADER_LEN;
        loop_pointer[name_offset] = 0xc0;
        loop_pointer[name_offset + 1] = name_offset as u8;
        assert_eq!(
            parse_dns_query(&loop_pointer),
            Err(DnsParseError::BadCompressionPointer)
        );
    }

    #[test]
    fn fuzz_smoke_dns_parsers_are_total() {
        let seeds = [Vec::new(), vec![0; 4], example_query()];
        for seed in seeds {
            for input in mutated_inputs(&seed) {
                let _ = parse_dns_query(&input);
                let _ = parse_dns_response(&input, None);
            }
        }
    }

    fn mutated_inputs(seed: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        out.push(seed.to_vec());
        for len in 0..=seed.len().min(16) {
            out.push(seed[..len].to_vec());
        }
        for index in 0..seed.len().min(32) {
            let mut mutated = seed.to_vec();
            mutated[index] ^= 0x80;
            out.push(mutated);
        }
        let mut generated = Vec::new();
        let mut state = seed.len() as u32 ^ 0x1357_2468;
        for _ in 0..96 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            generated.push((state >> 16) as u8);
        }
        out.push(generated);
        out
    }

    #[test]
    fn cache_entry_requires_address_and_expires() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        assert!(
            DnsCacheEntry::new(observation(now), Vec::new(), Duration::from_secs(10)).is_none()
        );
        let entry = DnsCacheEntry::new(
            observation(now),
            vec!["93.184.216.34".parse().unwrap()],
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(!entry.is_expired(now + Duration::from_secs(9)));
        assert!(entry.is_expired(now + Duration::from_secs(10)));
        assert_eq!(entry.attribution().source, AttributionSource::DnsCache);
    }

    #[test]
    fn cache_supports_hostname_and_reverse_lookup() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(200);
        let entry = DnsCacheEntry::new(
            observation(now),
            vec!["93.184.216.34".parse().unwrap()],
            Duration::from_secs(30),
        )
        .unwrap();
        let sandbox_id = entry.sandbox_id.clone();
        let hostname = entry.hostname.clone();
        let address = entry.addresses[0];
        let mut cache = DnsCache::default();
        cache.insert(entry);

        assert!(cache.lookup_hostname(&sandbox_id, &hostname, now).is_some());
        assert_eq!(
            cache
                .lookup_address(&sandbox_id, address, now)
                .unwrap()
                .hostname,
            hostname
        );
        assert_eq!(cache.expire(now + Duration::from_secs(31)), 1);
        assert!(cache.is_empty());
    }
}
