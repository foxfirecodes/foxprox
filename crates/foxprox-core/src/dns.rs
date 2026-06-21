use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::audit::{AttributionConfidence, AttributionSource};

/// DNS query types tracked by the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A,
    Aaaa,
    Cname,
    Other(u16),
}

impl QueryType {
    pub fn as_str(self) -> String {
        match self {
            Self::A => "A".to_string(),
            Self::Aaaa => "AAAA".to_string(),
            Self::Cname => "CNAME".to_string(),
            Self::Other(value) => format!("TYPE{value}"),
        }
    }
}

/// One normalized DNS query observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub hostname: String,
    pub query_type: QueryType,
}

impl DnsQuery {
    pub fn new(hostname: impl Into<String>, query_type: QueryType) -> Result<Self, String> {
        let hostname = normalize_hostname(&hostname.into())?;
        Ok(Self {
            hostname,
            query_type,
        })
    }
}

/// Hostname attribution for an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAttribution {
    pub hostname: String,
    pub source: AttributionSource,
    pub confidence: AttributionConfidence,
    pub expires_at_tick: u64,
}

/// Deterministic DNS cache keyed by IP address. Ticks are caller-owned so tests do not depend on clocks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsCache {
    by_ip: BTreeMap<IpAddr, Vec<HostAttribution>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            by_ip: BTreeMap::new(),
        }
    }

    pub fn observe_response(
        &mut self,
        hostname: impl Into<String>,
        addresses: impl IntoIterator<Item = IpAddr>,
        now_tick: u64,
        ttl_ticks: u64,
    ) -> Result<(), String> {
        let hostname = normalize_hostname(&hostname.into())?;
        let expires_at_tick = now_tick.saturating_add(ttl_ticks);
        for ip in addresses {
            self.by_ip.entry(ip).or_default().push(HostAttribution {
                hostname: hostname.clone(),
                source: AttributionSource::DnsCache,
                confidence: AttributionConfidence::Medium,
                expires_at_tick,
            });
        }
        Ok(())
    }

    pub fn attribution_for(&self, ip: IpAddr, now_tick: u64) -> Option<HostAttribution> {
        self.by_ip
            .get(&ip)?
            .iter()
            .filter(|entry| entry.expires_at_tick >= now_tick)
            .max_by_key(|entry| entry.expires_at_tick)
            .cloned()
    }

    pub fn expire(&mut self, now_tick: u64) {
        self.by_ip.retain(|_, entries| {
            entries.retain(|entry| entry.expires_at_tick >= now_tick);
            !entries.is_empty()
        });
    }
}

/// Parse a minimal DNS wire query with one question and return the normalized query.
///
/// Alpha scope intentionally supports the common uncompressed QNAME question form used by local
/// harness probes. Malformed, compressed, multi-question, or truncated inputs fail closed.
pub fn parse_dns_query(wire: &[u8]) -> Result<DnsQuery, String> {
    if wire.len() < 12 {
        return Err("DNS packet too short".to_string());
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]);
    if qdcount != 1 {
        return Err("DNS query must contain exactly one question".to_string());
    }
    let mut cursor = 12;
    let mut labels = Vec::new();
    loop {
        let Some(&len) = wire.get(cursor) else {
            return Err("DNS QNAME truncated".to_string());
        };
        cursor += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err("DNS compressed QNAME is unsupported in alpha queries".to_string());
        }
        if len > 63 {
            return Err("DNS label exceeds 63 octets".to_string());
        }
        let end = cursor + len as usize;
        if end > wire.len() {
            return Err("DNS label truncated".to_string());
        }
        let label = std::str::from_utf8(&wire[cursor..end])
            .map_err(|_| "DNS label is not UTF-8/ASCII".to_string())?;
        labels.push(label.to_string());
        cursor = end;
    }
    if cursor + 4 > wire.len() {
        return Err("DNS question trailer truncated".to_string());
    }
    let qtype = u16::from_be_bytes([wire[cursor], wire[cursor + 1]]);
    let qclass = u16::from_be_bytes([wire[cursor + 2], wire[cursor + 3]]);
    if qclass != 1 {
        return Err("only DNS class IN is supported in alpha".to_string());
    }
    let query_type = match qtype {
        1 => QueryType::A,
        28 => QueryType::Aaaa,
        5 => QueryType::Cname,
        other => QueryType::Other(other),
    };
    DnsQuery::new(labels.join("."), query_type)
}

/// Synthesize a minimal DNS A response for a query parsed by [`parse_dns_query`].
pub fn synthesize_a_response(
    query_wire: &[u8],
    answer: Ipv4Addr,
    ttl_seconds: u32,
) -> Result<Vec<u8>, String> {
    let query = parse_dns_query(query_wire)?;
    if query.query_type != QueryType::A {
        return Err("only DNS A responses are supported by the alpha DNS synthesizer".to_string());
    }
    let question_end = dns_question_end(query_wire)?;
    let mut out = Vec::with_capacity(question_end + 16);
    out.extend_from_slice(&query_wire[..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&query_wire[12..question_end]);
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&ttl_seconds.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x04]);
    out.extend_from_slice(&answer.octets());
    Ok(out)
}

fn dns_question_end(wire: &[u8]) -> Result<usize, String> {
    if wire.len() < 12 {
        return Err("DNS packet too short".to_string());
    }
    let mut cursor = 12;
    loop {
        let Some(&len) = wire.get(cursor) else {
            return Err("DNS QNAME truncated".to_string());
        };
        cursor += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err("DNS compressed QNAME is unsupported in alpha queries".to_string());
        }
        cursor += len as usize;
        if cursor > wire.len() {
            return Err("DNS label truncated".to_string());
        }
    }
    if cursor + 4 > wire.len() {
        return Err("DNS question trailer truncated".to_string());
    }
    Ok(cursor + 4)
}

pub fn normalize_hostname(input: &str) -> Result<String, String> {
    let hostname = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() {
        return Err("hostname is empty".to_string());
    }
    if hostname.len() > 253 {
        return Err("hostname exceeds 253 octets".to_string());
    }
    for label in hostname.split('.') {
        if label.is_empty() {
            return Err("hostname contains empty label".to_string());
        }
        if label.len() > 63 {
            return Err("hostname label exceeds 63 octets".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("hostname label starts or ends with '-'".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("hostname contains unsupported character".to_string());
        }
    }
    Ok(hostname)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn normalizes_and_validates_hostnames() {
        assert_eq!(normalize_hostname("Example.COM.").unwrap(), "example.com");
        assert!(normalize_hostname("bad..example").is_err());
        assert!(normalize_hostname("-bad.example").is_err());
    }

    #[test]
    fn parses_and_synthesizes_a_query_wire() {
        let query = a_query_wire("Example.COM");
        let parsed = parse_dns_query(&query).unwrap();
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.query_type, QueryType::A);
        let response = synthesize_a_response(&query, Ipv4Addr::new(203, 0, 113, 77), 60).unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(&response[2..4], &[0x81, 0x80]);
        assert!(response.ends_with(&[203, 0, 113, 77]));
    }

    #[test]
    fn malformed_dns_queries_fail_closed() {
        assert!(parse_dns_query(&[0; 11]).is_err());
        let mut compressed = a_query_wire("example.com");
        compressed[12] = 0xc0;
        compressed[13] = 0x0c;
        assert!(parse_dns_query(&compressed).is_err());
    }

    #[test]
    fn dns_cache_attributes_and_expires() {
        let mut cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        cache.observe_response("Example.COM", [ip], 10, 5).unwrap();
        let attr = cache.attribution_for(ip, 12).unwrap();
        assert_eq!(attr.hostname, "example.com");
        assert_eq!(attr.confidence, AttributionConfidence::Medium);
        assert!(cache.attribution_for(ip, 16).is_none());
    }

    fn a_query_wire(hostname: &str) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in hostname.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out
    }
}
