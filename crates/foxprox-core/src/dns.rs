use std::collections::BTreeMap;
use std::net::IpAddr;

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
    fn dns_cache_attributes_and_expires() {
        let mut cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        cache.observe_response("Example.COM", [ip], 10, 5).unwrap();
        let attr = cache.attribution_for(ip, 12).unwrap();
        assert_eq!(attr.hostname, "example.com");
        assert_eq!(attr.confidence, AttributionConfidence::Medium);
        assert!(cache.attribution_for(ip, 16).is_none());
    }
}
