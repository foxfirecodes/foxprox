//! DNS observation and cache types for transparent hostname attribution.
//!
//! This module is data-only: packet parsing, sockets, and upstream resolver I/O
//! live in frontend/egress crates. Core owns the normalized observation and cache
//! semantics that later policy/audit code can share across transparent and proxy
//! modes.

use crate::event::{Attribution, AttributionConfidence, AttributionSource, Hostname, SandboxId};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// DNS query type observed by the broker.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DnsQueryType {
    /// IPv4 address lookup.
    A,
    /// IPv6 address lookup.
    Aaaa,
    /// Other query type kept as an uppercase presentation string.
    Other(String),
}

impl DnsQueryType {
    /// Parses a DNS query type label.
    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_uppercase();
        if normalized.is_empty() {
            return None;
        }
        Some(match normalized.as_str() {
            "A" => Self::A,
            "AAAA" => Self::Aaaa,
            _ => Self::Other(normalized),
        })
    }

    /// Returns the query type as a presentation string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Other(value) => value.as_str(),
        }
    }
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

    #[test]
    fn query_type_normalizes_common_values() {
        assert_eq!(DnsQueryType::parse("a").unwrap(), DnsQueryType::A);
        assert_eq!(DnsQueryType::parse("AAAA").unwrap().as_str(), "AAAA");
        assert_eq!(DnsQueryType::parse("txt").unwrap().as_str(), "TXT");
        assert!(DnsQueryType::parse("   ").is_none());
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
