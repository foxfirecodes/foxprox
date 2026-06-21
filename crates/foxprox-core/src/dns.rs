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
}
