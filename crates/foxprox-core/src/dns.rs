use crate::types::{Hostname, HostnameAttribution};
use std::net::IpAddr;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
}
