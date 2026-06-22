use crate::audit::AuditRecord;
use crate::types::{
    AttributionConfidence, AttributionSource, AuditKind, ByteCounts, Frontend, HostnameAttribution,
    NetworkEndpoint, Protocol,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowKey {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: FlowProtocol,
}

impl FlowKey {
    pub fn udp(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> Self {
        Self::new(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            FlowProtocol::Udp,
        )
    }

    pub fn tcp(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> Self {
        Self::new(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            FlowProtocol::Tcp,
        )
    }

    pub fn new(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        protocol: FlowProtocol,
    ) -> Self {
        Self {
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
        }
    }

    pub fn source(&self) -> NetworkEndpoint {
        NetworkEndpoint::socket(self.source_ip, self.source_port)
    }

    pub fn destination(&self) -> NetworkEndpoint {
        NetworkEndpoint::socket(self.destination_ip, self.destination_port)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpClassification {
    Dns,
    QuicCandidate,
    Generic,
    OneShot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpFlow {
    pub key: FlowKey,
    pub classification: UdpClassification,
    pub created_at_ms: u64,
    pub last_seen_ms: u64,
    pub timeout_ms: u64,
    pub byte_counts: ByteCounts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpTimeoutConfig {
    pub dns_ms: u64,
    pub generic_ms: u64,
    pub quic_ms: u64,
    pub one_shot_ms: u64,
}

impl Default for UdpTimeoutConfig {
    fn default() -> Self {
        Self {
            dns_ms: 10_000,
            generic_ms: 60_000,
            quic_ms: 180_000,
            one_shot_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UdpFlowManager {
    sandbox_id: String,
    timeouts: UdpTimeoutConfig,
    flows: BTreeMap<FlowKey, UdpFlow>,
}

impl UdpFlowManager {
    pub fn new(sandbox_id: impl Into<String>, timeouts: UdpTimeoutConfig) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            timeouts,
            flows: BTreeMap::new(),
        }
    }

    pub fn observe_outbound_datagram(
        &mut self,
        key: FlowKey,
        byte_len: u64,
        now_ms: u64,
    ) -> Vec<AuditRecord> {
        self.observe_outbound_datagram_as(
            key.clone(),
            byte_len,
            now_ms,
            classify_udp(key.destination_port),
        )
    }

    pub fn observe_outbound_datagram_as(
        &mut self,
        key: FlowKey,
        byte_len: u64,
        now_ms: u64,
        classification: UdpClassification,
    ) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        let timeout_ms = self.timeout_for(classification);
        let flow = self.flows.entry(key.clone()).or_insert_with(|| {
            records.push(
                AuditRecord::new(AuditKind::UdpFlowCreated, self.sandbox_id.clone())
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Udp)
                    .with_source(key.source())
                    .with_destination(key.destination())
                    .with_timestamp_ms(now_ms as u128)
                    .with_detail(
                        "classification",
                        format!("{classification:?}").to_ascii_lowercase(),
                    )
                    .with_detail("timeout_ms", timeout_ms.to_string()),
            );
            if classification == UdpClassification::QuicCandidate {
                records.push(
                    AuditRecord::new(AuditKind::QuicCandidateFlowCreated, self.sandbox_id.clone())
                        .with_frontend(Frontend::Tun)
                        .with_protocol(Protocol::Quic)
                        .with_source(key.source())
                        .with_destination(key.destination())
                        .with_timestamp_ms(now_ms as u128),
                );
            }
            UdpFlow {
                key: key.clone(),
                classification,
                created_at_ms: now_ms,
                last_seen_ms: now_ms,
                timeout_ms,
                byte_counts: ByteCounts::ZERO,
            }
        });
        flow.last_seen_ms = now_ms;
        flow.byte_counts.from_sandbox = flow.byte_counts.from_sandbox.saturating_add(byte_len);
        records
    }

    pub fn observe_inbound_datagram(&mut self, key: &FlowKey, byte_len: u64, now_ms: u64) {
        if let Some(flow) = self.flows.get_mut(key) {
            flow.last_seen_ms = now_ms;
            flow.byte_counts.to_sandbox = flow.byte_counts.to_sandbox.saturating_add(byte_len);
        }
    }

    pub fn expire(&mut self, now_ms: u64) -> Vec<AuditRecord> {
        let expired_keys: Vec<_> = self
            .flows
            .iter()
            .filter(|(_, flow)| now_ms.saturating_sub(flow.last_seen_ms) >= flow.timeout_ms)
            .map(|(key, _)| key.clone())
            .collect();
        let mut records = Vec::new();
        for key in expired_keys {
            if let Some(flow) = self.flows.remove(&key) {
                records.push(
                    AuditRecord::new(AuditKind::UdpFlowExpired, self.sandbox_id.clone())
                        .with_frontend(Frontend::Tun)
                        .with_protocol(Protocol::Udp)
                        .with_source(flow.key.source())
                        .with_destination(flow.key.destination())
                        .with_timestamp_ms(now_ms as u128)
                        .with_byte_counts(flow.byte_counts)
                        .with_duration_ms(now_ms.saturating_sub(flow.created_at_ms))
                        .with_detail(
                            "classification",
                            format!("{:?}", flow.classification).to_ascii_lowercase(),
                        ),
                );
            }
        }
        records
    }

    pub fn get(&self, key: &FlowKey) -> Option<&UdpFlow> {
        self.flows.get(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    fn timeout_for(&self, classification: UdpClassification) -> u64 {
        match classification {
            UdpClassification::Dns => self.timeouts.dns_ms,
            UdpClassification::QuicCandidate => self.timeouts.quic_ms,
            UdpClassification::Generic => self.timeouts.generic_ms,
            UdpClassification::OneShot => self.timeouts.one_shot_ms,
        }
    }
}

fn classify_udp(destination_port: u16) -> UdpClassification {
    match destination_port {
        53 => UdpClassification::Dns,
        443 => UdpClassification::QuicCandidate,
        123 => UdpClassification::OneShot,
        _ => UdpClassification::Generic,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsObservation {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub query_type: String,
    pub observed_at_ms: u64,
    pub ttl_ms: u64,
}

impl DnsObservation {
    pub fn new(
        hostname: impl Into<String>,
        query_type: impl Into<String>,
        addresses: Vec<IpAddr>,
        observed_at_ms: u64,
        ttl_ms: u64,
    ) -> Self {
        Self {
            hostname: crate::types::normalize_hostname(&hostname.into()),
            addresses,
            query_type: query_type.into(),
            observed_at_ms,
            ttl_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolution {
    pub hostname: String,
    pub address: IpAddr,
    pub query_type: String,
    pub ttl_remaining_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct DnsCache {
    by_ip: BTreeMap<IpAddr, Vec<DnsObservation>>,
}

impl DnsCache {
    pub fn observe(
        &mut self,
        sandbox_id: impl Into<String>,
        hostname: impl Into<String>,
        query_type: impl Into<String>,
        addresses: Vec<IpAddr>,
        observed_at_ms: u64,
        ttl_ms: u64,
    ) -> AuditRecord {
        let observation =
            DnsObservation::new(hostname, query_type, addresses, observed_at_ms, ttl_ms);
        let audit = Self::observation_audit(sandbox_id, &observation);
        self.commit_observation(observation);
        audit
    }

    pub fn observation_audit(
        sandbox_id: impl Into<String>,
        observation: &DnsObservation,
    ) -> AuditRecord {
        AuditRecord::new(AuditKind::DnsQueryDecision, sandbox_id)
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Dns)
            .with_timestamp_ms(observation.observed_at_ms as u128)
            .with_hostname(observation.hostname.clone())
            .with_detail("dns_query_type", observation.query_type.clone())
            .with_detail(
                "returned_addresses",
                observation
                    .addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
    }

    pub fn commit_observation(&mut self, observation: DnsObservation) {
        for address in &observation.addresses {
            self.by_ip
                .entry(*address)
                .or_default()
                .push(observation.clone());
        }
    }

    pub fn rollback_observation(&mut self, observation: &DnsObservation) {
        for address in &observation.addresses {
            let should_remove_key = if let Some(observations) = self.by_ip.get_mut(address) {
                if let Some(index) = observations
                    .iter()
                    .rposition(|stored| stored == observation)
                {
                    observations.remove(index);
                }
                observations.is_empty()
            } else {
                false
            };
            if should_remove_key {
                self.by_ip.remove(address);
            }
        }
    }

    pub fn attribution_for(&self, ip: IpAddr, now_ms: u64) -> Option<HostnameAttribution> {
        self.by_ip.get(&ip).and_then(|observations| {
            observations
                .iter()
                .rev()
                .find(|observation| {
                    now_ms.saturating_sub(observation.observed_at_ms) <= observation.ttl_ms
                })
                .map(|observation| {
                    HostnameAttribution::new(
                        observation.hostname.clone(),
                        AttributionSource::BrokerDns,
                        AttributionConfidence::Medium,
                    )
                })
        })
    }

    pub fn resolve_hostname(&self, hostname: &str, now_ms: u64) -> Option<DnsResolution> {
        let hostname = crate::types::normalize_hostname(hostname);
        self.by_ip.iter().find_map(|(address, observations)| {
            observations.iter().rev().find_map(|observation| {
                let age_ms = now_ms.saturating_sub(observation.observed_at_ms);
                (observation.hostname == hostname && age_ms <= observation.ttl_ms).then(|| {
                    DnsResolution {
                        hostname: observation.hostname.clone(),
                        address: *address,
                        query_type: observation.query_type.clone(),
                        ttl_remaining_ms: observation.ttl_ms.saturating_sub(age_ms),
                    }
                })
            })
        })
    }

    pub fn addresses_for_hostname(&self, hostname: &str, now_ms: u64) -> Vec<IpAddr> {
        let hostname = crate::types::normalize_hostname(hostname);
        let mut addresses = Vec::new();
        for (address, observations) in &self.by_ip {
            if observations.iter().rev().any(|observation| {
                observation.hostname == hostname
                    && now_ms.saturating_sub(observation.observed_at_ms) <= observation.ttl_ms
            }) && !addresses.contains(address)
            {
                addresses.push(*address);
            }
        }
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn udp_flow_lifecycle_emits_create_quic_and_expire_audit() {
        let mut manager = UdpFlowManager::new("s1", UdpTimeoutConfig::default());
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            53000,
            "93.184.216.34".parse().unwrap(),
            443,
        );

        let records = manager.observe_outbound_datagram(key.clone(), 1200, 1_000);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::UdpFlowCreated);
        assert_eq!(records[0].decision, None);
        assert_eq!(records[0].timestamp_ms, 1_000);
        assert_eq!(records[1].kind, AuditKind::QuicCandidateFlowCreated);
        assert_eq!(records[1].decision, None);
        assert_eq!(manager.get(&key).unwrap().byte_counts.from_sandbox, 1200);

        manager.observe_inbound_datagram(&key, 900, 2_000);
        let expired = manager.expire(182_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].kind, AuditKind::UdpFlowExpired);
        assert_eq!(expired[0].timestamp_ms, 182_000);
        assert_eq!(expired[0].byte_counts.as_ref().unwrap().from_sandbox, 1200);
        assert_eq!(expired[0].byte_counts.as_ref().unwrap().to_sandbox, 900);
        assert!(manager.is_empty());
    }

    #[test]
    fn dns_cache_resolves_hostname_to_unexpired_observed_addresses() {
        let mut cache = DnsCache::default();
        cache.commit_observation(DnsObservation::new(
            "Example.COM",
            "A",
            vec!["93.184.216.34".parse().unwrap()],
            1_000,
            500,
        ));
        cache.commit_observation(DnsObservation::new(
            "expired.example",
            "A",
            vec!["203.0.113.9".parse().unwrap()],
            1_000,
            10,
        ));

        assert_eq!(
            cache.addresses_for_hostname("example.com", 1_100),
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert!(cache
            .addresses_for_hostname("expired.example", 1_100)
            .is_empty());
        assert!(cache
            .addresses_for_hostname("missing.example", 1_100)
            .is_empty());
    }

    #[test]
    fn dns_cache_returns_medium_confidence_attribution_until_ttl_expires() {
        let mut cache = DnsCache::default();
        let audit = cache.observe(
            "s1",
            "Example.COM.",
            "A",
            vec!["93.184.216.34".parse().unwrap()],
            1_000,
            30_000,
        );
        assert_eq!(audit.kind, AuditKind::DnsQueryDecision);
        assert_eq!(audit.timestamp_ms, 1_000);
        assert_eq!(audit.hostname.as_deref(), Some("example.com"));

        let attribution = cache
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .unwrap();
        assert_eq!(attribution.hostname, "example.com");
        assert_eq!(attribution.confidence, AttributionConfidence::Medium);
        assert!(cache
            .attribution_for("93.184.216.34".parse().unwrap(), 40_000)
            .is_none());
    }
}
