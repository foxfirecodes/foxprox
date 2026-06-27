use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::flow::{DnsCache, FlowKey, UdpClassification, UdpFlowManager, UdpTimeoutConfig};
use crate::inspect::is_quic_candidate;
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::types::{AuditKind, Decision, DenialReason, Frontend, NetworkEndpoint, Protocol};
use serde::{Deserialize, Serialize};

pub trait UdpEgress {
    fn send_datagram(
        &mut self,
        destination: NetworkEndpoint,
        payload: &[u8],
    ) -> Result<(), UdpEgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpEgressError {
    SendFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpForwardResult {
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub sent: bool,
}

#[derive(Clone, Debug)]
pub struct UdpForwarder<E> {
    sandbox_id: String,
    broker: BrokerCore,
    flows: UdpFlowManager,
    egress: E,
    max_active_flows: Option<usize>,
}

impl<E: UdpEgress> UdpForwarder<E> {
    pub fn new(
        sandbox_id: impl Into<String>,
        broker: BrokerCore,
        egress: E,
        timeouts: UdpTimeoutConfig,
    ) -> Self {
        let sandbox_id = sandbox_id.into();
        Self {
            flows: UdpFlowManager::new(sandbox_id.clone(), timeouts),
            sandbox_id,
            broker,
            egress,
            max_active_flows: None,
        }
    }

    pub fn with_max_active_flows(mut self, max_active_flows: usize) -> Self {
        self.max_active_flows = Some(max_active_flows);
        self
    }

    pub fn handle_outbound_datagram(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<UdpForwardResult, UdpEgressError> {
        self.handle_outbound_datagram_inner(key, payload, now_ms, None)
    }

    pub fn handle_outbound_datagram_with_dns_cache(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        now_ms: u64,
        dns_cache: &DnsCache,
    ) -> Result<UdpForwardResult, UdpEgressError> {
        self.handle_outbound_datagram_inner(key, payload, now_ms, Some(dns_cache))
    }

    fn handle_outbound_datagram_inner(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        now_ms: u64,
        dns_cache: Option<&DnsCache>,
    ) -> Result<UdpForwardResult, UdpEgressError> {
        let quic_candidate =
            key.destination_port != 53 && is_quic_candidate(key.destination_port, payload);
        let request = self.request_for_key(&key, dns_cache, now_ms, quic_candidate);
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false));
        }
        if let Some(decision) = self.expire(now_ms).into_iter().next() {
            return Ok(result_from_decision(decision, false));
        }
        if self.would_exceed_flow_limit(&key) {
            let resource_decision = PolicyDecision {
                decision: Decision::DenyDrop,
                reason: Some(DenialReason::ResourceLimit),
                rule_id: None,
                audit_kind: AuditKind::UdpPacketDecision,
            };
            let audit = AuditRecord::new(AuditKind::UdpPacketDecision, self.sandbox_id.clone())
                .with_frontend(Frontend::Tun)
                .with_protocol(Protocol::Udp)
                .with_source(key.source())
                .with_destination(key.destination())
                .with_decision(Decision::DenyDrop, Some(DenialReason::ResourceLimit))
                .with_detail("resource", "udp_active_flows")
                .with_detail("active_flows", self.flows.len().to_string())
                .with_detail(
                    "limit",
                    self.max_active_flows.unwrap_or_default().to_string(),
                );
            return match self.broker.append_audit_for(&request, audit) {
                Ok(_) => Ok(result_from_decision(resource_decision, false)),
                Err(decision) => Ok(result_from_decision(decision, false)),
            };
        }

        let previous_flows = self.flows.clone();
        let classification = match key.destination_port {
            53 => UdpClassification::Dns,
            _ if quic_candidate => UdpClassification::QuicCandidate,
            123 => UdpClassification::OneShot,
            _ => UdpClassification::Generic,
        };
        let flow_records = self.flows.observe_outbound_datagram_as(
            key.clone(),
            payload.len() as u64,
            now_ms,
            classification,
        );
        for record in flow_records {
            if let Err(decision) = self.broker.append_audit_for(&request, record) {
                self.flows = previous_flows;
                return Ok(result_from_decision(decision, false));
            }
        }

        if let Err(error) = self.egress.send_datagram(key.destination(), payload) {
            self.flows = previous_flows;
            let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                .with_frontend(Frontend::Tun)
                .with_protocol(Protocol::Udp)
                .with_source(key.source())
                .with_destination(key.destination())
                .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                .with_detail("error", "udp_egress_send_failed");
            let _ = self.broker.append_audit_for(&request, audit);
            return Err(error);
        }
        Ok(UdpForwardResult {
            decision: Decision::Allow,
            reason: None,
            sent: true,
        })
    }

    pub fn handle_inbound_datagram(&mut self, key: &FlowKey, payload: &[u8], now_ms: u64) {
        self.flows
            .observe_inbound_datagram(key, payload.len() as u64, now_ms);
    }

    pub fn expire(&mut self, now_ms: u64) -> Vec<PolicyDecision> {
        let previous_flows = self.flows.clone();
        let records = self.flows.expire(now_ms);
        let request = PolicyRequest::new(self.sandbox_id.clone(), Frontend::Tun, Protocol::Udp);
        let decisions: Vec<_> = records
            .into_iter()
            .filter_map(|record| self.broker.append_audit_for(&request, record).err())
            .collect();
        if !decisions.is_empty() {
            self.flows = previous_flows;
        }
        decisions
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn flows(&self) -> &UdpFlowManager {
        &self.flows
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn egress_mut(&mut self) -> &mut E {
        &mut self.egress
    }

    pub fn into_parts(self) -> (BrokerCore, UdpFlowManager, E) {
        (self.broker, self.flows, self.egress)
    }

    fn would_exceed_flow_limit(&self, key: &FlowKey) -> bool {
        self.max_active_flows
            .is_some_and(|limit| self.flows.get(key).is_none() && self.flows.len() >= limit)
    }

    fn request_for_key(
        &self,
        key: &FlowKey,
        dns_cache: Option<&DnsCache>,
        now_ms: u64,
        quic_candidate: bool,
    ) -> PolicyRequest {
        let protocol = match key.destination_port {
            53 => Protocol::Dns,
            _ if quic_candidate => Protocol::Quic,
            _ => Protocol::Udp,
        };
        let mut request = PolicyRequest::new(self.sandbox_id.clone(), Frontend::Tun, protocol)
            .with_destination(key.destination());
        request.source = key.source();
        if protocol == Protocol::Quic {
            request = request.with_detail("udp_classification", "quic_candidate");
            if let Some(attribution) =
                dns_cache.and_then(|cache| cache.attribution_for(key.destination_ip, now_ms))
            {
                request = request.with_attribution(attribution);
            }
        }
        request
    }
}

fn result_from_decision(decision: PolicyDecision, sent: bool) -> UdpForwardResult {
    UdpForwardResult {
        decision: decision.decision,
        reason: decision.reason,
        sent,
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryUdpEgress {
    sent: Vec<(NetworkEndpoint, Vec<u8>)>,
}

impl InMemoryUdpEgress {
    pub fn sent(&self) -> &[(NetworkEndpoint, Vec<u8>)] {
        &self.sent
    }
}

impl UdpEgress for InMemoryUdpEgress {
    fn send_datagram(
        &mut self,
        destination: NetworkEndpoint,
        payload: &[u8],
    ) -> Result<(), UdpEgressError> {
        self.sent.push((destination, payload.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::UdpClassification;
    use crate::policy::{Cidr, PolicyConfig, PolicyEngine, PolicyRule};
    use crate::types::AuditKind;
    use pretty_assertions::assert_eq;

    #[test]
    fn allowed_udp_datagram_records_decision_flow_and_fake_egress() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-udp-doc")
                .protocol(Protocol::Udp)
                .destination_cidr(Cidr::new("203.0.113.0".parse().unwrap(), 24))
                .destination_port(12345),
        );
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            12345,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key.clone(), b"hello", 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.sent);
        assert_eq!(forwarder.egress().sent().len(), 1);
        assert_eq!(
            forwarder
                .flows()
                .get(&key)
                .unwrap()
                .byte_counts
                .from_sandbox,
            5
        );
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::UdpPacketDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[1].kind, AuditKind::UdpFlowCreated);
        assert_eq!(records[1].details["classification"], "generic");
    }

    #[test]
    fn active_flow_limit_denies_new_flow_without_egress() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let first_key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            12345,
        );
        let second_key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40001,
            "203.0.113.43".parse().unwrap(),
            12345,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        )
        .with_max_active_flows(1);

        assert_eq!(
            forwarder
                .handle_outbound_datagram(first_key.clone(), b"first", 1_000)
                .unwrap()
                .decision,
            Decision::Allow
        );
        let result = forwarder
            .handle_outbound_datagram(second_key, b"second", 1_100)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::ResourceLimit));
        assert_eq!(forwarder.egress().sent().len(), 1);
        assert_eq!(forwarder.flows().len(), 1);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        let resource_record = records.last().unwrap();
        assert_eq!(resource_record.kind, AuditKind::UdpPacketDecision);
        assert_eq!(resource_record.reason, Some(DenialReason::ResourceLimit));
        assert_eq!(resource_record.details["resource"], "udp_active_flows");
        assert_eq!(resource_record.details["limit"], "1");
    }

    #[test]
    fn active_flow_limit_allows_existing_flow_updates() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            12345,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        )
        .with_max_active_flows(1);

        assert_eq!(
            forwarder
                .handle_outbound_datagram(key.clone(), b"first", 1_000)
                .unwrap()
                .decision,
            Decision::Allow
        );
        assert_eq!(
            forwarder
                .handle_outbound_datagram(key.clone(), b"second", 1_100)
                .unwrap()
                .decision,
            Decision::Allow
        );
        assert_eq!(forwarder.egress().sent().len(), 2);
        assert_eq!(
            forwarder
                .flows()
                .get(&key)
                .unwrap()
                .byte_counts
                .from_sandbox,
            11
        );
    }

    #[test]
    fn active_flow_limit_expires_stale_flow_before_denying_new_flow() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let first_key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            12345,
        );
        let second_key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40001,
            "203.0.113.43".parse().unwrap(),
            12345,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        )
        .with_max_active_flows(1);

        assert_eq!(
            forwarder
                .handle_outbound_datagram(first_key, b"first", 1_000)
                .unwrap()
                .decision,
            Decision::Allow
        );
        let result = forwarder
            .handle_outbound_datagram(second_key.clone(), b"second", 61_000)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(forwarder.flows().len(), 1);
        assert!(forwarder.flows().get(&second_key).is_some());
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert!(records
            .iter()
            .any(|record| record.kind == AuditKind::UdpFlowExpired));
    }

    #[test]
    fn denied_multicast_udp_does_not_send() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "224.0.0.1".parse().unwrap(),
            9999,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, b"hello", 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::MulticastDenied));
        assert!(!result.sent);
        assert!(forwarder.egress().sent().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.reason, Some(DenialReason::MulticastDenied));
    }

    #[test]
    fn direct_external_dns_udp_does_not_send() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "8.8.8.8".parse().unwrap(),
            53,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, b"dns", 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::DirectDnsBypass));
        assert!(forwarder.egress().sent().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::DnsQueryDecision);
        assert_eq!(record.reason, Some(DenialReason::DirectDnsBypass));
    }

    #[test]
    fn quic_hostname_policy_uses_dns_cache_attribution() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-quic-host")
                .protocol(Protocol::Quic)
                .hostname("example.com")
                .destination_port(443),
        );
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let mut dns_cache = DnsCache::default();
        dns_cache.observe(
            "s1",
            "example.com",
            "A",
            vec!["203.0.113.42".parse().unwrap()],
            1_000,
            60_000,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 5);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram_with_dns_cache(key, &[0xc0, 0, 0, 1], 2_000, &dns_cache)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.sent);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::UdpPacketDecision);
        assert_eq!(records[0].rule_id.as_deref(), Some("allow-quic-host"));
        assert_eq!(records[0].hostname.as_deref(), Some("example.com"));
        assert_eq!(records[0].details["udp_classification"], "quic_candidate");
    }

    #[test]
    fn non_443_long_header_quic_uses_dns_attribution_and_quic_timeout() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-quic-alt")
                .protocol(Protocol::Quic)
                .hostname("alt.example.com")
                .destination_port(4443),
        );
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.44".parse().unwrap(),
            4443,
        );
        let mut dns_cache = DnsCache::default();
        dns_cache.observe(
            "s1",
            "alt.example.com",
            "A",
            vec!["203.0.113.44".parse().unwrap()],
            1_000,
            60_000,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 5);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram_with_dns_cache(
                key.clone(),
                &[0xc0, 0, 0, 1],
                2_000,
                &dns_cache,
            )
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.sent);
        assert_eq!(
            forwarder.flows().get(&key).unwrap().classification,
            UdpClassification::QuicCandidate
        );
        assert_eq!(forwarder.flows().get(&key).unwrap().timeout_ms, 180_000);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::UdpPacketDecision);
        assert_eq!(records[0].rule_id.as_deref(), Some("allow-quic-alt"));
        assert_eq!(records[1].details["classification"], "quiccandidate");
    }

    #[test]
    fn non_443_long_header_quic_respects_quic_disabled_policy() {
        let config = PolicyConfig {
            allow_quic: false,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.44".parse().unwrap(),
            4443,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, &[0xc0, 0, 0, 1], 2_000)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::QuicDisabled));
        assert!(forwarder.egress().sent().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::UdpPacketDecision);
        assert_eq!(record.details["udp_classification"], "quic_candidate");
    }

    #[test]
    fn quic_hostname_policy_without_attribution_denies_before_egress() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-quic-host")
                .protocol(Protocol::Quic)
                .hostname("example.com")
                .destination_port(443),
        );
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, &[0xc0, 0, 0, 1], 2_000)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(
            result.reason,
            Some(DenialReason::HostnameAttributionRequired)
        );
        assert!(forwarder.egress().sent().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::UdpPacketDecision);
        assert_eq!(
            record.reason,
            Some(DenialReason::HostnameAttributionRequired)
        );
    }

    #[test]
    fn quic_candidate_records_lifecycle_and_uses_quic_timeout() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 5);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key.clone(), &[0xc0, 0, 0, 1], 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.sent);
        let flow = forwarder.flows().get(&key).unwrap();
        assert_eq!(flow.classification, UdpClassification::QuicCandidate);
        assert_eq!(flow.timeout_ms, 180_000);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::UdpPacketDecision);
        assert_eq!(records[0].details["udp_classification"], "quic_candidate");
        assert_eq!(records[1].kind, AuditKind::UdpFlowCreated);
        assert_eq!(records[2].kind, AuditKind::QuicCandidateFlowCreated);
    }

    #[test]
    fn flow_lifecycle_backpressure_prevents_unobservable_send() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            12345,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 1);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            InMemoryUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, b"hello", 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::AuditBackpressure));
        assert!(forwarder.egress().sent().is_empty());
        assert!(forwarder.flows().is_empty());
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
    }

    #[derive(Clone, Debug, Default)]
    struct FailingUdpEgress;

    impl UdpEgress for FailingUdpEgress {
        fn send_datagram(
            &mut self,
            _destination: NetworkEndpoint,
            _payload: &[u8],
        ) -> Result<(), UdpEgressError> {
            Err(UdpEgressError::SendFailed)
        }
    }

    #[test]
    fn egress_send_failure_rolls_back_flow_state() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            12345,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder =
            UdpForwarder::new("s1", broker, FailingUdpEgress, UdpTimeoutConfig::default());

        let error = forwarder
            .handle_outbound_datagram(key, b"hello", 1_000)
            .unwrap_err();
        assert_eq!(error, UdpEgressError::SendFailed);
        assert!(forwarder.flows().is_empty());
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.last().unwrap().kind, AuditKind::BrokerError);
        assert_eq!(
            records.last().unwrap().details["error"],
            "udp_egress_send_failed"
        );
    }
}
