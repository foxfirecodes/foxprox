use crate::broker::BrokerCore;
use crate::flow::{FlowKey, UdpFlowManager, UdpTimeoutConfig};
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::types::{Decision, DenialReason, Frontend, NetworkEndpoint, Protocol};
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
        }
    }

    pub fn handle_outbound_datagram(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<UdpForwardResult, UdpEgressError> {
        let request = self.request_for_key(&key);
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false));
        }

        let previous_flows = self.flows.clone();
        let flow_records =
            self.flows
                .observe_outbound_datagram(key.clone(), payload.len() as u64, now_ms);
        for record in flow_records {
            if let Err(decision) = self.broker.append_audit_for(&request, record) {
                self.flows = previous_flows;
                return Ok(result_from_decision(decision, false));
            }
        }

        if let Err(error) = self.egress.send_datagram(key.destination(), payload) {
            self.flows = previous_flows;
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

    pub fn into_parts(self) -> (BrokerCore, UdpFlowManager, E) {
        (self.broker, self.flows, self.egress)
    }

    fn request_for_key(&self, key: &FlowKey) -> PolicyRequest {
        let protocol = match key.destination_port {
            53 => Protocol::Dns,
            443 => Protocol::Quic,
            _ => Protocol::Udp,
        };
        let mut request = PolicyRequest::new(self.sandbox_id.clone(), Frontend::Tun, protocol)
            .with_destination(key.destination());
        request.source = key.source();
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
        assert_eq!(records[0].kind, AuditKind::QuicCandidateFlowCreated);
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
    }
}
