use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::flow::FlowKey;
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::types::{
    AuditKind, ByteCounts, Decision, DenialReason, Frontend, NetworkEndpoint, Protocol,
};
use serde::{Deserialize, Serialize};

pub trait TcpEgress {
    fn connect_and_exchange(
        &mut self,
        destination: NetworkEndpoint,
        from_sandbox: &[u8],
    ) -> Result<Vec<u8>, TcpEgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpEgressError {
    ConnectFailed,
    BridgeFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpForwardResult {
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub opened_egress: bool,
    pub byte_counts: ByteCounts,
}

#[derive(Clone, Debug)]
pub struct TcpForwarder<E> {
    sandbox_id: String,
    broker: BrokerCore,
    egress: E,
}

impl<E: TcpEgress> TcpForwarder<E> {
    pub fn new(sandbox_id: impl Into<String>, broker: BrokerCore, egress: E) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            broker,
            egress,
        }
    }

    pub fn connect_and_bridge(
        &mut self,
        key: FlowKey,
        from_sandbox: &[u8],
        opened_at_ms: u64,
        closed_at_ms: u64,
    ) -> Result<TcpForwardResult, TcpEgressError> {
        let request = self.request_for_key(&key);
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false, ByteCounts::ZERO));
        }

        let to_sandbox = self
            .egress
            .connect_and_exchange(key.destination(), from_sandbox)?;
        let byte_counts = ByteCounts {
            from_sandbox: from_sandbox.len() as u64,
            to_sandbox: to_sandbox.len() as u64,
        };
        let close_audit = AuditRecord::new_at(
            AuditKind::TcpFlowClosed,
            self.sandbox_id.clone(),
            closed_at_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Tcp)
        .with_source(key.source())
        .with_destination(key.destination())
        .with_byte_counts(byte_counts.clone())
        .with_duration_ms(closed_at_ms.saturating_sub(opened_at_ms));
        if let Err(decision) = self.broker.append_audit_for(&request, close_audit) {
            return Ok(result_from_decision(decision, true, byte_counts));
        }

        Ok(TcpForwardResult {
            decision: Decision::Allow,
            reason: None,
            opened_egress: true,
            byte_counts,
        })
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (BrokerCore, E) {
        (self.broker, self.egress)
    }

    fn request_for_key(&self, key: &FlowKey) -> PolicyRequest {
        let mut request = PolicyRequest::tcp_connect(
            self.sandbox_id.clone(),
            Frontend::Tun,
            key.source(),
            key.destination(),
        );
        request.protocol = Protocol::Tcp;
        request
    }
}

fn result_from_decision(
    decision: PolicyDecision,
    opened_egress: bool,
    byte_counts: ByteCounts,
) -> TcpForwardResult {
    TcpForwardResult {
        decision: decision.decision,
        reason: decision.reason,
        opened_egress,
        byte_counts,
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryTcpEgress {
    scripted_reply: Vec<u8>,
    opened: Vec<NetworkEndpoint>,
    sent_from_sandbox: Vec<Vec<u8>>,
}

impl InMemoryTcpEgress {
    pub fn with_scripted_reply(reply: impl Into<Vec<u8>>) -> Self {
        Self {
            scripted_reply: reply.into(),
            opened: Vec::new(),
            sent_from_sandbox: Vec::new(),
        }
    }

    pub fn opened(&self) -> &[NetworkEndpoint] {
        &self.opened
    }

    pub fn sent_from_sandbox(&self) -> &[Vec<u8>] {
        &self.sent_from_sandbox
    }
}

impl TcpEgress for InMemoryTcpEgress {
    fn connect_and_exchange(
        &mut self,
        destination: NetworkEndpoint,
        from_sandbox: &[u8],
    ) -> Result<Vec<u8>, TcpEgressError> {
        self.opened.push(destination);
        self.sent_from_sandbox.push(from_sandbox.to_vec());
        Ok(self.scripted_reply.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Cidr, PolicyConfig, PolicyEngine, PolicyRule};
    use pretty_assertions::assert_eq;

    #[test]
    fn allowed_tcp_connect_opens_egress_bridges_bytes_and_logs_close() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-web")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("203.0.113.0".parse().unwrap(), 24))
                .destination_port(80),
        );
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
        );

        let result = forwarder
            .connect_and_bridge(key, b"GET / HTTP/1.1\r\n\r\n", 1_000, 1_250)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.opened_egress);
        assert_eq!(result.byte_counts.from_sandbox, 18);
        assert_eq!(result.byte_counts.to_sandbox, 19);
        assert_eq!(forwarder.egress().opened().len(), 1);
        assert_eq!(forwarder.egress().sent_from_sandbox().len(), 1);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::TcpConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[1].kind, AuditKind::TcpFlowClosed);
        assert_eq!(records[1].duration_ms, Some(250));
        assert_eq!(records[1].byte_counts.as_ref().unwrap().from_sandbox, 18);
        assert_eq!(records[1].byte_counts.as_ref().unwrap().to_sandbox, 19);
    }

    #[test]
    fn denied_tcp_connect_does_not_open_egress() {
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(Vec::new()),
        );

        let result = forwarder
            .connect_and_bridge(key, b"GET / HTTP/1.1\r\n\r\n", 1_000, 1_250)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::DefaultDeny));
        assert!(!result.opened_egress);
        assert!(forwarder.egress().opened().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::TcpConnectDecision);
        assert_eq!(record.reason, Some(DenialReason::DefaultDeny));
    }

    #[test]
    fn close_audit_backpressure_is_visible() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 1);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(b"ok".to_vec()),
        );

        let result = forwarder
            .connect_and_bridge(key, b"hi", 1_000, 1_001)
            .unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::AuditBackpressure));
        assert!(result.opened_egress);
        assert_eq!(result.byte_counts.from_sandbox, 2);
        assert_eq!(result.byte_counts.to_sandbox, 2);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
    }
}
