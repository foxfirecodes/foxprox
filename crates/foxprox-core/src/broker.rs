use crate::audit::{AuditError, AuditRecord, BoundedAuditLedger};
use crate::policy::{PolicyDecision, PolicyEngine, PolicyRequest};
use crate::types::{AuditKind, Decision, DenialReason, Frontend};

/// Platform-independent broker core that couples policy evaluation with audit
/// emission. Runtime frontends can use this before opening host egress so audit
/// backpressure is treated as a correctness failure instead of an unbounded
/// queueing problem.
#[derive(Clone, Debug)]
pub struct BrokerCore {
    policy: PolicyEngine,
    audit: BoundedAuditLedger,
}

impl BrokerCore {
    pub fn new(policy: PolicyEngine, audit_capacity: usize) -> Self {
        Self {
            policy,
            audit: BoundedAuditLedger::new(audit_capacity),
        }
    }

    pub fn evaluate(&mut self, request: &PolicyRequest) -> PolicyDecision {
        let (decision, audit) = self.policy.decide_with_audit(request);
        match self.audit.append(audit) {
            Ok(_) => decision,
            Err(error) => self.fail_closed_for_audit_backpressure(request, error),
        }
    }

    pub fn audit(&self) -> &BoundedAuditLedger {
        &self.audit
    }

    pub fn into_audit(self) -> BoundedAuditLedger {
        self.audit
    }

    fn fail_closed_for_audit_backpressure(
        &mut self,
        request: &PolicyRequest,
        error: AuditError,
    ) -> PolicyDecision {
        let attempted_kind = match error {
            AuditError::BufferFull { attempted_kind, .. } => attempted_kind,
        };
        let record = AuditRecord::new(
            AuditKind::AuditBackpressure,
            request.sandbox.session_id.clone(),
        )
        .with_frontend(Frontend::Core)
        .with_decision(Decision::FailClosed, Some(DenialReason::AuditBackpressure))
        .with_detail(
            "attempted_kind",
            format!("{attempted_kind:?}").to_ascii_lowercase(),
        );
        self.audit.append_lossy(record);
        PolicyDecision {
            decision: Decision::FailClosed,
            reason: Some(DenialReason::AuditBackpressure),
            rule_id: None,
            audit_kind: AuditKind::AuditBackpressure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Cidr, PolicyConfig, PolicyRule};
    use crate::types::{NetworkEndpoint, Protocol};
    use pretty_assertions::assert_eq;

    #[test]
    fn broker_core_appends_policy_audit_before_allowing() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-doc-net")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("203.0.113.0".parse().unwrap(), 24))
                .destination_port(443),
        );
        let mut broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            NetworkEndpoint::socket("10.0.2.15".parse().unwrap(), 50000),
            NetworkEndpoint::socket("203.0.113.42".parse().unwrap(), 443),
        );

        let decision = broker.evaluate(&request);
        assert_eq!(decision.decision, Decision::Allow);
        let records: Vec<_> = broker.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::TcpConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[0].rule_id.as_deref(), Some("allow-doc-net"));
    }

    #[test]
    fn broker_core_fails_closed_when_audit_is_backpressured() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let mut broker = BrokerCore::new(PolicyEngine::new(config), 1);
        let request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            NetworkEndpoint::socket("10.0.2.15".parse().unwrap(), 50000),
            NetworkEndpoint::socket("203.0.113.42".parse().unwrap(), 443),
        );

        assert_eq!(broker.evaluate(&request).decision, Decision::Allow);
        let decision = broker.evaluate(&request);
        assert_eq!(decision.decision, Decision::FailClosed);
        assert_eq!(decision.reason, Some(DenialReason::AuditBackpressure));
        let records: Vec<_> = broker.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
        assert_eq!(records[0].reason, Some(DenialReason::AuditBackpressure));
    }
}
