use crate::audit::{AuditError, AuditSink};
use crate::event::NormalizedEvent;
use crate::policy::PolicyEngine;
use crate::types::{Decision, DecisionAction, DecisionReason};

#[derive(Debug)]
pub struct VerificationKernel<S> {
    policy: PolicyEngine,
    audit_sink: S,
}

impl<S> VerificationKernel<S> {
    pub fn new(policy: PolicyEngine, audit_sink: S) -> Self {
        Self { policy, audit_sink }
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn audit_sink(&self) -> &S {
        &self.audit_sink
    }

    pub fn into_parts(self) -> (PolicyEngine, S) {
        (self.policy, self.audit_sink)
    }
}

impl<S: AuditSink> VerificationKernel<S> {
    pub fn decide_and_audit(
        &mut self,
        event: &NormalizedEvent,
        timestamp_millis: u128,
    ) -> Decision {
        let decision = self.policy.evaluate(&event.to_policy_input());
        let audit_event = event
            .to_audit_event(timestamp_millis)
            .with_decision(decision.clone());
        match self.audit_sink.emit(audit_event) {
            Ok(()) => decision,
            Err(AuditError::Backpressure { .. }) => Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::AuditBackpressure,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::VecAuditSink;
    use crate::event::NormalizedEvent;
    use crate::policy::{PolicyConfig, PolicyRule, RuleSet};
    use crate::types::{DecisionAction, Endpoint, FrontendKind, Protocol, SandboxId};
    use std::net::{IpAddr, Ipv4Addr};

    fn tcp_event() -> NormalizedEvent {
        NormalizedEvent::TcpConnectAttempt {
            sandbox_id: SandboxId::new("kernel").unwrap(),
            frontend: FrontendKind::Tun,
            source: Some(Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000)),
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            hostname: None,
            sni_status: crate::types::SniStatus::Missing,
            sni_dns_mismatch: false,
        }
    }

    #[test]
    fn decision_is_written_to_audit_history() {
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-tcp");
        rule.protocol = Some(Protocol::Tcp);
        rules.push(rule);
        let policy = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        });
        let mut kernel = VerificationKernel::new(policy, VecAuditSink::bounded(4));
        let decision = kernel.decide_and_audit(&tcp_event(), 10);
        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0]
                .decision
                .as_ref()
                .unwrap()
                .action,
            DecisionAction::Allow
        );
    }

    #[test]
    fn audit_backpressure_fails_closed() {
        let policy = PolicyEngine::new(PolicyConfig {
            default_action: DecisionAction::Allow,
            ..PolicyConfig::default()
        });
        let mut kernel = VerificationKernel::new(policy, VecAuditSink::bounded(0));
        let decision = kernel.decide_and_audit(&tcp_event(), 10);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, DecisionReason::AuditBackpressure);
    }
}
