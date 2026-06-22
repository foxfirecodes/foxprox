use crate::audit::{AuditError, AuditRecord, BoundedAuditLedger};
use crate::types::{AuditKind, Decision, DenialReason, Frontend};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeComponent {
    TunDevice,
    SmoltcpStack,
    DnsListener,
    HttpProxyListener,
    Socks5Listener,
}

impl RuntimeComponent {
    pub fn as_detail(self) -> &'static str {
        match self {
            Self::TunDevice => "tun_device",
            Self::SmoltcpStack => "smoltcp_stack",
            Self::DnsListener => "dns_listener",
            Self::HttpProxyListener => "http_proxy_listener",
            Self::Socks5Listener => "socks5_listener",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeExitStatus {
    Clean,
    Failed,
}

impl RuntimeExitStatus {
    fn as_detail(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeLifecycleError {
    AuditBackpressure { attempted_kind: AuditKind },
    NotStarted,
}

#[derive(Clone, Debug)]
pub struct RuntimeLifecycleHarness {
    sandbox_id: String,
    audit: BoundedAuditLedger,
    components: Vec<RuntimeComponent>,
    started_at_ms: Option<u64>,
}

impl RuntimeLifecycleHarness {
    pub fn new(sandbox_id: impl Into<String>, audit_capacity: usize) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            audit: BoundedAuditLedger::new(audit_capacity),
            components: Vec::new(),
            started_at_ms: None,
        }
    }

    pub fn start(
        &mut self,
        components: Vec<RuntimeComponent>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let audit = AuditRecord::new_at(
            AuditKind::NetworkSessionStart,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_decision(Decision::Allow, None)
        .with_detail("runtime_components", component_list(&components))
        .with_detail("component_count", components.len().to_string());
        self.append_required(audit)?;
        self.components = components;
        self.started_at_ms = Some(now_ms);
        Ok(())
    }

    pub fn exit(
        &mut self,
        status: RuntimeExitStatus,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let started_at_ms = self
            .started_at_ms
            .ok_or(RuntimeLifecycleError::NotStarted)?;
        let (decision, reason) = match status {
            RuntimeExitStatus::Clean => (Decision::Allow, None),
            RuntimeExitStatus::Failed => (Decision::FailClosed, Some(DenialReason::SetupFailed)),
        };
        let audit = AuditRecord::new_at(
            AuditKind::NetworkSessionExit,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_decision(decision, reason)
        .with_duration_ms(now_ms.saturating_sub(started_at_ms))
        .with_detail("runtime_status", status.as_detail())
        .with_detail("runtime_components", component_list(&self.components))
        .with_detail("component_count", self.components.len().to_string());
        self.append_required(audit)
    }

    pub fn audit(&self) -> &BoundedAuditLedger {
        &self.audit
    }

    pub fn into_audit(self) -> BoundedAuditLedger {
        self.audit
    }

    fn append_required(&mut self, audit: AuditRecord) -> Result<(), RuntimeLifecycleError> {
        match self.audit.append(audit) {
            Ok(_) => Ok(()),
            Err(AuditError::BufferFull { attempted_kind, .. }) => {
                self.audit.append_lossy(
                    AuditRecord::new(AuditKind::AuditBackpressure, self.sandbox_id.clone())
                        .with_frontend(Frontend::Core)
                        .with_decision(Decision::FailClosed, Some(DenialReason::AuditBackpressure))
                        .with_detail(
                            "attempted_kind",
                            format!("{attempted_kind:?}").to_ascii_lowercase(),
                        ),
                );
                Err(RuntimeLifecycleError::AuditBackpressure { attempted_kind })
            }
        }
    }
}

fn component_list(components: &[RuntimeComponent]) -> String {
    components
        .iter()
        .map(|component| component.as_detail())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_lifecycle_records_start_and_clean_exit() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(
                vec![
                    RuntimeComponent::TunDevice,
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                    RuntimeComponent::Socks5Listener,
                ],
                1_000,
            )
            .unwrap();
        runtime.exit(RuntimeExitStatus::Clean, 1_250).unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(
            records[0].details["runtime_components"],
            "tun_device,dns_listener,http_proxy_listener,socks5_listener"
        );
        assert_eq!(records[0].details["component_count"], "4");
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].duration_ms, Some(250));
        assert_eq!(records[1].details["runtime_status"], "clean");
    }

    #[test]
    fn runtime_lifecycle_exit_backpressure_fails_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 1);
        runtime
            .start(vec![RuntimeComponent::TunDevice], 1_000)
            .unwrap();
        let error = runtime.exit(RuntimeExitStatus::Failed, 1_010).unwrap_err();
        assert_eq!(
            error,
            RuntimeLifecycleError::AuditBackpressure {
                attempted_kind: AuditKind::NetworkSessionExit,
            }
        );
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].details["attempted_kind"], "networksessionexit");
    }

    #[test]
    fn runtime_lifecycle_exit_before_start_is_rejected_without_audit() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        assert_eq!(
            runtime.exit(RuntimeExitStatus::Clean, 1_000),
            Err(RuntimeLifecycleError::NotStarted)
        );
        assert!(runtime.audit().is_empty());
    }
}
