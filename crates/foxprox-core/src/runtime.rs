use crate::audit::{AuditError, AuditRecord, BoundedAuditLedger, JsonLineAuditSink};
use crate::types::{AuditKind, Decision, DenialReason, Frontend, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeComponent {
    TunDevice,
    SmoltcpStack,
    DnsListener,
    HttpProxyListener,
    Socks5Listener,
    AuditFanIn,
    ChildProcess,
}

impl RuntimeComponent {
    pub fn as_detail(self) -> &'static str {
        match self {
            Self::TunDevice => "tun_device",
            Self::SmoltcpStack => "smoltcp_stack",
            Self::DnsListener => "dns_listener",
            Self::HttpProxyListener => "http_proxy_listener",
            Self::Socks5Listener => "socks5_listener",
            Self::AuditFanIn => "audit_fan_in",
            Self::ChildProcess => "child_process",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeListenerConfig {
    pub component: RuntimeComponent,
    pub bind_addr: String,
    pub reachable_addr: Option<String>,
}

impl RuntimeListenerConfig {
    pub fn new(component: RuntimeComponent, bind_addr: impl Into<String>) -> Self {
        Self {
            component,
            bind_addr: bind_addr.into(),
            reachable_addr: None,
        }
    }

    pub fn with_reachable_addr(mut self, reachable_addr: impl Into<String>) -> Self {
        self.reachable_addr = Some(reachable_addr.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCleanupAction {
    TunDevice,
    SmoltcpStack,
    DnsListener,
    HttpProxyListener,
    Socks5Listener,
    AuditFanIn,
    SetupControlFd,
    ChildProcess,
}

impl RuntimeCleanupAction {
    pub fn as_detail(self) -> &'static str {
        match self {
            Self::TunDevice => "tun_device",
            Self::SmoltcpStack => "smoltcp_stack",
            Self::DnsListener => "dns_listener",
            Self::HttpProxyListener => "http_proxy_listener",
            Self::Socks5Listener => "socks5_listener",
            Self::AuditFanIn => "audit_fan_in",
            Self::SetupControlFd => "setup_control_fd",
            Self::ChildProcess => "child_process",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCleanupReport {
    pub attempted: Vec<RuntimeCleanupAction>,
    pub failed: Vec<RuntimeCleanupAction>,
}

impl RuntimeCleanupReport {
    pub fn all_succeeded(actions: Vec<RuntimeCleanupAction>) -> Self {
        Self {
            attempted: actions,
            failed: Vec::new(),
        }
    }

    pub fn with_failures(
        attempted: Vec<RuntimeCleanupAction>,
        failed: Vec<RuntimeCleanupAction>,
    ) -> Self {
        Self { attempted, failed }
    }

    fn status_detail(&self) -> &'static str {
        if !self.failed.is_empty() {
            "failed"
        } else if self.attempted.is_empty() {
            "not_attempted"
        } else {
            "complete"
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTaskStatus {
    Completed,
    Cancelled,
    Failed,
    JoinFailed,
    TimedOut,
}

impl RuntimeTaskStatus {
    fn as_detail(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::JoinFailed => "join_failed",
            Self::TimedOut => "timed_out",
        }
    }

    fn is_failed(self) -> bool {
        matches!(self, Self::Failed | Self::JoinFailed | Self::TimedOut)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTaskExpectation {
    pub component: RuntimeComponent,
    pub task_name: String,
}

impl RuntimeTaskExpectation {
    pub fn new(component: RuntimeComponent, task_name: impl Into<String>) -> Self {
        Self {
            component,
            task_name: task_name.into(),
        }
    }

    fn as_detail(&self) -> String {
        format!("{}:{}", self.component.as_detail(), self.task_name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTaskOutcome {
    pub component: RuntimeComponent,
    pub task_name: String,
    pub status: RuntimeTaskStatus,
}

impl RuntimeTaskOutcome {
    pub fn new(
        component: RuntimeComponent,
        task_name: impl Into<String>,
        status: RuntimeTaskStatus,
    ) -> Self {
        Self {
            component,
            task_name: task_name.into(),
            status,
        }
    }

    fn as_detail(&self) -> String {
        format!(
            "{}:{}:{}",
            self.component.as_detail(),
            self.task_name,
            self.status.as_detail()
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTaskJoinReport {
    pub outcomes: Vec<RuntimeTaskOutcome>,
}

impl RuntimeTaskJoinReport {
    pub fn new(outcomes: Vec<RuntimeTaskOutcome>) -> Self {
        Self { outcomes }
    }

    fn status_detail(
        &self,
        expected_components: &[RuntimeComponent],
        expected_tasks: &[RuntimeTaskExpectation],
    ) -> &'static str {
        if self
            .outcomes
            .iter()
            .any(|outcome| outcome.status.is_failed())
        {
            "failed"
        } else if self.outcomes.is_empty() {
            "not_recorded"
        } else if !self
            .missing_task_details(expected_components, expected_tasks)
            .is_empty()
        {
            "incomplete"
        } else {
            "complete"
        }
    }

    fn has_failures_or_missing(
        &self,
        expected_components: &[RuntimeComponent],
        expected_tasks: &[RuntimeTaskExpectation],
    ) -> bool {
        self.outcomes
            .iter()
            .any(|outcome| outcome.status.is_failed())
            || !self
                .missing_task_details(expected_components, expected_tasks)
                .is_empty()
    }

    fn missing_task_details(
        &self,
        expected_components: &[RuntimeComponent],
        expected_tasks: &[RuntimeTaskExpectation],
    ) -> Vec<String> {
        if !expected_tasks.is_empty() {
            let mut missing: Vec<String> = expected_tasks
                .iter()
                .filter(|expected| {
                    !self.outcomes.iter().any(|outcome| {
                        outcome.component == expected.component
                            && outcome.task_name == expected.task_name
                    })
                })
                .map(RuntimeTaskExpectation::as_detail)
                .collect();
            missing.extend(
                expected_components
                    .iter()
                    .copied()
                    .filter(|component| {
                        !expected_tasks
                            .iter()
                            .any(|expected| expected.component == *component)
                    })
                    .map(|component| component.as_detail().to_string()),
            );
            return missing;
        }
        expected_components
            .iter()
            .copied()
            .filter(|component| {
                !self
                    .outcomes
                    .iter()
                    .any(|outcome| outcome.component == *component)
            })
            .map(|component| component.as_detail().to_string())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTaskHandle {
    pub id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeTaskSupervisorError {
    DuplicateTaskName {
        component: RuntimeComponent,
        task_name: String,
    },
    UnknownTask {
        task_id: u64,
    },
    DuplicateOutcome {
        task_id: u64,
    },
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeTaskSupervisor {
    next_task_id: u64,
    tasks: Vec<(RuntimeTaskHandle, RuntimeTaskExpectation)>,
    outcomes: Vec<(RuntimeTaskHandle, RuntimeTaskOutcome)>,
}

impl RuntimeTaskSupervisor {
    pub fn new() -> Self {
        Self {
            next_task_id: 1,
            tasks: Vec::new(),
            outcomes: Vec::new(),
        }
    }

    pub fn register_task(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
    ) -> Result<RuntimeTaskHandle, RuntimeTaskSupervisorError> {
        let task_name = task_name.into();
        if self
            .tasks
            .iter()
            .any(|(_, expected)| expected.component == component && expected.task_name == task_name)
        {
            return Err(RuntimeTaskSupervisorError::DuplicateTaskName {
                component,
                task_name,
            });
        }
        let handle = RuntimeTaskHandle {
            id: self.next_task_id,
        };
        self.next_task_id += 1;
        self.tasks
            .push((handle, RuntimeTaskExpectation::new(component, task_name)));
        Ok(handle)
    }

    pub fn record_outcome(
        &mut self,
        handle: RuntimeTaskHandle,
        status: RuntimeTaskStatus,
    ) -> Result<(), RuntimeTaskSupervisorError> {
        let Some((_, expected)) = self.tasks.iter().find(|(task, _)| *task == handle) else {
            return Err(RuntimeTaskSupervisorError::UnknownTask { task_id: handle.id });
        };
        if self.outcomes.iter().any(|(task, _)| *task == handle) {
            return Err(RuntimeTaskSupervisorError::DuplicateOutcome { task_id: handle.id });
        }
        self.outcomes.push((
            handle,
            RuntimeTaskOutcome::new(expected.component, expected.task_name.clone(), status),
        ));
        Ok(())
    }

    pub fn expectations(&self) -> Vec<RuntimeTaskExpectation> {
        self.tasks
            .iter()
            .map(|(_, expectation)| expectation.clone())
            .collect()
    }

    pub fn join_report(&self) -> RuntimeTaskJoinReport {
        RuntimeTaskJoinReport::new(
            self.outcomes
                .iter()
                .map(|(_, outcome)| outcome.clone())
                .collect(),
        )
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeChildExit {
    pub process_id: Option<u32>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

impl RuntimeChildExit {
    pub fn exited(process_id: u32, exit_code: i32) -> Self {
        Self {
            process_id: Some(process_id),
            exit_code: Some(exit_code),
            signal: None,
        }
    }

    pub fn signaled(process_id: u32, signal: i32) -> Self {
        Self {
            process_id: Some(process_id),
            exit_code: None,
            signal: Some(signal),
        }
    }

    fn status_detail(&self) -> &'static str {
        if self.signal.is_some() {
            "signaled"
        } else if self.process_id.is_some() && self.exit_code == Some(0) {
            "clean"
        } else if self.process_id.is_some() && self.exit_code.is_some() {
            "failed"
        } else {
            "unknown"
        }
    }

    fn is_failed(&self) -> bool {
        self.process_id.is_none() || self.signal.is_some() || self.exit_code != Some(0)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeLifecycleError {
    AuditBackpressure { attempted_kind: AuditKind },
    NotStarted,
    AlreadyRunning,
    AlreadyExited,
    DuplicateTaskExpectation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeAuditFanInError {
    AuditBackpressure {
        source: String,
        attempted_kind: AuditKind,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAuditIngestReport {
    pub source: String,
    pub accepted_records: usize,
    pub last_source_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAuditDrainReport {
    pub drained_records: usize,
    pub last_drained_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeAuditDrainError {
    SinkWriteFailed {
        attempted_sequence: u64,
        failure_record: Box<AuditRecord>,
        failure_sink_error_record: Option<Box<AuditRecord>>,
    },
}

#[derive(Clone, Debug)]
pub struct RuntimeAuditFanIn {
    sandbox_id: String,
    audit: BoundedAuditLedger,
    last_source_sequences: BTreeMap<String, u64>,
    last_drained_sequence: u64,
}

impl RuntimeAuditFanIn {
    pub fn new(sandbox_id: impl Into<String>, audit_capacity: usize) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            audit: BoundedAuditLedger::new(audit_capacity),
            last_source_sequences: BTreeMap::new(),
            last_drained_sequence: 0,
        }
    }

    pub fn ingest<'a>(
        &mut self,
        source: impl Into<String>,
        records: impl IntoIterator<Item = &'a AuditRecord>,
    ) -> Result<RuntimeAuditIngestReport, RuntimeAuditFanInError> {
        let source = source.into();
        let mut last_sequence = *self.last_source_sequences.get(&source).unwrap_or(&0);
        let mut accepted_records = 0usize;
        for record in records {
            if record.sequence <= last_sequence {
                continue;
            }
            match self.audit.append(record.clone()) {
                Ok(_) => {
                    last_sequence = record.sequence;
                    accepted_records += 1;
                }
                Err(AuditError::BufferFull { attempted_kind, .. }) => {
                    self.audit.append_lossy(
                        AuditRecord::new(AuditKind::AuditBackpressure, self.sandbox_id.clone())
                            .with_frontend(Frontend::Core)
                            .with_decision(
                                Decision::FailClosed,
                                Some(DenialReason::AuditBackpressure),
                            )
                            .with_detail("source", source.clone())
                            .with_detail(
                                "attempted_kind",
                                format!("{attempted_kind:?}").to_ascii_lowercase(),
                            )
                            .with_detail("source_sequence", record.sequence.to_string()),
                    );
                    self.last_source_sequences
                        .insert(source.clone(), last_sequence);
                    return Err(RuntimeAuditFanInError::AuditBackpressure {
                        source,
                        attempted_kind,
                    });
                }
            }
        }
        self.last_source_sequences
            .insert(source.clone(), last_sequence);
        Ok(RuntimeAuditIngestReport {
            source,
            accepted_records,
            last_source_sequence: last_sequence,
        })
    }

    pub fn drain_to_sink<W: Write>(
        &mut self,
        sink: &mut JsonLineAuditSink<W>,
    ) -> Result<RuntimeAuditDrainReport, RuntimeAuditDrainError> {
        self.drain_to_sink_with_failure_sink(sink, None::<&mut JsonLineAuditSink<Vec<u8>>>)
    }

    pub fn drain_to_sink_with_failure_sink<W: Write, E: Write>(
        &mut self,
        sink: &mut JsonLineAuditSink<W>,
        mut failure_sink: Option<&mut JsonLineAuditSink<E>>,
    ) -> Result<RuntimeAuditDrainReport, RuntimeAuditDrainError> {
        let records: Vec<_> = self
            .audit
            .records()
            .filter(|record| record.sequence > self.last_drained_sequence)
            .cloned()
            .collect();
        let mut drained_records = 0usize;
        for record in records {
            if sink.append(&record).is_err() {
                let failure_record =
                    AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                        .with_frontend(Frontend::Core)
                        .with_decision(Decision::FailClosed, Some(DenialReason::AuditBackpressure))
                        .with_detail("runtime_error", "audit_sink_write_failed")
                        .with_detail("attempted_sequence", record.sequence.to_string())
                        .with_detail(
                            "last_drained_sequence",
                            self.last_drained_sequence.to_string(),
                        );
                let mut failure_sink_error_record = None;
                if let Some(failure_sink) = failure_sink.as_deref_mut() {
                    if failure_sink.append(&failure_record).is_err() {
                        failure_sink_error_record = Some(Box::new(
                            AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                                .with_frontend(Frontend::Core)
                                .with_decision(
                                    Decision::FailClosed,
                                    Some(DenialReason::AuditBackpressure),
                                )
                                .with_detail("runtime_error", "audit_emergency_sink_write_failed")
                                .with_detail("primary_runtime_error", "audit_sink_write_failed")
                                .with_detail("attempted_sequence", record.sequence.to_string())
                                .with_detail(
                                    "last_drained_sequence",
                                    self.last_drained_sequence.to_string(),
                                ),
                        ));
                    }
                }
                return Err(RuntimeAuditDrainError::SinkWriteFailed {
                    attempted_sequence: record.sequence,
                    failure_record: Box::new(failure_record),
                    failure_sink_error_record,
                });
            }
            self.last_drained_sequence = record.sequence;
            drained_records += 1;
        }
        Ok(RuntimeAuditDrainReport {
            drained_records,
            last_drained_sequence: self.last_drained_sequence,
        })
    }

    pub fn audit(&self) -> &BoundedAuditLedger {
        &self.audit
    }

    pub fn last_source_sequence(&self, source: &str) -> u64 {
        *self.last_source_sequences.get(source).unwrap_or(&0)
    }
}

#[derive(Clone, Copy, Debug)]
enum RuntimeLifecycleState {
    NotStarted,
    Running {
        started_at_ms: u64,
    },
    Exited {
        started_at_ms: u64,
        exited_at_ms: u64,
        status: RuntimeExitStatus,
    },
}

impl RuntimeLifecycleState {
    fn as_detail(&self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Running { .. } => "running",
            Self::Exited { .. } => "exited",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeLifecycleHarness {
    sandbox_id: String,
    audit: BoundedAuditLedger,
    components: Vec<RuntimeComponent>,
    expected_tasks: Vec<RuntimeTaskExpectation>,
    state: RuntimeLifecycleState,
}

impl RuntimeLifecycleHarness {
    pub fn new(sandbox_id: impl Into<String>, audit_capacity: usize) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            audit: BoundedAuditLedger::new(audit_capacity),
            components: Vec::new(),
            expected_tasks: Vec::new(),
            state: RuntimeLifecycleState::NotStarted,
        }
    }

    pub fn start(
        &mut self,
        components: Vec<RuntimeComponent>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        self.start_with_task_expectations(components, Vec::new(), now_ms)
    }

    pub fn start_with_task_expectations(
        &mut self,
        components: Vec<RuntimeComponent>,
        expected_tasks: Vec<RuntimeTaskExpectation>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        match self.state {
            RuntimeLifecycleState::NotStarted => {}
            RuntimeLifecycleState::Running { .. } => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::AlreadyRunning,
                    "start",
                    now_ms,
                );
            }
            RuntimeLifecycleState::Exited { .. } => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::AlreadyExited,
                    "start",
                    now_ms,
                );
            }
        }
        if let Some(duplicate) = duplicate_task_expectation(&expected_tasks) {
            let audit = AuditRecord::new_at(
                AuditKind::BrokerError,
                self.sandbox_id.clone(),
                now_ms as u128,
            )
            .with_frontend(Frontend::Core)
            .with_decision(Decision::FailClosed, Some(DenialReason::RuntimeState))
            .with_detail("runtime_error", "duplicate_task_expectation")
            .with_detail("attempted_transition", "start")
            .with_detail("lifecycle_state", self.state.as_detail())
            .with_detail("duplicate_runtime_task", duplicate.as_detail())
            .with_detail("runtime_components", component_list(&components))
            .with_detail("component_count", components.len().to_string());
            self.append_required(audit)?;
            return Err(RuntimeLifecycleError::DuplicateTaskExpectation);
        }
        let audit = AuditRecord::new_at(
            AuditKind::NetworkSessionStart,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_decision(Decision::Allow, None)
        .with_detail("runtime_components", component_list(&components))
        .with_detail("component_count", components.len().to_string())
        .with_detail(
            "expected_runtime_tasks",
            task_expectation_list(&expected_tasks),
        )
        .with_detail(
            "expected_runtime_task_count",
            expected_tasks.len().to_string(),
        );
        self.append_required(audit)?;
        self.components = components;
        self.expected_tasks = expected_tasks;
        self.state = RuntimeLifecycleState::Running {
            started_at_ms: now_ms,
        };
        Ok(())
    }

    pub fn record_listener_config(
        &mut self,
        config: RuntimeListenerConfig,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        match self.state {
            RuntimeLifecycleState::Running { .. } => {}
            RuntimeLifecycleState::NotStarted => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::NotStarted,
                    "configure_listener",
                    now_ms,
                );
            }
            RuntimeLifecycleState::Exited { .. } => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::AlreadyExited,
                    "configure_listener",
                    now_ms,
                );
            }
        }
        let mut audit = AuditRecord::new_at(
            AuditKind::ProxyListenerConfigured,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(frontend_for_component(config.component))
        .with_protocol(protocol_for_component(config.component))
        .with_decision(Decision::Allow, None)
        .with_detail("listener_component", config.component.as_detail())
        .with_detail("bind_addr", config.bind_addr);
        if let Some(reachable_addr) = config.reachable_addr {
            audit = audit.with_detail("reachable_addr", reachable_addr);
        }
        self.append_required(audit)
    }

    pub fn record_child_supervision_error(
        &mut self,
        error: impl Into<String>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        match self.state {
            RuntimeLifecycleState::Running { .. } => {}
            RuntimeLifecycleState::NotStarted => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::NotStarted,
                    "child_supervision_error",
                    now_ms,
                );
            }
            RuntimeLifecycleState::Exited { .. } => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::AlreadyExited,
                    "child_supervision_error",
                    now_ms,
                );
            }
        }
        let audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_decision(Decision::FailClosed, Some(DenialReason::RuntimeState))
        .with_detail("runtime_error", "child_supervision_error")
        .with_detail("child_status", "unknown")
        .with_detail("child_supervision_error", error)
        .with_detail("lifecycle_state", self.state.as_detail())
        .with_detail("runtime_components", component_list(&self.components))
        .with_detail("component_count", self.components.len().to_string());
        self.append_required(audit)
    }

    pub fn exit(
        &mut self,
        status: RuntimeExitStatus,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        self.exit_with_cleanup(status, RuntimeCleanupReport::default(), now_ms)
    }

    pub fn exit_with_cleanup(
        &mut self,
        status: RuntimeExitStatus,
        cleanup: RuntimeCleanupReport,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        self.exit_with_cleanup_and_child(status, cleanup, None, now_ms)
    }

    pub fn exit_with_cleanup_and_child(
        &mut self,
        status: RuntimeExitStatus,
        cleanup: RuntimeCleanupReport,
        child_exit: Option<RuntimeChildExit>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        self.exit_with_cleanup_child_and_tasks(status, cleanup, child_exit, None, now_ms)
    }

    pub fn exit_with_cleanup_child_and_tasks(
        &mut self,
        status: RuntimeExitStatus,
        cleanup: RuntimeCleanupReport,
        child_exit: Option<RuntimeChildExit>,
        task_report: Option<RuntimeTaskJoinReport>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let started_at_ms = match self.state {
            RuntimeLifecycleState::Running { started_at_ms } => started_at_ms,
            RuntimeLifecycleState::NotStarted => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::NotStarted,
                    "exit",
                    now_ms,
                );
            }
            RuntimeLifecycleState::Exited { .. } => {
                return self.reject_invalid_transition(
                    RuntimeLifecycleError::AlreadyExited,
                    "exit",
                    now_ms,
                );
            }
        };
        let missing_child_status =
            self.components.contains(&RuntimeComponent::ChildProcess) && child_exit.is_none();
        let missing_required_task_report = task_report.is_none() && !self.expected_tasks.is_empty();
        let task_report_failure = task_report.as_ref().is_some_and(|report| {
            report.has_failures_or_missing(&self.components, &self.expected_tasks)
        });
        let (decision, reason) = if !cleanup.failed.is_empty() {
            (Decision::FailClosed, Some(DenialReason::SetupFailed))
        } else if missing_child_status
            || child_exit.as_ref().is_some_and(RuntimeChildExit::is_failed)
            || missing_required_task_report
            || task_report_failure
        {
            (Decision::FailClosed, Some(DenialReason::RuntimeState))
        } else {
            match status {
                RuntimeExitStatus::Clean => (Decision::Allow, None),
                RuntimeExitStatus::Failed => {
                    (Decision::FailClosed, Some(DenialReason::SetupFailed))
                }
            }
        };
        let mut audit = AuditRecord::new_at(
            AuditKind::NetworkSessionExit,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_decision(decision, reason)
        .with_duration_ms(now_ms.saturating_sub(started_at_ms))
        .with_detail("runtime_status", status.as_detail())
        .with_detail("runtime_components", component_list(&self.components))
        .with_detail("component_count", self.components.len().to_string())
        .with_detail("cleanup_status", cleanup.status_detail())
        .with_detail("cleanup_actions", cleanup_action_list(&cleanup.attempted))
        .with_detail("cleanup_count", cleanup.attempted.len().to_string())
        .with_detail(
            "failed_cleanup_actions",
            cleanup_action_list(&cleanup.failed),
        )
        .with_detail("failed_cleanup_count", cleanup.failed.len().to_string());
        if let Some(task_report) = task_report {
            audit = append_task_report_details(
                audit,
                &task_report,
                &self.components,
                &self.expected_tasks,
            );
        } else if missing_required_task_report {
            audit = append_task_report_details(
                audit,
                &RuntimeTaskJoinReport::default(),
                &self.components,
                &self.expected_tasks,
            );
        }
        if missing_child_status {
            audit = audit.with_detail("child_status", "unknown");
        }
        if let Some(child_exit) = child_exit {
            audit = audit.with_detail("child_status", child_exit.status_detail());
            if let Some(process_id) = child_exit.process_id {
                audit = audit.with_detail("child_process_id", process_id.to_string());
            }
            if let Some(exit_code) = child_exit.exit_code {
                audit = audit.with_detail("child_exit_code", exit_code.to_string());
            }
            if let Some(signal) = child_exit.signal {
                audit = audit.with_detail("child_signal", signal.to_string());
            }
        }
        self.append_required(audit)?;
        self.state = RuntimeLifecycleState::Exited {
            started_at_ms,
            exited_at_ms: now_ms,
            status,
        };
        Ok(())
    }

    pub fn audit(&self) -> &BoundedAuditLedger {
        &self.audit
    }

    pub fn into_audit(self) -> BoundedAuditLedger {
        self.audit
    }

    fn reject_invalid_transition(
        &mut self,
        error: RuntimeLifecycleError,
        attempted_transition: &'static str,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let mut audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_decision(Decision::FailClosed, Some(DenialReason::RuntimeState))
        .with_detail("runtime_error", runtime_error_detail(error))
        .with_detail("attempted_transition", attempted_transition)
        .with_detail("lifecycle_state", self.state.as_detail())
        .with_detail("runtime_components", component_list(&self.components))
        .with_detail("component_count", self.components.len().to_string());
        if let RuntimeLifecycleState::Exited {
            started_at_ms,
            exited_at_ms,
            status,
        } = self.state
        {
            audit = audit
                .with_duration_ms(exited_at_ms.saturating_sub(started_at_ms))
                .with_detail("runtime_status", status.as_detail());
        }
        self.append_required(audit)?;
        Err(error)
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

fn frontend_for_component(component: RuntimeComponent) -> Frontend {
    match component {
        RuntimeComponent::HttpProxyListener => Frontend::HttpProxy,
        RuntimeComponent::Socks5Listener => Frontend::Socks5Proxy,
        RuntimeComponent::TunDevice => Frontend::Tun,
        RuntimeComponent::SmoltcpStack
        | RuntimeComponent::DnsListener
        | RuntimeComponent::AuditFanIn
        | RuntimeComponent::ChildProcess => Frontend::Core,
    }
}

fn protocol_for_component(component: RuntimeComponent) -> Protocol {
    match component {
        RuntimeComponent::DnsListener => Protocol::Dns,
        RuntimeComponent::HttpProxyListener => Protocol::Http,
        RuntimeComponent::Socks5Listener => Protocol::Socks,
        RuntimeComponent::TunDevice
        | RuntimeComponent::SmoltcpStack
        | RuntimeComponent::AuditFanIn
        | RuntimeComponent::ChildProcess => Protocol::Unsupported,
    }
}

fn runtime_error_detail(error: RuntimeLifecycleError) -> &'static str {
    match error {
        RuntimeLifecycleError::AuditBackpressure { .. } => "audit_backpressure",
        RuntimeLifecycleError::NotStarted => "not_started",
        RuntimeLifecycleError::AlreadyRunning => "already_running",
        RuntimeLifecycleError::AlreadyExited => "already_exited",
        RuntimeLifecycleError::DuplicateTaskExpectation => "duplicate_task_expectation",
    }
}

fn duplicate_task_expectation(
    expectations: &[RuntimeTaskExpectation],
) -> Option<RuntimeTaskExpectation> {
    for (index, expectation) in expectations.iter().enumerate() {
        if expectations.iter().skip(index + 1).any(|other| {
            other.component == expectation.component && other.task_name == expectation.task_name
        }) {
            return Some(expectation.clone());
        }
    }
    None
}

fn cleanup_action_list(actions: &[RuntimeCleanupAction]) -> String {
    actions
        .iter()
        .map(|action| action.as_detail())
        .collect::<Vec<_>>()
        .join(",")
}

fn component_list(components: &[RuntimeComponent]) -> String {
    components
        .iter()
        .map(|component| component.as_detail())
        .collect::<Vec<_>>()
        .join(",")
}

fn append_task_report_details(
    audit: AuditRecord,
    task_report: &RuntimeTaskJoinReport,
    expected_components: &[RuntimeComponent],
    expected_tasks: &[RuntimeTaskExpectation],
) -> AuditRecord {
    let missing_tasks = task_report.missing_task_details(expected_components, expected_tasks);
    audit
        .with_detail(
            "task_join_status",
            task_report.status_detail(expected_components, expected_tasks),
        )
        .with_detail("runtime_tasks", task_outcome_list(&task_report.outcomes))
        .with_detail("runtime_task_count", task_report.outcomes.len().to_string())
        .with_detail(
            "failed_runtime_task_count",
            task_report
                .outcomes
                .iter()
                .filter(|outcome| outcome.status.is_failed())
                .count()
                .to_string(),
        )
        .with_detail("missing_runtime_tasks", string_list(&missing_tasks))
        .with_detail(
            "missing_runtime_task_count",
            missing_tasks.len().to_string(),
        )
}

fn task_expectation_list(expectations: &[RuntimeTaskExpectation]) -> String {
    expectations
        .iter()
        .map(RuntimeTaskExpectation::as_detail)
        .collect::<Vec<_>>()
        .join(",")
}

fn task_outcome_list(outcomes: &[RuntimeTaskOutcome]) -> String {
    outcomes
        .iter()
        .map(RuntimeTaskOutcome::as_detail)
        .collect::<Vec<_>>()
        .join(",")
}

fn string_list(values: &[String]) -> String {
    values.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_audit_fan_in_ingests_sequence_ordered_sources() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 8);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        let mut dns = AuditRecord::new_at(AuditKind::DnsQueryDecision, "s1", 1_010);
        dns.sequence = 2;
        let source_records = vec![start, dns];
        let report = fan_in.ingest("dns", &source_records).unwrap();
        assert_eq!(report.accepted_records, 2);
        assert_eq!(report.last_source_sequence, 2);
        let duplicate = fan_in.ingest("dns", &source_records).unwrap();
        assert_eq!(duplicate.accepted_records, 0);
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(records[1].kind, AuditKind::DnsQueryDecision);
    }

    #[test]
    fn runtime_audit_fan_in_backpressure_preserves_accepted_cursor() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 2);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        let mut dns = AuditRecord::new_at(AuditKind::DnsQueryDecision, "s1", 1_010);
        dns.sequence = 2;
        let mut listener = AuditRecord::new_at(AuditKind::ProxyListenerConfigured, "s1", 1_020);
        listener.sequence = 3;
        let source_records = vec![start, dns, listener];

        let error = fan_in.ingest("runtime", &source_records).unwrap_err();

        assert_eq!(
            error,
            RuntimeAuditFanInError::AuditBackpressure {
                source: "runtime".to_string(),
                attempted_kind: AuditKind::ProxyListenerConfigured,
            }
        );
        assert_eq!(fan_in.last_source_sequence("runtime"), 2);
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::DnsQueryDecision);
        assert_eq!(records[1].kind, AuditKind::AuditBackpressure);
        assert_eq!(records[1].details["source"], "runtime");
        assert_eq!(records[1].details["source_sequence"], "3");
    }

    #[test]
    fn runtime_audit_fan_in_backpressure_is_observable() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 1);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        let mut dns = AuditRecord::new_at(AuditKind::DnsQueryDecision, "s1", 1_010);
        dns.sequence = 2;
        let source_records = vec![start, dns];
        let error = fan_in.ingest("dns", &source_records).unwrap_err();
        assert_eq!(
            error,
            RuntimeAuditFanInError::AuditBackpressure {
                source: "dns".to_string(),
                attempted_kind: AuditKind::DnsQueryDecision,
            }
        );
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].details["source"], "dns");
        assert_eq!(records[0].details["source_sequence"], "2");
    }

    #[test]
    fn runtime_audit_fan_in_drains_to_json_sink_once() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 8);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        let mut exit = AuditRecord::new_at(AuditKind::NetworkSessionExit, "s1", 1_100);
        exit.sequence = 2;
        fan_in.ingest("lifecycle", &[start, exit]).unwrap();

        let mut sink = JsonLineAuditSink::new(Vec::new());
        let report = fan_in.drain_to_sink(&mut sink).unwrap();
        assert_eq!(report.drained_records, 2);
        assert_eq!(report.last_drained_sequence, 2);
        assert_eq!(sink.records_written(), 2);
        let duplicate = fan_in.drain_to_sink(&mut sink).unwrap();
        assert_eq!(duplicate.drained_records, 0);
        assert_eq!(sink.records_written(), 2);
    }

    #[derive(Debug)]
    struct FailingAuditWriter;

    impl std::io::Write for FailingAuditWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("audit sink unavailable"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn runtime_audit_fan_in_sink_failure_is_observable() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 4);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        fan_in.ingest("lifecycle", &[start]).unwrap();

        let mut sink = JsonLineAuditSink::new(FailingAuditWriter);
        let error = fan_in.drain_to_sink(&mut sink).unwrap_err();

        let RuntimeAuditDrainError::SinkWriteFailed {
            attempted_sequence,
            failure_record,
            failure_sink_error_record,
        } = error;
        assert_eq!(attempted_sequence, 1);
        assert!(failure_sink_error_record.is_none());
        assert_eq!(failure_record.kind, AuditKind::BrokerError);
        assert_eq!(failure_record.decision, Some(Decision::FailClosed));
        assert_eq!(failure_record.reason, Some(DenialReason::AuditBackpressure));
        assert_eq!(
            failure_record.details["runtime_error"],
            "audit_sink_write_failed"
        );
        assert_eq!(failure_record.details["attempted_sequence"], "1");
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
    }

    #[test]
    fn runtime_audit_fan_in_writes_sink_failure_to_emergency_sink() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 1);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        fan_in.ingest("lifecycle", &[start]).unwrap();

        let mut primary = JsonLineAuditSink::new(FailingAuditWriter);
        let mut emergency = JsonLineAuditSink::new(Vec::new());
        let error = fan_in
            .drain_to_sink_with_failure_sink(&mut primary, Some(&mut emergency))
            .unwrap_err();

        let RuntimeAuditDrainError::SinkWriteFailed {
            attempted_sequence,
            failure_record,
            failure_sink_error_record,
        } = error;
        assert_eq!(attempted_sequence, 1);
        assert!(failure_sink_error_record.is_none());
        assert_eq!(
            failure_record.details["runtime_error"],
            "audit_sink_write_failed"
        );
        assert_eq!(emergency.records_written(), 1);
        let emergency_output = String::from_utf8(emergency.into_inner()).unwrap();
        let emergency_record: serde_json::Value =
            serde_json::from_str(emergency_output.lines().next().unwrap()).unwrap();
        assert_eq!(emergency_record["kind"], "broker_error");
        assert_eq!(
            emergency_record["details"]["runtime_error"],
            "audit_sink_write_failed"
        );
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
    }

    #[test]
    fn runtime_audit_fan_in_emergency_sink_failure_is_observable() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 1);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        fan_in.ingest("lifecycle", &[start]).unwrap();

        let mut primary = JsonLineAuditSink::new(FailingAuditWriter);
        let mut emergency = JsonLineAuditSink::new(FailingAuditWriter);
        let error = fan_in
            .drain_to_sink_with_failure_sink(&mut primary, Some(&mut emergency))
            .unwrap_err();

        let RuntimeAuditDrainError::SinkWriteFailed {
            attempted_sequence,
            failure_record,
            failure_sink_error_record,
        } = error;
        assert_eq!(attempted_sequence, 1);
        assert_eq!(
            failure_record.details["runtime_error"],
            "audit_sink_write_failed"
        );
        let failure_sink_error_record = failure_sink_error_record.unwrap();
        assert_eq!(failure_sink_error_record.kind, AuditKind::BrokerError);
        assert_eq!(
            failure_sink_error_record.details["runtime_error"],
            "audit_emergency_sink_write_failed"
        );
        assert_eq!(
            failure_sink_error_record.details["primary_runtime_error"],
            "audit_sink_write_failed"
        );
        assert_eq!(failure_sink_error_record.details["attempted_sequence"], "1");
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(fan_in.last_drained_sequence, 0);
    }

    #[test]
    fn runtime_audit_fan_in_sink_failure_preserves_full_undrained_ledger() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 1);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start.sequence = 1;
        fan_in.ingest("lifecycle", &[start]).unwrap();

        let mut sink = JsonLineAuditSink::new(FailingAuditWriter);
        let error = fan_in.drain_to_sink(&mut sink).unwrap_err();

        let RuntimeAuditDrainError::SinkWriteFailed {
            attempted_sequence,
            failure_record,
            failure_sink_error_record,
        } = error;
        assert_eq!(attempted_sequence, 1);
        assert_eq!(failure_record.details["attempted_sequence"], "1");
        assert!(failure_sink_error_record.is_none());
        let records: Vec<_> = fan_in.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(fan_in.last_drained_sequence, 0);
    }

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
    fn runtime_lifecycle_records_listener_configuration() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                ],
                1_000,
            )
            .unwrap();
        runtime
            .record_listener_config(
                RuntimeListenerConfig::new(RuntimeComponent::DnsListener, "127.0.0.1:5300")
                    .with_reachable_addr("10.0.2.3:53"),
                1_001,
            )
            .unwrap();
        runtime
            .record_listener_config(
                RuntimeListenerConfig::new(RuntimeComponent::HttpProxyListener, "127.0.0.1:3128")
                    .with_reachable_addr("10.0.2.2:3128"),
                1_002,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].kind, AuditKind::ProxyListenerConfigured);
        assert_eq!(records[1].frontend, Some(Frontend::Core));
        assert_eq!(records[1].protocol, Some(Protocol::Dns));
        assert_eq!(records[1].details["listener_component"], "dns_listener");
        assert_eq!(records[1].details["bind_addr"], "127.0.0.1:5300");
        assert_eq!(records[1].details["reachable_addr"], "10.0.2.3:53");
        assert_eq!(records[2].kind, AuditKind::ProxyListenerConfigured);
        assert_eq!(records[2].frontend, Some(Frontend::HttpProxy));
        assert_eq!(records[2].protocol, Some(Protocol::Http));
        assert_eq!(
            records[2].details["listener_component"],
            "http_proxy_listener"
        );
    }

    #[test]
    fn runtime_lifecycle_listener_config_backpressure_fails_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 1);
        runtime
            .start(vec![RuntimeComponent::Socks5Listener], 1_000)
            .unwrap();
        let error = runtime
            .record_listener_config(
                RuntimeListenerConfig::new(RuntimeComponent::Socks5Listener, "127.0.0.1:1080"),
                1_001,
            )
            .unwrap_err();
        assert_eq!(
            error,
            RuntimeLifecycleError::AuditBackpressure {
                attempted_kind: AuditKind::ProxyListenerConfigured,
            }
        );
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
        assert_eq!(
            records[0].details["attempted_kind"],
            "proxylistenerconfigured"
        );
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
    fn runtime_lifecycle_exit_before_start_is_audited_and_rejected() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        assert_eq!(
            runtime.exit(RuntimeExitStatus::Clean, 1_000),
            Err(RuntimeLifecycleError::NotStarted)
        );
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[0].details["runtime_error"], "not_started");
        assert_eq!(records[0].details["attempted_transition"], "exit");
        assert_eq!(records[0].details["lifecycle_state"], "not_started");
    }

    #[test]
    fn runtime_lifecycle_duplicate_start_is_audited_without_new_start_record() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::TunDevice], 1_000)
            .unwrap();
        assert_eq!(
            runtime.start(vec![RuntimeComponent::DnsListener], 1_050),
            Err(RuntimeLifecycleError::AlreadyRunning)
        );

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(records[0].details["runtime_components"], "tun_device");
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["runtime_error"], "already_running");
        assert_eq!(records[1].details["attempted_transition"], "start");
        assert_eq!(records[1].details["lifecycle_state"], "running");
    }

    #[test]
    fn runtime_lifecycle_exit_records_cleanup_success() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(
                vec![RuntimeComponent::TunDevice, RuntimeComponent::DnsListener],
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::TunDevice,
                ]),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].details["cleanup_status"], "complete");
        assert_eq!(
            records[1].details["cleanup_actions"],
            "dns_listener,tun_device"
        );
        assert_eq!(records[1].details["cleanup_count"], "2");
        assert_eq!(records[1].details["failed_cleanup_actions"], "");
        assert_eq!(records[1].details["failed_cleanup_count"], "0");
    }

    #[test]
    fn runtime_lifecycle_records_task_join_report() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::SmoltcpStack,
                ],
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::SmoltcpStack,
                ]),
                None,
                Some(RuntimeTaskJoinReport::new(vec![
                    RuntimeTaskOutcome::new(
                        RuntimeComponent::DnsListener,
                        "dns_accept_loop",
                        RuntimeTaskStatus::Completed,
                    ),
                    RuntimeTaskOutcome::new(
                        RuntimeComponent::SmoltcpStack,
                        "stack_poll_loop",
                        RuntimeTaskStatus::Cancelled,
                    ),
                ])),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].details["task_join_status"], "complete");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "dns_listener:dns_accept_loop:completed,smoltcp_stack:stack_poll_loop:cancelled"
        );
        assert_eq!(records[1].details["runtime_task_count"], "2");
        assert_eq!(records[1].details["failed_runtime_task_count"], "0");
        assert_eq!(records[1].details["missing_runtime_tasks"], "");
        assert_eq!(records[1].details["missing_runtime_task_count"], "0");
    }

    #[test]
    fn runtime_lifecycle_missing_task_join_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                ],
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::HttpProxyListener,
                ]),
                None,
                Some(RuntimeTaskJoinReport::new(vec![RuntimeTaskOutcome::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                    RuntimeTaskStatus::Completed,
                )])),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "incomplete");
        assert_eq!(
            records[1].details["missing_runtime_tasks"],
            "http_proxy_listener"
        );
        assert_eq!(records[1].details["missing_runtime_task_count"], "1");
    }

    #[test]
    fn runtime_task_supervisor_derives_expectations_and_join_report() {
        let mut supervisor = RuntimeTaskSupervisor::new();
        let dns = supervisor
            .register_task(RuntimeComponent::DnsListener, "dns_accept_loop")
            .unwrap();
        let http = supervisor
            .register_task(RuntimeComponent::HttpProxyListener, "http_accept_loop")
            .unwrap();
        supervisor
            .record_outcome(dns, RuntimeTaskStatus::Completed)
            .unwrap();

        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                ],
                supervisor.expectations(),
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::HttpProxyListener,
                ]),
                None,
                Some(supervisor.join_report()),
                1_100,
            )
            .unwrap();

        assert_eq!(supervisor.task_count(), 2);
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].details["expected_runtime_task_count"], "2");
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "incomplete");
        assert_eq!(
            records[1].details["missing_runtime_tasks"],
            "http_proxy_listener:http_accept_loop"
        );
        assert_eq!(http.id, 2);
    }

    #[test]
    fn runtime_task_supervisor_rejects_unknown_duplicate_names_and_duplicate_outcomes() {
        let mut supervisor = RuntimeTaskSupervisor::new();
        let dns = supervisor
            .register_task(RuntimeComponent::DnsListener, "dns_accept_loop")
            .unwrap();
        assert_eq!(
            supervisor.register_task(RuntimeComponent::DnsListener, "dns_accept_loop"),
            Err(RuntimeTaskSupervisorError::DuplicateTaskName {
                component: RuntimeComponent::DnsListener,
                task_name: "dns_accept_loop".to_string(),
            })
        );
        supervisor
            .record_outcome(dns, RuntimeTaskStatus::Completed)
            .unwrap();
        assert_eq!(
            supervisor.record_outcome(dns, RuntimeTaskStatus::Failed),
            Err(RuntimeTaskSupervisorError::DuplicateOutcome { task_id: dns.id })
        );
        assert_eq!(
            supervisor.record_outcome(RuntimeTaskHandle { id: 999 }, RuntimeTaskStatus::Failed),
            Err(RuntimeTaskSupervisorError::UnknownTask { task_id: 999 })
        );
    }

    #[test]
    fn runtime_lifecycle_duplicate_task_expectations_are_rejected() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        let error = runtime
            .start_with_task_expectations(
                vec![RuntimeComponent::DnsListener],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                ],
                1_000,
            )
            .unwrap_err();

        assert_eq!(error, RuntimeLifecycleError::DuplicateTaskExpectation);
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].reason, Some(DenialReason::RuntimeState));
        assert_eq!(
            records[0].details["runtime_error"],
            "duplicate_task_expectation"
        );
        assert_eq!(records[0].details["attempted_transition"], "start");
        assert_eq!(
            records[0].details["duplicate_runtime_task"],
            "dns_listener:dns_accept_loop"
        );
    }

    #[test]
    fn runtime_lifecycle_expected_tasks_without_report_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start_with_task_expectations(
                vec![RuntimeComponent::DnsListener],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                )],
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::DnsListener]),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "not_recorded");
        assert_eq!(
            records[1].details["missing_runtime_tasks"],
            "dns_listener:dns_accept_loop"
        );
        assert_eq!(records[1].details["missing_runtime_task_count"], "1");
    }

    #[test]
    fn runtime_lifecycle_incomplete_expectation_list_keeps_component_coverage() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                ],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                )],
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::HttpProxyListener,
                ]),
                None,
                Some(RuntimeTaskJoinReport::new(vec![RuntimeTaskOutcome::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                    RuntimeTaskStatus::Completed,
                )])),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "incomplete");
        assert_eq!(
            records[1].details["missing_runtime_tasks"],
            "http_proxy_listener"
        );
        assert_eq!(records[1].details["missing_runtime_task_count"], "1");
    }

    #[test]
    fn runtime_lifecycle_missing_expected_task_name_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start_with_task_expectations(
                vec![RuntimeComponent::DnsListener],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_upstream_loop"),
                ],
                1_000,
            )
            .unwrap();
        runtime
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::DnsListener]),
                None,
                Some(RuntimeTaskJoinReport::new(vec![RuntimeTaskOutcome::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                    RuntimeTaskStatus::Completed,
                )])),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].details["expected_runtime_task_count"], "2");
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "incomplete");
        assert_eq!(
            records[1].details["missing_runtime_tasks"],
            "dns_listener:dns_upstream_loop"
        );
        assert_eq!(records[1].details["missing_runtime_task_count"], "1");
    }

    #[test]
    fn runtime_lifecycle_task_join_failure_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::TunDevice], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::TunDevice]),
                None,
                Some(RuntimeTaskJoinReport::new(vec![RuntimeTaskOutcome::new(
                    RuntimeComponent::TunDevice,
                    "tun_read_loop",
                    RuntimeTaskStatus::JoinFailed,
                )])),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "failed");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "tun_device:tun_read_loop:join_failed"
        );
        assert_eq!(records[1].details["failed_runtime_task_count"], "1");
    }

    #[test]
    fn runtime_lifecycle_child_supervision_error_is_audited() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::ChildProcess], 1_000)
            .unwrap();
        runtime
            .record_child_supervision_error("spawn_failed", 1_010)
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(
            records[1].details["runtime_error"],
            "child_supervision_error"
        );
        assert_eq!(records[1].details["child_status"], "unknown");
        assert_eq!(
            records[1].details["child_supervision_error"],
            "spawn_failed"
        );
        assert_eq!(records[1].details["lifecycle_state"], "running");
    }

    #[test]
    fn runtime_lifecycle_records_clean_child_exit() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::HttpProxyListener], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::HttpProxyListener]),
                Some(RuntimeChildExit::exited(42, 0)),
                1_250,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].details["child_status"], "clean");
        assert_eq!(records[1].details["child_process_id"], "42");
        assert_eq!(records[1].details["child_exit_code"], "0");
        assert!(!records[1].details.contains_key("child_signal"));
    }

    #[test]
    fn runtime_lifecycle_child_failure_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::Socks5Listener], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::Socks5Listener]),
                Some(RuntimeChildExit::signaled(43, 15)),
                1_250,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["runtime_status"], "clean");
        assert_eq!(records[1].details["child_status"], "signaled");
        assert_eq!(records[1].details["child_process_id"], "43");
        assert_eq!(records[1].details["child_signal"], "15");
    }

    #[test]
    fn runtime_lifecycle_child_process_without_status_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::ChildProcess], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::ChildProcess]),
                1_250,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["child_status"], "unknown");
        assert!(!records[1].details.contains_key("child_process_id"));
        assert!(!records[1].details.contains_key("child_exit_code"));
        assert!(!records[1].details.contains_key("child_signal"));
    }

    #[test]
    fn runtime_lifecycle_missing_child_process_id_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::Socks5Listener], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::Socks5Listener]),
                Some(RuntimeChildExit {
                    process_id: None,
                    exit_code: Some(0),
                    signal: None,
                }),
                1_250,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["child_status"], "unknown");
        assert_eq!(records[1].details["child_exit_code"], "0");
        assert!(!records[1].details.contains_key("child_process_id"));
    }

    #[test]
    fn runtime_lifecycle_unknown_child_status_is_fail_closed() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::Socks5Listener], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::Socks5Listener]),
                Some(RuntimeChildExit::default()),
                1_250,
            )
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["child_status"], "unknown");
        assert!(!records[1].details.contains_key("child_process_id"));
        assert!(!records[1].details.contains_key("child_exit_code"));
        assert!(!records[1].details.contains_key("child_signal"));
    }

    #[test]
    fn runtime_lifecycle_cleanup_failure_is_fail_closed_and_terminal() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 4);
        runtime
            .start(vec![RuntimeComponent::TunDevice], 1_000)
            .unwrap();
        runtime
            .exit_with_cleanup(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::with_failures(
                    vec![
                        RuntimeCleanupAction::TunDevice,
                        RuntimeCleanupAction::SetupControlFd,
                    ],
                    vec![RuntimeCleanupAction::TunDevice],
                ),
                1_100,
            )
            .unwrap();
        assert_eq!(
            runtime.exit(RuntimeExitStatus::Clean, 1_200),
            Err(RuntimeLifecycleError::AlreadyExited)
        );

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::SetupFailed));
        assert_eq!(records[1].details["runtime_status"], "clean");
        assert_eq!(records[1].details["cleanup_status"], "failed");
        assert_eq!(
            records[1].details["cleanup_actions"],
            "tun_device,setup_control_fd"
        );
        assert_eq!(records[1].details["failed_cleanup_actions"], "tun_device");
        assert_eq!(records[2].kind, AuditKind::BrokerError);
        assert_eq!(records[2].details["runtime_error"], "already_exited");
    }

    #[test]
    fn runtime_lifecycle_exit_is_terminal() {
        let mut runtime = RuntimeLifecycleHarness::new("s1", 6);
        runtime
            .start(vec![RuntimeComponent::TunDevice], 1_000)
            .unwrap();
        runtime.exit(RuntimeExitStatus::Clean, 1_100).unwrap();
        assert_eq!(
            runtime.exit(RuntimeExitStatus::Failed, 1_200),
            Err(RuntimeLifecycleError::AlreadyExited)
        );
        assert_eq!(
            runtime.start(vec![RuntimeComponent::DnsListener], 1_300),
            Err(RuntimeLifecycleError::AlreadyExited)
        );

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[2].kind, AuditKind::BrokerError);
        assert_eq!(records[2].details["runtime_error"], "already_exited");
        assert_eq!(records[2].details["attempted_transition"], "exit");
        assert_eq!(records[2].details["lifecycle_state"], "exited");
        assert_eq!(records[2].details["runtime_status"], "clean");
        assert_eq!(records[2].duration_ms, Some(100));
        assert_eq!(records[3].kind, AuditKind::BrokerError);
        assert_eq!(records[3].details["runtime_error"], "already_exited");
        assert_eq!(records[3].details["attempted_transition"], "start");
        assert_eq!(records[3].details["lifecycle_state"], "exited");
    }
}
