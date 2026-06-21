use crate::types::{
    AttributionConfidence, Decision, Endpoint, FrontendKind, Hostname, Protocol, SandboxId,
};
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuditEventKind {
    NetworkSessionStart,
    BrokerStart,
    TunConfigured,
    ProxyListenerConfigured,
    HttpRequest,
    HttpsConnect,
    TransparentHttpRequest,
    TlsClientHelloObserved,
    SniDnsMismatchDenied,
    HiddenSniDenied,
    SocksConnect,
    DnsQuery,
    TcpConnect,
    TcpFlowClosed,
    UdpFlowCreated,
    UdpPacketDenied,
    UdpFlowExpired,
    QuicCandidateFlowCreated,
    IcmpMessage,
    UnsupportedNetworkEvent,
    PolicyReload,
    BrokerError,
    NetworkSessionExit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp_millis: u128,
    pub kind: AuditEventKind,
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub protocol: Option<Protocol>,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub hostname: Option<Hostname>,
    pub hostname_confidence: Option<AttributionConfidence>,
    pub decision: Option<Decision>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub flow_duration: Option<Duration>,
}

impl AuditEvent {
    pub fn new(
        timestamp_millis: u128,
        kind: AuditEventKind,
        sandbox_id: SandboxId,
        frontend: FrontendKind,
    ) -> Self {
        Self {
            timestamp_millis,
            kind,
            sandbox_id,
            frontend,
            protocol: None,
            source: None,
            destination: None,
            hostname: None,
            hostname_confidence: None,
            decision: None,
            rule_id: None,
            reason: None,
            bytes_in: 0,
            bytes_out: 0,
            flow_duration: None,
        }
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn with_endpoints(mut self, source: Endpoint, destination: Endpoint) -> Self {
        self.source = Some(source);
        self.destination = Some(destination);
        self
    }

    pub fn with_hostname(mut self, hostname: Hostname, confidence: AttributionConfidence) -> Self {
        self.hostname = Some(hostname);
        self.hostname_confidence = Some(confidence);
        self
    }

    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.rule_id = decision.rule_id.clone();
        self.decision = Some(decision);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_byte_counts(mut self, bytes_in: u64, bytes_out: u64) -> Self {
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
        self
    }
}

pub trait AuditSink {
    fn emit(&mut self, event: AuditEvent) -> Result<(), AuditError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    Backpressure { capacity: usize },
}

#[derive(Clone, Debug)]
pub struct VecAuditSink {
    capacity: usize,
    events: VecDeque<AuditEvent>,
}

impl VecAuditSink {
    pub fn bounded(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
        }
    }

    pub fn events(&self) -> &VecDeque<AuditEvent> {
        &self.events
    }

    pub fn into_events(self) -> VecDeque<AuditEvent> {
        self.events
    }
}

impl AuditSink for VecAuditSink {
    fn emit(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        if self.events.len() >= self.capacity {
            return Err(AuditError::Backpressure {
                capacity: self.capacity,
            });
        }
        self.events.push_back(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_audit_sink_fails_closed_on_backpressure() {
        let sandbox = SandboxId::new("s").unwrap();
        let mut sink = VecAuditSink::bounded(1);
        sink.emit(AuditEvent::new(
            1,
            AuditEventKind::BrokerStart,
            sandbox.clone(),
            FrontendKind::Tun,
        ))
        .unwrap();
        let err = sink
            .emit(AuditEvent::new(
                2,
                AuditEventKind::BrokerStart,
                sandbox,
                FrontendKind::Tun,
            ))
            .unwrap_err();
        assert_eq!(err, AuditError::Backpressure { capacity: 1 });
    }
}
