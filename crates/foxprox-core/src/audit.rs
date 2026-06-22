use crate::types::{
    AttributionConfidence, Decision, Endpoint, FrontendKind, Hostname, Protocol, SandboxId,
};
use std::collections::VecDeque;
use std::io::Write;
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
    TcpFlowOpened,
    TcpFlowClosed,
    TcpFlowError,
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

    pub fn with_flow_duration(mut self, duration: Duration) -> Self {
        self.flow_duration = Some(duration);
        self
    }
}

pub trait AuditSink {
    fn emit(&mut self, event: AuditEvent) -> Result<(), AuditError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    Backpressure { capacity: usize },
    WriteFailed,
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

#[derive(Debug)]
pub struct LineAuditSink<W> {
    writer: W,
}

impl<W> LineAuditSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> AuditSink for LineAuditSink<W> {
    fn emit(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        let line = format_audit_line(&event);
        self.writer
            .write_all(line.as_bytes())
            .and_then(|_| self.writer.write_all(b"\n"))
            .map_err(|_| AuditError::WriteFailed)
    }
}

pub fn format_audit_line(event: &AuditEvent) -> String {
    let mut fields = vec![
        ("ts", event.timestamp_millis.to_string()),
        ("kind", format!("{:?}", event.kind)),
        ("sandbox", event.sandbox_id.to_string()),
        ("frontend", format!("{:?}", event.frontend)),
        ("bytes_in", event.bytes_in.to_string()),
        ("bytes_out", event.bytes_out.to_string()),
    ];
    if let Some(protocol) = event.protocol {
        fields.push(("protocol", format!("{:?}", protocol)));
    }
    if let Some(source) = &event.source {
        fields.push(("src", format!("{}:{}", source.ip, source.port)));
    }
    if let Some(destination) = &event.destination {
        fields.push(("dst", format!("{}:{}", destination.ip, destination.port)));
    }
    if let Some(hostname) = &event.hostname {
        fields.push(("host", hostname.to_string()));
    }
    if let Some(confidence) = event.hostname_confidence {
        fields.push(("host_confidence", format!("{:?}", confidence)));
    }
    if let Some(decision) = &event.decision {
        fields.push(("decision", format!("{:?}", decision.action)));
        fields.push(("decision_reason", format!("{:?}", decision.reason)));
    }
    if let Some(rule_id) = &event.rule_id {
        fields.push(("rule", rule_id.clone()));
    }
    if let Some(reason) = &event.reason {
        fields.push(("reason", reason.clone()));
    }
    if let Some(duration) = event.flow_duration {
        fields.push(("flow_duration_ms", duration.as_millis().to_string()));
    }
    fields
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, escape_value(&value)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn escape_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            ' ' | '\\' | '=' => ['\\', ch].into_iter().collect::<Vec<_>>(),
            _ => [ch].into_iter().collect(),
        })
        .collect()
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

    #[test]
    fn line_audit_sink_writes_structured_appendable_line() {
        let sandbox = SandboxId::new("s").unwrap();
        let mut sink = LineAuditSink::new(Vec::new());
        sink.emit(
            AuditEvent::new(7, AuditEventKind::TcpConnect, sandbox, FrontendKind::Tun)
                .with_protocol(Protocol::Tcp)
                .with_decision(Decision::allow(Some("rule-1".to_string()))),
        )
        .unwrap();
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.contains("ts=7"));
        assert!(output.contains("kind=TcpConnect"));
        assert!(output.contains("decision=Allow"));
        assert!(output.contains("rule=rule-1"));
        assert!(output.ends_with('\n'));
    }
}
