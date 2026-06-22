//! Structured audit event schema.

use crate::event::{
    Attribution, Frontend, Hostname, HttpMethod, Origin, Protocol, SandboxId, TransportEndpoint,
};
use crate::policy::Decision;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Type of broker event recorded by audit output.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AuditEventKind {
    /// Network session started.
    SessionStarted,
    /// Broker runtime started.
    BrokerStarted,
    /// TUN device configured for a session.
    TunConfigured,
    /// Proxy listener configured for a session.
    ProxyListenerConfigured,
    /// HTTP request was evaluated.
    HttpRequest,
    /// HTTPS CONNECT request was evaluated.
    HttpsConnect,
    /// Transparent plaintext HTTP request was evaluated.
    TransparentHttpRequest,
    /// TLS ClientHello SNI was observed.
    TlsClientHello,
    /// SNI and DNS attribution mismatch was denied.
    SniDnsMismatchDenied,
    /// Hidden-SNI/ECH-like case was denied.
    HiddenSniDenied,
    /// SOCKS CONNECT request was evaluated.
    SocksConnect,
    /// DNS query was evaluated.
    DnsQuery,
    /// TCP connect attempt was evaluated.
    TcpConnect,
    /// TCP flow closed.
    TcpFlowClosed,
    /// UDP flow was created.
    UdpFlowCreated,
    /// UDP packet was denied.
    UdpPacketDenied,
    /// UDP flow expired.
    UdpFlowExpired,
    /// QUIC candidate flow was created.
    QuicCandidateFlowCreated,
    /// ICMP message was evaluated.
    IcmpMessage,
    /// Unsupported packet or request was denied.
    UnsupportedDenied,
    /// Policy was reloaded.
    PolicyReload,
    /// Broker error occurred.
    BrokerError,
    /// Network session exited.
    SessionExited,
}

/// Structured audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Timestamp when the event was produced.
    pub timestamp: SystemTime,
    /// Sandbox/session identifier.
    pub sandbox_id: Option<SandboxId>,
    /// Frontend that produced the event.
    pub frontend: Frontend,
    /// Audit event kind.
    pub kind: AuditEventKind,
    /// Semantic protocol, when applicable.
    pub protocol: Option<Protocol>,
    /// Source transport endpoint, when applicable.
    pub source: Option<TransportEndpoint>,
    /// Destination transport endpoint, when an IP address is known.
    pub destination: Option<TransportEndpoint>,
    /// Destination port, when a host authority is known but no IP has been resolved yet.
    pub destination_port: Option<u16>,
    /// Hostname associated with the event, when available.
    pub hostname: Option<Hostname>,
    /// Hostname attribution metadata, when available.
    pub attribution: Option<Attribution>,
    /// HTTP origin metadata, when available.
    pub origin: Option<Origin>,
    /// HTTP method metadata, when available.
    pub http_method: Option<HttpMethod>,
    /// HTTP path and query metadata, when available.
    pub path_and_query: Option<String>,
    /// Policy decision, when the event records a policy evaluation.
    pub decision: Option<Decision>,
    /// DNS query type, when applicable.
    pub dns_query_type: Option<String>,
    /// DNS response code, when applicable.
    pub dns_rcode: Option<u8>,
    /// DNS answer addresses observed by the broker.
    pub dns_answers: Vec<IpAddr>,
    /// Bytes read from the sandbox side.
    pub bytes_from_sandbox: u64,
    /// Bytes written back to the sandbox side.
    pub bytes_to_sandbox: u64,
    /// Flow duration, when applicable.
    pub flow_duration: Option<Duration>,
    /// Human-readable detail for errors or setup messages.
    pub detail: Option<String>,
}

impl AuditEvent {
    /// Creates a minimal audit event with the current system timestamp.
    pub fn new(frontend: Frontend, kind: AuditEventKind) -> Self {
        Self {
            timestamp: SystemTime::now(),
            sandbox_id: None,
            frontend,
            kind,
            protocol: None,
            source: None,
            destination: None,
            destination_port: None,
            hostname: None,
            attribution: None,
            origin: None,
            http_method: None,
            path_and_query: None,
            decision: None,
            dns_query_type: None,
            dns_rcode: None,
            dns_answers: Vec::new(),
            bytes_from_sandbox: 0,
            bytes_to_sandbox: 0,
            flow_duration: None,
            detail: None,
        }
    }

    /// Returns a copy with sandbox identifier attached.
    pub fn with_sandbox_id(mut self, sandbox_id: SandboxId) -> Self {
        self.sandbox_id = Some(sandbox_id);
        self
    }

    /// Returns a copy with a policy decision attached.
    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Returns a copy with DNS metadata attached.
    pub fn with_dns_metadata(
        mut self,
        query_type: impl Into<String>,
        rcode: Option<u8>,
        answers: Vec<IpAddr>,
    ) -> Self {
        self.dns_query_type = Some(query_type.into());
        self.dns_rcode = rcode;
        self.dns_answers = answers;
        self
    }

    /// Returns a copy with structured HTTP metadata attached.
    pub fn with_http_metadata(
        mut self,
        origin: Origin,
        method: HttpMethod,
        path_and_query: impl Into<String>,
    ) -> Self {
        self.origin = Some(origin);
        self.http_method = Some(method);
        self.path_and_query = Some(path_and_query.into());
        self
    }

    /// Returns a copy with source and destination endpoints attached.
    pub const fn with_endpoints(
        mut self,
        source: Option<TransportEndpoint>,
        destination: Option<TransportEndpoint>,
    ) -> Self {
        self.source = source;
        self.destination = destination;
        self.destination_port = match destination {
            Some(endpoint) => Some(endpoint.port),
            None => None,
        };
        self
    }
}

/// Bounded in-memory audit event queue.
///
/// This type encodes audit backpressure without tying `foxprox-core` to an
/// async runtime or concrete sink. Runtime code should use `try_push` and treat
/// `AuditBackpressure` as a visible blocker or fail-closed signal rather than
/// allocating an unbounded queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditBuffer {
    capacity: usize,
    queue: VecDeque<AuditEvent>,
    dropped_events: u64,
}

impl AuditBuffer {
    /// Creates an empty bounded audit buffer.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            dropped_events: 0,
        }
    }

    /// Attempts to enqueue an audit event without exceeding capacity.
    pub fn try_push(&mut self, event: AuditEvent) -> Result<(), AuditBackpressure> {
        if self.capacity == 0 {
            self.dropped_events += 1;
            return Err(AuditBackpressure::DisabledCapacity);
        }
        if self.queue.len() >= self.capacity {
            self.dropped_events += 1;
            return Err(AuditBackpressure::Full {
                capacity: self.capacity,
            });
        }
        self.queue.push_back(event);
        Ok(())
    }

    /// Removes and returns the oldest queued audit event.
    pub fn pop_front(&mut self) -> Option<AuditEvent> {
        self.queue.pop_front()
    }

    /// Returns the number of queued audit events.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true when no events are queued.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns the configured maximum number of queued events.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of events rejected due to backpressure.
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }
}

/// Serializes one audit event as a dependency-free JSON line.
pub fn audit_event_json_line(event: &AuditEvent) -> String {
    let timestamp = event
        .timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut fields = vec![
        json_field("timestamp_secs", &timestamp.as_secs().to_string()),
        json_field("timestamp_nanos", &timestamp.subsec_nanos().to_string()),
        json_string_field("frontend", &format!("{:?}", event.frontend)),
        json_string_field("kind", &format!("{:?}", event.kind)),
    ];
    if let Some(sandbox_id) = &event.sandbox_id {
        fields.push(json_string_field("sandbox_id", sandbox_id.as_str()));
    }
    if let Some(protocol) = &event.protocol {
        fields.push(json_string_field("protocol", &format!("{:?}", protocol)));
    }
    if let Some(source) = event.source {
        fields.push(json_string_field(
            "source",
            &format!("{}:{}", source.ip, source.port),
        ));
    }
    if let Some(destination) = event.destination {
        fields.push(json_string_field(
            "destination",
            &format!("{}:{}", destination.ip, destination.port),
        ));
    }
    if let Some(port) = event.destination_port {
        fields.push(json_field("destination_port", &port.to_string()));
    }
    if let Some(hostname) = &event.hostname {
        fields.push(json_string_field("hostname", hostname.as_str()));
    }
    if let Some(attribution) = &event.attribution {
        fields.push(json_string_field(
            "attribution",
            &format!("{:?}", attribution),
        ));
    }
    if let Some(origin) = &event.origin {
        fields.push(json_string_field("origin", &format!("{:?}", origin)));
    }
    if let Some(method) = &event.http_method {
        fields.push(json_string_field("http_method", method.as_str()));
    }
    if let Some(path) = &event.path_and_query {
        fields.push(json_string_field("path_and_query", path));
    }
    if let Some(decision) = &event.decision {
        fields.push(json_string_field("decision", &format!("{:?}", decision)));
    }
    if let Some(query_type) = &event.dns_query_type {
        fields.push(json_string_field("dns_query_type", query_type));
    }
    if let Some(rcode) = event.dns_rcode {
        fields.push(json_field("dns_rcode", &rcode.to_string()));
    }
    if !event.dns_answers.is_empty() {
        let answers = event
            .dns_answers
            .iter()
            .map(|answer| json_string(&answer.to_string()))
            .collect::<Vec<_>>()
            .join(",");
        fields.push(format!("\"dns_answers\":[{answers}]"));
    }
    if event.bytes_from_sandbox != 0 {
        fields.push(json_field(
            "bytes_from_sandbox",
            &event.bytes_from_sandbox.to_string(),
        ));
    }
    if event.bytes_to_sandbox != 0 {
        fields.push(json_field(
            "bytes_to_sandbox",
            &event.bytes_to_sandbox.to_string(),
        ));
    }
    if let Some(duration) = event.flow_duration {
        fields.push(json_field(
            "flow_duration_ms",
            &duration.as_millis().to_string(),
        ));
    }
    if let Some(detail) = &event.detail {
        fields.push(json_string_field("detail", detail));
    }
    format!("{{{}}}", fields.join(","))
}

/// Drains queued audit events to a JSON-lines writer.
pub fn drain_audit_buffer_to_json_lines<W: Write>(
    buffer: &mut AuditBuffer,
    writer: &mut W,
) -> io::Result<usize> {
    let mut drained = 0;
    while let Some(event) = buffer.queue.front() {
        writeln!(writer, "{}", audit_event_json_line(event))?;
        let _ = buffer.queue.pop_front();
        drained += 1;
    }
    Ok(drained)
}

fn json_field(name: &str, value: &str) -> String {
    format!("\"{name}\":{value}")
}

fn json_string_field(name: &str, value: &str) -> String {
    format!("\"{name}\":{}", json_string(value))
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

/// Audit queue backpressure result.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AuditBackpressure {
    /// The queue capacity is zero, so no event can be stored.
    DisabledCapacity,
    /// The queue is full.
    Full {
        /// Configured queue capacity.
        capacity: usize,
    },
}

/// Platform-independent audit sink configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub enum AuditSinkConfig {
    /// Emit JSON lines to standard output.
    #[default]
    StdoutJson,
    /// Emit JSON lines to standard error.
    StderrJson,
    /// Emit JSON lines to a file path.
    FileJsonLines {
        /// Filesystem path for the audit log.
        path: String,
    },
    /// Disable audit output. Useful only for tests; production profiles should audit.
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DecisionAction;

    fn tcp_audit_event() -> AuditEvent {
        AuditEvent::new(Frontend::Tun, AuditEventKind::TcpConnect)
    }

    #[test]
    fn audit_event_builder_attaches_decision_and_endpoints() {
        let source = TransportEndpoint::new("10.0.0.2".parse().unwrap(), 40_000);
        let destination = TransportEndpoint::new("93.184.216.34".parse().unwrap(), 80);
        let event = AuditEvent::new(Frontend::Tun, AuditEventKind::TcpConnect)
            .with_endpoints(Some(source), Some(destination))
            .with_decision(crate::policy::Decision::default_deny(
                DecisionAction::DenyReset,
            ));

        assert_eq!(event.source, Some(source));
        assert_eq!(event.destination, Some(destination));
        assert_eq!(
            event.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::DenyReset)
        );
    }

    #[test]
    fn audit_event_builder_attaches_dns_metadata() {
        let answer = "93.184.216.34".parse().unwrap();
        let event = AuditEvent::new(Frontend::Tun, AuditEventKind::DnsQuery).with_dns_metadata(
            "A",
            Some(0),
            vec![answer],
        );

        assert_eq!(event.dns_query_type.as_deref(), Some("A"));
        assert_eq!(event.dns_rcode, Some(0));
        assert_eq!(event.dns_answers, vec![answer]);
    }

    #[test]
    fn audit_buffer_preserves_fifo_order() {
        let mut buffer = AuditBuffer::new(2);
        buffer.try_push(tcp_audit_event()).unwrap();
        buffer
            .try_push(AuditEvent::new(
                Frontend::Tun,
                AuditEventKind::TcpFlowClosed,
            ))
            .unwrap();

        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.pop_front().unwrap().kind, AuditEventKind::TcpConnect);
        assert_eq!(
            buffer.pop_front().unwrap().kind,
            AuditEventKind::TcpFlowClosed
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn audit_buffer_reports_backpressure_when_full() {
        let mut buffer = AuditBuffer::new(1);
        buffer.try_push(tcp_audit_event()).unwrap();
        let result = buffer.try_push(AuditEvent::new(
            Frontend::Tun,
            AuditEventKind::UdpFlowCreated,
        ));

        assert_eq!(result, Err(AuditBackpressure::Full { capacity: 1 }));
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.dropped_events(), 1);
    }

    #[test]
    fn audit_buffer_drains_json_lines() {
        let mut buffer = AuditBuffer::new(2);
        let mut event = AuditEvent::new(Frontend::Tun, AuditEventKind::DnsQuery)
            .with_sandbox_id(SandboxId::new("alpha").unwrap());
        event.hostname = Some(Hostname::parse("example.com").unwrap());
        event.detail = Some("quoted \"detail\"".to_string());
        buffer.try_push(event).unwrap();
        let mut output = Vec::new();

        let drained = drain_audit_buffer_to_json_lines(&mut buffer, &mut output).unwrap();
        let line = String::from_utf8(output).unwrap();

        assert_eq!(drained, 1);
        assert!(buffer.is_empty());
        assert!(line.contains("\"kind\":\"DnsQuery\""));
        assert!(line.contains("\"sandbox_id\":\"alpha\""));
        assert!(line.contains("\\\"detail\\\""));
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "sink failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn audit_drain_keeps_event_queued_when_sink_write_fails() {
        let mut buffer = AuditBuffer::new(1);
        buffer.try_push(tcp_audit_event()).unwrap();
        let mut writer = FailingWriter;

        let error = drain_audit_buffer_to_json_lines(&mut buffer, &mut writer).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.pop_front().unwrap().kind, AuditEventKind::TcpConnect);
    }

    #[test]
    fn audit_buffer_rejects_zero_capacity() {
        let mut buffer = AuditBuffer::new(0);
        assert_eq!(buffer.capacity(), 0);
        assert_eq!(
            buffer.try_push(tcp_audit_event()),
            Err(AuditBackpressure::DisabledCapacity)
        );
        assert_eq!(buffer.dropped_events(), 1);
        assert!(buffer.is_empty());
    }
}
