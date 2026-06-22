use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

/// Network protocol names used in normalized policy and audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Icmp,
    Http,
    HttpsConnect,
    Tls,
    Socks,
    Quic,
    Unsupported,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Dns => "dns",
            Self::Icmp => "icmp",
            Self::Http => "http",
            Self::HttpsConnect => "https_connect",
            Self::Tls => "tls",
            Self::Socks => "socks",
            Self::Quic => "quic",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Frontend through which a normalized event entered the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Frontend {
    Tun,
    HttpProxy,
    Socks5,
    Harness,
}

impl Frontend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::HttpProxy => "http_proxy",
            Self::Socks5 => "socks5",
            Self::Harness => "harness",
        }
    }
}

/// Decision visible in audit output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    DenyDrop,
    DenyReset,
    DenyIcmpUnreachable,
    FailClosed,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::DenyDrop => "deny_drop",
            Self::DenyReset => "deny_reset",
            Self::DenyIcmpUnreachable => "deny_icmp_unreachable",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Hostname attribution source for transparent traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttributionSource {
    ExplicitProxy,
    HttpHost,
    TlsSni,
    DnsCache,
    IpOnly,
    None,
}

impl AttributionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitProxy => "explicit_proxy",
            Self::HttpHost => "http_host",
            Self::TlsSni => "tls_sni",
            Self::DnsCache => "dns_cache",
            Self::IpOnly => "ip_only",
            Self::None => "none",
        }
    }
}

/// Confidence attached to hostname attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttributionConfidence {
    High,
    Medium,
    Low,
    None,
}

impl AttributionConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::None => "none",
        }
    }
}

/// Normalized event kinds emitted by frontends and packet/proxy parsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    SandboxStarted,
    BrokerStarted,
    TunConfigured,
    ProxyListenerConfigured,
    DnsQuery,
    TcpConnectAttempt,
    TcpFlowClosed,
    UdpFlowCreated,
    UdpFlowExpired,
    HttpRequest,
    HttpsConnect,
    TlsClientHello,
    SocksConnect,
    QuicCandidateFlow,
    IcmpMessage,
    UnsupportedNetworkEvent,
    PolicyReload,
    BrokerError,
    SandboxExited,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SandboxStarted => "sandbox_started",
            Self::BrokerStarted => "broker_started",
            Self::TunConfigured => "tun_configured",
            Self::ProxyListenerConfigured => "proxy_listener_configured",
            Self::DnsQuery => "dns_query",
            Self::TcpConnectAttempt => "tcp_connect_attempt",
            Self::TcpFlowClosed => "tcp_flow_closed",
            Self::UdpFlowCreated => "udp_flow_created",
            Self::UdpFlowExpired => "udp_flow_expired",
            Self::HttpRequest => "http_request",
            Self::HttpsConnect => "https_connect",
            Self::TlsClientHello => "tls_client_hello",
            Self::SocksConnect => "socks_connect",
            Self::QuicCandidateFlow => "quic_candidate_flow",
            Self::IcmpMessage => "icmp_message",
            Self::UnsupportedNetworkEvent => "unsupported_network_event",
            Self::PolicyReload => "policy_reload",
            Self::BrokerError => "broker_error",
            Self::SandboxExited => "sandbox_exited",
        }
    }
}

/// One structured audit record. The timestamp is caller-provided so tests can be deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub timestamp: String,
    pub sandbox_id: String,
    pub kind: EventKind,
    pub frontend: Frontend,
    pub protocol: Option<Protocol>,
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub hostname: Option<String>,
    pub attribution_source: AttributionSource,
    pub attribution_confidence: AttributionConfidence,
    pub decision: Decision,
    pub reason: String,
    pub rule_id: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub metadata: BTreeMap<String, String>,
}

impl AuditRecord {
    pub fn new(
        kind: EventKind,
        sandbox_id: impl Into<String>,
        decision: Decision,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: "1970-01-01T00:00:00Z".to_string(),
            sandbox_id: sandbox_id.into(),
            kind,
            frontend: Frontend::Harness,
            protocol: None,
            source: None,
            destination: None,
            hostname: None,
            attribution_source: AttributionSource::None,
            attribution_confidence: AttributionConfidence::None,
            decision,
            reason: reason.into(),
            rule_id: None,
            bytes_in: 0,
            bytes_out: 0,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_frontend(mut self, frontend: Frontend) -> Self {
        self.frontend = frontend;
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn with_addresses(
        mut self,
        source: Option<SocketAddr>,
        destination: Option<SocketAddr>,
    ) -> Self {
        self.source = source;
        self.destination = destination;
        self
    }

    pub fn with_hostname(
        mut self,
        hostname: Option<String>,
        source: AttributionSource,
        confidence: AttributionConfidence,
    ) -> Self {
        self.hostname = hostname;
        self.attribution_source = source;
        self.attribution_confidence = confidence;
        self
    }

    pub fn with_rule(mut self, rule_id: Option<String>) -> Self {
        self.rule_id = rule_id;
        self
    }

    pub fn with_bytes(mut self, bytes_in: u64, bytes_out: u64) -> Self {
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn to_json_line(&self) -> String {
        let mut fields = Vec::new();
        fields.push(json_field("timestamp", &self.timestamp));
        fields.push(json_field("sandbox_id", &self.sandbox_id));
        fields.push(json_field("event", self.kind.as_str()));
        fields.push(json_field("frontend", self.frontend.as_str()));
        if let Some(protocol) = self.protocol {
            fields.push(json_field("protocol", protocol.as_str()));
        }
        if let Some(source) = self.source {
            fields.push(json_field("source", &source.to_string()));
        }
        if let Some(destination) = self.destination {
            fields.push(json_field("destination", &destination.to_string()));
        }
        if let Some(hostname) = &self.hostname {
            fields.push(json_field("hostname", hostname));
        }
        fields.push(json_field(
            "attribution_source",
            self.attribution_source.as_str(),
        ));
        fields.push(json_field(
            "attribution_confidence",
            self.attribution_confidence.as_str(),
        ));
        fields.push(json_field("decision", self.decision.as_str()));
        fields.push(json_field("reason", &self.reason));
        if let Some(rule_id) = &self.rule_id {
            fields.push(json_field("rule_id", rule_id));
        }
        fields.push(format!("\"bytes_in\":{}", self.bytes_in));
        fields.push(format!("\"bytes_out\":{}", self.bytes_out));
        if !self.metadata.is_empty() {
            let metadata = self
                .metadata
                .iter()
                .map(|(key, value)| json_field(key, value))
                .collect::<Vec<_>>()
                .join(",");
            fields.push(format!("\"metadata\":{{{metadata}}}"));
        }
        format!("{{{}}}", fields.join(","))
    }
}

/// Bounded audit queue used by harnesses to model backpressure.
///
/// Forwarding paths should treat a full audit buffer as fail-closed or apply an explicit overflow
/// policy; this type makes that condition deterministic in tests instead of relying on unbounded
/// memory growth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedAuditBuffer {
    capacity: usize,
    records: VecDeque<AuditRecord>,
}

impl BoundedAuditBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            records: VecDeque::new(),
        }
    }

    pub fn push(&mut self, record: AuditRecord) -> Result<(), AuditRecord> {
        if self.records.len() >= self.capacity {
            return Err(record);
        }
        self.records.push_back(record);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<AuditRecord> {
        self.records.pop_front()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_full(&self) -> bool {
        self.records.len() >= self.capacity
    }
}

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_field(key: &str, value: &str) -> String {
    format!("\"{}\":\"{}\"", json_escape(key), json_escape(value))
}

pub fn socket(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_json_is_stable_and_escaped() {
        let record = AuditRecord::new(
            EventKind::BrokerError,
            "sandbox\"1",
            Decision::FailClosed,
            "bad\npacket",
        )
        .with_protocol(Protocol::Unsupported)
        .with_metadata("detail", "x\\y");
        let line = record.to_json_line();
        assert!(line.contains("\"sandbox_id\":\"sandbox\\\"1\""));
        assert!(line.contains("\"reason\":\"bad\\npacket\""));
        assert!(line.contains("\"detail\":\"x\\\\y\""));
    }

    #[test]
    fn bounded_audit_buffer_reports_backpressure() {
        let mut buffer = BoundedAuditBuffer::new(1);
        let first = AuditRecord::new(EventKind::BrokerStarted, "lab", Decision::Allow, "started");
        let second = AuditRecord::new(
            EventKind::BrokerError,
            "lab",
            Decision::FailClosed,
            "audit buffer full",
        );
        assert!(buffer.push(first).is_ok());
        assert!(buffer.is_full());
        let overflow = buffer.push(second).unwrap_err();
        assert_eq!(overflow.reason, "audit buffer full");
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.pop().unwrap().kind, EventKind::BrokerStarted);
        assert!(!buffer.is_full());
    }
}
