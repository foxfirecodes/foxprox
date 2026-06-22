//! Structured audit contract and bounded sinks for normalized foxprox events.
//!
//! Audit records consume normalized events and decisions only. They must not
//! depend on frontend implementation structs, raw packets, Linux fd types, or
//! parser-specific data.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use foxprox_core::{
    ByteCounts, DecisionReason, FrontendKind, Hostname, HostnameAttributionSource,
    HostnameConfidence, HostnameMismatch, HttpMethod, HttpScheme, NormalizedEvent, PolicyDecision,
    Protocol, SandboxId,
};

/// Stable audit event kind vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuditKind {
    NetworkSessionStart,
    BrokerStart,
    TunConfigured,
    ProxyListenerConfigured,
    DnsQuery,
    TcpConnect,
    UdpFlow,
    QuicCandidateFlow,
    HttpRequest,
    HttpsConnect,
    TlsClientHello,
    SocksConnect,
    IcmpMessage,
    UnsupportedNetworkEvent,
    FlowClosed,
    PolicyReload,
    BrokerError,
    NetworkSessionExit,
}

/// Decision value encoded for audit schemas without requiring consumers to parse
/// a debug string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuditDecision {
    Allow,
    DenyDrop,
    DenyReset,
    DenyIcmpUnreachable,
    RequireBrokerDns,
    FailClosed,
}

/// Security-sensitive audit record schema shared by all frontends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub kind: AuditKind,
    pub frontend: FrontendKind,
    pub protocol: Protocol,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub hostname: Option<Hostname>,
    pub hostname_attribution_source: Option<HostnameAttributionSource>,
    pub hostname_confidence: Option<HostnameConfidence>,
    pub http_method: Option<HttpMethod>,
    pub http_scheme: Option<HttpScheme>,
    pub http_path_query: Option<String>,
    pub hostname_mismatch: Option<HostnameMismatch>,
    pub decision: AuditDecision,
    pub rule_id: Option<String>,
    pub reason: Option<DecisionReason>,
    pub byte_counts: Option<ByteCounts>,
    pub flow_duration_millis: Option<u64>,
}

impl AuditRecord {
    pub fn from_event(
        sequence: u64,
        timestamp_millis: u64,
        event: &NormalizedEvent,
        decision: &PolicyDecision,
    ) -> Self {
        let attribution = event.hostname_attribution();
        Self {
            sequence,
            timestamp_millis,
            sandbox_id: event.sandbox_id().clone(),
            kind: audit_kind(event),
            frontend: event.frontend(),
            protocol: event.protocol(),
            source: source_string(event),
            destination: destination_string(event),
            hostname: event.explicit_hostname().cloned(),
            hostname_attribution_source: attribution.map(|value| value.source()),
            hostname_confidence: attribution.map(|value| value.confidence()),
            http_method: http_method(event),
            http_scheme: http_scheme(event),
            http_path_query: http_path_query(event),
            hostname_mismatch: hostname_mismatch(event),
            decision: AuditDecision::from(decision),
            rule_id: rule_id(decision),
            reason: decision.reason().cloned(),
            byte_counts: None,
            flow_duration_millis: None,
        }
    }

    /// Build a flow lifecycle audit record from normalized flow fields. Network
    /// stack adapter objects must be translated before calling this constructor.
    pub fn flow_closed(input: FlowClosedAudit) -> Self {
        Self {
            sequence: input.sequence,
            timestamp_millis: input.timestamp_millis,
            sandbox_id: input.sandbox_id,
            kind: AuditKind::FlowClosed,
            frontend: input.frontend,
            protocol: input.protocol,
            source: Some(input.source.to_string()),
            destination: Some(input.destination.to_string()),
            hostname: None,
            hostname_attribution_source: None,
            hostname_confidence: None,
            http_method: None,
            http_scheme: None,
            http_path_query: None,
            hostname_mismatch: None,
            decision: AuditDecision::Allow,
            rule_id: None,
            reason: Some("flow lifecycle closed".into()),
            byte_counts: Some(input.byte_counts),
            flow_duration_millis: Some(input.duration.as_millis().min(u128::from(u64::MAX)) as u64),
        }
    }

    /// Field names are intentionally stable; tests use this as a schema snapshot
    /// without pulling in a serialization dependency.
    pub fn schema_fields() -> &'static [&'static str] {
        &[
            "sequence",
            "timestamp_millis",
            "sandbox_id",
            "kind",
            "frontend",
            "protocol",
            "source",
            "destination",
            "hostname",
            "hostname_attribution_source",
            "hostname_confidence",
            "http_method",
            "http_scheme",
            "http_path_query",
            "hostname_mismatch",
            "decision",
            "rule_id",
            "reason",
            "byte_counts",
            "flow_duration_millis",
        ]
    }

    /// Serialize this record as one stable JSON line using only normalized audit
    /// schema fields. This avoids frontend-specific log formatting and keeps
    /// audit output reviewable before adding an async/file sink.
    pub fn to_json_line(&self) -> String {
        let fields = vec![
            format!("\"sequence\":{}", self.sequence),
            format!("\"timestamp_millis\":{}", self.timestamp_millis),
            json_field("sandbox_id", self.sandbox_id.as_str()),
            json_field("kind", audit_kind_name(self.kind)),
            json_field("frontend", frontend_name(self.frontend)),
            json_field("protocol", protocol_name(self.protocol)),
            json_optional_string("source", self.source.as_deref()),
            json_optional_string("destination", self.destination.as_deref()),
            json_optional_string("hostname", self.hostname.as_ref().map(Hostname::as_str)),
            json_optional_string(
                "hostname_attribution_source",
                self.hostname_attribution_source.map(hostname_source_name),
            ),
            json_optional_string(
                "hostname_confidence",
                self.hostname_confidence.map(hostname_confidence_name),
            ),
            json_optional_string(
                "http_method",
                self.http_method.as_ref().map(http_method_name),
            ),
            json_optional_string("http_scheme", self.http_scheme.map(http_scheme_name)),
            json_optional_string("http_path_query", self.http_path_query.as_deref()),
            json_optional_string(
                "hostname_mismatch",
                self.hostname_mismatch.map(mismatch_name),
            ),
            json_field("decision", audit_decision_name(self.decision)),
            json_optional_string("rule_id", self.rule_id.as_deref()),
            json_optional_string("reason", self.reason.as_ref().map(DecisionReason::as_str)),
            json_byte_counts("byte_counts", self.byte_counts),
            json_optional_u64("flow_duration_millis", self.flow_duration_millis),
        ];
        format!("{{{}}}\n", fields.join(","))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowClosedAudit {
    pub sequence: u64,
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub protocol: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub byte_counts: ByteCounts,
    pub duration: Duration,
}

fn json_field(name: &str, value: &str) -> String {
    format!("\"{name}\":{}", json_string(value))
}

fn json_optional_string(name: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => json_field(name, value),
        None => format!("\"{name}\":null"),
    }
}

fn json_optional_u64(name: &str, value: Option<u64>) -> String {
    match value {
        Some(value) => format!("\"{name}\":{value}"),
        None => format!("\"{name}\":null"),
    }
}

fn json_byte_counts(name: &str, value: Option<ByteCounts>) -> String {
    match value {
        Some(value) => format!(
            "\"{name}\":{{\"ingress\":{},\"egress\":{}}}",
            value.ingress, value.egress
        ),
        None => format!("\"{name}\":null"),
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn audit_kind_name(value: AuditKind) -> &'static str {
    match value {
        AuditKind::NetworkSessionStart => "network_session_start",
        AuditKind::BrokerStart => "broker_start",
        AuditKind::TunConfigured => "tun_configured",
        AuditKind::ProxyListenerConfigured => "proxy_listener_configured",
        AuditKind::DnsQuery => "dns_query",
        AuditKind::TcpConnect => "tcp_connect",
        AuditKind::UdpFlow => "udp_flow",
        AuditKind::QuicCandidateFlow => "quic_candidate_flow",
        AuditKind::HttpRequest => "http_request",
        AuditKind::HttpsConnect => "https_connect",
        AuditKind::TlsClientHello => "tls_client_hello",
        AuditKind::SocksConnect => "socks_connect",
        AuditKind::IcmpMessage => "icmp_message",
        AuditKind::UnsupportedNetworkEvent => "unsupported_network_event",
        AuditKind::FlowClosed => "flow_closed",
        AuditKind::PolicyReload => "policy_reload",
        AuditKind::BrokerError => "broker_error",
        AuditKind::NetworkSessionExit => "network_session_exit",
    }
}

fn audit_decision_name(value: AuditDecision) -> &'static str {
    match value {
        AuditDecision::Allow => "allow",
        AuditDecision::DenyDrop => "deny_drop",
        AuditDecision::DenyReset => "deny_reset",
        AuditDecision::DenyIcmpUnreachable => "deny_icmp_unreachable",
        AuditDecision::RequireBrokerDns => "require_broker_dns",
        AuditDecision::FailClosed => "fail_closed",
    }
}

fn frontend_name(value: FrontendKind) -> &'static str {
    match value {
        FrontendKind::Tun => "tun",
        FrontendKind::HttpProxy => "http_proxy",
        FrontendKind::Socks5 => "socks5",
        FrontendKind::SetupHelper => "setup_helper",
        FrontendKind::ExternalNamespace => "external_namespace",
    }
}

fn protocol_name(value: Protocol) -> &'static str {
    match value {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Dns => "dns",
        Protocol::Icmp => "icmp",
        Protocol::Http => "http",
        Protocol::HttpsConnect => "https_connect",
        Protocol::TlsClientHello => "tls_client_hello",
        Protocol::SocksConnect => "socks_connect",
        Protocol::QuicCandidate => "quic_candidate",
        Protocol::Unsupported => "unsupported",
    }
}

fn hostname_source_name(value: HostnameAttributionSource) -> &'static str {
    match value {
        HostnameAttributionSource::BrokerDns => "broker_dns",
        HostnameAttributionSource::HttpHostHeader => "http_host_header",
        HostnameAttributionSource::TlsSni => "tls_sni",
        HostnameAttributionSource::QuicTlsMetadata => "quic_tls_metadata",
        HostnameAttributionSource::ExplicitProxyDestination => "explicit_proxy_destination",
        HostnameAttributionSource::IpOnly => "ip_only",
    }
}

fn hostname_confidence_name(value: HostnameConfidence) -> &'static str {
    match value {
        HostnameConfidence::Unknown => "unknown",
        HostnameConfidence::Low => "low",
        HostnameConfidence::Medium => "medium",
        HostnameConfidence::High => "high",
    }
}

fn http_method_name(value: &HttpMethod) -> &str {
    match value {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Connect => "CONNECT",
        HttpMethod::Other(method) => method.as_str(),
    }
}

fn http_scheme_name(value: HttpScheme) -> &'static str {
    match value {
        HttpScheme::Http => "http",
        HttpScheme::Https => "https",
    }
}

fn mismatch_name(value: HostnameMismatch) -> &'static str {
    match value {
        HostnameMismatch::Matches => "matches",
        HostnameMismatch::Mismatch => "mismatch",
        HostnameMismatch::Unavailable => "unavailable",
        HostnameMismatch::NotChecked => "not_checked",
    }
}

impl From<&PolicyDecision> for AuditDecision {
    fn from(value: &PolicyDecision) -> Self {
        match value {
            PolicyDecision::Allow(_) => Self::Allow,
            PolicyDecision::Deny(deny) => match deny.action {
                foxprox_core::DenialAction::Drop => Self::DenyDrop,
                foxprox_core::DenialAction::Reset => Self::DenyReset,
                foxprox_core::DenialAction::IcmpUnreachable => Self::DenyIcmpUnreachable,
            },
            PolicyDecision::RequireBrokerDns { .. } => Self::RequireBrokerDns,
            PolicyDecision::FailClosed { .. } => Self::FailClosed,
        }
    }
}

fn audit_kind(event: &NormalizedEvent) -> AuditKind {
    match event {
        NormalizedEvent::TcpConnectAttempt(_) => AuditKind::TcpConnect,
        NormalizedEvent::UdpFlowAttempt(udp) => {
            if udp.classification == foxprox_core::UdpClassification::QuicCandidate {
                AuditKind::QuicCandidateFlow
            } else {
                AuditKind::UdpFlow
            }
        }
        NormalizedEvent::DnsQuery(_) => AuditKind::DnsQuery,
        NormalizedEvent::HttpRequest(_) => AuditKind::HttpRequest,
        NormalizedEvent::HttpsConnect(_) => AuditKind::HttpsConnect,
        NormalizedEvent::TlsClientHello(_) => AuditKind::TlsClientHello,
        NormalizedEvent::SocksConnect(_) => AuditKind::SocksConnect,
        NormalizedEvent::IcmpMessage(_) => AuditKind::IcmpMessage,
        NormalizedEvent::UnsupportedNetworkEvent(_) => AuditKind::UnsupportedNetworkEvent,
    }
}

fn source_string(event: &NormalizedEvent) -> Option<String> {
    match event {
        NormalizedEvent::TcpConnectAttempt(event) => Some(event.source.to_string()),
        NormalizedEvent::UdpFlowAttempt(event) => Some(event.source.to_string()),
        NormalizedEvent::DnsQuery(event) => Some(event.source.to_string()),
        NormalizedEvent::IcmpMessage(event) => Some(event.source.to_string()),
        _ => None,
    }
}

fn http_method(event: &NormalizedEvent) -> Option<HttpMethod> {
    match event {
        NormalizedEvent::HttpRequest(event) => Some(event.method.clone()),
        _ => None,
    }
}

fn http_scheme(event: &NormalizedEvent) -> Option<HttpScheme> {
    match event {
        NormalizedEvent::HttpRequest(event) => Some(event.scheme),
        _ => None,
    }
}

fn http_path_query(event: &NormalizedEvent) -> Option<String> {
    match event {
        NormalizedEvent::HttpRequest(event) => Some(event.path_query.clone()),
        _ => None,
    }
}

fn hostname_mismatch(event: &NormalizedEvent) -> Option<HostnameMismatch> {
    match event {
        NormalizedEvent::TlsClientHello(event) => Some(event.mismatch),
        _ => None,
    }
}

fn destination_string(event: &NormalizedEvent) -> Option<String> {
    match event {
        NormalizedEvent::TcpConnectAttempt(event) => Some(event.destination.to_string()),
        NormalizedEvent::UdpFlowAttempt(event) => Some(event.destination.to_string()),
        NormalizedEvent::DnsQuery(event) => Some(event.destination.to_string()),
        NormalizedEvent::HttpRequest(event) => Some(format_destination(&event.host, event.port)),
        NormalizedEvent::HttpsConnect(event) => Some(format_destination(&event.host, event.port)),
        NormalizedEvent::TlsClientHello(event) => Some(event.destination.to_string()),
        NormalizedEvent::SocksConnect(event) => {
            Some(format_destination(&event.destination, event.port))
        }
        NormalizedEvent::IcmpMessage(event) => Some(event.destination.to_string()),
        NormalizedEvent::UnsupportedNetworkEvent(_) => None,
    }
}

fn format_destination(host: &foxprox_core::DestinationHost, port: u16) -> String {
    match host {
        foxprox_core::DestinationHost::Hostname(hostname) => format!("{hostname}:{port}"),
        foxprox_core::DestinationHost::Ip(ip) => format!("{ip}:{port}"),
    }
}

fn rule_id(decision: &PolicyDecision) -> Option<String> {
    match decision {
        PolicyDecision::Allow(allow) => allow.rule_id.as_ref().map(|id| id.as_str().to_string()),
        PolicyDecision::Deny(deny) => deny.rule_id.as_ref().map(|id| id.as_str().to_string()),
        PolicyDecision::RequireBrokerDns { .. } | PolicyDecision::FailClosed { .. } => None,
    }
}

/// Audit sink contract. Implementations must apply backpressure rather than
/// grow without bound.
pub trait AuditSink {
    fn record(&mut self, record: AuditRecord) -> Result<(), AuditError>;
}

/// Bounded in-memory sink for tests and local diagnostics.
#[derive(Clone, Debug)]
pub struct BoundedAuditSink {
    capacity: usize,
    records: VecDeque<AuditRecord>,
}

impl BoundedAuditSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            records: VecDeque::with_capacity(capacity),
        }
    }

    pub fn records(&self) -> &VecDeque<AuditRecord> {
        &self.records
    }
}

impl AuditSink for BoundedAuditSink {
    fn record(&mut self, record: AuditRecord) -> Result<(), AuditError> {
        if self.records.len() >= self.capacity {
            return Err(AuditError::Backpressure {
                capacity: self.capacity,
            });
        }
        self.records.push_back(record);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuditError {
    Backpressure { capacity: usize },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backpressure { capacity } => write!(f, "audit sink capacity {capacity} reached"),
        }
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        DenialAction, DenyDecision, DestinationHost, FrontendKind, Hostname, HostnameAttribution,
        HostnameAttributionSource, HostnameConfidence, HostnameMismatch, HttpRequest, SandboxId,
        TcpConnectAttempt, TlsClientHello,
    };

    #[test]
    fn audit_schema_snapshot_contains_normalized_fields() {
        assert_eq!(
            AuditRecord::schema_fields(),
            &[
                "sequence",
                "timestamp_millis",
                "sandbox_id",
                "kind",
                "frontend",
                "protocol",
                "source",
                "destination",
                "hostname",
                "hostname_attribution_source",
                "hostname_confidence",
                "http_method",
                "http_scheme",
                "http_path_query",
                "hostname_mismatch",
                "decision",
                "rule_id",
                "reason",
                "byte_counts",
                "flow_duration_millis",
            ]
        );
    }

    #[test]
    fn record_uses_normalized_event_not_frontend_internal_data() {
        let event = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            hostname: Some(HostnameAttribution::new(
                Hostname::new("example.com").unwrap(),
                HostnameAttributionSource::BrokerDns,
                HostnameConfidence::Medium,
            )),
        });
        let decision = PolicyDecision::Deny(DenyDecision {
            action: DenialAction::Reset,
            rule_id: None,
            reason: "blocked".into(),
        });

        let record = AuditRecord::from_event(7, 1234, &event, &decision);
        assert_eq!(record.kind, AuditKind::TcpConnect);
        assert_eq!(record.decision, AuditDecision::DenyReset);
        assert_eq!(record.hostname.unwrap().as_str(), "example.com");
        assert_eq!(record.hostname_confidence, Some(HostnameConfidence::Medium));
    }

    #[test]
    fn http_audit_record_includes_visible_request_metadata() {
        let event = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::HttpProxy,
            method: HttpMethod::Post,
            scheme: HttpScheme::Http,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 80,
            path_query: "/submit?x=1".to_string(),
        });
        let decision = PolicyDecision::Allow(foxprox_core::AllowDecision {
            rule_id: None,
            timeout_override: None,
            reason: Some("allowed".into()),
        });

        let record = AuditRecord::from_event(8, 1234, &event, &decision);
        assert_eq!(record.kind, AuditKind::HttpRequest);
        assert_eq!(record.http_method, Some(HttpMethod::Post));
        assert_eq!(record.http_scheme, Some(HttpScheme::Http));
        assert_eq!(record.http_path_query.as_deref(), Some("/submit?x=1"));
    }

    #[test]
    fn audit_record_serializes_stable_json_line() {
        let event = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::HttpProxy,
            method: HttpMethod::Post,
            scheme: HttpScheme::Http,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 80,
            path_query: "/submit?x=\"quoted\"".to_string(),
        });
        let decision = PolicyDecision::Allow(foxprox_core::AllowDecision {
            rule_id: None,
            timeout_override: None,
            reason: Some("allowed".into()),
        });

        let line = AuditRecord::from_event(8, 1234, &event, &decision).to_json_line();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"kind\":\"http_request\""));
        assert!(line.contains("\"frontend\":\"http_proxy\""));
        assert!(line.contains("\"decision\":\"allow\""));
        assert!(line.contains("\"http_method\":\"POST\""));
        assert!(line.contains("\"http_path_query\":\"/submit?x=\\\"quoted\\\"\""));
        assert!(line.contains("\"byte_counts\":null"));
    }

    #[test]
    fn tls_audit_record_includes_mismatch_state() {
        let event = NormalizedEvent::TlsClientHello(TlsClientHello {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            destination: "203.0.113.10:443".parse().unwrap(),
            sni: Some(Hostname::new("evil.example").unwrap()),
            dns_hostname: Some(HostnameAttribution::new(
                Hostname::new("expected.example").unwrap(),
                HostnameAttributionSource::BrokerDns,
                HostnameConfidence::Medium,
            )),
            mismatch: HostnameMismatch::Mismatch,
        });
        let decision = PolicyDecision::Deny(DenyDecision {
            action: DenialAction::Reset,
            rule_id: None,
            reason: "SNI mismatch".into(),
        });

        let record = AuditRecord::from_event(9, 1234, &event, &decision);
        assert_eq!(record.kind, AuditKind::TlsClientHello);
        assert_eq!(record.hostname.unwrap().as_str(), "evil.example");
        assert_eq!(record.hostname_mismatch, Some(HostnameMismatch::Mismatch));
        assert_eq!(record.hostname_confidence, Some(HostnameConfidence::Medium));
    }

    #[test]
    fn flow_lifecycle_record_uses_normalized_fields() {
        let record = AuditRecord::flow_closed(FlowClosedAudit {
            sequence: 9,
            timestamp_millis: 1234,
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            protocol: Protocol::Tcp,
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "203.0.113.10:443".parse().unwrap(),
            byte_counts: ByteCounts::new(10, 20),
            duration: Duration::from_millis(2500),
        });

        assert_eq!(record.kind, AuditKind::FlowClosed);
        assert_eq!(record.source.as_deref(), Some("10.0.0.2:50000"));
        assert_eq!(record.destination.as_deref(), Some("203.0.113.10:443"));
        assert_eq!(record.byte_counts, Some(ByteCounts::new(10, 20)));
        assert_eq!(record.flow_duration_millis, Some(2500));
    }

    #[test]
    fn bounded_sink_reports_backpressure() {
        let mut sink = BoundedAuditSink::new(0);
        let record = AuditRecord {
            sequence: 0,
            timestamp_millis: 0,
            sandbox_id: SandboxId::new("s1").unwrap(),
            kind: AuditKind::BrokerStart,
            frontend: FrontendKind::Tun,
            protocol: Protocol::Unsupported,
            source: None,
            destination: None,
            hostname: None,
            hostname_attribution_source: None,
            hostname_confidence: None,
            http_method: None,
            http_scheme: None,
            http_path_query: None,
            hostname_mismatch: None,
            decision: AuditDecision::Allow,
            rule_id: None,
            reason: None,
            byte_counts: None,
            flow_duration_millis: None,
        };

        assert!(matches!(
            sink.record(record),
            Err(AuditError::Backpressure { capacity: 0 })
        ));
    }
}
