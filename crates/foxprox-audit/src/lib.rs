//! Audit output adapters for foxprox.
//!
//! The broker core emits typed `AuditRecord`s. This crate turns those records
//! into externally observable JSON Lines and enforces bounded buffering so slow
//! audit consumers cannot grow memory without limit.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use foxprox_core::{
    AttributionConfidence, AuditDecision, AuditKind, AuditRecord, DenialBehavior, Endpoint,
    FrontendKind, Protocol,
};
use serde::Serialize;

/// Audit sink/serialization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditSinkError {
    Serialize(String),
    Backpressure { capacity: usize },
}

impl fmt::Display for AuditSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(error) => write!(f, "audit-serialize-error: {error}"),
            Self::Backpressure { capacity } => {
                write!(f, "audit-sink-backpressure: capacity={capacity}")
            }
        }
    }
}

impl std::error::Error for AuditSinkError {}

/// Convert an audit record to one JSON line.
pub fn audit_record_to_json_line(record: &AuditRecord) -> Result<String, AuditSinkError> {
    let json_record = JsonAuditRecord::from(record);
    let mut line = serde_json::to_string(&json_record)
        .map_err(|error| AuditSinkError::Serialize(error.to_string()))?;
    line.push('\n');
    Ok(line)
}

/// Bounded in-memory JSON Lines audit sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedJsonAuditSink {
    capacity: usize,
    lines: VecDeque<String>,
}

impl BoundedJsonAuditSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            lines: VecDeque::new(),
        }
    }

    pub fn try_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
        if self.lines.len() >= self.capacity {
            return Err(AuditSinkError::Backpressure {
                capacity: self.capacity,
            });
        }
        self.lines.push_back(audit_record_to_json_line(record)?);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn pop_line(&mut self) -> Option<String> {
        self.lines.pop_front()
    }
}

#[derive(Serialize)]
struct JsonAuditRecord<'a> {
    timestamp_unix_ms: u128,
    kind: &'static str,
    sandbox_id: &'a str,
    frontend: &'static str,
    protocol: &'static str,
    source: Option<JsonEndpoint>,
    destination: Option<JsonEndpoint>,
    hostname: Option<&'a str>,
    hostname_confidence: Option<&'static str>,
    http_method: Option<&'a str>,
    http_scheme: Option<&'a str>,
    http_path_query: Option<&'a str>,
    decision: &'static str,
    denial_behavior: Option<&'static str>,
    rule_id: Option<&'a str>,
    reason: Option<&'a str>,
    byte_count: Option<u64>,
}

impl<'a> From<&'a AuditRecord> for JsonAuditRecord<'a> {
    fn from(record: &'a AuditRecord) -> Self {
        Self {
            timestamp_unix_ms: unix_millis(record.timestamp),
            kind: audit_kind(record.kind),
            sandbox_id: record.sandbox_id.as_str(),
            frontend: frontend_kind(record.frontend),
            protocol: protocol(record.protocol),
            source: record.source.map(JsonEndpoint::from),
            destination: record.destination.map(JsonEndpoint::from),
            hostname: record.hostname.as_deref(),
            hostname_confidence: record.hostname_confidence.map(attribution_confidence),
            http_method: record.http_method.as_deref(),
            http_scheme: record.http_scheme.as_deref(),
            http_path_query: record.http_path_query.as_deref(),
            decision: audit_decision(record.decision),
            denial_behavior: record.denial_behavior.map(denial_behavior),
            rule_id: record.rule_id.as_deref(),
            reason: record.reason.as_deref(),
            byte_count: record.byte_count,
        }
    }
}

#[derive(Serialize)]
struct JsonEndpoint {
    ip: String,
    port: Option<u16>,
}

impl From<Endpoint> for JsonEndpoint {
    fn from(value: Endpoint) -> Self {
        Self {
            ip: ip_addr(value.ip),
            port: value.port,
        }
    }
}

fn unix_millis(timestamp: SystemTime) -> u128 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn ip_addr(value: IpAddr) -> String {
    value.to_string()
}

fn audit_kind(value: AuditKind) -> &'static str {
    match value {
        AuditKind::TcpConnect => "tcp_connect",
        AuditKind::UdpFlow => "udp_flow",
        AuditKind::UdpFlowExpired => "udp_flow_expired",
        AuditKind::DnsQuery => "dns_query",
        AuditKind::HttpRequest => "http_request",
        AuditKind::HttpsConnect => "https_connect",
        AuditKind::TlsClientHello => "tls_client_hello",
        AuditKind::SocksConnect => "socks_connect",
        AuditKind::IcmpMessage => "icmp_message",
        AuditKind::UnsupportedNetworkEvent => "unsupported_network_event",
    }
}

fn frontend_kind(value: FrontendKind) -> &'static str {
    match value {
        FrontendKind::Tun => "tun",
        FrontendKind::HttpProxy => "http_proxy",
        FrontendKind::Socks5 => "socks5",
        FrontendKind::Setup => "setup",
        FrontendKind::External => "external",
    }
}

fn protocol(value: Protocol) -> &'static str {
    match value {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Dns => "dns",
        Protocol::Icmp => "icmp",
        Protocol::Http => "http",
        Protocol::HttpsConnect => "https_connect",
        Protocol::TlsClientHello => "tls_client_hello",
        Protocol::Socks => "socks",
        Protocol::QuicCandidate => "quic_candidate",
        Protocol::Unsupported => "unsupported",
    }
}

fn attribution_confidence(value: AttributionConfidence) -> &'static str {
    match value {
        AttributionConfidence::Low => "low",
        AttributionConfidence::Medium => "medium",
        AttributionConfidence::High => "high",
    }
}

fn audit_decision(value: AuditDecision) -> &'static str {
    match value {
        AuditDecision::Allowed => "allowed",
        AuditDecision::Denied => "denied",
        AuditDecision::FailClosed => "fail_closed",
        AuditDecision::Observed => "observed",
    }
}

fn denial_behavior(value: DenialBehavior) -> &'static str {
    match value {
        DenialBehavior::Drop => "drop",
        DenialBehavior::Reset => "reset",
        DenialBehavior::IcmpUnreachable => "icmp_unreachable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_broker::Ipv4PacketBroker;
    use foxprox_core::{
        Endpoint, FrontendKind, HttpRequest, NormalizedEvent, PolicyConfig, PolicyEngine,
        PolicyRule, Protocol, RuleAction, SandboxId,
    };
    use foxprox_packet::PacketContext;
    use serde_json::Value;

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("audit-test").unwrap(), FrontendKind::Tun)
    }

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_length = 20 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn allow_icmp_broker() -> Ipv4PacketBroker {
        let rule = PolicyRule::new("allow-icmp", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Icmp);
        Ipv4PacketBroker::new(PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        }))
    }

    #[test]
    fn serializes_broker_audit_record_as_json_line() {
        let packet = ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            b"\x08\x00\x00\x00\x12\x34\x00\x01payload",
        );
        let result = allow_icmp_broker().process_packet(&context(), &packet);

        let line = audit_record_to_json_line(&result.evaluation.audit).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();

        assert!(line.ends_with('\n'));
        assert_eq!(value["kind"], "icmp_message");
        assert_eq!(value["sandbox_id"], "audit-test");
        assert_eq!(value["frontend"], "tun");
        assert_eq!(value["protocol"], "icmp");
        assert_eq!(value["decision"], "allowed");
        assert_eq!(value["rule_id"], "allow-icmp");
        assert_eq!(value["source"]["ip"], "10.0.0.2");
        assert_eq!(value["destination"]["ip"], "203.0.113.10");
    }

    #[test]
    fn serializes_http_method_scheme_and_path_audit_fields() {
        let rule = PolicyRule::new("allow-http", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Http)
            .with_http_method("GET")
            .with_http_path_prefix("/public");
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let event = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: SandboxId::new("audit-http-test").unwrap(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: Some(Endpoint::tcp("93.184.216.34".parse().unwrap(), 80)),
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.com".to_owned(),
            port: 80,
            path_query: "/public/index.html".to_owned(),
        });
        let evaluation = engine.evaluate(&event);

        let line = audit_record_to_json_line(&evaluation.audit).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();

        assert_eq!(value["kind"], "http_request");
        assert_eq!(value["http_method"], "GET");
        assert_eq!(value["http_scheme"], "http");
        assert_eq!(value["http_path_query"], "/public/index.html");
    }

    #[test]
    fn bounded_sink_reports_backpressure_without_accepting_record() {
        let packet = ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            b"\x08\x00\x00\x00\x12\x34\x00\x01payload",
        );
        let result = allow_icmp_broker().process_packet(&context(), &packet);
        let mut sink = BoundedJsonAuditSink::new(1);

        sink.try_record(&result.evaluation.audit).unwrap();
        let error = sink.try_record(&result.evaluation.audit).unwrap_err();

        assert_eq!(error, AuditSinkError::Backpressure { capacity: 1 });
        assert_eq!(sink.len(), 1);
        assert!(sink
            .pop_line()
            .unwrap()
            .contains("\"decision\":\"allowed\""));
        assert!(sink.is_empty());
    }
}
