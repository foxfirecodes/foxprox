//! Structured audit contract and bounded sinks for normalized foxprox events.
//!
//! Audit records consume normalized events and decisions only. They must not
//! depend on frontend implementation structs, raw packets, Linux fd types, or
//! parser-specific data.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;

use foxprox_core::{
    ByteCounts, DecisionReason, FrontendKind, Hostname, HostnameAttributionSource,
    HostnameConfidence, NormalizedEvent, PolicyDecision, Protocol, SandboxId,
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
            decision: AuditDecision::from(decision),
            rule_id: rule_id(decision),
            reason: decision.reason().cloned(),
            byte_counts: None,
            flow_duration_millis: None,
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
            "decision",
            "rule_id",
            "reason",
            "byte_counts",
            "flow_duration_millis",
        ]
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

fn destination_string(event: &NormalizedEvent) -> Option<String> {
    match event {
        NormalizedEvent::TcpConnectAttempt(event) => Some(event.destination.to_string()),
        NormalizedEvent::UdpFlowAttempt(event) => Some(event.destination.to_string()),
        NormalizedEvent::DnsQuery(event) => Some(event.destination.to_string()),
        NormalizedEvent::HttpRequest(event) => Some(format!("{}:{}", event.host, event.port)),
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
        DenialAction, DenyDecision, FrontendKind, Hostname, HostnameAttribution,
        HostnameAttributionSource, HostnameConfidence, SandboxId, TcpConnectAttempt,
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
