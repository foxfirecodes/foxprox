use crate::types::{
    AuditKind, ByteCounts, Decision, DenialReason, Frontend, HostnameAttribution, NetworkEndpoint,
    Origin, Protocol,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub timestamp_ms: u128,
    pub kind: AuditKind,
    pub sandbox_id: String,
    pub process_id: Option<u32>,
    pub frontend: Option<Frontend>,
    pub protocol: Option<Protocol>,
    pub source: Option<NetworkEndpoint>,
    pub destination: Option<NetworkEndpoint>,
    pub hostname: Option<String>,
    pub hostname_attribution: Option<HostnameAttribution>,
    pub origin: Option<Origin>,
    pub decision: Option<Decision>,
    pub reason: Option<DenialReason>,
    pub rule_id: Option<String>,
    pub byte_counts: Option<ByteCounts>,
    pub duration_ms: Option<u64>,
    pub details: BTreeMap<String, String>,
}

impl AuditRecord {
    pub fn new(kind: AuditKind, sandbox_id: impl Into<String>) -> Self {
        Self::new_at(kind, sandbox_id, 0)
    }

    pub fn new_at(kind: AuditKind, sandbox_id: impl Into<String>, timestamp_ms: u128) -> Self {
        Self {
            sequence: 0,
            timestamp_ms,
            kind,
            sandbox_id: sandbox_id.into(),
            process_id: None,
            frontend: None,
            protocol: None,
            source: None,
            destination: None,
            hostname: None,
            hostname_attribution: None,
            origin: None,
            decision: None,
            reason: None,
            rule_id: None,
            byte_counts: None,
            duration_ms: None,
            details: BTreeMap::new(),
        }
    }

    pub fn with_timestamp_ms(mut self, timestamp_ms: u128) -> Self {
        self.timestamp_ms = timestamp_ms;
        self
    }

    pub fn with_frontend(mut self, frontend: Frontend) -> Self {
        self.frontend = Some(frontend);
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn with_source(mut self, source: NetworkEndpoint) -> Self {
        self.source = Some(source);
        self
    }

    pub fn with_destination(mut self, destination: NetworkEndpoint) -> Self {
        self.destination = Some(destination);
        self
    }

    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn with_attribution(mut self, attribution: HostnameAttribution) -> Self {
        self.hostname = Some(attribution.hostname.clone());
        self.hostname_attribution = Some(attribution);
        self
    }

    pub fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }

    pub fn with_decision(mut self, decision: Decision, reason: Option<DenialReason>) -> Self {
        self.decision = Some(decision);
        self.reason = reason;
        self
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn with_byte_counts(mut self, byte_counts: ByteCounts) -> Self {
        self.byte_counts = Some(byte_counts);
        self
    }

    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    BufferFull {
        capacity: usize,
        attempted_kind: AuditKind,
    },
}

#[derive(Clone, Debug)]
pub struct BoundedAuditLedger {
    capacity: usize,
    records: VecDeque<AuditRecord>,
    next_sequence: u64,
    dropped_records: u64,
}

impl BoundedAuditLedger {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            records: VecDeque::with_capacity(capacity),
            next_sequence: 1,
            dropped_records: 0,
        }
    }

    pub fn append(&mut self, mut record: AuditRecord) -> Result<u64, AuditError> {
        if self.records.len() >= self.capacity {
            self.dropped_records += 1;
            return Err(AuditError::BufferFull {
                capacity: self.capacity,
                attempted_kind: record.kind,
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        record.sequence = sequence;
        self.records.push_back(record);
        Ok(sequence)
    }

    pub fn append_lossy(&mut self, mut record: AuditRecord) -> u64 {
        if self.capacity == 0 {
            self.dropped_records += 1;
            return 0;
        }
        if self.records.len() >= self.capacity {
            self.records.pop_front();
            self.dropped_records += 1;
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        record.sequence = sequence;
        self.records.push_back(record);
        sequence
    }

    pub fn records(&self) -> impl Iterator<Item = &AuditRecord> {
        self.records.iter()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped_records(&self) -> u64 {
        self.dropped_records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttributionConfidence, AttributionSource};
    use pretty_assertions::assert_eq;

    #[test]
    fn audit_record_serializes_stable_structured_fields() {
        let record = AuditRecord::new_at(AuditKind::TcpConnectDecision, "sandbox-a", 1_717_171)
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Tcp)
            .with_destination(NetworkEndpoint::socket(
                "93.184.216.34".parse().unwrap(),
                443,
            ))
            .with_attribution(HostnameAttribution::new(
                "Example.COM.",
                AttributionSource::BrokerDns,
                AttributionConfidence::Medium,
            ))
            .with_decision(Decision::Allow, None)
            .with_rule("allow-example");

        let value: serde_json::Value =
            serde_json::from_str(&record.to_json_line().unwrap()).unwrap();
        assert_eq!(value["kind"], "tcp_connect_decision");
        assert_eq!(value["sandbox_id"], "sandbox-a");
        assert_eq!(value["timestamp_ms"], 1_717_171);
        assert_eq!(value["frontend"], "tun");
        assert_eq!(value["protocol"], "tcp");
        assert_eq!(value["hostname"], "example.com");
        assert_eq!(value["hostname_attribution"]["source"], "broker_dns");
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["rule_id"], "allow-example");
    }

    #[test]
    fn audit_ledger_backpressure_is_bounded_and_observable() {
        let mut ledger = BoundedAuditLedger::new(2);
        assert!(ledger
            .append(AuditRecord::new(AuditKind::BrokerStarted, "s"))
            .is_ok());
        assert!(ledger
            .append(AuditRecord::new(AuditKind::TunConfigured, "s"))
            .is_ok());
        let error = ledger
            .append(AuditRecord::new(AuditKind::TcpConnectDecision, "s"))
            .unwrap_err();

        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.capacity(), 2);
        assert_eq!(ledger.dropped_records(), 1);
        assert_eq!(
            error,
            AuditError::BufferFull {
                capacity: 2,
                attempted_kind: AuditKind::TcpConnectDecision
            }
        );
    }
}
