//! Platform-independent flow tracking for foxprox.
//!
//! This crate owns lifecycle state such as UDP pseudo-flow timeouts and byte
//! counters. It consumes normalized core events rather than raw packets.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use foxprox_core::{
    AuditDecision, AuditKind, AuditRecord, Endpoint, FrontendKind, HostnameAttribution,
    NormalizedEvent, Protocol, SandboxId, UdpClassification,
};

/// Configurable UDP idle timeouts by protocol class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFlowTimeouts {
    pub dns: Duration,
    pub generic: Duration,
    pub quic_candidate: Duration,
}

impl Default for UdpFlowTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(10),
            generic: Duration::from_secs(60),
            quic_candidate: Duration::from_secs(180),
        }
    }
}

impl UdpFlowTimeouts {
    fn timeout_for(self, classification: UdpClassification) -> Duration {
        match classification {
            UdpClassification::Dns => self.dns,
            UdpClassification::Generic => self.generic,
            UdpClassification::QuicCandidate => self.quic_candidate,
        }
    }
}

/// Stable key for one UDP pseudo-flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UdpFlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
}

/// Current UDP pseudo-flow state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowState {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub key: UdpFlowKey,
    pub classification: UdpClassification,
    pub attribution: Option<HostnameAttribution>,
    pub created_at: SystemTime,
    pub last_seen: SystemTime,
    pub expires_at: SystemTime,
    pub packet_count: u64,
    pub byte_count: u64,
}

/// Result of observing a packet/event for a UDP flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UdpFlowObservation {
    Created(UdpFlowState),
    Updated(UdpFlowState),
    IgnoredNonUdpEvent,
    IgnoredMissingEndpoint,
}

/// Expiration evidence emitted when a UDP pseudo-flow ages out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredUdpFlow {
    pub state: UdpFlowState,
    pub expired_at: SystemTime,
}

impl ExpiredUdpFlow {
    pub fn audit_record(&self) -> AuditRecord {
        AuditRecord {
            timestamp: self.expired_at,
            kind: AuditKind::UdpFlowExpired,
            sandbox_id: self.state.sandbox_id.clone(),
            frontend: self.state.frontend,
            protocol: protocol_for_classification(self.state.classification),
            source: Some(self.state.key.source),
            destination: Some(self.state.key.destination),
            hostname: self
                .state
                .attribution
                .as_ref()
                .map(|attribution| attribution.hostname.clone()),
            hostname_confidence: self.state.attribution.as_ref().map(|attr| attr.confidence),
            http_method: None,
            http_scheme: None,
            http_path_query: None,
            decision: AuditDecision::Observed,
            denial_behavior: None,
            rule_id: None,
            reason: Some("idle-timeout".to_owned()),
            byte_count: Some(self.state.byte_count),
            client_to_target_bytes: None,
            target_to_client_bytes: None,
        }
    }
}

/// Close evidence for one TCP flow after a bridge/tunnel finishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedTcpFlow {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub attribution: Option<HostnameAttribution>,
    pub closed_at: SystemTime,
    pub client_to_target_bytes: u64,
    pub target_to_client_bytes: u64,
    pub reason: String,
}

impl ClosedTcpFlow {
    pub fn audit_record(&self) -> AuditRecord {
        AuditRecord {
            timestamp: self.closed_at,
            kind: AuditKind::TcpFlowClosed,
            sandbox_id: self.sandbox_id.clone(),
            frontend: self.frontend,
            protocol: Protocol::Tcp,
            source: self.source,
            destination: self.destination,
            hostname: self
                .attribution
                .as_ref()
                .map(|attribution| attribution.hostname.clone()),
            hostname_confidence: self.attribution.as_ref().map(|attr| attr.confidence),
            http_method: None,
            http_scheme: None,
            http_path_query: None,
            decision: AuditDecision::Observed,
            denial_behavior: None,
            rule_id: None,
            reason: Some(self.reason.clone()),
            byte_count: Some(self.client_to_target_bytes + self.target_to_client_bytes),
            client_to_target_bytes: Some(self.client_to_target_bytes),
            target_to_client_bytes: Some(self.target_to_client_bytes),
        }
    }
}

fn protocol_for_classification(classification: UdpClassification) -> Protocol {
    match classification {
        UdpClassification::Dns => Protocol::Dns,
        UdpClassification::Generic => Protocol::Udp,
        UdpClassification::QuicCandidate => Protocol::QuicCandidate,
    }
}

/// UDP pseudo-flow table with deterministic expiration behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowTable {
    timeouts: UdpFlowTimeouts,
    flows: HashMap<UdpFlowKey, UdpFlowState>,
}

impl UdpFlowTable {
    pub fn new(timeouts: UdpFlowTimeouts) -> Self {
        Self {
            timeouts,
            flows: HashMap::new(),
        }
    }

    pub fn observe_event(
        &mut self,
        event: &NormalizedEvent,
        now: SystemTime,
        byte_count: u64,
    ) -> UdpFlowObservation {
        let Some(input) = UdpFlowInput::from_event(event) else {
            return UdpFlowObservation::IgnoredNonUdpEvent;
        };
        let Some(key) = input.key else {
            return UdpFlowObservation::IgnoredMissingEndpoint;
        };
        let timeout = self.timeouts.timeout_for(input.classification);
        let expires_at = now.checked_add(timeout).unwrap_or(SystemTime::UNIX_EPOCH);

        if let Some(existing) = self.flows.get_mut(&key) {
            existing.last_seen = now;
            existing.expires_at = expires_at;
            existing.packet_count = existing.packet_count.saturating_add(1);
            existing.byte_count = existing.byte_count.saturating_add(byte_count);
            if existing.attribution.is_none() {
                existing.attribution = input.attribution;
            }
            return UdpFlowObservation::Updated(existing.clone());
        }

        let state = UdpFlowState {
            sandbox_id: input.sandbox_id,
            frontend: input.frontend,
            key,
            classification: input.classification,
            attribution: input.attribution,
            created_at: now,
            last_seen: now,
            expires_at,
            packet_count: 1,
            byte_count,
        };
        self.flows.insert(key, state.clone());
        UdpFlowObservation::Created(state)
    }

    pub fn expire(&mut self, now: SystemTime) -> Vec<ExpiredUdpFlow> {
        let expired_keys = self
            .flows
            .iter()
            .filter_map(|(key, state)| (state.expires_at <= now).then_some(*key))
            .collect::<Vec<_>>();
        let mut expired = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(state) = self.flows.remove(&key) {
                expired.push(ExpiredUdpFlow {
                    state,
                    expired_at: now,
                });
            }
        }
        expired
    }

    pub fn get(&self, key: &UdpFlowKey) -> Option<&UdpFlowState> {
        self.flows.get(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UdpFlowInput {
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    key: Option<UdpFlowKey>,
    classification: UdpClassification,
    attribution: Option<HostnameAttribution>,
}

impl UdpFlowInput {
    fn from_event(event: &NormalizedEvent) -> Option<Self> {
        match event {
            NormalizedEvent::UdpFlowAttempt(udp) => Some(Self {
                sandbox_id: udp.sandbox_id.clone(),
                frontend: udp.frontend,
                key: Some(UdpFlowKey {
                    source: udp.source,
                    destination: udp.destination,
                }),
                classification: udp.classification,
                attribution: udp.attribution.clone(),
            }),
            NormalizedEvent::DnsQuery(query) => Some(Self {
                sandbox_id: query.sandbox_id.clone(),
                frontend: query.frontend,
                key: query.source.map(|source| UdpFlowKey {
                    source,
                    destination: query.resolver,
                }),
                classification: UdpClassification::Dns,
                attribution: None,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_audit::audit_record_to_json_line;
    use foxprox_core::{
        AttributionConfidence, AttributionSource, AuditDecision, AuditKind, FrontendKind,
        HostnameAttribution, Protocol, SandboxId,
    };
    use foxprox_packet::{parse_ipv4_packet, PacketContext};
    use serde_json::Value;
    use std::net::Ipv4Addr;

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("flow-test").unwrap(), FrontendKind::Tun)
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

    fn udp_payload(source_port: u16, destination_port: u16, body_len: usize) -> Vec<u8> {
        let udp_length = 8 + body_len;
        let mut payload = vec![0_u8; udp_length];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
        payload
    }

    fn udp_event(destination_port: u16) -> NormalizedEvent {
        let packet = ipv4_packet(
            17,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            &udp_payload(53000, destination_port, 8),
        );
        parse_ipv4_packet(&context(), &packet).unwrap()
    }

    #[test]
    fn quic_candidate_flow_uses_longer_timeout_and_expires() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut table = UdpFlowTable::new(UdpFlowTimeouts {
            dns: Duration::from_secs(5),
            generic: Duration::from_secs(30),
            quic_candidate: Duration::from_secs(120),
        });
        let event = udp_event(443);

        let observation = table.observe_event(&event, now, 48);

        let UdpFlowObservation::Created(state) = observation else {
            panic!("expected created flow");
        };
        assert_eq!(event.protocol(), Protocol::QuicCandidate);
        assert_eq!(state.classification, UdpClassification::QuicCandidate);
        assert_eq!(state.expires_at, now + Duration::from_secs(120));
        assert!(table.expire(now + Duration::from_secs(119)).is_empty());
        let expired = table.expire(now + Duration::from_secs(120));
        assert_eq!(expired.len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn expired_udp_flow_emits_structured_audit_record() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500);
        let mut table = UdpFlowTable::new(UdpFlowTimeouts {
            dns: Duration::from_secs(5),
            generic: Duration::from_secs(30),
            quic_candidate: Duration::from_secs(60),
        });
        let mut event = udp_event(443);
        match &mut event {
            NormalizedEvent::UdpFlowAttempt(udp) => {
                udp.attribution = Some(HostnameAttribution::new(
                    "video.example.com",
                    AttributionSource::DnsCache,
                    AttributionConfidence::Medium,
                ));
            }
            other => panic!("unexpected event: {other:?}"),
        }
        table.observe_event(&event, now, 128);

        let expired = table.expire(now + Duration::from_secs(60));
        let audit = expired[0].audit_record();
        let line = audit_record_to_json_line(&audit).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();

        assert_eq!(audit.kind, AuditKind::UdpFlowExpired);
        assert_eq!(audit.decision, AuditDecision::Observed);
        assert_eq!(audit.protocol, Protocol::QuicCandidate);
        assert_eq!(audit.hostname.as_deref(), Some("video.example.com"));
        assert_eq!(audit.byte_count, Some(128));
        assert_eq!(value["kind"], "udp_flow_expired");
        assert_eq!(value["decision"], "observed");
        assert_eq!(value["byte_count"], 128);
        assert_eq!(value["reason"], "idle-timeout");
    }

    #[test]
    fn closed_tcp_flow_emits_structured_audit_with_directional_byte_counts() {
        let closed = ClosedTcpFlow {
            sandbox_id: SandboxId::new("flow-test").unwrap(),
            frontend: FrontendKind::HttpProxy,
            source: Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)),
            destination: Some(Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443)),
            attribution: Some(HostnameAttribution::new(
                "api.example.com",
                AttributionSource::ExplicitProxyHost,
                AttributionConfidence::High,
            )),
            closed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(2_000),
            client_to_target_bytes: 123,
            target_to_client_bytes: 456,
            reason: "eof".to_owned(),
        };

        let audit = closed.audit_record();
        let line = audit_record_to_json_line(&audit).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();

        assert_eq!(audit.kind, AuditKind::TcpFlowClosed);
        assert_eq!(audit.decision, AuditDecision::Observed);
        assert_eq!(audit.protocol, Protocol::Tcp);
        assert_eq!(audit.byte_count, Some(579));
        assert_eq!(audit.client_to_target_bytes, Some(123));
        assert_eq!(audit.target_to_client_bytes, Some(456));
        assert_eq!(value["kind"], "tcp_flow_closed");
        assert_eq!(value["decision"], "observed");
        assert_eq!(value["hostname"], "api.example.com");
        assert_eq!(value["byte_count"], 579);
        assert_eq!(value["client_to_target_bytes"], 123);
        assert_eq!(value["target_to_client_bytes"], 456);
        assert_eq!(value["reason"], "eof");
    }

    #[test]
    fn repeated_udp_observation_refreshes_timeout_and_counts_bytes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let mut table = UdpFlowTable::new(UdpFlowTimeouts::default());
        let event = udp_event(12345);

        let first = table.observe_event(&event, now, 20);
        let second = table.observe_event(&event, now + Duration::from_secs(10), 30);

        assert!(matches!(first, UdpFlowObservation::Created(_)));
        let UdpFlowObservation::Updated(state) = second else {
            panic!("expected updated flow");
        };
        assert_eq!(state.classification, UdpClassification::Generic);
        assert_eq!(state.packet_count, 2);
        assert_eq!(state.byte_count, 50);
        assert_eq!(state.last_seen, now + Duration::from_secs(10));
        assert_eq!(state.expires_at, now + Duration::from_secs(70));
    }

    #[test]
    fn dns_query_event_uses_dns_timeout() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000);
        let mut table = UdpFlowTable::new(UdpFlowTimeouts {
            dns: Duration::from_secs(7),
            generic: Duration::from_secs(60),
            quic_candidate: Duration::from_secs(120),
        });
        let event = foxprox_core::NormalizedEvent::DnsQuery(foxprox_core::DnsQuery {
            sandbox_id: SandboxId::new("flow-test").unwrap(),
            frontend: FrontendKind::Tun,
            source: Some(Endpoint::udp(Ipv4Addr::new(10, 0, 0, 2).into(), 53000)),
            resolver: Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53),
            hostname: "example.com".to_owned(),
            query_type: "A".to_owned(),
        });

        let UdpFlowObservation::Created(state) = table.observe_event(&event, now, 33) else {
            panic!("expected dns flow creation");
        };

        assert_eq!(state.classification, UdpClassification::Dns);
        assert_eq!(state.expires_at, now + Duration::from_secs(7));
    }

    #[test]
    fn flow_preserves_existing_hostname_attribution() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(4_000);
        let mut table = UdpFlowTable::new(UdpFlowTimeouts::default());
        let mut event = udp_event(443);
        match &mut event {
            NormalizedEvent::UdpFlowAttempt(udp) => {
                udp.attribution = Some(HostnameAttribution::new(
                    "example.com",
                    AttributionSource::DnsCache,
                    AttributionConfidence::Medium,
                ));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let UdpFlowObservation::Created(state) = table.observe_event(&event, now, 42) else {
            panic!("expected attributed flow");
        };

        assert_eq!(
            state
                .attribution
                .as_ref()
                .map(|attr| attr.hostname.as_str()),
            Some("example.com")
        );
    }
}
