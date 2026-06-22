//! Network adapter and flow-management contracts for foxprox alpha.
//!
//! This crate is allowed to orchestrate core, policy, audit, and egress. Concrete
//! stack choices such as smoltcp must remain behind adapter traits.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use foxprox_audit::{AuditRecord, AuditSink, FlowClosedAudit};
use foxprox_core::{
    classify_udp_destination as core_classify_udp_destination, DenialAction, DestinationHost,
    DnsQuery, FrontendKind, Hostname, HostnameAttribution, HostnameAttributionSource,
    HostnameConfidence, NormalizedEvent, PolicyDecision, Protocol, SandboxId, UdpClassification,
    UdpTimeouts,
};
use foxprox_egress::{dispatch_allowed_event, EgressError, HostEgress};
use foxprox_policy::PolicyEngine;

/// Network-stack adapter boundary. Implementations may use smoltcp or another
/// stack, but must emit only normalized events and opaque outbound packets.
pub trait StackAdapter {
    fn ingest_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<StackEvent>, StackError>;
    fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError>;
}

/// Event emitted by a stack adapter after parsing/flow handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackEvent {
    PolicyEvent(NormalizedEvent),
    FlowClosed {
        sandbox_id: SandboxId,
        key: FlowKey,
        byte_counts: foxprox_core::ByteCounts,
    },
}

/// Opaque outbound IP packet to write back to TUN.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundIpPacket {
    bytes: Vec<u8>,
}

impl OutboundIpPacket {
    pub fn new(bytes: Vec<u8>) -> Result<Self, StackError> {
        if bytes.is_empty() {
            return Err(StackError::EmptyOutboundPacket);
        }
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackError {
    EmptyOutboundPacket,
    MalformedPacket,
    Adapter(String),
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyOutboundPacket => f.write_str("outbound packet must not be empty"),
            Self::MalformedPacket => f.write_str("malformed packet"),
            Self::Adapter(reason) => write!(f, "stack adapter error: {reason}"),
        }
    }
}

impl std::error::Error for StackError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FlowKey {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: FlowProtocol,
}

#[derive(Clone, Debug)]
pub struct FlowState {
    pub key: FlowKey,
    pub hostname: Option<HostnameAttribution>,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub idle_timeout: Duration,
    pub byte_counts: foxprox_core::ByteCounts,
    pub decision: PolicyDecision,
}

#[derive(Clone, Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTable {
    pub fn upsert(&mut self, state: FlowState) {
        self.flows.insert(state.key.clone(), state);
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(key)
    }

    pub fn expire_idle(&mut self, now: Instant, idle_after: Duration) -> Vec<FlowState> {
        self.expire_matching(|state| now.duration_since(state.last_seen) >= idle_after)
    }

    pub fn expire_by_flow_timeout(&mut self, now: Instant) -> Vec<FlowState> {
        self.expire_matching(|state| now.duration_since(state.last_seen) >= state.idle_timeout)
    }

    fn expire_matching(&mut self, should_expire: impl Fn(&FlowState) -> bool) -> Vec<FlowState> {
        let expired_keys: Vec<_> = self
            .flows
            .iter()
            .filter_map(|(key, state)| should_expire(state).then_some(key.clone()))
            .collect();
        expired_keys
            .into_iter()
            .filter_map(|key| self.flows.remove(&key))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

/// DNS cache used for medium-confidence transparent hostname attribution.
#[derive(Clone, Debug, Default)]
pub struct DnsAttributionCache {
    by_ip: HashMap<IpAddr, DnsAttribution>,
}

impl DnsAttributionCache {
    pub fn observe(
        &mut self,
        hostname: Hostname,
        addrs: impl IntoIterator<Item = IpAddr>,
        now: Instant,
        ttl: Duration,
    ) {
        for ip in addrs {
            self.by_ip.insert(
                ip,
                DnsAttribution {
                    hostname: hostname.clone(),
                    expires_at: now + ttl,
                },
            );
        }
    }

    /// Ingest normalized DNS address records emitted by `foxprox-dns` without
    /// exposing DNS wire/parser state to policy or flow code.
    pub fn observe_address_records(
        &mut self,
        records: impl IntoIterator<Item = foxprox_dns::DnsAddressRecord>,
        now: Instant,
    ) {
        for record in records {
            self.observe(record.hostname, [record.addr], now, record.ttl);
        }
    }

    pub fn attribution_for(&self, ip: IpAddr, now: Instant) -> Option<HostnameAttribution> {
        let attribution = self.by_ip.get(&ip)?;
        if attribution.expires_at <= now {
            return None;
        }
        Some(HostnameAttribution::new(
            attribution.hostname.clone(),
            HostnameAttributionSource::BrokerDns,
            HostnameConfidence::Medium,
        ))
    }
}

#[derive(Clone, Debug)]
struct DnsAttribution {
    hostname: Hostname,
    expires_at: Instant,
}

pub fn classify_udp_destination(destination: SocketAddr) -> UdpClassification {
    core_classify_udp_destination(destination)
}

pub fn udp_timeout(classification: UdpClassification, timeouts: &UdpTimeouts) -> Duration {
    match classification {
        UdpClassification::Dns => timeouts.dns,
        UdpClassification::QuicCandidate => timeouts.quic,
        UdpClassification::NtpLike => timeouts.ntp_like,
        UdpClassification::Generic | UdpClassification::MulticastOrBroadcast => timeouts.generic,
    }
}

pub fn flow_idle_timeout(decision: &PolicyDecision, fallback: Duration) -> Duration {
    match decision {
        PolicyDecision::Allow(allow) => allow.timeout_override.unwrap_or(fallback),
        PolicyDecision::Deny(_)
        | PolicyDecision::RequireBrokerDns { .. }
        | PolicyDecision::FailClosed { .. } => fallback,
    }
}

/// Process a normalized event through policy, audit, and shared egress.
pub fn handle_normalized_event<E, A>(
    event: &NormalizedEvent,
    policy: &PolicyEngine,
    egress: &mut E,
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
) -> Result<BrokerEventOutcome, BrokerError>
where
    E: HostEgress,
    A: AuditSink,
{
    let decision = policy.decide(event);
    let record = AuditRecord::from_event(sequence, timestamp_millis, event, &decision);
    audit.record(record).map_err(BrokerError::Audit)?;

    if decision.is_allowed() {
        match dispatch_allowed_event(egress, event) {
            Ok(_) => Ok(BrokerEventOutcome::Forwarded),
            Err(EgressError::UnsupportedAllowedEvent) => Ok(BrokerEventOutcome::NoEgressRequired),
            Err(error) => Err(BrokerError::Egress(error)),
        }
    } else {
        Ok(BrokerEventOutcome::Denied(decision_denial_action(
            &decision,
        )))
    }
}

/// Record a flow lifecycle close/expiry without exposing adapter-specific flow
/// state to the audit crate.
pub fn record_flow_closed<A>(
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    state: &FlowState,
    closed_at: Instant,
) -> Result<(), BrokerError>
where
    A: AuditSink,
{
    let protocol = match state.key.protocol {
        FlowProtocol::Tcp => Protocol::Tcp,
        FlowProtocol::Udp => Protocol::Udp,
    };
    let duration = closed_at.duration_since(state.created_at);
    let record = AuditRecord::flow_closed(FlowClosedAudit {
        sequence,
        timestamp_millis,
        sandbox_id,
        frontend,
        protocol,
        source: state.key.source,
        destination: state.key.destination,
        byte_counts: state.byte_counts,
        duration,
    });
    audit.record(record).map_err(BrokerError::Audit)
}

fn decision_denial_action(decision: &PolicyDecision) -> Option<DenialAction> {
    match decision {
        PolicyDecision::Deny(deny) => Some(deny.action),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BrokerEventOutcome {
    Forwarded,
    NoEgressRequired,
    Denied(Option<DenialAction>),
}

#[derive(Debug)]
pub enum BrokerError {
    Audit(foxprox_audit::AuditError),
    Egress(EgressError),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(error) => write!(f, "audit error: {error}"),
            Self::Egress(error) => write!(f, "egress error: {error}"),
        }
    }
}

impl std::error::Error for BrokerError {}

/// Build a high-confidence attribution value from explicit proxy destinations.
pub fn attribution_from_explicit_destination(
    host: &DestinationHost,
) -> Option<HostnameAttribution> {
    host.hostname().map(|hostname| {
        HostnameAttribution::new(
            hostname.clone(),
            HostnameAttributionSource::ExplicitProxyDestination,
            HostnameConfidence::High,
        )
    })
}

/// DNS query helper used by transparent and explicit DNS paths.
pub fn is_broker_dns_destination(query: &DnsQuery, broker_addrs: &[IpAddr]) -> bool {
    query.destination.port() == 53 && broker_addrs.contains(&query.destination.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_audit::BoundedAuditSink;
    use foxprox_core::{
        DestinationHost, FrontendKind, Hostname, HttpMethod, HttpRequest, HttpScheme, PolicyRule,
        PortMatcher, Protocol, ProtocolMatcher, RuleId, RuntimeConfig, TcpConnectAttempt,
        UdpFlowAttempt,
    };
    use foxprox_egress::MockEgress;

    #[test]
    fn dns_attribution_cache_returns_medium_confidence_until_expiry() {
        let now = Instant::now();
        let mut cache = DnsAttributionCache::default();
        cache.observe(
            Hostname::new("example.com").unwrap(),
            ["203.0.113.10".parse().unwrap()],
            now,
            Duration::from_secs(60),
        );

        let attribution = cache
            .attribution_for(
                "203.0.113.10".parse().unwrap(),
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(attribution.confidence(), HostnameConfidence::Medium);
        assert!(cache
            .attribution_for(
                "203.0.113.10".parse().unwrap(),
                now + Duration::from_secs(61)
            )
            .is_none());
    }

    #[test]
    fn dns_response_records_feed_attribution_cache_without_wire_types() {
        let now = Instant::now();
        let mut cache = DnsAttributionCache::default();
        cache.observe_address_records(
            [foxprox_dns::DnsAddressRecord {
                hostname: Hostname::new("example.com").unwrap(),
                addr: "203.0.113.10".parse().unwrap(),
                ttl: Duration::from_secs(30),
            }],
            now,
        );

        let attribution = cache
            .attribution_for("203.0.113.10".parse().unwrap(), now)
            .unwrap();
        assert_eq!(attribution.hostname().as_str(), "example.com");
        assert_eq!(attribution.confidence(), HostnameConfidence::Medium);
    }

    #[test]
    fn flow_table_expires_each_flow_by_stored_timeout() {
        let now = Instant::now();
        let mut table = FlowTable::default();
        let decision = PolicyDecision::Allow(foxprox_core::AllowDecision {
            rule_id: None,
            timeout_override: Some(Duration::from_secs(5)),
            reason: Some("test".into()),
        });
        let state = FlowState {
            key: FlowKey {
                source: "10.0.0.2:50000".parse().unwrap(),
                destination: "203.0.113.10:443".parse().unwrap(),
                protocol: FlowProtocol::Udp,
            },
            hostname: None,
            created_at: now,
            last_seen: now,
            idle_timeout: flow_idle_timeout(&decision, Duration::from_secs(60)),
            byte_counts: foxprox_core::ByteCounts::new(1, 2),
            decision,
        };
        table.upsert(state);

        assert!(table
            .expire_by_flow_timeout(now + Duration::from_secs(4))
            .is_empty());
        let expired = table.expire_by_flow_timeout(now + Duration::from_secs(5));
        assert_eq!(expired.len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn flow_closed_records_lifecycle_audit_without_adapter_types() {
        let now = Instant::now();
        let state = FlowState {
            key: FlowKey {
                source: "10.0.0.2:50000".parse().unwrap(),
                destination: "203.0.113.10:443".parse().unwrap(),
                protocol: FlowProtocol::Tcp,
            },
            hostname: None,
            created_at: now,
            last_seen: now + Duration::from_secs(1),
            idle_timeout: Duration::from_secs(5),
            byte_counts: foxprox_core::ByteCounts::new(100, 200),
            decision: PolicyDecision::Allow(foxprox_core::AllowDecision {
                rule_id: None,
                timeout_override: None,
                reason: Some("test".into()),
            }),
        };
        let mut audit = BoundedAuditSink::new(4);

        record_flow_closed(
            &mut audit,
            2,
            2000,
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            &state,
            now + Duration::from_secs(3),
        )
        .unwrap();

        let record = audit.records().front().unwrap();
        assert_eq!(record.kind, foxprox_audit::AuditKind::FlowClosed);
        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(
            record.byte_counts,
            Some(foxprox_core::ByteCounts::new(100, 200))
        );
        assert_eq!(record.flow_duration_millis, Some(3000));
    }

    #[test]
    fn classifies_quic_and_multicast_udp() {
        assert_eq!(
            classify_udp_destination("203.0.113.10:443".parse().unwrap()),
            UdpClassification::QuicCandidate
        );
        assert_eq!(
            classify_udp_destination("224.0.0.1:9999".parse().unwrap()),
            UdpClassification::MulticastOrBroadcast
        );
    }

    #[test]
    fn mock_frontend_event_can_be_policy_audited_and_egressed() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("tcp-80").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.port = PortMatcher::Exact(80);
        config.rules.push(rule);
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let event = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "203.0.113.10:80".parse().unwrap(),
            hostname: None,
        });

        let outcome =
            handle_normalized_event(&event, &policy, &mut egress, &mut audit, 1, 1000).unwrap();
        assert_eq!(outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(egress.tcp_connects.len(), 1);
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn allowed_http_request_reaches_shared_egress() {
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(RuleId::new("http").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Http);
        config.rules.push(rule);
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let event = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::HttpProxy,
            method: HttpMethod::Get,
            scheme: HttpScheme::Http,
            host: DestinationHost::Hostname(Hostname::new("example.com").unwrap()),
            port: 80,
            path_query: "/".to_string(),
        });

        let outcome =
            handle_normalized_event(&event, &policy, &mut egress, &mut audit, 1, 1000).unwrap();
        assert_eq!(outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(egress.http_requests.len(), 1);
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn denied_udp_does_not_reach_egress_but_is_audited() {
        let policy = PolicyEngine::new(RuntimeConfig::deny_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let event = NormalizedEvent::UdpFlowAttempt(UdpFlowAttempt {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:50000".parse().unwrap(),
            destination: "255.255.255.255:9999".parse().unwrap(),
            hostname: None,
            classification: UdpClassification::MulticastOrBroadcast,
        });

        let outcome =
            handle_normalized_event(&event, &policy, &mut egress, &mut audit, 1, 1000).unwrap();
        assert_eq!(
            outcome,
            BrokerEventOutcome::Denied(Some(DenialAction::Drop))
        );
        assert!(egress.udp_flows.is_empty());
        assert_eq!(audit.records().len(), 1);
    }
}
