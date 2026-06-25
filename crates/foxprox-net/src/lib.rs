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
use foxprox_dns::{build_address_response, build_refused_response, parse_dns_query_event};
use foxprox_egress::{
    dispatch_allowed_event, DispatchOutcome, EgressError, EgressOutcome, HostEgress, HostUdpFlow,
};
use foxprox_packet::{inspect_ipv4_packet, synthesize_ipv4_denial_response};
use foxprox_policy::PolicyEngine;

/// Network-stack adapter boundary. Implementations may use smoltcp or another
/// stack, but must emit only normalized events and opaque outbound packets.
pub trait StackAdapter {
    fn ingest_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<StackEvent>, StackError>;

    fn send_tcp_data_to_sandbox(&mut self, data: &StackTcpWrite) -> Result<usize, StackError> {
        let _ = data;
        Err(StackError::Adapter(
            "stack adapter does not support TCP write-back".into(),
        ))
    }

    fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError>;
}

/// Event emitted by a stack adapter after parsing/flow handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackEvent {
    PolicyEvent(NormalizedEvent),
    TcpData(StackTcpData),
    FlowClosed(StackFlowClosed),
}

/// Normalized TCP stream data emitted by a stack adapter after a connection is
/// accepted by the userspace stack. Raw TCP headers and stack socket objects stay
/// inside the adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackTcpData {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub bytes: Vec<u8>,
}

/// Normalized TCP stream bytes to inject into an adapter-managed sandbox flow.
/// The source/destination identify the original sandbox flow key; TCP packet
/// synthesis and socket buffering remain stack-adapter private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackTcpWrite {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub bytes: Vec<u8>,
}

/// Normalized flow lifecycle event emitted by a stack adapter without exposing
/// stack-specific socket or flow objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackFlowClosed {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub key: FlowKey,
    pub byte_counts: foxprox_core::ByteCounts,
    pub duration: Duration,
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

    /// Insert or replace a flow while enforcing a caller-provided maximum.
    /// Replacing an existing key is allowed even when the table is at capacity.
    pub fn try_upsert(&mut self, state: FlowState, max_flows: usize) -> Result<(), FlowLimitError> {
        if max_flows == 0 {
            return Err(FlowLimitError::ZeroLimit);
        }
        if self.flows.len() >= max_flows && !self.flows.contains_key(&state.key) {
            return Err(FlowLimitError::LimitReached { max_flows });
        }
        self.upsert(state);
        Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FlowLimitError {
    ZeroLimit,
    LimitReached { max_flows: usize },
}

impl fmt::Display for FlowLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit => f.write_str("flow limit must be greater than zero"),
            Self::LimitReached { max_flows } => write!(f, "flow limit {max_flows} reached"),
        }
    }
}

impl std::error::Error for FlowLimitError {}

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
    handle_normalized_event_with_egress(event, policy, egress, audit, sequence, timestamp_millis)
        .map(|evaluated| evaluated.outcome)
}

/// Process a normalized inline observation through policy and audit without
/// dispatching egress. Transparent TCP payload inspection uses this because the
/// host TCP stream was already opened through the shared egress contract.
pub fn handle_normalized_event_without_egress<A>(
    event: &NormalizedEvent,
    policy: &PolicyEngine,
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
) -> Result<PolicyAuditOutcome, BrokerError>
where
    A: AuditSink,
{
    let decision = policy.decide(event);
    let record = AuditRecord::from_event(sequence, timestamp_millis, event, &decision);
    audit.record(record).map_err(BrokerError::Audit)?;
    let outcome = if decision.is_allowed() {
        BrokerEventOutcome::NoEgressRequired
    } else {
        BrokerEventOutcome::Denied(decision_denial_action(&decision))
    };
    Ok(PolicyAuditOutcome { decision, outcome })
}

/// Process a normalized event and return the egress handle, when one was
/// created, so runtime bridge code can retain it without re-running policy or
/// opening sockets outside the shared egress boundary.
pub fn handle_normalized_event_with_egress<E, A>(
    event: &NormalizedEvent,
    policy: &PolicyEngine,
    egress: &mut E,
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
) -> Result<BrokerEventResult<E>, BrokerError>
where
    E: HostEgress,
    A: AuditSink,
{
    handle_normalized_event_with_decision(event, policy, egress, audit, sequence, timestamp_millis)
}

fn handle_normalized_event_with_decision<E, A>(
    event: &NormalizedEvent,
    policy: &PolicyEngine,
    egress: &mut E,
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
) -> Result<BrokerEventResult<E>, BrokerError>
where
    E: HostEgress,
    A: AuditSink,
{
    let decision = policy.decide(event);
    let record = AuditRecord::from_event(sequence, timestamp_millis, event, &decision);
    audit.record(record).map_err(BrokerError::Audit)?;

    let (outcome, egress_outcome) = if decision.is_allowed() {
        match dispatch_allowed_event(egress, event) {
            Ok(egress_outcome) => (BrokerEventOutcome::Forwarded, Some(egress_outcome)),
            Err(EgressError::UnsupportedAllowedEvent) => {
                (BrokerEventOutcome::NoEgressRequired, None)
            }
            Err(error) => return Err(BrokerError::Egress(error)),
        }
    } else {
        (
            BrokerEventOutcome::Denied(decision_denial_action(&decision)),
            None,
        )
    };

    Ok(BrokerEventResult {
        decision,
        outcome,
        egress_outcome,
    })
}

/// Result of policy/audit/egress handling for one normalized event.
pub struct BrokerEventResult<E: HostEgress> {
    pub decision: PolicyDecision,
    pub outcome: BrokerEventOutcome,
    pub egress_outcome: Option<DispatchOutcome<E>>,
}

/// Policy/audit result for inline observations that must not dispatch egress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAuditOutcome {
    pub decision: PolicyDecision,
    pub outcome: BrokerEventOutcome,
}

/// One inbound IPv4 packet plus the normalized session/frontend labels needed
/// to keep raw device bytes out of policy and audit APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundIpv4Packet<'a> {
    pub sandbox_id: &'a SandboxId,
    pub frontend: FrontendKind,
    pub bytes: &'a [u8],
}

/// Result of handling one inbound IPv4 packet at the packet-policy boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketBrokerOutcome {
    pub event: NormalizedEvent,
    pub decision: PolicyDecision,
    pub outcome: BrokerEventOutcome,
    pub udp_bytes_sent: usize,
    pub outbound_packets: Vec<OutboundIpPacket>,
}

/// Packet handling result that also preserves any egress handle opened while
/// processing the normalized event, for runtime flow bridge retention.
pub struct PacketBrokerResult<E: HostEgress> {
    pub event: NormalizedEvent,
    pub decision: PolicyDecision,
    pub outcome: BrokerEventOutcome,
    pub udp_bytes_sent: usize,
    pub outbound_packets: Vec<OutboundIpPacket>,
    pub egress_outcome: Option<DispatchOutcome<E>>,
}

impl<E: HostEgress> PacketBrokerResult<E> {
    pub fn into_outcome(self) -> PacketBrokerOutcome {
        PacketBrokerOutcome {
            event: self.event,
            decision: self.decision,
            outcome: self.outcome,
            udp_bytes_sent: self.udp_bytes_sent,
            outbound_packets: self.outbound_packets,
        }
    }
}

/// Normalize one inbound IPv4 packet, run policy/audit/egress, and return any
/// opaque packets that should be written back to the device frontend.
///
/// Raw packet bytes stay inside this orchestration boundary. Policy and audit
/// see only the normalized event; synthetic replies and denial packets are
/// returned as opaque `OutboundIpPacket` values for a TUN loop to write back.
pub fn handle_ipv4_packet<E, A>(
    packet: InboundIpv4Packet<'_>,
    policy: &PolicyEngine,
    egress: &mut E,
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
) -> Result<PacketBrokerOutcome, BrokerError>
where
    E: HostEgress,
    A: AuditSink,
{
    handle_ipv4_packet_with_egress(packet, policy, egress, audit, sequence, timestamp_millis)
        .map(PacketBrokerResult::into_outcome)
}

/// Normalize one inbound IPv4 packet, run policy/audit/egress, and preserve any
/// egress handle opened for runtime bridge retention.
pub fn handle_ipv4_packet_with_egress<E, A>(
    packet: InboundIpv4Packet<'_>,
    policy: &PolicyEngine,
    egress: &mut E,
    audit: &mut A,
    sequence: u64,
    timestamp_millis: u64,
) -> Result<PacketBrokerResult<E>, BrokerError>
where
    E: HostEgress,
    A: AuditSink,
{
    let inspection = inspect_ipv4_packet(packet.sandbox_id.clone(), packet.frontend, packet.bytes);
    let mut evaluated = handle_normalized_event_with_decision(
        &inspection.event,
        policy,
        egress,
        audit,
        sequence,
        timestamp_millis,
    )?;
    let mut outbound_packets = Vec::new();
    let mut udp_bytes_sent = 0;

    if evaluated.decision.is_allowed() {
        if let (Some(payload), Some(EgressOutcome::UdpOpened(udp))) =
            (&inspection.udp_payload, evaluated.egress_outcome.take())
        {
            let mut udp = udp;
            udp_bytes_sent = udp
                .send_from_sandbox(payload)
                .map_err(BrokerError::Egress)?;
            evaluated.egress_outcome = Some(EgressOutcome::UdpOpened(udp));
        }
        if let Some(reply) = inspection.synthetic_reply {
            outbound_packets
                .push(OutboundIpPacket::new(reply.bytes().to_vec()).map_err(BrokerError::Stack)?);
        }
    } else if let Some(reply) = synthesize_ipv4_denial_response(packet.bytes, &evaluated.decision)
        .map_err(BrokerError::Packet)?
    {
        outbound_packets
            .push(OutboundIpPacket::new(reply.bytes().to_vec()).map_err(BrokerError::Stack)?);
    }

    Ok(PacketBrokerResult {
        event: inspection.event,
        decision: evaluated.decision,
        outcome: evaluated.outcome,
        udp_bytes_sent,
        outbound_packets,
        egress_outcome: evaluated.egress_outcome,
    })
}

/// DNS packet handling input for the broker DNS service path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPacketRequest<'a> {
    pub sandbox_id: &'a SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub broker_dns_addrs: &'a [IpAddr],
    pub packet: &'a [u8],
    pub response_ttl: Duration,
    pub sequence: u64,
    pub timestamp_millis: u64,
}

/// Result of handling one DNS wire query through normalized policy/audit/egress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPacketOutcome {
    pub event: NormalizedEvent,
    pub decision: PolicyDecision,
    pub response: Option<Vec<u8>>,
}

/// Handle one DNS query packet without letting DNS wire data leak into policy or
/// audit. Allowed queries resolve through shared egress; denied/require-DNS
/// decisions receive a DNS REFUSED response when the query is parseable.
pub fn handle_dns_packet<E, A>(
    request: DnsPacketRequest<'_>,
    policy: &PolicyEngine,
    egress: &mut E,
    audit: &mut A,
) -> Result<DnsPacketOutcome, BrokerError>
where
    E: HostEgress,
    A: AuditSink,
{
    let event = parse_dns_query_event(
        request.sandbox_id.clone(),
        request.frontend,
        request.source,
        request.destination,
        request.broker_dns_addrs,
        request.packet,
    );
    let decision = policy.decide(&event);
    let record = AuditRecord::from_event(
        request.sequence,
        request.timestamp_millis,
        &event,
        &decision,
    );
    audit.record(record).map_err(BrokerError::Audit)?;

    let response = match (&event, decision.is_allowed()) {
        (NormalizedEvent::DnsQuery(query), true) => {
            let addrs = egress.resolve_dns(query).map_err(BrokerError::Egress)?;
            let ips = addrs.into_iter().map(|addr| addr.ip());
            Some(
                build_address_response(request.packet, ips, request.response_ttl)
                    .map_err(BrokerError::Dns)?,
            )
        }
        (_, false) => build_refused_response(request.packet).ok(),
        _ => None,
    };

    Ok(DnsPacketOutcome {
        event,
        decision,
        response,
    })
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
    Dns(foxprox_dns::DnsError),
    Egress(EgressError),
    Packet(foxprox_packet::PacketError),
    Stack(StackError),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(error) => write!(f, "audit error: {error}"),
            Self::Dns(error) => write!(f, "dns error: {error}"),
            Self::Egress(error) => write!(f, "egress error: {error}"),
            Self::Packet(error) => write!(f, "packet error: {error}"),
            Self::Stack(error) => write!(f, "stack error: {error}"),
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
    fn flow_table_enforces_configured_resource_limit() {
        let now = Instant::now();
        let mut table = FlowTable::default();
        let decision = PolicyDecision::Allow(foxprox_core::AllowDecision {
            rule_id: None,
            timeout_override: None,
            reason: Some("test".into()),
        });
        let first = FlowState {
            key: FlowKey {
                source: "10.0.0.2:50000".parse().unwrap(),
                destination: "203.0.113.10:443".parse().unwrap(),
                protocol: FlowProtocol::Tcp,
            },
            hostname: None,
            created_at: now,
            last_seen: now,
            idle_timeout: Duration::from_secs(60),
            byte_counts: foxprox_core::ByteCounts::default(),
            decision: decision.clone(),
        };
        let mut replacement = first.clone();
        replacement.byte_counts = foxprox_core::ByteCounts::new(10, 20);
        let second = FlowState {
            key: FlowKey {
                source: "10.0.0.2:50001".parse().unwrap(),
                destination: "203.0.113.11:443".parse().unwrap(),
                protocol: FlowProtocol::Tcp,
            },
            decision,
            ..first.clone()
        };
        let max_flows = RuntimeConfig::deny_by_default()
            .resource_limits
            .max_flows
            .min(1);

        table.try_upsert(first.clone(), max_flows).unwrap();
        table.try_upsert(replacement, max_flows).unwrap();
        assert_eq!(table.get(&first.key).unwrap().byte_counts.ingress, 10);
        assert_eq!(
            table.try_upsert(second, max_flows),
            Err(FlowLimitError::LimitReached { max_flows })
        );
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

    #[test]
    fn allowed_dns_packet_resolves_through_shared_egress_and_builds_response() {
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MockEgress {
            dns_results: vec!["203.0.113.10:0".parse().unwrap()],
            ..MockEgress::default()
        };
        let mut audit = BoundedAuditSink::new(8);
        let sandbox_id = SandboxId::new("s1").unwrap();
        let packet = dns_query_packet(0x1234, "example.com", 1);

        let outcome = handle_dns_packet(
            DnsPacketRequest {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                source: "10.0.0.2:53000".parse().unwrap(),
                destination: "10.255.0.1:53".parse().unwrap(),
                broker_dns_addrs: &["10.255.0.1".parse().unwrap()],
                packet: &packet,
                response_ttl: Duration::from_secs(60),
                sequence: 3,
                timestamp_millis: 3000,
            },
            &policy,
            &mut egress,
            &mut audit,
        )
        .unwrap();

        assert!(outcome.decision.is_allowed());
        assert_eq!(egress.dns_queries.len(), 1);
        assert_eq!(audit.records().len(), 1);
        let response = outcome.response.unwrap();
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
    }

    #[test]
    fn denied_dns_packet_returns_refused_without_egress() {
        let policy = PolicyEngine::new(RuntimeConfig::deny_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let sandbox_id = SandboxId::new("s1").unwrap();
        let packet = dns_query_packet(0x1234, "example.com", 1);

        let outcome = handle_dns_packet(
            DnsPacketRequest {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                source: "10.0.0.2:53000".parse().unwrap(),
                destination: "9.9.9.9:53".parse().unwrap(),
                broker_dns_addrs: &["10.255.0.1".parse().unwrap()],
                packet: &packet,
                response_ttl: Duration::from_secs(60),
                sequence: 4,
                timestamp_millis: 4000,
            },
            &policy,
            &mut egress,
            &mut audit,
        )
        .unwrap();

        assert!(matches!(
            outcome.decision,
            PolicyDecision::RequireBrokerDns { .. }
        ));
        assert!(egress.dns_queries.is_empty());
        assert_eq!(audit.records().len(), 1);
        let response = outcome.response.unwrap();
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 5);
    }

    #[test]
    fn allowed_icmp_echo_packet_returns_synthetic_reply_after_policy() {
        let mut config = RuntimeConfig::deny_by_default();
        config.allow_ping = true;
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let packet = echo_request_packet();

        let sandbox_id = SandboxId::new("s1").unwrap();
        let outcome = handle_ipv4_packet(
            InboundIpv4Packet {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                bytes: &packet,
            },
            &policy,
            &mut egress,
            &mut audit,
            1,
            1000,
        )
        .unwrap();

        assert_eq!(outcome.outcome, BrokerEventOutcome::NoEgressRequired);
        assert!(outcome.decision.is_allowed());
        assert_eq!(outcome.outbound_packets.len(), 1);
        assert_eq!(outcome.outbound_packets[0].bytes()[20], 0);
        assert_eq!(audit.records().len(), 1);
        assert!(egress.tcp_connects.is_empty());
        assert!(egress.udp_flows.is_empty());
    }

    #[test]
    fn allowed_udp_packet_sends_payload_through_shared_egress() {
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let sandbox_id = SandboxId::new("s1").unwrap();
        let packet = udp_packet(53000, 12345, b"ping");

        let outcome = handle_ipv4_packet(
            InboundIpv4Packet {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                bytes: &packet,
            },
            &policy,
            &mut egress,
            &mut audit,
            5,
            5000,
        )
        .unwrap();

        assert_eq!(outcome.outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(outcome.udp_bytes_sent, 4);
        assert_eq!(egress.udp_flows.len(), 1);
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn denied_udp_packet_can_synthesize_policy_icmp_unreachable() {
        let mut config = RuntimeConfig::allow_by_default();
        let mut rule = PolicyRule::deny(
            RuleId::new("udp-admin-deny").unwrap(),
            DenialAction::IcmpUnreachable,
        );
        rule.protocol = ProtocolMatcher::Exact(Protocol::Udp);
        rule.port = PortMatcher::Exact(12345);
        config.rules.push(rule);
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let packet = udp_packet(53000, 12345, &[1, 2, 3, 4]);

        let sandbox_id = SandboxId::new("s1").unwrap();
        let outcome = handle_ipv4_packet(
            InboundIpv4Packet {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                bytes: &packet,
            },
            &policy,
            &mut egress,
            &mut audit,
            2,
            2000,
        )
        .unwrap();

        assert_eq!(
            outcome.outcome,
            BrokerEventOutcome::Denied(Some(DenialAction::IcmpUnreachable))
        );
        assert_eq!(outcome.outbound_packets.len(), 1);
        assert_eq!(outcome.outbound_packets[0].bytes()[20], 3);
        assert_eq!(outcome.outbound_packets[0].bytes()[21], 13);
        assert!(egress.udp_flows.is_empty());
        assert_eq!(audit.records().len(), 1);
    }

    fn dns_query_packet(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        for label in hostname.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn echo_request_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[26..28].copy_from_slice(&1_u16.to_be_bytes());
        finish_ipv4_packet(packet)
    }

    fn udp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 10]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        finish_ipv4_packet(packet)
    }

    fn finish_ipv4_packet(mut packet: Vec<u8>) -> Vec<u8> {
        let ip_checksum = foxprox_packet::internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        if packet[9] == 1 {
            let icmp_checksum = foxprox_packet::internet_checksum(&packet[20..]);
            packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        }
        packet
    }
}
