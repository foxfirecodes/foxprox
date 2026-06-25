//! Runtime orchestration for foxprox broker loops.
//!
//! This crate wires device IO to packet-policy orchestration. It owns no policy
//! model and does not parse raw packets itself.

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use foxprox_audit::{AuditRecord, AuditSink, FlowClosedAudit};
use foxprox_core::{
    DenialAction, FrontendKind, NormalizedEvent, ParserLimits, Protocol, SandboxId,
    TcpConnectAttempt, UdpFlowAttempt, UdpTimeouts,
};
use foxprox_device::{DeviceError, DevicePacket, PacketDevice, TryPacketDevice};
use foxprox_egress::{
    EgressError, EgressOutcome, HostEgress, HostHttpResponse, HostTcpStream, HostUdpFlow,
};
use foxprox_net::{
    apply_dns_attribution, handle_ipv4_dns_service_packet, handle_ipv4_packet,
    handle_ipv4_packet_with_egress, handle_ipv6_dns_service_packet, handle_ipv6_packet,
    handle_ipv6_packet_with_egress, handle_normalized_event_with_egress,
    handle_normalized_event_without_egress, udp_timeout, BrokerError, BrokerEventOutcome,
    DnsAttributionCache, FlowProtocol, InboundIpv4Packet, InboundIpv6Packet, Ipv4DnsServiceRequest,
    Ipv6DnsServiceRequest, OutboundIpPacket, PacketBrokerOutcome, StackAdapter, StackEvent,
    StackTcpData, StackTcpWrite,
};
use foxprox_policy::PolicyEngine;

/// Context needed to process one packet from a device without widening function
/// parameters or leaking raw packet buffers to policy/audit.
pub struct DevicePacketStep<'a, E, A> {
    pub sandbox_id: &'a SandboxId,
    pub frontend: FrontendKind,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub sequence: u64,
    pub timestamp_millis: u64,
}

pub struct ExplicitHttpProxyStep<'a, E, A> {
    pub sandbox_id: &'a SandboxId,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub parser_limits: ParserLimits,
    pub max_response_bytes: usize,
    pub sequence: u64,
    pub timestamp_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitHttpProxyOutcome {
    pub event: NormalizedEvent,
    pub broker_outcome: BrokerEventOutcome,
    pub response_bytes_written: usize,
    pub connected_tunnel: bool,
}

/// Process one bounded explicit HTTP proxy request from a client stream.
///
/// This step keeps listener/session IO in runtime, parsing in frontends, policy
/// and audit in net/policy/audit, and host networking in egress. It intentionally
/// handles one request head; full-duplex CONNECT tunneling can reuse the returned
/// egress TCP stream contract in a later pump.
pub fn process_one_http_proxy_request<Io, E, A>(
    io: &mut Io,
    step: ExplicitHttpProxyStep<'_, E, A>,
) -> Result<ExplicitHttpProxyOutcome, RuntimeError>
where
    Io: Read + Write,
    E: HostEgress,
    E::HttpResponse: HostHttpResponse,
    A: AuditSink,
{
    let request = read_http_proxy_head(io, step.parser_limits.max_http_request_head_bytes)
        .map_err(RuntimeError::ProxyIo)?;
    let event = foxprox_frontends::parse_http_request_with_limits(
        step.sandbox_id.clone(),
        FrontendKind::HttpProxy,
        &request,
        step.parser_limits,
    );
    let mut result = handle_normalized_event_with_egress(
        &event,
        step.policy,
        step.egress,
        step.audit,
        step.sequence,
        step.timestamp_millis,
    )
    .map_err(RuntimeError::Broker)?;

    let mut response_bytes_written = 0;
    let mut connected_tunnel = false;
    match result.egress_outcome.take() {
        Some(EgressOutcome::HttpForwarded(mut response)) if result.decision.is_allowed() => {
            let bytes = response
                .read_to_proxy_client(step.max_response_bytes)
                .map_err(BrokerError::Egress)
                .map_err(RuntimeError::Broker)?;
            if !bytes.is_empty() {
                io.write_all(&bytes).map_err(RuntimeError::ProxyIo)?;
                response_bytes_written = bytes.len();
            }
        }
        Some(EgressOutcome::TcpConnected(_stream)) if result.decision.is_allowed() => {
            let established = b"HTTP/1.1 200 Connection Established\r\n\r\n";
            io.write_all(established).map_err(RuntimeError::ProxyIo)?;
            response_bytes_written = established.len();
            connected_tunnel = true;
        }
        _ if !result.decision.is_allowed() => {
            let status = match result.outcome {
                BrokerEventOutcome::Denied(Some(DenialAction::Reset)) => {
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".as_slice()
                }
                _ => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".as_slice(),
            };
            io.write_all(status).map_err(RuntimeError::ProxyIo)?;
            response_bytes_written = status.len();
        }
        _ => {}
    }

    Ok(ExplicitHttpProxyOutcome {
        event,
        broker_outcome: result.outcome,
        response_bytes_written,
        connected_tunnel,
    })
}

fn read_http_proxy_head<Io: Read>(
    io: &mut Io,
    max_bytes: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    while bytes.len() < max_bytes {
        match io.read(&mut one) {
            Ok(0) => break,
            Ok(_) => {
                bytes.push(one[0]);
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(bytes)
}

/// Read one IPv4 packet from `device`, run it through the existing normalized
/// packet/policy/audit/egress boundary, and write any returned opaque outbound
/// packets back to the same device.
pub fn process_one_ipv4_device_packet<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStep<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    process_ipv4_device_packet(device, packet, ctx)
}

/// Try to process one IPv4 packet without blocking on an idle device. `Ok(None)`
/// means no packet was ready, so callers can still run bridge maintenance.
pub fn process_one_ipv4_device_packet_if_ready<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStep<'_, E, A>,
) -> Result<Option<PacketBrokerOutcome>, RuntimeError>
where
    D: TryPacketDevice,
    E: HostEgress,
    A: AuditSink,
{
    let Some(packet) = device.try_read_packet().map_err(RuntimeError::Device)? else {
        return Ok(None);
    };
    process_ipv4_device_packet(device, packet, ctx).map(Some)
}

fn process_ipv4_device_packet<D, E, A>(
    device: &mut D,
    packet: DevicePacket,
    ctx: DevicePacketStep<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    A: AuditSink,
{
    let outcome = handle_ipv4_packet(
        InboundIpv4Packet {
            sandbox_id: ctx.sandbox_id,
            frontend: ctx.frontend,
            bytes: packet.bytes(),
        },
        ctx.policy,
        ctx.egress,
        ctx.audit,
        ctx.sequence,
        ctx.timestamp_millis,
    )
    .map_err(RuntimeError::Broker)?;

    write_outbound_packets(device, &outcome.outbound_packets)?;

    Ok(outcome)
}

/// Read one IPv6 packet from `device`, run it through the normalized
/// packet/policy/audit/egress boundary, and write any returned opaque outbound
/// packets back to the same device.
pub fn process_one_ipv6_device_packet<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStep<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    process_ipv6_device_packet(device, packet, ctx)
}

/// Try to process one IPv6 packet without blocking on an idle device.
pub fn process_one_ipv6_device_packet_if_ready<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStep<'_, E, A>,
) -> Result<Option<PacketBrokerOutcome>, RuntimeError>
where
    D: TryPacketDevice,
    E: HostEgress,
    A: AuditSink,
{
    let Some(packet) = device.try_read_packet().map_err(RuntimeError::Device)? else {
        return Ok(None);
    };
    process_ipv6_device_packet(device, packet, ctx).map(Some)
}

fn process_ipv6_device_packet<D, E, A>(
    device: &mut D,
    packet: DevicePacket,
    ctx: DevicePacketStep<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    A: AuditSink,
{
    let outcome = handle_ipv6_packet(
        InboundIpv6Packet {
            sandbox_id: ctx.sandbox_id,
            frontend: ctx.frontend,
            bytes: packet.bytes(),
        },
        ctx.policy,
        ctx.egress,
        ctx.audit,
        ctx.sequence,
        ctx.timestamp_millis,
    )
    .map_err(RuntimeError::Broker)?;

    write_outbound_packets(device, &outcome.outbound_packets)?;

    Ok(outcome)
}

/// Normalized key for a UDP pseudo-flow bridged to a host egress UDP handle.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UdpFlowKey {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl UdpFlowKey {
    pub fn from_attempt(event: &UdpFlowAttempt) -> Self {
        Self {
            sandbox_id: event.sandbox_id.clone(),
            frontend: event.frontend,
            source: event.source,
            destination: event.destination,
        }
    }
}

/// Runtime-owned UDP flow table. It stores only egress-owned UDP handles behind
/// the shared `HostUdpFlow` contract.
pub const DEFAULT_UDP_BRIDGE_IDLE_TIMEOUT_MILLIS: u64 = 60_000;
pub const DEFAULT_MAX_UDP_BRIDGES: usize = 4096;
pub const DEFAULT_MAX_UDP_BRIDGES_PER_SANDBOX: usize = 1024;
pub const DEFAULT_MAX_TCP_BRIDGES: usize = 4096;
pub const DEFAULT_MAX_TCP_BRIDGES_PER_SANDBOX: usize = 1024;
pub const DEFAULT_MAX_TCP_BRIDGES_PER_TICK: usize = 64;
pub const DEFAULT_MAX_UDP_BRIDGES_PER_TICK: usize = 64;
pub const DEFAULT_MAX_TCP_BRIDGES_PER_SANDBOX_PER_TICK: usize = 16;
pub const DEFAULT_MAX_UDP_BRIDGES_PER_SANDBOX_PER_TICK: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeMaintenanceBudget {
    pub max_tcp_streams_per_tick: usize,
    pub max_udp_flows_per_tick: usize,
    pub max_tcp_streams_per_sandbox_per_tick: usize,
    pub max_udp_flows_per_sandbox_per_tick: usize,
    pub max_tcp_bytes_per_sandbox_per_tick: usize,
    pub max_udp_bytes_per_sandbox_per_tick: usize,
}

impl Default for BridgeMaintenanceBudget {
    fn default() -> Self {
        Self {
            max_tcp_streams_per_tick: DEFAULT_MAX_TCP_BRIDGES_PER_TICK,
            max_udp_flows_per_tick: DEFAULT_MAX_UDP_BRIDGES_PER_TICK,
            max_tcp_streams_per_sandbox_per_tick: DEFAULT_MAX_TCP_BRIDGES_PER_SANDBOX_PER_TICK,
            max_udp_flows_per_sandbox_per_tick: DEFAULT_MAX_UDP_BRIDGES_PER_SANDBOX_PER_TICK,
            max_tcp_bytes_per_sandbox_per_tick: usize::MAX,
            max_udp_bytes_per_sandbox_per_tick: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpBridgeLimits {
    pub max_flows: usize,
    pub max_flows_per_sandbox: usize,
}

impl Default for UdpBridgeLimits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_UDP_BRIDGES,
            max_flows_per_sandbox: DEFAULT_MAX_UDP_BRIDGES_PER_SANDBOX,
        }
    }
}

pub struct UdpBridgeTable<U> {
    flows: HashMap<UdpFlowKey, UdpBridge<U>>,
    limits: UdpBridgeLimits,
    read_cursor: usize,
}

struct UdpBridge<U> {
    flow: U,
    last_activity_millis: u64,
    idle_timeout_millis: u64,
}

impl<U> Default for UdpBridgeTable<U> {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            limits: UdpBridgeLimits::default(),
            read_cursor: 0,
        }
    }
}

impl<U> UdpBridgeTable<U> {
    pub fn with_limits(limits: UdpBridgeLimits) -> Self {
        Self {
            flows: HashMap::new(),
            limits,
            read_cursor: 0,
        }
    }

    pub fn limits(&self) -> UdpBridgeLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn read_cursor(&self) -> usize {
        self.read_cursor
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn contains_key(&self, key: &UdpFlowKey) -> bool {
        self.flows.contains_key(key)
    }

    pub fn insert(&mut self, key: UdpFlowKey, flow: U) -> Option<U> {
        self.insert_with_timeout(key, flow, 0, DEFAULT_UDP_BRIDGE_IDLE_TIMEOUT_MILLIS)
    }

    pub fn insert_with_timeout(
        &mut self,
        key: UdpFlowKey,
        flow: U,
        now_millis: u64,
        idle_timeout_millis: u64,
    ) -> Option<U> {
        self.try_insert_with_timeout(key, flow, now_millis, idle_timeout_millis)
            .expect("default UDP bridge limits exceeded")
    }

    pub fn try_insert_with_timeout(
        &mut self,
        key: UdpFlowKey,
        flow: U,
        now_millis: u64,
        idle_timeout_millis: u64,
    ) -> Result<Option<U>, EgressError> {
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.limits.max_flows {
                return Err(EgressError::StreamIo(
                    "UDP bridge flow limit exceeded".into(),
                ));
            }
            let sandbox_flows = self
                .flows
                .keys()
                .filter(|existing| existing.sandbox_id == key.sandbox_id)
                .count();
            if sandbox_flows >= self.limits.max_flows_per_sandbox {
                return Err(EgressError::StreamIo(
                    "UDP bridge sandbox flow limit exceeded".into(),
                ));
            }
        }
        Ok(self
            .flows
            .insert(
                key,
                UdpBridge {
                    flow,
                    last_activity_millis: now_millis,
                    idle_timeout_millis,
                },
            )
            .map(|bridge| bridge.flow))
    }

    pub fn remove(&mut self, key: &UdpFlowKey) -> Option<U> {
        self.flows.remove(key).map(|bridge| bridge.flow)
    }

    pub fn expire_idle(&mut self, now_millis: u64) -> usize {
        let before = self.flows.len();
        self.flows.retain(|_, bridge| {
            now_millis.saturating_sub(bridge.last_activity_millis) < bridge.idle_timeout_millis
        });
        before - self.flows.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpBridgeReadOutcome {
    pub udp_flows_read: usize,
    pub udp_bytes_read_from_egress: usize,
    pub udp_flows_removed_on_error: usize,
    pub outbound_packets_written: usize,
}

/// Read host UDP replies from retained flow handles, synthesize opaque IPv4 UDP
/// packets, and write them to the device.
pub fn flush_udp_bridge_reads_to_device<D, U>(
    device: &mut D,
    bridges: &mut UdpBridgeTable<U>,
    max_bytes_per_flow: usize,
    now_millis: u64,
) -> Result<UdpBridgeReadOutcome, RuntimeError>
where
    D: PacketDevice,
    U: HostUdpFlow,
{
    flush_udp_bridge_reads_to_device_with_limit(
        device,
        bridges,
        max_bytes_per_flow,
        usize::MAX,
        now_millis,
    )
}

/// Read host UDP replies from at most `max_flows` retained flow handles.
pub fn flush_udp_bridge_reads_to_device_with_limit<D, U>(
    device: &mut D,
    bridges: &mut UdpBridgeTable<U>,
    max_bytes_per_flow: usize,
    max_flows: usize,
    now_millis: u64,
) -> Result<UdpBridgeReadOutcome, RuntimeError>
where
    D: PacketDevice,
    U: HostUdpFlow,
{
    flush_udp_bridge_reads_to_device_with_fairness(
        device,
        bridges,
        max_bytes_per_flow,
        max_flows,
        usize::MAX,
        usize::MAX,
        now_millis,
    )
}

fn flush_udp_bridge_reads_to_device_with_fairness<D, U>(
    device: &mut D,
    bridges: &mut UdpBridgeTable<U>,
    max_bytes_per_flow: usize,
    max_flows: usize,
    max_flows_per_sandbox: usize,
    max_bytes_per_sandbox: usize,
    now_millis: u64,
) -> Result<UdpBridgeReadOutcome, RuntimeError>
where
    D: PacketDevice,
    U: HostUdpFlow,
{
    let mut replies = Vec::new();
    let mut failed_flows = Vec::new();
    let mut keys: Vec<_> = bridges.flows.keys().cloned().collect();
    keys.sort_by_key(|key| format!("{key:?}"));
    let flow_count = keys.len();
    let start = if flow_count == 0 {
        0
    } else {
        bridges.read_cursor % flow_count
    };
    let mut selected = 0;
    let mut visited = 0;
    let mut per_sandbox = HashMap::<SandboxId, usize>::new();
    let mut bytes_per_sandbox = HashMap::<SandboxId, usize>::new();
    while visited < flow_count && selected < max_flows {
        let key = keys[(start + visited) % flow_count].clone();
        visited += 1;
        let sandbox_count = per_sandbox.entry(key.sandbox_id.clone()).or_default();
        if *sandbox_count >= max_flows_per_sandbox {
            continue;
        }
        let sandbox_bytes = bytes_per_sandbox.entry(key.sandbox_id.clone()).or_default();
        let remaining_bytes = max_bytes_per_sandbox.saturating_sub(*sandbox_bytes);
        if remaining_bytes == 0 {
            continue;
        }
        *sandbox_count += 1;
        selected += 1;
        let Some(bridge) = bridges.flows.get_mut(&key) else {
            continue;
        };
        match bridge
            .flow
            .recv_to_sandbox(max_bytes_per_flow.min(remaining_bytes))
        {
            Ok(bytes) if !bytes.is_empty() => {
                bridge.last_activity_millis = now_millis;
                *sandbox_bytes += bytes.len();
                replies.push((key.clone(), bytes));
            }
            Ok(_) => {}
            Err(error) => {
                let same_family = matches!(
                    (key.source.ip(), key.destination.ip()),
                    (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                        | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
                );
                if same_family {
                    failed_flows.push(key.clone());
                } else {
                    return Err(RuntimeError::Broker(BrokerError::Egress(error)));
                }
            }
        }
    }
    if flow_count > 0 {
        bridges.read_cursor = (start + visited) % flow_count;
    }

    let udp_flows_read = replies.len();
    let udp_flows_removed_on_error = failed_flows.len();
    let mut udp_bytes_read_from_egress = 0;
    let mut outbound_packets_written = 0;
    for (key, bytes) in replies {
        udp_bytes_read_from_egress += bytes.len();
        let packet = match (key.source.ip(), key.destination.ip()) {
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => {
                foxprox_packet::synthesize_udp_ipv4_response(key.source, key.destination, &bytes)
            }
            (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => {
                foxprox_packet::synthesize_udp_ipv6_response(key.source, key.destination, &bytes)
            }
            _ => Err(foxprox_packet::PacketError::unsupported(
                "udp bridge response address families differ",
            )),
        }
        .map_err(BrokerError::Packet)
        .map_err(RuntimeError::Broker)?;
        let outbound =
            OutboundIpPacket::new(packet.bytes().to_vec()).map_err(RuntimeError::Stack)?;
        write_outbound_packets(device, &[outbound])?;
        outbound_packets_written += 1;
    }
    for key in failed_flows {
        bridges.remove(&key);
        let packet = match (key.source.ip(), key.destination.ip()) {
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => {
                foxprox_packet::synthesize_udp_ipv4_unreachable_from_flow(
                    key.source,
                    key.destination,
                    3,
                )
            }
            (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => {
                foxprox_packet::synthesize_udp_ipv6_unreachable_from_flow(
                    key.source,
                    key.destination,
                    4,
                )
            }
            _ => Err(foxprox_packet::PacketError::unsupported(
                "udp bridge error address families differ",
            )),
        }
        .map_err(BrokerError::Packet)
        .map_err(RuntimeError::Broker)?;
        let outbound =
            OutboundIpPacket::new(packet.bytes().to_vec()).map_err(RuntimeError::Stack)?;
        write_outbound_packets(device, &[outbound])?;
        outbound_packets_written += 1;
    }

    Ok(UdpBridgeReadOutcome {
        udp_flows_read,
        udp_bytes_read_from_egress,
        udp_flows_removed_on_error,
        outbound_packets_written,
    })
}

#[derive(Clone, Copy)]
pub struct StackDnsAttribution<'a> {
    pub cache: &'a DnsAttributionCache,
    pub now: Instant,
}

pub struct StackRuntimeTickStep<'a, S, E, A, U>
where
    E: HostEgress,
{
    pub adapter: &'a mut S,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub tcp_bridges: &'a mut StackTcpBridgeTable<E::TcpStream>,
    pub udp_bridges: &'a mut UdpBridgeTable<U>,
    pub sequence_start: u64,
    pub timestamp_millis: u64,
    pub dns_attribution: Option<StackDnsAttribution<'a>>,
    pub max_tcp_read_bytes_per_stream: usize,
    pub max_udp_read_bytes_per_flow: usize,
    pub budget: BridgeMaintenanceBudget,
    pub now_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackRuntimeTickOutcome {
    pub stack_packet: Option<StackDevicePacketOutcome>,
    pub maintenance: BridgeMaintenanceOutcome,
}

impl StackRuntimeTickOutcome {
    pub fn made_progress(&self) -> bool {
        self.stack_packet.is_some()
            || self.maintenance.tcp_pending_bytes_written_to_egress > 0
            || self.maintenance.tcp_streams_read > 0
            || self.maintenance.udp_flows_read > 0
            || self.maintenance.udp_flows_removed_on_error > 0
            || self.maintenance.udp_flows_expired > 0
            || self.maintenance.outbound_packets_written > 0
    }

    pub fn sequence_slots_used(&self) -> u64 {
        let Some(packet) = &self.stack_packet else {
            return 0;
        };
        let audited_events = packet
            .broker_outcomes
            .len()
            .saturating_add(packet.transparent_inspection_events)
            .saturating_add(packet.flow_closed_events);
        audited_events as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackRuntimeLoopConfig {
    pub max_ticks: usize,
    pub max_idle_ticks: Option<usize>,
    pub tick_millis: u64,
    pub max_tcp_read_bytes_per_stream: usize,
    pub max_udp_read_bytes_per_flow: usize,
    pub budget: BridgeMaintenanceBudget,
}

impl Default for StackRuntimeLoopConfig {
    fn default() -> Self {
        Self {
            max_ticks: 1024,
            max_idle_ticks: None,
            tick_millis: 10,
            max_tcp_read_bytes_per_stream: 16 * 1024,
            max_udp_read_bytes_per_flow: 2048,
            budget: BridgeMaintenanceBudget::default(),
        }
    }
}

pub struct StackRuntimeLoopStep<'a, S, E, A, U>
where
    E: HostEgress,
{
    pub adapter: &'a mut S,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub tcp_bridges: &'a mut StackTcpBridgeTable<E::TcpStream>,
    pub udp_bridges: &'a mut UdpBridgeTable<U>,
    pub dns_attribution: Option<StackDnsAttribution<'a>>,
    pub config: StackRuntimeLoopConfig,
    pub sequence_start: u64,
    pub timestamp_millis: u64,
    pub now_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackRuntimeLoopOutcome {
    pub ticks_run: usize,
    pub progress_ticks: usize,
    pub idle_ticks: usize,
    pub next_sequence: u64,
    pub next_timestamp_millis: u64,
    pub next_now_millis: u64,
    pub device_packets_processed: usize,
    pub maintenance: BridgeMaintenanceOutcome,
}

/// Run a bounded nonblocking stack runtime loop. This is the production-facing
/// scheduler primitive: it repeatedly checks device readiness via
/// `TryPacketDevice`, always runs bridge maintenance, advances audit sequence
/// numbers, and can return after a configured idle streak for cooperative
/// shutdown or outer OS-readiness waits.
pub fn run_stack_runtime_loop<D, S, E, A, U>(
    device: &mut D,
    step: StackRuntimeLoopStep<'_, S, E, A, U>,
) -> Result<StackRuntimeLoopOutcome, RuntimeError>
where
    D: TryPacketDevice,
    S: StackAdapter,
    E: HostEgress,
    E::TcpStream: HostTcpStream,
    A: AuditSink,
    U: HostUdpFlow,
{
    let StackRuntimeLoopStep {
        adapter,
        policy,
        egress,
        audit,
        tcp_bridges,
        udp_bridges,
        dns_attribution,
        config,
        mut sequence_start,
        mut timestamp_millis,
        mut now_millis,
    } = step;

    let mut outcome = StackRuntimeLoopOutcome {
        ticks_run: 0,
        progress_ticks: 0,
        idle_ticks: 0,
        next_sequence: sequence_start,
        next_timestamp_millis: timestamp_millis,
        next_now_millis: now_millis,
        device_packets_processed: 0,
        maintenance: BridgeMaintenanceOutcome::default(),
    };

    for tick_index in 0..config.max_ticks {
        let tick_dns = dns_attribution.map(|attribution| StackDnsAttribution {
            cache: attribution.cache,
            now: attribution.now + Duration::from_millis(config.tick_millis * tick_index as u64),
        });
        let tick = process_stack_runtime_tick(
            device,
            StackRuntimeTickStep {
                adapter,
                policy,
                egress,
                audit,
                tcp_bridges,
                udp_bridges,
                sequence_start,
                timestamp_millis,
                dns_attribution: tick_dns,
                max_tcp_read_bytes_per_stream: config.max_tcp_read_bytes_per_stream,
                max_udp_read_bytes_per_flow: config.max_udp_read_bytes_per_flow,
                budget: config.budget,
                now_millis,
            },
        )?;

        outcome.ticks_run += 1;
        if tick.stack_packet.is_some() {
            outcome.device_packets_processed += 1;
        }
        outcome.maintenance.accumulate(&tick.maintenance);
        let sequence_slots = tick.sequence_slots_used().max(1);
        sequence_start = sequence_start.saturating_add(sequence_slots);
        timestamp_millis = timestamp_millis.saturating_add(config.tick_millis);
        now_millis = now_millis.saturating_add(config.tick_millis);
        outcome.next_sequence = sequence_start;
        outcome.next_timestamp_millis = timestamp_millis;
        outcome.next_now_millis = now_millis;

        if tick.made_progress() {
            outcome.progress_ticks += 1;
            outcome.idle_ticks = 0;
        } else {
            outcome.idle_ticks += 1;
            if config
                .max_idle_ticks
                .is_some_and(|max_idle| outcome.idle_ticks >= max_idle)
            {
                break;
            }
        }
    }

    Ok(outcome)
}

/// Run one nonblocking stack runtime tick: optionally ingest one device packet,
/// then always flush bridge maintenance.
pub fn process_stack_runtime_tick<D, S, E, A, U>(
    device: &mut D,
    step: StackRuntimeTickStep<'_, S, E, A, U>,
) -> Result<StackRuntimeTickOutcome, RuntimeError>
where
    D: TryPacketDevice,
    S: StackAdapter,
    E: HostEgress,
    E::TcpStream: HostTcpStream,
    A: AuditSink,
    U: HostUdpFlow,
{
    let StackRuntimeTickStep {
        adapter,
        policy,
        egress,
        audit,
        tcp_bridges,
        udp_bridges,
        sequence_start,
        timestamp_millis,
        dns_attribution,
        max_tcp_read_bytes_per_stream,
        max_udp_read_bytes_per_flow,
        budget,
        now_millis,
    } = step;

    let stack_packet = process_one_stack_device_packet_if_ready(
        device,
        StackDevicePacketStep {
            adapter,
            policy,
            egress,
            audit,
            tcp_bridges,
            sequence_start,
            timestamp_millis,
            dns_attribution,
        },
    )?;
    let maintenance = process_bridge_maintenance_tick(
        device,
        BridgeMaintenanceStep {
            adapter,
            tcp_bridges,
            udp_bridges,
            max_tcp_read_bytes_per_stream,
            max_udp_read_bytes_per_flow,
            budget,
            now_millis,
        },
    )?;

    Ok(StackRuntimeTickOutcome {
        stack_packet,
        maintenance,
    })
}

pub struct BridgeMaintenanceStep<'a, S, T, U> {
    pub adapter: &'a mut S,
    pub tcp_bridges: &'a mut StackTcpBridgeTable<T>,
    pub udp_bridges: &'a mut UdpBridgeTable<U>,
    pub max_tcp_read_bytes_per_stream: usize,
    pub max_udp_read_bytes_per_flow: usize,
    pub budget: BridgeMaintenanceBudget,
    pub now_millis: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BridgeMaintenanceOutcome {
    pub tcp_pending_bytes_written_to_egress: usize,
    pub tcp_streams_read: usize,
    pub tcp_bytes_read_from_egress: usize,
    pub tcp_bytes_enqueued_to_stack: usize,
    pub udp_flows_read: usize,
    pub udp_bytes_read_from_egress: usize,
    pub udp_flows_removed_on_error: usize,
    pub udp_flows_expired: usize,
    pub outbound_packets_written: usize,
}

impl BridgeMaintenanceOutcome {
    pub fn accumulate(&mut self, other: &Self) {
        self.tcp_pending_bytes_written_to_egress += other.tcp_pending_bytes_written_to_egress;
        self.tcp_streams_read += other.tcp_streams_read;
        self.tcp_bytes_read_from_egress += other.tcp_bytes_read_from_egress;
        self.tcp_bytes_enqueued_to_stack += other.tcp_bytes_enqueued_to_stack;
        self.udp_flows_read += other.udp_flows_read;
        self.udp_bytes_read_from_egress += other.udp_bytes_read_from_egress;
        self.udp_flows_removed_on_error += other.udp_flows_removed_on_error;
        self.udp_flows_expired += other.udp_flows_expired;
        self.outbound_packets_written += other.outbound_packets_written;
    }
}

/// Flush bridge state once without reading a new device packet or invoking
/// policy. This is the synchronous maintenance primitive for a future event loop.
pub fn process_bridge_maintenance_tick<D, S, T, U>(
    device: &mut D,
    step: BridgeMaintenanceStep<'_, S, T, U>,
) -> Result<BridgeMaintenanceOutcome, RuntimeError>
where
    D: PacketDevice,
    S: StackAdapter,
    T: HostTcpStream,
    U: HostUdpFlow,
{
    let tcp_pending_bytes_written_to_egress = step
        .tcp_bridges
        .flush_pending_sandbox_writes()
        .map_err(BrokerError::Egress)
        .map_err(RuntimeError::Broker)?;
    let tcp = flush_tcp_bridge_reads_to_stack_device_with_fairness(
        device,
        step.adapter,
        step.tcp_bridges,
        step.max_tcp_read_bytes_per_stream,
        step.budget.max_tcp_streams_per_tick,
        step.budget.max_tcp_streams_per_sandbox_per_tick,
        step.budget.max_tcp_bytes_per_sandbox_per_tick,
    )?;
    let udp = flush_udp_bridge_reads_to_device_with_fairness(
        device,
        step.udp_bridges,
        step.max_udp_read_bytes_per_flow,
        step.budget.max_udp_flows_per_tick,
        step.budget.max_udp_flows_per_sandbox_per_tick,
        step.budget.max_udp_bytes_per_sandbox_per_tick,
        step.now_millis,
    )?;
    let udp_flows_expired = step.udp_bridges.expire_idle(step.now_millis);

    Ok(BridgeMaintenanceOutcome {
        tcp_pending_bytes_written_to_egress,
        tcp_streams_read: tcp.tcp_streams_read,
        tcp_bytes_read_from_egress: tcp.tcp_bytes_read_from_egress,
        tcp_bytes_enqueued_to_stack: tcp.tcp_bytes_enqueued_to_stack,
        udp_flows_read: udp.udp_flows_read,
        udp_bytes_read_from_egress: udp.udp_bytes_read_from_egress,
        udp_flows_removed_on_error: udp.udp_flows_removed_on_error,
        udp_flows_expired,
        outbound_packets_written: tcp.outbound_packets_written + udp.outbound_packets_written,
    })
}

/// Context for processing one IPv4 packet while retaining UDP egress handles.
pub struct DevicePacketStepWithUdp<'a, E, A>
where
    E: HostEgress,
{
    pub sandbox_id: &'a SandboxId,
    pub frontend: FrontendKind,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub udp_bridges: &'a mut UdpBridgeTable<E::UdpHandle>,
    pub udp_timeouts: UdpTimeouts,
    pub sequence: u64,
    pub timestamp_millis: u64,
}

pub struct DevicePacketStepWithDnsAndUdp<'a, E, A>
where
    E: HostEgress,
{
    pub sandbox_id: &'a SandboxId,
    pub frontend: FrontendKind,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub udp_bridges: &'a mut UdpBridgeTable<E::UdpHandle>,
    pub udp_timeouts: UdpTimeouts,
    pub broker_dns_addrs: &'a [IpAddr],
    pub dns_response_ttl: Duration,
    pub dns_cache: &'a mut DnsAttributionCache,
    pub cache_now: Instant,
    pub sequence: u64,
    pub timestamp_millis: u64,
}

/// Process one IPv4 packet, servicing broker DNS packets before falling back to
/// generic UDP bridge retention.
pub fn process_one_ipv4_device_packet_with_dns_and_udp_bridges<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStepWithDnsAndUdp<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    E::UdpHandle: HostUdpFlow,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    if let Some((outcome, cache_update)) = handle_ipv4_dns_service_packet(
        Ipv4DnsServiceRequest {
            packet: InboundIpv4Packet {
                sandbox_id: ctx.sandbox_id,
                frontend: ctx.frontend,
                bytes: packet.bytes(),
            },
            broker_dns_addrs: ctx.broker_dns_addrs,
            response_ttl: ctx.dns_response_ttl,
            sequence: ctx.sequence,
            timestamp_millis: ctx.timestamp_millis,
        },
        ctx.policy,
        ctx.egress,
        ctx.audit,
    )
    .map_err(RuntimeError::Broker)?
    {
        ctx.dns_cache
            .observe_address_records(cache_update.records, ctx.cache_now);
        write_outbound_packets(device, &outcome.outbound_packets)?;
        return Ok(outcome);
    }

    process_ipv4_device_packet_with_udp_bridges(
        device,
        packet,
        DevicePacketStepWithUdp {
            sandbox_id: ctx.sandbox_id,
            frontend: ctx.frontend,
            policy: ctx.policy,
            egress: ctx.egress,
            audit: ctx.audit,
            udp_bridges: ctx.udp_bridges,
            udp_timeouts: ctx.udp_timeouts,
            sequence: ctx.sequence,
            timestamp_millis: ctx.timestamp_millis,
        },
    )
}

/// Process one IPv4 packet and retain any opened UDP flow handle for later
/// response routing.
pub fn process_one_ipv4_device_packet_with_udp_bridges<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStepWithUdp<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    E::UdpHandle: HostUdpFlow,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    process_ipv4_device_packet_with_udp_bridges(device, packet, ctx)
}

fn process_ipv4_device_packet_with_udp_bridges<D, E, A>(
    device: &mut D,
    packet: DevicePacket,
    ctx: DevicePacketStepWithUdp<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    E::UdpHandle: HostUdpFlow,
    A: AuditSink,
{
    let mut result = handle_ipv4_packet_with_egress(
        InboundIpv4Packet {
            sandbox_id: ctx.sandbox_id,
            frontend: ctx.frontend,
            bytes: packet.bytes(),
        },
        ctx.policy,
        ctx.egress,
        ctx.audit,
        ctx.sequence,
        ctx.timestamp_millis,
    )
    .map_err(RuntimeError::Broker)?;

    if let (NormalizedEvent::UdpFlowAttempt(event), Some(EgressOutcome::UdpOpened(flow))) =
        (&result.event, result.egress_outcome.take())
    {
        ctx.udp_bridges
            .try_insert_with_timeout(
                UdpFlowKey::from_attempt(event),
                flow,
                ctx.timestamp_millis,
                udp_timeout(event.classification, &ctx.udp_timeouts).as_millis() as u64,
            )
            .map_err(BrokerError::Egress)
            .map_err(RuntimeError::Broker)?;
    }

    write_outbound_packets(device, &result.outbound_packets)?;

    Ok(result.into_outcome())
}

/// Process one IPv6 packet, servicing broker DNS packets before falling back to
/// generic UDP bridge retention.
pub fn process_one_ipv6_device_packet_with_dns_and_udp_bridges<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStepWithDnsAndUdp<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    E::UdpHandle: HostUdpFlow,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    if let Some((outcome, cache_update)) = handle_ipv6_dns_service_packet(
        Ipv6DnsServiceRequest {
            packet: InboundIpv6Packet {
                sandbox_id: ctx.sandbox_id,
                frontend: ctx.frontend,
                bytes: packet.bytes(),
            },
            broker_dns_addrs: ctx.broker_dns_addrs,
            response_ttl: ctx.dns_response_ttl,
            sequence: ctx.sequence,
            timestamp_millis: ctx.timestamp_millis,
        },
        ctx.policy,
        ctx.egress,
        ctx.audit,
    )
    .map_err(RuntimeError::Broker)?
    {
        ctx.dns_cache
            .observe_address_records(cache_update.records, ctx.cache_now);
        write_outbound_packets(device, &outcome.outbound_packets)?;
        return Ok(outcome);
    }

    process_ipv6_device_packet_with_udp_bridges(
        device,
        packet,
        DevicePacketStepWithUdp {
            sandbox_id: ctx.sandbox_id,
            frontend: ctx.frontend,
            policy: ctx.policy,
            egress: ctx.egress,
            audit: ctx.audit,
            udp_bridges: ctx.udp_bridges,
            udp_timeouts: ctx.udp_timeouts,
            sequence: ctx.sequence,
            timestamp_millis: ctx.timestamp_millis,
        },
    )
}

/// Process one IPv6 packet and retain any opened UDP flow handle for later
/// response routing.
pub fn process_one_ipv6_device_packet_with_udp_bridges<D, E, A>(
    device: &mut D,
    ctx: DevicePacketStepWithUdp<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    E::UdpHandle: HostUdpFlow,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    process_ipv6_device_packet_with_udp_bridges(device, packet, ctx)
}

fn process_ipv6_device_packet_with_udp_bridges<D, E, A>(
    device: &mut D,
    packet: DevicePacket,
    ctx: DevicePacketStepWithUdp<'_, E, A>,
) -> Result<PacketBrokerOutcome, RuntimeError>
where
    D: PacketDevice,
    E: HostEgress,
    E::UdpHandle: HostUdpFlow,
    A: AuditSink,
{
    let mut result = handle_ipv6_packet_with_egress(
        InboundIpv6Packet {
            sandbox_id: ctx.sandbox_id,
            frontend: ctx.frontend,
            bytes: packet.bytes(),
        },
        ctx.policy,
        ctx.egress,
        ctx.audit,
        ctx.sequence,
        ctx.timestamp_millis,
    )
    .map_err(RuntimeError::Broker)?;

    if let (NormalizedEvent::UdpFlowAttempt(event), Some(EgressOutcome::UdpOpened(flow))) =
        (&result.event, result.egress_outcome.take())
    {
        ctx.udp_bridges
            .try_insert_with_timeout(
                UdpFlowKey::from_attempt(event),
                flow,
                ctx.timestamp_millis,
                udp_timeout(event.classification, &ctx.udp_timeouts).as_millis() as u64,
            )
            .map_err(BrokerError::Egress)
            .map_err(RuntimeError::Broker)?;
    }

    write_outbound_packets(device, &result.outbound_packets)?;

    Ok(result.into_outcome())
}

/// Normalized key for a stack TCP flow bridged to a host egress stream.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StackTcpFlowKey {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl StackTcpFlowKey {
    pub fn new(
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        Self {
            sandbox_id,
            frontend,
            source,
            destination,
        }
    }

    pub fn from_connect_attempt(event: &TcpConnectAttempt) -> Self {
        Self::new(
            event.sandbox_id.clone(),
            event.frontend,
            event.source,
            event.destination,
        )
    }

    pub fn from_tcp_data(event: &StackTcpData) -> Self {
        Self::new(
            event.sandbox_id.clone(),
            event.frontend,
            event.source,
            event.destination,
        )
    }
}

/// Runtime-owned bridge table from normalized stack flows to egress-owned host
/// TCP streams. The table deliberately stores only `HostTcpStream` handles; it
/// never exposes smoltcp sockets or std socket details to policy or audit.
pub const DEFAULT_MAX_PENDING_SANDBOX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackTcpBridgeLimits {
    pub max_pending_sandbox_bytes: usize,
    pub max_streams: usize,
    pub max_streams_per_sandbox: usize,
}

impl Default for StackTcpBridgeLimits {
    fn default() -> Self {
        Self {
            max_pending_sandbox_bytes: DEFAULT_MAX_PENDING_SANDBOX_BYTES,
            max_streams: DEFAULT_MAX_TCP_BRIDGES,
            max_streams_per_sandbox: DEFAULT_MAX_TCP_BRIDGES_PER_SANDBOX,
        }
    }
}

pub struct StackTcpBridgeTable<T> {
    streams: HashMap<StackTcpFlowKey, StackTcpBridge<T>>,
    limits: StackTcpBridgeLimits,
    read_cursor: usize,
}

struct StackTcpBridge<T> {
    stream: T,
    pending_sandbox_to_host: VecDeque<Vec<u8>>,
    first_payload_inspected: bool,
}

impl<T> StackTcpBridge<T> {
    fn new(stream: T) -> Self {
        Self {
            stream,
            pending_sandbox_to_host: VecDeque::new(),
            first_payload_inspected: false,
        }
    }

    fn pending_sandbox_bytes(&self) -> usize {
        self.pending_sandbox_to_host
            .iter()
            .map(Vec::len)
            .sum::<usize>()
    }
}

impl<T> Default for StackTcpBridgeTable<T> {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
            limits: StackTcpBridgeLimits::default(),
            read_cursor: 0,
        }
    }
}

impl<T> StackTcpBridgeTable<T> {
    pub fn with_limits(limits: StackTcpBridgeLimits) -> Self {
        Self {
            streams: HashMap::new(),
            limits,
            read_cursor: 0,
        }
    }

    pub fn limits(&self) -> StackTcpBridgeLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn read_cursor(&self) -> usize {
        self.read_cursor
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub fn contains_key(&self, key: &StackTcpFlowKey) -> bool {
        self.streams.contains_key(key)
    }

    pub fn insert(&mut self, key: StackTcpFlowKey, stream: T) -> Option<T> {
        self.try_insert(key, stream)
            .expect("default TCP bridge limits exceeded")
    }

    pub fn try_insert(
        &mut self,
        key: StackTcpFlowKey,
        stream: T,
    ) -> Result<Option<T>, EgressError> {
        if !self.streams.contains_key(&key) {
            if self.streams.len() >= self.limits.max_streams {
                return Err(EgressError::StreamIo(
                    "TCP bridge stream limit exceeded".into(),
                ));
            }
            let sandbox_streams = self
                .streams
                .keys()
                .filter(|existing| existing.sandbox_id == key.sandbox_id)
                .count();
            if sandbox_streams >= self.limits.max_streams_per_sandbox {
                return Err(EgressError::StreamIo(
                    "TCP bridge sandbox stream limit exceeded".into(),
                ));
            }
        }
        Ok(self
            .streams
            .insert(key, StackTcpBridge::new(stream))
            .map(|bridge| bridge.stream))
    }

    pub fn remove(&mut self, key: &StackTcpFlowKey) -> Option<T> {
        self.streams.remove(key).map(|bridge| bridge.stream)
    }

    pub fn pending_sandbox_bytes(&self, key: &StackTcpFlowKey) -> usize {
        self.streams
            .get(key)
            .map(StackTcpBridge::pending_sandbox_bytes)
            .unwrap_or(0)
    }

    fn mark_first_payload_inspected(&mut self, key: &StackTcpFlowKey) -> Option<bool> {
        let bridge = self.streams.get_mut(key)?;
        if bridge.first_payload_inspected {
            Some(false)
        } else {
            bridge.first_payload_inspected = true;
            Some(true)
        }
    }

    pub fn total_pending_sandbox_bytes(&self) -> usize {
        self.streams
            .values()
            .map(StackTcpBridge::pending_sandbox_bytes)
            .sum()
    }
}

impl<T> StackTcpBridge<T>
where
    T: HostTcpStream,
{
    fn write_from_sandbox(
        &mut self,
        bytes: &[u8],
        limits: StackTcpBridgeLimits,
    ) -> Result<usize, EgressError> {
        if !self.pending_sandbox_to_host.is_empty() {
            self.queue_pending_sandbox_bytes(bytes, limits)?;
            return Ok(0);
        }
        let written = self.stream.write_from_sandbox(bytes)?;
        if written < bytes.len() {
            self.queue_pending_sandbox_bytes(&bytes[written..], limits)?;
        }
        Ok(written)
    }

    fn queue_pending_sandbox_bytes(
        &mut self,
        bytes: &[u8],
        limits: StackTcpBridgeLimits,
    ) -> Result<(), EgressError> {
        let pending_after = self.pending_sandbox_bytes().saturating_add(bytes.len());
        if pending_after > limits.max_pending_sandbox_bytes {
            return Err(EgressError::StreamIo(
                "TCP bridge pending sandbox buffer limit exceeded".into(),
            ));
        }
        self.pending_sandbox_to_host.push_back(bytes.to_vec());
        Ok(())
    }

    fn flush_pending_sandbox_writes(&mut self) -> Result<usize, EgressError> {
        let mut total = 0;
        while let Some(bytes) = self.pending_sandbox_to_host.pop_front() {
            let written = self.stream.write_from_sandbox(&bytes)?;
            total += written;
            if written < bytes.len() {
                self.pending_sandbox_to_host
                    .push_front(bytes[written..].to_vec());
                break;
            }
        }
        Ok(total)
    }
}

impl<T> StackTcpBridgeTable<T>
where
    T: HostTcpStream,
{
    pub fn write_from_sandbox(
        &mut self,
        event: &StackTcpData,
    ) -> Result<Option<usize>, EgressError> {
        let key = StackTcpFlowKey::from_tcp_data(event);
        let Some(bridge) = self.streams.get_mut(&key) else {
            return Ok(None);
        };
        bridge
            .write_from_sandbox(&event.bytes, self.limits)
            .map(Some)
    }

    pub fn flush_pending_sandbox_writes(&mut self) -> Result<usize, EgressError> {
        let mut total = 0;
        for bridge in self.streams.values_mut() {
            total += bridge.flush_pending_sandbox_writes()?;
        }
        Ok(total)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackBridgeReadOutcome {
    pub tcp_streams_read: usize,
    pub tcp_bytes_read_from_egress: usize,
    pub tcp_bytes_enqueued_to_stack: usize,
    pub outbound_packets_written: usize,
}

/// Read pending host-side bytes from bridged TCP streams, enqueue them into the
/// stack adapter, and write adapter-produced opaque packets to the device.
pub fn flush_tcp_bridge_reads_to_stack_device<D, S, T>(
    device: &mut D,
    adapter: &mut S,
    bridges: &mut StackTcpBridgeTable<T>,
    max_bytes_per_stream: usize,
) -> Result<StackBridgeReadOutcome, RuntimeError>
where
    D: PacketDevice,
    S: StackAdapter,
    T: HostTcpStream,
{
    flush_tcp_bridge_reads_to_stack_device_with_limit(
        device,
        adapter,
        bridges,
        max_bytes_per_stream,
        usize::MAX,
    )
}

/// Read pending host-side bytes from at most `max_streams` TCP streams.
pub fn flush_tcp_bridge_reads_to_stack_device_with_limit<D, S, T>(
    device: &mut D,
    adapter: &mut S,
    bridges: &mut StackTcpBridgeTable<T>,
    max_bytes_per_stream: usize,
    max_streams: usize,
) -> Result<StackBridgeReadOutcome, RuntimeError>
where
    D: PacketDevice,
    S: StackAdapter,
    T: HostTcpStream,
{
    flush_tcp_bridge_reads_to_stack_device_with_fairness(
        device,
        adapter,
        bridges,
        max_bytes_per_stream,
        max_streams,
        usize::MAX,
        usize::MAX,
    )
}

fn flush_tcp_bridge_reads_to_stack_device_with_fairness<D, S, T>(
    device: &mut D,
    adapter: &mut S,
    bridges: &mut StackTcpBridgeTable<T>,
    max_bytes_per_stream: usize,
    max_streams: usize,
    max_streams_per_sandbox: usize,
    max_bytes_per_sandbox: usize,
) -> Result<StackBridgeReadOutcome, RuntimeError>
where
    D: PacketDevice,
    S: StackAdapter,
    T: HostTcpStream,
{
    let mut reads = Vec::new();
    let mut keys: Vec<_> = bridges.streams.keys().cloned().collect();
    keys.sort_by_key(|key| format!("{key:?}"));
    let stream_count = keys.len();
    let start = if stream_count == 0 {
        0
    } else {
        bridges.read_cursor % stream_count
    };
    let mut selected = 0;
    let mut visited = 0;
    let mut per_sandbox = HashMap::<SandboxId, usize>::new();
    let mut bytes_per_sandbox = HashMap::<SandboxId, usize>::new();
    while visited < stream_count && selected < max_streams {
        let key = keys[(start + visited) % stream_count].clone();
        visited += 1;
        let sandbox_count = per_sandbox.entry(key.sandbox_id.clone()).or_default();
        if *sandbox_count >= max_streams_per_sandbox {
            continue;
        }
        let sandbox_bytes = bytes_per_sandbox.entry(key.sandbox_id.clone()).or_default();
        let remaining_bytes = max_bytes_per_sandbox.saturating_sub(*sandbox_bytes);
        if remaining_bytes == 0 {
            continue;
        }
        *sandbox_count += 1;
        selected += 1;
        let Some(bridge) = bridges.streams.get_mut(&key) else {
            continue;
        };
        let bytes = bridge
            .stream
            .read_to_sandbox(max_bytes_per_stream.min(remaining_bytes))
            .map_err(BrokerError::Egress)
            .map_err(RuntimeError::Broker)?;
        if !bytes.is_empty() {
            *sandbox_bytes += bytes.len();
            reads.push((key, bytes));
        }
    }
    if stream_count > 0 {
        bridges.read_cursor = (start + visited) % stream_count;
    }

    let tcp_streams_read = reads.len();
    let mut tcp_bytes_read_from_egress = 0;
    let mut tcp_bytes_enqueued_to_stack = 0;
    for (key, bytes) in reads {
        tcp_bytes_read_from_egress += bytes.len();
        let write = StackTcpWrite {
            sandbox_id: key.sandbox_id,
            frontend: key.frontend,
            source: key.source,
            destination: key.destination,
            bytes,
        };
        tcp_bytes_enqueued_to_stack += adapter
            .send_tcp_data_to_sandbox(&write)
            .map_err(RuntimeError::Stack)?;
    }

    let outbound_packets = adapter
        .poll_outbound_packets()
        .map_err(RuntimeError::Stack)?;
    let outbound_packets_written = outbound_packets.len();
    write_outbound_packets(device, &outbound_packets)?;

    Ok(StackBridgeReadOutcome {
        tcp_streams_read,
        tcp_bytes_read_from_egress,
        tcp_bytes_enqueued_to_stack,
        outbound_packets_written,
    })
}

/// Context for processing one packet through a stack adapter.
pub struct StackDevicePacketStep<'a, S, E, A>
where
    E: HostEgress,
{
    pub adapter: &'a mut S,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub tcp_bridges: &'a mut StackTcpBridgeTable<E::TcpStream>,
    pub sequence_start: u64,
    pub timestamp_millis: u64,
    pub dns_attribution: Option<StackDnsAttribution<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackDevicePacketOutcome {
    pub broker_outcomes: Vec<BrokerEventOutcome>,
    pub tcp_data_events: usize,
    pub tcp_bytes_written_to_egress: usize,
    pub tcp_bytes_pending_to_egress: usize,
    pub tcp_data_without_bridge: usize,
    pub transparent_inspection_events: usize,
    pub transparent_inspection_denials: usize,
    pub tcp_bridges_removed: usize,
    pub flow_closed_events: usize,
    pub outbound_packets_written: usize,
}

/// Read one opaque packet from a device, feed it to a stack adapter, apply
/// policy/audit/egress to emitted normalized events, and write opaque adapter
/// output back to the device.
pub fn process_one_stack_device_packet<D, S, E, A>(
    device: &mut D,
    ctx: StackDevicePacketStep<'_, S, E, A>,
) -> Result<StackDevicePacketOutcome, RuntimeError>
where
    D: PacketDevice,
    S: StackAdapter,
    E: HostEgress,
    A: AuditSink,
{
    let packet = device.read_packet().map_err(RuntimeError::Device)?;
    process_stack_device_packet(device, packet, ctx)
}

/// Try to process one stack packet without blocking on an idle device. `Ok(None)`
/// means callers can proceed with bridge maintenance only.
pub fn process_one_stack_device_packet_if_ready<D, S, E, A>(
    device: &mut D,
    ctx: StackDevicePacketStep<'_, S, E, A>,
) -> Result<Option<StackDevicePacketOutcome>, RuntimeError>
where
    D: TryPacketDevice,
    S: StackAdapter,
    E: HostEgress,
    A: AuditSink,
{
    let Some(packet) = device.try_read_packet().map_err(RuntimeError::Device)? else {
        return Ok(None);
    };
    process_stack_device_packet(device, packet, ctx).map(Some)
}

fn transparent_first_payload_event(data: &StackTcpData) -> Option<NormalizedEvent> {
    match data.destination.port() {
        80 => Some(foxprox_inspect::inspect_plaintext_http_request(
            data.sandbox_id.clone(),
            data.frontend,
            &data.bytes,
        )),
        443 => Some(foxprox_inspect::inspect_tls_client_hello(
            data.sandbox_id.clone(),
            data.frontend,
            data.destination,
            None,
            &data.bytes,
        )),
        _ => None,
    }
}

fn process_stack_device_packet<D, S, E, A>(
    device: &mut D,
    packet: DevicePacket,
    ctx: StackDevicePacketStep<'_, S, E, A>,
) -> Result<StackDevicePacketOutcome, RuntimeError>
where
    D: PacketDevice,
    S: StackAdapter,
    E: HostEgress,
    A: AuditSink,
{
    let events = ctx
        .adapter
        .ingest_ip_packet(packet.bytes())
        .map_err(RuntimeError::Stack)?;
    let mut broker_outcomes = Vec::new();
    let mut tcp_data_events = 0;
    let mut tcp_bytes_written_to_egress = 0;
    let mut tcp_data_without_bridge = 0;
    let mut transparent_inspection_events = 0;
    let mut transparent_inspection_denials = 0;
    let mut tcp_bridges_removed = 0;
    let mut flow_closed_events = 0;

    for (offset, event) in events.into_iter().enumerate() {
        match event {
            StackEvent::PolicyEvent(mut event) => {
                if let Some(dns_attribution) = ctx.dns_attribution {
                    apply_dns_attribution(&mut event, dns_attribution.cache, dns_attribution.now);
                }
                let result = handle_normalized_event_with_egress(
                    &event,
                    ctx.policy,
                    ctx.egress,
                    ctx.audit,
                    ctx.sequence_start + offset as u64,
                    ctx.timestamp_millis,
                )
                .map_err(RuntimeError::Broker)?;
                if let (
                    NormalizedEvent::TcpConnectAttempt(connect),
                    Some(EgressOutcome::TcpConnected(stream)),
                ) = (&event, result.egress_outcome)
                {
                    ctx.tcp_bridges
                        .try_insert(StackTcpFlowKey::from_connect_attempt(connect), stream)
                        .map_err(BrokerError::Egress)
                        .map_err(RuntimeError::Broker)?;
                }
                broker_outcomes.push(result.outcome);
            }
            StackEvent::TcpData(data) => {
                tcp_data_events += 1;
                if ctx
                    .tcp_bridges
                    .mark_first_payload_inspected(&StackTcpFlowKey::from_tcp_data(&data))
                    .unwrap_or(false)
                {
                    if let Some(event) = transparent_first_payload_event(&data) {
                        transparent_inspection_events += 1;
                        let result = handle_normalized_event_without_egress(
                            &event,
                            ctx.policy,
                            ctx.audit,
                            ctx.sequence_start + offset as u64,
                            ctx.timestamp_millis,
                        )
                        .map_err(RuntimeError::Broker)?;
                        if !result.decision.is_allowed() {
                            transparent_inspection_denials += 1;
                            ctx.tcp_bridges
                                .remove(&StackTcpFlowKey::from_tcp_data(&data));
                            continue;
                        }
                    }
                }
                match ctx
                    .tcp_bridges
                    .write_from_sandbox(&data)
                    .map_err(BrokerError::Egress)
                    .map_err(RuntimeError::Broker)?
                {
                    Some(bytes) => tcp_bytes_written_to_egress += bytes,
                    None => tcp_data_without_bridge += 1,
                }
            }
            StackEvent::FlowClosed(closed) => {
                let bridge_key = if closed.key.protocol == FlowProtocol::Tcp {
                    Some(StackTcpFlowKey::new(
                        closed.sandbox_id.clone(),
                        closed.frontend,
                        closed.key.source,
                        closed.key.destination,
                    ))
                } else {
                    None
                };
                let protocol = match closed.key.protocol {
                    FlowProtocol::Tcp => Protocol::Tcp,
                    FlowProtocol::Udp => Protocol::Udp,
                };
                ctx.audit
                    .record(AuditRecord::flow_closed(FlowClosedAudit {
                        sequence: ctx.sequence_start + offset as u64,
                        timestamp_millis: ctx.timestamp_millis,
                        sandbox_id: closed.sandbox_id,
                        frontend: closed.frontend,
                        protocol,
                        source: closed.key.source,
                        destination: closed.key.destination,
                        byte_counts: closed.byte_counts,
                        duration: closed.duration,
                    }))
                    .map_err(BrokerError::Audit)
                    .map_err(RuntimeError::Broker)?;
                if let Some(key) = bridge_key {
                    if ctx.tcp_bridges.remove(&key).is_some() {
                        tcp_bridges_removed += 1;
                    }
                }
                flow_closed_events += 1;
            }
        }
    }

    let outbound_packets = ctx
        .adapter
        .poll_outbound_packets()
        .map_err(RuntimeError::Stack)?;
    let outbound_packets_written = outbound_packets.len();
    write_outbound_packets(device, &outbound_packets)?;

    Ok(StackDevicePacketOutcome {
        broker_outcomes,
        tcp_data_events,
        tcp_bytes_written_to_egress,
        tcp_bytes_pending_to_egress: ctx.tcp_bridges.total_pending_sandbox_bytes(),
        tcp_data_without_bridge,
        transparent_inspection_events,
        transparent_inspection_denials,
        tcp_bridges_removed,
        flow_closed_events,
        outbound_packets_written,
    })
}

fn write_outbound_packets<D>(
    device: &mut D,
    outbound_packets: &[OutboundIpPacket],
) -> Result<(), RuntimeError>
where
    D: PacketDevice,
{
    for outbound in outbound_packets {
        let packet = DevicePacket::new(outbound.bytes().to_vec()).map_err(RuntimeError::Device)?;
        device.write_packet(&packet).map_err(RuntimeError::Device)?;
    }
    Ok(())
}

#[derive(Debug)]
pub enum RuntimeError {
    Device(DeviceError),
    Broker(BrokerError),
    Stack(foxprox_net::StackError),
    ProxyIo(std::io::Error),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => write!(f, "device runtime error: {error}"),
            Self::Broker(error) => write!(f, "broker runtime error: {error}"),
            Self::Stack(error) => write!(f, "stack runtime error: {error}"),
            Self::ProxyIo(error) => write!(f, "proxy runtime io error: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        io::{Cursor, ErrorKind, Read, Write},
        rc::Rc,
    };

    use foxprox_audit::BoundedAuditSink;
    use foxprox_core::{
        DestinationMatcher, DnsQuery, Hostname, HttpRequest, HttpsConnect, NormalizedEvent,
        PolicyRule, PortMatcher, Protocol, ProtocolMatcher, RuntimeConfig, SocksConnect,
        TcpConnectAttempt, UdpFlowAttempt,
    };
    use foxprox_device::PreopenedTunDevice;
    use foxprox_egress::{MockEgress, MockHttpResponse, MockTcpStream, MockUdpHandle};
    use foxprox_net::StackError;

    #[test]
    fn explicit_http_proxy_request_uses_shared_policy_audit_and_egress() {
        let request = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let request_len = request.len();
        let mut io = Cursor::new(request);
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(foxprox_core::RuleId::new("http").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Http);
        config.rules.push(rule);
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress {
            http_response_bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            ..MockEgress::default()
        };
        let mut audit = BoundedAuditSink::new(4);
        let sandbox_id = SandboxId::new("s1").unwrap();

        let outcome = process_one_http_proxy_request(
            &mut io,
            ExplicitHttpProxyStep {
                sandbox_id: &sandbox_id,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                parser_limits: ParserLimits::default(),
                max_response_bytes: 1024,
                sequence: 1,
                timestamp_millis: 1000,
            },
        )
        .unwrap();

        assert_eq!(outcome.broker_outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(egress.http_requests.len(), 1);
        assert_eq!(audit.records().len(), 1);
        let bytes = io.into_inner();
        assert_eq!(
            &bytes[request_len..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        );
        assert_eq!(outcome.response_bytes_written, bytes.len() - request_len);
    }

    #[test]
    fn explicit_http_proxy_denial_writes_forbidden_without_egress() {
        let request = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let request_len = request.len();
        let mut io = Cursor::new(request);
        let policy = PolicyEngine::new(RuntimeConfig::deny_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let sandbox_id = SandboxId::new("s1").unwrap();

        let outcome = process_one_http_proxy_request(
            &mut io,
            ExplicitHttpProxyStep {
                sandbox_id: &sandbox_id,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                parser_limits: ParserLimits::default(),
                max_response_bytes: 1024,
                sequence: 1,
                timestamp_millis: 1000,
            },
        )
        .unwrap();

        assert_eq!(
            outcome.broker_outcome,
            BrokerEventOutcome::Denied(Some(DenialAction::Drop))
        );
        assert!(egress.http_requests.is_empty());
        assert_eq!(audit.records().len(), 1);
        let bytes = io.into_inner();
        assert_eq!(
            &bytes[request_len..],
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn one_step_runtime_reads_a_packet_and_writes_policy_allowed_reply() {
        let inbound = echo_request_packet();
        let cursor = Cursor::new(inbound.clone());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut config = RuntimeConfig::deny_by_default();
        config.allow_ping = true;
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let sandbox_id = SandboxId::new("s1").unwrap();

        let outcome = process_one_ipv4_device_packet(
            &mut device,
            DevicePacketStep {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                sequence: 1,
                timestamp_millis: 1000,
            },
        )
        .unwrap();

        assert!(outcome.decision.is_allowed());
        assert_eq!(outcome.outbound_packets.len(), 1);
        assert_eq!(audit.records().len(), 1);
        let bytes = device.into_inner().into_inner();
        assert_eq!(&bytes[..inbound.len()], inbound.as_slice());
        assert_eq!(bytes[inbound.len() + 20], 0);
    }

    #[test]
    fn one_step_ipv4_runtime_returns_none_when_device_not_ready() {
        let mut device = PreopenedTunDevice::from_io(WouldBlockIo, 1500).unwrap();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let sandbox_id = SandboxId::new("s1").unwrap();

        let outcome = process_one_ipv4_device_packet_if_ready(
            &mut device,
            DevicePacketStep {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                sequence: 2,
                timestamp_millis: 2000,
            },
        )
        .unwrap();

        assert!(outcome.is_none());
        assert!(audit.records().is_empty());
        assert!(egress.tcp_connects.is_empty());
    }

    #[test]
    fn one_step_ipv4_runtime_services_broker_dns_and_updates_cache() {
        let dns_payload = dns_query_packet(0x1234, "example.com", 1);
        let inbound = udp_packet(53000, 53, &dns_payload);
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MockEgress {
            dns_results: vec!["203.0.113.10:0".parse().unwrap()],
            ..MockEgress::default()
        };
        let mut audit = BoundedAuditSink::new(4);
        let mut udp_bridges = UdpBridgeTable::default();
        let sandbox_id = SandboxId::new("s1").unwrap();
        let mut dns_cache = DnsAttributionCache::default();
        let now = Instant::now();

        let outcome = process_one_ipv4_device_packet_with_dns_and_udp_bridges(
            &mut device,
            DevicePacketStepWithDnsAndUdp {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                udp_bridges: &mut udp_bridges,
                udp_timeouts: UdpTimeouts::default(),
                broker_dns_addrs: &["10.0.0.1".parse().unwrap()],
                dns_response_ttl: Duration::from_secs(60),
                dns_cache: &mut dns_cache,
                cache_now: now,
                sequence: 2,
                timestamp_millis: 2000,
            },
        )
        .unwrap();

        assert_eq!(outcome.outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(outcome.outbound_packets.len(), 1);
        assert_eq!(udp_bridges.len(), 0);
        assert_eq!(egress.dns_queries.len(), 1);
        assert_eq!(audit.records().len(), 1);
        assert_eq!(
            dns_cache
                .attribution_for("203.0.113.10".parse().unwrap(), now)
                .unwrap()
                .hostname()
                .as_str(),
            "example.com"
        );
        let bytes = device.into_inner().into_inner();
        let response = &bytes[28 + dns_payload.len()..];
        assert_eq!(response[9], 17);
        assert_eq!(&response[12..16], &[10, 0, 0, 1]);
        assert_eq!(&response[16..20], &[10, 0, 0, 2]);
    }

    #[test]
    fn one_step_ipv4_runtime_retains_allowed_udp_bridge() {
        let inbound = udp_packet(53000, 12345, b"ping");
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut egress = RecordingUdpEgress::new(Rc::clone(&writes));
        let mut audit = BoundedAuditSink::new(4);
        let mut udp_bridges = UdpBridgeTable::default();
        let sandbox_id = SandboxId::new("s1").unwrap();

        let outcome = process_one_ipv4_device_packet_with_udp_bridges(
            &mut device,
            DevicePacketStepWithUdp {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                udp_bridges: &mut udp_bridges,
                udp_timeouts: UdpTimeouts::default(),
                sequence: 2,
                timestamp_millis: 2000,
            },
        )
        .unwrap();

        assert_eq!(outcome.outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(outcome.udp_bytes_sent, 4);
        assert_eq!(udp_bridges.len(), 1);
        assert!(udp_bridges.contains_key(&UdpFlowKey {
            sandbox_id,
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "10.0.0.1:12345".parse().unwrap(),
        }));
        assert_eq!(writes.borrow().as_slice(), &[b"ping".to_vec()]);
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn one_step_ipv6_runtime_retains_allowed_udp_bridge() {
        let inbound = udp_ipv6_packet(53000, 12345, b"ping");
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut egress = RecordingUdpEgress::new(Rc::clone(&writes));
        let mut audit = BoundedAuditSink::new(4);
        let mut udp_bridges = UdpBridgeTable::default();
        let sandbox_id = SandboxId::new("s1").unwrap();

        let outcome = process_one_ipv6_device_packet_with_udp_bridges(
            &mut device,
            DevicePacketStepWithUdp {
                sandbox_id: &sandbox_id,
                frontend: FrontendKind::Tun,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                udp_bridges: &mut udp_bridges,
                udp_timeouts: UdpTimeouts::default(),
                sequence: 2,
                timestamp_millis: 2000,
            },
        )
        .unwrap();

        assert_eq!(outcome.outcome, BrokerEventOutcome::Forwarded);
        assert_eq!(outcome.udp_bytes_sent, 4);
        assert_eq!(udp_bridges.len(), 1);
        assert!(udp_bridges.contains_key(&UdpFlowKey {
            sandbox_id,
            frontend: FrontendKind::Tun,
            source: "[2001:db8::2]:53000".parse().unwrap(),
            destination: "[2001:db8::1]:12345".parse().unwrap(),
        }));
        assert_eq!(writes.borrow().as_slice(), &[b"ping".to_vec()]);
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn stack_runtime_loop_runs_until_idle_after_progress() {
        let mut device = PreopenedTunDevice::from_io(WouldBlockIo, 1500).unwrap();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MaintenanceEgress;
        let mut audit = BoundedAuditSink::new(4);
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: vec![OutboundIpPacket::new(vec![0x45, 0, 0, 20]).unwrap()],
        };
        let mut tcp_bridges = StackTcpBridgeTable::default();
        tcp_bridges.insert(
            StackTcpFlowKey::new(
                SandboxId::new("s1").unwrap(),
                FrontendKind::Tun,
                "10.0.0.2:49152".parse().unwrap(),
                "203.0.113.10:80".parse().unwrap(),
            ),
            ReadableTcpStream::new(vec![b"abc".to_vec()].into()),
        );
        let mut udp_bridges = UdpBridgeTable::<MockUdpHandle>::default();

        let outcome = run_stack_runtime_loop(
            &mut device,
            StackRuntimeLoopStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                udp_bridges: &mut udp_bridges,
                dns_attribution: None,
                config: StackRuntimeLoopConfig {
                    max_ticks: 4,
                    max_idle_ticks: Some(1),
                    tick_millis: 5,
                    max_tcp_read_bytes_per_stream: 1024,
                    max_udp_read_bytes_per_flow: 1024,
                    budget: BridgeMaintenanceBudget::default(),
                },
                sequence_start: 10,
                timestamp_millis: 1000,
                now_millis: 2000,
            },
        )
        .unwrap();

        assert_eq!(outcome.ticks_run, 2);
        assert_eq!(outcome.progress_ticks, 1);
        assert_eq!(outcome.idle_ticks, 1);
        assert_eq!(outcome.next_sequence, 12);
        assert_eq!(outcome.next_timestamp_millis, 1010);
        assert_eq!(outcome.next_now_millis, 2010);
        assert_eq!(outcome.maintenance.tcp_streams_read, 1);
        assert_eq!(outcome.maintenance.tcp_bytes_read_from_egress, 3);
        assert_eq!(outcome.maintenance.outbound_packets_written, 1);
        assert_eq!(adapter.writes.len(), 1);
    }

    #[test]
    fn stack_runtime_tick_runs_maintenance_when_device_not_ready() {
        let mut device = PreopenedTunDevice::from_io(WouldBlockIo, 1500).unwrap();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MaintenanceEgress;
        let mut audit = BoundedAuditSink::new(4);
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: vec![OutboundIpPacket::new(vec![0x45, 0, 0, 20]).unwrap()],
        };
        let mut tcp_bridges = StackTcpBridgeTable::default();
        tcp_bridges.insert(
            StackTcpFlowKey::new(
                SandboxId::new("s1").unwrap(),
                FrontendKind::Tun,
                "10.0.0.2:49152".parse().unwrap(),
                "203.0.113.10:80".parse().unwrap(),
            ),
            ReadableTcpStream::new(vec![b"tcp".to_vec()].into()),
        );
        let mut udp_bridges: UdpBridgeTable<MockUdpHandle> = UdpBridgeTable::default();

        let outcome = process_stack_runtime_tick(
            &mut device,
            StackRuntimeTickStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                udp_bridges: &mut udp_bridges,
                sequence_start: 1,
                timestamp_millis: 1000,
                dns_attribution: None,
                max_tcp_read_bytes_per_stream: 1024,
                max_udp_read_bytes_per_flow: 1024,
                budget: BridgeMaintenanceBudget::default(),
                now_millis: 1000,
            },
        )
        .unwrap();

        assert!(outcome.stack_packet.is_none());
        assert_eq!(outcome.maintenance.tcp_streams_read, 1);
        assert_eq!(outcome.maintenance.tcp_bytes_enqueued_to_stack, 3);
        assert_eq!(outcome.maintenance.outbound_packets_written, 1);
        assert_eq!(adapter.writes[0].bytes, b"tcp");
        assert!(audit.records().is_empty());
    }

    #[test]
    fn bridge_maintenance_tick_flushes_tcp_udp_and_expiry() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let tcp_key = StackTcpFlowKey::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.2:49152".parse().unwrap(),
            "203.0.113.10:80".parse().unwrap(),
        );
        let mut tcp_bridges = StackTcpBridgeTable::default();
        tcp_bridges.insert(
            tcp_key,
            ReadableTcpStream::new(vec![b"tcp".to_vec()].into()),
        );
        let udp_key = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "203.0.113.10:12345".parse().unwrap(),
        };
        let mut udp_bridges = UdpBridgeTable::default();
        udp_bridges.insert_with_timeout(
            udp_key,
            ReadableUdpFlow::new(vec![b"udp".to_vec()].into()),
            10,
            5,
        );
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: vec![OutboundIpPacket::new(vec![0x45, 0, 0, 20]).unwrap()],
        };

        let outcome = process_bridge_maintenance_tick(
            &mut device,
            BridgeMaintenanceStep {
                adapter: &mut adapter,
                tcp_bridges: &mut tcp_bridges,
                udp_bridges: &mut udp_bridges,
                max_tcp_read_bytes_per_stream: 1024,
                max_udp_read_bytes_per_flow: 1024,
                budget: BridgeMaintenanceBudget::default(),
                now_millis: 20,
            },
        )
        .unwrap();

        assert_eq!(outcome.tcp_streams_read, 1);
        assert_eq!(outcome.tcp_bytes_read_from_egress, 3);
        assert_eq!(outcome.tcp_bytes_enqueued_to_stack, 3);
        assert_eq!(outcome.udp_flows_read, 1);
        assert_eq!(outcome.udp_bytes_read_from_egress, 3);
        assert_eq!(outcome.udp_flows_expired, 0);
        assert_eq!(outcome.outbound_packets_written, 2);
        assert_eq!(adapter.writes[0].bytes, b"tcp");
    }

    #[test]
    fn udp_bridge_table_enforces_max_flow_limit() {
        let first = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "203.0.113.10:12345".parse().unwrap(),
        };
        let second = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53001".parse().unwrap(),
            destination: "203.0.113.11:12345".parse().unwrap(),
        };
        let mut bridges = UdpBridgeTable::with_limits(UdpBridgeLimits {
            max_flows: 1,
            max_flows_per_sandbox: usize::MAX,
        });

        bridges
            .try_insert_with_timeout(first, ReadableUdpFlow::new(VecDeque::new()), 0, 30)
            .unwrap();
        let error = match bridges.try_insert_with_timeout(
            second,
            ReadableUdpFlow::new(VecDeque::new()),
            0,
            30,
        ) {
            Ok(_) => panic!("expected UDP bridge flow limit error"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("UDP bridge flow limit"));
        assert_eq!(bridges.len(), 1);
    }

    #[test]
    fn udp_bridge_table_enforces_per_sandbox_flow_limit() {
        let mut bridges = UdpBridgeTable::with_limits(UdpBridgeLimits {
            max_flows: usize::MAX,
            max_flows_per_sandbox: 1,
        });
        let first = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "203.0.113.10:12345".parse().unwrap(),
        };
        let second = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53001".parse().unwrap(),
            destination: "203.0.113.11:12345".parse().unwrap(),
        };

        bridges
            .try_insert_with_timeout(first, ReadableUdpFlow::new(VecDeque::new()), 0, 30)
            .unwrap();
        let error = match bridges.try_insert_with_timeout(
            second,
            ReadableUdpFlow::new(VecDeque::new()),
            0,
            30,
        ) {
            Ok(_) => panic!("expected UDP bridge sandbox flow limit error"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("UDP bridge sandbox flow limit"));
        assert_eq!(bridges.len(), 1);
    }

    #[test]
    fn udp_bridge_table_expires_idle_flows_by_timeout() {
        let key = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "203.0.113.10:12345".parse().unwrap(),
        };
        let mut bridges = UdpBridgeTable::default();
        bridges.insert_with_timeout(key, ReadableUdpFlow::new(VecDeque::new()), 100, 30);

        assert_eq!(bridges.expire_idle(129), 0);
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges.expire_idle(130), 1);
        assert!(bridges.is_empty());
    }

    #[test]
    fn tcp_bridge_read_budget_advances_round_robin_cursor() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut bridges = StackTcpBridgeTable::default();
        for port in [50000, 50001, 50002] {
            bridges.insert(
                StackTcpFlowKey::new(
                    SandboxId::new("s1").unwrap(),
                    FrontendKind::Tun,
                    format!("10.0.0.2:{port}").parse().unwrap(),
                    "203.0.113.10:80".parse().unwrap(),
                ),
                ReadableTcpStream::new(vec![vec![port as u8]].into()),
            );
        }
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: Vec::new(),
        };

        for _ in 0..3 {
            let outcome = flush_tcp_bridge_reads_to_stack_device_with_limit(
                &mut device,
                &mut adapter,
                &mut bridges,
                1024,
                1,
            )
            .unwrap();
            assert_eq!(outcome.tcp_streams_read, 1);
        }

        let ports: std::collections::HashSet<_> = adapter
            .writes
            .iter()
            .map(|write| write.source.port())
            .collect();
        assert_eq!(ports.len(), 3);
        assert_eq!(bridges.read_cursor(), 0);
    }

    #[test]
    fn udp_bridge_read_budget_advances_round_robin_cursor() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut bridges = UdpBridgeTable::default();
        for port in [50000, 50001, 50002] {
            bridges.insert(
                UdpFlowKey {
                    sandbox_id: SandboxId::new("s1").unwrap(),
                    frontend: FrontendKind::Tun,
                    source: format!("10.0.0.2:{port}").parse().unwrap(),
                    destination: "203.0.113.10:12345".parse().unwrap(),
                },
                ReadableUdpFlow::new(vec![vec![port as u8]].into()),
            );
        }

        for _ in 0..3 {
            let outcome =
                flush_udp_bridge_reads_to_device_with_limit(&mut device, &mut bridges, 1024, 1, 20)
                    .unwrap();
            assert_eq!(outcome.udp_flows_read, 1);
        }

        assert_eq!(bridges.read_cursor(), 0);
    }

    #[test]
    fn tcp_bridge_read_budget_caps_each_sandbox_per_tick() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut bridges = StackTcpBridgeTable::default();
        for (sandbox, port) in [("s1", 50000), ("s1", 50001), ("s2", 50002)] {
            bridges.insert(
                StackTcpFlowKey::new(
                    SandboxId::new(sandbox).unwrap(),
                    FrontendKind::Tun,
                    format!("10.0.0.2:{port}").parse().unwrap(),
                    "203.0.113.10:80".parse().unwrap(),
                ),
                ReadableTcpStream::new(vec![vec![port as u8]].into()),
            );
        }
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: Vec::new(),
        };

        let outcome = flush_tcp_bridge_reads_to_stack_device_with_fairness(
            &mut device,
            &mut adapter,
            &mut bridges,
            1024,
            2,
            1,
            usize::MAX,
        )
        .unwrap();

        assert_eq!(outcome.tcp_streams_read, 2);
        let sandboxes: std::collections::HashSet<_> = adapter
            .writes
            .iter()
            .map(|write| write.sandbox_id.as_str().to_string())
            .collect();
        let expected: std::collections::HashSet<_> =
            ["s1".to_string(), "s2".to_string()].into_iter().collect();
        assert_eq!(sandboxes, expected);
    }

    #[test]
    fn udp_bridge_read_budget_caps_each_sandbox_per_tick() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut bridges = UdpBridgeTable::default();
        for (sandbox, port) in [("s1", 50000), ("s1", 50001), ("s2", 50002)] {
            bridges.insert(
                UdpFlowKey {
                    sandbox_id: SandboxId::new(sandbox).unwrap(),
                    frontend: FrontendKind::Tun,
                    source: format!("10.0.0.2:{port}").parse().unwrap(),
                    destination: "203.0.113.10:12345".parse().unwrap(),
                },
                ReadableUdpFlow::new(vec![vec![port as u8]].into()),
            );
        }

        let outcome = flush_udp_bridge_reads_to_device_with_fairness(
            &mut device,
            &mut bridges,
            1024,
            2,
            1,
            usize::MAX,
            20,
        )
        .unwrap();

        assert_eq!(outcome.udp_flows_read, 2);
        assert_eq!(outcome.outbound_packets_written, 2);
    }

    #[test]
    fn tcp_bridge_read_budget_caps_bytes_per_sandbox_per_tick() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut bridges = StackTcpBridgeTable::default();
        bridges.insert(
            StackTcpFlowKey::new(
                SandboxId::new("s1").unwrap(),
                FrontendKind::Tun,
                "10.0.0.2:50000".parse().unwrap(),
                "203.0.113.10:80".parse().unwrap(),
            ),
            ReadableTcpStream::new(vec![b"abcdef".to_vec()].into()),
        );
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: Vec::new(),
        };

        let outcome = flush_tcp_bridge_reads_to_stack_device_with_fairness(
            &mut device,
            &mut adapter,
            &mut bridges,
            1024,
            1,
            1,
            3,
        )
        .unwrap();

        assert_eq!(outcome.tcp_bytes_read_from_egress, 3);
        assert_eq!(adapter.writes[0].bytes, b"abc".to_vec());
    }

    #[test]
    fn udp_bridge_read_budget_caps_bytes_per_sandbox_per_tick() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut bridges = UdpBridgeTable::default();
        bridges.insert(
            UdpFlowKey {
                sandbox_id: SandboxId::new("s1").unwrap(),
                frontend: FrontendKind::Tun,
                source: "10.0.0.2:50000".parse().unwrap(),
                destination: "203.0.113.10:12345".parse().unwrap(),
            },
            ReadableUdpFlow::new(vec![b"abcdef".to_vec()].into()),
        );

        let outcome = flush_udp_bridge_reads_to_device_with_fairness(
            &mut device,
            &mut bridges,
            1024,
            1,
            1,
            3,
            20,
        )
        .unwrap();

        assert_eq!(outcome.udp_bytes_read_from_egress, 3);
    }

    #[test]
    fn bridge_maintenance_tick_honors_flow_count_budget() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut tcp_bridges = StackTcpBridgeTable::default();
        for port in [49152, 49153] {
            tcp_bridges.insert(
                StackTcpFlowKey::new(
                    SandboxId::new("s1").unwrap(),
                    FrontendKind::Tun,
                    format!("10.0.0.2:{port}").parse().unwrap(),
                    "203.0.113.10:80".parse().unwrap(),
                ),
                ReadableTcpStream::new(vec![b"tcp".to_vec()].into()),
            );
        }
        let mut udp_bridges = UdpBridgeTable::default();
        for port in [53000, 53001] {
            udp_bridges.insert_with_timeout(
                UdpFlowKey {
                    sandbox_id: SandboxId::new("s1").unwrap(),
                    frontend: FrontendKind::Tun,
                    source: format!("10.0.0.2:{port}").parse().unwrap(),
                    destination: "203.0.113.10:12345".parse().unwrap(),
                },
                ReadableUdpFlow::new(vec![b"udp".to_vec()].into()),
                10,
                60_000,
            );
        }
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: vec![OutboundIpPacket::new(vec![0x45, 0, 0, 20]).unwrap()],
        };

        let outcome = process_bridge_maintenance_tick(
            &mut device,
            BridgeMaintenanceStep {
                adapter: &mut adapter,
                tcp_bridges: &mut tcp_bridges,
                udp_bridges: &mut udp_bridges,
                max_tcp_read_bytes_per_stream: 1024,
                max_udp_read_bytes_per_flow: 1024,
                budget: BridgeMaintenanceBudget {
                    max_tcp_streams_per_tick: 1,
                    max_udp_flows_per_tick: 1,
                    max_tcp_streams_per_sandbox_per_tick: 1,
                    max_udp_flows_per_sandbox_per_tick: 1,
                    max_tcp_bytes_per_sandbox_per_tick: usize::MAX,
                    max_udp_bytes_per_sandbox_per_tick: usize::MAX,
                },
                now_millis: 20,
            },
        )
        .unwrap();

        assert_eq!(outcome.tcp_streams_read, 1);
        assert_eq!(outcome.tcp_bytes_read_from_egress, 3);
        assert_eq!(outcome.udp_flows_read, 1);
        assert_eq!(outcome.udp_bytes_read_from_egress, 3);
        assert_eq!(outcome.outbound_packets_written, 2);
        assert_eq!(adapter.writes.len(), 1);
    }

    #[test]
    fn udp_bridge_reads_host_reply_and_writes_sandbox_packet() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let key = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "203.0.113.10:12345".parse().unwrap(),
        };
        let mut bridges = UdpBridgeTable::default();
        bridges.insert(key, ReadableUdpFlow::new(vec![b"pong".to_vec()].into()));

        let outcome =
            flush_udp_bridge_reads_to_device(&mut device, &mut bridges, 1024, 20).unwrap();

        assert_eq!(outcome.udp_flows_read, 1);
        assert_eq!(outcome.udp_bytes_read_from_egress, 4);
        assert_eq!(outcome.outbound_packets_written, 1);
        let bytes = device.into_inner().into_inner();
        assert_eq!(bytes[9], 17);
        assert_eq!(&bytes[12..16], &[203, 0, 113, 10]);
        assert_eq!(&bytes[16..20], &[10, 0, 0, 2]);
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 12345);
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 53000);
        assert_eq!(&bytes[28..], b"pong");
    }

    #[test]
    fn udp_bridge_host_error_writes_ipv4_icmp_unreachable_and_removes_flow() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let key = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:53000".parse().unwrap(),
            destination: "203.0.113.10:12345".parse().unwrap(),
        };
        let mut bridges = UdpBridgeTable::default();
        bridges.insert(key, FailingUdpFlow);

        let outcome =
            flush_udp_bridge_reads_to_device(&mut device, &mut bridges, 1024, 20).unwrap();

        assert_eq!(outcome.udp_flows_read, 0);
        assert_eq!(outcome.udp_flows_removed_on_error, 1);
        assert_eq!(outcome.outbound_packets_written, 1);
        assert!(bridges.is_empty());
        let bytes = device.into_inner().into_inner();
        assert_eq!(bytes[9], 1);
        assert_eq!(bytes[20], 3);
        assert_eq!(bytes[21], 3);
        assert_eq!(&bytes[12..16], &[203, 0, 113, 10]);
        assert_eq!(&bytes[16..20], &[10, 0, 0, 2]);
    }

    #[test]
    fn udp_bridge_host_error_writes_ipv6_icmp_unreachable_and_removes_flow() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let key = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "[2001:db8::2]:53000".parse().unwrap(),
            destination: "[2001:db8::10]:12345".parse().unwrap(),
        };
        let mut bridges = UdpBridgeTable::default();
        bridges.insert(key, FailingUdpFlow);

        let outcome =
            flush_udp_bridge_reads_to_device(&mut device, &mut bridges, 1024, 20).unwrap();

        assert_eq!(outcome.udp_flows_read, 0);
        assert_eq!(outcome.udp_flows_removed_on_error, 1);
        assert_eq!(outcome.outbound_packets_written, 1);
        assert!(bridges.is_empty());
        let bytes = device.into_inner().into_inner();
        assert_eq!(bytes[6], 58);
        assert_eq!(bytes[40], 1);
        assert_eq!(bytes[41], 4);
    }

    #[test]
    fn udp_bridge_reads_ipv6_host_reply_and_writes_sandbox_packet() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let key = UdpFlowKey {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "[2001:db8::2]:53000".parse().unwrap(),
            destination: "[2001:db8::10]:12345".parse().unwrap(),
        };
        let mut bridges = UdpBridgeTable::default();
        bridges.insert(key, ReadableUdpFlow::new(vec![b"pong".to_vec()].into()));

        let outcome =
            flush_udp_bridge_reads_to_device(&mut device, &mut bridges, 1024, 20).unwrap();

        assert_eq!(outcome.udp_flows_read, 1);
        assert_eq!(outcome.udp_bytes_read_from_egress, 4);
        assert_eq!(outcome.outbound_packets_written, 1);
        let bytes = device.into_inner().into_inner();
        assert_eq!(bytes[0] >> 4, 6);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 12);
        assert_eq!(bytes[6], 17);
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(
            &bytes[24..40],
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(u16::from_be_bytes([bytes[40], bytes[41]]), 12345);
        assert_eq!(u16::from_be_bytes([bytes[42], bytes[43]]), 53000);
        assert_eq!(&bytes[48..], b"pong");
    }

    #[test]
    fn one_step_stack_runtime_returns_none_when_device_not_ready() {
        let mut device = PreopenedTunDevice::from_io(WouldBlockIo, 1500).unwrap();
        let mut adapter = MockStackAdapter::new();
        let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet_if_ready(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 20,
                timestamp_millis: 3000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert!(outcome.is_none());
        assert!(adapter.ingested.is_empty());
        assert!(audit.records().is_empty());
        assert!(tcp_bridges.is_empty());
    }

    #[test]
    fn one_step_runtime_records_stack_flow_close_audit() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut adapter = FlowClosedStackAdapter;
        let policy = PolicyEngine::new(RuntimeConfig::deny_by_default());
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();
        tcp_bridges.insert(
            StackTcpFlowKey::new(
                SandboxId::new("s1").unwrap(),
                FrontendKind::Tun,
                "10.0.0.2:49152".parse().unwrap(),
                "203.0.113.10:80".parse().unwrap(),
            ),
            MockTcpStream,
        );

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 20,
                timestamp_millis: 3000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert_eq!(outcome.flow_closed_events, 1);
        assert_eq!(outcome.tcp_bridges_removed, 1);
        assert!(tcp_bridges.is_empty());
        assert_eq!(audit.records().len(), 1);
        let record = audit.records().front().unwrap();
        assert_eq!(record.kind, foxprox_audit::AuditKind::FlowClosed);
        assert_eq!(record.flow_duration_millis, Some(250));
    }

    #[test]
    fn one_step_runtime_feeds_stack_adapter_events_through_policy_and_writes_output() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound.clone());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut adapter = MockStackAdapter::new();
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(foxprox_core::RuleId::new("tcp-80").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.port = PortMatcher::Exact(80);
        config.rules.push(rule);
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 10,
                timestamp_millis: 2000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert_eq!(outcome.broker_outcomes, vec![BrokerEventOutcome::Forwarded]);
        assert_eq!(outcome.outbound_packets_written, 1);
        assert_eq!(egress.tcp_connects.len(), 1);
        assert_eq!(audit.records().len(), 1);
        assert_eq!(adapter.ingested, vec![inbound.clone()]);
        let bytes = device.into_inner().into_inner();
        assert_eq!(&bytes[..inbound.len()], inbound.as_slice());
        assert_eq!(&bytes[inbound.len()..], &[0x45, 0, 0, 20]);
    }

    #[test]
    fn stack_policy_events_use_dns_attribution_before_policy() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let connect = tcp_connect_event();
        let mut adapter = ScriptedStackAdapter::new(vec![StackEvent::PolicyEvent(
            NormalizedEvent::TcpConnectAttempt(connect.clone()),
        )]);
        let now = Instant::now();
        let mut cache = DnsAttributionCache::default();
        cache.observe(
            Hostname::new("example.com").unwrap(),
            [connect.destination.ip()],
            now,
            std::time::Duration::from_secs(60),
        );
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(foxprox_core::RuleId::new("dns-domain").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.destination = DestinationMatcher::Hostname(Hostname::new("example.com").unwrap());
        config.rules.push(rule);
        let policy = PolicyEngine::new(config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 25,
                timestamp_millis: 3500,
                dns_attribution: Some(StackDnsAttribution { cache: &cache, now }),
            },
        )
        .unwrap();

        assert_eq!(outcome.broker_outcomes, vec![BrokerEventOutcome::Forwarded]);
        assert_eq!(egress.tcp_connects.len(), 1);
        let record = audit.records().front().unwrap();
        assert_eq!(record.hostname.as_ref().unwrap().as_str(), "example.com");
    }

    #[test]
    fn allowed_stack_tcp_connect_stores_bridge_and_writes_payload_to_egress() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let connect = tcp_connect_event();
        let data = foxprox_net::StackTcpData {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:49152".parse().unwrap(),
            destination: "203.0.113.10:80".parse().unwrap(),
            bytes: b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        };
        let mut adapter = ScriptedStackAdapter::new(vec![
            StackEvent::PolicyEvent(NormalizedEvent::TcpConnectAttempt(connect.clone())),
            StackEvent::TcpData(data),
        ]);
        let mut config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(foxprox_core::RuleId::new("tcp-80").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.port = PortMatcher::Exact(80);
        config.rules.push(rule);
        let mut http_rule = PolicyRule::allow(foxprox_core::RuleId::new("http").unwrap());
        http_rule.protocol = ProtocolMatcher::Exact(Protocol::Http);
        config.rules.push(http_rule);
        let policy = PolicyEngine::new(config);
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut egress = RecordingEgress::new(Rc::clone(&writes));
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 30,
                timestamp_millis: 4000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert_eq!(outcome.broker_outcomes, vec![BrokerEventOutcome::Forwarded]);
        assert_eq!(outcome.tcp_data_events, 1);
        assert_eq!(
            outcome.tcp_bytes_written_to_egress,
            b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n".len()
        );
        assert_eq!(outcome.tcp_data_without_bridge, 0);
        assert_eq!(outcome.transparent_inspection_events, 1);
        assert_eq!(outcome.transparent_inspection_denials, 0);
        assert_eq!(tcp_bridges.len(), 1);
        assert!(tcp_bridges.contains_key(&StackTcpFlowKey::from_connect_attempt(&connect)));
        assert_eq!(egress.tcp_connects, vec![connect]);
        assert_eq!(
            writes.borrow().as_slice(),
            &[b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()]
        );
        assert_eq!(audit.records().len(), 2);
    }

    #[test]
    fn transparent_http_denial_removes_bridge_without_forwarding_payload() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let connect = tcp_connect_event();
        let data = foxprox_net::StackTcpData {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:49152".parse().unwrap(),
            destination: "203.0.113.10:80".parse().unwrap(),
            bytes: b"GET /blocked HTTP/1.1\r\nHost: denied.example\r\n\r\n".to_vec(),
        };
        let mut adapter = ScriptedStackAdapter::new(vec![
            StackEvent::PolicyEvent(NormalizedEvent::TcpConnectAttempt(connect)),
            StackEvent::TcpData(data),
        ]);
        let mut config = RuntimeConfig::deny_by_default();
        let mut tcp_rule = PolicyRule::allow(foxprox_core::RuleId::new("tcp-80").unwrap());
        tcp_rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        tcp_rule.port = PortMatcher::Exact(80);
        config.rules.push(tcp_rule);
        let policy = PolicyEngine::new(config);
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut egress = RecordingEgress::new(Rc::clone(&writes));
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 30,
                timestamp_millis: 4000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert_eq!(outcome.broker_outcomes, vec![BrokerEventOutcome::Forwarded]);
        assert_eq!(outcome.transparent_inspection_events, 1);
        assert_eq!(outcome.transparent_inspection_denials, 1);
        assert_eq!(outcome.tcp_bytes_written_to_egress, 0);
        assert!(writes.borrow().is_empty());
        assert!(tcp_bridges.is_empty());
        assert_eq!(audit.records().len(), 2);
    }

    #[test]
    fn denied_stack_tcp_connect_does_not_store_bridge_or_write_payload() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let connect = tcp_connect_event();
        let data = foxprox_net::StackTcpData {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:49152".parse().unwrap(),
            destination: "203.0.113.10:80".parse().unwrap(),
            bytes: b"blocked".to_vec(),
        };
        let mut adapter = ScriptedStackAdapter::new(vec![
            StackEvent::PolicyEvent(NormalizedEvent::TcpConnectAttempt(connect)),
            StackEvent::TcpData(data),
        ]);
        let policy = PolicyEngine::new(RuntimeConfig::deny_by_default());
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut egress = RecordingEgress::new(Rc::clone(&writes));
        let mut audit = BoundedAuditSink::new(4);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 40,
                timestamp_millis: 5000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert_eq!(
            outcome.broker_outcomes,
            vec![BrokerEventOutcome::Denied(Some(
                foxprox_core::DenialAction::Drop
            ))]
        );
        assert_eq!(outcome.tcp_data_events, 1);
        assert_eq!(outcome.tcp_bytes_written_to_egress, 0);
        assert_eq!(outcome.tcp_data_without_bridge, 1);
        assert!(tcp_bridges.is_empty());
        assert!(egress.tcp_connects.is_empty());
        assert!(writes.borrow().is_empty());
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn bridge_table_retains_partial_sandbox_writes_for_later_flush() {
        let key = StackTcpFlowKey::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.2:49152".parse().unwrap(),
            "203.0.113.10:80".parse().unwrap(),
        );
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut bridges = StackTcpBridgeTable::default();
        bridges.insert(
            key.clone(),
            PartialWriteTcpStream {
                max_write: 2,
                writes: Rc::clone(&writes),
            },
        );
        let data = foxprox_net::StackTcpData {
            sandbox_id: key.sandbox_id.clone(),
            frontend: key.frontend,
            source: key.source,
            destination: key.destination,
            bytes: b"hello".to_vec(),
        };

        assert_eq!(bridges.write_from_sandbox(&data).unwrap(), Some(2));
        assert_eq!(bridges.pending_sandbox_bytes(&key), 3);
        assert_eq!(bridges.flush_pending_sandbox_writes().unwrap(), 2);
        assert_eq!(bridges.pending_sandbox_bytes(&key), 1);
        assert_eq!(bridges.flush_pending_sandbox_writes().unwrap(), 1);
        assert_eq!(bridges.pending_sandbox_bytes(&key), 0);
        assert_eq!(
            writes.borrow().as_slice(),
            &[b"he".to_vec(), b"ll".to_vec(), b"o".to_vec()]
        );
    }

    #[test]
    fn tcp_bridge_table_enforces_per_sandbox_stream_limit() {
        let mut bridges = StackTcpBridgeTable::with_limits(StackTcpBridgeLimits {
            max_pending_sandbox_bytes: usize::MAX,
            max_streams: usize::MAX,
            max_streams_per_sandbox: 1,
        });
        let first = StackTcpFlowKey::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.2:49152".parse().unwrap(),
            "203.0.113.10:80".parse().unwrap(),
        );
        let second = StackTcpFlowKey::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.2:49153".parse().unwrap(),
            "203.0.113.11:80".parse().unwrap(),
        );

        bridges.try_insert(first, MockTcpStream).unwrap();
        let error = match bridges.try_insert(second, MockTcpStream) {
            Ok(_) => panic!("expected TCP bridge sandbox stream limit error"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("TCP bridge sandbox stream limit"));
        assert_eq!(bridges.len(), 1);
    }

    #[test]
    fn bridge_table_rejects_pending_sandbox_bytes_over_limit() {
        let key = StackTcpFlowKey::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.2:49152".parse().unwrap(),
            "203.0.113.10:80".parse().unwrap(),
        );
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut bridges = StackTcpBridgeTable::with_limits(StackTcpBridgeLimits {
            max_pending_sandbox_bytes: 3,
            max_streams: usize::MAX,
            max_streams_per_sandbox: usize::MAX,
        });
        bridges.insert(
            key.clone(),
            PartialWriteTcpStream {
                max_write: 1,
                writes,
            },
        );
        let first = foxprox_net::StackTcpData {
            sandbox_id: key.sandbox_id.clone(),
            frontend: key.frontend,
            source: key.source,
            destination: key.destination,
            bytes: b"abc".to_vec(),
        };
        let second = foxprox_net::StackTcpData {
            sandbox_id: key.sandbox_id.clone(),
            frontend: key.frontend,
            source: key.source,
            destination: key.destination,
            bytes: b"de".to_vec(),
        };

        assert_eq!(bridges.write_from_sandbox(&first).unwrap(), Some(1));
        assert_eq!(bridges.pending_sandbox_bytes(&key), 2);
        let error = bridges.write_from_sandbox(&second).unwrap_err();

        assert!(error.to_string().contains("pending sandbox buffer limit"));
        assert_eq!(bridges.pending_sandbox_bytes(&key), 2);
    }

    #[test]
    fn bridge_reads_host_bytes_into_stack_adapter_and_writes_device_packets() {
        let cursor = Cursor::new(Vec::new());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let key = StackTcpFlowKey::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.2:49152".parse().unwrap(),
            "203.0.113.10:80".parse().unwrap(),
        );
        let mut bridges = StackTcpBridgeTable::default();
        bridges.insert(
            key.clone(),
            ReadableTcpStream::new(vec![b"world".to_vec()].into()),
        );
        let mut adapter = ReadBackStackAdapter {
            writes: Vec::new(),
            outbound: vec![OutboundIpPacket::new(vec![0x45, 0, 0, 20]).unwrap()],
        };

        let outcome =
            flush_tcp_bridge_reads_to_stack_device(&mut device, &mut adapter, &mut bridges, 1024)
                .unwrap();

        assert_eq!(outcome.tcp_streams_read, 1);
        assert_eq!(outcome.tcp_bytes_read_from_egress, 5);
        assert_eq!(outcome.tcp_bytes_enqueued_to_stack, 5);
        assert_eq!(outcome.outbound_packets_written, 1);
        assert_eq!(adapter.writes.len(), 1);
        assert_eq!(adapter.writes[0].source, key.source);
        assert_eq!(adapter.writes[0].destination, key.destination);
        assert_eq!(adapter.writes[0].bytes, b"world");
        assert_eq!(device.into_inner().into_inner(), vec![0x45, 0, 0, 20]);
    }

    struct FlowClosedStackAdapter;

    impl StackAdapter for FlowClosedStackAdapter {
        fn ingest_ip_packet(&mut self, _packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
            Ok(vec![StackEvent::FlowClosed(foxprox_net::StackFlowClosed {
                sandbox_id: SandboxId::new("s1").unwrap(),
                frontend: FrontendKind::Tun,
                key: foxprox_net::FlowKey {
                    source: "10.0.0.2:49152".parse().unwrap(),
                    destination: "203.0.113.10:80".parse().unwrap(),
                    protocol: FlowProtocol::Tcp,
                },
                byte_counts: foxprox_core::ByteCounts::new(10, 20),
                duration: std::time::Duration::from_millis(250),
            })])
        }

        fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError> {
            Ok(Vec::new())
        }
    }

    struct MockStackAdapter {
        ingested: Vec<Vec<u8>>,
        outbound: Vec<OutboundIpPacket>,
        event: NormalizedEvent,
    }

    impl MockStackAdapter {
        fn new() -> Self {
            Self {
                ingested: Vec::new(),
                outbound: vec![OutboundIpPacket::new(vec![0x45, 0, 0, 20]).unwrap()],
                event: NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
                    sandbox_id: SandboxId::new("s1").unwrap(),
                    frontend: FrontendKind::Tun,
                    source: "10.0.0.2:49152".parse().unwrap(),
                    destination: "203.0.113.10:80".parse().unwrap(),
                    hostname: None,
                }),
            }
        }
    }

    impl StackAdapter for MockStackAdapter {
        fn ingest_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
            self.ingested.push(packet.to_vec());
            Ok(vec![StackEvent::PolicyEvent(self.event.clone())])
        }

        fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError> {
            Ok(std::mem::take(&mut self.outbound))
        }
    }

    struct ScriptedStackAdapter {
        events: Vec<StackEvent>,
    }

    impl ScriptedStackAdapter {
        fn new(events: Vec<StackEvent>) -> Self {
            Self { events }
        }
    }

    impl StackAdapter for ScriptedStackAdapter {
        fn ingest_ip_packet(&mut self, _packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
            Ok(std::mem::take(&mut self.events))
        }

        fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError> {
            Ok(Vec::new())
        }
    }

    struct WouldBlockIo;

    impl Read for WouldBlockIo {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(ErrorKind::WouldBlock))
        }
    }

    impl Write for WouldBlockIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MaintenanceEgress;

    impl HostEgress for MaintenanceEgress {
        type TcpStream = ReadableTcpStream;
        type UdpHandle = MockUdpHandle;
        type HttpResponse = MockHttpResponse;

        fn connect_tcp(
            &mut self,
            _event: &TcpConnectAttempt,
        ) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn open_udp_flow(
            &mut self,
            _event: &UdpFlowAttempt,
        ) -> Result<Self::UdpHandle, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn proxy_http_request(
            &mut self,
            _event: &HttpRequest,
        ) -> Result<Self::HttpResponse, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn proxy_connect(&mut self, _event: &HttpsConnect) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn socks_connect(&mut self, _event: &SocksConnect) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn resolve_dns(&mut self, _event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError> {
            Ok(Vec::new())
        }
    }

    struct RecordingUdpEgress {
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl RecordingUdpEgress {
        fn new(writes: Rc<RefCell<Vec<Vec<u8>>>>) -> Self {
            Self { writes }
        }
    }

    impl HostEgress for RecordingUdpEgress {
        type TcpStream = MockTcpStream;
        type UdpHandle = RecordingUdpFlow;
        type HttpResponse = MockHttpResponse;

        fn connect_tcp(
            &mut self,
            _event: &TcpConnectAttempt,
        ) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn open_udp_flow(
            &mut self,
            _event: &UdpFlowAttempt,
        ) -> Result<Self::UdpHandle, EgressError> {
            Ok(RecordingUdpFlow {
                writes: Rc::clone(&self.writes),
            })
        }

        fn proxy_http_request(
            &mut self,
            _event: &HttpRequest,
        ) -> Result<Self::HttpResponse, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn proxy_connect(&mut self, _event: &HttpsConnect) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn socks_connect(&mut self, _event: &SocksConnect) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn resolve_dns(&mut self, _event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError> {
            Ok(Vec::new())
        }
    }

    struct RecordingUdpFlow {
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl HostUdpFlow for RecordingUdpFlow {
        fn send_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
            self.writes.borrow_mut().push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn recv_to_sandbox(&mut self, _max_bytes: usize) -> Result<Vec<u8>, EgressError> {
            Ok(Vec::new())
        }
    }

    struct ReadableUdpFlow {
        reads: std::collections::VecDeque<Vec<u8>>,
    }

    impl ReadableUdpFlow {
        fn new(reads: std::collections::VecDeque<Vec<u8>>) -> Self {
            Self { reads }
        }
    }

    impl HostUdpFlow for ReadableUdpFlow {
        fn send_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
            Ok(bytes.len())
        }

        fn recv_to_sandbox(&mut self, max_bytes: usize) -> Result<Vec<u8>, EgressError> {
            let Some(mut bytes) = self.reads.pop_front() else {
                return Ok(Vec::new());
            };
            bytes.truncate(max_bytes);
            Ok(bytes)
        }
    }

    struct FailingUdpFlow;

    impl HostUdpFlow for FailingUdpFlow {
        fn send_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
            Ok(bytes.len())
        }

        fn recv_to_sandbox(&mut self, _max_bytes: usize) -> Result<Vec<u8>, EgressError> {
            Err(EgressError::StreamIo("udp host failure".into()))
        }
    }

    struct RecordingEgress {
        tcp_connects: Vec<TcpConnectAttempt>,
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl RecordingEgress {
        fn new(writes: Rc<RefCell<Vec<Vec<u8>>>>) -> Self {
            Self {
                tcp_connects: Vec::new(),
                writes,
            }
        }
    }

    impl HostEgress for RecordingEgress {
        type TcpStream = RecordingTcpStream;
        type UdpHandle = MockUdpHandle;
        type HttpResponse = MockHttpResponse;

        fn connect_tcp(
            &mut self,
            event: &TcpConnectAttempt,
        ) -> Result<Self::TcpStream, EgressError> {
            self.tcp_connects.push(event.clone());
            Ok(RecordingTcpStream {
                writes: Rc::clone(&self.writes),
            })
        }

        fn open_udp_flow(
            &mut self,
            _event: &UdpFlowAttempt,
        ) -> Result<Self::UdpHandle, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn proxy_http_request(
            &mut self,
            _event: &HttpRequest,
        ) -> Result<Self::HttpResponse, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn proxy_connect(&mut self, _event: &HttpsConnect) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn socks_connect(&mut self, _event: &SocksConnect) -> Result<Self::TcpStream, EgressError> {
            Err(EgressError::UnsupportedAllowedEvent)
        }

        fn resolve_dns(&mut self, _event: &DnsQuery) -> Result<Vec<SocketAddr>, EgressError> {
            Ok(Vec::new())
        }
    }

    struct RecordingTcpStream {
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl HostTcpStream for RecordingTcpStream {
        fn write_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
            self.writes.borrow_mut().push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn read_to_sandbox(&mut self, _max_bytes: usize) -> Result<Vec<u8>, EgressError> {
            Ok(Vec::new())
        }
    }

    struct PartialWriteTcpStream {
        max_write: usize,
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl HostTcpStream for PartialWriteTcpStream {
        fn write_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
            let len = self.max_write.min(bytes.len());
            self.writes.borrow_mut().push(bytes[..len].to_vec());
            Ok(len)
        }

        fn read_to_sandbox(&mut self, _max_bytes: usize) -> Result<Vec<u8>, EgressError> {
            Ok(Vec::new())
        }
    }

    struct ReadableTcpStream {
        reads: std::collections::VecDeque<Vec<u8>>,
    }

    impl ReadableTcpStream {
        fn new(reads: std::collections::VecDeque<Vec<u8>>) -> Self {
            Self { reads }
        }
    }

    impl HostTcpStream for ReadableTcpStream {
        fn write_from_sandbox(&mut self, bytes: &[u8]) -> Result<usize, EgressError> {
            Ok(bytes.len())
        }

        fn read_to_sandbox(&mut self, max_bytes: usize) -> Result<Vec<u8>, EgressError> {
            let Some(mut bytes) = self.reads.pop_front() else {
                return Ok(Vec::new());
            };
            bytes.truncate(max_bytes);
            Ok(bytes)
        }
    }

    struct ReadBackStackAdapter {
        writes: Vec<StackTcpWrite>,
        outbound: Vec<OutboundIpPacket>,
    }

    impl StackAdapter for ReadBackStackAdapter {
        fn ingest_ip_packet(&mut self, _packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
            Ok(Vec::new())
        }

        fn send_tcp_data_to_sandbox(&mut self, data: &StackTcpWrite) -> Result<usize, StackError> {
            self.writes.push(data.clone());
            Ok(data.bytes.len())
        }

        fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError> {
            Ok(std::mem::take(&mut self.outbound))
        }
    }

    fn tcp_connect_event() -> TcpConnectAttempt {
        TcpConnectAttempt {
            sandbox_id: SandboxId::new("s1").unwrap(),
            frontend: FrontendKind::Tun,
            source: "10.0.0.2:49152".parse().unwrap(),
            destination: "203.0.113.10:80".parse().unwrap(),
            hostname: None,
        }
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

    fn udp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = 28 + payload.len();
        let udp_len = 8 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let ip_checksum = foxprox_packet::internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn udp_ipv6_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let source = "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap();
        let destination = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        let udp_len = 8 + payload.len();
        let mut packet = vec![0_u8; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
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
        let icmp_checksum = foxprox_packet::internet_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        let ip_checksum = foxprox_packet::internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }
}
