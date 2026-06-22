//! Runtime orchestration for foxprox broker loops.
//!
//! This crate wires device IO to packet-policy orchestration. It owns no policy
//! model and does not parse raw packets itself.

#![forbid(unsafe_code)]

use std::{collections::HashMap, fmt, net::SocketAddr};

use foxprox_audit::{AuditRecord, AuditSink, FlowClosedAudit};
use foxprox_core::{FrontendKind, NormalizedEvent, Protocol, SandboxId, TcpConnectAttempt};
use foxprox_device::{DeviceError, DevicePacket, PacketDevice};
use foxprox_egress::{EgressError, EgressOutcome, HostEgress, HostTcpStream};
use foxprox_net::{
    handle_ipv4_packet, handle_normalized_event_with_egress, BrokerError, BrokerEventOutcome,
    FlowProtocol, InboundIpv4Packet, OutboundIpPacket, PacketBrokerOutcome, StackAdapter,
    StackEvent, StackTcpData, StackTcpWrite,
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
pub struct StackTcpBridgeTable<T> {
    streams: HashMap<StackTcpFlowKey, T>,
}

impl<T> Default for StackTcpBridgeTable<T> {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }
}

impl<T> StackTcpBridgeTable<T> {
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub fn contains_key(&self, key: &StackTcpFlowKey) -> bool {
        self.streams.contains_key(key)
    }

    pub fn insert(&mut self, key: StackTcpFlowKey, stream: T) -> Option<T> {
        self.streams.insert(key, stream)
    }

    pub fn remove(&mut self, key: &StackTcpFlowKey) -> Option<T> {
        self.streams.remove(key)
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
        let Some(stream) = self.streams.get_mut(&key) else {
            return Ok(None);
        };
        stream.write_from_sandbox(&event.bytes).map(Some)
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
    let mut reads = Vec::new();
    for (key, stream) in &mut bridges.streams {
        let bytes = stream
            .read_to_sandbox(max_bytes_per_stream)
            .map_err(BrokerError::Egress)
            .map_err(RuntimeError::Broker)?;
        if !bytes.is_empty() {
            reads.push((key.clone(), bytes));
        }
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackDevicePacketOutcome {
    pub broker_outcomes: Vec<BrokerEventOutcome>,
    pub tcp_data_events: usize,
    pub tcp_bytes_written_to_egress: usize,
    pub tcp_data_without_bridge: usize,
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
    let events = ctx
        .adapter
        .ingest_ip_packet(packet.bytes())
        .map_err(RuntimeError::Stack)?;
    let mut broker_outcomes = Vec::new();
    let mut tcp_data_events = 0;
    let mut tcp_bytes_written_to_egress = 0;
    let mut tcp_data_without_bridge = 0;
    let mut flow_closed_events = 0;

    for (offset, event) in events.into_iter().enumerate() {
        match event {
            StackEvent::PolicyEvent(event) => {
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
                        .insert(StackTcpFlowKey::from_connect_attempt(connect), stream);
                }
                broker_outcomes.push(result.outcome);
            }
            StackEvent::TcpData(data) => {
                tcp_data_events += 1;
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
        tcp_data_without_bridge,
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
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => write!(f, "device runtime error: {error}"),
            Self::Broker(error) => write!(f, "broker runtime error: {error}"),
            Self::Stack(error) => write!(f, "stack runtime error: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, io::Cursor, rc::Rc};

    use foxprox_audit::BoundedAuditSink;
    use foxprox_core::{
        DnsQuery, HttpRequest, HttpsConnect, NormalizedEvent, PolicyRule, PortMatcher, Protocol,
        ProtocolMatcher, RuntimeConfig, SocksConnect, TcpConnectAttempt, UdpFlowAttempt,
    };
    use foxprox_device::PreopenedTunDevice;
    use foxprox_egress::{MockEgress, MockHttpResponse, MockUdpHandle};
    use foxprox_net::StackError;

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
    fn one_step_runtime_records_stack_flow_close_audit() {
        let inbound = vec![0x45, 0, 0, 20];
        let cursor = Cursor::new(inbound);
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
        let mut adapter = FlowClosedStackAdapter;
        let policy = PolicyEngine::new(RuntimeConfig::deny_by_default());
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
                sequence_start: 20,
                timestamp_millis: 3000,
            },
        )
        .unwrap();

        assert_eq!(outcome.flow_closed_events, 1);
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
            bytes: b"hello".to_vec(),
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
            },
        )
        .unwrap();

        assert_eq!(outcome.broker_outcomes, vec![BrokerEventOutcome::Forwarded]);
        assert_eq!(outcome.tcp_data_events, 1);
        assert_eq!(outcome.tcp_bytes_written_to_egress, 5);
        assert_eq!(outcome.tcp_data_without_bridge, 0);
        assert_eq!(tcp_bridges.len(), 1);
        assert!(tcp_bridges.contains_key(&StackTcpFlowKey::from_connect_attempt(&connect)));
        assert_eq!(egress.tcp_connects, vec![connect]);
        assert_eq!(writes.borrow().as_slice(), &[b"hello".to_vec()]);
        assert_eq!(audit.records().len(), 1);
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
