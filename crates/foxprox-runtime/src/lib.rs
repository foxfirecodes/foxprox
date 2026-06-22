//! Runtime orchestration for foxprox broker loops.
//!
//! This crate wires device IO to packet-policy orchestration. It owns no policy
//! model and does not parse raw packets itself.

#![forbid(unsafe_code)]

use std::fmt;

use foxprox_audit::{AuditRecord, AuditSink, FlowClosedAudit};
use foxprox_core::{FrontendKind, Protocol, SandboxId};
use foxprox_device::{DeviceError, DevicePacket, PacketDevice};
use foxprox_egress::HostEgress;
use foxprox_net::{
    handle_ipv4_packet, handle_normalized_event, BrokerError, BrokerEventOutcome, FlowProtocol,
    InboundIpv4Packet, OutboundIpPacket, PacketBrokerOutcome, StackAdapter, StackEvent,
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

/// Context for processing one packet through a stack adapter.
pub struct StackDevicePacketStep<'a, S, E, A> {
    pub adapter: &'a mut S,
    pub policy: &'a PolicyEngine,
    pub egress: &'a mut E,
    pub audit: &'a mut A,
    pub sequence_start: u64,
    pub timestamp_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackDevicePacketOutcome {
    pub broker_outcomes: Vec<BrokerEventOutcome>,
    pub tcp_data_events: usize,
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
    let mut flow_closed_events = 0;

    for (offset, event) in events.into_iter().enumerate() {
        match event {
            StackEvent::PolicyEvent(event) => {
                let outcome = handle_normalized_event(
                    &event,
                    ctx.policy,
                    ctx.egress,
                    ctx.audit,
                    ctx.sequence_start + offset as u64,
                    ctx.timestamp_millis,
                )
                .map_err(RuntimeError::Broker)?;
                broker_outcomes.push(outcome);
            }
            StackEvent::TcpData(_) => {
                tcp_data_events += 1;
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
    use std::io::Cursor;

    use foxprox_audit::BoundedAuditSink;
    use foxprox_core::{
        NormalizedEvent, PolicyRule, PortMatcher, Protocol, ProtocolMatcher, RuntimeConfig,
        TcpConnectAttempt,
    };
    use foxprox_device::PreopenedTunDevice;
    use foxprox_egress::MockEgress;
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

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
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

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
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
