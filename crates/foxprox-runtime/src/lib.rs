//! Runtime orchestration for foxprox broker loops.
//!
//! This crate wires device IO to packet-policy orchestration. It owns no policy
//! model and does not parse raw packets itself.

#![forbid(unsafe_code)]

use std::fmt;

use foxprox_audit::AuditSink;
use foxprox_core::{FrontendKind, SandboxId};
use foxprox_device::{DeviceError, DevicePacket, PacketDevice};
use foxprox_egress::HostEgress;
use foxprox_net::{handle_ipv4_packet, BrokerError, InboundIpv4Packet, PacketBrokerOutcome};
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

    for outbound in &outcome.outbound_packets {
        let packet = DevicePacket::new(outbound.bytes().to_vec()).map_err(RuntimeError::Device)?;
        device.write_packet(&packet).map_err(RuntimeError::Device)?;
    }

    Ok(outcome)
}

#[derive(Debug)]
pub enum RuntimeError {
    Device(DeviceError),
    Broker(BrokerError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => write!(f, "device runtime error: {error}"),
            Self::Broker(error) => write!(f, "broker runtime error: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use foxprox_audit::BoundedAuditSink;
    use foxprox_core::RuntimeConfig;
    use foxprox_device::PreopenedTunDevice;
    use foxprox_egress::MockEgress;

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
