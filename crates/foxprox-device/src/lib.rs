//! Device IO adapters for foxprox alpha runtime integration.
//!
//! `foxprox-core` owns policy/audit/packet contracts. This crate provides a
//! small TUN-like packet device adapter over replaceable `Read`/`Write` objects
//! so Linux-specific TUN opening can be added without changing core logic.

#![forbid(unsafe_code)]

use foxprox_core::{DeviceIoError, PacketDevice};
use std::io::{Read, Write};

#[derive(Debug)]
pub struct TunIoPacketDevice<RW> {
    io: RW,
    mtu: usize,
}

impl<RW> TunIoPacketDevice<RW> {
    pub fn new(io: RW, mtu: usize) -> Self {
        Self { io, mtu }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn into_inner(self) -> RW {
        self.io
    }
}

impl<RW: Read + Write> PacketDevice for TunIoPacketDevice<RW> {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
        let mut packet = vec![0u8; self.mtu.max(1)];
        match self.io.read(&mut packet) {
            Ok(0) => Ok(None),
            Ok(len) => {
                packet.truncate(len);
                Ok(Some(packet))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(DeviceIoError::ReadFailed),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceIoError> {
        if packet.len() > self.mtu {
            return Err(DeviceIoError::WriteFailed);
        }
        self.io
            .write_all(packet)
            .map_err(|_| DeviceIoError::WriteFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        checksum, BrokerCore, Decision, PolicyConfig, PolicyEngine, TunPacketHarness,
    };
    use pretty_assertions::assert_eq;
    use std::collections::VecDeque;
    use std::io;

    #[derive(Debug, Default)]
    struct ScriptedTunIo {
        reads: VecDeque<io::Result<Vec<u8>>>,
        writes: Vec<Vec<u8>>,
        fail_writes: bool,
    }

    impl ScriptedTunIo {
        fn with_packets(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                reads: packets.into_iter().map(Ok).collect(),
                writes: Vec::new(),
                fail_writes: false,
            }
        }
    }

    impl Read for ScriptedTunIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                Some(Ok(packet)) => {
                    let len = packet.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                }
                Some(Err(error)) => Err(error),
                None => Ok(0),
            }
        }
    }

    impl Write for ScriptedTunIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_writes {
                return Err(io::Error::other("write failed"));
            }
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tun_io_device_feeds_packet_harness_observation() {
        let packet = ipv4_packet(17, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let io = ScriptedTunIo::with_packets([packet]);
        let device = TunIoPacketDevice::new(io, 1500);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(1_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[0].details["packet_len"], "28");
    }

    #[test]
    fn tun_io_device_writes_icmp_reply_after_audit() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, &icmp);
        let io = ScriptedTunIo::with_packets([packet]);
        let device = TunIoPacketDevice::new(io, 1500);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(2_000).unwrap().unwrap();
        assert!(result.wrote_packet);
        let (_, device) = harness.into_parts();
        let io = device.into_inner();
        assert_eq!(io.writes.len(), 1);
        assert_eq!(io.writes[0][20], 0);
    }

    #[test]
    fn tun_io_device_maps_would_block_to_idle_read() {
        let mut io = ScriptedTunIo::default();
        io.reads.push_back(Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "no packet ready",
        )));
        let mut device = TunIoPacketDevice::new(io, 1500);

        assert_eq!(device.read_packet().unwrap(), None);
    }

    #[test]
    fn tun_io_device_maps_read_write_failures() {
        let mut read_fail = ScriptedTunIo::default();
        read_fail
            .reads
            .push_back(Err(io::Error::other("read failed")));
        let mut device = TunIoPacketDevice::new(read_fail, 1500);
        assert_eq!(device.read_packet().unwrap_err(), DeviceIoError::ReadFailed);

        let write_fail = ScriptedTunIo {
            fail_writes: true,
            ..ScriptedTunIo::default()
        };
        let mut device = TunIoPacketDevice::new(write_fail, 1500);
        assert_eq!(
            device.write_packet(b"abc").unwrap_err(),
            DeviceIoError::WriteFailed
        );
        assert_eq!(
            device.write_packet(&vec![0; 1501]).unwrap_err(),
            DeviceIoError::WriteFailed
        );
    }

    fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 2, 15]);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        packet[20..].copy_from_slice(payload);
        let csum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&csum.to_be_bytes());
        packet
    }
}
