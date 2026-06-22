//! smoltcp-backed network stack adapter for foxprox.
//!
//! This crate is the stack-specific boundary: smoltcp types remain private and
//! callers interact through `foxprox-net::StackAdapter` only.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use foxprox_net::{OutboundIpPacket, StackAdapter, StackError, StackEvent};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

pub const CRATE_NAME: &str = "foxprox-smoltcp";

/// Public, stack-neutral configuration for the smoltcp adapter proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SmoltcpAdapterConfig {
    pub ipv4_addr: Ipv4Addr,
    pub ipv4_prefix_len: u8,
    pub mtu: usize,
    pub random_seed: u64,
}

impl SmoltcpAdapterConfig {
    pub fn new(ipv4_addr: Ipv4Addr, ipv4_prefix_len: u8, mtu: usize) -> Result<Self, StackError> {
        if mtu == 0 {
            return Err(StackError::Adapter(
                "smoltcp MTU must be greater than zero".into(),
            ));
        }
        if ipv4_prefix_len > 32 {
            return Err(StackError::Adapter("IPv4 prefix length exceeds 32".into()));
        }
        Ok(Self {
            ipv4_addr,
            ipv4_prefix_len,
            mtu,
            random_seed: 0x6650_584f_4c54,
        })
    }
}

/// smoltcp-backed adapter. All smoltcp interface/device/socket types are private
/// so policy, audit, and frontend crates cannot couple to the selected stack.
pub struct SmoltcpStackAdapter {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueuedIpDevice,
    now_millis: i64,
}

impl SmoltcpStackAdapter {
    pub fn new(config: SmoltcpAdapterConfig) -> Result<Self, StackError> {
        let mut device = QueuedIpDevice::new(config.mtu);
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = config.random_seed;
        let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
        let mut push_result = Ok(());
        iface.update_ip_addrs(|addrs| {
            push_result = addrs
                .push(IpCidr::new(
                    IpAddress::Ipv4(config.ipv4_addr),
                    config.ipv4_prefix_len,
                ))
                .map_err(|_| StackError::Adapter("smoltcp IP address table is full".into()));
        });
        push_result?;
        Ok(Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            now_millis: 0,
        })
    }

    fn now(&mut self) -> Instant {
        self.now_millis += 1;
        Instant::from_millis(self.now_millis)
    }
}

impl StackAdapter for SmoltcpStackAdapter {
    fn ingest_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
        if packet.is_empty() {
            return Err(StackError::MalformedPacket);
        }
        self.device.push_inbound(packet.to_vec())?;
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        Ok(Vec::new())
    }

    fn poll_outbound_packets(&mut self) -> Result<Vec<OutboundIpPacket>, StackError> {
        self.device
            .drain_outbound()
            .into_iter()
            .map(OutboundIpPacket::new)
            .collect()
    }
}

#[derive(Debug)]
struct QueuedIpDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueuedIpDevice {
    fn new(mtu: usize) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            mtu,
        }
    }

    fn push_inbound(&mut self, packet: Vec<u8>) -> Result<(), StackError> {
        if packet.len() > self.mtu {
            return Err(StackError::Adapter(format!(
                "inbound packet length {} exceeds smoltcp MTU {}",
                packet.len(),
                self.mtu
            )));
        }
        self.inbound.push_back(packet);
        Ok(())
    }

    fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }
}

impl Device for QueuedIpDevice {
    type RxToken<'a>
        = QueuedRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueuedTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inbound.pop_front().map(|buffer| {
            (
                QueuedRxToken { buffer },
                QueuedTxToken {
                    outbound: &mut self.outbound,
                    mtu: self.mtu,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueuedTxToken {
            outbound: &mut self.outbound,
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

struct QueuedRxToken {
    buffer: Vec<u8>,
}

impl RxToken for QueuedRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct QueuedTxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TxToken for QueuedTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let capped_len = len.min(self.mtu);
        let mut buffer = vec![0_u8; capped_len];
        let result = f(&mut buffer);
        self.outbound.push_back(buffer);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_marker() {
        assert_eq!(CRATE_NAME, "foxprox-smoltcp");
    }

    #[test]
    fn smoltcp_adapter_keeps_stack_types_private_and_emits_opaque_packets() {
        let config = SmoltcpAdapterConfig::new("10.0.0.1".parse().unwrap(), 24, 1500).unwrap();
        let mut adapter = SmoltcpStackAdapter::new(config).unwrap();
        let request = echo_request_packet();

        let events = adapter.ingest_ip_packet(&request).unwrap();
        let outbound = adapter.poll_outbound_packets().unwrap();

        assert!(events.is_empty());
        assert_eq!(outbound.len(), 1);
        let packet = outbound[0].bytes();
        assert_eq!(&packet[12..16], &[10, 0, 0, 1]);
        assert_eq!(&packet[16..20], &[10, 0, 0, 2]);
        assert_eq!(packet[20], 0);
        assert_eq!(foxprox_packet::internet_checksum(&packet[..20]), 0);
        assert_eq!(foxprox_packet::internet_checksum(&packet[20..]), 0);
    }

    #[test]
    fn adapter_rejects_invalid_public_config_without_exposing_smoltcp_errors() {
        assert!(SmoltcpAdapterConfig::new("10.0.0.1".parse().unwrap(), 33, 1500).is_err());
        assert!(SmoltcpAdapterConfig::new("10.0.0.1".parse().unwrap(), 24, 0).is_err());
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
