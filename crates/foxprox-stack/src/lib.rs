//! Userspace IP stack adapter proof for foxprox alpha.
//!
//! This crate intentionally keeps `smoltcp` types out of `foxprox-core`: core
//! owns policy/audit contracts, while this adapter proves that TUN-style IP
//! packets can be fed into the selected userspace stack and that outbound IP
//! packets can be collected for a future TUN fd writer.

#![forbid(unsafe_code)]

use smoltcp::iface::{Config, Interface, PollResult, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackPollEvidence {
    pub poll_result: &'static str,
    pub packets_emitted: usize,
    pub outbound_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct InMemoryIpDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: Rc<RefCell<Vec<Vec<u8>>>>,
    mtu: usize,
}

impl InMemoryIpDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: Rc::new(RefCell::new(Vec::new())),
            mtu,
        }
    }

    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    pub fn outbound_packets(&self) -> Vec<Vec<u8>> {
        self.outbound.borrow().clone()
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl Device for InMemoryIpDevice {
    type RxToken<'a>
        = InMemoryRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = InMemoryTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            InMemoryRxToken { packet },
            InMemoryTxToken {
                outbound: Rc::clone(&self.outbound),
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(InMemoryTxToken {
            outbound: Rc::clone(&self.outbound),
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

#[derive(Clone, Debug)]
pub struct InMemoryRxToken {
    packet: Vec<u8>,
}

impl RxToken for InMemoryRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[derive(Clone, Debug)]
pub struct InMemoryTxToken {
    outbound: Rc<RefCell<Vec<Vec<u8>>>>,
    mtu: usize,
}

impl TxToken for InMemoryTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= self.mtu, "smoltcp emitted packet larger than MTU");
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.outbound.borrow_mut().push(packet);
        result
    }
}

pub struct SmoltcpIpStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: InMemoryIpDevice,
}

impl SmoltcpIpStack {
    pub fn new_ipv4(address: [u8; 4], prefix_len: u8, mtu: usize) -> Self {
        let mut device = InMemoryIpDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5eed_1234;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(
                    IpAddress::v4(address[0], address[1], address[2], address[3]),
                    prefix_len,
                ))
                .expect("single interface address fits");
        });
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
        }
    }

    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.device.push_inbound(packet);
    }

    pub fn poll(&mut self, now_ms: i64) -> StackPollEvidence {
        let before = self.device.outbound.borrow().len();
        let result = self.iface.poll(
            Instant::from_millis(now_ms),
            &mut self.device,
            &mut self.sockets,
        );
        let outbound = self.device.outbound.borrow();
        let emitted = outbound.len().saturating_sub(before);
        let outbound_bytes = outbound.iter().skip(before).map(Vec::len).sum();
        StackPollEvidence {
            poll_result: poll_result_name(result),
            packets_emitted: emitted,
            outbound_bytes,
        }
    }

    pub fn outbound_packets(&self) -> Vec<Vec<u8>> {
        self.device.outbound_packets()
    }

    pub fn mtu(&self) -> usize {
        self.device.mtu()
    }
}

fn poll_result_name(result: PollResult) -> &'static str {
    match result {
        PollResult::None => "none",
        PollResult::SocketStateChanged => "socket_state_changed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{checksum, ParsedIpPacket};
    use pretty_assertions::assert_eq;

    #[test]
    fn smoltcp_stack_consumes_ip_packet_and_emits_icmp_reply() {
        let mut stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.inject_packet(ipv4_icmp_echo_request());

        let evidence = stack.poll(1_000);
        assert_eq!(evidence.packets_emitted, 1);
        assert!(evidence.outbound_bytes >= 28);
        assert_eq!(evidence.poll_result, "socket_state_changed");

        let outbound = stack.outbound_packets();
        let parsed = ParsedIpPacket::parse_ipv4(&outbound[0]).unwrap();
        assert_eq!(parsed.source.to_string(), "10.0.2.1");
        assert_eq!(parsed.destination.to_string(), "10.0.2.15");
        assert_eq!(parsed.icmp_type, Some(0));
        assert_eq!(checksum(&outbound[0][..20]), 0);
        assert_eq!(checksum(&outbound[0][20..]), 0);
    }

    #[test]
    fn in_memory_ip_device_exposes_bounded_mtu_capabilities() {
        let device = InMemoryIpDevice::new(1280);
        let capabilities = device.capabilities();
        assert_eq!(capabilities.medium, Medium::Ip);
        assert_eq!(capabilities.max_transmission_unit, 1280);
        assert_eq!(capabilities.max_burst_size, Some(1));
    }

    fn ipv4_icmp_echo_request() -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i'];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let total_len = 20 + icmp.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 2, 15]);
        packet[16..20].copy_from_slice(&[10, 0, 2, 1]);
        packet[20..].copy_from_slice(&icmp);
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }
}
