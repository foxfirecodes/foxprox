//! Deterministic smoltcp gate checks for the future transparent TCP stack adapter.
//!
//! This module intentionally uses an in-memory IP-medium device instead of Linux fd handling. It
//! proves that TUN-shaped IPv4 packets can enter smoltcp and that smoltcp emits IP packets back out,
//! while the real broker/device code remains responsible for wiring those packets to a TUN fd.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::rc::Rc;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// Result from feeding one TCP SYN into the in-memory smoltcp IP device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmoltcpTcpGateResult {
    pub socket_active_after_poll: bool,
    pub emitted_packets: Vec<Vec<u8>>,
}

/// Feed a TUN-shaped IPv4/TCP packet into smoltcp and listen on `listen_ip:listen_port`.
///
/// This is the smallest reusable proof for the alpha TCP forwarding gate: the stack consumes an
/// inbound IP packet, recognizes a listening TCP socket, and emits at least one outbound IP packet
/// that a TUN frontend could write back to the sandbox.
pub fn feed_tcp_syn_to_smoltcp_listener(
    syn_packet: Vec<u8>,
    listen_ip: Ipv4Addr,
    listen_port: u16,
) -> Result<SmoltcpTcpGateResult, String> {
    let transmitted = Rc::new(RefCell::new(Vec::new()));
    let mut device = MemoryIpDevice {
        rx: VecDeque::from([syn_packet]),
        tx: transmitted.clone(),
    };

    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x5eed_1234;
    let timestamp = Instant::from_millis(0);
    let mut iface = Interface::new(config, &mut device, timestamp);
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(
                IpAddress::v4(
                    listen_ip.octets()[0],
                    listen_ip.octets()[1],
                    listen_ip.octets()[2],
                    listen_ip.octets()[3],
                ),
                32,
            ))
            .expect("smoltcp IP address storage should have room for one IPv4 address");
    });

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
    let mut socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
    socket
        .listen(listen_port)
        .map_err(|err| format!("smoltcp TCP listen failed: {err:?}"))?;
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(socket);

    iface.poll(timestamp, &mut device, &mut sockets);
    let socket = sockets.get::<tcp::Socket>(handle);
    let socket_active_after_poll = socket.is_active();
    let emitted_packets = transmitted.borrow().clone();
    Ok(SmoltcpTcpGateResult {
        socket_active_after_poll,
        emitted_packets,
    })
}

#[derive(Debug)]
struct MemoryIpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl Device for MemoryIpDevice {
    type RxToken<'a>
        = MemoryRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = MemoryTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(|packet| {
            (
                MemoryRxToken { packet },
                MemoryTxToken {
                    transmitted: self.tx.clone(),
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(MemoryTxToken {
            transmitted: self.tx.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);
        caps
    }
}

#[derive(Debug)]
struct MemoryRxToken {
    packet: Vec<u8>,
}

impl RxToken for MemoryRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[derive(Debug)]
struct MemoryTxToken {
    transmitted: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl TxToken for MemoryTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.transmitted.borrow_mut().push(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::packet::{checksum, parse_ipv4, parse_tcp};

    use super::*;

    #[test]
    fn smoltcp_consumes_tun_shaped_tcp_syn_and_emits_syn_ack() {
        let listen_ip = Ipv4Addr::new(203, 0, 113, 20);
        let syn = tcp_syn_packet(Ipv4Addr::new(10, 0, 2, 2), listen_ip, 49152, 8080);
        let result = feed_tcp_syn_to_smoltcp_listener(syn, listen_ip, 8080).unwrap();
        assert!(result.socket_active_after_poll);
        let syn_ack = result
            .emitted_packets
            .iter()
            .find_map(|packet| {
                let ipv4 = parse_ipv4(packet).ok()?;
                let tcp = parse_tcp(ipv4.payload).ok()?;
                (ipv4.source == listen_ip
                    && ipv4.destination == Ipv4Addr::new(10, 0, 2, 2)
                    && tcp.source_port == 8080
                    && tcp.destination_port == 49152
                    && tcp.syn
                    && tcp.ack)
                    .then_some(())
            })
            .is_some();
        assert!(syn_ack, "smoltcp did not emit expected SYN-ACK: {result:?}");
    }

    fn tcp_syn_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let total_len = 40;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&64240_u16.to_be_bytes());
        let tcp_sum = tcp_checksum_ipv4(source, destination, tcp);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    fn tcp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp_segment);
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }
        checksum(&pseudo)
    }

    #[test]
    fn test_syn_packet_has_valid_shape_for_parser() {
        let destination = Ipv4Addr::new(203, 0, 113, 20);
        let packet = tcp_syn_packet(Ipv4Addr::new(10, 0, 2, 2), destination, 49152, 8080);
        let ipv4 = parse_ipv4(&packet).unwrap();
        let tcp = parse_tcp(ipv4.payload).unwrap();
        assert_eq!(ipv4.destination, destination);
        assert_eq!(tcp.destination_port, 8080);
        assert!(tcp.syn);
        assert!(!tcp.ack);
        assert_eq!(IpAddr::V4(ipv4.source).to_string(), "10.0.2.2");
    }
}
