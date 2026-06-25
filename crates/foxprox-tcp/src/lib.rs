//! Userspace TCP/IP stack integration proofs for foxprox.
//!
//! This crate starts with a narrow smoltcp device adapter proof: feed one raw IP
//! packet into smoltcp and capture outbound raw IP packets for TUN write-back.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::rc::Rc;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// In-memory raw-IP device for smoltcp/TUN integration tests.
#[derive(Debug)]
pub struct InMemoryIpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Rc<RefCell<Vec<Vec<u8>>>>,
    mtu: usize,
}

impl InMemoryIpDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Rc::new(RefCell::new(Vec::new())),
            mtu,
        }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    pub fn take_tx(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.tx.borrow_mut())
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
        let packet = self.rx.pop_front()?;
        Some((
            InMemoryRxToken { packet },
            InMemoryTxToken {
                tx: Rc::clone(&self.tx),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(InMemoryTxToken {
            tx: Rc::clone(&self.tx),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = self.mtu;
        capabilities.medium = Medium::Ip;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct InMemoryTxToken {
    tx: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl TxToken for InMemoryTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.tx.borrow_mut().push(packet);
        result
    }
}

/// Byte counts for one smoltcp socket ↔ host stream relay step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpRelayOnceStats {
    pub sandbox_to_host_bytes: usize,
    pub host_to_sandbox_bytes: usize,
}

/// Errors from one smoltcp socket ↔ host stream relay step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpRelayError {
    SmoltcpRecv(String),
    HostWrite(String),
    HostRead(String),
    SmoltcpSend(String),
}

impl std::fmt::Display for TcpRelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SmoltcpRecv(error) => write!(f, "tcp-relay-smoltcp-recv-error: {error}"),
            Self::HostWrite(error) => write!(f, "tcp-relay-host-write-error: {error}"),
            Self::HostRead(error) => write!(f, "tcp-relay-host-read-error: {error}"),
            Self::SmoltcpSend(error) => write!(f, "tcp-relay-smoltcp-send-error: {error}"),
        }
    }
}

impl std::error::Error for TcpRelayError {}

/// Minimal smoltcp TCP server wrapper for TUN integration proofs.
pub struct SmoltcpTcpServer {
    iface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    device: InMemoryIpDevice,
    now_millis: i64,
}

impl SmoltcpTcpServer {
    pub fn new(ip: Ipv4Addr, prefix_len: u8, listen_port: u16, mtu: usize) -> Self {
        let mut device = InMemoryIpDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1234;
        let now = Instant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::Ipv4(ip), prefix_len))
                .unwrap();
        });
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 8192]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 8192]);
        let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(tcp_socket);
        sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(listen_port)
            .unwrap();
        Self {
            iface,
            sockets,
            handle,
            device,
            now_millis: 0,
        }
    }

    pub fn accept_packet(&mut self, packet: Vec<u8>) -> Vec<Vec<u8>> {
        self.device.push_rx(packet);
        self.poll()
    }

    pub fn relay_once<H: Read + Write>(
        &mut self,
        host: &mut H,
        sandbox_buffer_len: usize,
        host_buffer_len: usize,
    ) -> Result<TcpRelayOnceStats, TcpRelayError> {
        relay_tcp_socket_once(
            self.sockets.get_mut::<tcp::Socket>(self.handle),
            host,
            sandbox_buffer_len,
            host_buffer_len,
        )
    }

    pub fn can_recv(&mut self) -> bool {
        self.sockets.get_mut::<tcp::Socket>(self.handle).can_recv()
    }

    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::from_millis(self.now_millis);
        self.now_millis += 1;
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.device.take_tx()
    }
}

/// Relay one available smoltcp TCP payload to a host stream and one host
/// response back into the smoltcp socket.
pub fn relay_tcp_socket_once<H: Read + Write>(
    socket: &mut tcp::Socket<'_>,
    host: &mut H,
    sandbox_buffer_len: usize,
    host_buffer_len: usize,
) -> Result<TcpRelayOnceStats, TcpRelayError> {
    let mut sandbox_payload = vec![0_u8; sandbox_buffer_len];
    let sandbox_to_host_bytes = socket
        .recv_slice(&mut sandbox_payload)
        .map_err(|error| TcpRelayError::SmoltcpRecv(format!("{error:?}")))?;
    sandbox_payload.truncate(sandbox_to_host_bytes);
    host.write_all(&sandbox_payload)
        .map_err(|error| TcpRelayError::HostWrite(error.to_string()))?;

    let mut host_payload = vec![0_u8; host_buffer_len];
    let host_to_sandbox_bytes = host
        .read(&mut host_payload)
        .map_err(|error| TcpRelayError::HostRead(error.to_string()))?;
    host_payload.truncate(host_to_sandbox_bytes);
    socket
        .send_slice(&host_payload)
        .map_err(|error| TcpRelayError::SmoltcpSend(format!("{error:?}")))?;

    Ok(TcpRelayOnceStats {
        sandbox_to_host_bytes,
        host_to_sandbox_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::socket::tcp;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    #[test]
    fn smoltcp_socket_receives_and_sends_payload_after_handshake() {
        let mut device = InMemoryIpDevice::new(1500);
        device.push_rx(ipv4_tcp_syn_packet());
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1234;
        let now = Instant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
        });
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(tcp_socket);
        sockets.get_mut::<tcp::Socket>(handle).listen(8080).unwrap();

        iface.poll(now, &mut device, &mut sockets);
        let syn_ack = device
            .take_tx()
            .into_iter()
            .find(|packet| packet.len() >= 40 && packet[9] == 6)
            .unwrap();
        let server_seq = u32::from_be_bytes([syn_ack[24], syn_ack[25], syn_ack[26], syn_ack[27]]);
        device.push_rx(ipv4_tcp_packet(2, server_seq + 1, 0x18, b"hello"));

        iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_addr = listener.local_addr().unwrap();
        let host_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = [0_u8; 16];
            let length = stream.read(&mut received).unwrap();
            assert_eq!(&received[..length], b"hello");
            stream.write_all(b"world").unwrap();
        });
        let mut host = TcpStream::connect(host_addr).unwrap();
        let stats =
            relay_tcp_socket_once(sockets.get_mut::<tcp::Socket>(handle), &mut host, 16, 16)
                .unwrap();
        host_thread.join().unwrap();
        assert_eq!(
            stats,
            TcpRelayOnceStats {
                sandbox_to_host_bytes: 5,
                host_to_sandbox_bytes: 5,
            }
        );

        let _ack_only = device.take_tx();
        iface.poll(Instant::from_millis(2), &mut device, &mut sockets);
        let outbound = device.take_tx();
        let data_packet = outbound
            .iter()
            .find(|packet| packet.ends_with(b"world"))
            .expect("smoltcp emits TCP payload packet");
        assert_eq!(&data_packet[12..16], &[10, 0, 0, 1]);
        assert_eq!(&data_packet[16..20], &[10, 0, 0, 2]);
        assert_eq!(u16::from_be_bytes([data_packet[20], data_packet[21]]), 8080);
        assert_eq!(
            u16::from_be_bytes([data_packet[22], data_packet[23]]),
            49152
        );
    }

    #[test]
    fn smoltcp_ip_device_accepts_tcp_syn_and_emits_syn_ack() {
        let mut device = InMemoryIpDevice::new(1500);
        device.push_rx(ipv4_tcp_syn_packet());
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1234;
        let now = Instant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
        });
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(tcp_socket);
        sockets.get_mut::<tcp::Socket>(handle).listen(8080).unwrap();

        iface.poll(now, &mut device, &mut sockets);
        let outbound = device.take_tx();

        assert!(sockets.get::<tcp::Socket>(handle).is_active());
        let syn_ack = outbound
            .iter()
            .find(|packet| packet.len() >= 40 && packet[9] == 6)
            .expect("smoltcp emits TCP response packet");
        assert_eq!(syn_ack[0] >> 4, 4);
        assert_eq!(&syn_ack[12..16], &[10, 0, 0, 1]);
        assert_eq!(&syn_ack[16..20], &[10, 0, 0, 2]);
        assert_eq!(u16::from_be_bytes([syn_ack[20], syn_ack[21]]), 8080);
        assert_eq!(u16::from_be_bytes([syn_ack[22], syn_ack[23]]), 49152);
        assert_eq!(syn_ack[33] & 0x12, 0x12, "SYN and ACK flags are set");
    }

    fn ipv4_tcp_syn_packet() -> Vec<u8> {
        ipv4_tcp_packet(1, 0, 0x02, &[])
    }

    fn ipv4_tcp_packet(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0_u8; 20 + payload.len()];
        tcp[0..2].copy_from_slice(&49152_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&8080_u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240_u16.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        let mut packet = ipv4_packet(6, [10, 0, 0, 2], [10, 0, 0, 1], &tcp);
        let checksum = tcp_checksum(&packet);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_length = 20 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..].copy_from_slice(payload);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn tcp_checksum(packet: &[u8]) -> u16 {
        let tcp = &packet[20..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..16]);
        pseudo.extend_from_slice(&packet[16..20]);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        internet_checksum(&pseudo)
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from(chunk[0]) << 8
            };
            sum += u32::from(word);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
        }
        !(sum as u16)
    }
}
