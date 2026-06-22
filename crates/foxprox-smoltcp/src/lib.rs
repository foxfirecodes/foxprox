//! smoltcp-backed network stack adapter for foxprox.
//!
//! This crate is the stack-specific boundary: smoltcp types remain private and
//! callers interact through `foxprox-net::StackAdapter` only.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use foxprox_core::{FrontendKind, NormalizedEvent, SandboxId, TcpConnectAttempt};
use foxprox_net::{OutboundIpPacket, StackAdapter, StackError, StackEvent};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

pub const CRATE_NAME: &str = "foxprox-smoltcp";

/// Public, stack-neutral configuration for the smoltcp adapter proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmoltcpAdapterConfig {
    pub sandbox_id: SandboxId,
    pub frontend: FrontendKind,
    pub ipv4_addr: Ipv4Addr,
    pub ipv4_prefix_len: u8,
    pub mtu: usize,
    pub random_seed: u64,
    pub tcp_listen_ports: Vec<u16>,
}

impl SmoltcpAdapterConfig {
    pub fn new(
        sandbox_id: SandboxId,
        frontend: FrontendKind,
        ipv4_addr: Ipv4Addr,
        ipv4_prefix_len: u8,
        mtu: usize,
    ) -> Result<Self, StackError> {
        if mtu == 0 {
            return Err(StackError::Adapter(
                "smoltcp MTU must be greater than zero".into(),
            ));
        }
        if ipv4_prefix_len > 32 {
            return Err(StackError::Adapter("IPv4 prefix length exceeds 32".into()));
        }
        Ok(Self {
            sandbox_id,
            frontend,
            ipv4_addr,
            ipv4_prefix_len,
            mtu,
            random_seed: 0x6650_584f_4c54,
            tcp_listen_ports: Vec::new(),
        })
    }

    pub fn with_tcp_listener(mut self, port: u16) -> Self {
        self.tcp_listen_ports.push(port);
        self
    }
}

/// smoltcp-backed adapter. All smoltcp interface/device/socket types are private
/// so policy, audit, and frontend crates cannot couple to the selected stack.
pub struct SmoltcpStackAdapter {
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp_listeners: Vec<TcpListenerState>,
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
        let mut sockets = SocketSet::new(Vec::new());
        let mut tcp_listeners = Vec::new();
        for port in config.tcp_listen_ports.iter().copied() {
            let handle = add_tcp_listener(&mut sockets, port)?;
            tcp_listeners.push(TcpListenerState {
                handle,
                observed_connect: false,
            });
        }
        Ok(Self {
            sandbox_id: config.sandbox_id,
            frontend: config.frontend,
            iface,
            sockets,
            tcp_listeners,
            device,
            now_millis: 0,
        })
    }

    fn now(&mut self) -> Instant {
        self.now_millis += 1;
        Instant::from_millis(self.now_millis)
    }

    fn collect_tcp_connect_events(&mut self) -> Vec<StackEvent> {
        let mut events = Vec::new();
        for listener in &mut self.tcp_listeners {
            if listener.observed_connect {
                continue;
            }
            let socket = self.sockets.get::<tcp::Socket>(listener.handle);
            let Some(remote) = endpoint_to_socket_addr(socket.remote_endpoint()) else {
                continue;
            };
            let Some(local) = endpoint_to_socket_addr(socket.local_endpoint()) else {
                continue;
            };
            listener.observed_connect = true;
            events.push(StackEvent::PolicyEvent(NormalizedEvent::TcpConnectAttempt(
                TcpConnectAttempt {
                    sandbox_id: self.sandbox_id.clone(),
                    frontend: self.frontend,
                    source: remote,
                    destination: local,
                    hostname: None,
                },
            )));
        }
        events
    }
}

fn add_tcp_listener(
    sockets: &mut SocketSet<'static>,
    port: u16,
) -> Result<SocketHandle, StackError> {
    if port == 0 {
        return Err(StackError::Adapter(
            "TCP listener port must not be zero".into(),
        ));
    }
    let rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
    let tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
    let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
    socket
        .listen(port)
        .map_err(|error| StackError::Adapter(format!("smoltcp TCP listen failed: {error:?}")))?;
    Ok(sockets.add(socket))
}

fn endpoint_to_socket_addr(endpoint: Option<IpEndpoint>) -> Option<SocketAddr> {
    let endpoint = endpoint?;
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip),
    };
    Some(SocketAddr::new(ip, endpoint.port))
}

struct TcpListenerState {
    handle: SocketHandle,
    observed_connect: bool,
}

impl StackAdapter for SmoltcpStackAdapter {
    fn ingest_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
        if packet.is_empty() {
            return Err(StackError::MalformedPacket);
        }
        self.device.push_inbound(packet.to_vec())?;
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        Ok(self.collect_tcp_connect_events())
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
        let config = SmoltcpAdapterConfig::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.1".parse().unwrap(),
            24,
            1500,
        )
        .unwrap();
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
        assert!(SmoltcpAdapterConfig::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.1".parse().unwrap(),
            33,
            1500
        )
        .is_err());
        assert!(SmoltcpAdapterConfig::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.1".parse().unwrap(),
            24,
            0
        )
        .is_err());
    }

    #[test]
    fn tcp_syn_to_listened_port_emits_normalized_connect_attempt() {
        let config = SmoltcpAdapterConfig::new(
            SandboxId::new("s1").unwrap(),
            FrontendKind::Tun,
            "10.0.0.1".parse().unwrap(),
            24,
            1500,
        )
        .unwrap()
        .with_tcp_listener(80);
        let mut adapter = SmoltcpStackAdapter::new(config).unwrap();
        let syn = tcp_syn_packet();

        let events = adapter.ingest_ip_packet(&syn).unwrap();
        let outbound = adapter.poll_outbound_packets().unwrap();

        assert_eq!(events.len(), 1);
        let StackEvent::PolicyEvent(NormalizedEvent::TcpConnectAttempt(event)) = &events[0] else {
            panic!("expected TCP connect attempt");
        };
        assert_eq!(event.sandbox_id.as_str(), "s1");
        assert_eq!(event.frontend, FrontendKind::Tun);
        assert_eq!(event.source, "10.0.0.2:49152".parse().unwrap());
        assert_eq!(event.destination, "10.0.0.1:80".parse().unwrap());
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].bytes()[9], 6);
    }

    fn tcp_syn_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&49152_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x02;
        packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
        let tcp_checksum = tcp_checksum_ipv4([10, 0, 0, 2], [10, 0, 0, 1], &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        let ip_checksum = foxprox_packet::internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn tcp_checksum_ipv4(source: [u8; 4], destination: [u8; 4], tcp: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        foxprox_packet::internet_checksum(&pseudo)
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
