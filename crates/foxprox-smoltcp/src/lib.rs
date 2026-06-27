//! smoltcp-backed network stack adapter for foxprox.
//!
//! This crate is the stack-specific boundary: smoltcp types remain private and
//! callers interact through `foxprox-net::StackAdapter` only.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use foxprox_core::{ByteCounts, FrontendKind, NormalizedEvent, SandboxId, TcpConnectAttempt};
use foxprox_net::{
    FlowKey, FlowProtocol, OutboundIpPacket, StackAdapter, StackError, StackEvent, StackFlowClosed,
    StackTcpData, StackTcpWrite,
};
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
    pub accept_any_ip: bool,
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
            accept_any_ip: false,
        })
    }

    pub fn with_tcp_listener(mut self, port: u16) -> Self {
        self.tcp_listen_ports.push(port);
        self
    }

    pub fn with_any_ip(mut self) -> Self {
        self.accept_any_ip = true;
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
        if config.accept_any_ip {
            iface.set_any_ip(true);
            iface
                .routes_mut()
                .add_default_ipv4_route(config.ipv4_addr)
                .map_err(|_| StackError::Adapter("smoltcp route table is full".into()))?;
        }
        let mut sockets = SocketSet::new(Vec::new());
        let mut tcp_listeners = Vec::new();
        for port in config.tcp_listen_ports.iter().copied() {
            let handle = add_tcp_listener(&mut sockets, port)?;
            tcp_listeners.push(TcpListenerState {
                handle,
                observed_connect: false,
                closed_reported: false,
                flow_key: None,
                sandbox_to_host_bytes: 0,
                host_to_sandbox_bytes: 0,
                connected_at_millis: 0,
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

    fn collect_tcp_events(&mut self) -> Vec<StackEvent> {
        let mut events = Vec::new();
        for listener in &mut self.tcp_listeners {
            let socket = self.sockets.get_mut::<tcp::Socket>(listener.handle);
            if listener.observed_connect && !listener.closed_reported && !socket.is_active() {
                if let Some(key) = listener.flow_key.clone() {
                    listener.closed_reported = true;
                    events.push(StackEvent::FlowClosed(StackFlowClosed {
                        sandbox_id: self.sandbox_id.clone(),
                        frontend: self.frontend,
                        key,
                        byte_counts: ByteCounts::new(
                            listener.sandbox_to_host_bytes,
                            listener.host_to_sandbox_bytes,
                        ),
                        duration: std::time::Duration::from_millis(
                            self.now_millis
                                .saturating_sub(listener.connected_at_millis)
                                .max(0) as u64,
                        ),
                    }));
                }
                continue;
            }
            let Some(remote) = endpoint_to_socket_addr(socket.remote_endpoint()) else {
                continue;
            };
            let Some(local) = endpoint_to_socket_addr(socket.local_endpoint()) else {
                continue;
            };
            if !listener.observed_connect {
                listener.observed_connect = true;
                listener.closed_reported = false;
                listener.flow_key = Some(FlowKey {
                    source: remote,
                    destination: local,
                    protocol: FlowProtocol::Tcp,
                });
                listener.sandbox_to_host_bytes = 0;
                listener.host_to_sandbox_bytes = 0;
                listener.connected_at_millis = self.now_millis;
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
            if socket.can_recv() {
                let data = socket
                    .recv(|bytes| (bytes.len(), bytes.to_vec()))
                    .unwrap_or_default();
                if !data.is_empty() {
                    listener.sandbox_to_host_bytes += data.len() as u64;
                    events.push(StackEvent::TcpData(StackTcpData {
                        sandbox_id: self.sandbox_id.clone(),
                        frontend: self.frontend,
                        source: remote,
                        destination: local,
                        bytes: data,
                    }));
                }
            }
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
    closed_reported: bool,
    flow_key: Option<FlowKey>,
    sandbox_to_host_bytes: u64,
    host_to_sandbox_bytes: u64,
    connected_at_millis: i64,
}

impl StackAdapter for SmoltcpStackAdapter {
    fn ingest_ip_packet(&mut self, packet: &[u8]) -> Result<Vec<StackEvent>, StackError> {
        if packet.is_empty() {
            return Err(StackError::MalformedPacket);
        }
        self.device.push_inbound(packet.to_vec())?;
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        Ok(self.collect_tcp_events())
    }

    fn send_tcp_data_to_sandbox(&mut self, data: &StackTcpWrite) -> Result<usize, StackError> {
        for listener in &mut self.tcp_listeners {
            let socket = self.sockets.get_mut::<tcp::Socket>(listener.handle);
            let Some(remote) = endpoint_to_socket_addr(socket.remote_endpoint()) else {
                continue;
            };
            let Some(local) = endpoint_to_socket_addr(socket.local_endpoint()) else {
                continue;
            };
            if remote == data.source && local == data.destination {
                let written = socket.send_slice(&data.bytes).map_err(|error| {
                    StackError::Adapter(format!("smoltcp TCP send failed: {error:?}"))
                })?;
                listener.host_to_sandbox_bytes += written as u64;
                let now = self.now();
                self.iface.poll(now, &mut self.device, &mut self.sockets);
                return Ok(written);
            }
        }
        Err(StackError::Adapter(
            "no smoltcp TCP flow for write-back".into(),
        ))
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
    fn established_tcp_payload_emits_stack_data_event() {
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
        let connect_events = adapter.ingest_ip_packet(&syn).unwrap();
        let syn_ack = adapter
            .poll_outbound_packets()
            .unwrap()
            .remove(0)
            .bytes()
            .to_vec();
        let server_seq = u32::from_be_bytes([syn_ack[24], syn_ack[25], syn_ack[26], syn_ack[27]]);
        assert_eq!(connect_events.len(), 1);

        let data_packet = tcp_ack_data_packet(0x1234_5679, server_seq.wrapping_add(1), b"hello");
        let data_events = adapter.ingest_ip_packet(&data_packet).unwrap();

        let Some(StackEvent::TcpData(data)) = data_events
            .iter()
            .find(|event| matches!(event, StackEvent::TcpData(_)))
        else {
            panic!("expected TCP data event");
        };
        assert_eq!(data.source, "10.0.0.2:49152".parse().unwrap());
        assert_eq!(data.destination, "10.0.0.1:80".parse().unwrap());
        assert_eq!(data.bytes, b"hello");
    }

    #[test]
    fn tcp_write_back_emits_opaque_outbound_packet() {
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
        adapter.ingest_ip_packet(&syn).unwrap();
        let syn_ack = adapter
            .poll_outbound_packets()
            .unwrap()
            .remove(0)
            .bytes()
            .to_vec();
        let server_seq = u32::from_be_bytes([syn_ack[24], syn_ack[25], syn_ack[26], syn_ack[27]]);
        let ack_packet = tcp_ack_packet(0x1234_5679, server_seq.wrapping_add(1));
        adapter.ingest_ip_packet(&ack_packet).unwrap();
        adapter.poll_outbound_packets().unwrap();

        let written = adapter
            .send_tcp_data_to_sandbox(&StackTcpWrite {
                sandbox_id: SandboxId::new("s1").unwrap(),
                frontend: FrontendKind::Tun,
                source: "10.0.0.2:49152".parse().unwrap(),
                destination: "10.0.0.1:80".parse().unwrap(),
                bytes: b"world".to_vec(),
            })
            .unwrap();
        let outbound = adapter.poll_outbound_packets().unwrap();

        assert_eq!(written, 5);
        assert!(outbound
            .iter()
            .any(|packet| packet.bytes().windows(5).any(|window| window == b"world")));
    }

    #[test]
    fn tcp_reset_emits_normalized_flow_closed_event_with_byte_counts() {
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
        adapter.ingest_ip_packet(&syn).unwrap();
        let syn_ack = adapter
            .poll_outbound_packets()
            .unwrap()
            .remove(0)
            .bytes()
            .to_vec();
        let server_seq = u32::from_be_bytes([syn_ack[24], syn_ack[25], syn_ack[26], syn_ack[27]]);
        let data_packet = tcp_ack_data_packet(0x1234_5679, server_seq.wrapping_add(1), b"hello");
        let data_events = adapter.ingest_ip_packet(&data_packet).unwrap();
        assert!(data_events
            .iter()
            .any(|event| matches!(event, StackEvent::TcpData(_))));
        adapter
            .send_tcp_data_to_sandbox(&StackTcpWrite {
                sandbox_id: SandboxId::new("s1").unwrap(),
                frontend: FrontendKind::Tun,
                source: "10.0.0.2:49152".parse().unwrap(),
                destination: "10.0.0.1:80".parse().unwrap(),
                bytes: b"world!".to_vec(),
            })
            .unwrap();
        adapter.poll_outbound_packets().unwrap();

        let rst = tcp_rst_packet(0x1234_567e, server_seq.wrapping_add(7));
        let close_events = adapter.ingest_ip_packet(&rst).unwrap();

        let Some(StackEvent::FlowClosed(closed)) = close_events
            .iter()
            .find(|event| matches!(event, StackEvent::FlowClosed(_)))
        else {
            panic!("expected flow closed event");
        };
        assert_eq!(closed.key.source, "10.0.0.2:49152".parse().unwrap());
        assert_eq!(closed.key.destination, "10.0.0.1:80".parse().unwrap());
        assert_eq!(closed.byte_counts, ByteCounts::new(5, 6));
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
    fn smoltcp_adapter_plugs_into_runtime_stack_loop() {
        use std::io::Cursor;

        use foxprox_audit::BoundedAuditSink;
        use foxprox_core::{PolicyRule, PortMatcher, Protocol, ProtocolMatcher, RuntimeConfig};
        use foxprox_device::PreopenedTunDevice;
        use foxprox_egress::MockEgress;
        use foxprox_runtime::{
            process_one_stack_device_packet, StackDevicePacketStep, StackTcpBridgeTable,
        };

        let syn = tcp_syn_packet();
        let cursor = Cursor::new(syn.clone());
        let mut device = PreopenedTunDevice::from_io(cursor, 1500).unwrap();
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
        let mut runtime_config = RuntimeConfig::deny_by_default();
        let mut rule = PolicyRule::allow(foxprox_core::RuleId::new("tcp-80").unwrap());
        rule.protocol = ProtocolMatcher::Exact(Protocol::Tcp);
        rule.port = PortMatcher::Exact(80);
        runtime_config.rules.push(rule);
        let policy = foxprox_policy::PolicyEngine::new(runtime_config);
        let mut egress = MockEgress::default();
        let mut audit = BoundedAuditSink::new(8);
        let mut tcp_bridges = StackTcpBridgeTable::default();

        let outcome = process_one_stack_device_packet(
            &mut device,
            StackDevicePacketStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                sequence_start: 1,
                timestamp_millis: 1000,
                dns_attribution: None,
            },
        )
        .unwrap();

        assert_eq!(outcome.outbound_packets_written, 1);
        assert_eq!(egress.tcp_connects.len(), 1);
        assert_eq!(audit.records().len(), 1);
        let bytes = device.into_inner().into_inner();
        assert_eq!(&bytes[..syn.len()], syn.as_slice());
        assert_eq!(bytes[syn.len() + 9], 6);
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

    fn tcp_rst_packet(seq: u32, ack: u32) -> Vec<u8> {
        let mut packet = tcp_ack_data_packet(seq, ack, &[]);
        packet[33] = 0x14;
        packet[36] = 0;
        packet[37] = 0;
        let tcp_checksum = tcp_checksum_ipv4([10, 0, 0, 2], [10, 0, 0, 1], &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        packet
    }

    fn tcp_ack_packet(seq: u32, ack: u32) -> Vec<u8> {
        let mut packet = tcp_ack_data_packet(seq, ack, &[]);
        packet[33] = 0x10;
        packet[36] = 0;
        packet[37] = 0;
        let tcp_checksum = tcp_checksum_ipv4([10, 0, 0, 2], [10, 0, 0, 1], &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        packet
    }

    fn tcp_ack_data_packet(seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let total_len = 40 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&49152_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        packet[28..32].copy_from_slice(&ack.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let tcp_checksum = tcp_checksum_ipv4([10, 0, 0, 2], [10, 0, 0, 1], &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        let ip_checksum = foxprox_packet::internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
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
