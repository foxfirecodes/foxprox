//! Userspace IP stack adapter proof for foxprox alpha.
//!
//! This crate intentionally keeps `smoltcp` types out of `foxprox-core`: core
//! owns policy/audit contracts, while this adapter proves that TUN-style IP
//! packets can be fed into the selected userspace stack and that outbound IP
//! packets can be collected for a future TUN fd writer.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditKind, AuditRecord, BrokerCore, Decision, DenialReason, DeviceIoError, Frontend,
    PacketDevice, ParsedIpPacket, PolicyDecision, PolicyRequest,
};
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
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
    tcp_handles: Vec<SocketHandle>,
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
            tcp_handles: Vec::new(),
        }
    }

    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.device.push_inbound(packet);
    }

    pub fn listen_tcp(&mut self, port: u16, rx_capacity: usize, tx_capacity: usize) {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; rx_capacity]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; tx_capacity]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        socket.listen(port).expect("tcp listen port is valid");
        let handle = self.sockets.add(socket);
        self.tcp_handles.push(handle);
    }

    pub fn drain_first_tcp_recv(&mut self, limit: usize) -> Vec<u8> {
        let Some(handle) = self.tcp_handles.first().copied() else {
            return Vec::new();
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.may_recv() {
            return Vec::new();
        }
        let mut buffer = vec![0; limit];
        match socket.recv_slice(&mut buffer) {
            Ok(len) => {
                buffer.truncate(len);
                buffer
            }
            Err(_) => Vec::new(),
        }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpTunBridgeResult {
    pub inbound_observed: bool,
    pub stack: StackPollEvidence,
    pub packets_written: usize,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
}

pub struct SmoltcpTunBridge<D> {
    sandbox_id: String,
    broker: BrokerCore,
    stack: SmoltcpIpStack,
    device: D,
}

impl<D: PacketDevice> SmoltcpTunBridge<D> {
    pub fn new(
        sandbox_id: impl Into<String>,
        broker: BrokerCore,
        stack: SmoltcpIpStack,
        device: D,
    ) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            broker,
            stack,
            device,
        }
    }

    pub fn process_next_packet(
        &mut self,
        now_ms: i64,
    ) -> Result<Option<SmoltcpTunBridgeResult>, DeviceIoError> {
        let Some(packet) = self.device.read_packet()? else {
            return Ok(None);
        };
        let parsed = match ParsedIpPacket::parse(&packet) {
            Ok(parsed) => parsed,
            Err(error) => {
                let request = PolicyRequest::unsupported(
                    self.sandbox_id.clone(),
                    Frontend::Tun,
                    error.denial_reason(),
                );
                let audit = error
                    .audit_record(self.sandbox_id.clone())
                    .with_timestamp_ms(now_ms as u128);
                let decision = match self.broker.append_audit_for(&request, audit) {
                    Ok(_) => PolicyDecision {
                        decision: Decision::FailClosed,
                        reason: Some(error.denial_reason()),
                        rule_id: None,
                        audit_kind: AuditKind::PacketMalformedDenied,
                    },
                    Err(decision) => decision,
                };
                return Ok(Some(bridge_result(
                    false,
                    StackPollEvidence::none(),
                    0,
                    decision,
                )));
            }
        };
        let request = request_for_packet(&self.sandbox_id, &parsed);
        let inbound_audit = packet_audit(
            &self.sandbox_id,
            &parsed,
            now_ms,
            packet.len(),
            "from_sandbox",
        )
        .with_detail("stack", "smoltcp");
        if let Err(decision) = self.broker.append_audit_for(&request, inbound_audit) {
            return Ok(Some(bridge_result(
                false,
                StackPollEvidence::none(),
                0,
                decision,
            )));
        }

        let policy_decision = self.broker.evaluate(&request);
        if policy_decision.decision.is_deny() {
            return Ok(Some(bridge_result(
                true,
                StackPollEvidence::none(),
                0,
                policy_decision,
            )));
        }

        self.stack.inject_packet(packet);
        let stack_evidence = self.stack.poll(now_ms);
        let outbound = self.stack.outbound_packets();
        let mut written = 0usize;
        for packet in outbound
            .into_iter()
            .rev()
            .take(stack_evidence.packets_emitted)
            .rev()
        {
            let parsed = match ParsedIpPacket::parse(&packet) {
                Ok(parsed) => parsed,
                Err(error) => {
                    let request = PolicyRequest::unsupported(
                        self.sandbox_id.clone(),
                        Frontend::Tun,
                        error.denial_reason(),
                    );
                    let audit = error
                        .audit_record(self.sandbox_id.clone())
                        .with_timestamp_ms(now_ms as u128);
                    let decision = match self.broker.append_audit_for(&request, audit) {
                        Ok(_) => PolicyDecision {
                            decision: Decision::FailClosed,
                            reason: Some(error.denial_reason()),
                            rule_id: None,
                            audit_kind: AuditKind::PacketMalformedDenied,
                        },
                        Err(decision) => decision,
                    };
                    return Ok(Some(bridge_result(true, stack_evidence, written, decision)));
                }
            };
            let request = request_for_packet(&self.sandbox_id, &parsed);
            let outbound_audit = packet_audit(
                &self.sandbox_id,
                &parsed,
                now_ms,
                packet.len(),
                "to_sandbox",
            )
            .with_detail("stack", "smoltcp")
            .with_detail("write_phase", "attempt");
            if let Err(decision) = self.broker.append_audit_for(&request, outbound_audit) {
                return Ok(Some(bridge_result(true, stack_evidence, written, decision)));
            }
            if let Err(error) = self.device.write_packet(&packet) {
                let error_audit = AuditRecord::new_at(
                    AuditKind::BrokerError,
                    self.sandbox_id.clone(),
                    now_ms as u128,
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol)
                .with_source(parsed.source_endpoint())
                .with_destination(parsed.destination_endpoint())
                .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                .with_detail("stack", "smoltcp")
                .with_detail("direction", "to_sandbox")
                .with_detail("device_io_error", "write_failed");
                let _ = self.broker.append_audit_for(&request, error_audit);
                return Err(error);
            }
            written += 1;
        }

        Ok(Some(SmoltcpTunBridgeResult {
            inbound_observed: true,
            stack: stack_evidence,
            packets_written: written,
            decision: policy_decision.decision,
            reason: policy_decision.reason,
        }))
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn device(&self) -> &D {
        &self.device
    }
}

impl StackPollEvidence {
    fn none() -> Self {
        Self {
            poll_result: "none",
            packets_emitted: 0,
            outbound_bytes: 0,
        }
    }
}

fn bridge_result(
    inbound_observed: bool,
    stack: StackPollEvidence,
    packets_written: usize,
    decision: PolicyDecision,
) -> SmoltcpTunBridgeResult {
    SmoltcpTunBridgeResult {
        inbound_observed,
        stack,
        packets_written,
        decision: decision.decision,
        reason: decision.reason,
    }
}

fn request_for_packet(sandbox_id: &str, parsed: &ParsedIpPacket) -> PolicyRequest {
    let mut request = PolicyRequest::new(sandbox_id, Frontend::Tun, parsed.protocol)
        .with_destination(parsed.destination_endpoint());
    request.source = parsed.source_endpoint();
    request.icmp_type = parsed.icmp_type;
    request.icmp_code = parsed.icmp_code;
    request
}

fn packet_audit(
    sandbox_id: &str,
    parsed: &ParsedIpPacket,
    now_ms: i64,
    packet_len: usize,
    direction: &str,
) -> AuditRecord {
    AuditRecord::new_at(
        AuditKind::PacketObserved,
        sandbox_id.to_string(),
        now_ms as u128,
    )
    .with_frontend(Frontend::Tun)
    .with_protocol(parsed.protocol)
    .with_source(parsed.source_endpoint())
    .with_destination(parsed.destination_endpoint())
    .with_detail("direction", direction)
    .with_detail("ip_version", parsed.ip_version.to_string())
    .with_detail("packet_len", packet_len.to_string())
    .with_detail("payload_len", parsed.payload_len.to_string())
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
    use foxprox_core::{checksum, InMemoryPacketDevice, PolicyConfig, PolicyEngine};
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
    fn smoltcp_tun_bridge_audits_and_writes_stack_output() {
        let packet = ipv4_icmp_echo_request();
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);

        let result = bridge.process_next_packet(2_000).unwrap().unwrap();
        assert!(result.inbound_observed);
        assert_eq!(result.stack.packets_emitted, 1);
        assert_eq!(result.packets_written, 1);
        assert_eq!(result.decision, Decision::Allow);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[0].details["stack"], "smoltcp");
        assert_eq!(records[1].kind, AuditKind::IcmpDecision);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[2].details["direction"], "to_sandbox");
        assert_eq!(records[2].details["write_phase"], "attempt");
        let reply = &bridge.device().outbound()[0];
        let parsed = ParsedIpPacket::parse_ipv4(reply).unwrap();
        assert_eq!(parsed.icmp_type, Some(0));
    }

    #[test]
    fn smoltcp_tun_bridge_default_denies_before_stack_poll_or_write() {
        let packet = ipv4_icmp_echo_request();
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);

        let result = bridge.process_next_packet(2_500).unwrap().unwrap();
        assert!(result.inbound_observed);
        assert_eq!(result.stack.packets_emitted, 0);
        assert_eq!(result.packets_written, 0);
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::IcmpUnsupported));
        assert!(bridge.device().outbound().is_empty());
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::PacketObserved);
        assert_eq!(records[0].details["stack"], "smoltcp");
        assert_eq!(records[1].kind, AuditKind::IcmpDecision);
        assert_eq!(records[1].decision, Some(Decision::DenyDrop));
        assert_eq!(records[1].reason, Some(DenialReason::IcmpUnsupported));
    }

    #[test]
    fn smoltcp_tcp_listener_accepts_handshake_and_receives_bytes() {
        let mut stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.listen_tcp(8080, 1024, 1024);

        let client_seq = 0x0102_0304;
        stack.inject_packet(ipv4_tcp_packet(TcpPacketSpec {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 1],
            source_port: 50_000,
            destination_port: 8080,
            sequence: client_seq,
            acknowledgment: 0,
            flags: TCP_SYN,
            payload: &[],
        }));
        let syn_ack_evidence = stack.poll(3_000);
        assert_eq!(syn_ack_evidence.packets_emitted, 1);
        let syn_ack_packets = stack.outbound_packets();
        let syn_ack = &syn_ack_packets[0];
        let syn_ack_tcp = &syn_ack[20..];
        assert_eq!(syn_ack_tcp[13] & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
        let server_seq = u32::from_be_bytes([
            syn_ack_tcp[4],
            syn_ack_tcp[5],
            syn_ack_tcp[6],
            syn_ack_tcp[7],
        ]);
        assert_eq!(
            u32::from_be_bytes([
                syn_ack_tcp[8],
                syn_ack_tcp[9],
                syn_ack_tcp[10],
                syn_ack_tcp[11],
            ]),
            client_seq + 1
        );

        stack.inject_packet(ipv4_tcp_packet(TcpPacketSpec {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 1],
            source_port: 50_000,
            destination_port: 8080,
            sequence: client_seq + 1,
            acknowledgment: server_seq + 1,
            flags: TCP_ACK,
            payload: &[],
        }));
        stack.poll(3_010);
        stack.inject_packet(ipv4_tcp_packet(TcpPacketSpec {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 1],
            source_port: 50_000,
            destination_port: 8080,
            sequence: client_seq + 1,
            acknowledgment: server_seq + 1,
            flags: TCP_ACK | TCP_PSH,
            payload: b"hello foxprox",
        }));
        stack.poll(3_020);

        assert_eq!(stack.drain_first_tcp_recv(64), b"hello foxprox");
    }

    #[test]
    fn in_memory_ip_device_exposes_bounded_mtu_capabilities() {
        let device = InMemoryIpDevice::new(1280);
        let capabilities = device.capabilities();
        assert_eq!(capabilities.medium, Medium::Ip);
        assert_eq!(capabilities.max_transmission_unit, 1280);
        assert_eq!(capabilities.max_burst_size, Some(1));
    }

    const TCP_SYN: u8 = 0x02;
    const TCP_PSH: u8 = 0x08;
    const TCP_ACK: u8 = 0x10;

    #[derive(Clone, Copy)]
    struct TcpPacketSpec<'a> {
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        payload: &'a [u8],
    }

    fn ipv4_tcp_packet(spec: TcpPacketSpec<'_>) -> Vec<u8> {
        let tcp_len = 20 + spec.payload.len();
        let total_len = 20 + tcp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&spec.source);
        packet[16..20].copy_from_slice(&spec.destination);

        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&spec.source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&spec.destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&spec.sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&spec.acknowledgment.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = spec.flags;
        tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
        tcp[20..].copy_from_slice(spec.payload);

        let tcp_checksum = tcp_checksum(spec.source, spec.destination, tcp);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    fn tcp_checksum(source: [u8; 4], destination: [u8; 4], tcp: &[u8]) -> u16 {
        let mut bytes = Vec::with_capacity(12 + tcp.len());
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.push(0);
        bytes.push(6);
        bytes.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        bytes.extend_from_slice(tcp);
        checksum(&bytes)
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
