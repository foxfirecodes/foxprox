//! Userspace IP stack adapter proof for foxprox alpha.
//!
//! This crate intentionally keeps `smoltcp` types out of `foxprox-core`: core
//! owns policy/audit contracts, while this adapter proves that TUN-style IP
//! packets can be fed into the selected userspace stack and that outbound IP
//! packets can be collected for a future TUN fd writer.

#![forbid(unsafe_code)]

use foxprox_core::{
    checksum, AuditKind, AuditRecord, BrokerCore, ByteCounts, Decision, DenialReason,
    DeviceIoError, Frontend, NetworkEndpoint, PacketDevice, ParsedIpPacket, PolicyDecision,
    PolicyRequest, RuntimeComponent, RuntimeTaskExpectation, RuntimeTaskOutcome,
    RuntimeTaskReadiness, RuntimeTaskStatus, TcpEgress, TcpEgressError,
};
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackPollEvidence {
    pub poll_result: &'static str,
    pub packets_emitted: usize,
    pub outbound_bytes: usize,
    pub next_poll_delay_ms: Option<u64>,
}

impl StackPollEvidence {
    pub fn runtime_timer_readiness(&self) -> RuntimeTaskReadiness {
        RuntimeTaskReadiness::new(RuntimeComponent::SmoltcpStack, "smoltcp_tun_bridge_loop")
            .with_ready(self.next_poll_delay_ms == Some(0))
            .with_next_ready_delay_ms(self.next_poll_delay_ms.filter(|delay| *delay > 0))
    }
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

    pub fn runtime_timer_readiness(&mut self, now_ms: i64) -> RuntimeTaskReadiness {
        let next_poll_delay_ms = self
            .iface
            .poll_delay(Instant::from_millis(now_ms), &self.sockets)
            .map(|delay| delay.total_millis());
        RuntimeTaskReadiness::new(RuntimeComponent::SmoltcpStack, "smoltcp_tun_bridge_loop")
            .with_ready(next_poll_delay_ms == Some(0))
            .with_next_ready_delay_ms(next_poll_delay_ms.filter(|delay| *delay > 0))
    }

    pub fn poll_ready_task(
        &mut self,
        ready_tasks: &[RuntimeTaskExpectation],
        now_ms: i64,
    ) -> Option<StackPollEvidence> {
        let should_poll = ready_tasks.iter().any(|task| {
            task.component == RuntimeComponent::SmoltcpStack
                && task.task_name == "smoltcp_tun_bridge_loop"
        });
        should_poll.then(|| self.poll(now_ms))
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
        let next_poll_delay_ms = self
            .iface
            .poll_delay(Instant::from_millis(now_ms), &self.sockets)
            .map(|delay| delay.total_millis());
        StackPollEvidence {
            poll_result: poll_result_name(result),
            packets_emitted: emitted,
            outbound_bytes,
            next_poll_delay_ms,
        }
    }

    pub fn outbound_packets(&self) -> Vec<Vec<u8>> {
        self.device.outbound_packets()
    }

    pub fn outbound_len(&self) -> usize {
        self.device.outbound.borrow().len()
    }

    pub fn outbound_packets_since(&self, index: usize) -> Vec<Vec<u8>> {
        self.device
            .outbound
            .borrow()
            .iter()
            .skip(index)
            .cloned()
            .collect()
    }

    pub fn first_tcp_endpoints(&mut self) -> Option<(NetworkEndpoint, NetworkEndpoint)> {
        let handle = self.tcp_handles.first().copied()?;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let remote = socket.remote_endpoint()?;
        let local = socket.local_endpoint()?;
        Some((network_endpoint(remote), network_endpoint(local)))
    }

    pub fn mtu(&self) -> usize {
        self.device.mtu()
    }

    pub fn bridge_first_tcp_stream_to_egress<E: TcpEgress>(
        &mut self,
        egress: &mut E,
        destination: NetworkEndpoint,
        max_from_sandbox: usize,
        now_ms: i64,
    ) -> Result<TcpStreamBridgeEvidence, TcpEgressError> {
        let from_sandbox = self.drain_first_tcp_recv(max_from_sandbox);
        if from_sandbox.is_empty() {
            return Ok(tcp_stream_evidence(
                ByteCounts::ZERO,
                StackPollEvidence::none(),
                false,
                Decision::Allow,
                None,
            ));
        }
        let to_sandbox = egress.connect_and_exchange(destination, &from_sandbox)?;
        let stack = self.send_first_tcp_stream_response(&to_sandbox, now_ms)?;
        Ok(tcp_stream_evidence(
            ByteCounts {
                from_sandbox: from_sandbox.len() as u64,
                to_sandbox: to_sandbox.len() as u64,
            },
            stack,
            true,
            Decision::Allow,
            None,
        ))
    }

    pub fn send_first_tcp_stream_response(
        &mut self,
        to_sandbox: &[u8],
        now_ms: i64,
    ) -> Result<StackPollEvidence, TcpEgressError> {
        let Some(handle) = self.tcp_handles.first().copied() else {
            return Err(TcpEgressError::BridgeFailed);
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let sent = socket
            .send_slice(to_sandbox)
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        if sent != to_sandbox.len() {
            return Err(TcpEgressError::BridgeFailed);
        }
        Ok(self.poll(now_ms))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpStreamBridgeEvidence {
    pub byte_counts: ByteCounts,
    pub stack: StackPollEvidence,
    pub opened_egress: bool,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
}

pub trait UdpDatagramExchange {
    fn exchange_datagram(
        &mut self,
        destination: NetworkEndpoint,
        payload: &[u8],
    ) -> Result<Vec<u8>, UdpExchangeError>;

    fn audit_records(&self) -> Vec<AuditRecord> {
        Vec::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpExchangeError {
    SendFailed,
    ReceiveFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagramBridgeEvidence {
    pub byte_counts: ByteCounts,
    pub exchanged: bool,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpTunBridgeResult {
    pub inbound_observed: bool,
    pub stack: StackPollEvidence,
    pub packets_written: usize,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpBridgeLoopReport {
    pub processed_packets: usize,
    pub error: Option<DeviceIoError>,
    pub task_outcome: RuntimeTaskOutcome,
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
        let packet = match self.device.read_packet() {
            Ok(Some(packet)) => packet,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.record_device_read_failure(now_ms);
                return Err(error);
            }
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

    pub fn process_packet_loop(
        &mut self,
        now_ms: i64,
        max_packets: usize,
    ) -> SmoltcpBridgeLoopReport {
        self.process_packet_loop_until(now_ms, max_packets, || false)
    }

    pub fn process_packet_loop_until(
        &mut self,
        now_ms: i64,
        max_packets: usize,
        mut should_cancel: impl FnMut() -> bool,
    ) -> SmoltcpBridgeLoopReport {
        let mut processed_packets = 0usize;
        while processed_packets < max_packets {
            if should_cancel() {
                return SmoltcpBridgeLoopReport {
                    processed_packets,
                    error: None,
                    task_outcome: smoltcp_task_outcome(RuntimeTaskStatus::Cancelled),
                };
            }
            match self.process_next_packet(now_ms) {
                Ok(Some(_)) => processed_packets += 1,
                Ok(None) => {
                    return SmoltcpBridgeLoopReport {
                        processed_packets,
                        error: None,
                        task_outcome: smoltcp_task_outcome(RuntimeTaskStatus::Completed),
                    };
                }
                Err(error) => {
                    return SmoltcpBridgeLoopReport {
                        processed_packets,
                        error: Some(error),
                        task_outcome: smoltcp_task_outcome(RuntimeTaskStatus::Failed),
                    };
                }
            }
        }
        SmoltcpBridgeLoopReport {
            processed_packets,
            error: None,
            task_outcome: smoltcp_task_outcome(RuntimeTaskStatus::TimedOut),
        }
    }

    pub fn process_ready_task(
        &mut self,
        ready_tasks: &[RuntimeTaskExpectation],
        now_ms: i64,
        max_packets: usize,
    ) -> Option<SmoltcpBridgeLoopReport> {
        let should_process = ready_tasks.iter().any(|task| {
            task.component == RuntimeComponent::SmoltcpStack
                && task.task_name == "smoltcp_tun_bridge_loop"
        });
        should_process.then(|| self.process_packet_loop(now_ms, max_packets))
    }

    pub fn poll_stack_ready_task(
        &mut self,
        ready_tasks: &[RuntimeTaskExpectation],
        now_ms: i64,
    ) -> Result<Option<SmoltcpTunBridgeResult>, DeviceIoError> {
        let should_poll = ready_tasks.iter().any(|task| {
            task.component == RuntimeComponent::SmoltcpStack
                && task.task_name == "smoltcp_tun_bridge_loop"
        });
        if !should_poll {
            return Ok(None);
        }
        let before = self.stack.outbound_len();
        let stack_evidence = self.stack.poll(now_ms);
        let mut written = 0usize;
        for packet in self.stack.outbound_packets_since(before) {
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
                        stack_evidence,
                        written,
                        decision,
                    )));
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
                return Ok(Some(bridge_result(
                    false,
                    stack_evidence,
                    written,
                    decision,
                )));
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
            inbound_observed: false,
            stack: stack_evidence,
            packets_written: written,
            decision: Decision::Allow,
            reason: None,
        }))
    }

    fn record_device_read_failure(&mut self, now_ms: i64) {
        let request = PolicyRequest::unsupported(
            self.sandbox_id.clone(),
            Frontend::Tun,
            DenialReason::SetupFailed,
        );
        let audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        .with_detail("stack", "smoltcp")
        .with_detail("direction", "from_sandbox")
        .with_detail("device_io_error", "read_failed");
        let _ = self.broker.append_audit_for(&request, audit);
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn bridge_next_udp_datagram_to_egress<E: UdpDatagramExchange>(
        &mut self,
        egress: &mut E,
        now_ms: i64,
    ) -> Result<Option<UdpDatagramBridgeEvidence>, UdpExchangeError> {
        let packet = match self.device.read_packet() {
            Ok(Some(packet)) => packet,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.record_device_read_failure(now_ms);
                return Err(match error {
                    DeviceIoError::ReadFailed => UdpExchangeError::ReceiveFailed,
                    DeviceIoError::WriteFailed => UdpExchangeError::SendFailed,
                });
            }
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
                return Ok(Some(udp_datagram_evidence(
                    ByteCounts::ZERO,
                    false,
                    decision.decision,
                    decision.reason,
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
        .with_detail("stack", "udp_exchange");
        if let Err(decision) = self.broker.append_audit_for(&request, inbound_audit) {
            return Ok(Some(udp_datagram_evidence(
                ByteCounts::ZERO,
                false,
                decision.decision,
                decision.reason,
            )));
        }
        if parsed.protocol != foxprox_core::Protocol::Udp {
            let audit = AuditRecord::new_at(
                AuditKind::BrokerError,
                self.sandbox_id.clone(),
                now_ms as u128,
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(parsed.protocol)
            .with_source(parsed.source_endpoint())
            .with_destination(parsed.destination_endpoint())
            .with_decision(
                Decision::FailClosed,
                Some(DenialReason::UnsupportedProtocol),
            )
            .with_detail("stack", "udp_exchange")
            .with_detail("error", "non_udp_packet_in_udp_exchange");
            let _ = self.broker.append_audit_for(&request, audit);
            return Ok(Some(udp_datagram_evidence(
                ByteCounts::ZERO,
                false,
                Decision::FailClosed,
                Some(DenialReason::UnsupportedProtocol),
            )));
        }
        let Some((payload, response_template)) = udp_payload_and_response_template(&packet) else {
            let audit = AuditRecord::new_at(
                AuditKind::BrokerError,
                self.sandbox_id.clone(),
                now_ms as u128,
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(parsed.protocol)
            .with_source(parsed.source_endpoint())
            .with_destination(parsed.destination_endpoint())
            .with_decision(Decision::FailClosed, Some(DenialReason::MalformedPacket))
            .with_detail("stack", "udp_exchange")
            .with_detail("error", "udp_response_template_failed");
            let _ = self.broker.append_audit_for(&request, audit);
            return Ok(Some(udp_datagram_evidence(
                ByteCounts::ZERO,
                false,
                Decision::FailClosed,
                Some(DenialReason::MalformedPacket),
            )));
        };
        let policy_decision = self.broker.evaluate(&request);
        if policy_decision.decision.is_deny() {
            return Ok(Some(udp_datagram_evidence(
                ByteCounts::ZERO,
                false,
                policy_decision.decision,
                policy_decision.reason,
            )));
        }
        let response_payload =
            match egress.exchange_datagram(parsed.destination_endpoint(), payload) {
                Ok(response) => response,
                Err(error) => {
                    let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                        .with_frontend(Frontend::Tun)
                        .with_protocol(foxprox_core::Protocol::Udp)
                        .with_source(parsed.source_endpoint())
                        .with_destination(parsed.destination_endpoint())
                        .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                        .with_detail("stack", "udp_exchange")
                        .with_detail("error", udp_exchange_error_detail(&error));
                    let _ = self.broker.append_audit_for(&request, audit);
                    return Err(error);
                }
            };
        let response = match response_packet(&response_template, &response_payload) {
            Some(response) => response,
            None => {
                let audit = AuditRecord::new_at(
                    AuditKind::BrokerError,
                    self.sandbox_id.clone(),
                    now_ms as u128,
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(foxprox_core::Protocol::Udp)
                .with_source(parsed.destination_endpoint())
                .with_destination(parsed.source_endpoint())
                .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                .with_detail("stack", "udp_exchange")
                .with_detail("error", "udp_response_packet_synthesis_failed");
                let _ = self.broker.append_audit_for(&request, audit);
                return Err(UdpExchangeError::SendFailed);
            }
        };
        let response_parsed = match ParsedIpPacket::parse(&response) {
            Ok(parsed) => parsed,
            Err(_) => {
                let audit = AuditRecord::new_at(
                    AuditKind::BrokerError,
                    self.sandbox_id.clone(),
                    now_ms as u128,
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(foxprox_core::Protocol::Udp)
                .with_source(parsed.destination_endpoint())
                .with_destination(parsed.source_endpoint())
                .with_decision(Decision::FailClosed, Some(DenialReason::MalformedPacket))
                .with_detail("stack", "udp_exchange")
                .with_detail("error", "udp_response_packet_parse_failed");
                let _ = self.broker.append_audit_for(&request, audit);
                return Err(UdpExchangeError::SendFailed);
            }
        };
        let response_request = request_for_packet(&self.sandbox_id, &response_parsed);
        let outbound_audit = packet_audit(
            &self.sandbox_id,
            &response_parsed,
            now_ms,
            response.len(),
            "to_sandbox",
        )
        .with_detail("stack", "udp_exchange")
        .with_detail("write_phase", "attempt");
        if let Err(decision) = self
            .broker
            .append_audit_for(&response_request, outbound_audit)
        {
            return Ok(Some(udp_datagram_evidence(
                ByteCounts::ZERO,
                false,
                decision.decision,
                decision.reason,
            )));
        }
        if self.device.write_packet(&response).is_err() {
            let error_audit = AuditRecord::new_at(
                AuditKind::BrokerError,
                self.sandbox_id.clone(),
                now_ms as u128,
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(foxprox_core::Protocol::Udp)
            .with_source(response_parsed.source_endpoint())
            .with_destination(response_parsed.destination_endpoint())
            .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
            .with_detail("stack", "udp_exchange")
            .with_detail("direction", "to_sandbox")
            .with_detail("device_io_error", "write_failed");
            let _ = self.broker.append_audit_for(&response_request, error_audit);
            return Err(UdpExchangeError::SendFailed);
        }
        Ok(Some(udp_datagram_evidence(
            ByteCounts {
                from_sandbox: payload.len() as u64,
                to_sandbox: response_payload.len() as u64,
            },
            true,
            Decision::Allow,
            None,
        )))
    }

    pub fn bridge_first_tcp_stream_to_egress<E: TcpEgress>(
        &mut self,
        egress: &mut E,
        destination: NetworkEndpoint,
        max_from_sandbox: usize,
        opened_at_ms: u64,
        closed_at_ms: u64,
    ) -> Result<TcpStreamBridgeEvidence, TcpEgressError> {
        let from_sandbox = self.stack.drain_first_tcp_recv(max_from_sandbox);
        if from_sandbox.is_empty() {
            return Ok(tcp_stream_evidence(
                ByteCounts::ZERO,
                StackPollEvidence::none(),
                false,
                Decision::Allow,
                None,
            ));
        }
        let (source, local_destination) = self
            .stack
            .first_tcp_endpoints()
            .ok_or(TcpEgressError::BridgeFailed)?;
        let request = PolicyRequest::tcp_connect(
            self.sandbox_id.clone(),
            Frontend::Tun,
            source.clone(),
            local_destination.clone(),
        );
        let policy_decision = self.broker.evaluate(&request);
        if policy_decision.decision.is_deny() {
            return Ok(tcp_stream_evidence(
                ByteCounts::ZERO,
                StackPollEvidence::none(),
                false,
                policy_decision.decision,
                policy_decision.reason,
            ));
        }
        let to_sandbox = match egress.connect_and_exchange(destination.clone(), &from_sandbox) {
            Ok(to_sandbox) => to_sandbox,
            Err(error) => {
                let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                    .with_frontend(Frontend::Tun)
                    .with_protocol(foxprox_core::Protocol::Tcp)
                    .with_source(source.clone())
                    .with_destination(local_destination.clone())
                    .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                    .with_detail("stack", "smoltcp")
                    .with_detail("egress_destination", endpoint_detail(&destination))
                    .with_detail("error", tcp_egress_error_detail(&error));
                let _ = self.broker.append_audit_for(&request, audit);
                return Err(error);
            }
        };
        let outbound_start = self.stack.outbound_len();
        let stack = self
            .stack
            .send_first_tcp_stream_response(&to_sandbox, closed_at_ms as i64)?;
        let emitted_packets = self.stack.outbound_packets_since(outbound_start);
        let mut packets_written = 0usize;
        for packet in emitted_packets {
            let parsed =
                ParsedIpPacket::parse(&packet).map_err(|_| TcpEgressError::BridgeFailed)?;
            let packet_request = request_for_packet(&self.sandbox_id, &parsed);
            let outbound_audit = packet_audit(
                &self.sandbox_id,
                &parsed,
                closed_at_ms as i64,
                packet.len(),
                "to_sandbox",
            )
            .with_detail("stack", "smoltcp")
            .with_detail("write_phase", "attempt")
            .with_detail("tcp_stream_local", endpoint_detail(&local_destination))
            .with_detail("tcp_stream_remote", endpoint_detail(&source));
            if let Err(decision) = self
                .broker
                .append_audit_for(&packet_request, outbound_audit)
            {
                return Ok(tcp_stream_evidence(
                    ByteCounts::ZERO,
                    stack,
                    false,
                    decision.decision,
                    decision.reason,
                ));
            }
            if self.device.write_packet(&packet).is_err() {
                let error_audit = AuditRecord::new_at(
                    AuditKind::BrokerError,
                    self.sandbox_id.clone(),
                    closed_at_ms as u128,
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol)
                .with_source(parsed.source_endpoint())
                .with_destination(parsed.destination_endpoint())
                .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                .with_detail("stack", "smoltcp")
                .with_detail("direction", "to_sandbox")
                .with_detail("device_io_error", "write_failed")
                .with_detail("tcp_stream_local", endpoint_detail(&local_destination))
                .with_detail("tcp_stream_remote", endpoint_detail(&source));
                let _ = self.broker.append_audit_for(&packet_request, error_audit);
                return Err(TcpEgressError::BridgeFailed);
            }
            packets_written += 1;
        }
        let byte_counts = ByteCounts {
            from_sandbox: from_sandbox.len() as u64,
            to_sandbox: to_sandbox.len() as u64,
        };
        let close_audit = AuditRecord::new_at(
            AuditKind::TcpFlowClosed,
            self.sandbox_id.clone(),
            closed_at_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(foxprox_core::Protocol::Tcp)
        .with_source(source)
        .with_destination(local_destination.clone())
        .with_byte_counts(byte_counts.clone())
        .with_duration_ms(closed_at_ms.saturating_sub(opened_at_ms))
        .with_detail("stack", "smoltcp")
        .with_detail("egress_destination", endpoint_detail(&destination));
        if let Err(decision) = self.broker.append_audit_for(&request, close_audit) {
            return Ok(tcp_stream_evidence(
                byte_counts,
                stack,
                packets_written > 0,
                decision.decision,
                decision.reason,
            ));
        }
        Ok(tcp_stream_evidence(
            byte_counts,
            stack,
            packets_written > 0,
            Decision::Allow,
            None,
        ))
    }
}

impl StackPollEvidence {
    fn none() -> Self {
        Self {
            poll_result: "none",
            packets_emitted: 0,
            outbound_bytes: 0,
            next_poll_delay_ms: None,
        }
    }
}

fn network_endpoint(endpoint: smoltcp::wire::IpEndpoint) -> NetworkEndpoint {
    NetworkEndpoint::socket(smoltcp_ip_to_std(endpoint.addr), endpoint.port)
}

fn smoltcp_ip_to_std(address: IpAddress) -> IpAddr {
    address
        .to_string()
        .parse()
        .expect("smoltcp IP formats as std IP")
}

fn endpoint_detail(endpoint: &NetworkEndpoint) -> String {
    match (endpoint.ip, endpoint.port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (Some(ip), None) => ip.to_string(),
        (None, Some(port)) => format!(":{port}"),
        (None, None) => "unknown".to_string(),
    }
}

fn tcp_stream_evidence(
    byte_counts: ByteCounts,
    stack: StackPollEvidence,
    opened_egress: bool,
    decision: Decision,
    reason: Option<DenialReason>,
) -> TcpStreamBridgeEvidence {
    TcpStreamBridgeEvidence {
        byte_counts,
        stack,
        opened_egress,
        decision,
        reason,
    }
}

fn udp_datagram_evidence(
    byte_counts: ByteCounts,
    exchanged: bool,
    decision: Decision,
    reason: Option<DenialReason>,
) -> UdpDatagramBridgeEvidence {
    UdpDatagramBridgeEvidence {
        byte_counts,
        exchanged,
        decision,
        reason,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UdpResponseTemplate {
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
}

fn udp_payload_and_response_template(packet: &[u8]) -> Option<(&[u8], UdpResponseTemplate)> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
    if total_len > packet.len() || udp_len < 8 || ihl + udp_len > total_len {
        return None;
    }
    let payload = &packet[ihl + 8..ihl + udp_len];
    let template = UdpResponseTemplate {
        source: [packet[16], packet[17], packet[18], packet[19]],
        destination: [packet[12], packet[13], packet[14], packet[15]],
        source_port: u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        destination_port: u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
    };
    Some((payload, template))
}

fn response_packet(template: &UdpResponseTemplate, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&template.source);
    packet[16..20].copy_from_slice(&template.destination);
    packet[20..22].copy_from_slice(&template.source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&template.destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // IPv4 UDP checksum of zero is allowed and means no UDP checksum.
    packet[28..].copy_from_slice(payload);
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Some(packet)
}

fn tcp_egress_error_detail(error: &TcpEgressError) -> &'static str {
    match error {
        TcpEgressError::ConnectFailed => "connect_failed",
        TcpEgressError::BridgeFailed => "bridge_failed",
    }
}

fn udp_exchange_error_detail(error: &UdpExchangeError) -> &'static str {
    match error {
        UdpExchangeError::SendFailed => "send_failed",
        UdpExchangeError::ReceiveFailed => "receive_failed",
    }
}

fn smoltcp_task_outcome(status: RuntimeTaskStatus) -> RuntimeTaskOutcome {
    RuntimeTaskOutcome::new(
        RuntimeComponent::SmoltcpStack,
        "smoltcp_tun_bridge_loop",
        status,
    )
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
    use foxprox_core::{
        checksum, InMemoryPacketDevice, PolicyConfig, PolicyEngine, RuntimeReadinessPlan,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn smoltcp_stack_consumes_ip_packet_and_emits_icmp_reply() {
        let mut stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.inject_packet(ipv4_icmp_echo_request());

        let evidence = stack.poll(1_000);
        assert_eq!(evidence.packets_emitted, 1);
        assert!(evidence.outbound_bytes >= 28);
        assert_eq!(evidence.poll_result, "socket_state_changed");
        assert_eq!(evidence.next_poll_delay_ms, None);

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
    fn udp_exchange_bridge_sends_host_response_back_to_tun() {
        let packet = ipv4_udp_packet([10, 0, 2, 15], [198, 51, 100, 1], 50_000, 5353, b"ping");
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([198, 51, 100, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let mut egress = MockUdpExchange::new(b"pong".to_vec());

        let evidence = bridge
            .bridge_next_udp_datagram_to_egress(&mut egress, 6_000)
            .unwrap()
            .unwrap();

        assert!(evidence.exchanged);
        assert_eq!(evidence.byte_counts.from_sandbox, 4);
        assert_eq!(evidence.byte_counts.to_sandbox, 4);
        assert_eq!(egress.requests, vec![b"ping".to_vec()]);
        let outbound = &bridge.device().outbound()[0];
        let parsed = ParsedIpPacket::parse(outbound).unwrap();
        assert_eq!(parsed.protocol, foxprox_core::Protocol::Udp);
        assert_eq!(parsed.source.to_string(), "198.51.100.1");
        assert_eq!(parsed.destination.to_string(), "10.0.2.15");
        assert_eq!(parsed.source_port, Some(5353));
        assert_eq!(parsed.destination_port, Some(50_000));
        assert_eq!(&outbound[28..], b"pong");
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert!(records.iter().any(|record| {
            record.kind == AuditKind::PacketObserved
                && record.details.get("stack").map(String::as_str) == Some("udp_exchange")
                && record.details.get("direction").map(String::as_str) == Some("from_sandbox")
        }));
        assert!(records.iter().any(|record| {
            record.kind == AuditKind::PacketObserved
                && record.details.get("stack").map(String::as_str) == Some("udp_exchange")
                && record.details.get("direction").map(String::as_str) == Some("to_sandbox")
                && record.details.get("write_phase").map(String::as_str) == Some("attempt")
        }));
    }

    #[test]
    fn udp_exchange_bridge_fails_closed_and_audits_non_udp_packets() {
        let device = InMemoryPacketDevice::with_inbound([ipv4_icmp_echo_request()]);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([198, 51, 100, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let mut egress = MockUdpExchange::new(b"pong".to_vec());

        let evidence = bridge
            .bridge_next_udp_datagram_to_egress(&mut egress, 6_100)
            .unwrap()
            .unwrap();

        assert!(!evidence.exchanged);
        assert_eq!(evidence.decision, Decision::FailClosed);
        assert_eq!(evidence.reason, Some(DenialReason::UnsupportedProtocol));
        assert!(egress.requests.is_empty());
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert!(records.iter().any(|record| {
            record.kind == AuditKind::PacketObserved
                && record.details.get("stack").map(String::as_str) == Some("udp_exchange")
                && record.details.get("direction").map(String::as_str) == Some("from_sandbox")
        }));
        assert!(records.iter().any(|record| {
            record.kind == AuditKind::BrokerError
                && record.decision == Some(Decision::FailClosed)
                && record.reason == Some(DenialReason::UnsupportedProtocol)
                && record.details.get("error").map(String::as_str)
                    == Some("non_udp_packet_in_udp_exchange")
        }));
    }

    #[test]
    fn udp_exchange_bridge_audits_response_synthesis_failure() {
        let packet = ipv4_udp_packet([10, 0, 2, 15], [198, 51, 100, 1], 50_000, 5353, b"ping");
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([198, 51, 100, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let mut egress = MockUdpExchange::new(vec![0u8; 70_000]);

        let error = bridge
            .bridge_next_udp_datagram_to_egress(&mut egress, 6_200)
            .unwrap_err();

        assert_eq!(error, UdpExchangeError::SendFailed);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert!(records.iter().any(|record| {
            record.kind == AuditKind::BrokerError
                && record.decision == Some(Decision::FailClosed)
                && record.details.get("error").map(String::as_str)
                    == Some("udp_response_packet_synthesis_failed")
        }));
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
    fn smoltcp_tun_bridge_read_failure_is_audited_and_reported() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, FailingReadPacketDevice);

        let report = bridge.process_packet_loop(2_750, 8);

        assert_eq!(report.processed_packets, 0);
        assert_eq!(report.error, Some(DeviceIoError::ReadFailed));
        assert_eq!(
            report.task_outcome.component,
            RuntimeComponent::SmoltcpStack
        );
        assert_eq!(report.task_outcome.task_name, "smoltcp_tun_bridge_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Failed);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].details["stack"], "smoltcp");
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[0].details["device_io_error"], "read_failed");
    }

    #[test]
    fn smoltcp_tun_bridge_loop_reports_write_failure() {
        let packet = ipv4_icmp_echo_request();
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut device = FailingWritePacketDevice::default();
        device.push_inbound(packet);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);

        let report = bridge.process_packet_loop(2_775, 8);

        assert_eq!(report.processed_packets, 0);
        assert_eq!(report.error, Some(DeviceIoError::WriteFailed));
        assert_eq!(
            report.task_outcome.component,
            RuntimeComponent::SmoltcpStack
        );
        assert_eq!(report.task_outcome.task_name, "smoltcp_tun_bridge_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Failed);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records[3].kind, AuditKind::BrokerError);
        assert_eq!(records[3].details["stack"], "smoltcp");
        assert_eq!(records[3].details["direction"], "to_sandbox");
        assert_eq!(records[3].details["device_io_error"], "write_failed");
    }

    #[test]
    fn smoltcp_tun_bridge_loop_reports_idle_completion() {
        let packet = ipv4_icmp_echo_request();
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);

        let report = bridge.process_packet_loop(2_790, 8);

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.error, None);
        assert_eq!(
            report.task_outcome.component,
            RuntimeComponent::SmoltcpStack
        );
        assert_eq!(report.task_outcome.task_name, "smoltcp_tun_bridge_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Completed);
    }

    #[test]
    fn smoltcp_tun_bridge_processes_ready_scheduler_task() {
        let packet = ipv4_icmp_echo_request();
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let ready_tasks = vec![RuntimeTaskExpectation::new(
            RuntimeComponent::SmoltcpStack,
            "smoltcp_tun_bridge_loop",
        )];

        let report = bridge.process_ready_task(&ready_tasks, 2_792, 8).unwrap();

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Completed);
        assert_eq!(bridge.device().outbound().len(), 1);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, AuditKind::PacketObserved);
        assert_eq!(records[0].details["stack"], "smoltcp");
        assert_eq!(records[1].kind, AuditKind::IcmpDecision);
        assert_eq!(records[2].details["direction"], "to_sandbox");
        assert!(bridge
            .process_ready_task(
                &[RuntimeTaskExpectation::new(
                    RuntimeComponent::AuditFanIn,
                    "audit_fan_in_loop"
                )],
                2_793,
                8,
            )
            .is_none());
    }

    #[test]
    fn smoltcp_tun_bridge_loop_reports_external_cancellation() {
        let packet = ipv4_icmp_echo_request();
        let device = InMemoryPacketDevice::with_inbound([packet.clone(), packet]);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let mut checks = 0usize;

        let report = bridge.process_packet_loop_until(2_795, 8, || {
            checks += 1;
            checks > 1
        });

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.error, None);
        assert_eq!(
            report.task_outcome.component,
            RuntimeComponent::SmoltcpStack
        );
        assert_eq!(report.task_outcome.task_name, "smoltcp_tun_bridge_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Cancelled);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::PacketObserved);
        assert_eq!(records[0].details["stack"], "smoltcp");
    }

    #[test]
    fn smoltcp_tun_bridge_loop_reports_budget_timeout() {
        let packet = ipv4_icmp_echo_request();
        let device = InMemoryPacketDevice::with_inbound([packet.clone(), packet]);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);

        let report = bridge.process_packet_loop(2_800, 1);

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.error, None);
        assert_eq!(
            report.task_outcome.component,
            RuntimeComponent::SmoltcpStack
        );
        assert_eq!(report.task_outcome.task_name, "smoltcp_tun_bridge_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::TimedOut);
    }

    #[test]
    fn smoltcp_timer_readiness_dispatch_polls_stack_without_tun_packet() {
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
        let delay = syn_ack_evidence.next_poll_delay_ms.unwrap();
        let waiting_readiness = stack.runtime_timer_readiness(3_000);
        let waiting_plan = RuntimeReadinessPlan::from_tasks(&[waiting_readiness]);
        assert_eq!(waiting_plan.status_detail(), "timer_wait");
        assert_eq!(waiting_plan.next_ready_delay_ms, Some(delay));

        let due_ms = 3_000 + delay as i64;
        let ready = stack.runtime_timer_readiness(due_ms);
        assert_eq!(
            ready,
            RuntimeTaskReadiness::ready(RuntimeComponent::SmoltcpStack, "smoltcp_tun_bridge_loop")
        );
        let ready_tasks = vec![RuntimeTaskExpectation::new(
            RuntimeComponent::SmoltcpStack,
            "smoltcp_tun_bridge_loop",
        )];
        let before_outbound = stack.outbound_len();

        let poll = stack.poll_ready_task(&ready_tasks, due_ms).unwrap();

        assert!(poll.next_poll_delay_ms.is_some());
        assert!(stack.outbound_len() >= before_outbound);
        assert!(stack
            .poll_ready_task(
                &[RuntimeTaskExpectation::new(
                    RuntimeComponent::AuditFanIn,
                    "audit_fan_in_loop"
                )],
                due_ms,
            )
            .is_none());
    }

    #[test]
    fn smoltcp_bridge_timer_dispatch_writes_retransmitted_stack_output() {
        let device = InMemoryPacketDevice::default();
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16);
        let stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        bridge.stack.listen_tcp(8080, 1024, 1024);
        let client_seq = 0x0102_0304;
        bridge.stack.inject_packet(ipv4_tcp_packet(TcpPacketSpec {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 1],
            source_port: 50_000,
            destination_port: 8080,
            sequence: client_seq,
            acknowledgment: 0,
            flags: TCP_SYN,
            payload: &[],
        }));
        let syn_ack = bridge.stack.poll(3_000);
        assert_eq!(syn_ack.packets_emitted, 1);
        let due_ms = 3_000 + syn_ack.next_poll_delay_ms.unwrap() as i64;
        let ready = bridge.stack.runtime_timer_readiness(due_ms);
        assert_eq!(
            ready,
            RuntimeTaskReadiness::ready(RuntimeComponent::SmoltcpStack, "smoltcp_tun_bridge_loop")
        );
        let ready_tasks = vec![RuntimeTaskExpectation::new(
            RuntimeComponent::SmoltcpStack,
            "smoltcp_tun_bridge_loop",
        )];

        let result = bridge
            .poll_stack_ready_task(&ready_tasks, due_ms)
            .unwrap()
            .unwrap();

        assert!(!result.inbound_observed);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.stack.packets_emitted, 1);
        assert_eq!(result.packets_written, 1);
        assert_eq!(bridge.device().outbound().len(), 1);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::PacketObserved);
        assert_eq!(records[0].details["direction"], "to_sandbox");
        assert_eq!(records[0].details["stack"], "smoltcp");
        assert_eq!(records[0].details["write_phase"], "attempt");
        assert!(bridge
            .poll_stack_ready_task(
                &[RuntimeTaskExpectation::new(
                    RuntimeComponent::AuditFanIn,
                    "audit_fan_in_loop"
                )],
                due_ms,
            )
            .unwrap()
            .is_none());
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
        assert!(syn_ack_evidence.next_poll_delay_ms.is_some());
        let readiness = syn_ack_evidence.runtime_timer_readiness();
        let plan = RuntimeReadinessPlan::from_tasks(&[readiness]);
        assert_eq!(plan.status_detail(), "timer_wait");
        assert_eq!(
            plan.next_ready_delay_ms,
            syn_ack_evidence.next_poll_delay_ms
        );
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
    fn smoltcp_tcp_stream_bridges_host_response_back_to_stack_packets() {
        let mut stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.listen_tcp(8080, 1024, 1024);
        complete_tcp_handshake_and_send_payload(&mut stack, b"hello foxprox");
        let mut egress = MockTcpEgress::new(b"host pong".to_vec());

        let evidence = stack
            .bridge_first_tcp_stream_to_egress(
                &mut egress,
                NetworkEndpoint::socket("127.0.0.1".parse().unwrap(), 8080),
                64,
                4_000,
            )
            .unwrap();

        assert!(evidence.opened_egress);
        assert_eq!(evidence.byte_counts.from_sandbox, 13);
        assert_eq!(evidence.byte_counts.to_sandbox, 9);
        assert!(evidence.stack.packets_emitted >= 1);
        assert_eq!(egress.requests, vec![b"hello foxprox".to_vec()]);
        let outbound = stack.outbound_packets();
        assert_eq!(tcp_payload(outbound.last().unwrap()), b"host pong");
    }

    #[test]
    fn smoltcp_tun_bridge_audits_tcp_egress_and_flow_close() {
        let mut stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.listen_tcp(8080, 1024, 1024);
        complete_tcp_handshake_and_send_payload(&mut stack, b"hello foxprox");
        let device = InMemoryPacketDevice::default();
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let mut egress = MockTcpEgress::new(b"host pong".to_vec());

        let evidence = bridge
            .bridge_first_tcp_stream_to_egress(
                &mut egress,
                NetworkEndpoint::socket("127.0.0.1".parse().unwrap(), 8080),
                64,
                5_000,
                5_025,
            )
            .unwrap();

        assert_eq!(evidence.decision, Decision::Allow);
        assert!(evidence.opened_egress);
        assert_eq!(evidence.byte_counts.from_sandbox, 13);
        assert_eq!(evidence.byte_counts.to_sandbox, 9);
        assert!(evidence.stack.packets_emitted >= 1);
        assert_eq!(egress.requests, vec![b"hello foxprox".to_vec()]);
        let reply = bridge.device().outbound().last().unwrap();
        assert_eq!(tcp_payload(reply), b"host pong");
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, AuditKind::TcpConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(
            records[0].source.as_ref().unwrap().ip.unwrap().to_string(),
            "10.0.2.15"
        );
        assert_eq!(records[0].source.as_ref().unwrap().port, Some(50_000));
        assert_eq!(records[1].kind, AuditKind::PacketObserved);
        assert_eq!(records[1].details["direction"], "to_sandbox");
        assert_eq!(records[1].details["write_phase"], "attempt");
        assert_eq!(records[1].details["tcp_stream_remote"], "10.0.2.15:50000");
        assert_eq!(records[2].kind, AuditKind::TcpFlowClosed);
        assert_eq!(records[2].details["stack"], "smoltcp");
        assert_eq!(records[2].details["egress_destination"], "127.0.0.1:8080");
        assert_eq!(
            records[2].source.as_ref().unwrap().ip.unwrap().to_string(),
            "10.0.2.15"
        );
        assert_eq!(records[2].source.as_ref().unwrap().port, Some(50_000));
        assert_eq!(
            records[2]
                .destination
                .as_ref()
                .unwrap()
                .ip
                .unwrap()
                .to_string(),
            "10.0.2.1"
        );
        assert_eq!(records[2].destination.as_ref().unwrap().port, Some(8080));
        assert_eq!(records[2].byte_counts.as_ref().unwrap().from_sandbox, 13);
        assert_eq!(records[2].byte_counts.as_ref().unwrap().to_sandbox, 9);
    }

    #[test]
    fn smoltcp_tun_bridge_audits_tcp_response_write_failure() {
        let mut stack = SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.listen_tcp(8080, 1024, 1024);
        complete_tcp_handshake_and_send_payload(&mut stack, b"hello foxprox");
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let device = FailingWritePacketDevice::default();
        let mut bridge = SmoltcpTunBridge::new("s1", broker, stack, device);
        let mut egress = MockTcpEgress::new(b"host pong".to_vec());

        let error = bridge
            .bridge_first_tcp_stream_to_egress(
                &mut egress,
                NetworkEndpoint::socket("127.0.0.1".parse().unwrap(), 8080),
                64,
                6_000,
                6_025,
            )
            .unwrap_err();

        assert_eq!(error, TcpEgressError::BridgeFailed);
        let records: Vec<_> = bridge.broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, AuditKind::TcpConnectDecision);
        assert_eq!(records[1].kind, AuditKind::PacketObserved);
        assert_eq!(records[1].details["write_phase"], "attempt");
        assert_eq!(records[2].kind, AuditKind::BrokerError);
        assert_eq!(records[2].decision, Some(Decision::FailClosed));
        assert_eq!(records[2].details["device_io_error"], "write_failed");
        assert_eq!(records[2].details["direction"], "to_sandbox");
        assert_eq!(records[2].details["stack"], "smoltcp");
        assert_eq!(records[2].details["tcp_stream_remote"], "10.0.2.15:50000");
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

    #[derive(Clone, Debug, Default)]
    struct FailingReadPacketDevice;

    impl PacketDevice for FailingReadPacketDevice {
        fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
            Err(DeviceIoError::ReadFailed)
        }

        fn write_packet(&mut self, _packet: &[u8]) -> Result<(), DeviceIoError> {
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct FailingWritePacketDevice {
        inbound: VecDeque<Vec<u8>>,
    }

    impl FailingWritePacketDevice {
        fn push_inbound(&mut self, packet: Vec<u8>) {
            self.inbound.push_back(packet);
        }
    }

    impl PacketDevice for FailingWritePacketDevice {
        fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
            Ok(self.inbound.pop_front())
        }

        fn write_packet(&mut self, _packet: &[u8]) -> Result<(), DeviceIoError> {
            Err(DeviceIoError::WriteFailed)
        }
    }

    #[derive(Clone, Debug)]
    struct MockTcpEgress {
        response: Vec<u8>,
        requests: Vec<Vec<u8>>,
    }

    impl MockTcpEgress {
        fn new(response: Vec<u8>) -> Self {
            Self {
                response,
                requests: Vec::new(),
            }
        }
    }

    impl TcpEgress for MockTcpEgress {
        fn connect_and_exchange(
            &mut self,
            _destination: NetworkEndpoint,
            from_sandbox: &[u8],
        ) -> Result<Vec<u8>, TcpEgressError> {
            self.requests.push(from_sandbox.to_vec());
            Ok(self.response.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct MockUdpExchange {
        response: Vec<u8>,
        requests: Vec<Vec<u8>>,
    }

    impl MockUdpExchange {
        fn new(response: Vec<u8>) -> Self {
            Self {
                response,
                requests: Vec::new(),
            }
        }
    }

    impl UdpDatagramExchange for MockUdpExchange {
        fn exchange_datagram(
            &mut self,
            _destination: NetworkEndpoint,
            payload: &[u8],
        ) -> Result<Vec<u8>, UdpExchangeError> {
            self.requests.push(payload.to_vec());
            Ok(self.response.clone())
        }
    }

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

    fn complete_tcp_handshake_and_send_payload(stack: &mut SmoltcpIpStack, payload: &[u8]) {
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
        stack.poll(3_000);
        let syn_ack_packets = stack.outbound_packets();
        let syn_ack_tcp = &syn_ack_packets[0][20..];
        let server_seq = u32::from_be_bytes([
            syn_ack_tcp[4],
            syn_ack_tcp[5],
            syn_ack_tcp[6],
            syn_ack_tcp[7],
        ]);
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
            payload,
        }));
        stack.poll(3_020);
    }

    fn tcp_payload(packet: &[u8]) -> &[u8] {
        let ip_header_len = ((packet[0] & 0x0f) as usize) * 4;
        let tcp_header_len = ((packet[ip_header_len + 12] >> 4) as usize) * 4;
        &packet[ip_header_len + tcp_header_len..]
    }

    fn ipv4_udp_packet(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
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
