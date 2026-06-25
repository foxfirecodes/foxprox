//! smoltcp adapter boundary for foxprox.
//!
//! This crate is allowed to depend on smoltcp. Core policy/audit crates must
//! continue to see only foxprox normalized runtime types.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use foxprox_core::{Endpoint, FlowKey, Protocol};
use foxprox_runtime::{
    TcpBridgeError, TcpFlowRuntime, TcpStackAdapter, TcpStackConnectAttempt,
    TcpStackLifecycleEvent, TcpStreamBridge,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpIpConfig {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmoltcpAdapterError {
    InvalidPrefixLen,
    AddressRejected,
    InvalidTcpPort,
    InvalidTcpBufferSize,
    TcpListenRejected,
    TcpConnectRejected,
    EmptyIpPacket,
    NoMatchingTcpSocket,
    TcpSendRejected,
    TcpRecvRejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpTcpPayload {
    pub flow: FlowKey,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpConnectReportMode {
    ActiveClientSockets,
    AcceptedListenerSockets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmoltcpTunPumpOutcome {
    NoPacket,
    PacketProcessed {
        outbound_packets: usize,
        outbound_bytes: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmoltcpTcpBridgeSessionError {
    Adapter(SmoltcpAdapterError),
    Bridge(TcpBridgeError),
    Audit(foxprox_core::AuditError),
    HostConnectFailed,
    NoConnectAttempt,
    PolicyDenied(foxprox_core::Decision),
    InvalidLifecycle,
    TunWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpTcpBridgeSessionOutcome {
    pub flow: FlowKey,
    pub bytes_forwarded: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpSandboxPacketStepOutcome {
    pub pump: SmoltcpTunPumpOutcome,
    pub forwarded: Option<SmoltcpTcpBridgeSessionOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpHostToSandboxPumpOutcome {
    pub host_read: foxprox_runtime::TcpHostReadOutcome,
    pub sandbox_bytes: usize,
    pub outbound_packets: usize,
    pub outbound_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpBidirectionalTickOutcome {
    pub sandbox: SmoltcpSandboxPacketStepOutcome,
    pub host: SmoltcpHostToSandboxPumpOutcome,
}

impl SmoltcpBidirectionalTickOutcome {
    pub fn sandbox_bytes_forwarded(&self) -> usize {
        self.sandbox
            .forwarded
            .as_ref()
            .map_or(0, |forwarded| forwarded.bytes_forwarded)
    }

    pub fn host_bytes_read(&self) -> usize {
        match self.host.host_read {
            foxprox_runtime::TcpHostReadOutcome::Bytes { count } => count,
            foxprox_runtime::TcpHostReadOutcome::Eof
            | foxprox_runtime::TcpHostReadOutcome::WouldBlock => 0,
        }
    }

    pub fn made_progress(&self) -> bool {
        self.sandbox_bytes_forwarded() > 0
            || self.host_bytes_read() > 0
            || self.host.outbound_packets > 0
            || matches!(
                self.sandbox.pump,
                SmoltcpTunPumpOutcome::PacketProcessed {
                    outbound_packets,
                    ..
                } if outbound_packets > 0
            )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmoltcpTcpBridgeLoopState {
    pub ticks: u64,
    pub progress_ticks: u64,
    pub idle_ticks: u64,
}

impl SmoltcpTcpBridgeLoopState {
    fn record(&mut self, made_progress: bool) {
        self.ticks += 1;
        if made_progress {
            self.progress_ticks += 1;
        } else {
            self.idle_ticks += 1;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpTcpBridgeLoopStep {
    pub tick: SmoltcpBidirectionalTickOutcome,
    pub made_progress: bool,
}

pub struct SmoltcpTcpBridgeSession<B> {
    adapter: SmoltcpIpLoopback,
    flow_runtime: TcpFlowRuntime<B>,
}

pub struct SmoltcpTcpBridgeIoSession<T> {
    session: SmoltcpTcpBridgeSession<foxprox_runtime::StdTcpStreamBridge<Vec<u8>>>,
    tun_io: T,
    buffer: Vec<u8>,
    state: SmoltcpTcpBridgeLoopState,
    flow: FlowKey,
    listener_port: u16,
    max_sandbox_payload_bytes: usize,
    max_host_bytes: usize,
}

impl<T> SmoltcpTcpBridgeIoSession<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: SmoltcpTcpBridgeSession<foxprox_runtime::StdTcpStreamBridge<Vec<u8>>>,
        tun_io: T,
        buffer_bytes: usize,
        flow: FlowKey,
        listener_port: u16,
        max_sandbox_payload_bytes: usize,
        max_host_bytes: usize,
    ) -> Self {
        Self {
            session,
            tun_io,
            buffer: vec![0; buffer_bytes],
            state: SmoltcpTcpBridgeLoopState::default(),
            flow,
            listener_port,
            max_sandbox_payload_bytes,
            max_host_bytes,
        }
    }

    pub fn state(&self) -> &SmoltcpTcpBridgeLoopState {
        &self.state
    }

    pub fn flow(&self) -> &FlowKey {
        &self.flow
    }

    pub fn tun_io(&self) -> &T {
        &self.tun_io
    }

    pub fn into_parts(
        self,
    ) -> (
        SmoltcpTcpBridgeSession<foxprox_runtime::StdTcpStreamBridge<Vec<u8>>>,
        T,
        SmoltcpTcpBridgeLoopState,
    ) {
        (self.session, self.tun_io, self.state)
    }
}

impl<T: Read + Write> SmoltcpTcpBridgeIoSession<T> {
    pub fn run_tick(
        &mut self,
        now_millis: i64,
    ) -> Result<SmoltcpTcpBridgeLoopStep, SmoltcpTcpBridgeSessionError> {
        let tick = self.session.pump_bidirectional_io_once(
            &mut self.tun_io,
            &mut self.buffer,
            self.listener_port,
            self.max_sandbox_payload_bytes,
            &self.flow,
            self.max_host_bytes,
            now_millis,
        )?;
        let made_progress = tick.made_progress();
        self.state.record(made_progress);
        Ok(SmoltcpTcpBridgeLoopStep {
            tick,
            made_progress,
        })
    }
}

impl<B> SmoltcpTcpBridgeSession<B> {
    pub fn new(adapter: SmoltcpIpLoopback, flow_runtime: TcpFlowRuntime<B>) -> Self {
        Self {
            adapter,
            flow_runtime,
        }
    }

    pub fn adapter(&self) -> &SmoltcpIpLoopback {
        &self.adapter
    }

    pub fn flow_runtime(&self) -> &TcpFlowRuntime<B> {
        &self.flow_runtime
    }

    pub fn into_parts(self) -> (SmoltcpIpLoopback, TcpFlowRuntime<B>) {
        (self.adapter, self.flow_runtime)
    }

    pub fn mark_opened_connect(
        &mut self,
        attempt: &TcpStackConnectAttempt,
    ) -> Result<FlowKey, TcpBridgeError> {
        let flow = FlowKey::new(
            Protocol::Tcp,
            attempt.source.clone(),
            attempt.destination.clone(),
        );
        self.flow_runtime.mark_opened(flow.clone())?;
        Ok(flow)
    }

    pub fn close_flow(
        &mut self,
        flow: &FlowKey,
        duration: Duration,
    ) -> Result<TcpStackLifecycleEvent, TcpBridgeError> {
        self.flow_runtime.close_flow(flow, duration)
    }

    pub fn close_and_audit_flow<S: foxprox_core::AuditSink>(
        &mut self,
        flow: &FlowKey,
        duration: Duration,
        kernel: &mut foxprox_core::VerificationKernel<S>,
        sandbox_id: foxprox_core::SandboxId,
        timestamp_millis: u128,
    ) -> Result<TcpStackLifecycleEvent, SmoltcpTcpBridgeSessionError> {
        let lifecycle = self
            .close_flow(flow, duration)
            .map_err(SmoltcpTcpBridgeSessionError::Bridge)?;
        let audit_event =
            foxprox_runtime::tcp_lifecycle_audit_event(sandbox_id, timestamp_millis, &lifecycle)
                .map_err(|_| SmoltcpTcpBridgeSessionError::InvalidLifecycle)?;
        kernel
            .emit_audit_event(audit_event)
            .map_err(SmoltcpTcpBridgeSessionError::Audit)?;
        Ok(lifecycle)
    }
}

impl<B: TcpStreamBridge> SmoltcpTcpBridgeSession<B> {
    pub fn forward_sandbox_payload_once(
        &mut self,
        listener_port: u16,
        max_bytes: usize,
    ) -> Result<SmoltcpTcpBridgeSessionOutcome, SmoltcpTcpBridgeSessionError> {
        let payload = self
            .adapter
            .recv_on_listener_port_with_flow(listener_port, max_bytes)
            .map_err(SmoltcpTcpBridgeSessionError::Adapter)?;
        self.flow_runtime
            .send_sandbox_payload_to_host(&payload.flow, &payload.bytes)
            .map_err(SmoltcpTcpBridgeSessionError::Bridge)?;
        Ok(SmoltcpTcpBridgeSessionOutcome {
            flow: payload.flow,
            bytes_forwarded: payload.bytes.len(),
        })
    }

    pub fn pump_tun_packet_and_forward_sandbox_payload<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        listener_port: u16,
        max_payload_bytes: usize,
        now_millis: i64,
    ) -> Result<SmoltcpSandboxPacketStepOutcome, SmoltcpTcpBridgeSessionError> {
        let pump = pump_one_tun_packet(&mut self.adapter, reader, writer, buffer, now_millis)
            .map_err(|_| SmoltcpTcpBridgeSessionError::TunWrite)?;
        let forwarded = match self
            .adapter
            .recv_on_listener_port_with_flow(listener_port, max_payload_bytes)
        {
            Ok(payload) if !payload.bytes.is_empty() => {
                self.flow_runtime
                    .send_sandbox_payload_to_host(&payload.flow, &payload.bytes)
                    .map_err(SmoltcpTcpBridgeSessionError::Bridge)?;
                Some(SmoltcpTcpBridgeSessionOutcome {
                    flow: payload.flow,
                    bytes_forwarded: payload.bytes.len(),
                })
            }
            Ok(_) | Err(SmoltcpAdapterError::TcpRecvRejected) => None,
            Err(error) => return Err(SmoltcpTcpBridgeSessionError::Adapter(error)),
        };
        Ok(SmoltcpSandboxPacketStepOutcome { pump, forwarded })
    }
}

impl SmoltcpTcpBridgeSession<foxprox_runtime::StdTcpStreamBridge<Vec<u8>>> {
    pub fn from_allowed_connect(
        adapter: SmoltcpIpLoopback,
        components: &foxprox_runtime::BrokerRuntimeComponents,
        attempt: &TcpStackConnectAttempt,
        host_stream: std::net::TcpStream,
    ) -> Result<(Self, FlowKey), TcpBridgeError> {
        let flow = FlowKey::new(
            Protocol::Tcp,
            attempt.source.clone(),
            attempt.destination.clone(),
        );
        let bridge =
            foxprox_runtime::StdTcpStreamBridge::new(flow.clone(), host_stream, Vec::new())?;
        let mut flow_runtime = TcpFlowRuntime::new(components, bridge);
        flow_runtime.mark_opened(flow.clone())?;
        Ok((Self::new(adapter, flow_runtime), flow))
    }

    pub fn connect_allowed_host_session(
        adapter: SmoltcpIpLoopback,
        components: &foxprox_runtime::BrokerRuntimeComponents,
        attempt: &TcpStackConnectAttempt,
        host_address: SocketAddr,
    ) -> Result<(Self, FlowKey), SmoltcpTcpBridgeSessionError> {
        let host_stream = std::net::TcpStream::connect(host_address)
            .map_err(|_| SmoltcpTcpBridgeSessionError::HostConnectFailed)?;
        host_stream
            .set_nonblocking(true)
            .map_err(|_| SmoltcpTcpBridgeSessionError::HostConnectFailed)?;
        Self::from_allowed_connect(adapter, components, attempt, host_stream)
            .map_err(SmoltcpTcpBridgeSessionError::Bridge)
    }

    pub fn connect_next_allowed_host_session<S: foxprox_core::AuditSink>(
        adapter: SmoltcpIpLoopback,
        components: &foxprox_runtime::BrokerRuntimeComponents,
        kernel: &mut foxprox_core::VerificationKernel<S>,
        sandbox_id: foxprox_core::SandboxId,
        host_address: SocketAddr,
        timestamp_millis: u128,
    ) -> Result<(Self, FlowKey, foxprox_core::Decision), SmoltcpTcpBridgeSessionError> {
        Self::connect_next_allowed_host_session_with_dns_cache(
            adapter,
            components,
            kernel,
            sandbox_id,
            None,
            host_address,
            timestamp_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_next_allowed_host_session_with_dns_cache<S: foxprox_core::AuditSink>(
        mut adapter: SmoltcpIpLoopback,
        components: &foxprox_runtime::BrokerRuntimeComponents,
        kernel: &mut foxprox_core::VerificationKernel<S>,
        sandbox_id: foxprox_core::SandboxId,
        dns_cache: Option<&foxprox_core::DnsCache>,
        host_address: SocketAddr,
        timestamp_millis: u128,
    ) -> Result<(Self, FlowKey, foxprox_core::Decision), SmoltcpTcpBridgeSessionError> {
        let attempt = adapter
            .next_connect_attempt()
            .ok_or(SmoltcpTcpBridgeSessionError::NoConnectAttempt)?;
        let hostname =
            dns_cache.and_then(|cache| cache.lookup_ip(attempt.destination.ip, timestamp_millis));
        let event = foxprox_core::NormalizedEvent::TcpConnectAttempt {
            sandbox_id,
            frontend: foxprox_core::FrontendKind::Tun,
            source: Some(attempt.source.clone()),
            destination: attempt.destination.clone(),
            hostname,
            sni_status: foxprox_core::SniStatus::Missing,
            sni_dns_mismatch: false,
        };
        let decision = kernel.decide_and_audit(&event, timestamp_millis);
        if decision.action != foxprox_core::DecisionAction::Allow {
            adapter.reset_connect(&attempt);
            return Err(SmoltcpTcpBridgeSessionError::PolicyDenied(decision));
        }
        let host_stream = match std::net::TcpStream::connect(host_address) {
            Ok(stream) => stream,
            Err(_) => {
                adapter.reset_connect(&attempt);
                return Err(SmoltcpTcpBridgeSessionError::HostConnectFailed);
            }
        };
        if host_stream.set_nonblocking(true).is_err() {
            adapter.reset_connect(&attempt);
            return Err(SmoltcpTcpBridgeSessionError::HostConnectFailed);
        }
        adapter.mark_connect_opened(&attempt);
        let (session, flow) =
            Self::from_allowed_connect(adapter, components, &attempt, host_stream)
                .map_err(SmoltcpTcpBridgeSessionError::Bridge)?;
        Ok((session, flow, decision))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pump_tun_and_open_next_allowed_host_session<
        R: Read,
        W: Write,
        S: foxprox_core::AuditSink,
    >(
        adapter: SmoltcpIpLoopback,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        components: &foxprox_runtime::BrokerRuntimeComponents,
        kernel: &mut foxprox_core::VerificationKernel<S>,
        sandbox_id: foxprox_core::SandboxId,
        host_address: SocketAddr,
        poll_millis: i64,
        timestamp_millis: u128,
    ) -> Result<
        (Self, FlowKey, foxprox_core::Decision, SmoltcpTunPumpOutcome),
        SmoltcpTcpBridgeSessionError,
    > {
        Self::pump_tun_and_open_next_allowed_host_session_with_dns_cache(
            adapter,
            reader,
            writer,
            buffer,
            components,
            kernel,
            sandbox_id,
            None,
            host_address,
            poll_millis,
            timestamp_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pump_tun_and_open_next_allowed_host_session_with_dns_cache<
        R: Read,
        W: Write,
        S: foxprox_core::AuditSink,
    >(
        mut adapter: SmoltcpIpLoopback,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        components: &foxprox_runtime::BrokerRuntimeComponents,
        kernel: &mut foxprox_core::VerificationKernel<S>,
        sandbox_id: foxprox_core::SandboxId,
        dns_cache: Option<&foxprox_core::DnsCache>,
        host_address: SocketAddr,
        poll_millis: i64,
        timestamp_millis: u128,
    ) -> Result<
        (Self, FlowKey, foxprox_core::Decision, SmoltcpTunPumpOutcome),
        SmoltcpTcpBridgeSessionError,
    > {
        let pump = pump_one_tun_packet(&mut adapter, reader, writer, buffer, poll_millis)
            .map_err(|_| SmoltcpTcpBridgeSessionError::TunWrite)?;
        let (session, flow, decision) = Self::connect_next_allowed_host_session_with_dns_cache(
            adapter,
            components,
            kernel,
            sandbox_id,
            dns_cache,
            host_address,
            timestamp_millis,
        )?;
        Ok((session, flow, decision, pump))
    }

    pub fn pump_host_to_sandbox_once<W: Write>(
        &mut self,
        flow: &FlowKey,
        max_host_bytes: usize,
        tun_writer: &mut W,
        now_millis: i64,
    ) -> Result<SmoltcpHostToSandboxPumpOutcome, SmoltcpTcpBridgeSessionError> {
        let previous_writer_len = self.flow_runtime.bridge().bridge().sandbox_writer().len();
        let host_read = self
            .flow_runtime
            .pump_host_once_to_sandbox_writer(flow, max_host_bytes)
            .map_err(SmoltcpTcpBridgeSessionError::Bridge)?;
        let sandbox_bytes =
            self.flow_runtime.bridge().bridge().sandbox_writer()[previous_writer_len..].to_vec();
        if !sandbox_bytes.is_empty() {
            self.adapter
                .send_to_sandbox_on_flow(flow, &sandbox_bytes)
                .map_err(SmoltcpTcpBridgeSessionError::Adapter)?;
        }
        self.adapter.poll_once(now_millis);

        let mut outbound_packets = 0;
        let mut outbound_bytes = 0;
        while let Some(packet) = self.adapter.next_outbound_ip_packet() {
            tun_writer
                .write_all(&packet)
                .map_err(|_| SmoltcpTcpBridgeSessionError::TunWrite)?;
            outbound_packets += 1;
            outbound_bytes += packet.len();
        }

        Ok(SmoltcpHostToSandboxPumpOutcome {
            host_read,
            sandbox_bytes: sandbox_bytes.len(),
            outbound_packets,
            outbound_bytes,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pump_bidirectional_once<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        listener_port: u16,
        max_sandbox_payload_bytes: usize,
        flow: &FlowKey,
        max_host_bytes: usize,
        now_millis: i64,
    ) -> Result<SmoltcpBidirectionalTickOutcome, SmoltcpTcpBridgeSessionError> {
        let sandbox = self.pump_tun_packet_and_forward_sandbox_payload(
            reader,
            writer,
            buffer,
            listener_port,
            max_sandbox_payload_bytes,
            now_millis,
        )?;
        let host = self.pump_host_to_sandbox_once(flow, max_host_bytes, writer, now_millis + 1)?;
        Ok(SmoltcpBidirectionalTickOutcome { sandbox, host })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pump_bidirectional_io_once<T: Read + Write>(
        &mut self,
        io: &mut T,
        buffer: &mut [u8],
        listener_port: u16,
        max_sandbox_payload_bytes: usize,
        flow: &FlowKey,
        max_host_bytes: usize,
        now_millis: i64,
    ) -> Result<SmoltcpBidirectionalTickOutcome, SmoltcpTcpBridgeSessionError> {
        let pump = pump_one_tun_packet_io(&mut self.adapter, io, buffer, now_millis)
            .map_err(|_| SmoltcpTcpBridgeSessionError::TunWrite)?;
        let forwarded = match self
            .adapter
            .recv_on_listener_port_with_flow(listener_port, max_sandbox_payload_bytes)
        {
            Ok(payload) if !payload.bytes.is_empty() => {
                self.flow_runtime
                    .send_sandbox_payload_to_host(&payload.flow, &payload.bytes)
                    .map_err(SmoltcpTcpBridgeSessionError::Bridge)?;
                Some(SmoltcpTcpBridgeSessionOutcome {
                    flow: payload.flow,
                    bytes_forwarded: payload.bytes.len(),
                })
            }
            Ok(_) | Err(SmoltcpAdapterError::TcpRecvRejected) => None,
            Err(error) => return Err(SmoltcpTcpBridgeSessionError::Adapter(error)),
        };
        let sandbox = SmoltcpSandboxPacketStepOutcome { pump, forwarded };
        let host = self.pump_host_to_sandbox_once(flow, max_host_bytes, io, now_millis + 1)?;
        Ok(SmoltcpBidirectionalTickOutcome { sandbox, host })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_loop_tick<R: Read, W: Write>(
        &mut self,
        state: &mut SmoltcpTcpBridgeLoopState,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        listener_port: u16,
        max_sandbox_payload_bytes: usize,
        flow: &FlowKey,
        max_host_bytes: usize,
        now_millis: i64,
    ) -> Result<SmoltcpTcpBridgeLoopStep, SmoltcpTcpBridgeSessionError> {
        let tick = self.pump_bidirectional_once(
            reader,
            writer,
            buffer,
            listener_port,
            max_sandbox_payload_bytes,
            flow,
            max_host_bytes,
            now_millis,
        )?;
        let made_progress = tick.made_progress();
        state.record(made_progress);
        Ok(SmoltcpTcpBridgeLoopStep {
            tick,
            made_progress,
        })
    }
}

pub struct SmoltcpIpLoopback {
    iface: Interface,
    device: QueuedIpDevice,
    sockets: SocketSet<'static>,
    tcp_handles: Vec<SocketHandle>,
    listener_ports: Vec<u16>,
    reported_connects: Vec<TcpStackConnectAttempt>,
    connect_report_mode: TcpConnectReportMode,
    config: SmoltcpIpConfig,
}

impl SmoltcpIpLoopback {
    pub fn new(config: SmoltcpIpConfig, now_millis: i64) -> Result<Self, SmoltcpAdapterError> {
        if config.prefix_len > 32 {
            return Err(SmoltcpAdapterError::InvalidPrefixLen);
        }
        let mut device = QueuedIpDevice::new(true);
        let iface_config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(now_millis));
        let cidr = IpCidr::new(ipv4_to_smoltcp(config.address), config.prefix_len);
        let mut accepted = false;
        iface.update_ip_addrs(|addresses| {
            accepted = addresses.push(cidr).is_ok();
        });
        if !accepted {
            return Err(SmoltcpAdapterError::AddressRejected);
        }
        Ok(Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_handles: Vec::new(),
            listener_ports: Vec::new(),
            reported_connects: Vec::new(),
            connect_report_mode: TcpConnectReportMode::ActiveClientSockets,
            config,
        })
    }

    pub fn config(&self) -> &SmoltcpIpConfig {
        &self.config
    }

    pub fn set_connect_report_mode(&mut self, mode: TcpConnectReportMode) {
        self.connect_report_mode = mode;
    }

    pub fn set_packet_loopback(&mut self, enabled: bool) {
        self.device.set_loopback_transmit(enabled);
    }

    pub fn listen_tcp(
        &mut self,
        port: u16,
        rx_bytes: usize,
        tx_bytes: usize,
    ) -> Result<(), SmoltcpAdapterError> {
        if port == 0 {
            return Err(SmoltcpAdapterError::InvalidTcpPort);
        }
        if rx_bytes == 0 || tx_bytes == 0 {
            return Err(SmoltcpAdapterError::InvalidTcpBufferSize);
        }
        let rx_buffer = tcp::SocketBuffer::new(vec![0; rx_bytes]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; tx_bytes]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let handle = self.sockets.add(socket);
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(port)
            .map_err(|_| SmoltcpAdapterError::TcpListenRejected)?;
        self.tcp_handles.push(handle);
        self.listener_ports.push(port);
        Ok(())
    }

    pub fn connect_tcp(
        &mut self,
        remote: Ipv4Addr,
        remote_port: u16,
        local_port: u16,
        rx_bytes: usize,
        tx_bytes: usize,
    ) -> Result<(), SmoltcpAdapterError> {
        if remote_port == 0 || local_port == 0 {
            return Err(SmoltcpAdapterError::InvalidTcpPort);
        }
        if rx_bytes == 0 || tx_bytes == 0 {
            return Err(SmoltcpAdapterError::InvalidTcpBufferSize);
        }
        let rx_buffer = tcp::SocketBuffer::new(vec![0; rx_bytes]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; tx_bytes]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let handle = self.sockets.add(socket);
        let cx = self.iface.context();
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(cx, (ipv4_to_smoltcp(remote), remote_port), local_port)
            .map_err(|_| SmoltcpAdapterError::TcpConnectRejected)?;
        self.tcp_handles.push(handle);
        Ok(())
    }

    pub fn active_tcp_socket_count(&mut self) -> usize {
        self.tcp_handles
            .iter()
            .filter(|handle| self.sockets.get::<tcp::Socket>(**handle).is_active())
            .count()
    }

    fn remember_reported(&mut self, attempt: &TcpStackConnectAttempt) {
        if !self.reported_connects.contains(attempt) {
            self.reported_connects.push(attempt.clone());
        }
    }

    fn abort_matching_connect(&mut self, attempt: &TcpStackConnectAttempt) {
        for handle in &self.tcp_handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket_matches_attempt(socket, attempt)
                || socket_matches_attempt_reversed(socket, attempt)
            {
                socket.abort();
            }
        }
    }

    pub fn has_active_socket_for_attempt(&mut self, attempt: &TcpStackConnectAttempt) -> bool {
        self.tcp_handles.iter().any(|handle| {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            socket.is_active() && socket_matches_attempt(socket, attempt)
        })
    }

    pub fn has_active_socket_for_attempt_either_direction(
        &mut self,
        attempt: &TcpStackConnectAttempt,
    ) -> bool {
        self.tcp_handles.iter().any(|handle| {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            socket.is_active()
                && (socket_matches_attempt(socket, attempt)
                    || socket_matches_attempt_reversed(socket, attempt))
        })
    }

    pub fn send_on_connect_attempt(
        &mut self,
        attempt: &TcpStackConnectAttempt,
        bytes: &[u8],
    ) -> Result<usize, SmoltcpAdapterError> {
        for handle in &self.tcp_handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket_matches_attempt(socket, attempt) {
                return socket
                    .send_slice(bytes)
                    .map_err(|_| SmoltcpAdapterError::TcpSendRejected);
            }
        }
        Err(SmoltcpAdapterError::NoMatchingTcpSocket)
    }

    pub fn recv_on_listener_port(
        &mut self,
        port: u16,
        max_bytes: usize,
    ) -> Result<Vec<u8>, SmoltcpAdapterError> {
        self.recv_on_listener_port_with_flow(port, max_bytes)
            .map(|payload| payload.bytes)
    }

    pub fn send_to_sandbox_on_flow(
        &mut self,
        flow: &FlowKey,
        bytes: &[u8],
    ) -> Result<usize, SmoltcpAdapterError> {
        for handle in &self.tcp_handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            let Some(local) = socket.local_endpoint().and_then(endpoint_to_foxprox) else {
                continue;
            };
            let Some(remote) = socket.remote_endpoint().and_then(endpoint_to_foxprox) else {
                continue;
            };
            if local == flow.destination && remote == flow.source {
                return socket
                    .send_slice(bytes)
                    .map_err(|_| SmoltcpAdapterError::TcpSendRejected);
            }
        }
        Err(SmoltcpAdapterError::NoMatchingTcpSocket)
    }

    pub fn recv_on_listener_port_with_flow(
        &mut self,
        port: u16,
        max_bytes: usize,
    ) -> Result<SmoltcpTcpPayload, SmoltcpAdapterError> {
        for handle in &self.tcp_handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket
                .local_endpoint()
                .is_some_and(|endpoint| endpoint.port == port)
            {
                let local = socket
                    .local_endpoint()
                    .and_then(endpoint_to_foxprox)
                    .ok_or(SmoltcpAdapterError::NoMatchingTcpSocket)?;
                let remote = socket
                    .remote_endpoint()
                    .and_then(endpoint_to_foxprox)
                    .ok_or(SmoltcpAdapterError::NoMatchingTcpSocket)?;
                let mut bytes = vec![0; max_bytes];
                let count = socket
                    .recv_slice(&mut bytes)
                    .map_err(|_| SmoltcpAdapterError::TcpRecvRejected)?;
                bytes.truncate(count);
                return Ok(SmoltcpTcpPayload {
                    flow: FlowKey::new(Protocol::Tcp, remote, local),
                    bytes,
                });
            }
        }
        Err(SmoltcpAdapterError::NoMatchingTcpSocket)
    }

    pub fn active_tcp_connect_attempts(&mut self) -> Vec<TcpStackConnectAttempt> {
        self.tcp_handles
            .iter()
            .filter_map(|handle| {
                let socket = self.sockets.get::<tcp::Socket>(*handle);
                if !socket.is_active() {
                    return None;
                }
                let local = socket.local_endpoint()?;
                if self.listener_ports.contains(&local.port) {
                    return None;
                }
                let remote = socket.remote_endpoint()?;
                Some(TcpStackConnectAttempt {
                    source: endpoint_to_foxprox(local)?,
                    destination: endpoint_to_foxprox(remote)?,
                })
            })
            .collect()
    }

    pub fn accepted_tcp_connect_attempts(&mut self) -> Vec<TcpStackConnectAttempt> {
        self.tcp_handles
            .iter()
            .filter_map(|handle| {
                let socket = self.sockets.get::<tcp::Socket>(*handle);
                if !socket.is_active() {
                    return None;
                }
                let local = socket.local_endpoint()?;
                if !self.listener_ports.contains(&local.port) {
                    return None;
                }
                let remote = socket.remote_endpoint()?;
                Some(TcpStackConnectAttempt {
                    source: endpoint_to_foxprox(remote)?,
                    destination: endpoint_to_foxprox(local)?,
                })
            })
            .collect()
    }

    fn tcp_connect_attempts_for_mode(&mut self) -> Vec<TcpStackConnectAttempt> {
        match self.connect_report_mode {
            TcpConnectReportMode::ActiveClientSockets => self.active_tcp_connect_attempts(),
            TcpConnectReportMode::AcceptedListenerSockets => self.accepted_tcp_connect_attempts(),
        }
    }

    pub fn ingest_ip_packet(&mut self, packet: Vec<u8>) -> Result<(), SmoltcpAdapterError> {
        if packet.is_empty() {
            return Err(SmoltcpAdapterError::EmptyIpPacket);
        }
        self.device.push_inbound(packet);
        Ok(())
    }

    pub fn next_outbound_ip_packet(&mut self) -> Option<Vec<u8>> {
        self.device.pop_outbound()
    }

    pub fn poll_once(&mut self, now_millis: i64) {
        let _ = self.iface.poll(
            Instant::from_millis(now_millis),
            &mut self.device,
            &mut self.sockets,
        );
    }
}

struct QueuedIpDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    loopback_transmit: bool,
}

impl QueuedIpDevice {
    fn new(loopback_transmit: bool) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            loopback_transmit,
        }
    }

    fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    fn set_loopback_transmit(&mut self, enabled: bool) {
        self.loopback_transmit = enabled;
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
        let buffer = self.inbound.pop_front()?;
        Some((
            QueuedRxToken { buffer },
            QueuedTxToken {
                inbound: &mut self.inbound,
                outbound: &mut self.outbound,
                loopback_transmit: self.loopback_transmit,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueuedTxToken {
            inbound: &mut self.inbound,
            outbound: &mut self.outbound,
            loopback_transmit: self.loopback_transmit,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 65535;
        capabilities.medium = Medium::Ip;
        capabilities
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
    inbound: &'a mut VecDeque<Vec<u8>>,
    outbound: &'a mut VecDeque<Vec<u8>>,
    loopback_transmit: bool,
}

impl TxToken for QueuedTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.outbound.push_back(buffer.clone());
        if self.loopback_transmit {
            self.inbound.push_back(buffer);
        }
        result
    }
}

fn ipv4_to_smoltcp(address: Ipv4Addr) -> IpAddress {
    let octets = address.octets();
    IpAddress::v4(octets[0], octets[1], octets[2], octets[3])
}

fn endpoint_to_foxprox(endpoint: smoltcp::wire::IpEndpoint) -> Option<Endpoint> {
    match endpoint.addr {
        IpAddress::Ipv4(address) => Some(Endpoint::new(IpAddr::V4(address), endpoint.port)),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

fn socket_matches_attempt(socket: &tcp::Socket<'_>, attempt: &TcpStackConnectAttempt) -> bool {
    let Some(local) = socket.local_endpoint().and_then(endpoint_to_foxprox) else {
        return false;
    };
    let Some(remote) = socket.remote_endpoint().and_then(endpoint_to_foxprox) else {
        return false;
    };
    local == attempt.source && remote == attempt.destination
}

fn socket_matches_attempt_reversed(
    socket: &tcp::Socket<'_>,
    attempt: &TcpStackConnectAttempt,
) -> bool {
    let Some(local) = socket.local_endpoint().and_then(endpoint_to_foxprox) else {
        return false;
    };
    let Some(remote) = socket.remote_endpoint().and_then(endpoint_to_foxprox) else {
        return false;
    };
    remote == attempt.source && local == attempt.destination
}

impl TcpStackAdapter for SmoltcpIpLoopback {
    fn next_connect_attempt(&mut self) -> Option<TcpStackConnectAttempt> {
        self.tcp_connect_attempts_for_mode()
            .into_iter()
            .find(|attempt| !self.reported_connects.contains(attempt))
    }

    fn reset_connect(&mut self, attempt: &TcpStackConnectAttempt) {
        self.remember_reported(attempt);
        self.abort_matching_connect(attempt);
    }

    fn mark_connect_opened(&mut self, attempt: &TcpStackConnectAttempt) {
        self.remember_reported(attempt);
    }
}

pub fn pump_one_tun_packet<R: Read, W: Write>(
    adapter: &mut SmoltcpIpLoopback,
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    now_millis: i64,
) -> io::Result<SmoltcpTunPumpOutcome> {
    let bytes_read = reader.read(buffer)?;
    pump_read_tun_packet(adapter, writer, &buffer[..bytes_read], now_millis)
}

pub fn pump_one_tun_packet_io<T: Read + Write>(
    adapter: &mut SmoltcpIpLoopback,
    io: &mut T,
    buffer: &mut [u8],
    now_millis: i64,
) -> io::Result<SmoltcpTunPumpOutcome> {
    let bytes_read = io.read(buffer)?;
    pump_read_tun_packet(adapter, io, &buffer[..bytes_read], now_millis)
}

fn pump_read_tun_packet<W: Write>(
    adapter: &mut SmoltcpIpLoopback,
    writer: &mut W,
    packet: &[u8],
    now_millis: i64,
) -> io::Result<SmoltcpTunPumpOutcome> {
    if packet.is_empty() {
        return Ok(SmoltcpTunPumpOutcome::NoPacket);
    }
    adapter
        .ingest_ip_packet(packet.to_vec())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("{error:?}")))?;
    adapter.poll_once(now_millis);

    let mut outbound_packets = 0;
    let mut outbound_bytes = 0;
    while let Some(packet) = adapter.next_outbound_ip_packet() {
        writer.write_all(&packet)?;
        outbound_packets += 1;
        outbound_bytes += packet.len();
    }

    Ok(SmoltcpTunPumpOutcome::PacketProcessed {
        outbound_packets,
        outbound_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        parse_ip_packet, AttributionConfidence, DecisionAction, DnsCache, DnsObservation, Hostname,
        ParsedIpPacket, PolicyConfig, PolicyEngine, PolicyRule, Protocol, RuleSet, SandboxId,
        VecAuditSink, VerificationKernel,
    };
    use foxprox_runtime::{
        build_runtime_components, BrokerRuntimeConfig, EgressError, HostEgress, StdTcpStreamBridge,
        TcpConnectRequest, TcpHostReadOutcome, TcpStackOutcome, TcpStackRuntime,
        UdpDatagramRequest,
    };
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[derive(Default)]
    struct FakeEgress {
        tcp_attempts: usize,
    }

    #[derive(Default)]
    struct FakeBridge {
        host_writes: Vec<Vec<u8>>,
    }

    #[derive(Default)]
    struct RecordingWriter {
        writes: Vec<Vec<u8>>,
    }

    struct ScriptedTunIo {
        reads: VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
    }

    impl ScriptedTunIo {
        fn new(reads: Vec<Vec<u8>>) -> Self {
            Self {
                reads: reads.into(),
                writes: Vec::new(),
            }
        }
    }

    impl Read for ScriptedTunIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(packet) = self.reads.pop_front() else {
                return Ok(0);
            };
            assert!(packet.len() <= buf.len());
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    impl Write for ScriptedTunIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl TcpStreamBridge for FakeBridge {
        fn write_to_host(&mut self, _flow: &FlowKey, bytes: &[u8]) -> Result<(), TcpBridgeError> {
            self.host_writes.push(bytes.to_vec());
            Ok(())
        }

        fn write_to_sandbox(
            &mut self,
            _flow: &FlowKey,
            _bytes: &[u8],
        ) -> Result<(), TcpBridgeError> {
            Ok(())
        }
    }

    impl HostEgress for FakeEgress {
        fn open_tcp(&mut self, _request: TcpConnectRequest) -> Result<(), EgressError> {
            self.tcp_attempts += 1;
            Ok(())
        }

        fn send_udp(&mut self, _request: UdpDatagramRequest) -> Result<(), EgressError> {
            Err(EgressError::UnsupportedProtocol)
        }
    }

    fn ipv4_tcp_syn_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
    ) -> Vec<u8> {
        ipv4_tcp_packet(
            source,
            destination,
            source_port,
            destination_port,
            sequence,
            0,
            0x02,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn ipv4_tcp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 40 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        let tcp_checksum = tcp_ipv4_checksum(source, destination, tcp);
        tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
        packet
    }

    fn tcp_ipv4_checksum(source: Ipv4Addr, destination: Ipv4Addr, tcp: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        checksum(&pseudo)
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
        }
        !(sum as u16)
    }

    fn connected_adapter() -> SmoltcpIpLoopback {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        adapter
            .connect_tcp(Ipv4Addr::new(10, 66, 0, 1), 8080, 50000, 1024, 1024)
            .unwrap();
        for millis in 1..20 {
            adapter.poll_once(millis);
            if !adapter.active_tcp_connect_attempts().is_empty() {
                break;
            }
        }
        adapter
    }

    fn packet_pumped_adapter_with_unread_payload(bytes: &[u8]) -> SmoltcpIpLoopback {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let source = Ipv4Addr::new(10, 66, 0, 2);
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        let syn = ipv4_tcp_syn_packet(source, destination, 50001, 8080, 7);
        pump_one_tun_packet(
            &mut adapter,
            &mut Cursor::new(syn),
            &mut writer,
            &mut buffer,
            1,
        )
        .unwrap();
        let syn_ack = match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => segment,
            other => panic!("expected SYN/ACK, got {other:?}"),
        };
        let server_ack = syn_ack.sequence + 1;
        writer.clear();
        let ack = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x10, &[]);
        pump_one_tun_packet(
            &mut adapter,
            &mut Cursor::new(ack),
            &mut writer,
            &mut buffer,
            2,
        )
        .unwrap();
        writer.clear();
        let data = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x18, bytes);
        pump_one_tun_packet(
            &mut adapter,
            &mut Cursor::new(data),
            &mut writer,
            &mut buffer,
            3,
        )
        .unwrap();
        adapter
    }

    fn packet_pumped_adapter_with_payload(bytes: &[u8]) -> (SmoltcpIpLoopback, SmoltcpTcpPayload) {
        let mut adapter = packet_pumped_adapter_with_unread_payload(bytes);
        let payload = adapter.recv_on_listener_port_with_flow(8080, 64).unwrap();
        (adapter, payload)
    }

    fn packet_pumped_listener_payload(bytes: &[u8]) -> SmoltcpTcpPayload {
        packet_pumped_adapter_with_payload(bytes).1
    }

    #[test]
    fn ip_loopback_interface_accepts_configured_ipv4_address() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        adapter.poll_once(1);

        assert_eq!(adapter.config().address, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(adapter.config().prefix_len, 24);
    }

    #[test]
    fn tcp_listener_socket_is_allocated_with_explicit_buffers() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        adapter.poll_once(1);
    }

    #[test]
    fn raw_ip_packet_ingress_emits_outbound_ip_packet_without_smoltcp_type_leakage() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let syn = ipv4_tcp_syn_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            50001,
            8080,
            7,
        );

        adapter.ingest_ip_packet(syn).unwrap();
        let mut outbound = None;
        for millis in 1..10 {
            adapter.poll_once(millis);
            if let Some(packet) = adapter.next_outbound_ip_packet() {
                outbound = Some(packet);
                break;
            }
        }
        let outbound = outbound.expect("smoltcp should emit a TCP response packet");

        match parse_ip_packet(&outbound).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => {
                assert_eq!(segment.source, Ipv4Addr::new(10, 66, 0, 1));
                assert_eq!(segment.destination, Ipv4Addr::new(10, 66, 0, 2));
                assert_eq!(segment.source_port, 8080);
                assert_eq!(segment.destination_port, 50001);
                assert!(segment.syn);
                assert!(segment.ack);
            }
            other => panic!("expected TCP response packet, got {other:?}"),
        }
    }

    #[test]
    fn tun_packet_pump_reads_ip_packet_and_writes_smoltcp_response() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let syn = ipv4_tcp_syn_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            50001,
            8080,
            7,
        );
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];

        let outcome =
            pump_one_tun_packet(&mut adapter, &mut reader, &mut writer, &mut buffer, 1).unwrap();

        assert_eq!(
            outcome,
            SmoltcpTunPumpOutcome::PacketProcessed {
                outbound_packets: 1,
                outbound_bytes: writer.len()
            }
        );
        match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => {
                assert_eq!(segment.source, Ipv4Addr::new(10, 66, 0, 1));
                assert_eq!(segment.destination, Ipv4Addr::new(10, 66, 0, 2));
                assert_eq!(segment.source_port, 8080);
                assert_eq!(segment.destination_port, 50001);
                assert!(segment.syn);
                assert!(segment.ack);
            }
            other => panic!("expected TCP response packet, got {other:?}"),
        }
    }

    #[test]
    fn packet_pumped_tcp_handshake_exports_listener_payload() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let source = Ipv4Addr::new(10, 66, 0, 2);
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];

        let syn = ipv4_tcp_syn_packet(source, destination, 50001, 8080, 7);
        pump_one_tun_packet(
            &mut adapter,
            &mut Cursor::new(syn),
            &mut writer,
            &mut buffer,
            1,
        )
        .unwrap();
        let syn_ack = match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => segment,
            other => panic!("expected SYN/ACK, got {other:?}"),
        };
        assert!(syn_ack.syn);
        assert!(syn_ack.ack);
        assert_eq!(syn_ack.acknowledgement, 8);
        let server_ack = syn_ack.sequence + 1;
        writer.clear();

        let ack = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x10, &[]);
        pump_one_tun_packet(
            &mut adapter,
            &mut Cursor::new(ack),
            &mut writer,
            &mut buffer,
            2,
        )
        .unwrap();
        writer.clear();

        let data = ipv4_tcp_packet(
            source,
            destination,
            50001,
            8080,
            8,
            server_ack,
            0x18,
            b"tun-data",
        );
        pump_one_tun_packet(
            &mut adapter,
            &mut Cursor::new(data),
            &mut writer,
            &mut buffer,
            3,
        )
        .unwrap();
        let payload = adapter.recv_on_listener_port_with_flow(8080, 64).unwrap();

        assert_eq!(payload.bytes, b"tun-data".to_vec());
        assert_eq!(payload.flow.source.ip, IpAddr::V4(source));
        assert_eq!(payload.flow.source.port, 50001);
        assert_eq!(payload.flow.destination.ip, IpAddr::V4(destination));
        assert_eq!(payload.flow.destination.port, 8080);
    }

    #[test]
    fn packet_pumped_payload_reaches_real_loopback_host_bridge() {
        let payload = packet_pumped_listener_payload(b"tun-host");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"tun-host".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("packet-pumped-host-bridge").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge =
            StdTcpStreamBridge::new(payload.flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(payload.flow.clone()).unwrap();

        flow_runtime
            .send_sandbox_payload_to_host(&payload.flow, &payload.bytes)
            .unwrap();

        assert_eq!(server.join().unwrap(), b"tun-host".to_vec());
    }

    #[test]
    fn bridge_session_forwards_packet_pumped_payload_to_real_host() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"session-host");
        let attempt = adapter.accepted_tcp_connect_attempts().remove(0);
        let flow = FlowKey::new(Protocol::Tcp, attempt.source, attempt.destination);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"session-host".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("packet-pumped-session").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge = StdTcpStreamBridge::new(flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(flow.clone()).unwrap();
        let mut session = SmoltcpTcpBridgeSession::new(adapter, flow_runtime);

        let outcome = session.forward_sandbox_payload_once(8080, 64).unwrap();

        assert_eq!(
            outcome,
            SmoltcpTcpBridgeSessionOutcome {
                flow,
                bytes_forwarded: b"session-host".len()
            }
        );
        assert_eq!(server.join().unwrap(), b"session-host".to_vec());
    }

    #[test]
    fn policy_allowed_packet_pumped_connect_marks_session_flow_open() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"policy-session");
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        let mut rule = PolicyRule::allow("allow-policy-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            adapter,
            FakeEgress::default(),
            kernel,
            SandboxId::new("policy-session").unwrap(),
        );
        let outcome = runtime.handle_next_connect(2).unwrap();
        let (adapter, egress, kernel) = runtime.into_parts();
        let attempt = match outcome {
            TcpStackOutcome::HostConnectOpened { attempt, .. } => attempt,
            other => panic!("expected opened connect, got {other:?}"),
        };
        let flow = FlowKey::new(
            Protocol::Tcp,
            attempt.source.clone(),
            attempt.destination.clone(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"policy-session".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("policy-session-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge = StdTcpStreamBridge::new(flow.clone(), host_stream, Vec::new()).unwrap();
        let flow_runtime = TcpFlowRuntime::new(&components, bridge);
        let mut session = SmoltcpTcpBridgeSession::new(adapter, flow_runtime);

        let opened_flow = session.mark_opened_connect(&attempt).unwrap();
        let forwarded = session.forward_sandbox_payload_once(8080, 64).unwrap();

        assert_eq!(egress.tcp_attempts, 1);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(opened_flow, flow);
        assert_eq!(forwarded.bytes_forwarded, b"policy-session".len());
        assert_eq!(server.join().unwrap(), b"policy-session".to_vec());
    }

    #[test]
    fn allowed_connect_factory_builds_open_bridge_session() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"factory-open");
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        let mut rule = PolicyRule::allow("allow-factory-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            adapter,
            FakeEgress::default(),
            kernel,
            SandboxId::new("factory-session").unwrap(),
        );
        let outcome = runtime.handle_next_connect(2).unwrap();
        let (adapter, _, _) = runtime.into_parts();
        let attempt = match outcome {
            TcpStackOutcome::HostConnectOpened { attempt, .. } => attempt,
            other => panic!("expected opened connect, got {other:?}"),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"factory-open".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("factory-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let (mut session, flow) = SmoltcpTcpBridgeSession::from_allowed_connect(
            adapter,
            &components,
            &attempt,
            host_stream,
        )
        .unwrap();

        let forwarded = session.forward_sandbox_payload_once(8080, 64).unwrap();

        assert_eq!(forwarded.flow, flow);
        assert_eq!(forwarded.bytes_forwarded, b"factory-open".len());
        assert_eq!(server.join().unwrap(), b"factory-open".to_vec());
    }

    #[test]
    fn allowed_connect_factory_dials_real_loopback_host() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"dialed-host");
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        let mut rule = PolicyRule::allow("allow-dialed-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            adapter,
            FakeEgress::default(),
            kernel,
            SandboxId::new("dialed-session").unwrap(),
        );
        let outcome = runtime.handle_next_connect(2).unwrap();
        let (adapter, _, _) = runtime.into_parts();
        let attempt = match outcome {
            TcpStackOutcome::HostConnectOpened { attempt, .. } => attempt,
            other => panic!("expected opened connect, got {other:?}"),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"dialed-host".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("dialed-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let (mut session, flow) = SmoltcpTcpBridgeSession::connect_allowed_host_session(
            adapter,
            &components,
            &attempt,
            listen_addr,
        )
        .unwrap();

        let forwarded = session.forward_sandbox_payload_once(8080, 64).unwrap();

        assert_eq!(forwarded.flow, flow);
        assert_eq!(forwarded.bytes_forwarded, b"dialed-host".len());
        assert_eq!(server.join().unwrap(), b"dialed-host".to_vec());
    }

    #[test]
    fn next_allowed_connect_helper_policy_gates_dials_and_opens_session() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"one-call-open");
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        let mut rule = PolicyRule::allow("allow-one-call-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"one-call-open".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("one-call-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();

        let (mut session, flow, decision) =
            SmoltcpTcpBridgeSession::connect_next_allowed_host_session(
                adapter,
                &components,
                &mut kernel,
                SandboxId::new("one-call-session").unwrap(),
                listen_addr,
                5,
            )
            .unwrap();
        let forwarded = session.forward_sandbox_payload_once(8080, 64).unwrap();

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(forwarded.flow, flow);
        assert_eq!(forwarded.bytes_forwarded, b"one-call-open".len());
        assert_eq!(server.join().unwrap(), b"one-call-open".to_vec());
    }

    #[test]
    fn next_allowed_connect_helper_resets_denied_attempt_before_dialing() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"denied-one-call");
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("denied-one-call-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();

        let error = match SmoltcpTcpBridgeSession::connect_next_allowed_host_session(
            adapter,
            &components,
            &mut kernel,
            SandboxId::new("denied-one-call").unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            5,
        ) {
            Ok(_) => panic!("denied connect should not open a session"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SmoltcpTcpBridgeSessionError::PolicyDenied(_)
        ));
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0]
                .decision
                .as_ref()
                .unwrap()
                .action,
            DecisionAction::DenyDrop
        );
    }

    #[test]
    fn tun_pump_can_open_policy_allowed_real_host_session_from_syn() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let syn = ipv4_tcp_syn_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            50001,
            8080,
            7,
        );
        let mut rule = PolicyRule::allow("allow-pumped-open");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("pumped-open-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];

        let (session, flow, decision, pump) =
            SmoltcpTcpBridgeSession::pump_tun_and_open_next_allowed_host_session(
                adapter,
                &mut reader,
                &mut writer,
                &mut buffer,
                &components,
                &mut kernel,
                SandboxId::new("pumped-open").unwrap(),
                listen_addr,
                1,
                6,
            )
            .unwrap();
        server.join().unwrap();

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(session.flow_runtime().bridge().open_flows().len(), 1);
        assert!(session
            .flow_runtime()
            .bridge()
            .open_flows()
            .contains_key(&flow));
        assert!(matches!(
            pump,
            SmoltcpTunPumpOutcome::PacketProcessed {
                outbound_packets: 1,
                ..
            }
        ));
        match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => {
                assert_eq!(segment.source, Ipv4Addr::new(10, 66, 0, 1));
                assert_eq!(segment.destination, Ipv4Addr::new(10, 66, 0, 2));
                assert!(segment.syn);
                assert!(segment.ack);
            }
            other => panic!("expected SYN/ACK packet, got {other:?}"),
        }
    }

    #[test]
    fn pumped_host_session_can_use_dns_cache_domain_policy() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let syn = ipv4_tcp_syn_packet(Ipv4Addr::new(10, 66, 0, 2), destination, 50001, 8080, 7);
        let mut rule = PolicyRule::allow("allow-dns-attributed-pumped-open");
        rule.protocol = Some(Protocol::Tcp);
        rule.domain_suffix = Some(Hostname::normalize("example.test").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::Medium);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut dns_cache = DnsCache::new();
        dns_cache.record(DnsObservation::new(
            Hostname::normalize("api.example.test").unwrap(),
            vec![IpAddr::V4(destination)],
            5,
            10_000,
        ));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("dns-pumped-open-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];

        let (_session, flow, decision, _pump) =
            SmoltcpTcpBridgeSession::pump_tun_and_open_next_allowed_host_session_with_dns_cache(
                adapter,
                &mut reader,
                &mut writer,
                &mut buffer,
                &components,
                &mut kernel,
                SandboxId::new("dns-pumped-open").unwrap(),
                Some(&dns_cache),
                listen_addr,
                1,
                6,
            )
            .unwrap();
        server.join().unwrap();

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("allow-dns-attributed-pumped-open")
        );
        assert_eq!(flow.destination.ip, IpAddr::V4(destination));
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0]
                .hostname
                .as_ref()
                .map(|hostname| hostname.as_str()),
            Some("api.example.test")
        );
    }

    #[test]
    fn open_session_pumps_subsequent_tun_data_to_real_host() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let source = Ipv4Addr::new(10, 66, 0, 2);
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let syn = ipv4_tcp_syn_packet(source, destination, 50001, 8080, 7);
        let mut rule = PolicyRule::allow("allow-step-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"step-data".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("step-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        let (mut session, flow, _, _) =
            SmoltcpTcpBridgeSession::pump_tun_and_open_next_allowed_host_session(
                adapter,
                &mut reader,
                &mut writer,
                &mut buffer,
                &components,
                &mut kernel,
                SandboxId::new("step-session").unwrap(),
                listen_addr,
                1,
                6,
            )
            .unwrap();
        let syn_ack = match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => segment,
            other => panic!("expected SYN/ACK, got {other:?}"),
        };
        let server_ack = syn_ack.sequence + 1;
        writer.clear();

        let ack = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x10, &[]);
        let ack_step = session
            .pump_tun_packet_and_forward_sandbox_payload(
                &mut Cursor::new(ack),
                &mut writer,
                &mut buffer,
                8080,
                64,
                2,
            )
            .unwrap();
        writer.clear();
        let data = ipv4_tcp_packet(
            source,
            destination,
            50001,
            8080,
            8,
            server_ack,
            0x18,
            b"step-data",
        );
        let data_step = session
            .pump_tun_packet_and_forward_sandbox_payload(
                &mut Cursor::new(data),
                &mut writer,
                &mut buffer,
                8080,
                64,
                3,
            )
            .unwrap();

        assert!(ack_step.forwarded.is_none());
        assert_eq!(
            data_step.forwarded,
            Some(SmoltcpTcpBridgeSessionOutcome {
                flow,
                bytes_forwarded: b"step-data".len()
            })
        );
        assert_eq!(server.join().unwrap(), b"step-data".to_vec());
    }

    #[test]
    fn bidirectional_tick_forwards_sandbox_data_and_emits_host_reply() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let source = Ipv4Addr::new(10, 66, 0, 2);
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let syn = ipv4_tcp_syn_packet(source, destination, 50001, 8080, 7);
        let mut rule = PolicyRule::allow("allow-bidi-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"tick-data".len()];
            stream.read_exact(&mut received).unwrap();
            stream.write_all(b"tick-reply").unwrap();
            received
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("bidi-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        let (mut session, flow, _, _) =
            SmoltcpTcpBridgeSession::pump_tun_and_open_next_allowed_host_session(
                adapter,
                &mut reader,
                &mut writer,
                &mut buffer,
                &components,
                &mut kernel,
                SandboxId::new("bidi-session").unwrap(),
                listen_addr,
                1,
                6,
            )
            .unwrap();
        let syn_ack = match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => segment,
            other => panic!("expected SYN/ACK, got {other:?}"),
        };
        let server_ack = syn_ack.sequence + 1;
        writer.clear();
        let ack = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x10, &[]);
        session
            .pump_tun_packet_and_forward_sandbox_payload(
                &mut Cursor::new(ack),
                &mut writer,
                &mut buffer,
                8080,
                64,
                2,
            )
            .unwrap();
        let data = ipv4_tcp_packet(
            source,
            destination,
            50001,
            8080,
            8,
            server_ack,
            0x18,
            b"tick-data",
        );
        let mut recording_writer = RecordingWriter::default();

        let mut outcome = session
            .pump_bidirectional_once(
                &mut Cursor::new(data),
                &mut recording_writer,
                &mut buffer,
                8080,
                64,
                &flow,
                64,
                3,
            )
            .unwrap();
        let initial_forwarded = outcome.sandbox.forwarded.clone();
        for millis in 4..40 {
            if matches!(outcome.host.host_read, TcpHostReadOutcome::Bytes { .. }) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
            outcome = session
                .pump_bidirectional_once(
                    &mut Cursor::new(Vec::new()),
                    &mut recording_writer,
                    &mut buffer,
                    8080,
                    64,
                    &flow,
                    64,
                    millis,
                )
                .unwrap();
        }

        assert_eq!(server.join().unwrap(), b"tick-data".to_vec());
        assert_eq!(
            initial_forwarded,
            Some(SmoltcpTcpBridgeSessionOutcome {
                flow,
                bytes_forwarded: b"tick-data".len()
            })
        );
        assert!(matches!(
            outcome.host.host_read,
            TcpHostReadOutcome::Bytes {
                count
            } if count == b"tick-reply".len()
        ));
        assert!(recording_writer.writes.iter().any(|packet| {
            matches!(
                parse_ip_packet(packet),
                Ok(ParsedIpPacket::Tcpv4Segment(segment)) if segment.payload == b"tick-reply"
            )
        }));
    }

    #[test]
    fn loop_state_tracks_idle_wouldblock_and_later_host_progress() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let source = Ipv4Addr::new(10, 66, 0, 2);
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let syn = ipv4_tcp_syn_packet(source, destination, 50001, 8080, 7);
        let mut rule = PolicyRule::allow("allow-loop-state");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (send_reply, receive_reply) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            receive_reply.recv().unwrap();
            stream.write_all(b"loop-reply").unwrap();
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("loop-state-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        let (mut session, flow, _, _) =
            SmoltcpTcpBridgeSession::pump_tun_and_open_next_allowed_host_session(
                adapter,
                &mut reader,
                &mut writer,
                &mut buffer,
                &components,
                &mut kernel,
                SandboxId::new("loop-state").unwrap(),
                listen_addr,
                1,
                6,
            )
            .unwrap();
        let syn_ack = match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => segment,
            other => panic!("expected SYN/ACK, got {other:?}"),
        };
        let server_ack = syn_ack.sequence + 1;
        writer.clear();
        let ack = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x10, &[]);
        session
            .pump_tun_packet_and_forward_sandbox_payload(
                &mut Cursor::new(ack),
                &mut writer,
                &mut buffer,
                8080,
                64,
                2,
            )
            .unwrap();
        let mut state = SmoltcpTcpBridgeLoopState::default();
        let mut recording_writer = RecordingWriter::default();

        let idle = session
            .run_loop_tick(
                &mut state,
                &mut Cursor::new(Vec::new()),
                &mut recording_writer,
                &mut buffer,
                8080,
                64,
                &flow,
                64,
                3,
            )
            .unwrap();
        send_reply.send(()).unwrap();
        let mut progress = None;
        for millis in 4..40 {
            let step = session
                .run_loop_tick(
                    &mut state,
                    &mut Cursor::new(Vec::new()),
                    &mut recording_writer,
                    &mut buffer,
                    8080,
                    64,
                    &flow,
                    64,
                    millis,
                )
                .unwrap();
            if step.made_progress {
                progress = Some(step);
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let progress = progress.expect("host reply should eventually make loop progress");
        server.join().unwrap();

        assert!(!idle.made_progress);
        assert!(state.idle_ticks >= 1);
        assert!(state.progress_ticks >= 1);
        assert!(matches!(
            idle.tick.host.host_read,
            TcpHostReadOutcome::WouldBlock
        ));
        assert!(matches!(
            progress.tick.host.host_read,
            TcpHostReadOutcome::Bytes {
                count
            } if count == b"loop-reply".len()
        ));
        assert!(recording_writer.writes.iter().any(|packet| {
            matches!(
                parse_ip_packet(packet),
                Ok(ParsedIpPacket::Tcpv4Segment(segment)) if segment.payload == b"loop-reply"
            )
        }));
    }

    #[test]
    fn io_session_owns_buffer_state_and_tun_like_io_across_ticks() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_packet_loopback(false);
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let source = Ipv4Addr::new(10, 66, 0, 2);
        let destination = Ipv4Addr::new(10, 66, 0, 1);
        let syn = ipv4_tcp_syn_packet(source, destination, 50001, 8080, 7);
        let mut rule = PolicyRule::allow("allow-io-session");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"owned-io".len()];
            stream.read_exact(&mut received).unwrap();
            stream.write_all(b"owned-reply").unwrap();
            received
        });
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("io-session-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        let (session, flow, _, _) =
            SmoltcpTcpBridgeSession::pump_tun_and_open_next_allowed_host_session(
                adapter,
                &mut reader,
                &mut writer,
                &mut buffer,
                &components,
                &mut kernel,
                SandboxId::new("io-session").unwrap(),
                listen_addr,
                1,
                6,
            )
            .unwrap();
        let syn_ack = match parse_ip_packet(&writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => segment,
            other => panic!("expected SYN/ACK, got {other:?}"),
        };
        let server_ack = syn_ack.sequence + 1;
        let ack = ipv4_tcp_packet(source, destination, 50001, 8080, 8, server_ack, 0x10, &[]);
        let data = ipv4_tcp_packet(
            source,
            destination,
            50001,
            8080,
            8,
            server_ack,
            0x18,
            b"owned-io",
        );
        let tun = ScriptedTunIo::new(vec![ack, data]);
        let mut io_session = SmoltcpTcpBridgeIoSession::new(session, tun, 1500, flow, 8080, 64, 64);

        let first = io_session.run_tick(2).unwrap();
        let second = io_session.run_tick(3).unwrap();
        let mut saw_reply = false;
        for millis in 4..40 {
            let step = io_session.run_tick(millis).unwrap();
            if matches!(step.tick.host.host_read, TcpHostReadOutcome::Bytes { .. }) {
                saw_reply = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let (_, tun, state) = io_session.into_parts();

        assert_eq!(server.join().unwrap(), b"owned-io".to_vec());
        assert!(!first.made_progress);
        assert!(second.made_progress);
        assert!(saw_reply);
        assert!(state.ticks >= 3);
        assert!(state.progress_ticks >= 2);
        assert!(tun.writes.iter().any(|packet| {
            matches!(
                parse_ip_packet(packet),
                Ok(ParsedIpPacket::Tcpv4Segment(segment)) if segment.payload == b"owned-reply"
            )
        }));
    }

    #[test]
    fn host_bytes_on_packet_pumped_flow_emit_sandbox_ip_packet() {
        let (mut adapter, payload) = packet_pumped_adapter_with_payload(b"sandbox-request");

        let sent = adapter
            .send_to_sandbox_on_flow(&payload.flow, b"host-response")
            .unwrap();
        adapter.poll_once(4);
        let outbound = adapter
            .next_outbound_ip_packet()
            .expect("host bytes should emit an outbound TCP packet");

        assert_eq!(sent, b"host-response".len());
        match parse_ip_packet(&outbound).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => {
                assert_eq!(segment.source, Ipv4Addr::new(10, 66, 0, 1));
                assert_eq!(segment.destination, Ipv4Addr::new(10, 66, 0, 2));
                assert_eq!(segment.source_port, 8080);
                assert_eq!(segment.destination_port, 50001);
                assert!(segment.ack);
                assert_eq!(segment.payload, b"host-response");
            }
            other => panic!("expected TCP payload packet, got {other:?}"),
        }
    }

    #[test]
    fn host_read_from_tcp_flow_runtime_emits_packet_pumped_sandbox_packet() {
        let (mut adapter, payload) = packet_pumped_adapter_with_payload(b"sandbox-request");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"host-via-runtime").unwrap();
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("packet-pumped-host-read").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge =
            StdTcpStreamBridge::new(payload.flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(payload.flow.clone()).unwrap();

        let host_read = flow_runtime
            .pump_host_once_to_sandbox_writer(&payload.flow, 64)
            .unwrap();
        let sandbox_bytes = flow_runtime.bridge().bridge().sandbox_writer().clone();
        let sent = adapter
            .send_to_sandbox_on_flow(&payload.flow, &sandbox_bytes)
            .unwrap();
        adapter.poll_once(4);
        let outbound = adapter
            .next_outbound_ip_packet()
            .expect("host runtime bytes should emit a sandbox packet");
        server.join().unwrap();

        assert_eq!(
            host_read,
            TcpHostReadOutcome::Bytes {
                count: b"host-via-runtime".len()
            }
        );
        assert_eq!(sent, b"host-via-runtime".len());
        match parse_ip_packet(&outbound).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => {
                assert_eq!(segment.source, Ipv4Addr::new(10, 66, 0, 1));
                assert_eq!(segment.destination, Ipv4Addr::new(10, 66, 0, 2));
                assert_eq!(segment.source_port, 8080);
                assert_eq!(segment.destination_port, 50001);
                assert_eq!(segment.payload, b"host-via-runtime");
            }
            other => panic!("expected TCP payload packet, got {other:?}"),
        }
    }

    #[test]
    fn bridge_session_pumps_host_bytes_to_tun_writer() {
        let (adapter, payload) = packet_pumped_adapter_with_payload(b"sandbox-request");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"session-reply").unwrap();
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("packet-pumped-session-reply").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge =
            StdTcpStreamBridge::new(payload.flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(payload.flow.clone()).unwrap();
        let mut session = SmoltcpTcpBridgeSession::new(adapter, flow_runtime);
        let mut tun_writer = Vec::new();

        let outcome = session
            .pump_host_to_sandbox_once(&payload.flow, 64, &mut tun_writer, 4)
            .unwrap();
        server.join().unwrap();

        assert_eq!(
            outcome,
            SmoltcpHostToSandboxPumpOutcome {
                host_read: TcpHostReadOutcome::Bytes {
                    count: b"session-reply".len()
                },
                sandbox_bytes: b"session-reply".len(),
                outbound_packets: 1,
                outbound_bytes: tun_writer.len()
            }
        );
        match parse_ip_packet(&tun_writer).unwrap() {
            ParsedIpPacket::Tcpv4Segment(segment) => {
                assert_eq!(segment.source, Ipv4Addr::new(10, 66, 0, 1));
                assert_eq!(segment.destination, Ipv4Addr::new(10, 66, 0, 2));
                assert_eq!(segment.source_port, 8080);
                assert_eq!(segment.destination_port, 50001);
                assert_eq!(segment.payload, b"session-reply");
            }
            other => panic!("expected TCP payload packet, got {other:?}"),
        }
    }

    #[test]
    fn bridge_session_close_reports_bidirectional_byte_counts() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"close-request");
        let attempt = adapter.accepted_tcp_connect_attempts().remove(0);
        let flow = FlowKey::new(Protocol::Tcp, attempt.source, attempt.destination);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"close-request".len()];
            stream.read_exact(&mut received).unwrap();
            stream.write_all(b"close-reply").unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("packet-pumped-close").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge = StdTcpStreamBridge::new(flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(flow.clone()).unwrap();
        let mut session = SmoltcpTcpBridgeSession::new(adapter, flow_runtime);
        let mut tun_writer = Vec::new();

        session.forward_sandbox_payload_once(8080, 64).unwrap();
        session
            .pump_host_to_sandbox_once(&flow, 64, &mut tun_writer, 4)
            .unwrap();
        let lifecycle = session
            .close_flow(&flow, Duration::from_millis(25))
            .unwrap();

        assert_eq!(server.join().unwrap(), b"close-request".to_vec());
        assert!(!tun_writer.is_empty());
        assert_eq!(
            lifecycle,
            TcpStackLifecycleEvent::FlowClosed {
                flow,
                bytes_from_sandbox: b"close-request".len() as u64,
                bytes_from_host: b"close-reply".len() as u64,
                duration: Duration::from_millis(25)
            }
        );
    }

    #[test]
    fn bridge_session_close_emits_lifecycle_audit_event() {
        let mut adapter = packet_pumped_adapter_with_unread_payload(b"audit-close");
        let attempt = adapter.accepted_tcp_connect_attempts().remove(0);
        let flow = FlowKey::new(Protocol::Tcp, attempt.source, attempt.destination);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"audit-close".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("audit-close-components").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge = StdTcpStreamBridge::new(flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(flow.clone()).unwrap();
        let mut session = SmoltcpTcpBridgeSession::new(adapter, flow_runtime);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );

        session.forward_sandbox_payload_once(8080, 64).unwrap();
        let lifecycle = session
            .close_and_audit_flow(
                &flow,
                Duration::from_millis(30),
                &mut kernel,
                SandboxId::new("audit-close").unwrap(),
                42,
            )
            .unwrap();

        assert_eq!(server.join().unwrap(), b"audit-close".to_vec());
        assert!(matches!(
            lifecycle,
            TcpStackLifecycleEvent::FlowClosed { .. }
        ));
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "audit-close"
        );
        assert_eq!(
            kernel.audit_sink().events()[0].flow_duration,
            Some(Duration::from_millis(30))
        );
    }

    #[test]
    fn tun_ingressed_syn_exports_accepted_listener_connect_attempt() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let syn = ipv4_tcp_syn_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            50001,
            8080,
            7,
        );
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];

        pump_one_tun_packet(&mut adapter, &mut reader, &mut writer, &mut buffer, 1).unwrap();
        let attempts = adapter.accepted_tcp_connect_attempts();

        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].source.ip,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2))
        );
        assert_eq!(attempts[0].source.port, 50001);
        assert_eq!(
            attempts[0].destination.ip,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))
        );
        assert_eq!(attempts[0].destination.port, 8080);
    }

    #[test]
    fn tun_ingressed_syn_is_policy_gated_by_tcp_stack_runtime() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let syn = ipv4_tcp_syn_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            50001,
            8080,
            7,
        );
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        pump_one_tun_packet(&mut adapter, &mut reader, &mut writer, &mut buffer, 1).unwrap();
        let mut rule = PolicyRule::allow("allow-tun-smoltcp-tcp");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            adapter,
            FakeEgress::default(),
            kernel,
            SandboxId::new("smoltcp-tun-runtime").unwrap(),
        );

        let outcome = runtime.handle_next_connect(2).unwrap();
        let (_adapter, egress, kernel) = runtime.into_parts();

        assert!(matches!(outcome, TcpStackOutcome::HostConnectOpened { .. }));
        assert_eq!(egress.tcp_attempts, 1);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0]
                .decision
                .as_ref()
                .unwrap()
                .action,
            DecisionAction::Allow
        );
    }

    #[test]
    fn denied_tun_ingressed_syn_aborts_and_suppresses_accepted_socket() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        let syn = ipv4_tcp_syn_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            50001,
            8080,
            7,
        );
        let mut reader = Cursor::new(syn);
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];
        pump_one_tun_packet(&mut adapter, &mut reader, &mut writer, &mut buffer, 1).unwrap();
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            adapter,
            FakeEgress::default(),
            kernel,
            SandboxId::new("smoltcp-tun-deny").unwrap(),
        );

        let outcome = runtime.handle_next_connect(2).unwrap();
        let (mut adapter, egress, kernel) = runtime.into_parts();
        let attempt = match outcome {
            TcpStackOutcome::DeniedReset { decision, attempt } => {
                assert_eq!(decision.action, DecisionAction::DenyDrop);
                attempt
            }
            other => panic!("expected denied reset, got {other:?}"),
        };

        assert_eq!(egress.tcp_attempts, 0);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert!(!adapter.has_active_socket_for_attempt_either_direction(&attempt));
        assert!(adapter.next_connect_attempt().is_none());
    }

    #[test]
    fn tun_packet_pump_reports_empty_reads_without_polling() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        let mut reader = Cursor::new(Vec::new());
        let mut writer = Vec::new();
        let mut buffer = vec![0; 1500];

        let outcome =
            pump_one_tun_packet(&mut adapter, &mut reader, &mut writer, &mut buffer, 1).unwrap();

        assert_eq!(outcome, SmoltcpTunPumpOutcome::NoPacket);
        assert!(writer.is_empty());
    }

    #[test]
    fn raw_ip_packet_ingress_rejects_empty_packets() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        assert!(matches!(
            adapter.ingest_ip_packet(Vec::new()),
            Err(SmoltcpAdapterError::EmptyIpPacket)
        ));
    }

    #[test]
    fn loopback_client_connection_makes_tcp_sockets_active() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        adapter
            .connect_tcp(Ipv4Addr::new(10, 66, 0, 1), 8080, 50000, 1024, 1024)
            .unwrap();

        for millis in 1..20 {
            adapter.poll_once(millis);
            if adapter.active_tcp_socket_count() >= 2 {
                break;
            }
        }

        assert_eq!(adapter.active_tcp_socket_count(), 2);
    }

    #[test]
    fn active_loopback_client_exports_normalized_connect_attempt() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();
        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        adapter
            .connect_tcp(Ipv4Addr::new(10, 66, 0, 1), 8080, 50000, 1024, 1024)
            .unwrap();
        for millis in 1..20 {
            adapter.poll_once(millis);
            if !adapter.active_tcp_connect_attempts().is_empty() {
                break;
            }
        }

        let attempts = adapter.active_tcp_connect_attempts();

        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].source.ip,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))
        );
        assert_eq!(attempts[0].source.port, 50000);
        assert_eq!(
            attempts[0].destination.ip,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))
        );
        assert_eq!(attempts[0].destination.port, 8080);
    }

    #[test]
    fn smoltcp_loopback_moves_client_payload_to_listener_socket() {
        let mut adapter = connected_adapter();
        let attempt = adapter.next_connect_attempt().unwrap();

        let mut sent = None;
        for millis in 20..60 {
            match adapter.send_on_connect_attempt(&attempt, b"hello-smoltcp") {
                Ok(count) => {
                    sent = Some(count);
                    break;
                }
                Err(SmoltcpAdapterError::TcpSendRejected) => adapter.poll_once(millis),
                Err(error) => panic!("unexpected send error: {error:?}"),
            }
        }
        let sent = sent.expect("client socket should become send-ready");
        let mut received = None;
        for millis in 60..100 {
            adapter.poll_once(millis);
            match adapter.recv_on_listener_port_with_flow(8080, 64) {
                Ok(payload) if !payload.bytes.is_empty() => {
                    received = Some(payload);
                    break;
                }
                Ok(_) | Err(SmoltcpAdapterError::TcpRecvRejected) => {}
                Err(error) => panic!("unexpected recv error: {error:?}"),
            }
        }
        let received = received.expect("listener should receive payload");

        assert_eq!(sent, b"hello-smoltcp".len());
        assert_eq!(received.bytes, b"hello-smoltcp".to_vec());
        assert_eq!(received.flow.source, attempt.source);
        assert_eq!(received.flow.destination, attempt.destination);
    }

    #[test]
    fn smoltcp_payload_flow_can_be_handed_to_tcp_flow_runtime() {
        let mut adapter = connected_adapter();
        let attempt = adapter.next_connect_attempt().unwrap();
        for millis in 20..60 {
            match adapter.send_on_connect_attempt(&attempt, b"bridge-me") {
                Ok(_) => break,
                Err(SmoltcpAdapterError::TcpSendRejected) => adapter.poll_once(millis),
                Err(error) => panic!("unexpected send error: {error:?}"),
            }
        }
        let mut payload = None;
        for millis in 60..100 {
            adapter.poll_once(millis);
            match adapter.recv_on_listener_port_with_flow(8080, 64) {
                Ok(received) if !received.bytes.is_empty() => {
                    payload = Some(received);
                    break;
                }
                Ok(_) | Err(SmoltcpAdapterError::TcpRecvRejected) => {}
                Err(error) => panic!("unexpected recv error: {error:?}"),
            }
        }
        let payload = payload.unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("smoltcp-flow-runtime").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, FakeBridge::default());
        flow_runtime.mark_opened(payload.flow.clone()).unwrap();

        flow_runtime
            .send_sandbox_payload_to_host(&payload.flow, &payload.bytes)
            .unwrap();
        let (bridge, _) = flow_runtime.into_parts();
        let (fake, _) = bridge.into_parts();

        assert_eq!(fake.host_writes, vec![b"bridge-me".to_vec()]);
    }

    #[test]
    fn smoltcp_payload_flow_reaches_real_loopback_host_bridge() {
        let mut adapter = connected_adapter();
        let attempt = adapter.next_connect_attempt().unwrap();
        for millis in 20..60 {
            match adapter.send_on_connect_attempt(&attempt, b"host-bridge") {
                Ok(_) => break,
                Err(SmoltcpAdapterError::TcpSendRejected) => adapter.poll_once(millis),
                Err(error) => panic!("unexpected send error: {error:?}"),
            }
        }
        let mut payload = None;
        for millis in 60..100 {
            adapter.poll_once(millis);
            match adapter.recv_on_listener_port_with_flow(8080, 64) {
                Ok(received) if !received.bytes.is_empty() => {
                    payload = Some(received);
                    break;
                }
                Ok(_) | Err(SmoltcpAdapterError::TcpRecvRejected) => {}
                Err(error) => panic!("unexpected recv error: {error:?}"),
            }
        }
        let payload = payload.unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; b"host-bridge".len()];
            stream.read_exact(&mut received).unwrap();
            received
        });
        let host_stream = TcpStream::connect(listen_addr).unwrap();
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("smoltcp-std-bridge").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
            tcp_max_open_flows: 8,
            tcp_metadata_buffer_bytes: 1024,
        })
        .unwrap();
        let bridge =
            StdTcpStreamBridge::new(payload.flow.clone(), host_stream, Vec::new()).unwrap();
        let mut flow_runtime = TcpFlowRuntime::new(&components, bridge);
        flow_runtime.mark_opened(payload.flow.clone()).unwrap();

        flow_runtime
            .send_sandbox_payload_to_host(&payload.flow, &payload.bytes)
            .unwrap();

        assert_eq!(server.join().unwrap(), b"host-bridge".to_vec());
    }

    #[test]
    fn smoltcp_adapter_connect_attempt_is_policy_gated_by_runtime() {
        let adapter = connected_adapter();
        let mut rule = PolicyRule::allow("allow-smoltcp-tcp");
        rule.protocol = Some(Protocol::Tcp);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            adapter,
            FakeEgress::default(),
            kernel,
            SandboxId::new("smoltcp-runtime").unwrap(),
        );

        let outcome = runtime.handle_next_connect(10).unwrap();
        let (_adapter, egress, kernel) = runtime.into_parts();

        assert!(matches!(outcome, TcpStackOutcome::HostConnectOpened { .. }));
        assert_eq!(egress.tcp_attempts, 1);
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0]
                .decision
                .as_ref()
                .unwrap()
                .action,
            DecisionAction::Allow
        );
    }

    #[test]
    fn smoltcp_adapter_suppresses_connect_after_open_callback() {
        let mut adapter = connected_adapter();
        let attempt = adapter.next_connect_attempt().unwrap();

        adapter.mark_connect_opened(&attempt);

        assert!(adapter.next_connect_attempt().is_none());
    }

    #[test]
    fn smoltcp_adapter_suppresses_connect_after_reset_callback() {
        let mut adapter = connected_adapter();
        let attempt = adapter.next_connect_attempt().unwrap();

        adapter.reset_connect(&attempt);

        assert!(adapter.next_connect_attempt().is_none());
    }

    #[test]
    fn smoltcp_adapter_reset_aborts_matching_active_socket() {
        let mut adapter = connected_adapter();
        let attempt = adapter.next_connect_attempt().unwrap();
        assert!(adapter.has_active_socket_for_attempt(&attempt));

        adapter.reset_connect(&attempt);
        adapter.poll_once(30);

        assert!(!adapter.has_active_socket_for_attempt(&attempt));
        assert!(adapter.next_connect_attempt().is_none());
    }

    #[test]
    fn tcp_client_rejects_invalid_port_and_buffers() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        assert!(matches!(
            adapter.connect_tcp(Ipv4Addr::new(10, 66, 0, 1), 0, 50000, 1024, 1024),
            Err(SmoltcpAdapterError::InvalidTcpPort)
        ));
        assert!(matches!(
            adapter.connect_tcp(Ipv4Addr::new(10, 66, 0, 1), 8080, 0, 1024, 1024),
            Err(SmoltcpAdapterError::InvalidTcpPort)
        ));
        assert!(matches!(
            adapter.connect_tcp(Ipv4Addr::new(10, 66, 0, 1), 8080, 50000, 0, 1024),
            Err(SmoltcpAdapterError::InvalidTcpBufferSize)
        ));
    }

    #[test]
    fn tcp_listener_rejects_invalid_port_and_buffers() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        assert!(matches!(
            adapter.listen_tcp(0, 1024, 1024),
            Err(SmoltcpAdapterError::InvalidTcpPort)
        ));
        assert!(matches!(
            adapter.listen_tcp(8080, 0, 1024),
            Err(SmoltcpAdapterError::InvalidTcpBufferSize)
        ));
        assert!(matches!(
            adapter.listen_tcp(8080, 1024, 0),
            Err(SmoltcpAdapterError::InvalidTcpBufferSize)
        ));
    }

    #[test]
    fn ip_loopback_rejects_invalid_ipv4_prefix_before_interface_build() {
        let result = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 33,
            },
            0,
        );

        assert!(matches!(result, Err(SmoltcpAdapterError::InvalidPrefixLen)));
    }
}
