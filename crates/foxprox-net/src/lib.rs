//! smoltcp-backed transparent TCP forwarding proof.
//!
//! This crate is intentionally a narrow Milestone 2 adapter: it consumes a TUN
//! file descriptor, feeds a smoltcp IPv4 stack, accepts one configured TCP
//! destination port, opens host TCP sockets, and bridges bytes in both
//! directions. Policy is temporarily allow-all for accepted TCP connects.

#![deny(missing_docs)]

mod combined;
mod udp;

pub use combined::{
    run_combined_transparent_proof, run_combined_transparent_proof_with_ready,
    CombinedTransparentProofConfig, ExplicitHttpProxyBridgeConfig, ExplicitProxyBridgeConfig,
};
pub use udp::{run_udp_dns_proof, run_udp_dns_proof_with_ready, UdpDnsProofConfig};

use foxprox_core::{
    parse_http_request_head, parse_tls_client_hello, Attribution, AttributionConfidence,
    AttributionSource, AuditBackpressure, AuditBuffer, AuditEvent, AuditEventKind, Decision,
    DenialReason, DnsCache, EgressContext, Frontend, NetworkEvent, PolicyEngine, PolicyRuleSet,
    Protocol, SandboxId, TcpEgressRequest, TransportEndpoint, UnsupportedReason,
};
use foxprox_egress::{egress_error_to_io, StdHostEgress};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Medium, TunTapInterface};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant as StdInstant, SystemTime};

/// Configuration for the smoltcp TCP forwarding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpProofConfig {
    /// Sandbox/session identifier used in normalized events.
    pub sandbox_id: SandboxId,
    /// Broker/gateway IPv4 address configured on the smoltcp interface.
    pub broker_ip: Ipv4Addr,
    /// Network prefix length for the broker interface address.
    pub prefix_len: u8,
    /// TUN MTU.
    pub mtu: usize,
    /// Destination TCP port to listen for transparently.
    pub tcp_port: u16,
    /// Host connect timeout.
    pub connect_timeout: Duration,
    /// Maximum buffered bytes in either bridge direction.
    pub pending_buffer_limit: usize,
    /// Idle timeout for a proof TCP flow.
    pub idle_timeout: Duration,
    /// Policy used before host TCP connect in the proof runtime.
    pub policy: PolicyRuleSet,
    /// Maximum queued audit events before TCP proof paths fail closed.
    pub audit_queue_capacity: usize,
    /// Optional host-side TCP destination override used for local service bridges.
    pub tcp_egress_override: Option<SocketAddr>,
}

impl TcpProofConfig {
    /// Creates a proof config using the repository's default TUN addresses.
    pub fn new(sandbox_id: SandboxId) -> Self {
        Self {
            sandbox_id,
            broker_ip: Ipv4Addr::new(10, 255, 0, 1),
            prefix_len: 24,
            mtu: 1500,
            tcp_port: 80,
            connect_timeout: Duration::from_secs(5),
            pending_buffer_limit: 256 * 1024,
            idle_timeout: Duration::from_secs(30),
            policy: PolicyRuleSet::default(),
            audit_queue_capacity: 8192,
            tcp_egress_override: None,
        }
    }
}

/// Runs the TCP forwarding proof until the TUN fd errors or the process is interrupted.
pub fn run_tcp_proof(tun_fd: OwnedFd, config: TcpProofConfig) -> io::Result<()> {
    run_tcp_proof_with_ready(tun_fd, config, || Ok(()))
}

/// Runs the TCP forwarding proof and calls `ready` after the smoltcp listener is installed.
pub fn run_tcp_proof_with_ready<F>(
    tun_fd: OwnedFd,
    config: TcpProofConfig,
    ready: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    let mut audit = audit_buffer(config.audit_queue_capacity)?;
    set_nonblocking(tun_fd.as_raw_fd())?;
    let raw_fd = tun_fd.into_raw_fd();
    let mut device = TunTapInterface::from_fd(raw_fd, Medium::Ip, config.mtu).map_err(|error| {
        io::Error::other(format!("failed to create smoltcp TUN device: {error}"))
    })?;

    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = 0x0f0f_7078_u64;
    let mut iface = Interface::new(iface_config, &mut device, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(smoltcp_ipv4(config.broker_ip)),
            config.prefix_len,
        ));
    });
    iface.set_any_ip(true);
    iface
        .routes_mut()
        .add_default_ipv4_route(smoltcp_ipv4(config.broker_ip))
        .map_err(|error| io::Error::other(format!("failed to add smoltcp route: {error}")))?;

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65_535]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65_535]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);
    sockets
        .get_mut::<tcp::Socket>(tcp_handle)
        .listen(config.tcp_port)
        .map_err(|error| io::Error::other(format!("listen failed: {error}")))?;
    emit_tcp_lifecycle_audit(&mut audit, &config, AuditEventKind::SessionStarted)?;
    emit_tcp_lifecycle_audit(&mut audit, &config, AuditEventKind::BrokerStarted)?;
    emit_tcp_lifecycle_audit(&mut audit, &config, AuditEventKind::TunConfigured)?;
    eprintln!(
        "foxprox-net: listening for transparent TCP port {}",
        config.tcp_port
    );
    ready()?;

    let mut tcp_state = TransparentTcpState::new();

    loop {
        iface.poll(Instant::now(), &mut device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        tcp_state.poll(socket, &config, &mut audit, None)?;
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn audit_buffer(capacity: usize) -> io::Result<AuditBuffer> {
    if capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit queue capacity must be non-zero",
        ));
    }
    Ok(AuditBuffer::new(capacity))
}

fn emit_tcp_audit(
    audit: &mut AuditBuffer,
    event: &NetworkEvent,
    decision: Decision,
) -> io::Result<()> {
    let audit_event = transparent_tcp_audit_event(event, decision);
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(audit_event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: audit event={audit_event:?}");
    Ok(())
}

fn audit_backpressure_error(error: AuditBackpressure) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!("audit queue backpressure: {error:?}"),
    )
}

fn emit_tcp_lifecycle_audit(
    audit: &mut AuditBuffer,
    config: &TcpProofConfig,
    kind: AuditEventKind,
) -> io::Result<()> {
    let mut event = AuditEvent::new(Frontend::Tun, kind).with_sandbox_id(config.sandbox_id.clone());
    event.protocol = Some(Protocol::Tcp);
    event.destination = Some(TransportEndpoint::new(
        IpAddr::V4(config.broker_ip),
        config.tcp_port,
    ));
    event.detail = Some(format!(
        "tcp_port={} broker_ip={} mtu={} prefix_len={}",
        config.tcp_port, config.broker_ip, config.mtu, config.prefix_len
    ));
    emit_raw_audit(audit, event)
}

fn emit_tcp_unsupported_audit(
    audit: &mut AuditBuffer,
    sandbox_id: &SandboxId,
    detail: impl Into<String>,
) -> io::Result<()> {
    let event = NetworkEvent::Unsupported {
        sandbox_id: Some(sandbox_id.clone()),
        frontend: Frontend::Tun,
        reason: UnsupportedReason::Malformed(detail.into()),
    };
    let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
    emit_tcp_audit(audit, &event, decision)
}

fn emit_tcp_flow_closed_audit(
    audit: &mut AuditBuffer,
    sandbox_id: &SandboxId,
    active: &ActiveFlow,
) -> io::Result<()> {
    let mut event = AuditEvent::new(Frontend::Tun, AuditEventKind::TcpFlowClosed)
        .with_sandbox_id(sandbox_id.clone())
        .with_endpoints(
            Some(active.source),
            Some(TransportEndpoint::from(active.destination)),
        );
    event.protocol = Some(Protocol::Tcp);
    event.bytes_from_sandbox = active.bytes_to_host;
    event.bytes_to_sandbox = active.bytes_to_sandbox;
    event.flow_duration = Some(active.started_at.elapsed());
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: audit event={event:?}");
    Ok(())
}

#[cfg(not(test))]
fn drain_audit_to_stderr(audit: &mut AuditBuffer) -> io::Result<()> {
    let mut stderr = io::stderr();
    foxprox_core::drain_audit_buffer_to_json_lines(audit, &mut stderr)
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("audit sink write failed: {error}")))
}

#[cfg(test)]
fn drain_audit_to_stderr(_audit: &mut AuditBuffer) -> io::Result<()> {
    Ok(())
}

fn egress_context(
    sandbox_id: &SandboxId,
    event: &NetworkEvent,
    decision: Decision,
) -> EgressContext {
    EgressContext {
        sandbox_id: sandbox_id.clone(),
        frontend: Frontend::Tun,
        decision,
        attribution: egress_attribution(event),
    }
}

fn egress_attribution(event: &NetworkEvent) -> Attribution {
    match event {
        NetworkEvent::TcpConnectAttempt { attribution, .. } => attribution.clone(),
        NetworkEvent::HttpRequest { origin, .. } => Attribution {
            hostname: Some(origin.host.clone()),
            source: AttributionSource::HttpHostHeader,
            confidence: AttributionConfidence::High,
        },
        NetworkEvent::TlsClientHello {
            sni, dns_hostname, ..
        } => {
            if let Some(sni) = sni.clone() {
                Attribution {
                    hostname: Some(sni),
                    source: AttributionSource::TlsSni,
                    confidence: AttributionConfidence::High,
                }
            } else if let Some(dns_hostname) = dns_hostname.clone() {
                Attribution {
                    hostname: Some(dns_hostname),
                    source: AttributionSource::DnsCache,
                    confidence: AttributionConfidence::Medium,
                }
            } else {
                Attribution::ip_only()
            }
        }
        _ => Attribution::ip_only(),
    }
}

pub(crate) fn emit_raw_audit(audit: &mut AuditBuffer, audit_event: AuditEvent) -> io::Result<()> {
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(audit_event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: audit event={audit_event:?}");
    Ok(())
}

fn transparent_tcp_audit_kind(event: &NetworkEvent, decision: &Decision) -> AuditEventKind {
    if matches!(decision.reason, Some(DenialReason::SniDnsMismatch)) {
        return AuditEventKind::SniDnsMismatchDenied;
    }
    if matches!(decision.reason, Some(DenialReason::HiddenSni)) {
        return AuditEventKind::HiddenSniDenied;
    }
    match event {
        NetworkEvent::TcpConnectAttempt { .. } => AuditEventKind::TcpConnect,
        NetworkEvent::HttpRequest { .. } => AuditEventKind::TransparentHttpRequest,
        NetworkEvent::TlsClientHello { .. } => AuditEventKind::TlsClientHello,
        _ => AuditEventKind::UnsupportedDenied,
    }
}

fn transparent_tcp_audit_event(event: &NetworkEvent, decision: Decision) -> AuditEvent {
    let kind = transparent_tcp_audit_kind(event, &decision);
    let mut audit = AuditEvent::new(Frontend::Tun, kind).with_decision(decision);
    if let Some(sandbox_id) = event.sandbox_id() {
        audit = audit.with_sandbox_id(sandbox_id.clone());
    }
    audit.protocol = Some(event.protocol());
    match event {
        NetworkEvent::TcpConnectAttempt {
            source,
            destination,
            attribution,
            ..
        } => {
            audit = audit.with_endpoints(*source, Some(*destination));
            audit.attribution = Some(attribution.clone());
            audit.hostname = attribution.hostname.clone();
        }
        NetworkEvent::HttpRequest {
            origin,
            method,
            path_and_query,
            ..
        } => {
            audit.hostname = Some(origin.host.clone());
            audit.destination_port = Some(origin.port);
            audit.attribution = Some(Attribution {
                hostname: Some(origin.host.clone()),
                source: AttributionSource::HttpHostHeader,
                confidence: AttributionConfidence::High,
            });
            audit.origin = Some(origin.clone());
            audit.http_method = Some(method.clone());
            audit.path_and_query = Some(path_and_query.clone());
        }
        NetworkEvent::TlsClientHello {
            destination,
            sni,
            dns_hostname,
            ..
        } => {
            audit = audit.with_endpoints(None, Some(*destination));
            if let Some(sni) = sni.clone() {
                audit.hostname = Some(sni.clone());
                audit.attribution = Some(Attribution {
                    hostname: Some(sni),
                    source: AttributionSource::TlsSni,
                    confidence: AttributionConfidence::High,
                });
            } else if let Some(dns_hostname) = dns_hostname.clone() {
                audit.hostname = Some(dns_hostname.clone());
                audit.attribution = Some(Attribution {
                    hostname: Some(dns_hostname),
                    source: AttributionSource::DnsCache,
                    confidence: AttributionConfidence::Medium,
                });
            } else {
                audit.attribution = Some(Attribution::ip_only());
            }
        }
        NetworkEvent::Unsupported { reason, .. } => {
            audit.detail = Some(format!("{reason:?}"));
        }
        _ => {}
    }
    audit
}

pub(crate) struct TransparentTcpState {
    flow: Option<FlowState>,
}

impl TransparentTcpState {
    pub(crate) const fn new() -> Self {
        Self { flow: None }
    }

    pub(crate) fn poll(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        config: &TcpProofConfig,
        audit: &mut AuditBuffer,
        dns_cache: Option<&DnsCache>,
    ) -> io::Result<()> {
        if self.flow.is_none() && !socket.is_open() {
            socket
                .listen(config.tcp_port)
                .map_err(|error| io::Error::other(format!("listen failed: {error}")))?;
            eprintln!(
                "foxprox-net: listening for transparent TCP port {}",
                config.tcp_port
            );
        }

        if self.flow.is_none() && socket.is_active() {
            if let (Some(local), Some(remote)) = (socket.local_endpoint(), socket.remote_endpoint())
            {
                let destination = endpoint_to_socket_addr(local)?;
                let source = endpoint_to_transport(remote)?;
                eprintln!(
                    "foxprox-net: tcp connect sandbox={}:{} destination={}",
                    source.ip, source.port, destination
                );
                let event = NetworkEvent::TcpConnectAttempt {
                    sandbox_id: config.sandbox_id.clone(),
                    frontend: Frontend::Tun,
                    source: Some(source),
                    destination: TransportEndpoint::from(destination),
                    attribution: tcp_attribution_for_destination(
                        &config.sandbox_id,
                        dns_cache,
                        destination.ip(),
                        SystemTime::now(),
                    ),
                };
                let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
                eprintln!("foxprox-net: tcp policy decision={decision:?} event={event:?}");
                if let Err(error) = emit_tcp_audit(audit, &event, decision.clone()) {
                    eprintln!("foxprox-net: tcp audit backpressure: {error}");
                    socket.abort();
                } else if decision.is_allowed() {
                    self.flow = Some(
                        if let Some(override_destination) = config.tcp_egress_override {
                            FlowState::Connecting(ConnectingFlow::new_with_egress(
                                source,
                                destination,
                                override_destination,
                                egress_context(&config.sandbox_id, &event, decision.clone()),
                                config.connect_timeout,
                                Vec::new(),
                            ))
                        } else if should_inspect_http(destination.port()) {
                            FlowState::InspectingHttp(InspectingHttpFlow::new(source, destination))
                        } else if should_inspect_tls(destination.port()) {
                            FlowState::InspectingTls(InspectingTlsFlow::new(source, destination))
                        } else {
                            FlowState::Connecting(ConnectingFlow::new(
                                source,
                                destination,
                                egress_context(&config.sandbox_id, &event, decision.clone()),
                                config.connect_timeout,
                            ))
                        },
                    );
                } else {
                    socket.abort();
                }
            }
        }

        let mut clear_flow = false;
        if let Some(state) = self.flow.as_mut() {
            match state {
                FlowState::InspectingHttp(inspecting) => {
                    match inspecting.pump(
                        socket,
                        &config.sandbox_id,
                        &config.policy,
                        audit,
                        config.pending_buffer_limit,
                        config.connect_timeout,
                    ) {
                        Ok(Some(connecting)) => *state = FlowState::Connecting(connecting),
                        Ok(None) => {
                            if inspecting.is_expired(config.connect_timeout) || !socket.is_active()
                            {
                                eprintln!(
                                    "foxprox-net: HTTP inspection timed out or socket closed"
                                );
                                socket.abort();
                                clear_flow = true;
                            }
                        }
                        Err(error) => {
                            eprintln!("foxprox-net: HTTP inspection denied/failed: {error}");
                            socket.abort();
                            clear_flow = true;
                        }
                    }
                }
                FlowState::InspectingTls(inspecting) => {
                    match inspecting.pump(socket, config, dns_cache, audit) {
                        Ok(Some(connecting)) => *state = FlowState::Connecting(connecting),
                        Ok(None) => {
                            if inspecting.is_expired(config.connect_timeout) || !socket.is_active()
                            {
                                eprintln!("foxprox-net: TLS inspection timed out or socket closed");
                                socket.abort();
                                clear_flow = true;
                            }
                        }
                        Err(error) => {
                            eprintln!("foxprox-net: TLS inspection denied/failed: {error}");
                            socket.abort();
                            clear_flow = true;
                        }
                    }
                }
                FlowState::Connecting(connecting) => {
                    let mut connected = None;
                    if let Err(error) = connecting.pump(socket, config.pending_buffer_limit) {
                        eprintln!("foxprox-net: connecting flow error: {error}");
                        socket.abort();
                        clear_flow = true;
                    } else {
                        match connecting.try_finish() {
                            Ok(Some(active)) => connected = Some(active),
                            Ok(None) => {}
                            Err(error) => {
                                eprintln!("foxprox-net: host connect failed: {error}");
                                socket.abort();
                                clear_flow = true;
                            }
                        }
                    }
                    if !clear_flow
                        && connected.is_none()
                        && (!socket.is_active() || connecting.is_expired(config.connect_timeout))
                    {
                        eprintln!("foxprox-net: connect timed out or sandbox socket closed");
                        socket.abort();
                        clear_flow = true;
                    }
                    if let Some(active) = connected {
                        *state = FlowState::Active(active);
                    }
                }
                FlowState::Active(active) => {
                    if let Err(error) = active.pump(socket, config.pending_buffer_limit) {
                        eprintln!("foxprox-net: tcp flow error: {error}");
                        socket.abort();
                        clear_flow = true;
                    } else if active.is_idle(config.idle_timeout) {
                        eprintln!("foxprox-net: tcp flow idle timeout");
                        socket.abort();
                        clear_flow = true;
                    } else if !socket.is_active()
                        && active.pending_to_host.is_empty()
                        && active.pending_to_sandbox.is_empty()
                    {
                        emit_tcp_flow_closed_audit(audit, &config.sandbox_id, active)?;
                        eprintln!(
                            "foxprox-net: tcp flow closed sandbox_to_host={} host_to_sandbox={}",
                            active.bytes_to_host, active.bytes_to_sandbox
                        );
                        clear_flow = true;
                    }
                }
            }
        }
        if clear_flow {
            self.flow = None;
        }
        Ok(())
    }
}

enum FlowState {
    InspectingHttp(InspectingHttpFlow),
    InspectingTls(InspectingTlsFlow),
    Connecting(ConnectingFlow),
    Active(ActiveFlow),
}

struct InspectingHttpFlow {
    source: TransportEndpoint,
    destination: SocketAddr,
    pending_to_host: Vec<u8>,
    started_at: StdInstant,
    last_activity: StdInstant,
}

impl InspectingHttpFlow {
    fn new(source: TransportEndpoint, destination: SocketAddr) -> Self {
        let now = StdInstant::now();
        Self {
            source,
            destination,
            pending_to_host: Vec::new(),
            started_at: now,
            last_activity: now,
        }
    }

    fn pump(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        sandbox_id: &SandboxId,
        policy: &PolicyRuleSet,
        audit: &mut AuditBuffer,
        pending_limit: usize,
        connect_timeout: Duration,
    ) -> io::Result<Option<ConnectingFlow>> {
        recv_socket_to_vec(
            socket,
            &mut self.pending_to_host,
            pending_limit,
            &mut self.last_activity,
        )?;
        let inspection = match parse_http_request_head(
            &self.pending_to_host,
            self.destination.port(),
        ) {
            Ok(inspection) => inspection,
            Err(foxprox_core::InspectionError::Truncated) => return Ok(None),
            Err(error) => {
                emit_tcp_unsupported_audit(
                        audit,
                        sandbox_id,
                        format!(
                            "malformed or unsupported HTTP request head source={}:{} destination={} error={error:?}",
                            self.source.ip, self.source.port, self.destination
                        ),
                    )?;
                return Err(io::Error::other(format!(
                    "malformed or unsupported HTTP request head: {error:?}"
                )));
            }
        };
        let event = NetworkEvent::HttpRequest {
            sandbox_id: sandbox_id.clone(),
            frontend: Frontend::Tun,
            method: inspection.method,
            origin: inspection.origin,
            path_and_query: inspection.path_and_query,
        };
        let decision = PolicyEngine::new(policy.clone()).evaluate(&event);
        eprintln!("foxprox-net: transparent HTTP policy decision={decision:?} event={event:?}");
        emit_tcp_audit(audit, &event, decision.clone())?;
        if !decision.is_allowed() {
            return Err(io::Error::other("transparent HTTP policy denied request"));
        }
        Ok(Some(ConnectingFlow::new_with_pending(
            self.source,
            self.destination,
            egress_context(sandbox_id, &event, decision),
            connect_timeout,
            std::mem::take(&mut self.pending_to_host),
        )))
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }
}

struct InspectingTlsFlow {
    source: TransportEndpoint,
    destination: SocketAddr,
    pending_to_host: Vec<u8>,
    started_at: StdInstant,
    last_activity: StdInstant,
}

impl InspectingTlsFlow {
    fn new(source: TransportEndpoint, destination: SocketAddr) -> Self {
        let now = StdInstant::now();
        Self {
            source,
            destination,
            pending_to_host: Vec::new(),
            started_at: now,
            last_activity: now,
        }
    }

    fn pump(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        config: &TcpProofConfig,
        dns_cache: Option<&DnsCache>,
        audit: &mut AuditBuffer,
    ) -> io::Result<Option<ConnectingFlow>> {
        recv_socket_to_vec(
            socket,
            &mut self.pending_to_host,
            config.pending_buffer_limit,
            &mut self.last_activity,
        )?;
        let inspection = match parse_tls_client_hello(&self.pending_to_host) {
            Ok(inspection) => inspection,
            Err(foxprox_core::InspectionError::Truncated) => return Ok(None),
            Err(error) => {
                emit_tcp_unsupported_audit(
                    audit,
                    &config.sandbox_id,
                    format!(
                        "malformed or unsupported TLS ClientHello source={}:{} destination={} error={error:?}",
                        self.source.ip, self.source.port, self.destination
                    ),
                )?;
                return Err(io::Error::other(format!(
                    "malformed or unsupported TLS ClientHello: {error:?}"
                )));
            }
        };
        let dns_hostname = dns_cache.and_then(|cache| {
            cache
                .lookup_address(&config.sandbox_id, self.destination.ip(), SystemTime::now())
                .map(|entry| entry.hostname.clone())
        });
        let mismatch = inspection
            .sni
            .as_ref()
            .zip(dns_hostname.as_ref())
            .is_some_and(|(sni, dns_hostname)| sni != dns_hostname);
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: config.sandbox_id.clone(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::from(self.destination),
            sni: inspection.sni,
            ech_present: inspection.ech_present,
            dns_hostname,
            mismatch,
        };
        let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
        eprintln!("foxprox-net: transparent TLS policy decision={decision:?} event={event:?}");
        emit_tcp_audit(audit, &event, decision.clone())?;
        if !decision.is_allowed() {
            return Err(io::Error::other(
                "transparent TLS policy denied ClientHello",
            ));
        }
        Ok(Some(ConnectingFlow::new_with_pending(
            self.source,
            self.destination,
            egress_context(&config.sandbox_id, &event, decision),
            config.connect_timeout,
            std::mem::take(&mut self.pending_to_host),
        )))
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }
}

struct ConnectingFlow {
    source: TransportEndpoint,
    requested_destination: SocketAddr,
    host_destination: SocketAddr,
    receiver: Receiver<io::Result<TcpStream>>,
    pending_to_host: Vec<u8>,
    started_at: StdInstant,
    last_activity: StdInstant,
}

impl ConnectingFlow {
    fn new(
        source: TransportEndpoint,
        destination: SocketAddr,
        context: EgressContext,
        timeout: Duration,
    ) -> Self {
        Self::new_with_pending(source, destination, context, timeout, Vec::new())
    }

    fn new_with_pending(
        source: TransportEndpoint,
        destination: SocketAddr,
        context: EgressContext,
        timeout: Duration,
        pending_to_host: Vec<u8>,
    ) -> Self {
        Self::new_with_egress(
            source,
            destination,
            destination,
            context,
            timeout,
            pending_to_host,
        )
    }

    fn new_with_egress(
        source: TransportEndpoint,
        requested_destination: SocketAddr,
        host_destination: SocketAddr,
        context: EgressContext,
        timeout: Duration,
        pending_to_host: Vec<u8>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let request = TcpEgressRequest {
                context,
                source: Some(source),
                destination: TransportEndpoint::from(host_destination),
                connect_timeout: Some(timeout),
            };
            let result = StdHostEgress::new()
                .connect_tcp_nonblocking(request)
                .map_err(egress_error_to_io);
            let _ = sender.send(result);
        });
        let now = StdInstant::now();
        Self {
            source,
            requested_destination,
            host_destination,
            receiver,
            pending_to_host,
            started_at: now,
            last_activity: now,
        }
    }

    fn pump(&mut self, socket: &mut tcp::Socket<'_>, pending_limit: usize) -> io::Result<()> {
        recv_socket_to_vec(
            socket,
            &mut self.pending_to_host,
            pending_limit,
            &mut self.last_activity,
        )
    }

    fn try_finish(&mut self) -> io::Result<Option<ActiveFlow>> {
        match self.receiver.try_recv() {
            Ok(Ok(stream)) => {
                eprintln!(
                    "foxprox-net: host connected sandbox={}:{} destination={} host_destination={}",
                    self.source.ip,
                    self.source.port,
                    self.requested_destination,
                    self.host_destination
                );
                Ok(Some(ActiveFlow::new(
                    self.source,
                    self.requested_destination,
                    stream,
                    std::mem::take(&mut self.pending_to_host),
                )))
            }
            Ok(Err(error)) => Err(error),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(io::Error::other("host connector worker ended")),
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout + Duration::from_secs(1)
    }
}

struct ActiveFlow {
    source: TransportEndpoint,
    destination: SocketAddr,
    host: TcpStream,
    pending_to_host: Vec<u8>,
    pending_to_sandbox: Vec<u8>,
    host_eof: bool,
    host_write_shutdown: bool,
    bytes_to_host: u64,
    bytes_to_sandbox: u64,
    started_at: StdInstant,
    last_activity: StdInstant,
}

impl ActiveFlow {
    fn new(
        source: TransportEndpoint,
        destination: SocketAddr,
        host: TcpStream,
        pending_to_host: Vec<u8>,
    ) -> Self {
        let now = StdInstant::now();
        Self {
            source,
            destination,
            host,
            pending_to_host,
            pending_to_sandbox: Vec::new(),
            host_eof: false,
            host_write_shutdown: false,
            bytes_to_host: 0,
            bytes_to_sandbox: 0,
            started_at: now,
            last_activity: now,
        }
    }

    fn pump(&mut self, socket: &mut tcp::Socket<'_>, pending_limit: usize) -> io::Result<()> {
        self.flush_to_host()?;
        self.recv_from_sandbox(socket, pending_limit)?;
        if !socket.may_recv() && self.pending_to_host.is_empty() && !self.host_write_shutdown {
            self.host.shutdown(Shutdown::Write)?;
            self.host_write_shutdown = true;
        }
        self.read_from_host(pending_limit)?;
        self.flush_to_sandbox(socket)?;
        if self.host_eof && self.pending_to_sandbox.is_empty() {
            socket.close();
        }
        Ok(())
    }

    fn recv_from_sandbox(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        pending_limit: usize,
    ) -> io::Result<()> {
        recv_socket_to_vec(
            socket,
            &mut self.pending_to_host,
            pending_limit,
            &mut self.last_activity,
        )?;
        self.flush_to_host()
    }

    fn flush_to_host(&mut self) -> io::Result<()> {
        while !self.pending_to_host.is_empty() {
            match self.host.write(&self.pending_to_host) {
                Ok(0) => break,
                Ok(written) => {
                    self.pending_to_host.drain(..written);
                    self.bytes_to_host += written as u64;
                    self.last_activity = StdInstant::now();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read_from_host(&mut self, pending_limit: usize) -> io::Result<()> {
        let mut buffer = [0_u8; 8192];
        while self.pending_to_sandbox.len() < pending_limit {
            match self.host.read(&mut buffer) {
                Ok(0) => {
                    self.host_eof = true;
                    break;
                }
                Ok(read_len) => {
                    self.pending_to_sandbox
                        .extend_from_slice(&buffer[..read_len]);
                    self.last_activity = StdInstant::now();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn flush_to_sandbox(&mut self, socket: &mut tcp::Socket<'_>) -> io::Result<()> {
        while !self.pending_to_sandbox.is_empty() && socket.can_send() {
            let written = socket
                .send_slice(&self.pending_to_sandbox)
                .map_err(|error| io::Error::other(format!("smoltcp send failed: {error}")))?;
            if written == 0 {
                break;
            }
            self.pending_to_sandbox.drain(..written);
            self.bytes_to_sandbox += written as u64;
            self.last_activity = StdInstant::now();
        }
        Ok(())
    }

    fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_activity.elapsed() > idle_timeout
    }
}

fn recv_socket_to_vec(
    socket: &mut tcp::Socket<'_>,
    pending: &mut Vec<u8>,
    pending_limit: usize,
    last_activity: &mut StdInstant,
) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    while socket.can_recv() && pending.len() < pending_limit {
        let read_len = socket
            .recv_slice(&mut buffer)
            .map_err(|error| io::Error::other(format!("smoltcp recv failed: {error}")))?;
        if read_len == 0 {
            break;
        }
        let remaining = pending_limit.saturating_sub(pending.len());
        let copy_len = read_len.min(remaining);
        pending.extend_from_slice(&buffer[..copy_len]);
        *last_activity = StdInstant::now();
        if copy_len < read_len {
            return Err(io::Error::other("pending buffer limit exceeded"));
        }
    }
    Ok(())
}

fn tcp_attribution_for_destination(
    sandbox_id: &SandboxId,
    dns_cache: Option<&DnsCache>,
    destination_ip: IpAddr,
    now: SystemTime,
) -> Attribution {
    dns_cache
        .and_then(|cache| cache.lookup_address(sandbox_id, destination_ip, now))
        .map(|entry| entry.attribution())
        .unwrap_or_else(Attribution::ip_only)
}

fn should_inspect_http(port: u16) -> bool {
    port == 80
}

fn should_inspect_tls(port: u16) -> bool {
    port == 443
}

fn endpoint_to_socket_addr(endpoint: smoltcp::wire::IpEndpoint) -> io::Result<SocketAddr> {
    Ok(SocketAddr::new(ip_to_std(endpoint.addr)?, endpoint.port))
}

fn endpoint_to_transport(endpoint: smoltcp::wire::IpEndpoint) -> io::Result<TransportEndpoint> {
    Ok(TransportEndpoint::new(
        ip_to_std(endpoint.addr)?,
        endpoint.port,
    ))
}

fn ip_to_std(ip: IpAddress) -> io::Result<IpAddr> {
    match ip {
        IpAddress::Ipv4(ip) => Ok(IpAddr::V4(Ipv4Addr::from(ip.octets()))),
    }
}

fn smoltcp_ipv4(ip: Ipv4Addr) -> Ipv4Address {
    let [a, b, c, d] = ip.octets();
    Ipv4Address::new(a, b, c, d)
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        DecisionAction, DnsCacheEntry, DnsObservation, DnsQueryType, Hostname, HttpMethod, Origin,
        Protocol,
    };
    use std::net::TcpListener;

    #[test]
    fn default_config_is_bounded() {
        let config = TcpProofConfig::new(SandboxId::new("test").unwrap());
        assert_eq!(config.tcp_port, 80);
        assert!(config.connect_timeout <= Duration::from_secs(5));
        assert!(config.idle_timeout <= Duration::from_secs(30));
        assert_eq!(config.pending_buffer_limit, 256 * 1024);
        assert!(config.audit_queue_capacity > 0);
        assert!(config.tcp_egress_override.is_none());
    }

    #[test]
    fn tcp_egress_override_uses_raw_connecting_flow() {
        let mut config = TcpProofConfig::new(SandboxId::new("test").unwrap());
        config.tcp_egress_override = Some(SocketAddr::from(([127, 0, 0, 1], 18080)));
        assert_eq!(config.tcp_egress_override.unwrap().port(), 18080);
    }

    #[test]
    fn transparent_http_inspection_is_limited_to_default_http_port() {
        assert!(should_inspect_http(80));
        assert!(!should_inspect_http(443));
    }

    #[test]
    fn transparent_tls_inspection_is_limited_to_default_https_port() {
        assert!(should_inspect_tls(443));
        assert!(!should_inspect_tls(80));
    }

    #[test]
    fn default_tcp_policy_denies_host_connect_events() {
        let config = TcpProofConfig::new(SandboxId::new("test").unwrap());
        let event = NetworkEvent::TcpConnectAttempt {
            sandbox_id: config.sandbox_id.clone(),
            frontend: Frontend::Tun,
            source: Some(TransportEndpoint::new(
                IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
                44_444,
            )),
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            attribution: Attribution::ip_only(),
        };
        assert!(!PolicyEngine::new(config.policy)
            .evaluate(&event)
            .is_allowed());
    }

    #[test]
    fn tcp_attribution_uses_dns_cache_when_available() {
        let sandbox_id = SandboxId::new("test").unwrap();
        let now = SystemTime::now();
        let entry = DnsCacheEntry::new(
            DnsObservation {
                sandbox_id: sandbox_id.clone(),
                hostname: Hostname::parse("www.example.com").unwrap(),
                query_type: DnsQueryType::A,
                observed_at: now,
                broker_controlled: true,
            },
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            Duration::from_secs(60),
        )
        .unwrap();
        let mut cache = DnsCache::default();
        cache.insert(entry);

        let attribution = tcp_attribution_for_destination(
            &sandbox_id,
            Some(&cache),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            now,
        );

        assert_eq!(attribution.hostname.unwrap().as_str(), "www.example.com");
        assert_eq!(attribution.source, AttributionSource::DnsCache);
        assert_eq!(attribution.confidence, AttributionConfidence::Medium);
    }

    #[test]
    fn tcp_attribution_falls_back_to_ip_only_without_dns_cache() {
        let attribution = tcp_attribution_for_destination(
            &SandboxId::new("test").unwrap(),
            None,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            SystemTime::now(),
        );

        assert!(attribution.hostname.is_none());
        assert_eq!(attribution.source, AttributionSource::IpOnly);
        assert_eq!(attribution.confidence, AttributionConfidence::Low);
    }

    #[test]
    fn tls_audit_event_records_dns_hostname_and_mismatch_metadata() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            sni: Some(Hostname::parse("visible.example.com").unwrap()),
            ech_present: false,
            dns_hostname: Some(Hostname::parse("dns.example.com").unwrap()),
            mismatch: true,
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::SniDnsMismatchDenied);
        assert_eq!(audit.hostname.unwrap().as_str(), "visible.example.com");
        assert_eq!(audit.attribution.unwrap().source, AttributionSource::TlsSni);
        assert_eq!(
            audit.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::FailClosed)
        );
    }

    #[test]
    fn transparent_tcp_audit_event_records_endpoints_and_decision() {
        let event = NetworkEvent::TcpConnectAttempt {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            source: Some(TransportEndpoint::new(
                IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
                44_444,
            )),
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            attribution: Attribution::ip_only(),
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::TcpConnect);
        assert_eq!(audit.protocol, Some(Protocol::Tcp));
        assert_eq!(audit.source.unwrap().port, 44_444);
        assert_eq!(audit.destination.unwrap().port, 80);
        assert_eq!(audit.destination_port, Some(80));
        assert!(audit.decision.is_some());
    }

    #[test]
    fn transparent_http_audit_event_records_origin_metadata() {
        let event = NetworkEvent::HttpRequest {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            method: HttpMethod::parse("GET").unwrap(),
            origin: Origin {
                scheme: "http".to_string(),
                host: Hostname::parse("example.com").unwrap(),
                port: 80,
            },
            path_and_query: "/proof?q=1".to_string(),
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::TransparentHttpRequest);
        assert_eq!(audit.protocol, Some(Protocol::Http));
        assert_eq!(audit.hostname.unwrap().as_str(), "example.com");
        assert_eq!(audit.destination_port, Some(80));
        assert_eq!(audit.path_and_query.as_deref(), Some("/proof?q=1"));
        assert_eq!(
            audit.attribution.unwrap().source,
            AttributionSource::HttpHostHeader
        );
    }

    #[test]
    fn transparent_tls_audit_event_records_sni_and_endpoint() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            sni: Some(Hostname::parse("example.com").unwrap()),
            ech_present: false,
            dns_hostname: None,
            mismatch: false,
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::TlsClientHello);
        assert_eq!(audit.protocol, Some(Protocol::Tls));
        assert_eq!(audit.hostname.unwrap().as_str(), "example.com");
        assert_eq!(audit.destination.unwrap().port, 443);
        assert_eq!(audit.destination_port, Some(443));
        assert_eq!(audit.attribution.unwrap().source, AttributionSource::TlsSni);
    }

    #[test]
    fn transparent_tls_mismatch_audit_uses_specific_denial_kind() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            sni: Some(Hostname::parse("wrong.example").unwrap()),
            ech_present: false,
            dns_hostname: Some(Hostname::parse("example.com").unwrap()),
            mismatch: true,
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::SniDnsMismatchDenied);
    }

    #[test]
    fn transparent_tls_hidden_sni_audit_uses_specific_denial_kind() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            sni: None,
            ech_present: true,
            dns_hostname: Some(Hostname::parse("example.com").unwrap()),
            mismatch: false,
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::HiddenSniDenied);
    }

    #[test]
    fn transparent_tls_audit_uses_dns_cache_source_when_sni_is_absent() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            sni: None,
            ech_present: true,
            dns_hostname: Some(Hostname::parse("dns.example.com").unwrap()),
            mismatch: false,
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);
        let attribution = audit.attribution.unwrap();

        assert_eq!(audit.hostname.unwrap().as_str(), "dns.example.com");
        assert_eq!(attribution.source, AttributionSource::DnsCache);
        assert_eq!(attribution.confidence, AttributionConfidence::Medium);
    }

    fn empty_tcp_socket() -> tcp::Socket<'static> {
        let rx = tcp::SocketBuffer::new(vec![0; 1024]);
        let tx = tcp::SocketBuffer::new(vec![0; 1024]);
        tcp::Socket::new(rx, tx)
    }

    #[test]
    fn transparent_tcp_audit_event_records_unsupported_metadata() {
        let event = NetworkEvent::Unsupported {
            sandbox_id: Some(SandboxId::new("test").unwrap()),
            frontend: Frontend::Tun,
            reason: UnsupportedReason::Malformed("bad transparent data".to_string()),
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = transparent_tcp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::UnsupportedDenied);
        assert_eq!(audit.protocol, Some(Protocol::Unsupported));
        assert_eq!(audit.frontend, Frontend::Tun);
        assert_eq!(
            audit.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::FailClosed)
        );
        assert!(audit
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("bad transparent data")));
    }

    #[test]
    fn malformed_transparent_http_head_emits_unsupported_audit() {
        let sandbox_id = SandboxId::new("test").unwrap();
        let policy = PolicyRuleSet::default();
        let mut audit = audit_buffer(8).unwrap();
        let mut socket = empty_tcp_socket();
        let mut flow = InspectingHttpFlow::new(
            TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_444),
            SocketAddr::from(([93, 184, 216, 34], 80)),
        );
        flow.pending_to_host
            .extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");

        let error = match flow.pump(
            &mut socket,
            &sandbox_id,
            &policy,
            &mut audit,
            4096,
            Duration::from_secs(1),
        ) {
            Ok(_) => panic!("malformed transparent HTTP unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        let event = audit.pop_front().unwrap();
        assert_eq!(event.kind, AuditEventKind::UnsupportedDenied);
        assert_eq!(event.protocol, Some(Protocol::Unsupported));
        assert_eq!(
            event.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::FailClosed)
        );
        assert!(event
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("HTTP request head")));
    }

    #[test]
    fn malformed_transparent_tls_hello_emits_unsupported_audit() {
        let config = TcpProofConfig::new(SandboxId::new("test").unwrap());
        let mut audit = audit_buffer(8).unwrap();
        let mut socket = empty_tcp_socket();
        let mut flow = InspectingTlsFlow::new(
            TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_445),
            SocketAddr::from(([93, 184, 216, 34], 443)),
        );
        flow.pending_to_host
            .extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x04, 0, 0, 0, 0]);

        let error = match flow.pump(&mut socket, &config, None, &mut audit) {
            Ok(_) => panic!("malformed transparent TLS unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        let event = audit.pop_front().unwrap();
        assert_eq!(event.kind, AuditEventKind::UnsupportedDenied);
        assert_eq!(event.protocol, Some(Protocol::Unsupported));
        assert_eq!(
            event.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::FailClosed)
        );
        assert!(event
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("TLS ClientHello")));
    }

    #[test]
    fn malformed_transparent_http_backpressure_fails_closed() {
        let sandbox_id = SandboxId::new("test").unwrap();
        let policy = PolicyRuleSet::default();
        let mut audit = audit_buffer(1).unwrap();
        let filled = NetworkEvent::TcpConnectAttempt {
            sandbox_id: sandbox_id.clone(),
            frontend: Frontend::Tun,
            source: None,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            attribution: Attribution::ip_only(),
        };
        let decision = PolicyEngine::new(policy.clone()).evaluate(&filled);
        emit_tcp_audit(&mut audit, &filled, decision).unwrap();
        let mut socket = empty_tcp_socket();
        let mut flow = InspectingHttpFlow::new(
            TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_444),
            SocketAddr::from(([93, 184, 216, 34], 80)),
        );
        flow.pending_to_host
            .extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");

        let error = match flow.pump(
            &mut socket,
            &sandbox_id,
            &policy,
            &mut audit,
            4096,
            Duration::from_secs(1),
        ) {
            Ok(_) => panic!("malformed transparent HTTP unexpectedly bypassed audit backpressure"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn tcp_flow_closed_audit_records_bytes_duration_and_endpoints() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(server);
        let active = ActiveFlow {
            source: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_444),
            destination: SocketAddr::from(([93, 184, 216, 34], 80)),
            host: client,
            pending_to_host: Vec::new(),
            pending_to_sandbox: Vec::new(),
            host_eof: true,
            host_write_shutdown: true,
            bytes_to_host: 123,
            bytes_to_sandbox: 456,
            started_at: StdInstant::now() - Duration::from_millis(5),
            last_activity: StdInstant::now(),
        };
        let mut audit = audit_buffer(8).unwrap();

        emit_tcp_flow_closed_audit(&mut audit, &SandboxId::new("test").unwrap(), &active).unwrap();
        let event = audit.pop_front().unwrap();

        assert_eq!(event.kind, AuditEventKind::TcpFlowClosed);
        assert_eq!(event.protocol, Some(Protocol::Tcp));
        assert_eq!(event.source.unwrap().port, 44_444);
        assert_eq!(event.destination.unwrap().port, 80);
        assert_eq!(event.bytes_from_sandbox, 123);
        assert_eq!(event.bytes_to_sandbox, 456);
        assert!(event.flow_duration.is_some());
    }

    #[test]
    fn transparent_tcp_audit_enqueue_reports_backpressure() {
        let event = NetworkEvent::TcpConnectAttempt {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            source: None,
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            attribution: Attribution::ip_only(),
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let mut audit = audit_buffer(1).unwrap();

        emit_tcp_audit(&mut audit, &event, decision.clone()).unwrap();
        let error = emit_tcp_audit(&mut audit, &event, decision).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn transparent_tcp_audit_rejects_zero_capacity() {
        assert_eq!(
            audit_buffer(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
