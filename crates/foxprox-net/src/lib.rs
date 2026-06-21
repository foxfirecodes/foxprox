//! smoltcp-backed transparent TCP forwarding proof.
//!
//! This crate is intentionally a narrow Milestone 2 adapter: it consumes a TUN
//! file descriptor, feeds a smoltcp IPv4 stack, accepts one configured TCP
//! destination port, opens host TCP sockets, and bridges bytes in both
//! directions. Policy is temporarily allow-all for accepted TCP connects.

#![deny(missing_docs)]

mod udp;

pub use udp::{run_udp_dns_proof, run_udp_dns_proof_with_ready, UdpDnsProofConfig};

use foxprox_core::{
    parse_http_request_head, parse_tls_client_hello, Attribution, Frontend, NetworkEvent,
    PolicyEngine, PolicyRuleSet, SandboxId, TransportEndpoint,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Medium, TunTapInterface};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant as StdInstant};

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
    eprintln!(
        "foxprox-net: listening for transparent TCP port {}",
        config.tcp_port
    );
    ready()?;

    let mut flow: Option<FlowState> = None;

    loop {
        let now = Instant::now();
        iface.poll(now, &mut device, &mut sockets);

        {
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            if flow.is_none() && !socket.is_open() {
                socket
                    .listen(config.tcp_port)
                    .map_err(|error| io::Error::other(format!("listen failed: {error}")))?;
                eprintln!(
                    "foxprox-net: listening for transparent TCP port {}",
                    config.tcp_port
                );
            }
        }

        if flow.is_none() {
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            if socket.is_active() {
                if let (Some(local), Some(remote)) =
                    (socket.local_endpoint(), socket.remote_endpoint())
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
                        attribution: Attribution::ip_only(),
                    };
                    let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
                    eprintln!("foxprox-net: tcp policy decision={decision:?} event={event:?}");
                    if decision.is_allowed() {
                        flow = Some(if should_inspect_http(destination.port()) {
                            FlowState::InspectingHttp(InspectingHttpFlow::new(source, destination))
                        } else if should_inspect_tls(destination.port()) {
                            FlowState::InspectingTls(InspectingTlsFlow::new(source, destination))
                        } else {
                            FlowState::Connecting(ConnectingFlow::new(
                                source,
                                destination,
                                config.connect_timeout,
                            ))
                        });
                    } else {
                        socket.abort();
                    }
                }
            }
        }

        let mut clear_flow = false;
        if let Some(state) = flow.as_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            match state {
                FlowState::InspectingHttp(inspecting) => {
                    match inspecting.pump(
                        socket,
                        &config.sandbox_id,
                        &config.policy,
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
                    match inspecting.pump(
                        socket,
                        &config.sandbox_id,
                        &config.policy,
                        config.pending_buffer_limit,
                        config.connect_timeout,
                    ) {
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
            flow = None;
        }

        std::thread::sleep(Duration::from_millis(2));
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
        pending_limit: usize,
        connect_timeout: Duration,
    ) -> io::Result<Option<ConnectingFlow>> {
        recv_socket_to_vec(
            socket,
            &mut self.pending_to_host,
            pending_limit,
            &mut self.last_activity,
        )?;
        let inspection =
            match parse_http_request_head(&self.pending_to_host, self.destination.port()) {
                Ok(inspection) => inspection,
                Err(foxprox_core::InspectionError::Truncated) => return Ok(None),
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "malformed or unsupported HTTP request head: {error:?}"
                    )))
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
        if !decision.is_allowed() {
            return Err(io::Error::other("transparent HTTP policy denied request"));
        }
        Ok(Some(ConnectingFlow::new_with_pending(
            self.source,
            self.destination,
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
        sandbox_id: &SandboxId,
        policy: &PolicyRuleSet,
        pending_limit: usize,
        connect_timeout: Duration,
    ) -> io::Result<Option<ConnectingFlow>> {
        recv_socket_to_vec(
            socket,
            &mut self.pending_to_host,
            pending_limit,
            &mut self.last_activity,
        )?;
        let inspection = match parse_tls_client_hello(&self.pending_to_host) {
            Ok(inspection) => inspection,
            Err(foxprox_core::InspectionError::Truncated) => return Ok(None),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "malformed or unsupported TLS ClientHello: {error:?}"
                )))
            }
        };
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id.clone(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::from(self.destination),
            sni: inspection.sni,
            ech_present: inspection.ech_present,
            dns_hostname: None,
            mismatch: false,
        };
        let decision = PolicyEngine::new(policy.clone()).evaluate(&event);
        eprintln!("foxprox-net: transparent TLS policy decision={decision:?} event={event:?}");
        if !decision.is_allowed() {
            return Err(io::Error::other(
                "transparent TLS policy denied ClientHello",
            ));
        }
        Ok(Some(ConnectingFlow::new_with_pending(
            self.source,
            self.destination,
            connect_timeout,
            std::mem::take(&mut self.pending_to_host),
        )))
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }
}

struct ConnectingFlow {
    source: TransportEndpoint,
    destination: SocketAddr,
    receiver: Receiver<io::Result<TcpStream>>,
    pending_to_host: Vec<u8>,
    started_at: StdInstant,
    last_activity: StdInstant,
}

impl ConnectingFlow {
    fn new(source: TransportEndpoint, destination: SocketAddr, timeout: Duration) -> Self {
        Self::new_with_pending(source, destination, timeout, Vec::new())
    }

    fn new_with_pending(
        source: TransportEndpoint,
        destination: SocketAddr,
        timeout: Duration,
        pending_to_host: Vec<u8>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = TcpStream::connect_timeout(&destination, timeout).and_then(|stream| {
                stream.set_nonblocking(true)?;
                Ok(stream)
            });
            let _ = sender.send(result);
        });
        let now = StdInstant::now();
        Self {
            source,
            destination,
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
                    "foxprox-net: host connected sandbox={}:{} destination={}",
                    self.source.ip, self.source.port, self.destination
                );
                Ok(Some(ActiveFlow::new(
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
    host: TcpStream,
    pending_to_host: Vec<u8>,
    pending_to_sandbox: Vec<u8>,
    host_eof: bool,
    host_write_shutdown: bool,
    bytes_to_host: u64,
    bytes_to_sandbox: u64,
    last_activity: StdInstant,
}

impl ActiveFlow {
    fn new(host: TcpStream, pending_to_host: Vec<u8>) -> Self {
        Self {
            host,
            pending_to_host,
            pending_to_sandbox: Vec::new(),
            host_eof: false,
            host_write_shutdown: false,
            bytes_to_host: 0,
            bytes_to_sandbox: 0,
            last_activity: StdInstant::now(),
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

    #[test]
    fn default_config_is_bounded() {
        let config = TcpProofConfig::new(SandboxId::new("test").unwrap());
        assert_eq!(config.tcp_port, 80);
        assert!(config.connect_timeout <= Duration::from_secs(5));
        assert!(config.idle_timeout <= Duration::from_secs(30));
        assert_eq!(config.pending_buffer_limit, 256 * 1024);
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
}
