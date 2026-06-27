use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use foxprox_core::{
    handle_broker_dns_query_with_pending, handle_broker_dns_response, AuditEvent, AuditEventKind,
    AuditPolicyContext, BrokerDnsQueryContext, BrokerDnsQueryOutcome, BrokerDnsResponseContext,
    BrokerDnsResponseOutcome, DnsAttributionCache, DnsAttributionLookup, EgressPermit, Endpoint,
    Frontend, HostAttribution, PendingDnsQueryTable, PolicyConfig, PolicyEngine, PolicyRequest,
    Protocol, SandboxId,
};
use foxprox_device::TunDevice;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use crate::{connect_tcp_with_permit, SmolTunDevice};

#[derive(Clone, Debug)]
pub struct AlphaBrokerConfig {
    pub policy: PolicyConfig,
    pub sandbox_id: SandboxId,
    pub broker_ip: IpAddr,
    pub broker_prefix_len: u8,
    pub mtu: usize,
    pub tcp_listen_ports: Vec<u16>,
    pub tcp_destinations: HashMap<(IpAddr, u16), SocketAddr>,
    pub udp_listen_ports: Vec<u16>,
    pub udp_destinations: HashMap<(IpAddr, u16), SocketAddr>,
    pub dns_upstream: Option<SocketAddr>,
    pub audit_stdout: bool,
    pub max_runtime: Option<Duration>,
}

impl AlphaBrokerConfig {
    pub fn new(policy: PolicyConfig, sandbox_id: SandboxId, broker_ip: IpAddr) -> Self {
        Self {
            policy,
            sandbox_id,
            broker_ip,
            broker_prefix_len: 24,
            mtu: 1300,
            tcp_listen_ports: Vec::new(),
            tcp_destinations: HashMap::new(),
            udp_listen_ports: Vec::new(),
            udp_destinations: HashMap::new(),
            dns_upstream: None,
            audit_stdout: true,
            max_runtime: None,
        }
    }
}

#[derive(Debug)]
pub enum AlphaBrokerError {
    Tun(crate::SmolTunError),
    DnsBind(io::Error),
    TcpListen,
    UnsupportedBrokerIp,
}

pub fn run_alpha_broker<F>(
    tun: TunDevice,
    mut config: AlphaBrokerConfig,
    mut should_stop: F,
) -> Result<(), AlphaBrokerError>
where
    F: FnMut() -> bool,
{
    config.tcp_listen_ports.sort_unstable();
    config.tcp_listen_ports.dedup();
    config.udp_listen_ports.sort_unstable();
    config.udp_listen_ports.dedup();
    if !config.broker_ip.is_ipv4() {
        return Err(AlphaBrokerError::UnsupportedBrokerIp);
    }

    let mut device = SmolTunDevice::new(tun, config.mtu).map_err(AlphaBrokerError::Tun)?;
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = 0x5eed_f00d;
    let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
    iface.set_any_ip(true);
    if let IpAddr::V4(broker_v4) = config.broker_ip {
        let _ = iface.routes_mut().add_default_ipv4_route(broker_v4);
    }
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                ip_address(config.broker_ip),
                config.broker_prefix_len,
            ))
            .unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_bridges = Vec::new();
    for port in &config.tcp_listen_ports {
        let handle = add_tcp_listener(&mut sockets, *port)?;
        tcp_bridges.push(TcpBridge {
            handle,
            listen_port: *port,
            host: None,
            opened: false,
        });
    }

    let mut udp_bridges = Vec::new();
    for port in &config.udp_listen_ports {
        if *port == 53 {
            continue;
        }
        let handle = add_udp_listener(&mut sockets, *port);
        let host = UdpSocket::bind("0.0.0.0:0").map_err(AlphaBrokerError::DnsBind)?;
        host.set_nonblocking(true)
            .map_err(AlphaBrokerError::DnsBind)?;
        udp_bridges.push(UdpBridge {
            handle,
            listen_port: *port,
            host,
            last_peer: None,
        });
    }

    let dns_handle = add_dns_socket(&mut sockets);
    let dns_socket = if config.dns_upstream.is_some() {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(AlphaBrokerError::DnsBind)?;
        socket
            .set_nonblocking(true)
            .map_err(AlphaBrokerError::DnsBind)?;
        Some(socket)
    } else {
        None
    };
    let mut dns_state = DnsRuntimeState {
        pending: PendingDnsQueryTable::new(256, 5_000),
        cache: DnsAttributionCache::new(1024, 300_000),
        peers: HashMap::new(),
    };
    let started = StdInstant::now();

    emit_audit(
        &config,
        AuditEvent::lifecycle(
            0,
            config.sandbox_id.clone(),
            AuditEventKind::BrokerStart,
            Some(Frontend::Tun),
        ),
    );

    while !should_stop()
        && match config.max_runtime {
            Some(limit) => started.elapsed() < limit,
            None => true,
        }
    {
        let timestamp = started.elapsed().as_millis() as u64;
        let now = Instant::from_millis(timestamp as i64);
        iface.poll(now, &mut device, &mut sockets);

        drive_dns(
            &mut sockets,
            dns_handle,
            dns_socket.as_ref(),
            &config,
            &mut dns_state,
            timestamp,
        );

        for bridge in &mut tcp_bridges {
            drive_tcp_bridge(
                &mut sockets,
                bridge,
                &config,
                &mut dns_state.cache,
                timestamp,
            );
        }
        for bridge in &mut udp_bridges {
            drive_udp_bridge(&mut sockets, bridge, &config, timestamp);
        }

        std::thread::sleep(Duration::from_millis(5));
    }

    emit_audit(
        &config,
        AuditEvent::lifecycle(
            started.elapsed().as_millis() as u64,
            config.sandbox_id.clone(),
            AuditEventKind::NetworkSessionExit,
            Some(Frontend::Tun),
        ),
    );
    Ok(())
}

fn add_tcp_listener(
    sockets: &mut SocketSet<'_>,
    port: u16,
) -> Result<SocketHandle, AlphaBrokerError> {
    let rx = tcp::SocketBuffer::new(vec![0; 65_536]);
    let tx = tcp::SocketBuffer::new(vec![0; 65_536]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket
        .listen(port)
        .map_err(|_| AlphaBrokerError::TcpListen)?;
    Ok(sockets.add(socket))
}

fn add_udp_listener(sockets: &mut SocketSet<'_>, port: u16) -> SocketHandle {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
    let mut socket = udp::Socket::new(rx, tx);
    socket.bind(port).unwrap();
    sockets.add(socket)
}

fn add_dns_socket(sockets: &mut SocketSet<'_>) -> SocketHandle {
    add_udp_listener(sockets, 53)
}

struct TcpBridge {
    handle: SocketHandle,
    listen_port: u16,
    host: Option<TcpStream>,
    opened: bool,
}

fn drive_tcp_bridge(
    sockets: &mut SocketSet<'_>,
    bridge: &mut TcpBridge,
    config: &AlphaBrokerConfig,
    dns_cache: &mut DnsAttributionCache,
    timestamp: u64,
) {
    let socket = sockets.get_mut::<tcp::Socket>(bridge.handle);

    if socket.state() == tcp::State::Closed {
        bridge.host = None;
        bridge.opened = false;
        let _ = socket.listen(bridge.listen_port);
        return;
    }

    if socket.local_endpoint().is_some() && bridge.host.is_none() {
        let local = socket.local_endpoint().unwrap();
        let remote = socket.remote_endpoint();
        let host_destination = config
            .tcp_destinations
            .get(&(endpoint_ip(local.addr), local.port))
            .copied()
            .unwrap_or_else(|| SocketAddr::new(endpoint_ip(local.addr), local.port));
        let egress_destination = Endpoint::tcp(host_destination.ip(), host_destination.port());
        let mut request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(egress_destination)
            .with_requested_port(local.port);
        request.sandbox_id = config.sandbox_id.clone();
        request.frontend = Frontend::Tun;
        request.source = remote.map(|peer| endpoint_from_ip_endpoint(peer, Protocol::Tcp));
        request.dns_attribution = match dns_cache.lookup_unique(host_destination.ip(), timestamp) {
            DnsAttributionLookup::Unique(attribution) => attribution.hostname.clone(),
            DnsAttributionLookup::NotFound | DnsAttributionLookup::Ambiguous { .. } => None,
        };
        if let Some(hostname) = request.dns_attribution.clone() {
            request.attribution = HostAttribution::dns(hostname);
        }
        let decision = PolicyEngine::decide(&config.policy, &request);
        emit_audit(
            config,
            AuditEvent::from_policy_decision(
                AuditPolicyContext::from_request(timestamp, AuditEventKind::TcpConnect, &request),
                &decision,
            ),
        );
        let Ok(permit) = EgressPermit::from_policy_decision(&request, &decision) else {
            socket.abort();
            return;
        };
        match connect_tcp_with_permit(&permit) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                bridge.host = Some(stream);
                bridge.opened = true;
            }
            Err(_) => socket.abort(),
        }
    }

    if let Some(stream) = bridge.host.as_mut() {
        if socket.can_recv() {
            match socket.recv(|data| (data.len(), data.to_vec())) {
                Ok(data) if !data.is_empty() && stream.write_all(&data).is_err() => {
                    socket.abort();
                }
                _ => {}
            }
        }

        let mut buffer = [0_u8; 8192];
        match stream.read(&mut buffer) {
            Ok(0) => {
                socket.close();
            }
            Ok(n) => {
                if socket.can_send() {
                    let _ = socket.send_slice(&buffer[..n]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => socket.abort(),
        }
    }
}

struct UdpBridge {
    handle: SocketHandle,
    listen_port: u16,
    host: UdpSocket,
    last_peer: Option<IpEndpoint>,
}

fn drive_udp_bridge(
    sockets: &mut SocketSet<'_>,
    bridge: &mut UdpBridge,
    config: &AlphaBrokerConfig,
    timestamp: u64,
) {
    let socket = sockets.get_mut::<udp::Socket>(bridge.handle);
    while socket.can_recv() {
        let Ok((data, meta)) = socket.recv() else {
            break;
        };
        let host_destination = config
            .udp_destinations
            .get(&(config.broker_ip, bridge.listen_port))
            .copied()
            .unwrap_or_else(|| SocketAddr::new(config.broker_ip, bridge.listen_port));
        let mut request = PolicyRequest::new(Protocol::Udp)
            .with_destination(Endpoint::udp(
                host_destination.ip(),
                host_destination.port(),
            ))
            .with_requested_port(bridge.listen_port);
        request.sandbox_id = config.sandbox_id.clone();
        request.frontend = Frontend::Tun;
        request.source = Some(endpoint_from_ip_endpoint(meta.endpoint, Protocol::Udp));
        let decision = PolicyEngine::decide(&config.policy, &request);
        emit_audit(
            config,
            AuditEvent::from_policy_decision(
                AuditPolicyContext::from_request(timestamp, AuditEventKind::UdpPacket, &request),
                &decision,
            ),
        );
        if EgressPermit::from_policy_decision(&request, &decision).is_ok()
            && bridge.host.send_to(data, host_destination).is_ok()
        {
            bridge.last_peer = Some(meta.endpoint);
        }
    }

    let mut buffer = [0_u8; 8192];
    loop {
        match bridge.host.recv_from(&mut buffer) {
            Ok((n, _)) => {
                if let Some(peer) = bridge.last_peer {
                    let _ = socket.send_slice(&buffer[..n], peer);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

struct DnsRuntimeState {
    pending: PendingDnsQueryTable,
    cache: DnsAttributionCache,
    peers: HashMap<u16, IpEndpoint>,
}

fn drive_dns(
    sockets: &mut SocketSet<'_>,
    dns_handle: SocketHandle,
    host_socket: Option<&UdpSocket>,
    config: &AlphaBrokerConfig,
    state: &mut DnsRuntimeState,
    timestamp: u64,
) {
    let socket = sockets.get_mut::<udp::Socket>(dns_handle);
    while socket.can_recv() {
        let Ok((data, meta)) = socket.recv() else {
            break;
        };
        let client = endpoint_from_ip_endpoint(meta.endpoint, Protocol::Dns);
        let broker = Endpoint::udp(config.broker_ip, 53);
        let Some(upstream) = config
            .dns_upstream
            .map(|addr| Endpoint::udp(addr.ip(), addr.port()))
        else {
            let outcome = handle_broker_dns_query_with_pending(
                data,
                &config.policy,
                BrokerDnsQueryContext {
                    timestamp_millis: timestamp,
                    sandbox_id: config.sandbox_id.clone(),
                    frontend: Frontend::Tun,
                    source: Some(client),
                    destination: Some(broker),
                    max_query_bytes: 512,
                    max_response_bytes: 512,
                },
                &mut state.pending,
                Endpoint::udp(config.broker_ip, 53),
                timestamp,
            );
            if let BrokerDnsQueryOutcome::Respond {
                response, audit, ..
            } = outcome
            {
                emit_audit(config, audit);
                let _ = socket.send_slice(&response, meta.endpoint);
            }
            continue;
        };
        let outcome = handle_broker_dns_query_with_pending(
            data,
            &config.policy,
            BrokerDnsQueryContext {
                timestamp_millis: timestamp,
                sandbox_id: config.sandbox_id.clone(),
                frontend: Frontend::Tun,
                source: Some(client),
                destination: Some(broker),
                max_query_bytes: 512,
                max_response_bytes: 512,
            },
            &mut state.pending,
            upstream,
            timestamp,
        );
        match outcome {
            BrokerDnsQueryOutcome::Forward {
                query, wire, audit, ..
            } => {
                emit_audit(config, audit);
                state.peers.insert(query.transaction_id, meta.endpoint);
                if let (Some(host_socket), Some(upstream_addr)) = (host_socket, config.dns_upstream)
                {
                    let _ = host_socket.send_to(&wire, upstream_addr);
                }
            }
            BrokerDnsQueryOutcome::Respond {
                response, audit, ..
            } => {
                emit_audit(config, audit);
                let _ = socket.send_slice(&response, meta.endpoint);
            }
            BrokerDnsQueryOutcome::Drop { audit, .. } => emit_audit(config, audit),
        }
    }

    if let Some(host_socket) = host_socket {
        let mut buffer = [0_u8; 512];
        loop {
            match host_socket.recv_from(&mut buffer) {
                Ok((n, source)) => {
                    let Ok(response) =
                        foxprox_core::parse_dns_address_response(&buffer[..n], 512, 32)
                    else {
                        continue;
                    };
                    let Some(peer) = state.peers.remove(&response.transaction_id) else {
                        continue;
                    };
                    let client = endpoint_from_ip_endpoint(peer, Protocol::Dns);
                    let outcome = handle_broker_dns_response(
                        &buffer[..n],
                        &mut state.pending,
                        &mut state.cache,
                        BrokerDnsResponseContext {
                            timestamp_millis: timestamp,
                            sandbox_id: config.sandbox_id.clone(),
                            frontend: Frontend::Tun,
                            source: Some(Endpoint::udp(source.ip(), source.port())),
                            destination: Some(client),
                            max_response_bytes: 512,
                            max_answers: 32,
                            now_millis: timestamp,
                        },
                    );
                    match outcome {
                        BrokerDnsResponseOutcome::Forward { wire, audit, .. } => {
                            emit_audit(config, audit);
                            let _ = socket.send_slice(&wire, peer);
                        }
                        BrokerDnsResponseOutcome::Drop { audit, .. } => emit_audit(config, audit),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
}

fn emit_audit(config: &AlphaBrokerConfig, event: AuditEvent) {
    if config.audit_stdout {
        let _ = writeln!(io::stdout(), "{}", event.to_json_line());
    }
}

fn endpoint_from_ip_endpoint(endpoint: IpEndpoint, protocol: Protocol) -> Endpoint {
    match protocol {
        Protocol::Udp | Protocol::Dns => Endpoint::udp(endpoint_ip(endpoint.addr), endpoint.port),
        _ => Endpoint::tcp(endpoint_ip(endpoint.addr), endpoint.port),
    }
}

fn endpoint_ip(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(addr) => IpAddr::V4(addr),
    }
}

fn ip_address(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(addr) => IpAddress::Ipv4(addr),
        IpAddr::V6(_) => IpAddress::v4(0, 0, 0, 0),
    }
}
