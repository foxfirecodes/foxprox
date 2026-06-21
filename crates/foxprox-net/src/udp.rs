//! smoltcp-backed UDP/DNS forwarding proof.
//!
//! This module implements the first live Milestone 4 gate: a broker-reachable
//! DNS service at the TUN broker IP, direct external DNS fail-closed logging,
//! and configured generic UDP forwarding proof ports.

use foxprox_core::{
    parse_dns_query, parse_dns_response, Attribution, DnsCache, DnsCacheEntry, FlowKey,
    FlowTimeoutClass, Frontend, NetworkEvent, SandboxId, TransportEndpoint, UdpFlowTable,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Medium, PacketMeta, TunTapInterface};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, SystemTime};

/// Configuration for the UDP/DNS forwarding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDnsProofConfig {
    /// Sandbox/session identifier used in normalized events.
    pub sandbox_id: SandboxId,
    /// Broker/gateway IPv4 address configured on the smoltcp interface.
    pub broker_ip: Ipv4Addr,
    /// Network prefix length for the broker interface address.
    pub prefix_len: u8,
    /// TUN MTU.
    pub mtu: usize,
    /// Broker DNS port reachable from the sandbox.
    pub dns_port: u16,
    /// Upstream DNS resolver used by the proof.
    pub upstream_dns: SocketAddr,
    /// Maximum queued UDP packets in each smoltcp UDP direction.
    pub udp_packet_capacity: usize,
    /// Maximum queued UDP payload bytes in each smoltcp UDP direction.
    pub udp_payload_capacity: usize,
    /// Timeout for one upstream DNS query.
    pub upstream_timeout: Duration,
    /// Destination UDP ports to forward without filtering for this proof.
    pub udp_forward_ports: Vec<u16>,
    /// Timeout for one generic UDP response read.
    pub udp_forward_timeout: Duration,
}

struct UdpForwardSocket {
    port: u16,
    handle: smoltcp::iface::SocketHandle,
}

enum UdpWorkerResult {
    Dns {
        metadata: udp::UdpMetadata,
        source: TransportEndpoint,
        response: io::Result<Vec<u8>>,
        cache_entries: Vec<DnsCacheEntry>,
    },
    Forward {
        handle: smoltcp::iface::SocketHandle,
        metadata: udp::UdpMetadata,
        source: TransportEndpoint,
        destination: TransportEndpoint,
        key: FlowKey,
        response: io::Result<Option<Vec<u8>>>,
    },
}

impl UdpDnsProofConfig {
    /// Creates a proof config using the repository's default TUN addresses.
    pub fn new(sandbox_id: SandboxId) -> Self {
        Self {
            sandbox_id,
            broker_ip: Ipv4Addr::new(10, 255, 0, 1),
            prefix_len: 24,
            mtu: 1500,
            dns_port: 53,
            upstream_dns: SocketAddr::from(([1, 1, 1, 1], 53)),
            udp_packet_capacity: 16,
            udp_payload_capacity: 16 * 1500,
            upstream_timeout: Duration::from_secs(5),
            udp_forward_ports: Vec::new(),
            udp_forward_timeout: Duration::from_secs(3),
        }
    }
}

/// Runs the UDP/DNS proof until the TUN fd errors or the process is interrupted.
pub fn run_udp_dns_proof(tun_fd: OwnedFd, config: UdpDnsProofConfig) -> io::Result<()> {
    run_udp_dns_proof_with_ready(tun_fd, config, || Ok(()))
}

/// Runs the UDP/DNS proof and calls `ready` after UDP sockets are installed.
pub fn run_udp_dns_proof_with_ready<F>(
    tun_fd: OwnedFd,
    config: UdpDnsProofConfig,
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
    iface_config.random_seed = 0x0f0f_7564_u64;
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

    let mut dns_socket = udp_socket(&config)?;
    dns_socket
        .bind(config.dns_port)
        .map_err(|error| io::Error::other(format!("udp dns bind failed: {error}")))?;
    let mut sockets = SocketSet::new(vec![]);
    let dns_handle = sockets.add(dns_socket);
    let mut forward_sockets = Vec::new();
    for port in &config.udp_forward_ports {
        if *port == config.dns_port {
            continue;
        }
        let mut socket = udp_socket(&config)?;
        socket
            .bind(*port)
            .map_err(|error| io::Error::other(format!("udp forward bind failed: {error}")))?;
        forward_sockets.push(UdpForwardSocket {
            port: *port,
            handle: sockets.add(socket),
        });
    }
    eprintln!(
        "foxprox-net: DNS proof listening on {}:{} upstream={} udp_forward_ports={:?}",
        config.broker_ip, config.dns_port, config.upstream_dns, config.udp_forward_ports
    );
    ready()?;

    let (worker_tx, worker_rx) = mpsc::channel();
    let mut cache = DnsCache::default();
    let mut udp_flows = UdpFlowTable::default();
    loop {
        iface.poll(Instant::now(), &mut device, &mut sockets);
        handle_worker_results(
            &config,
            &mut cache,
            &mut udp_flows,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );

        let mut received = Vec::new();
        {
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((payload, metadata)) => received.push((payload.to_vec(), metadata)),
                    Err(error) => {
                        eprintln!("foxprox-net: udp recv failed: {error}");
                        break;
                    }
                }
            }
        }
        for (payload, metadata) in received {
            if let Err(error) = handle_dns_datagram(&config, worker_tx.clone(), payload, metadata) {
                eprintln!("foxprox-net: dns datagram handling failed: {error}");
            }
        }

        let mut forward_received = Vec::new();
        for forward_socket in &forward_sockets {
            let socket = sockets.get_mut::<udp::Socket>(forward_socket.handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((payload, metadata)) => forward_received.push((
                        forward_socket.handle,
                        forward_socket.port,
                        payload.to_vec(),
                        metadata,
                    )),
                    Err(error) => {
                        eprintln!("foxprox-net: udp forward recv failed: {error}");
                        break;
                    }
                }
            }
        }
        for (handle, port, payload, metadata) in forward_received {
            if let Err(error) = handle_udp_forward_datagram(
                &config,
                &mut udp_flows,
                worker_tx.clone(),
                handle,
                port,
                payload,
                metadata,
            ) {
                eprintln!("foxprox-net: udp datagram handling failed: {error}");
            }
        }
        handle_worker_results(
            &config,
            &mut cache,
            &mut udp_flows,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );
        for expired in udp_flows.expire(SystemTime::now()) {
            eprintln!(
                "foxprox-net: udp flow expired destination={}:{} sandbox_to_host={} host_to_sandbox={}",
                expired.key.destination_ip,
                expired.key.destination_port,
                expired.bytes_from_sandbox,
                expired.bytes_to_sandbox
            );
        }

        std::thread::sleep(Duration::from_millis(2));
    }
}

fn udp_socket(config: &UdpDnsProofConfig) -> io::Result<udp::Socket<'static>> {
    if config.udp_packet_capacity == 0 || config.udp_payload_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "udp capacities must be non-zero",
        ));
    }
    let rx_meta = vec![udp::PacketMetadata::EMPTY; config.udp_packet_capacity];
    let tx_meta = vec![udp::PacketMetadata::EMPTY; config.udp_packet_capacity];
    let rx_buffer = udp::PacketBuffer::new(rx_meta, vec![0; config.udp_payload_capacity]);
    let tx_buffer = udp::PacketBuffer::new(tx_meta, vec![0; config.udp_payload_capacity]);
    Ok(udp::Socket::new(rx_buffer, tx_buffer))
}

fn handle_worker_results(
    config: &UdpDnsProofConfig,
    cache: &mut DnsCache,
    flows: &mut UdpFlowTable,
    sockets: &mut SocketSet<'_>,
    dns_handle: smoltcp::iface::SocketHandle,
    worker_rx: &Receiver<UdpWorkerResult>,
) {
    while let Ok(result) = worker_rx.try_recv() {
        match result {
            UdpWorkerResult::Dns {
                metadata,
                source,
                response,
                cache_entries,
            } => {
                for entry in cache_entries {
                    eprintln!(
                        "foxprox-net: dns cache host={} answers={:?}",
                        entry.hostname.as_str(),
                        entry.addresses
                    );
                    cache.insert(entry);
                }
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        eprintln!("foxprox-net: upstream DNS failed: {error}");
                        continue;
                    }
                };
                if let Err(error) = send_udp_response(
                    sockets,
                    dns_handle,
                    metadata.endpoint,
                    IpAddress::Ipv4(smoltcp_ipv4(config.broker_ip)),
                    &response,
                ) {
                    eprintln!("foxprox-net: dns response send failed: {error}");
                    continue;
                }
                eprintln!(
                    "foxprox-net: dns response sandbox={}:{} len={} cache_entries={}",
                    source.ip,
                    source.port,
                    response.len(),
                    cache.len()
                );
            }
            UdpWorkerResult::Forward {
                handle,
                metadata,
                source,
                destination,
                key,
                response,
            } => {
                let response = match response {
                    Ok(Some(response)) => response,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!("foxprox-net: host UDP forward failed: {error}");
                        continue;
                    }
                };
                flows.record_host_datagram(&key, response.len(), SystemTime::now());
                let local_address = match std_ip_to_smoltcp(destination.ip) {
                    Ok(address) => address,
                    Err(error) => {
                        eprintln!("foxprox-net: udp response address failed: {error}");
                        continue;
                    }
                };
                if let Err(error) =
                    send_udp_response(sockets, handle, metadata.endpoint, local_address, &response)
                {
                    eprintln!("foxprox-net: udp response send failed: {error}");
                    continue;
                }
                eprintln!(
                    "foxprox-net: udp response sandbox={}:{} destination={}:{} len={}",
                    source.ip,
                    source.port,
                    destination.ip,
                    destination.port,
                    response.len()
                );
            }
        }
    }
}

fn handle_dns_datagram(
    config: &UdpDnsProofConfig,
    worker_tx: Sender<UdpWorkerResult>,
    payload: Vec<u8>,
    metadata: udp::UdpMetadata,
) -> io::Result<()> {
    let destination_ip = metadata
        .local_address
        .map(ip_to_std)
        .transpose()?
        .ok_or_else(|| io::Error::other("udp metadata missing local destination"))?;
    let source = endpoint_to_transport(metadata.endpoint)?;
    let destination = TransportEndpoint::new(destination_ip, config.dns_port);

    if destination_ip != IpAddr::V4(config.broker_ip) {
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: config.sandbox_id.clone(),
            frontend: Frontend::Tun,
            source,
            destination,
            attribution: Attribution::ip_only(),
            classification: foxprox_core::Protocol::Dns,
        };
        eprintln!("foxprox-net: deny direct DNS bypass {event:?}");
        return Ok(());
    }

    let question = match parse_dns_query(&payload) {
        Ok(question) => question,
        Err(error) => {
            eprintln!(
                "foxprox-net: drop malformed DNS query sandbox={}:{} error={:?}",
                source.ip, source.port, error
            );
            return Ok(());
        }
    };
    let event = NetworkEvent::DnsQuery {
        sandbox_id: config.sandbox_id.clone(),
        hostname: question.hostname.clone(),
        query_type: question.query_type.as_str().to_string(),
        frontend: Frontend::Tun,
    };
    eprintln!(
        "foxprox-net: dns query sandbox={}:{} host={} type={} event={:?}",
        source.ip,
        source.port,
        question.hostname.as_str(),
        question.query_type.as_str(),
        event
    );

    let upstream = config.upstream_dns;
    let timeout = config.upstream_timeout;
    let sandbox_id = config.sandbox_id.clone();
    std::thread::spawn(move || {
        let response = forward_dns_query(&payload, upstream, timeout);
        let cache_entries = response
            .as_ref()
            .ok()
            .and_then(|response| parse_dns_response(response, Some(&question)).ok())
            .map(|observation| {
                DnsCacheEntry::from_response(sandbox_id, &observation, SystemTime::now(), true)
            })
            .unwrap_or_default();
        let _ = worker_tx.send(UdpWorkerResult::Dns {
            metadata,
            source,
            response,
            cache_entries,
        });
    });
    Ok(())
}

fn handle_udp_forward_datagram(
    config: &UdpDnsProofConfig,
    flows: &mut UdpFlowTable,
    worker_tx: Sender<UdpWorkerResult>,
    handle: smoltcp::iface::SocketHandle,
    port: u16,
    payload: Vec<u8>,
    metadata: udp::UdpMetadata,
) -> io::Result<()> {
    let destination_ip = metadata
        .local_address
        .map(ip_to_std)
        .transpose()?
        .ok_or_else(|| io::Error::other("udp metadata missing local destination"))?;
    let source = endpoint_to_transport(metadata.endpoint)?;
    let destination = TransportEndpoint::new(destination_ip, port);
    let key = FlowKey::udp(source.ip, source.port, destination.ip, destination.port);
    let timeout_class = if port == 443 {
        FlowTimeoutClass::Quic
    } else {
        FlowTimeoutClass::GenericUdp
    };
    flows.record_sandbox_datagram(
        key,
        timeout_class,
        Attribution::ip_only(),
        payload.len(),
        SystemTime::now(),
    );
    let event = NetworkEvent::UdpFlowAttempt {
        sandbox_id: config.sandbox_id.clone(),
        frontend: Frontend::Tun,
        source,
        destination,
        attribution: Attribution::ip_only(),
        classification: foxprox_core::Protocol::Udp,
    };
    eprintln!(
        "foxprox-net: udp forward sandbox={}:{} destination={}:{} len={} event={:?}",
        source.ip,
        source.port,
        destination.ip,
        destination.port,
        payload.len(),
        event
    );

    let timeout = config.udp_forward_timeout;
    std::thread::spawn(move || {
        let response = forward_udp_datagram(
            &payload,
            SocketAddr::new(destination.ip, destination.port),
            timeout,
        );
        let _ = worker_tx.send(UdpWorkerResult::Forward {
            handle,
            metadata,
            source,
            destination,
            key,
            response,
        });
    });
    Ok(())
}

fn send_udp_response(
    sockets: &mut SocketSet<'_>,
    handle: smoltcp::iface::SocketHandle,
    endpoint: smoltcp::wire::IpEndpoint,
    local_address: IpAddress,
    response: &[u8],
) -> io::Result<()> {
    let response_meta = udp::UdpMetadata {
        endpoint,
        local_address: Some(local_address),
        meta: PacketMeta::default(),
    };
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket
        .send_slice(response, response_meta)
        .map_err(|error| io::Error::other(format!("smoltcp udp send failed: {error}")))
}

fn forward_udp_datagram(
    payload: &[u8],
    destination: SocketAddr,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let bind_addr = if destination.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.send_to(payload, destination)?;
    let mut response = vec![0_u8; 65_535];
    match socket.recv(&mut response) {
        Ok(len) => {
            response.truncate(len);
            Ok(Some(response))
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn forward_dns_query(
    payload: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let bind_addr = if upstream.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.send_to(payload, upstream)?;
    let mut response = vec![0_u8; 4096];
    let len = socket.recv(&mut response)?;
    response.truncate(len);
    Ok(response)
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

fn std_ip_to_smoltcp(ip: IpAddr) -> io::Result<IpAddress> {
    match ip {
        IpAddr::V4(ip) => Ok(IpAddress::Ipv4(smoltcp_ipv4(ip))),
        IpAddr::V6(_) => Err(io::Error::other("IPv6 is unsupported in UDP proof")),
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
    fn default_udp_dns_config_is_bounded() {
        let config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        assert_eq!(config.dns_port, 53);
        assert_eq!(config.broker_ip, Ipv4Addr::new(10, 255, 0, 1));
        assert!(config.udp_packet_capacity >= 4);
        assert!(config.udp_payload_capacity >= 1500);
        assert!(config.upstream_timeout <= Duration::from_secs(5));
        assert!(config.udp_forward_timeout <= Duration::from_secs(3));
    }
}
