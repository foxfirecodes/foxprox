//! Combined transparent TCP, UDP, and broker-DNS proof runtime.

use crate::udp::{
    expire_udp_flows_with_audit, handle_dns_datagram, handle_udp_forward_datagram,
    handle_worker_results, udp_socket, UdpForwardDatagram, UdpForwardSocket, WorkerLimiter,
};
use crate::{audit_buffer, set_nonblocking, smoltcp_ipv4, TcpProofConfig, TransparentTcpState};
use foxprox_core::{DnsCache, PolicyRuleSet, SandboxId, UdpFlowTable};
use smoltcp::iface::{Config, SocketSet};
use smoltcp::phy::{Medium, TunTapInterface};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

/// Configuration for the combined transparent TCP/UDP/DNS proof runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CombinedTransparentProofConfig {
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
    /// Host TCP connect timeout.
    pub connect_timeout: Duration,
    /// Maximum buffered bytes in either TCP bridge direction.
    pub pending_buffer_limit: usize,
    /// Idle timeout for a proof TCP flow.
    pub idle_timeout: Duration,
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
    /// Destination UDP ports to forward through policy for this proof.
    pub udp_forward_ports: Vec<u16>,
    /// Timeout for one generic UDP response read.
    pub udp_forward_timeout: Duration,
    /// Shared policy used before host egress.
    pub policy: PolicyRuleSet,
    /// Maximum queued audit events before proof paths fail closed.
    pub audit_queue_capacity: usize,
    /// Maximum simultaneous DNS/UDP host worker threads.
    pub max_worker_threads: usize,
}

impl CombinedTransparentProofConfig {
    /// Creates a combined proof config using the repository's default TUN addresses.
    pub fn new(sandbox_id: SandboxId) -> Self {
        let tcp = TcpProofConfig::new(sandbox_id.clone());
        let udp = crate::UdpDnsProofConfig::new(sandbox_id.clone());
        Self {
            sandbox_id,
            broker_ip: tcp.broker_ip,
            prefix_len: tcp.prefix_len,
            mtu: tcp.mtu,
            tcp_port: tcp.tcp_port,
            connect_timeout: tcp.connect_timeout,
            pending_buffer_limit: tcp.pending_buffer_limit,
            idle_timeout: tcp.idle_timeout,
            dns_port: udp.dns_port,
            upstream_dns: udp.upstream_dns,
            udp_packet_capacity: udp.udp_packet_capacity,
            udp_payload_capacity: udp.udp_payload_capacity,
            upstream_timeout: udp.upstream_timeout,
            udp_forward_ports: udp.udp_forward_ports,
            udp_forward_timeout: udp.udp_forward_timeout,
            policy: PolicyRuleSet::default(),
            audit_queue_capacity: udp.audit_queue_capacity,
            max_worker_threads: udp.max_worker_threads,
        }
    }

    fn tcp_config(&self) -> TcpProofConfig {
        TcpProofConfig {
            sandbox_id: self.sandbox_id.clone(),
            broker_ip: self.broker_ip,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            tcp_port: self.tcp_port,
            connect_timeout: self.connect_timeout,
            pending_buffer_limit: self.pending_buffer_limit,
            idle_timeout: self.idle_timeout,
            policy: self.policy.clone(),
            audit_queue_capacity: self.audit_queue_capacity,
        }
    }

    fn udp_config(&self) -> crate::UdpDnsProofConfig {
        crate::UdpDnsProofConfig {
            sandbox_id: self.sandbox_id.clone(),
            broker_ip: self.broker_ip,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            dns_port: self.dns_port,
            upstream_dns: self.upstream_dns,
            udp_packet_capacity: self.udp_packet_capacity,
            udp_payload_capacity: self.udp_payload_capacity,
            upstream_timeout: self.upstream_timeout,
            udp_forward_ports: self.udp_forward_ports.clone(),
            udp_forward_timeout: self.udp_forward_timeout,
            policy: self.policy.clone(),
            audit_queue_capacity: self.audit_queue_capacity,
            max_worker_threads: self.max_worker_threads,
        }
    }
}

/// Runs the combined transparent proof until the TUN fd errors or the process is interrupted.
pub fn run_combined_transparent_proof(
    tun_fd: OwnedFd,
    config: CombinedTransparentProofConfig,
) -> io::Result<()> {
    run_combined_transparent_proof_with_ready(tun_fd, config, || Ok(()))
}

/// Runs the combined transparent proof and calls `ready` after sockets are installed.
pub fn run_combined_transparent_proof_with_ready<F>(
    tun_fd: OwnedFd,
    config: CombinedTransparentProofConfig,
    ready: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    let mut audit = audit_buffer(config.audit_queue_capacity)?;
    let worker_limiter = WorkerLimiter::new(config.max_worker_threads)?;
    set_nonblocking(tun_fd.as_raw_fd())?;
    let raw_fd = tun_fd.into_raw_fd();
    let mut device = TunTapInterface::from_fd(raw_fd, Medium::Ip, config.mtu).map_err(|error| {
        io::Error::other(format!("failed to create smoltcp TUN device: {error}"))
    })?;

    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = 0x0f0f_636f_u64;
    let mut iface = smoltcp::iface::Interface::new(iface_config, &mut device, Instant::now());
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
    let mut dns_socket = udp_socket(&config.udp_config())?;
    dns_socket
        .bind(config.dns_port)
        .map_err(|error| io::Error::other(format!("udp dns bind failed: {error}")))?;

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);
    let dns_handle = sockets.add(dns_socket);
    let udp_config = config.udp_config();
    let mut forward_sockets = Vec::new();
    for port in &config.udp_forward_ports {
        if *port == config.dns_port {
            continue;
        }
        let mut socket = udp_socket(&udp_config)?;
        socket
            .bind(*port)
            .map_err(|error| io::Error::other(format!("udp forward bind failed: {error}")))?;
        forward_sockets.push(UdpForwardSocket {
            port: *port,
            handle: sockets.add(socket),
        });
    }

    install_tcp_listener(sockets.get_mut::<tcp::Socket>(tcp_handle), config.tcp_port)?;
    eprintln!(
        "foxprox-net: combined transparent proof listening tcp_port={} dns={}:{} upstream={} udp_forward_ports={:?}",
        config.tcp_port,
        config.broker_ip,
        config.dns_port,
        config.upstream_dns,
        config.udp_forward_ports
    );
    ready()?;

    let tcp_config = config.tcp_config();
    let (worker_tx, worker_rx) = mpsc::channel();
    let mut tcp_state = TransparentTcpState::new();
    let mut cache = DnsCache::default();
    let mut udp_flows = UdpFlowTable::default();
    loop {
        iface.poll(Instant::now(), &mut device, &mut sockets);
        handle_worker_results(
            &udp_config,
            &mut cache,
            &mut udp_flows,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );

        {
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            tcp_state.poll(socket, &tcp_config, &mut audit, Some(&cache))?;
        }

        let mut dns_received = Vec::new();
        {
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((payload, metadata)) => dns_received.push((payload.to_vec(), metadata)),
                    Err(error) => {
                        eprintln!("foxprox-net: combined dns recv failed: {error}");
                        break;
                    }
                }
            }
        }
        for (payload, metadata) in dns_received {
            if let Err(error) = handle_dns_datagram(
                &udp_config,
                &mut audit,
                &worker_limiter,
                worker_tx.clone(),
                payload,
                metadata,
            ) {
                eprintln!("foxprox-net: combined DNS datagram handling failed: {error}");
            }
        }

        let mut forward_received = Vec::new();
        for forward_socket in &forward_sockets {
            let socket = sockets.get_mut::<udp::Socket>(forward_socket.handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((payload, metadata)) => {
                        forward_received.push((*forward_socket, payload.to_vec(), metadata));
                    }
                    Err(error) => {
                        eprintln!("foxprox-net: combined udp forward recv failed: {error}");
                        break;
                    }
                }
            }
        }
        for (forward_socket, payload, metadata) in forward_received {
            if let Err(error) = handle_udp_forward_datagram(
                &udp_config,
                &cache,
                &mut udp_flows,
                &mut audit,
                &worker_limiter,
                worker_tx.clone(),
                UdpForwardDatagram {
                    socket: forward_socket,
                    payload,
                    metadata,
                },
            ) {
                eprintln!("foxprox-net: combined UDP datagram handling failed: {error}");
            }
        }

        handle_worker_results(
            &udp_config,
            &mut cache,
            &mut udp_flows,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );
        let now = SystemTime::now();
        let expired_cache_entries = cache.expire(now);
        if expired_cache_entries > 0 {
            eprintln!("foxprox-net: expired {expired_cache_entries} DNS cache entries");
        }
        if let Err(error) =
            expire_udp_flows_with_audit(&mut audit, &config.sandbox_id, &mut udp_flows, now)
        {
            eprintln!("foxprox-net: combined udp expiry audit failed: {error}");
        }

        std::thread::sleep(Duration::from_millis(2));
    }
}

fn install_tcp_listener(socket: &mut tcp::Socket<'_>, tcp_port: u16) -> io::Result<()> {
    socket
        .listen(tcp_port)
        .map_err(|error| io::Error::other(format!("listen failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_tcp_socket() -> tcp::Socket<'static> {
        let rx = tcp::SocketBuffer::new(vec![0; 1024]);
        let tx = tcp::SocketBuffer::new(vec![0; 1024]);
        tcp::Socket::new(rx, tx)
    }

    #[test]
    fn default_combined_transparent_config_is_bounded() {
        let config = CombinedTransparentProofConfig::new(SandboxId::new("test").unwrap());

        assert_eq!(config.tcp_port, 80);
        assert_eq!(config.dns_port, 53);
        assert_eq!(config.broker_ip, Ipv4Addr::new(10, 255, 0, 1));
        assert!(config.connect_timeout <= Duration::from_secs(5));
        assert!(config.idle_timeout <= Duration::from_secs(30));
        assert_eq!(config.pending_buffer_limit, 256 * 1024);
        assert!(config.udp_packet_capacity >= 4);
        assert!(config.udp_payload_capacity >= 1500);
        assert!(config.audit_queue_capacity > 0);
        assert!(config.max_worker_threads > 0);
    }

    #[test]
    fn combined_rejects_zero_audit_capacity_before_tun_setup() {
        let mut config = CombinedTransparentProofConfig::new(SandboxId::new("test").unwrap());
        config.audit_queue_capacity = 0;
        assert_eq!(
            audit_buffer(config.audit_queue_capacity)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn combined_rejects_zero_worker_capacity_before_tun_setup() {
        let error = match WorkerLimiter::new(0) {
            Ok(_) => panic!("zero-capacity worker limiter unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn combined_installs_tcp_listener_before_ready_point() {
        let mut socket = empty_tcp_socket();
        install_tcp_listener(&mut socket, 80).unwrap();
        assert!(socket.is_open());
    }
}
