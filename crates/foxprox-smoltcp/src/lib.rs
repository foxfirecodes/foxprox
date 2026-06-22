//! smoltcp adapter boundary for foxprox.
//!
//! This crate is allowed to depend on smoltcp. Core policy/audit crates must
//! continue to see only foxprox normalized runtime types.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

use foxprox_core::Endpoint;
use foxprox_runtime::{TcpStackAdapter, TcpStackConnectAttempt};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Loopback, Medium};
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
    NoMatchingTcpSocket,
    TcpSendRejected,
    TcpRecvRejected,
}

pub struct SmoltcpIpLoopback {
    iface: Interface,
    device: Loopback,
    sockets: SocketSet<'static>,
    tcp_handles: Vec<SocketHandle>,
    listener_ports: Vec<u16>,
    reported_connects: Vec<TcpStackConnectAttempt>,
    config: SmoltcpIpConfig,
}

impl SmoltcpIpLoopback {
    pub fn new(config: SmoltcpIpConfig, now_millis: i64) -> Result<Self, SmoltcpAdapterError> {
        if config.prefix_len > 32 {
            return Err(SmoltcpAdapterError::InvalidPrefixLen);
        }
        let mut device = Loopback::new(Medium::Ip);
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
            config,
        })
    }

    pub fn config(&self) -> &SmoltcpIpConfig {
        &self.config
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
            if socket_matches_attempt(socket, attempt) {
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
        for handle in &self.tcp_handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket
                .local_endpoint()
                .is_some_and(|endpoint| endpoint.port == port)
            {
                let mut bytes = vec![0; max_bytes];
                let count = socket
                    .recv_slice(&mut bytes)
                    .map_err(|_| SmoltcpAdapterError::TcpRecvRejected)?;
                bytes.truncate(count);
                return Ok(bytes);
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

    pub fn poll_once(&mut self, now_millis: i64) {
        let _ = self.iface.poll(
            Instant::from_millis(now_millis),
            &mut self.device,
            &mut self.sockets,
        );
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

impl TcpStackAdapter for SmoltcpIpLoopback {
    fn next_connect_attempt(&mut self) -> Option<TcpStackConnectAttempt> {
        self.active_tcp_connect_attempts()
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

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        DecisionAction, PolicyConfig, PolicyEngine, PolicyRule, Protocol, RuleSet, SandboxId,
        VecAuditSink, VerificationKernel,
    };
    use foxprox_runtime::{
        EgressError, HostEgress, TcpConnectRequest, TcpStackOutcome, TcpStackRuntime,
        UdpDatagramRequest,
    };

    #[derive(Default)]
    struct FakeEgress {
        tcp_attempts: usize,
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
            match adapter.recv_on_listener_port(8080, 64) {
                Ok(bytes) if !bytes.is_empty() => {
                    received = Some(bytes);
                    break;
                }
                Ok(_) | Err(SmoltcpAdapterError::TcpRecvRejected) => {}
                Err(error) => panic!("unexpected recv error: {error:?}"),
            }
        }

        assert_eq!(sent, b"hello-smoltcp".len());
        assert_eq!(
            received.expect("listener should receive payload"),
            b"hello-smoltcp".to_vec()
        );
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
