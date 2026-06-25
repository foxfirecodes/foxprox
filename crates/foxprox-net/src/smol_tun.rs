use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};

use foxprox_core::{
    handle_tun_packet, BoundedAuditBuffer, PolicyConfig, PushOutcome, SandboxId, TunPacketContext,
    TunPacketOutcome,
};
use foxprox_device::TunDevice;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

#[derive(Debug)]
pub enum SmolTunError {
    Fcntl(io::Error),
}

impl PartialEq for SmolTunError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Fcntl(_), Self::Fcntl(_)))
    }
}

impl Eq for SmolTunError {}

pub struct SmolTunDevice {
    file: File,
    mtu: usize,
}

impl SmolTunDevice {
    pub fn new(device: TunDevice, mtu: usize) -> Result<Self, SmolTunError> {
        let file = device.into_file();
        set_nonblocking(file.as_raw_fd())?;
        Ok(Self { file, mtu })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

pub struct MediatedTunDevice {
    file: File,
    mtu: usize,
    config: PolicyConfig,
    sandbox_id: SandboxId,
    audit: BoundedAuditBuffer,
    dropped_audit_events: usize,
}

impl MediatedTunDevice {
    pub fn new(
        device: TunDevice,
        mtu: usize,
        config: PolicyConfig,
        sandbox_id: SandboxId,
        audit_capacity: usize,
    ) -> Result<Self, SmolTunError> {
        let file = device.into_file();
        set_nonblocking(file.as_raw_fd())?;
        Ok(Self {
            file,
            mtu,
            config,
            sandbox_id,
            audit: BoundedAuditBuffer::new(audit_capacity),
            dropped_audit_events: 0,
        })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn audit(&self) -> &BoundedAuditBuffer {
        &self.audit
    }

    pub fn audit_mut(&mut self) -> &mut BoundedAuditBuffer {
        &mut self.audit
    }

    pub fn dropped_audit_events(&self) -> usize {
        self.dropped_audit_events
    }

    fn push_audit(&mut self, event: foxprox_core::AuditEvent) {
        if matches!(self.audit.push(event), PushOutcome::Backpressure { .. }) {
            self.dropped_audit_events = self.dropped_audit_events.saturating_add(1);
        }
    }
}

impl Device for MediatedTunDevice {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        for _ in 0..16 {
            let mut buffer = vec![0_u8; self.mtu];
            match self.file.read(&mut buffer) {
                Ok(0) => return None,
                Ok(n) => {
                    buffer.truncate(n);
                    let outcome = handle_tun_packet(
                        &buffer,
                        &self.config,
                        TunPacketContext {
                            timestamp_millis: 0,
                            sandbox_id: self.sandbox_id.clone(),
                            dns_attribution: None,
                        },
                    );
                    match outcome {
                        TunPacketOutcome::Forward { wire, audit, .. } => {
                            self.push_audit(*audit);
                            return Some((
                                TunRxToken { buffer: wire },
                                TunTxToken {
                                    fd: self.file.as_raw_fd(),
                                },
                            ));
                        }
                        TunPacketOutcome::WriteBack {
                            response, audit, ..
                        } => {
                            self.push_audit(*audit);
                            write_all_fd(self.file.as_raw_fd(), &response);
                        }
                        TunPacketOutcome::Drop { audit, .. } => {
                            self.push_audit(*audit);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return None,
                Err(_) => return None,
            }
        }
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            fd: self.file.as_raw_fd(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        caps
    }
}

impl Device for SmolTunDevice {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buffer = vec![0_u8; self.mtu];
        match self.file.read(&mut buffer) {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some((
                    TunRxToken { buffer },
                    TunTxToken {
                        fd: self.file.as_raw_fd(),
                    },
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            fd: self.file.as_raw_fd(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        caps
    }
}

pub struct TunRxToken {
    buffer: Vec<u8>,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TunTxToken {
    fd: RawFd,
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0_u8; len];
        let result = f(&mut buffer);
        write_all_fd(self.fd, &buffer);
        result
    }
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `fd` is owned by `SmolTunDevice` and remains open while the
        // token is alive; `bytes.as_ptr()` is valid for `bytes.len()` bytes for
        // the duration of this syscall.
        let rc = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if rc <= 0 {
            return;
        }
        bytes = &bytes[rc as usize..];
    }
}

pub fn set_nonblocking(fd: RawFd) -> Result<(), SmolTunError> {
    // SAFETY: F_GETFL only reads kernel flags for an open fd and does not touch
    // Rust-managed memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(SmolTunError::Fcntl(io::Error::last_os_error()));
    }
    // SAFETY: F_SETFL mutates kernel descriptor flags only; `fd` remains owned
    // by its File/TunDevice and the bit-or preserves existing flags.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(SmolTunError::Fcntl(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::process::Command;
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    use foxprox_core::{
        build_dns_address_response, parse_dns_address_response, parse_dns_query, AuditDecision,
        BrokerDnsQueryContext, BrokerDnsQueryOutcome, BrokerDnsResponseContext,
        BrokerDnsResponseOutcome, Cidr, Decision, DnsAttributionCache, DnsAttributionLookup,
        EgressPermit, Endpoint, Frontend, HostMatcher, PendingDnsQueryTable, PolicyConfig,
        PolicyRequest, PolicyRule, Protocol, SandboxId,
    };
    use foxprox_device::{
        configure_tun_interface, create_tun, IpCommandRunner, TunConfig, TunSetup,
    };
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::socket::{tcp, udp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

    use super::*;

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn smoltcp_accepts_tcp_from_real_tun() {
        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let mut device = SmolTunDevice::new(tun, 1300).unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1234_5678;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });

        let rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let mut tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp_socket.listen(8080).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(tcp_socket);

        let mut curl = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "http://10.0.0.2:8080/",
            ])
            .spawn()
            .unwrap();

        let started = StdInstant::now();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nfoxok\n";
        let mut served = false;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            if socket.can_recv() {
                let _ = socket.recv(|data| (data.len(), data.len())).unwrap();
            }
            if socket.may_send() && !served && socket.send_slice(response).is_ok() {
                socket.close();
                served = true;
            }
            if served && socket.state() == tcp::State::Closed {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }

        let status = curl.wait().unwrap();
        assert!(
            served,
            "smoltcp should receive the HTTP request and send a response"
        );
        assert!(status.success(), "curl should receive the smoltcp response");
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn smoltcp_bridges_tun_tcp_to_host_socket() {
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let n = stream.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(request.starts_with(b"GET /"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nbridge\n",
                )
                .unwrap();
        });

        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let mut device = SmolTunDevice::new(tun, 1300).unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x8765_4321;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });

        let rx_buffer = tcp::SocketBuffer::new(vec![0; 8192]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 8192]);
        let mut tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp_socket.listen(8080).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(tcp_socket);

        let mut curl = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "http://10.0.0.2:8080/",
            ])
            .spawn()
            .unwrap();

        let started = StdInstant::now();
        let mut host_stream: Option<TcpStream> = None;
        let mut bridged_request = false;
        let mut bridged_response = false;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

            if socket.can_recv() {
                let data = socket.recv(|data| (data.len(), data.to_vec())).unwrap();
                let stream = host_stream.get_or_insert_with(|| {
                    let request = PolicyRequest::new(Protocol::Tcp)
                        .with_destination(Endpoint::tcp(listener_addr.ip(), listener_addr.port()));
                    let permit = EgressPermit::from_policy_decision(
                        &request,
                        &Decision::Allow {
                            rule_id: Some("allow-host-bridge".into()),
                        },
                    )
                    .unwrap();
                    let stream = crate::connect_tcp_with_permit(&permit).unwrap();
                    stream.set_nonblocking(true).unwrap();
                    stream
                });
                stream.write_all(&data).unwrap();
                bridged_request = true;
            }

            if let Some(stream) = host_stream.as_mut() {
                let mut buffer = [0_u8; 1024];
                match stream.read(&mut buffer) {
                    Ok(0) => {}
                    Ok(n) => {
                        if socket.can_send() && socket.send_slice(&buffer[..n]).is_ok() {
                            socket.close();
                            bridged_response = true;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("host stream read failed: {error}"),
                }
            }

            if bridged_response && socket.state() == tcp::State::Closed {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }

        let status = curl.wait().unwrap();
        server.join().unwrap();
        assert!(
            bridged_request,
            "expected sandbox request bytes to reach host socket"
        );
        assert!(
            bridged_response,
            "expected host response bytes to return through smoltcp"
        );
        assert!(
            status.success(),
            "curl should receive the bridged host response"
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn smoltcp_bridges_tun_udp_to_host_socket() {
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap();
        let host_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host_addr = host_server.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut buffer = [0_u8; 1024];
            let (n, peer) = host_server.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..n], b"ping");
            host_server.send_to(b"pong", peer).unwrap();
        });

        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let client = UdpSocket::bind("10.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        client.send_to(b"ping", "10.0.0.2:9000").unwrap();

        let mut device = SmolTunDevice::new(tun, 1300).unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0xfeed_beef;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });

        let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let mut udp_socket = udp::Socket::new(rx_buffer, tx_buffer);
        udp_socket.bind(9000).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let udp_handle = sockets.add(udp_socket);
        let host_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_client.set_nonblocking(true).unwrap();

        let started = StdInstant::now();
        let mut sandbox_peer: Option<IpEndpoint> = None;
        let mut bridged_request = false;
        let mut bridged_response = false;
        let mut response_ready_at: Option<StdInstant> = None;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<udp::Socket>(udp_handle);

            if socket.can_recv() {
                let (data, meta) = socket.recv().unwrap();
                host_client.send_to(data, host_addr).unwrap();
                sandbox_peer = Some(meta.endpoint);
                bridged_request = true;
            }

            let mut buffer = [0_u8; 1024];
            match host_client.recv_from(&mut buffer) {
                Ok((n, _)) => {
                    if let Some(peer) = sandbox_peer {
                        socket.send_slice(&buffer[..n], peer).unwrap();
                        bridged_response = true;
                        response_ready_at = Some(StdInstant::now());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("host UDP read failed: {error}"),
            }

            if response_ready_at
                .is_some_and(|sent_at| sent_at.elapsed() > StdDuration::from_millis(50))
            {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }

        let mut response = [0_u8; 16];
        let (n, _) = client.recv_from(&mut response).unwrap();
        server.join().unwrap();
        assert!(
            bridged_request,
            "expected sandbox UDP datagram to reach host socket"
        );
        assert!(
            bridged_response,
            "expected host UDP response to return through smoltcp"
        );
        assert_eq!(&response[..n], b"pong");
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn smoltcp_dns_broker_returns_policy_denial_response_over_tun() {
        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let client = UdpSocket::bind("10.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let query = dns_query("blocked.example", 1);
        client.send_to(&query, "10.0.0.2:53").unwrap();

        let mut device = SmolTunDevice::new(tun, 1300).unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0xfeed_5300;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });

        let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let mut udp_socket = udp::Socket::new(rx_buffer, tx_buffer);
        udp_socket.bind(53).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let udp_handle = sockets.add(udp_socket);
        let mut policy = PolicyConfig::default();
        policy.broker_dns_servers.push("10.0.0.2".parse().unwrap());

        let started = StdInstant::now();
        let mut responded = false;
        let mut response_ready_at: Option<StdInstant> = None;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<udp::Socket>(udp_handle);

            if socket.can_recv() {
                let (data, meta) = socket.recv().unwrap();
                let outcome = foxprox_core::handle_broker_dns_query(
                    data,
                    &policy,
                    BrokerDnsQueryContext {
                        timestamp_millis: 1,
                        sandbox_id: SandboxId::new("dns-e2e"),
                        frontend: Frontend::Tun,
                        source: Some(Endpoint::udp(
                            "10.0.0.1".parse().unwrap(),
                            meta.endpoint.port,
                        )),
                        destination: Some(Endpoint::udp("10.0.0.2".parse().unwrap(), 53)),
                        max_query_bytes: 512,
                        max_response_bytes: 512,
                    },
                );
                let BrokerDnsQueryOutcome::Respond {
                    response, audit, ..
                } = outcome
                else {
                    panic!("expected denied DNS query response");
                };
                assert_eq!(audit.reason, Some(foxprox_core::DenialReason::DefaultDeny));
                socket.send_slice(&response, meta.endpoint).unwrap();
                responded = true;
                response_ready_at = Some(StdInstant::now());
            }

            if response_ready_at
                .is_some_and(|sent_at| sent_at.elapsed() > StdDuration::from_millis(50))
            {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }

        let mut response = [0_u8; 512];
        let (n, _) = client.recv_from(&mut response).unwrap();
        let metadata = parse_dns_address_response(&response[..n], 512, 4).unwrap();
        assert!(responded, "expected DNS broker to send a response");
        assert_eq!(metadata.hostname.as_str(), "blocked.example");
        assert_eq!(
            metadata.response_code,
            foxprox_core::DnsResponseCode::Refused
        );
        assert!(metadata.addresses.is_empty());
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn smoltcp_dns_broker_forwards_allowed_response_and_updates_cache() {
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_server = std::thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (n, peer) = upstream.recv_from(&mut buffer).unwrap();
            let query = parse_dns_query(&buffer[..n], 512).unwrap();
            let response =
                build_dns_address_response(&query, ["198.51.100.5".parse().unwrap()], 30, 512, 4)
                    .unwrap();
            upstream.send_to(&response, peer).unwrap();
        });

        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let client = UdpSocket::bind("10.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let query = dns_query("allowed.example", 1);
        client.send_to(&query, "10.0.0.2:53").unwrap();

        let mut device = SmolTunDevice::new(tun, 1300).unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0xfeed_5301;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });

        let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let mut udp_socket = udp::Socket::new(rx_buffer, tx_buffer);
        udp_socket.bind(53).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let udp_handle = sockets.add(udp_socket);
        let host_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_client.set_nonblocking(true).unwrap();
        let upstream_endpoint = Endpoint::udp(upstream_addr.ip(), upstream_addr.port());
        let mut pending = PendingDnsQueryTable::new(8, 5_000);
        let mut cache = DnsAttributionCache::new(8, 60_000);
        let mut policy = PolicyConfig::default();
        policy.broker_dns_servers.push("10.0.0.2".parse().unwrap());
        policy.rules.push(PolicyRule::allow_domain(
            "allow-dns-query",
            HostMatcher::exact("allowed.example").unwrap(),
            Some(53),
        ));

        let started = StdInstant::now();
        let mut sandbox_peer: Option<IpEndpoint> = None;
        let mut forwarded_query = false;
        let mut forwarded_response = false;
        let mut response_ready_at: Option<StdInstant> = None;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<udp::Socket>(udp_handle);

            if socket.can_recv() {
                let (data, meta) = socket.recv().unwrap();
                let client_endpoint =
                    Endpoint::udp("10.0.0.1".parse().unwrap(), meta.endpoint.port);
                let outcome = foxprox_core::handle_broker_dns_query_with_pending(
                    data,
                    &policy,
                    BrokerDnsQueryContext {
                        timestamp_millis: 1,
                        sandbox_id: SandboxId::new("dns-allow-e2e"),
                        frontend: Frontend::Tun,
                        source: Some(client_endpoint),
                        destination: Some(Endpoint::udp("10.0.0.2".parse().unwrap(), 53)),
                        max_query_bytes: 512,
                        max_response_bytes: 512,
                    },
                    &mut pending,
                    upstream_endpoint,
                    10,
                );
                let BrokerDnsQueryOutcome::Forward { wire, audit, .. } = outcome else {
                    panic!("expected allowed DNS query forward");
                };
                assert_eq!(audit.decision, Some(AuditDecision::Allow));
                host_client.send_to(&wire, upstream_addr).unwrap();
                sandbox_peer = Some(meta.endpoint);
                forwarded_query = true;
            }

            let mut upstream_response = [0_u8; 512];
            match host_client.recv_from(&mut upstream_response) {
                Ok((n, _)) => {
                    let client_endpoint =
                        Endpoint::udp("10.0.0.1".parse().unwrap(), sandbox_peer.unwrap().port);
                    let outcome = foxprox_core::handle_broker_dns_response(
                        &upstream_response[..n],
                        &mut pending,
                        &mut cache,
                        BrokerDnsResponseContext {
                            timestamp_millis: 2,
                            sandbox_id: SandboxId::new("dns-allow-e2e"),
                            frontend: Frontend::Tun,
                            source: Some(upstream_endpoint),
                            destination: Some(client_endpoint),
                            max_response_bytes: 512,
                            max_answers: 4,
                            now_millis: 20,
                        },
                    );
                    let BrokerDnsResponseOutcome::Forward { wire, audit, .. } = outcome else {
                        panic!("expected correlated DNS response forward");
                    };
                    assert_eq!(audit.decision, Some(AuditDecision::Allow));
                    socket.send_slice(&wire, sandbox_peer.unwrap()).unwrap();
                    forwarded_response = true;
                    response_ready_at = Some(StdInstant::now());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("upstream response read failed: {error}"),
            }

            if response_ready_at
                .is_some_and(|sent_at| sent_at.elapsed() > StdDuration::from_millis(50))
            {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }

        let mut response = [0_u8; 512];
        let (n, _) = client.recv_from(&mut response).unwrap();
        let metadata = parse_dns_address_response(&response[..n], 512, 4).unwrap();
        upstream_server.join().unwrap();
        assert!(forwarded_query);
        assert!(forwarded_response);
        assert_eq!(metadata.hostname.as_str(), "allowed.example");
        assert_eq!(
            metadata.addresses,
            vec!["198.51.100.5".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(matches!(
            cache.lookup_unique("198.51.100.5".parse().unwrap(), 21),
            DnsAttributionLookup::Unique(attribution)
                if attribution.hostname.as_ref().unwrap().as_str() == "allowed.example"
        ));
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn mediated_tun_drops_default_denied_tcp_before_smoltcp() {
        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let mut device = MediatedTunDevice::new(
            tun,
            1300,
            PolicyConfig::default(),
            SandboxId::new("mediated-deny"),
            8,
        )
        .unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1111_2222;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let mut tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp_socket.listen(8080).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        sockets.add(tcp_socket);

        let mut curl = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "1",
                "http://10.0.0.2:8080/",
            ])
            .spawn()
            .unwrap();
        let started = StdInstant::now();
        while started.elapsed() < StdDuration::from_secs(1) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            std::thread::sleep(StdDuration::from_millis(5));
        }
        let status = curl.wait().unwrap();
        assert!(
            !status.success(),
            "default-denied TCP should not reach smoltcp"
        );
        let batch = device.audit_mut().drain_json_lines(8);
        assert!(batch
            .lines
            .iter()
            .any(|line| line.contains("\"decision\":\"deny\"")
                && line.contains("\"reason\":\"default_deny\"")));
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn mediated_tun_allows_tcp_to_smoltcp_with_audit() {
        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let mut policy = PolicyConfig::default();
        policy.rules.push(PolicyRule::allow_ip(
            "allow-smoltcp-http",
            Cidr::host("10.0.0.2".parse().unwrap()),
            Some(8080),
        ));
        let mut device =
            MediatedTunDevice::new(tun, 1300, policy, SandboxId::new("mediated-allow"), 16)
                .unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x3333_4444;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let mut tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp_socket.listen(8080).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(tcp_socket);

        let mut curl = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "http://10.0.0.2:8080/",
            ])
            .spawn()
            .unwrap();

        let started = StdInstant::now();
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nmediated\n";
        let mut served = false;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            if socket.can_recv() {
                let _ = socket.recv(|data| (data.len(), data.len())).unwrap();
            }
            if socket.may_send() && !served && socket.send_slice(response).is_ok() {
                socket.close();
                served = true;
            }
            if served && socket.state() == tcp::State::Closed {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }
        let status = curl.wait().unwrap();
        assert!(status.success(), "allowed TCP should reach smoltcp");
        let mut saw_allow = false;
        while let Some(event) = device.audit_mut().pop() {
            if event.decision == Some(AuditDecision::Allow)
                && event.rule_id.as_deref() == Some("allow-smoltcp-http")
            {
                saw_allow = true;
                break;
            }
        }
        assert!(saw_allow, "expected allow audit before smoltcp ingress");
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, // transaction id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&qtype.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes
    }
}
