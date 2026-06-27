#![cfg(unix)]

use foxprox_cli::{
    accept_setup_control_tun_handoff_with_timeouts, run_host_setup_control_session_with_runner,
    HostSetupControlHandoffStatus, HostSetupProcessExit, HostSetupProcessRunner,
};
use foxprox_core::{
    AuditKind, BrokerCore, BrokerRuntimeConfig, BwrapSetupPlan, Decision, JsonLineAuditSink,
    NetworkEndpoint, NetworkSetupConfig, PolicyConfig, PolicyEngine, Protocol, RuntimeAuditFanIn,
};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct RewritingBwrapRunner {
    setup_helper: PathBuf,
    child: Option<std::process::Child>,
}

impl RewritingBwrapRunner {
    fn new(setup_helper: impl Into<PathBuf>) -> Self {
        Self {
            setup_helper: setup_helper.into(),
            child: None,
        }
    }
}

impl HostSetupProcessRunner for RewritingBwrapRunner {
    fn start_setup_process(&mut self, plan: &BwrapSetupPlan) -> Result<(), String> {
        if self.child.is_some() {
            return Err("setup process already started".to_string());
        }
        let mut command = plan.full_command();
        for arg in &mut command {
            if arg == "foxproxsetup" {
                *arg = self.setup_helper.display().to_string();
                break;
            }
        }
        let Some((program, args)) = command.split_first() else {
            return Err("empty bwrap command".to_string());
        };
        let child = Command::new(program)
            .args(args)
            .spawn()
            .map_err(|error| format!("spawn {program}: {error}"))?;
        self.child = Some(child);
        Ok(())
    }

    fn poll_setup_process(&mut self) -> Result<Option<HostSetupProcessExit>, String> {
        let Some(child) = self.child.as_mut() else {
            return Err("setup process was not started".to_string());
        };
        child
            .try_wait()
            .map(|status| {
                status.map(|status| HostSetupProcessExit {
                    exit_code: status.code(),
                    success: status.success(),
                })
            })
            .map_err(|error| error.to_string())
    }

    fn wait_setup_process(&mut self) -> Result<HostSetupProcessExit, String> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| "setup process was not started".to_string())?;
        let status = child.wait().map_err(|error| error.to_string())?;
        Ok(HostSetupProcessExit {
            exit_code: status.code(),
            success: status.success(),
        })
    }

    fn wait_setup_process_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<HostSetupProcessExit>, String> {
        let started = std::time::Instant::now();
        loop {
            if let Some(exit) = self.poll_setup_process()? {
                return Ok(Some(exit));
            }
            if started.elapsed() >= timeout {
                let child = self
                    .child
                    .as_mut()
                    .ok_or_else(|| "setup process was not started".to_string())?;
                let _ = child.kill();
                let status = child.wait().map_err(|error| error.to_string())?;
                return Err(format!(
                    "timed out waiting for setup process exit after fd handoff; terminated with code {:?}",
                    status.code()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, and CAP_NET_ADMIN inside bwrap user/net namespace"]
fn bwrap_foxproxsetup_creates_tun_hands_fd_drops_cap_and_execs_target() {
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let socket_path = std::env::temp_dir().join(format!(
        "foxprox-bwrap-e2e-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let mut config = NetworkSetupConfig::alpha_default(format!("bwrap-e2e-{unique}"));
    config.tun_name = format!("fxp{:x}", std::process::id() % 0x00ff_ffff);
    config.setup_control_socket_path = Some(socket_path.to_string_lossy().to_string());

    let target = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        concat!(
            "cap=$(awk '/CapEff/ {print $2}' /proc/self/status); ",
            "test \"$cap\" = 0000000000000000; ",
            "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ",
            "s.sendto(b\"foxprox-bwrap-e2e\", (\"198.51.100.1\", 443))'"
        )
        .to_string(),
    ];
    let mut runner = RewritingBwrapRunner::new(setup_helper);

    let mut report =
        run_host_setup_control_session_with_runner(&listener, config, &target, &mut runner);
    let _ = std::fs::remove_file(&socket_path);

    assert_eq!(report.status, HostSetupControlHandoffStatus::Complete);
    let received = report.handoff.received.take().unwrap();
    assert!(report
        .process_exit
        .as_ref()
        .is_some_and(|exit| exit.success));
    assert_eq!(report.audit_records[0].kind, AuditKind::SetupPlanCreated);
    assert!(report.audit_records.iter().any(|record| {
        record.kind == AuditKind::TunConfigured
            && record.details.get("fd_source").map(String::as_str) == Some("scm_rights")
    }));
    assert!(report.audit_records.iter().any(|record| {
        record.kind == AuditKind::TunConfigured
            && record.details.get("setup_phase").map(String::as_str)
                == Some("host_setup_control_handoff")
            && record.decision == Some(Decision::Allow)
    }));
    assert!(report.audit_records.iter().any(|record| {
        record.kind == AuditKind::TunConfigured
            && record.details.get("setup_phase").map(String::as_str) == Some("host_setup_process")
            && record.details.get("setup_status").map(String::as_str) == Some("complete")
    }));

    foxprox_device::set_fd_nonblocking(&received.fd, true).unwrap();
    let mut tun_file = std::fs::File::from(received.fd);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut observed_packets = Vec::new();
    let packet = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "target UDP send produces a matching TUN packet; observed {} other packets",
            observed_packets.len()
        );
        let mut packet = vec![0u8; 2048];
        let len = match tun_file.read(&mut packet) {
            Ok(len) => len,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => panic!("TUN packet read succeeds: {error}"),
        };
        packet.truncate(len);
        let ipv4_header_len = packet
            .first()
            .map(|first| ((first & 0x0f) as usize) * 4)
            .unwrap_or(0);
        let is_target_packet = packet.len() >= 20
            && packet.len() >= ipv4_header_len + 8
            && packet[0] >> 4 == 4
            && packet[9] == 17
            && packet[12..16] == [10, 0, 2, 15]
            && packet[16..20] == [198, 51, 100, 1]
            && u16::from_be_bytes([packet[ipv4_header_len + 2], packet[ipv4_header_len + 3]])
                == 443
            && packet
                .windows(b"foxprox-bwrap-e2e".len())
                .any(|window| window == b"foxprox-bwrap-e2e");
        if is_target_packet {
            break packet;
        }
        observed_packets.push(packet);
    };

    assert!(packet.len() >= 28, "packet too short: {}", packet.len());
    assert_eq!(packet[0] >> 4, 4, "expected IPv4 packet: {packet:02x?}");
    assert_eq!(packet[9], 17, "expected UDP packet: {packet:02x?}");
    assert_eq!(&packet[12..16], &[10, 0, 2, 15]);
    assert_eq!(&packet[16..20], &[198, 51, 100, 1]);
    let ipv4_header_len = ((packet[0] & 0x0f) as usize) * 4;
    assert_eq!(
        u16::from_be_bytes([packet[ipv4_header_len + 2], packet[ipv4_header_len + 3]]),
        443
    );
    assert!(packet
        .windows(b"foxprox-bwrap-e2e".len())
        .any(|window| window == b"foxprox-bwrap-e2e"));
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and real smoltcp runtime response"]
fn bwrap_foxproxsetup_received_tun_fd_drives_smoltcp_tcp_handshake() {
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let socket_path = std::env::temp_dir().join(format!(
        "foxprox-bwrap-smoltcp-e2e-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let mut config = NetworkSetupConfig::alpha_default(format!("bwrap-smoltcp-e2e-{unique}"));
    config.tun_name = format!("fxt{:x}", std::process::id() % 0x00ff_ffff);
    config.setup_control_socket_path = Some(socket_path.to_string_lossy().to_string());

    let target = vec![
        "python3".to_string(),
        "-c".to_string(),
        concat!(
            "import socket; ",
            "s=socket.create_connection((\"198.51.100.1\", 8080), 3.0); ",
            "s.close()"
        )
        .to_string(),
    ];
    let mut runner = RewritingBwrapRunner::new(setup_helper);
    let plan = BwrapSetupPlan::new(config.clone(), &target);
    runner.start_setup_process(&plan).unwrap();

    let mut handoff = accept_setup_control_tun_handoff_with_timeouts(
        &listener,
        config,
        &target,
        Some(Duration::from_secs(3)),
        Some(Duration::from_secs(3)),
    );
    let _ = std::fs::remove_file(&socket_path);
    assert_eq!(handoff.status, HostSetupControlHandoffStatus::Complete);
    let received = handoff.received.take().unwrap();
    foxprox_device::set_fd_nonblocking(&received.fd, true).unwrap();
    let (device, _handoff_report) = received.into_file_device(1500);

    let mut stack = foxprox_stack::SmoltcpIpStack::new_ipv4([198, 51, 100, 1], 24, 1500);
    stack.listen_tcp(8080, 1024, 1024);
    let policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    let broker = BrokerCore::new(PolicyEngine::new(policy), 32);
    let mut bridge =
        foxprox_stack::SmoltcpTunBridge::new("bwrap-smoltcp-e2e", broker, stack, device);

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut processed_packets = 0usize;
    while Instant::now() < deadline {
        let report = bridge.process_packet_loop(9_000, 4);
        assert_eq!(report.error, None);
        processed_packets += report.processed_packets;
        let wrote_smoltcp_response = bridge.broker().audit().records().any(|record| {
            record.kind == AuditKind::PacketObserved
                && record.details.get("stack").map(String::as_str) == Some("smoltcp")
                && record.details.get("direction").map(String::as_str) == Some("to_sandbox")
                && record.details.get("write_phase").map(String::as_str) == Some("attempt")
        });
        if wrote_smoltcp_response {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        processed_packets > 0,
        "smoltcp bridge processed target packets"
    );

    let exit = runner
        .wait_setup_process_with_timeout(Duration::from_secs(3))
        .expect("target process wait succeeds")
        .expect("target process exits after smoltcp handshake");
    assert!(exit.success, "target TCP connect completed: {exit:?}");

    let records: Vec<_> = bridge.broker().audit().records().collect();
    assert!(records.iter().any(|record| {
        record.kind == AuditKind::PacketObserved
            && record.protocol == Some(Protocol::Tcp)
            && record.details.get("stack").map(String::as_str) == Some("smoltcp")
            && record.details.get("direction").map(String::as_str) == Some("from_sandbox")
            && record
                .destination
                .as_ref()
                .and_then(|endpoint| endpoint.ip)
                .is_some_and(|ip| ip.to_string() == "198.51.100.1")
            && record
                .destination
                .as_ref()
                .and_then(|endpoint| endpoint.port)
                == Some(8080)
    }));
    assert!(records.iter().any(|record| {
        record.kind == AuditKind::PacketObserved
            && record.protocol == Some(Protocol::Tcp)
            && record.details.get("stack").map(String::as_str) == Some("smoltcp")
            && record.details.get("direction").map(String::as_str) == Some("to_sandbox")
            && record.details.get("write_phase").map(String::as_str) == Some("attempt")
            && record
                .source
                .as_ref()
                .and_then(|endpoint| endpoint.ip)
                .is_some_and(|ip| ip.to_string() == "198.51.100.1")
            && record.source.as_ref().and_then(|endpoint| endpoint.port) == Some(8080)
    }));
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and real host TCP egress"]
fn bwrap_foxproxsetup_received_tun_fd_bridges_tcp_bytes_to_host_socket() {
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let host_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host_addr = host_listener.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let host_server = std::thread::spawn(move || {
        let (mut stream, _) = host_listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(b"pong").unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        server_tx.send(request).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let socket_path = std::env::temp_dir().join(format!(
        "foxprox-bwrap-tcp-egress-e2e-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let mut config = NetworkSetupConfig::alpha_default(format!("bwrap-tcp-egress-e2e-{unique}"));
    config.tun_name = format!("fxe{:x}", std::process::id() % 0x00ff_ffff);
    config.setup_control_socket_path = Some(socket_path.to_string_lossy().to_string());

    let target = vec![
        "python3".to_string(),
        "-c".to_string(),
        concat!(
            "import socket; ",
            "s=socket.create_connection((\"198.51.100.1\", 8080), 3.0); ",
            "s.sendall(b\"ping\"); ",
            "data=s.recv(4); ",
            "assert data == b\"pong\", data; ",
            "s.close()"
        )
        .to_string(),
    ];
    let mut runner = RewritingBwrapRunner::new(setup_helper);
    let plan = BwrapSetupPlan::new(config.clone(), &target);
    runner.start_setup_process(&plan).unwrap();

    let mut handoff = accept_setup_control_tun_handoff_with_timeouts(
        &listener,
        config,
        &target,
        Some(Duration::from_secs(3)),
        Some(Duration::from_secs(3)),
    );
    let _ = std::fs::remove_file(&socket_path);
    assert_eq!(handoff.status, HostSetupControlHandoffStatus::Complete);
    let received = handoff.received.take().unwrap();

    let mut stack = foxprox_stack::SmoltcpIpStack::new_ipv4([198, 51, 100, 1], 24, 1500);
    stack.listen_tcp(8080, 4096, 4096);
    let policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    let broker = BrokerCore::new(PolicyEngine::new(policy), 128);
    let egress = foxprox_egress::BlockingTcpEgress::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        1024,
    );
    let mut fan_in = RuntimeAuditFanIn::new("bwrap-tcp-egress-e2e", 256);
    let mut audit_output = Vec::new();
    let mut sink = JsonLineAuditSink::new(&mut audit_output);
    let cancellation = foxprox_egress::AsyncRuntimeCancellationToken::uncancelled();
    let report = foxprox_egress::run_received_tun_fd_smoltcp_tcp_egress_and_drain(
        foxprox_egress::ReceivedTunSmoltcpTcpEgressSession {
            setup_source: "host_setup_session".to_string(),
            setup_records: &handoff.audit_records,
            received,
            sandbox_id: "bwrap-tcp-egress-e2e".to_string(),
            broker,
            stack,
            egress,
            egress_destination: NetworkEndpoint::socket(host_addr.ip(), host_addr.port()),
            now_ms: 10_000,
            max_packets_per_attempt: 8,
            max_attempts: 300,
            max_from_sandbox_bytes: 1024,
            attempt_sleep: Duration::from_millis(10),
        },
        &mut fan_in,
        &mut sink,
        &cancellation,
    )
    .expect("received TUN fd bridges TCP bytes to host socket");

    assert!(report.tcp_bridge.opened_egress, "{report:?}");
    assert_eq!(report.tcp_bridge.byte_counts.from_sandbox, 4);
    assert_eq!(report.tcp_bridge.byte_counts.to_sandbox, 4);
    let host_request = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("host socket receives sandbox bytes");
    assert_eq!(host_request, b"ping");
    host_server.join().unwrap();

    let exit = runner
        .wait_setup_process_with_timeout(Duration::from_secs(3))
        .expect("target process wait succeeds")
        .expect("target process exits after TCP egress response");
    assert!(exit.success, "target exchanged TCP bytes: {exit:?}");

    let audit_text = String::from_utf8(audit_output).unwrap();
    assert!(audit_text.contains("tcp_flow_closed"), "{audit_text}");
    assert!(audit_text.contains("smoltcp"), "{audit_text}");
    assert!(audit_text.contains("from_sandbox"), "{audit_text}");
    assert!(audit_text.contains("to_sandbox"), "{audit_text}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and foxprox launcher TCP egress"]
fn foxprox_run_bwrap_tcp_egress_command_bridges_target_bytes() {
    let foxprox = env!("CARGO_BIN_EXE_foxprox");
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(foxprox).exists());
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let host_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host_addr = host_listener.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let host_server = std::thread::spawn(move || {
        let (mut stream, _) = host_listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(b"pong").unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        server_tx.send(request).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("foxprox-run-bwrap-tcp-egress-{unique}.json"));
    let mut config = BrokerRuntimeConfig::alpha_default(format!("foxprox-cli-e2e-{unique}"));
    config.setup.tun_name = format!("fxc{:x}", std::process::id() % 0x00ff_ffff);
    config.policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let target = [
        "python3",
        "-c",
        concat!(
            "import socket; ",
            "s=socket.create_connection((\"198.51.100.1\", 8080), 3.0); ",
            "s.sendall(b\"ping\"); ",
            "data=s.recv(4); ",
            "assert data == b\"pong\", data; ",
            "s.close()"
        ),
    ];
    let setup_dir = std::path::Path::new(setup_helper).parent().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", setup_dir.display(), path.to_string_lossy());
    let output = Command::new(foxprox)
        .env("PATH", path)
        .arg("run-bwrap-tcp-egress")
        .arg(&config_path)
        .arg("198.51.100.1:8080")
        .arg(host_addr.to_string())
        .arg("--")
        .args(target)
        .output()
        .expect("foxprox launcher command runs");
    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let host_request = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("host socket receives bytes through CLI launcher");
    assert_eq!(host_request, b"ping");
    host_server.join().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("tcp_flow_closed"), "{stdout}");
    assert!(stdout.contains("smoltcp"), "{stdout}");
    assert!(stdout.contains("host_setup_control_handoff"), "{stdout}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and real UDP egress"]
fn bwrap_foxproxsetup_received_tun_fd_bridges_udp_datagram_to_host_socket() {
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let host_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_addr = host_socket.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let host_server = std::thread::spawn(move || {
        let mut request = [0u8; 128];
        let (len, peer) = host_socket.recv_from(&mut request).unwrap();
        host_socket.send_to(b"pong", peer).unwrap();
        server_tx.send(request[..len].to_vec()).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let socket_path = std::env::temp_dir().join(format!(
        "foxprox-bwrap-udp-egress-e2e-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let mut config = NetworkSetupConfig::alpha_default(format!("bwrap-udp-egress-e2e-{unique}"));
    config.tun_name = format!("fxu{:x}", std::process::id() % 0x00ff_ffff);
    config.setup_control_socket_path = Some(socket_path.to_string_lossy().to_string());

    let target = vec![
        "python3".to_string(),
        "-c".to_string(),
        concat!(
            "import socket; ",
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ",
            "s.settimeout(3.0); ",
            "s.sendto(b\"ping\", (\"198.51.100.1\", 5353)); ",
            "data,_=s.recvfrom(4); ",
            "assert data == b\"pong\", data; ",
            "s.close()"
        )
        .to_string(),
    ];
    let mut runner = RewritingBwrapRunner::new(setup_helper);
    let plan = BwrapSetupPlan::new(config.clone(), &target);
    runner.start_setup_process(&plan).unwrap();

    let mut handoff = accept_setup_control_tun_handoff_with_timeouts(
        &listener,
        config,
        &target,
        Some(Duration::from_secs(3)),
        Some(Duration::from_secs(3)),
    );
    let _ = std::fs::remove_file(&socket_path);
    assert_eq!(handoff.status, HostSetupControlHandoffStatus::Complete);
    let received = handoff.received.take().unwrap();

    let stack = foxprox_stack::SmoltcpIpStack::new_ipv4([198, 51, 100, 1], 24, 1500);
    let policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    let broker = BrokerCore::new(PolicyEngine::new(policy), 128);
    let egress =
        foxprox_egress::BlockingMappedUdpExchange::new(host_addr, Duration::from_secs(1), 1024);
    let mut fan_in = RuntimeAuditFanIn::new("bwrap-udp-egress-e2e", 256);
    let mut audit_output = Vec::new();
    let mut sink = JsonLineAuditSink::new(&mut audit_output);
    let cancellation = foxprox_egress::AsyncRuntimeCancellationToken::uncancelled();
    let report = foxprox_egress::run_received_tun_fd_udp_exchange_and_drain(
        foxprox_egress::ReceivedTunUdpExchangeSession {
            setup_source: "host_setup_session".to_string(),
            setup_records: &handoff.audit_records,
            received,
            sandbox_id: "bwrap-udp-egress-e2e".to_string(),
            broker,
            stack,
            egress,
            now_ms: 20_000,
            max_attempts: 300,
            attempt_sleep: Duration::from_millis(10),
        },
        &mut fan_in,
        &mut sink,
        &cancellation,
    )
    .expect("received TUN fd bridges UDP datagram to host socket");

    assert!(report.udp_bridge.exchanged, "{report:?}");
    assert_eq!(report.udp_bridge.byte_counts.from_sandbox, 4);
    assert_eq!(report.udp_bridge.byte_counts.to_sandbox, 4);
    let host_request = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("host UDP socket receives sandbox datagram");
    assert_eq!(host_request, b"ping");
    host_server.join().unwrap();

    let exit = runner
        .wait_setup_process_with_timeout(Duration::from_secs(3))
        .expect("target process wait succeeds")
        .expect("target process exits after UDP response");
    assert!(exit.success, "target exchanged UDP datagram: {exit:?}");

    let audit_text = String::from_utf8(audit_output).unwrap();
    assert!(audit_text.contains("udp_exchange"), "{audit_text}");
    assert!(audit_text.contains("from_sandbox"), "{audit_text}");
    assert!(audit_text.contains("to_sandbox"), "{audit_text}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and foxprox launcher UDP egress"]
fn foxprox_run_bwrap_udp_egress_command_bridges_target_datagram() {
    let foxprox = env!("CARGO_BIN_EXE_foxprox");
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(foxprox).exists());
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let host_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_addr = host_socket.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let host_server = std::thread::spawn(move || {
        let mut request = [0u8; 128];
        let (len, peer) = host_socket.recv_from(&mut request).unwrap();
        host_socket.send_to(b"pong", peer).unwrap();
        server_tx.send(request[..len].to_vec()).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("foxprox-run-bwrap-udp-egress-{unique}.json"));
    let mut config = BrokerRuntimeConfig::alpha_default(format!("foxprox-udp-cli-e2e-{unique}"));
    config.setup.tun_name = format!("fxd{:x}", std::process::id() % 0x00ff_ffff);
    config.policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let target = [
        "python3",
        "-c",
        concat!(
            "import socket; ",
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ",
            "s.settimeout(3.0); ",
            "s.sendto(b\"ping\", (\"198.51.100.1\", 5353)); ",
            "data,_=s.recvfrom(4); ",
            "assert data == b\"pong\", data; ",
            "s.close()"
        ),
    ];
    let setup_dir = std::path::Path::new(setup_helper).parent().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", setup_dir.display(), path.to_string_lossy());
    let output = Command::new(foxprox)
        .env("PATH", path)
        .arg("run-bwrap-udp-egress")
        .arg(&config_path)
        .arg(host_addr.to_string())
        .arg("--")
        .args(target)
        .output()
        .expect("foxprox UDP launcher command runs");
    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let host_request = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("host UDP socket receives datagram through CLI launcher");
    assert_eq!(host_request, b"ping");
    host_server.join().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("udp_exchange"), "{stdout}");
    assert!(stdout.contains("host_setup_control_handoff"), "{stdout}");
    assert!(stdout.contains("to_sandbox"), "{stdout}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and foxprox launcher DNS egress"]
fn foxprox_run_bwrap_dns_egress_command_answers_target_query() {
    let foxprox = env!("CARGO_BIN_EXE_foxprox");
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(foxprox).exists());
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let upstream_server = std::thread::spawn(move || {
        let mut query = [0u8; 512];
        let (len, peer) = upstream.recv_from(&mut query).unwrap();
        let query = query[..len].to_vec();
        let response = dns_a_response(&query, [203, 0, 113, 7]);
        upstream.send_to(&response, peer).unwrap();
        server_tx.send(query).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("foxprox-run-bwrap-dns-egress-{unique}.json"));
    let mut config = BrokerRuntimeConfig::alpha_default(format!("foxprox-dns-cli-e2e-{unique}"));
    config.setup.tun_name = format!("fxn{:x}", std::process::id() % 0x00ff_ffff);
    config.dns_upstream = upstream_addr;
    config.policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let target = [
        "python3",
        "-c",
        concat!(
            "import socket; ",
            "q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + b'\\x07example\\x04test\\x00' + b'\\x00\\x01\\x00\\x01'; ",
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ",
            "s.settimeout(3.0); ",
            "s.sendto(q, (\"10.0.2.3\", 53)); ",
            "data,_=s.recvfrom(512); ",
            "assert b'\\xcb\\x00\\x71\\x07' in data, data.hex(); ",
            "s.close()"
        ),
    ];
    let setup_dir = std::path::Path::new(setup_helper).parent().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", setup_dir.display(), path.to_string_lossy());
    let output = Command::new(foxprox)
        .env("PATH", path)
        .arg("run-bwrap-dns-egress")
        .arg(&config_path)
        .arg("--")
        .args(target)
        .output()
        .expect("foxprox DNS launcher command runs");
    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let upstream_query = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("upstream receives DNS query through launcher");
    assert!(upstream_query
        .windows(b"example".len())
        .any(|w| w == b"example"));
    upstream_server.join().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dns_query"), "{stdout}");
    assert!(stdout.contains("returned_addresses"), "{stdout}");
    assert!(stdout.contains("to_sandbox"), "{stdout}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and combined foxprox alpha launcher"]
fn foxprox_run_bwrap_alpha_command_answers_dns_query() {
    let foxprox = env!("CARGO_BIN_EXE_foxprox");
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(foxprox).exists());
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let upstream_server = std::thread::spawn(move || {
        let mut query = [0u8; 512];
        let (len, peer) = upstream.recv_from(&mut query).unwrap();
        let query = query[..len].to_vec();
        let response = dns_a_response(&query, [203, 0, 113, 8]);
        upstream.send_to(&response, peer).unwrap();
        server_tx.send(query).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!("foxprox-run-bwrap-alpha-{unique}.json"));
    let mut config = BrokerRuntimeConfig::alpha_default(format!("foxprox-alpha-cli-e2e-{unique}"));
    config.setup.tun_name = format!("fxa{:x}", std::process::id() % 0x00ff_ffff);
    config.dns_upstream = upstream_addr;
    config.policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let target = [
        "python3",
        "-c",
        concat!(
            "import socket; ",
            "q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + b'\\x07example\\x04test\\x00' + b'\\x00\\x01\\x00\\x01'; ",
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ",
            "s.settimeout(3.0); ",
            "s.sendto(q, (\"10.0.2.3\", 53)); ",
            "data,_=s.recvfrom(512); ",
            "assert b'\\xcb\\x00\\x71\\x08' in data, data.hex(); ",
            "s.close()"
        ),
    ];
    let setup_dir = std::path::Path::new(setup_helper).parent().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", setup_dir.display(), path.to_string_lossy());
    let output = Command::new(foxprox)
        .env("PATH", path)
        .arg("run-bwrap-alpha")
        .arg(&config_path)
        .arg("--")
        .args(target)
        .output()
        .expect("foxprox alpha launcher command runs");
    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let upstream_query = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("upstream receives DNS query through alpha launcher");
    assert!(upstream_query
        .windows(b"example".len())
        .any(|w| w == b"example"));
    upstream_server.join().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dns_query"), "{stdout}");
    assert!(stdout.contains("returned_addresses"), "{stdout}");
    assert!(stdout.contains("to_sandbox"), "{stdout}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and combined foxprox alpha transparent TCP"]
fn foxprox_run_bwrap_alpha_command_bridges_transparent_tcp() {
    let foxprox = env!("CARGO_BIN_EXE_foxprox");
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(foxprox).exists());
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let host_ip = host_primary_ipv4();
    let host_listener = TcpListener::bind((host_ip, 0)).unwrap();
    let host_addr = host_listener.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let host_server = std::thread::spawn(move || {
        let (mut stream, peer) = host_listener.accept().unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).unwrap();
        stream.write_all(b"pong").unwrap();
        server_tx.send((peer, request)).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("foxprox-run-bwrap-alpha-tcp-{unique}.json"));
    let mut config = BrokerRuntimeConfig::alpha_default(format!("foxprox-alpha-tcp-e2e-{unique}"));
    config.setup.tun_name = format!("fxt{:x}", std::process::id() % 0x00ff_ffff);
    config.policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let script = format!(
        concat!(
            "import socket; ",
            "s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); ",
            "s.settimeout(5.0); ",
            "s.connect(({host:?}, {port})); ",
            "s.sendall(b'ping'); ",
            "data=s.recv(4); ",
            "assert data == b'pong', data; ",
            "s.close()"
        ),
        host = host_addr.ip().to_string(),
        port = host_addr.port()
    );
    let setup_dir = std::path::Path::new(setup_helper).parent().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", setup_dir.display(), path.to_string_lossy());
    let output = Command::new(foxprox)
        .env("PATH", path)
        .arg("run-bwrap-alpha")
        .arg(&config_path)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("foxprox alpha TCP launcher command runs");
    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let (_peer, request) = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("host TCP listener receives bytes through alpha launcher");
    assert_eq!(&request, b"ping");
    host_server.join().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("tcp_connect"), "{stdout}");
    assert!(stdout.contains("tcp_flow_closed"), "{stdout}");
    assert!(stdout.contains(&host_addr.ip().to_string()), "{stdout}");
}

#[test]
#[ignore = "requires rootless bwrap, /dev/net/tun, CAP_NET_ADMIN inside bwrap, and combined foxprox alpha transparent UDP"]
fn foxprox_run_bwrap_alpha_command_bridges_transparent_udp() {
    let foxprox = env!("CARGO_BIN_EXE_foxprox");
    let setup_helper = env!("CARGO_BIN_EXE_foxproxsetup");
    assert!(std::path::Path::new(foxprox).exists());
    assert!(std::path::Path::new(setup_helper).exists());
    assert!(std::path::Path::new("/dev/net/tun").exists());

    let host_ip = host_primary_ipv4();
    let host_socket = std::net::UdpSocket::bind((host_ip, 0)).unwrap();
    let host_addr = host_socket.local_addr().unwrap();
    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let host_server = std::thread::spawn(move || {
        let mut request = [0u8; 64];
        let (len, peer) = host_socket.recv_from(&mut request).unwrap();
        host_socket.send_to(b"pong", peer).unwrap();
        server_tx.send((peer, request[..len].to_vec())).unwrap();
    });

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("foxprox-run-bwrap-alpha-udp-{unique}.json"));
    let mut config = BrokerRuntimeConfig::alpha_default(format!("foxprox-alpha-udp-e2e-{unique}"));
    config.setup.tun_name = format!("fxu{:x}", std::process::id() % 0x00ff_ffff);
    config.policy = PolicyConfig {
        default_decision: Decision::Allow,
        ..PolicyConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();

    let script = format!(
        concat!(
            "import socket; ",
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ",
            "s.settimeout(5.0); ",
            "s.sendto(b'ping', ({host:?}, {port})); ",
            "data,_=s.recvfrom(64); ",
            "assert data == b'pong', data; ",
            "s.close()"
        ),
        host = host_addr.ip().to_string(),
        port = host_addr.port()
    );
    let setup_dir = std::path::Path::new(setup_helper).parent().unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", setup_dir.display(), path.to_string_lossy());
    let output = Command::new(foxprox)
        .env("PATH", path)
        .arg("run-bwrap-alpha")
        .arg(&config_path)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("foxprox alpha UDP launcher command runs");
    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let (_peer, request) = server_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("host UDP socket receives datagram through alpha launcher");
    assert_eq!(request, b"ping");
    host_server.join().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("udp_exchange"), "{stdout}");
    assert!(stdout.contains("to_sandbox"), "{stdout}");
    assert!(stdout.contains(&host_addr.ip().to_string()), "{stdout}");
}

fn host_primary_ipv4() -> std::net::Ipv4Addr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("1.1.1.1:53").unwrap();
    match socket.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => panic!("expected IPv4 primary address"),
    }
}

fn dns_a_response(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    assert!(query.len() >= 12);
    let mut question_end = 12;
    while question_end < query.len() && query[question_end] != 0 {
        question_end += query[question_end] as usize + 1;
    }
    question_end += 5;
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
    response.extend_from_slice(&60u32.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x04]);
    response.extend_from_slice(&ip);
    response
}
