#![cfg(unix)]

use foxprox_cli::{
    accept_setup_control_tun_handoff_with_timeouts, run_host_setup_control_session_with_runner,
    HostSetupControlHandoffStatus, HostSetupProcessExit, HostSetupProcessRunner,
};
use foxprox_core::{
    AuditKind, BrokerCore, BwrapSetupPlan, Decision, NetworkSetupConfig, PolicyConfig,
    PolicyEngine, Protocol,
};
use std::io::{ErrorKind, Read};
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
