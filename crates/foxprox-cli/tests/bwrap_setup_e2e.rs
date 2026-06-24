#![cfg(unix)]

use foxprox_cli::{
    run_host_setup_control_session_with_runner, HostSetupControlHandoffStatus,
    HostSetupProcessExit, HostSetupProcessRunner,
};
use foxprox_core::{AuditKind, BwrapSetupPlan, Decision, NetworkSetupConfig};
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    let mut tun_file = std::fs::File::from(received.fd);
    let (packet_tx, packet_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || loop {
        let mut packet = vec![0u8; 2048];
        let result = tun_file.read(&mut packet).map(|len| {
            packet.truncate(len);
            packet
        });
        let should_continue = result.is_ok();
        if packet_tx.send(result).is_err() || !should_continue {
            break;
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut observed_packets = Vec::new();
    let packet = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let packet = packet_rx
            .recv_timeout(remaining)
            .expect("target UDP send produces a matching TUN packet")
            .expect("TUN packet read succeeds");
        let is_target_packet = packet.len() >= 28
            && packet[0] >> 4 == 4
            && packet[9] == 17
            && packet[12..16] == [10, 0, 2, 15]
            && packet[16..20] == [198, 51, 100, 1]
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
    assert!(packet
        .windows(b"foxprox-bwrap-e2e".len())
        .any(|window| window == b"foxprox-bwrap-e2e"));
}
