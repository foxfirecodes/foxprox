#![cfg(unix)]

use foxprox_cli::{
    run_host_setup_control_session_with_runner, HostSetupControlHandoffStatus,
    HostSetupProcessExit, HostSetupProcessRunner,
};
use foxprox_core::{AuditKind, BwrapSetupPlan, Decision, NetworkSetupConfig};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
        "cap=$(awk '/CapEff/ {print $2}' /proc/self/status); test \"$cap\" = 0000000000000000"
            .to_string(),
    ];
    let mut runner = RewritingBwrapRunner::new(setup_helper);

    let report =
        run_host_setup_control_session_with_runner(&listener, config, &target, &mut runner);
    let _ = std::fs::remove_file(&socket_path);

    assert_eq!(report.status, HostSetupControlHandoffStatus::Complete);
    assert!(report.handoff.received.is_some());
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
}
