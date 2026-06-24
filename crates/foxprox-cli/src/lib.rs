use foxprox_core::{
    AuditKind, AuditRecord, BrokerRuntimeConfig, BwrapSetupPlan, Decision, DenialReason, Frontend,
    NetworkSetupConfig, SetupHelperPlan, SetupHelperStep,
};
use serde_json::json;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
use foxprox_device::{execute_tun_setup_handoff, TunSetupDeviceOps, TunSetupHandoffStatus};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_args(args: &[String]) -> CliOutput {
    if args.first().is_some_and(|command| command == "plan-bwrap") {
        return plan_bwrap_args(&args[1..]);
    }
    match args {
        [command, path] if command == "validate-config" => validate_config_path(path),
        [command, sandbox_id] if command == "default-config" => default_config(sandbox_id),
        _ => usage_output(),
    }
}

pub fn run_foxproxsetup_entry_args(args: &[String]) -> CliOutput {
    if let Some(setup_args) = strip_execute_setup_flag(args) {
        return run_foxproxsetup_execute_setup_args(&setup_args);
    }
    run_foxproxsetup_args(args)
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn run_foxproxsetup_execute_setup_args(args: &[String]) -> CliOutput {
    run_foxproxsetup_linux_execute_setup_connecting(args)
}

#[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
fn run_foxproxsetup_execute_setup_args(_args: &[String]) -> CliOutput {
    error_output(
        "setup_execute_unsupported_platform",
        "foxproxsetup --execute-setup requires Linux TUN support".to_string(),
    )
}

#[cfg(unix)]
pub fn run_foxproxsetup_entry_args_with_ops<O: TunSetupDeviceOps>(
    args: &[String],
    ops: &mut O,
) -> CliOutput {
    if let Some(setup_args) = strip_execute_setup_flag(args) {
        return run_foxproxsetup_handoff_connecting_with_ops(&setup_args, ops);
    }
    run_foxproxsetup_args(args)
}

#[cfg(unix)]
pub fn run_foxproxsetup_entry_args_with_ops_and_runner<
    O: TunSetupDeviceOps,
    R: SandboxSetupCommandRunner + PostSetupLifecycleRunner,
>(
    args: &[String],
    ops: &mut O,
    runner: &mut R,
) -> CliOutput {
    if let Some(setup_args) = strip_execute_setup_flag(args) {
        return run_foxproxsetup_execute_setup_connecting_with_ops_and_runner(
            &setup_args,
            ops,
            runner,
        );
    }
    run_foxproxsetup_args(args)
}

fn strip_execute_setup_flag(args: &[String]) -> Option<Vec<String>> {
    if args.first().is_some_and(|arg| arg == "--execute-setup") {
        Some(args[1..].to_vec())
    } else {
        None
    }
}

pub fn run_foxproxsetup_args(args: &[String]) -> CliOutput {
    let (config, target) = match parse_foxproxsetup_invocation(args) {
        Ok(invocation) => invocation,
        Err((code, detail)) => return error_output(code, detail),
    };
    let plan = SetupHelperPlan::new(config, &target);
    let output = json!({
        "plan": plan,
        "audit": plan.audit_record(),
    });
    json_output(0, "setup_serialize_error", output)
}

#[cfg(unix)]
pub fn run_foxproxsetup_handoff_with_ops<O: TunSetupDeviceOps>(
    args: &[String],
    control: &UnixStream,
    ops: &mut O,
) -> CliOutput {
    let (config, target) = match parse_foxproxsetup_invocation(args) {
        Ok(invocation) => invocation,
        Err((code, detail)) => return error_output(code, detail),
    };
    if config.setup_control_fd.is_none() && config.setup_control_socket_path.is_none() {
        return error_output(
            "setup_missing_control_channel",
            "expected --setup-control-fd or --setup-control-socket for TUN handoff execution"
                .to_string(),
        );
    }

    run_foxproxsetup_handoff_with_config(config, target, control, ops)
}

#[cfg(unix)]
pub fn run_foxproxsetup_handoff_connecting_with_ops<O: TunSetupDeviceOps>(
    args: &[String],
    ops: &mut O,
) -> CliOutput {
    let (config, target) = match parse_foxproxsetup_invocation(args) {
        Ok(invocation) => invocation,
        Err((code, detail)) => return error_output(code, detail),
    };
    let Some(path) = config.setup_control_socket_path.clone() else {
        return error_output(
            "setup_missing_control_socket",
            "expected --setup-control-socket for safe TUN handoff execution".to_string(),
        );
    };
    let control = match UnixStream::connect(&path) {
        Ok(control) => control,
        Err(error) => {
            return error_output(
                "setup_control_socket_connect_error",
                format!("{path}: {error}"),
            )
        }
    };
    run_foxproxsetup_handoff_with_config(config, target, &control, ops)
}

#[cfg(unix)]
fn run_foxproxsetup_handoff_with_config<O: TunSetupDeviceOps>(
    config: NetworkSetupConfig,
    target: Vec<String>,
    control: &UnixStream,
    ops: &mut O,
) -> CliOutput {
    let report = execute_tun_setup_handoff(ops, control, &config);
    let audit_records = report.audit_records_with_summary(config.sandbox_id.clone());
    let exit_code = if report.status == TunSetupHandoffStatus::Complete {
        0
    } else {
        2
    };
    let output = json!({
        "setup": {
            "status": match report.status {
                TunSetupHandoffStatus::Complete => "complete",
                TunSetupHandoffStatus::Failed => "failed",
            },
            "completed_steps": report.completed_steps,
            "failed_step": report.failed_step,
        },
        "audit": audit_records,
        "proxy_environment": config.proxy_environment(),
        "target_command": target,
    });
    json_output(exit_code, "setup_execute_serialize_error", output)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSetupControlHandoffStatus {
    Complete,
    Failed,
}

#[cfg(unix)]
#[derive(Debug)]
pub struct HostSetupControlHandoffReport {
    pub status: HostSetupControlHandoffStatus,
    pub plan: BwrapSetupPlan,
    pub received: Option<foxprox_device::ReceivedTunFd>,
    pub failed_report: Option<foxprox_device::TunFdHandoffReport>,
    pub audit_records: Vec<AuditRecord>,
}

#[cfg(unix)]
pub fn accept_setup_control_tun_handoff(
    listener: &UnixListener,
    mut config: NetworkSetupConfig,
    target: &[String],
) -> HostSetupControlHandoffReport {
    if config.setup_control_socket_path.is_none() {
        let local_path = listener
            .local_addr()
            .ok()
            .and_then(|addr| addr.as_pathname().map(|path| path.display().to_string()));
        config.setup_control_socket_path = local_path;
    }
    let plan = BwrapSetupPlan::new(config.clone(), target);
    let mut audit_records = vec![plan.audit_record()];
    let (stream, _) = match listener.accept() {
        Ok(accepted) => accepted,
        Err(error) => {
            audit_records.push(
                AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
                    .with_frontend(Frontend::Setup)
                    .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                    .with_detail("setup_phase", "host_setup_control_handoff")
                    .with_detail("setup_status", "failed")
                    .with_detail("setup_error", error.to_string()),
            );
            return HostSetupControlHandoffReport {
                status: HostSetupControlHandoffStatus::Failed,
                plan,
                received: None,
                failed_report: None,
                audit_records,
            };
        }
    };
    match foxprox_device::recv_tun_fd(&stream, &config.tun_name) {
        Ok(received) => {
            audit_records.push(received.report.audit_record(config.sandbox_id.clone()));
            audit_records.push(
                AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
                    .with_frontend(Frontend::Setup)
                    .with_decision(Decision::Allow, None)
                    .with_detail("setup_phase", "host_setup_control_handoff")
                    .with_detail("setup_status", "complete")
                    .with_detail("tun_name", config.tun_name.clone())
                    .with_detail(
                        "setup_control_socket",
                        config.setup_control_socket_path.unwrap_or_default(),
                    ),
            );
            HostSetupControlHandoffReport {
                status: HostSetupControlHandoffStatus::Complete,
                plan,
                received: Some(received),
                failed_report: None,
                audit_records,
            }
        }
        Err(report) => {
            audit_records.push(report.audit_record(config.sandbox_id.clone()));
            HostSetupControlHandoffReport {
                status: HostSetupControlHandoffStatus::Failed,
                plan,
                received: None,
                failed_report: Some(report),
                audit_records,
            }
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSetupProcessExit {
    pub exit_code: Option<i32>,
    pub success: bool,
}

#[cfg(unix)]
pub trait HostSetupProcessRunner {
    fn start_setup_process(&mut self, plan: &BwrapSetupPlan) -> Result<(), String>;
    fn poll_setup_process(&mut self) -> Result<Option<HostSetupProcessExit>, String> {
        Ok(None)
    }
    fn wait_setup_process(&mut self) -> Result<HostSetupProcessExit, String>;
}

#[cfg(unix)]
#[derive(Debug)]
pub struct CommandHostSetupProcessRunner {
    child: Option<std::process::Child>,
}

#[cfg(unix)]
impl CommandHostSetupProcessRunner {
    pub fn new() -> Self {
        Self { child: None }
    }
}

#[cfg(unix)]
impl Default for CommandHostSetupProcessRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl HostSetupProcessRunner for CommandHostSetupProcessRunner {
    fn start_setup_process(&mut self, plan: &BwrapSetupPlan) -> Result<(), String> {
        if self.child.is_some() {
            return Err("setup process already started".to_string());
        }
        let command = plan.full_command();
        let Some((program, args)) = command.split_first() else {
            return Err("empty setup command".to_string());
        };
        let child = Command::new(program)
            .args(args)
            .spawn()
            .map_err(|error| error.to_string())?;
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

#[cfg(unix)]
#[derive(Debug)]
pub struct HostSetupSessionReport {
    pub status: HostSetupControlHandoffStatus,
    pub handoff: HostSetupControlHandoffReport,
    pub process_exit: Option<HostSetupProcessExit>,
    pub audit_records: Vec<AuditRecord>,
}

#[cfg(unix)]
pub fn run_host_setup_control_session_with_runner<R: HostSetupProcessRunner>(
    listener: &UnixListener,
    config: NetworkSetupConfig,
    target: &[String],
    runner: &mut R,
) -> HostSetupSessionReport {
    run_host_setup_control_session_with_runner_and_timeouts(
        listener,
        config,
        target,
        runner,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
}

#[cfg(unix)]
fn run_host_setup_control_session_with_runner_and_timeouts<R: HostSetupProcessRunner>(
    listener: &UnixListener,
    mut config: NetworkSetupConfig,
    target: &[String],
    runner: &mut R,
    accept_timeout: Duration,
    read_timeout: Duration,
) -> HostSetupSessionReport {
    if config.setup_control_socket_path.is_none() {
        config.setup_control_socket_path = listener
            .local_addr()
            .ok()
            .and_then(|addr| addr.as_pathname().map(|path| path.display().to_string()));
    }
    let plan = BwrapSetupPlan::new(config.clone(), target);
    let mut audit_records = vec![plan.audit_record()];
    if let Err(error) = runner.start_setup_process(&plan) {
        audit_records.push(host_setup_process_failure_audit(
            &config,
            "start_setup_process",
            error,
        ));
        let handoff = HostSetupControlHandoffReport {
            status: HostSetupControlHandoffStatus::Failed,
            plan,
            received: None,
            failed_report: None,
            audit_records: audit_records.clone(),
        };
        return HostSetupSessionReport {
            status: HostSetupControlHandoffStatus::Failed,
            audit_records,
            handoff,
            process_exit: None,
        };
    }

    if let Err(error) = listener.set_nonblocking(true) {
        audit_records.push(host_setup_process_failure_audit(
            &config,
            "prepare_setup_control_accept",
            error.to_string(),
        ));
        let handoff = HostSetupControlHandoffReport {
            status: HostSetupControlHandoffStatus::Failed,
            plan,
            received: None,
            failed_report: None,
            audit_records: audit_records.clone(),
        };
        return HostSetupSessionReport {
            status: HostSetupControlHandoffStatus::Failed,
            audit_records,
            handoff,
            process_exit: None,
        };
    }

    let accept_started = Instant::now();
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                match runner.poll_setup_process() {
                    Ok(Some(exit)) => {
                        let _ = listener.set_nonblocking(false);
                        audit_records.push(host_setup_process_failure_audit(
                            &config,
                            "setup_control_handoff",
                            format!(
                                "setup process exited before fd handoff with code {:?}",
                                exit.exit_code
                            ),
                        ));
                        let handoff = HostSetupControlHandoffReport {
                            status: HostSetupControlHandoffStatus::Failed,
                            plan,
                            received: None,
                            failed_report: None,
                            audit_records: audit_records.clone(),
                        };
                        return HostSetupSessionReport {
                            status: HostSetupControlHandoffStatus::Failed,
                            handoff,
                            process_exit: Some(exit),
                            audit_records,
                        };
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = listener.set_nonblocking(false);
                        audit_records.push(host_setup_process_failure_audit(
                            &config,
                            "poll_setup_process",
                            error,
                        ));
                        let handoff = HostSetupControlHandoffReport {
                            status: HostSetupControlHandoffStatus::Failed,
                            plan,
                            received: None,
                            failed_report: None,
                            audit_records: audit_records.clone(),
                        };
                        return HostSetupSessionReport {
                            status: HostSetupControlHandoffStatus::Failed,
                            handoff,
                            process_exit: None,
                            audit_records,
                        };
                    }
                }
                if accept_started.elapsed() >= accept_timeout {
                    let _ = listener.set_nonblocking(false);
                    audit_records.push(host_setup_process_failure_audit(
                        &config,
                        "setup_control_handoff",
                        "timed out waiting for setup-control fd handoff".to_string(),
                    ));
                    let process_exit = runner.poll_setup_process().ok().flatten();
                    let handoff = HostSetupControlHandoffReport {
                        status: HostSetupControlHandoffStatus::Failed,
                        plan,
                        received: None,
                        failed_report: None,
                        audit_records: audit_records.clone(),
                    };
                    return HostSetupSessionReport {
                        status: HostSetupControlHandoffStatus::Failed,
                        handoff,
                        process_exit,
                        audit_records,
                    };
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = listener.set_nonblocking(false);
                audit_records.push(
                    AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
                        .with_frontend(Frontend::Setup)
                        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                        .with_detail("setup_phase", "host_setup_control_handoff")
                        .with_detail("setup_status", "failed")
                        .with_detail("setup_error", error.to_string()),
                );
                let handoff = HostSetupControlHandoffReport {
                    status: HostSetupControlHandoffStatus::Failed,
                    plan,
                    received: None,
                    failed_report: None,
                    audit_records: audit_records.clone(),
                };
                return HostSetupSessionReport {
                    status: HostSetupControlHandoffStatus::Failed,
                    handoff,
                    process_exit: None,
                    audit_records,
                };
            }
        }
    };
    let _ = listener.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(read_timeout));

    let mut handoff = match foxprox_device::recv_tun_fd(&stream, &config.tun_name) {
        Ok(received) => {
            audit_records.push(received.report.audit_record(config.sandbox_id.clone()));
            audit_records.push(
                AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
                    .with_frontend(Frontend::Setup)
                    .with_decision(Decision::Allow, None)
                    .with_detail("setup_phase", "host_setup_control_handoff")
                    .with_detail("setup_status", "complete")
                    .with_detail("tun_name", config.tun_name.clone())
                    .with_detail(
                        "setup_control_socket",
                        config.setup_control_socket_path.clone().unwrap_or_default(),
                    ),
            );
            HostSetupControlHandoffReport {
                status: HostSetupControlHandoffStatus::Complete,
                plan,
                received: Some(received),
                failed_report: None,
                audit_records: audit_records.clone(),
            }
        }
        Err(report) => {
            audit_records.push(report.audit_record(config.sandbox_id.clone()));
            HostSetupControlHandoffReport {
                status: HostSetupControlHandoffStatus::Failed,
                plan,
                received: None,
                failed_report: Some(report),
                audit_records: audit_records.clone(),
            }
        }
    };

    let process_exit = if handoff.status == HostSetupControlHandoffStatus::Complete {
        runner.wait_setup_process().map(Some)
    } else {
        runner.poll_setup_process()
    };
    let mut status = handoff.status;
    let process_exit = match process_exit {
        Ok(Some(exit)) => {
            if exit.success && status == HostSetupControlHandoffStatus::Complete {
                audit_records.push(
                    AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
                        .with_frontend(Frontend::Setup)
                        .with_decision(Decision::Allow, None)
                        .with_detail("setup_phase", "host_setup_process")
                        .with_detail("setup_status", "complete")
                        .with_detail(
                            "exit_code",
                            exit.exit_code
                                .map(|code| code.to_string())
                                .unwrap_or_else(|| "signal_or_unknown".to_string()),
                        ),
                );
            } else if !exit.success {
                status = HostSetupControlHandoffStatus::Failed;
                audit_records.push(host_setup_process_failure_audit(
                    &config,
                    "wait_setup_process",
                    format!("nonzero exit {:?}", exit.exit_code),
                ));
            }
            Some(exit)
        }
        Ok(None) => None,
        Err(error) => {
            status = HostSetupControlHandoffStatus::Failed;
            audit_records.push(host_setup_process_failure_audit(
                &config,
                "wait_setup_process",
                error,
            ));
            None
        }
    };
    handoff.status = status;
    handoff.audit_records = audit_records.clone();
    HostSetupSessionReport {
        status,
        handoff,
        process_exit,
        audit_records,
    }
}

#[cfg(unix)]
fn host_setup_process_failure_audit(
    config: &NetworkSetupConfig,
    step: &str,
    error: String,
) -> AuditRecord {
    AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
        .with_frontend(Frontend::Setup)
        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        .with_detail("setup_phase", "host_setup_process")
        .with_detail("setup_status", "failed")
        .with_detail("setup_step", step)
        .with_detail("setup_error", error)
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub fn run_foxproxsetup_linux_handoff_with_control(
    args: &[String],
    control: &UnixStream,
) -> CliOutput {
    let mut ops = foxprox_device::LinuxTunSetupOps::new();
    run_foxproxsetup_handoff_with_ops(args, control, &mut ops)
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub fn run_foxproxsetup_linux_handoff_connecting(args: &[String]) -> CliOutput {
    let mut ops = foxprox_device::LinuxTunSetupOps::new();
    run_foxproxsetup_handoff_connecting_with_ops(args, &mut ops)
}

#[cfg(unix)]
pub fn run_foxproxsetup_execute_setup_connecting_with_ops_and_runner<
    O: TunSetupDeviceOps,
    R: SandboxSetupCommandRunner + PostSetupLifecycleRunner,
>(
    args: &[String],
    ops: &mut O,
    runner: &mut R,
) -> CliOutput {
    let (config, target) = match parse_foxproxsetup_invocation(args) {
        Ok(invocation) => invocation,
        Err((code, detail)) => return error_output(code, detail),
    };
    let Some(path) = config.setup_control_socket_path.clone() else {
        return error_output(
            "setup_missing_control_socket",
            "expected --setup-control-socket for safe TUN handoff execution".to_string(),
        );
    };
    let control = match UnixStream::connect(&path) {
        Ok(control) => control,
        Err(error) => {
            return error_output(
                "setup_control_socket_connect_error",
                format!("{path}: {error}"),
            )
        }
    };
    run_foxproxsetup_execute_setup_with_config(config, target, control, ops, runner)
}

#[cfg(unix)]
fn run_foxproxsetup_execute_setup_with_config<
    O: TunSetupDeviceOps,
    R: SandboxSetupCommandRunner + PostSetupLifecycleRunner,
>(
    config: NetworkSetupConfig,
    target: Vec<String>,
    control: UnixStream,
    ops: &mut O,
    runner: &mut R,
) -> CliOutput {
    let handoff_report = execute_tun_setup_handoff(ops, &control, &config);
    let mut audit_records = handoff_report.audit_records_with_summary(config.sandbox_id.clone());
    if handoff_report.status != TunSetupHandoffStatus::Complete {
        let output = json!({
            "setup": {
                "status": "failed",
                "failed_phase": "tun_handoff",
            },
            "tun_handoff": {
                "status": "failed",
                "completed_steps": handoff_report.completed_steps,
                "failed_step": handoff_report.failed_step,
            },
            "sandbox_network": {
                "status": "skipped",
                "completed_steps": [],
                "failed_step": null,
            },
            "audit": audit_records,
            "proxy_environment": config.proxy_environment(),
            "target_command": target,
        });
        return json_output(2, "setup_execute_serialize_error", output);
    }

    let command_report = run_sandbox_network_setup_commands_with_runner(&config, &target, runner);
    let sandbox_status = if command_report.failed_step.is_none() {
        "complete"
    } else {
        "failed"
    };
    if command_report.failed_step.is_some() {
        audit_records.push(command_report.audit.clone());
        let output = json!({
            "setup": {
                "status": "failed",
                "failed_phase": "sandbox_network_commands",
            },
            "tun_handoff": {
                "status": "complete",
                "completed_steps": handoff_report.completed_steps,
                "failed_step": handoff_report.failed_step,
            },
            "sandbox_network": {
                "status": sandbox_status,
                "completed_steps": command_report.completed_steps,
                "failed_step": command_report.failed_step,
            },
            "post_setup_lifecycle": {
                "status": "skipped",
                "completed_steps": [],
                "failed_step": null,
            },
            "audit": audit_records,
            "proxy_environment": config.proxy_environment(),
            "target_command": target,
        });
        return json_output(2, "setup_execute_serialize_error", output);
    }
    audit_records.push(command_report.audit.clone());

    drop(control);
    let lifecycle_report = run_post_setup_lifecycle_with_runner(&config, &target, runner);
    let lifecycle_status = if lifecycle_report.failed_step.is_none() {
        "complete"
    } else {
        "failed"
    };
    let exit_code = if lifecycle_report.failed_step.is_none() {
        0
    } else {
        2
    };
    audit_records.push(lifecycle_report.audit.clone());
    let output = json!({
        "setup": {
            "status": if exit_code == 0 { "complete" } else { "failed" },
            "failed_phase": if exit_code == 0 { serde_json::Value::Null } else { json!("post_setup_lifecycle") },
        },
        "tun_handoff": {
            "status": "complete",
            "completed_steps": handoff_report.completed_steps,
            "failed_step": handoff_report.failed_step,
        },
        "sandbox_network": {
            "status": sandbox_status,
            "completed_steps": command_report.completed_steps,
            "failed_step": command_report.failed_step,
        },
        "post_setup_lifecycle": {
            "status": lifecycle_status,
            "completed_steps": lifecycle_report.completed_steps,
            "failed_step": lifecycle_report.failed_step,
        },
        "audit": audit_records,
        "proxy_environment": config.proxy_environment(),
        "target_command": target,
    });
    json_output(exit_code, "setup_execute_serialize_error", output)
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub fn run_foxproxsetup_linux_execute_setup_connecting(args: &[String]) -> CliOutput {
    let mut ops = foxprox_device::LinuxTunSetupOps::new();
    let mut runner = CommandSandboxSetupRunner::default();
    run_foxproxsetup_execute_setup_connecting_with_ops_and_runner(args, &mut ops, &mut runner)
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSetupCommandReport {
    pub completed_steps: Vec<String>,
    pub failed_step: Option<String>,
    pub audit: AuditRecord,
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostSetupLifecycleReport {
    pub completed_steps: Vec<String>,
    pub failed_step: Option<String>,
    pub audit: AuditRecord,
}

#[cfg(unix)]
pub trait SandboxSetupCommandRunner {
    fn run_setup_command(&mut self, step: &SetupHelperStep) -> Result<(), String>;
}

#[cfg(unix)]
pub trait PostSetupLifecycleRunner {
    fn close_setup_fds(&mut self, config: &NetworkSetupConfig) -> Result<(), String>;
    fn drop_setup_capability(&mut self, config: &NetworkSetupConfig) -> Result<(), String>;
    fn exec_target(&mut self, target: &[String]) -> Result<(), String>;
}

#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct CommandSandboxSetupRunner {
    resolv_conf_path: PathBuf,
}

#[cfg(unix)]
impl Default for CommandSandboxSetupRunner {
    fn default() -> Self {
        Self {
            resolv_conf_path: PathBuf::from("/etc/resolv.conf"),
        }
    }
}

#[cfg(unix)]
impl CommandSandboxSetupRunner {
    pub fn with_resolv_conf_path(path: impl Into<PathBuf>) -> Self {
        Self {
            resolv_conf_path: path.into(),
        }
    }
}

#[cfg(unix)]
impl SandboxSetupCommandRunner for CommandSandboxSetupRunner {
    fn run_setup_command(&mut self, step: &SetupHelperStep) -> Result<(), String> {
        match step.name.as_str() {
            "configure_default_route" => {
                let (program, args) = step
                    .command
                    .split_first()
                    .ok_or_else(|| "empty route command".to_string())?;
                let status = Command::new(program)
                    .args(args)
                    .status()
                    .map_err(|error| error.to_string())?;
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("route command exited with {status}"))
                }
            }
            "configure_dns" => {
                let nameserver = step
                    .command
                    .get(1)
                    .ok_or_else(|| "missing DNS nameserver line".to_string())?;
                fs::write(&self.resolv_conf_path, format!("{nameserver}\n"))
                    .map_err(|error| error.to_string())
            }
            "configure_proxy_reachability" => Ok(()),
            other => Err(format!("unsupported sandbox setup command {other}")),
        }
    }
}

#[cfg(unix)]
impl PostSetupLifecycleRunner for CommandSandboxSetupRunner {
    fn close_setup_fds(&mut self, _config: &NetworkSetupConfig) -> Result<(), String> {
        Ok(())
    }

    fn drop_setup_capability(&mut self, _config: &NetworkSetupConfig) -> Result<(), String> {
        drop_cap_net_admin()
    }

    fn exec_target(&mut self, target: &[String]) -> Result<(), String> {
        let Some((program, args)) = target.split_first() else {
            return Err("missing target command".to_string());
        };
        use std::os::unix::process::CommandExt;
        Err(Command::new(program).args(args).exec().to_string())
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn drop_cap_net_admin() -> Result<(), String> {
    for set in [
        caps::CapSet::Ambient,
        caps::CapSet::Effective,
        caps::CapSet::Inheritable,
        caps::CapSet::Permitted,
        caps::CapSet::Bounding,
    ] {
        if caps::has_cap(None, set, caps::Capability::CAP_NET_ADMIN)
            .map_err(|error| format!("read CAP_NET_ADMIN from {set:?}: {error}"))?
        {
            caps::drop(None, set, caps::Capability::CAP_NET_ADMIN)
                .map_err(|error| format!("drop CAP_NET_ADMIN from {set:?}: {error}"))?;
        }
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
fn drop_cap_net_admin() -> Result<(), String> {
    Err("CAP_NET_ADMIN drop requires Linux capability support".to_string())
}

#[cfg(unix)]
pub fn run_sandbox_network_setup_commands_with_runner<R: SandboxSetupCommandRunner>(
    config: &NetworkSetupConfig,
    target: &[String],
    runner: &mut R,
) -> SandboxSetupCommandReport {
    let plan = SetupHelperPlan::new(config.clone(), target);
    let mut completed_steps = Vec::new();
    for step_name in [
        "configure_default_route",
        "configure_dns",
        "configure_proxy_reachability",
    ] {
        let Some(step) = plan.steps.iter().find(|step| step.name == step_name) else {
            let audit = setup_command_failure_audit(
                config,
                step_name,
                "missing setup step".to_string(),
                &completed_steps,
            );
            return SandboxSetupCommandReport {
                completed_steps,
                failed_step: Some(step_name.to_string()),
                audit,
            };
        };
        if let Err(error) = runner.run_setup_command(step) {
            let audit = setup_command_failure_audit(config, step_name, error, &completed_steps);
            return SandboxSetupCommandReport {
                completed_steps,
                failed_step: Some(step_name.to_string()),
                audit,
            };
        }
        completed_steps.push(step_name.to_string());
    }

    let audit = AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
        .with_frontend(Frontend::Setup)
        .with_decision(Decision::Allow, None)
        .with_detail("setup_phase", "sandbox_network_commands")
        .with_detail("setup_status", "complete")
        .with_detail("completed_steps", completed_steps.join(","))
        .with_detail("tun_name", config.tun_name.clone())
        .with_detail("default_route_via", config.gateway_ip.to_string())
        .with_detail("broker_dns_ip", config.broker_dns_ip.to_string())
        .with_detail("http_proxy", config.proxy_environment().http_proxy)
        .with_detail("all_proxy", config.proxy_environment().all_proxy);
    SandboxSetupCommandReport {
        completed_steps,
        failed_step: None,
        audit,
    }
}

#[cfg(unix)]
fn setup_command_failure_audit(
    config: &NetworkSetupConfig,
    step_name: &str,
    error: String,
    completed_steps: &[String],
) -> AuditRecord {
    AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
        .with_frontend(Frontend::Setup)
        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        .with_detail("setup_phase", "sandbox_network_commands")
        .with_detail("setup_status", "failed")
        .with_detail("setup_step", step_name)
        .with_detail("setup_error", error)
        .with_detail("completed_steps", completed_steps.join(","))
}

#[cfg(unix)]
pub fn run_post_setup_lifecycle_with_runner<R: PostSetupLifecycleRunner>(
    config: &NetworkSetupConfig,
    target: &[String],
    runner: &mut R,
) -> PostSetupLifecycleReport {
    let mut completed_steps = Vec::new();
    for step_name in ["close_setup_fds", "drop_setup_capability"] {
        let result = match step_name {
            "close_setup_fds" => runner.close_setup_fds(config),
            "drop_setup_capability" => runner.drop_setup_capability(config),
            _ => unreachable!("known post-setup lifecycle step"),
        };
        if let Err(error) = result {
            let audit =
                post_setup_lifecycle_failure_audit(config, step_name, error, &completed_steps);
            return PostSetupLifecycleReport {
                completed_steps,
                failed_step: Some(step_name.to_string()),
                audit,
            };
        }
        completed_steps.push(step_name.to_string());
    }

    if let Err(error) = runner.exec_target(target) {
        let audit =
            post_setup_lifecycle_failure_audit(config, "exec_target", error, &completed_steps);
        return PostSetupLifecycleReport {
            completed_steps,
            failed_step: Some("exec_target".to_string()),
            audit,
        };
    }
    completed_steps.push("exec_target".to_string());

    let audit = AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
        .with_frontend(Frontend::Setup)
        .with_decision(Decision::Allow, None)
        .with_detail("setup_phase", "post_setup_lifecycle")
        .with_detail("setup_status", "complete")
        .with_detail("completed_steps", completed_steps.join(","))
        .with_detail("dropped_capability", "CAP_NET_ADMIN")
        .with_detail("target_exec_ready", "true")
        .with_detail("target_argc", target.len().to_string());
    PostSetupLifecycleReport {
        completed_steps,
        failed_step: None,
        audit,
    }
}

#[cfg(unix)]
fn post_setup_lifecycle_failure_audit(
    config: &NetworkSetupConfig,
    step_name: &str,
    error: String,
    completed_steps: &[String],
) -> AuditRecord {
    AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
        .with_frontend(Frontend::Setup)
        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        .with_detail("setup_phase", "post_setup_lifecycle")
        .with_detail("setup_status", "failed")
        .with_detail("setup_step", step_name)
        .with_detail("setup_error", error)
        .with_detail("completed_steps", completed_steps.join(","))
}

fn parse_foxproxsetup_invocation(
    args: &[String],
) -> Result<(NetworkSetupConfig, Vec<String>), (&'static str, String)> {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return Err((
            "setup_missing_separator",
            "expected foxproxsetup <setup flags> -- <target...>".to_string(),
        ));
    };
    if args.len() <= separator + 1 {
        return Err((
            "setup_missing_target",
            "expected non-empty target command after --".to_string(),
        ));
    }
    let target = args[separator + 1..].to_vec();
    let config =
        parse_setup_config(&args[..separator]).map_err(|error| ("setup_parse_error", error))?;
    Ok((config, target))
}

fn parse_setup_config(args: &[String]) -> Result<NetworkSetupConfig, String> {
    let mut sandbox_id: Option<String> = None;
    let mut tun_name: Option<String> = None;
    let mut sandbox_ip = None;
    let mut gateway_ip = None;
    let mut mtu = None;
    let mut broker_dns_ip = None;
    let mut http_proxy_port = None;
    let mut socks_proxy_port = None;
    let mut setup_control_fd = None;
    let mut setup_control_socket_path = None;
    let mut index = 0usize;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--sandbox-id" => sandbox_id = Some(value.clone()),
            "--tun-name" => tun_name = Some(value.clone()),
            "--sandbox-ip" => sandbox_ip = Some(value.parse().map_err(|_| "invalid sandbox ip")?),
            "--gateway-ip" => gateway_ip = Some(value.parse().map_err(|_| "invalid gateway ip")?),
            "--mtu" => mtu = Some(value.parse().map_err(|_| "invalid mtu")?),
            "--dns" => broker_dns_ip = Some(value.parse().map_err(|_| "invalid dns ip")?),
            "--http-proxy" => http_proxy_port = Some(parse_proxy_port(value)?),
            "--socks-proxy" => socks_proxy_port = Some(parse_proxy_port(value)?),
            "--setup-control-fd" => {
                setup_control_fd = Some(value.parse().map_err(|_| "invalid setup control fd")?)
            }
            "--setup-control-socket" => setup_control_socket_path = Some(value.clone()),
            "--drop-cap" if value == "CAP_NET_ADMIN" => {}
            other => return Err(format!("unsupported setup flag {other}")),
        }
        index += 2;
    }
    Ok(NetworkSetupConfig {
        sandbox_id: sandbox_id.ok_or("missing --sandbox-id")?,
        tun_name: tun_name.ok_or("missing --tun-name")?,
        sandbox_ip: sandbox_ip.ok_or("missing --sandbox-ip")?,
        gateway_ip: gateway_ip.ok_or("missing --gateway-ip")?,
        mtu: mtu.ok_or("missing --mtu")?,
        broker_dns_ip: broker_dns_ip.ok_or("missing --dns")?,
        http_proxy_port: http_proxy_port.ok_or("missing --http-proxy")?,
        socks_proxy_port: socks_proxy_port.ok_or("missing --socks-proxy")?,
        setup_control_fd,
        setup_control_socket_path,
    })
}

fn parse_proxy_port(value: &str) -> Result<u16, String> {
    value
        .rsplit_once(':')
        .ok_or_else(|| "proxy endpoint must include port".to_string())?
        .1
        .parse()
        .map_err(|_| "invalid proxy port".to_string())
}

pub fn validate_config_path(path: impl AsRef<Path>) -> CliOutput {
    match fs::read_to_string(path.as_ref()) {
        Ok(text) => validate_config_text(&text),
        Err(error) => error_output("config_io_error", error.to_string()),
    }
}

pub fn validate_config_text(text: &str) -> CliOutput {
    match serde_json::from_str::<BrokerRuntimeConfig>(text) {
        Ok(config) => {
            let audit = config.validation_audit();
            let valid = audit.decision == Some(Decision::Allow);
            audit_output(if valid { 0 } else { 2 }, audit)
        }
        Err(error) => error_output("config_parse_error", error.to_string()),
    }
}

fn plan_bwrap_args(args: &[String]) -> CliOutput {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return error_output(
            "plan_bwrap_missing_separator",
            "expected: plan-bwrap <config> -- <target...>".to_string(),
        );
    };
    if separator != 1 || args.len() <= separator + 1 {
        return error_output(
            "plan_bwrap_missing_target",
            "expected non-empty target command after --".to_string(),
        );
    }
    let config_path = &args[0];
    let target = &args[separator + 1..];
    let text = match fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(error) => return error_output("config_io_error", error.to_string()),
    };
    let config = match serde_json::from_str::<BrokerRuntimeConfig>(&text) {
        Ok(config) => config,
        Err(error) => return error_output("config_parse_error", error.to_string()),
    };
    let validation = config.validation_audit();
    if validation.decision != Some(Decision::Allow) {
        return audit_output(2, validation);
    }
    let plan = BwrapSetupPlan::new(config.setup.clone(), target);
    let output = json!({
        "plan": plan,
        "audit": plan.audit_record(),
    });
    match serde_json::to_string(&output) {
        Ok(json) => CliOutput {
            exit_code: 0,
            stdout: format!("{json}\n"),
            stderr: String::new(),
        },
        Err(error) => error_output("plan_bwrap_serialize_error", error.to_string()),
    }
}

fn default_config(sandbox_id: &str) -> CliOutput {
    match serde_json::to_string_pretty(&BrokerRuntimeConfig::alpha_default(sandbox_id)) {
        Ok(json) => CliOutput {
            exit_code: 0,
            stdout: format!("{json}\n"),
            stderr: String::new(),
        },
        Err(error) => error_output("config_serialize_error", error.to_string()),
    }
}

fn usage_output() -> CliOutput {
    CliOutput {
        exit_code: 64,
        stdout: String::new(),
        stderr: "usage: foxprox validate-config <path> | default-config <sandbox-id> | plan-bwrap <config> -- <target...>\n".to_string(),
    }
}

fn error_output(code: &str, detail: String) -> CliOutput {
    let audit = AuditRecord::new(AuditKind::BrokerError, "unknown")
        .with_frontend(Frontend::Core)
        .with_decision(Decision::FailClosed, Some(DenialReason::PolicyConfig))
        .with_detail("error_codes", code)
        .with_detail("error_detail", detail);
    audit_output(1, audit)
}

fn json_output(exit_code: i32, error_code: &'static str, output: serde_json::Value) -> CliOutput {
    match serde_json::to_string(&output) {
        Ok(json) => CliOutput {
            exit_code,
            stdout: format!("{json}\n"),
            stderr: String::new(),
        },
        Err(error) => error_output(error_code, error.to_string()),
    }
}

fn audit_output(exit_code: i32, audit: AuditRecord) -> CliOutput {
    CliOutput {
        exit_code,
        stdout: format!(
            "{}\n",
            audit.to_json_line().expect("audit record serializes")
        ),
        stderr: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::Value;

    #[cfg(unix)]
    use foxprox_device::{recv_tun_fd, send_tun_fd, TunFdHandoffReport};
    #[cfg(unix)]
    use std::os::unix::net::{UnixListener, UnixStream};

    fn setup_args_with_control_fd() -> Vec<String> {
        vec![
            "--sandbox-id".to_string(),
            "s1".to_string(),
            "--tun-name".to_string(),
            "foxprox0".to_string(),
            "--sandbox-ip".to_string(),
            "10.0.2.15".to_string(),
            "--gateway-ip".to_string(),
            "10.0.2.2".to_string(),
            "--mtu".to_string(),
            "1500".to_string(),
            "--dns".to_string(),
            "10.0.2.3".to_string(),
            "--http-proxy".to_string(),
            "10.0.2.2:3128".to_string(),
            "--socks-proxy".to_string(),
            "10.0.2.2:1080".to_string(),
            "--setup-control-fd".to_string(),
            "9".to_string(),
            "--drop-cap".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--".to_string(),
            "curl".to_string(),
            "http://example.com".to_string(),
        ]
    }

    #[cfg(unix)]
    fn setup_args_with_control_socket(path: &std::path::Path) -> Vec<String> {
        let mut args = setup_args_with_control_fd();
        let control_flag = args
            .iter()
            .position(|arg| arg == "--setup-control-fd")
            .unwrap();
        args.splice(
            control_flag..control_flag + 2,
            [
                "--setup-control-socket".to_string(),
                path.to_string_lossy().to_string(),
            ],
        );
        args
    }

    #[test]
    fn validate_config_text_prints_broker_started_audit_for_valid_config() {
        let config = BrokerRuntimeConfig::alpha_default("s1");
        let text = serde_json::to_string(&config).unwrap();
        let output = validate_config_text(&text);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_started");
        assert_eq!(value["sandbox_id"], "s1");
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["details"]["audit_capacity"], "1024");
    }

    #[test]
    fn validate_config_text_prints_fail_closed_audit_for_invalid_config() {
        let mut config = BrokerRuntimeConfig::alpha_default("s1");
        config.audit_capacity = 0;
        config.policy.broker_dns.clear();
        let text = serde_json::to_string(&config).unwrap();
        let output = validate_config_text(&text);
        assert_eq!(output.exit_code, 2);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["decision"], "fail_closed");
        assert!(value["details"]["error_codes"]
            .as_str()
            .unwrap()
            .contains("audit_capacity_zero"));
        assert!(value["details"]["error_codes"]
            .as_str()
            .unwrap()
            .contains("policy_broker_dns_empty"));
    }

    #[test]
    fn malformed_config_json_prints_parse_error_audit() {
        let output = validate_config_text("{not json");
        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["details"]["error_codes"], "config_parse_error");
    }

    #[test]
    fn plan_bwrap_prints_plan_and_setup_audit() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-config-{}-{}.json",
            std::process::id(),
            "plan"
        ));
        let config = BrokerRuntimeConfig::alpha_default("s1");
        std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
        let output = run_args(&[
            "plan-bwrap".to_string(),
            path.to_string_lossy().to_string(),
            "--".to_string(),
            "curl".to_string(),
            "http://example.com".to_string(),
        ]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["plan"]["setup_command"][0], "foxproxsetup");
        assert_eq!(
            value["plan"]["setup_command"]
                .as_array()
                .unwrap()
                .last()
                .unwrap(),
            "http://example.com"
        );
        assert_eq!(value["audit"]["kind"], "setup_plan_created");
        assert_eq!(value["audit"]["details"]["tun_name"], "foxprox0");
    }

    #[test]
    fn plan_bwrap_missing_target_prints_fail_closed_audit() {
        let output = run_args(&[
            "plan-bwrap".to_string(),
            "config.json".to_string(),
            "--".to_string(),
        ]);
        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["details"]["error_codes"], "plan_bwrap_missing_target");
    }

    #[test]
    fn foxproxsetup_plan_parses_bwrap_helper_flags() {
        let output = run_foxproxsetup_args(&[
            "--sandbox-id".to_string(),
            "s1".to_string(),
            "--tun-name".to_string(),
            "foxprox0".to_string(),
            "--sandbox-ip".to_string(),
            "10.0.2.15".to_string(),
            "--gateway-ip".to_string(),
            "10.0.2.2".to_string(),
            "--mtu".to_string(),
            "1500".to_string(),
            "--dns".to_string(),
            "10.0.2.3".to_string(),
            "--http-proxy".to_string(),
            "10.0.2.2:3128".to_string(),
            "--socks-proxy".to_string(),
            "10.0.2.2:1080".to_string(),
            "--setup-control-fd".to_string(),
            "9".to_string(),
            "--drop-cap".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--".to_string(),
            "curl".to_string(),
            "http://example.com".to_string(),
        ]);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["audit"]["kind"], "tun_configured");
        assert_eq!(value["plan"]["steps"][0]["name"], "create_tun");
        assert_eq!(value["plan"]["steps"][6]["name"], "handoff_tun_fd");
        assert_eq!(value["plan"]["steps"][7]["name"], "close_setup_fds");
        assert_eq!(value["plan"]["target_command"][0], "curl");
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct CliScriptedSetupCommandRunner {
        ran_steps: Vec<String>,
        lifecycle_steps: Vec<String>,
        fail_step: Option<String>,
        fail_lifecycle_step: Option<String>,
    }

    #[cfg(unix)]
    impl SandboxSetupCommandRunner for CliScriptedSetupCommandRunner {
        fn run_setup_command(&mut self, step: &SetupHelperStep) -> Result<(), String> {
            if self.fail_step.as_deref() == Some(step.name.as_str()) {
                return Err(format!("{} failed", step.name));
            }
            self.ran_steps.push(step.name.clone());
            Ok(())
        }
    }

    #[cfg(unix)]
    impl PostSetupLifecycleRunner for CliScriptedSetupCommandRunner {
        fn close_setup_fds(&mut self, _config: &NetworkSetupConfig) -> Result<(), String> {
            if self.fail_lifecycle_step.as_deref() == Some("close_setup_fds") {
                return Err("close_setup_fds failed".to_string());
            }
            self.lifecycle_steps.push("close_setup_fds".to_string());
            Ok(())
        }

        fn drop_setup_capability(&mut self, _config: &NetworkSetupConfig) -> Result<(), String> {
            if self.fail_lifecycle_step.as_deref() == Some("drop_setup_capability") {
                return Err("drop_setup_capability failed".to_string());
            }
            self.lifecycle_steps
                .push("drop_setup_capability".to_string());
            Ok(())
        }

        fn exec_target(&mut self, _target: &[String]) -> Result<(), String> {
            if self.fail_lifecycle_step.as_deref() == Some("exec_target") {
                return Err("exec_target failed".to_string());
            }
            self.lifecycle_steps.push("exec_target".to_string());
            Ok(())
        }
    }

    #[cfg(unix)]
    struct CliScriptedHostSetupProcessRunner {
        tun_fd: Option<UnixStream>,
        sender: Option<std::thread::JoinHandle<()>>,
        exit: HostSetupProcessExit,
        fail_start: bool,
        exit_before_handoff: bool,
        skip_handoff_connection: bool,
        connect_without_handoff: bool,
    }

    #[cfg(unix)]
    impl HostSetupProcessRunner for CliScriptedHostSetupProcessRunner {
        fn start_setup_process(&mut self, plan: &BwrapSetupPlan) -> Result<(), String> {
            if self.fail_start {
                return Err("scripted start failure".to_string());
            }
            let path = plan
                .config
                .setup_control_socket_path
                .clone()
                .ok_or_else(|| "missing setup control socket path".to_string())?;
            if self.exit_before_handoff || self.skip_handoff_connection {
                return Ok(());
            }
            if self.connect_without_handoff {
                self.sender = Some(std::thread::spawn(move || {
                    let _control = UnixStream::connect(path).unwrap();
                    std::thread::sleep(Duration::from_millis(100));
                }));
                return Ok(());
            }
            let tun_fd = self
                .tun_fd
                .take()
                .ok_or_else(|| "missing scripted tun fd".to_string())?;
            let tun_name = plan.config.tun_name.clone();
            self.sender = Some(std::thread::spawn(move || {
                let control = UnixStream::connect(path).unwrap();
                send_tun_fd(&control, &tun_name, &tun_fd).unwrap();
            }));
            Ok(())
        }

        fn poll_setup_process(&mut self) -> Result<Option<HostSetupProcessExit>, String> {
            if self.exit_before_handoff {
                Ok(Some(self.exit.clone()))
            } else {
                Ok(None)
            }
        }

        fn wait_setup_process(&mut self) -> Result<HostSetupProcessExit, String> {
            if let Some(sender) = self.sender.take() {
                sender.join().unwrap();
            }
            Ok(self.exit.clone())
        }
    }

    #[cfg(unix)]
    struct CliScriptedTunOps {
        fail_configure: bool,
        fail_handoff: bool,
    }

    #[cfg(unix)]
    impl TunSetupDeviceOps for CliScriptedTunOps {
        type TunFd = UnixStream;

        fn open_tun(
            &mut self,
            config: &NetworkSetupConfig,
        ) -> Result<(Self::TunFd, TunFdHandoffReport), TunFdHandoffReport> {
            let (tun_fd, _sandbox_peer) = UnixStream::pair().unwrap();
            Ok((
                tun_fd,
                TunFdHandoffReport::for_opened_device("/dev/net/tun", config.tun_name.clone()),
            ))
        }

        fn configure_tun(
            &mut self,
            config: &NetworkSetupConfig,
            _fd: &Self::TunFd,
        ) -> Result<AuditRecord, Box<AuditRecord>> {
            if self.fail_configure {
                return Err(Box::new(
                    AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
                        .with_frontend(Frontend::Setup)
                        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                        .with_detail("setup_step", "configure_tun")
                        .with_detail("configure_error", "scripted"),
                ));
            }
            Ok(
                AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
                    .with_frontend(Frontend::Setup)
                    .with_decision(Decision::Allow, None)
                    .with_detail("setup_step", "configure_tun")
                    .with_detail("configured_by", "scripted"),
            )
        }

        fn send_tun_fd(
            &mut self,
            control: &UnixStream,
            config: &NetworkSetupConfig,
            fd: &Self::TunFd,
        ) -> Result<TunFdHandoffReport, TunFdHandoffReport> {
            if self.fail_handoff {
                return Err(TunFdHandoffReport::failed(
                    config.tun_name.clone(),
                    "",
                    0,
                    foxprox_device::TunFdHandoffErrorKind::SendFailed,
                ));
            }
            send_tun_fd(control, &config.tun_name, fd)
        }
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_control_accepts_tun_fd_and_records_handoff_audit() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-setup-control-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_socket_path = Some(path.to_string_lossy().to_string());
        let (tun_fd, _sandbox_peer) = UnixStream::pair().unwrap();
        let sender_path = path.clone();
        let sender = std::thread::spawn(move || {
            let control = UnixStream::connect(sender_path).unwrap();
            send_tun_fd(&control, "foxprox0", &tun_fd).unwrap();
        });

        let report = accept_setup_control_tun_handoff(
            &listener,
            config,
            &["curl".to_string(), "http://example.com".to_string()],
        );
        sender.join().unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Complete);
        assert!(report.received.is_some());
        assert_eq!(report.plan.setup_command[1], "--execute-setup");
        assert_eq!(report.audit_records[0].kind, AuditKind::SetupPlanCreated);
        assert_eq!(report.audit_records[1].kind, AuditKind::TunConfigured);
        assert_eq!(report.audit_records[1].details["fd_source"], "scm_rights");
        assert_eq!(
            report.audit_records[2].details["setup_phase"],
            "host_setup_control_handoff"
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_session_starts_process_receives_fd_and_records_exit() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-session-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_socket_path = Some(path.to_string_lossy().to_string());
        let (tun_fd, _sandbox_peer) = UnixStream::pair().unwrap();
        let mut runner = CliScriptedHostSetupProcessRunner {
            tun_fd: Some(tun_fd),
            sender: None,
            exit: HostSetupProcessExit {
                exit_code: Some(0),
                success: true,
            },
            fail_start: false,
            exit_before_handoff: false,
            skip_handoff_connection: false,
            connect_without_handoff: false,
        };

        let report = run_host_setup_control_session_with_runner(
            &listener,
            config,
            &["true".to_string()],
            &mut runner,
        );
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Complete);
        assert!(report.handoff.received.is_some());
        assert_eq!(report.process_exit.unwrap().exit_code, Some(0));
        assert_eq!(report.audit_records[0].kind, AuditKind::SetupPlanCreated);
        assert!(report.audit_records.iter().any(|record| record
            .details
            .get("setup_phase")
            .map(String::as_str)
            == Some("host_setup_control_handoff")));
        assert_eq!(
            report.audit_records.last().unwrap().details["setup_phase"],
            "host_setup_process"
        );
        assert_eq!(
            report.audit_records.last().unwrap().details["setup_status"],
            "complete"
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_session_fails_closed_on_nonzero_setup_process_exit() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-session-fail-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_socket_path = Some(path.to_string_lossy().to_string());
        let (tun_fd, _sandbox_peer) = UnixStream::pair().unwrap();
        let mut runner = CliScriptedHostSetupProcessRunner {
            tun_fd: Some(tun_fd),
            sender: None,
            exit: HostSetupProcessExit {
                exit_code: Some(42),
                success: false,
            },
            fail_start: false,
            exit_before_handoff: false,
            skip_handoff_connection: false,
            connect_without_handoff: false,
        };

        let report = run_host_setup_control_session_with_runner(
            &listener,
            config,
            &["false".to_string()],
            &mut runner,
        );
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Failed);
        assert!(report.handoff.received.is_some());
        assert_eq!(report.process_exit.unwrap().exit_code, Some(42));
        let audit = report.audit_records.last().unwrap();
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.details["setup_phase"], "host_setup_process");
        assert_eq!(audit.details["setup_step"], "wait_setup_process");
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_session_infers_socket_path_before_starting_process() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-session-infer-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let config = NetworkSetupConfig::alpha_default("s1");
        let (tun_fd, _sandbox_peer) = UnixStream::pair().unwrap();
        let mut runner = CliScriptedHostSetupProcessRunner {
            tun_fd: Some(tun_fd),
            sender: None,
            exit: HostSetupProcessExit {
                exit_code: Some(0),
                success: true,
            },
            fail_start: false,
            exit_before_handoff: false,
            skip_handoff_connection: false,
            connect_without_handoff: false,
        };

        let report = run_host_setup_control_session_with_runner(
            &listener,
            config,
            &["true".to_string()],
            &mut runner,
        );
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Complete);
        let full_command = report.handoff.plan.full_command();
        assert!(full_command.iter().any(|arg| arg == "--execute-setup"));
        assert!(full_command
            .windows(2)
            .any(|args| args[0] == "--setup-control-socket" && args[1] == path.to_string_lossy()));
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_session_fails_closed_if_process_exits_before_handoff() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-session-early-exit-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_socket_path = Some(path.to_string_lossy().to_string());
        let mut runner = CliScriptedHostSetupProcessRunner {
            tun_fd: None,
            sender: None,
            exit: HostSetupProcessExit {
                exit_code: Some(19),
                success: false,
            },
            fail_start: false,
            exit_before_handoff: true,
            skip_handoff_connection: false,
            connect_without_handoff: false,
        };

        let report = run_host_setup_control_session_with_runner(
            &listener,
            config,
            &["false".to_string()],
            &mut runner,
        );
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Failed);
        assert!(report.handoff.received.is_none());
        assert_eq!(report.process_exit.unwrap().exit_code, Some(19));
        let audit = report.audit_records.last().unwrap();
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.details["setup_phase"], "host_setup_process");
        assert_eq!(audit.details["setup_step"], "setup_control_handoff");
        assert!(audit.details["setup_error"].contains("before fd handoff"));
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_session_fails_closed_on_accept_timeout_without_connection() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-session-timeout-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_socket_path = Some(path.to_string_lossy().to_string());
        let mut runner = CliScriptedHostSetupProcessRunner {
            tun_fd: None,
            sender: None,
            exit: HostSetupProcessExit {
                exit_code: Some(0),
                success: true,
            },
            fail_start: false,
            exit_before_handoff: false,
            skip_handoff_connection: true,
            connect_without_handoff: false,
        };

        let report = run_host_setup_control_session_with_runner_and_timeouts(
            &listener,
            config,
            &["true".to_string()],
            &mut runner,
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Failed);
        assert!(report.handoff.received.is_none());
        assert!(report.process_exit.is_none());
        let audit = report.audit_records.last().unwrap();
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.details["setup_phase"], "host_setup_process");
        assert_eq!(audit.details["setup_step"], "setup_control_handoff");
        assert!(audit.details["setup_error"].contains("timed out"));
    }

    #[cfg(unix)]
    #[test]
    fn host_setup_session_fails_closed_on_read_timeout_without_fd_handoff() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-host-session-read-timeout-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_socket_path = Some(path.to_string_lossy().to_string());
        let mut runner = CliScriptedHostSetupProcessRunner {
            tun_fd: None,
            sender: None,
            exit: HostSetupProcessExit {
                exit_code: Some(0),
                success: true,
            },
            fail_start: false,
            exit_before_handoff: false,
            skip_handoff_connection: false,
            connect_without_handoff: true,
        };

        let report = run_host_setup_control_session_with_runner_and_timeouts(
            &listener,
            config,
            &["true".to_string()],
            &mut runner,
            Duration::from_secs(1),
            Duration::from_millis(10),
        );
        let _ = runner.wait_setup_process();
        let _ = std::fs::remove_file(&path);

        assert_eq!(report.status, HostSetupControlHandoffStatus::Failed);
        assert!(report.handoff.received.is_none());
        let audit = report
            .audit_records
            .iter()
            .find(|record| {
                record.details.get("handoff_error").map(String::as_str) == Some("receive_failed")
            })
            .unwrap();
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_network_setup_commands_run_route_dns_and_proxy_steps() {
        let config = NetworkSetupConfig::alpha_default("s1");
        let mut runner = CliScriptedSetupCommandRunner::default();
        let report = run_sandbox_network_setup_commands_with_runner(
            &config,
            &["curl".to_string(), "http://example.com".to_string()],
            &mut runner,
        );

        assert_eq!(
            report.completed_steps,
            vec![
                "configure_default_route".to_string(),
                "configure_dns".to_string(),
                "configure_proxy_reachability".to_string(),
            ]
        );
        assert_eq!(runner.ran_steps, report.completed_steps);
        assert!(report.failed_step.is_none());
        assert_eq!(report.audit.kind, AuditKind::TunConfigured);
        assert_eq!(report.audit.decision, Some(Decision::Allow));
        assert_eq!(
            report.audit.details["setup_phase"],
            "sandbox_network_commands"
        );
        assert_eq!(report.audit.details["default_route_via"], "10.0.2.2");
        assert_eq!(report.audit.details["broker_dns_ip"], "10.0.2.3");
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_network_setup_commands_fail_closed_before_later_steps() {
        let config = NetworkSetupConfig::alpha_default("s1");
        let mut runner = CliScriptedSetupCommandRunner {
            fail_step: Some("configure_dns".to_string()),
            ..CliScriptedSetupCommandRunner::default()
        };
        let report = run_sandbox_network_setup_commands_with_runner(
            &config,
            &["curl".to_string()],
            &mut runner,
        );

        assert_eq!(report.failed_step.as_deref(), Some("configure_dns"));
        assert_eq!(
            runner.ran_steps,
            vec!["configure_default_route".to_string()]
        );
        assert_eq!(report.completed_steps, runner.ran_steps);
        assert_eq!(report.audit.kind, AuditKind::BrokerError);
        assert_eq!(report.audit.decision, Some(Decision::FailClosed));
        assert_eq!(report.audit.reason, Some(DenialReason::SetupFailed));
        assert_eq!(report.audit.details["setup_step"], "configure_dns");
        assert_eq!(
            report.audit.details["completed_steps"],
            "configure_default_route"
        );
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_handoff_with_ops_executes_setup_and_outputs_audits() {
        let (control_tx, control_rx) = UnixStream::pair().unwrap();
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };
        let output =
            run_foxproxsetup_handoff_with_ops(&setup_args_with_control_fd(), &control_tx, &mut ops);

        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["setup"]["status"], "complete");
        assert_eq!(
            value["setup"]["completed_steps"].as_array().unwrap().len(),
            3
        );
        assert_eq!(value["audit"][0]["kind"], "tun_fd_opened");
        assert_eq!(value["audit"][1]["details"]["configured_by"], "scripted");
        assert_eq!(value["audit"][2]["details"]["fd_source"], "scm_rights");
        assert_eq!(value["audit"][3]["details"]["setup_status"], "complete");
        assert_eq!(
            value["proxy_environment"]["http_proxy"],
            "http://10.0.2.2:3128"
        );
        assert_eq!(value["target_command"][0], "curl");

        let received = recv_tun_fd(&control_rx, "foxprox0").unwrap();
        assert_eq!(received.report.tun_name, "foxprox0");
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_can_connect_to_safe_setup_control_socket_path() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-setup-control-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };

        let output = run_foxproxsetup_handoff_connecting_with_ops(
            &setup_args_with_control_socket(&path),
            &mut ops,
        );
        assert_eq!(output.exit_code, 0);
        let (accepted, _) = listener.accept().unwrap();
        let received = recv_tun_fd(&accepted, "foxprox0").unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(received.report.tun_name, "foxprox0");
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["setup"]["status"], "complete");
        assert_eq!(value["audit"][2]["details"]["fd_source"], "scm_rights");
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_entry_execute_mode_uses_safe_control_socket_path() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-entry-setup-control-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };
        let mut runner = CliScriptedSetupCommandRunner::default();
        let mut args = vec!["--execute-setup".to_string()];
        args.extend(setup_args_with_control_socket(&path));

        let output = run_foxproxsetup_entry_args_with_ops_and_runner(&args, &mut ops, &mut runner);
        assert_eq!(output.exit_code, 0);
        let (accepted, _) = listener.accept().unwrap();
        let received = recv_tun_fd(&accepted, "foxprox0").unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(received.report.tun_name, "foxprox0");
        assert_eq!(
            runner.ran_steps,
            vec![
                "configure_default_route".to_string(),
                "configure_dns".to_string(),
                "configure_proxy_reachability".to_string(),
            ]
        );
        assert_eq!(
            runner.lifecycle_steps,
            vec![
                "close_setup_fds".to_string(),
                "drop_setup_capability".to_string(),
                "exec_target".to_string(),
            ]
        );
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["setup"]["status"], "complete");
        assert_eq!(value["tun_handoff"]["status"], "complete");
        assert_eq!(value["sandbox_network"]["status"], "complete");
        assert_eq!(value["post_setup_lifecycle"]["status"], "complete");
        assert_eq!(value["audit"].as_array().unwrap().len(), 6);
        assert_eq!(
            value["audit"][4]["details"]["setup_phase"],
            "sandbox_network_commands"
        );
        assert_eq!(
            value["audit"][5]["details"]["setup_phase"],
            "post_setup_lifecycle"
        );
        assert_eq!(value["target_command"][0], "curl");
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_entry_execute_mode_fails_closed_on_sandbox_command_failure() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-entry-fail-setup-control-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };
        let mut runner = CliScriptedSetupCommandRunner {
            fail_step: Some("configure_dns".to_string()),
            ..CliScriptedSetupCommandRunner::default()
        };
        let mut args = vec!["--execute-setup".to_string()];
        args.extend(setup_args_with_control_socket(&path));

        let output = run_foxproxsetup_entry_args_with_ops_and_runner(&args, &mut ops, &mut runner);
        assert_eq!(output.exit_code, 2);
        let (accepted, _) = listener.accept().unwrap();
        let received = recv_tun_fd(&accepted, "foxprox0").unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(received.report.tun_name, "foxprox0");
        assert_eq!(
            runner.ran_steps,
            vec!["configure_default_route".to_string()]
        );
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["setup"]["status"], "failed");
        assert_eq!(value["setup"]["failed_phase"], "sandbox_network_commands");
        assert_eq!(value["tun_handoff"]["status"], "complete");
        assert_eq!(value["sandbox_network"]["status"], "failed");
        assert_eq!(value["sandbox_network"]["failed_step"], "configure_dns");
        assert_eq!(value["post_setup_lifecycle"]["status"], "skipped");
        assert_eq!(value["audit"][4]["kind"], "broker_error");
        assert_eq!(value["audit"][4]["decision"], "fail_closed");
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_entry_execute_mode_fails_closed_on_lifecycle_failure() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-entry-lifecycle-fail-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };
        let mut runner = CliScriptedSetupCommandRunner {
            fail_lifecycle_step: Some("drop_setup_capability".to_string()),
            ..CliScriptedSetupCommandRunner::default()
        };
        let mut args = vec!["--execute-setup".to_string()];
        args.extend(setup_args_with_control_socket(&path));

        let output = run_foxproxsetup_entry_args_with_ops_and_runner(&args, &mut ops, &mut runner);
        assert_eq!(output.exit_code, 2);
        let (accepted, _) = listener.accept().unwrap();
        let received = recv_tun_fd(&accepted, "foxprox0").unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(received.report.tun_name, "foxprox0");
        assert_eq!(runner.lifecycle_steps, vec!["close_setup_fds".to_string()]);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["setup"]["status"], "failed");
        assert_eq!(value["setup"]["failed_phase"], "post_setup_lifecycle");
        assert_eq!(value["sandbox_network"]["status"], "complete");
        assert_eq!(value["post_setup_lifecycle"]["status"], "failed");
        assert_eq!(
            value["post_setup_lifecycle"]["failed_step"],
            "drop_setup_capability"
        );
        assert_eq!(value["audit"][5]["kind"], "broker_error");
        assert_eq!(value["audit"][5]["decision"], "fail_closed");
    }

    #[test]
    fn foxproxsetup_entry_defaults_to_plan_mode_without_execute_flag() {
        let output = run_foxproxsetup_entry_args(&setup_args_with_control_fd());

        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["plan"]["steps"][6]["name"], "handoff_tun_fd");
        assert_eq!(value["audit"]["kind"], "tun_configured");
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_control_socket_connect_error_fails_closed_before_setup() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-missing-setup-control-{}-{}.sock",
            std::process::id(),
            "cli"
        ));
        let _ = std::fs::remove_file(&path);
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };

        let output = run_foxproxsetup_handoff_connecting_with_ops(
            &setup_args_with_control_socket(&path),
            &mut ops,
        );

        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(
            value["details"]["error_codes"],
            "setup_control_socket_connect_error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_handoff_with_ops_fails_closed_before_handoff_on_configure_error() {
        let (control_tx, _control_rx) = UnixStream::pair().unwrap();
        let mut ops = CliScriptedTunOps {
            fail_configure: true,
            fail_handoff: false,
        };
        let output =
            run_foxproxsetup_handoff_with_ops(&setup_args_with_control_fd(), &control_tx, &mut ops);

        assert_eq!(output.exit_code, 2);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["setup"]["status"], "failed");
        assert_eq!(value["setup"]["failed_step"], "configure_tun");
        assert_eq!(value["audit"][1]["kind"], "broker_error");
        assert_eq!(value["audit"][1]["decision"], "fail_closed");
        assert_eq!(value["audit"][2]["details"]["setup_status"], "failed");
        assert_eq!(value["audit"][2]["details"]["failed_step"], "configure_tun");
    }

    #[cfg(unix)]
    #[test]
    fn foxproxsetup_handoff_requires_setup_control_fd() {
        let (control_tx, _control_rx) = UnixStream::pair().unwrap();
        let mut args = setup_args_with_control_fd();
        let control_flag = args
            .iter()
            .position(|arg| arg == "--setup-control-fd")
            .unwrap();
        args.drain(control_flag..control_flag + 2);
        let mut ops = CliScriptedTunOps {
            fail_configure: false,
            fail_handoff: false,
        };
        let output = run_foxproxsetup_handoff_with_ops(&args, &control_tx, &mut ops);

        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(
            value["details"]["error_codes"],
            "setup_missing_control_channel"
        );
    }

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and /dev/net/tun access"]
    fn foxproxsetup_linux_handoff_uses_real_tun_setup_when_privileged() {
        let (control_tx, control_rx) = UnixStream::pair().unwrap();
        let mut args = setup_args_with_control_fd();
        let tun_name_value = args
            .iter()
            .position(|arg| arg == "--tun-name")
            .map(|index| index + 1)
            .unwrap();
        args[tun_name_value] = format!("fpxcli{}", std::process::id() % 10_000);

        let output = run_foxproxsetup_linux_handoff_with_control(&args, &control_tx);
        if output.exit_code == 0 {
            let received = recv_tun_fd(&control_rx, &args[tun_name_value]).unwrap();
            assert_eq!(received.report.tun_name, args[tun_name_value]);
            let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
            assert_eq!(value["audit"][1]["details"]["configured_by"], "tun-rs");
        } else {
            let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
            assert_eq!(value["setup"]["status"], "failed");
            assert_eq!(
                value["audit"].as_array().unwrap().last().unwrap()["kind"],
                "broker_error"
            );
        }
    }

    #[test]
    fn foxproxsetup_missing_target_prints_fail_closed_audit() {
        let output = run_foxproxsetup_args(&[
            "--sandbox-id".to_string(),
            "s1".to_string(),
            "--".to_string(),
        ]);
        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["details"]["error_codes"], "setup_missing_target");
    }

    #[test]
    fn default_config_prints_json_config() {
        let output = run_args(&["default-config".to_string(), "s1".to_string()]);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["setup"]["sandbox_id"], "s1");
    }
}
