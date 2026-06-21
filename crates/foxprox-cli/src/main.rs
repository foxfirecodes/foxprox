use std::env;
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

use foxprox_core::audit::{AuditRecord, Decision, EventKind, Frontend, Protocol};
use foxprox_core::egress::{EgressBackend, EgressOutcome, EgressRequest};
use foxprox_core::policy::{Cidr, PolicyConfig, PolicyEngine, PolicyRule, RuleAction};
use foxprox_core::runtime::TransparentUdpRuntime;
use foxprox_core::scenario::{run_scenario, ScenarioName};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("foxprox-lab: {err}");
            usage();
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [] => {
            usage();
            Ok(())
        }
        [cmd] if cmd == "help" || cmd == "--help" || cmd == "-h" => {
            usage();
            Ok(())
        }
        [cmd] if cmd == "list" => {
            for name in ScenarioName::list() {
                println!("{name}");
            }
            println!("env-smoke");
            println!("tun-smoke");
            println!("setup-smoke");
            println!("handoff-smoke");
            println!("writeback-smoke");
            println!("udp-forward-smoke");
            println!("udp-deny-smoke");
            Ok(())
        }
        [cmd, scenario] if cmd == "run" => run_named_scenario(scenario),
        [cmd, flag, scenario] if cmd == "run" && flag == "--scenario" => {
            run_named_scenario(scenario)
        }
        _ => Err("unknown command".to_string()),
    }
}

fn run_named_scenario(scenario: &str) -> Result<(), String> {
    let records = if scenario == "env-smoke" {
        env_smoke_records()
    } else if scenario == "tun-smoke" {
        tun_smoke_records()
    } else if scenario == "setup-smoke" {
        setup_smoke_records()
    } else if scenario == "handoff-smoke" {
        handoff_smoke_records()
    } else if scenario == "writeback-smoke" {
        writeback_smoke_records()
    } else if scenario == "udp-forward-smoke" {
        udp_forward_smoke_records()
    } else if scenario == "udp-deny-smoke" {
        udp_deny_smoke_records()
    } else {
        run_scenario(ScenarioName::parse(scenario)?)
    };
    for record in records {
        println!("{}", record.to_json_line());
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "usage: foxprox-lab list | run [--scenario] <{}|env-smoke|tun-smoke|setup-smoke|handoff-smoke|writeback-smoke|udp-forward-smoke|udp-deny-smoke>",
        ScenarioName::list().join("|")
    );
}

fn env_smoke_records() -> Vec<AuditRecord> {
    let tun_exists = Path::new("/dev/net/tun").exists();
    let bwrap_version = Command::new("bwrap").arg("--version").output();
    let bwrap_available = bwrap_version
        .as_ref()
        .is_ok_and(|output| output.status.success());
    let bwrap_text = bwrap_version
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string());

    vec![
        AuditRecord::new(
            EventKind::TunConfigured,
            "env-smoke",
            if tun_exists {
                Decision::Allow
            } else {
                Decision::FailClosed
            },
            if tun_exists {
                "/dev/net/tun exists"
            } else {
                "/dev/net/tun missing"
            },
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Unsupported)
        .with_metadata("path", "/dev/net/tun"),
        AuditRecord::new(
            EventKind::SandboxStarted,
            "env-smoke",
            if bwrap_available {
                Decision::Allow
            } else {
                Decision::FailClosed
            },
            if bwrap_available {
                "bwrap executable responds"
            } else {
                "bwrap executable unavailable"
            },
        )
        .with_frontend(Frontend::Harness)
        .with_metadata("bwrap_version", bwrap_text),
    ]
}

fn tun_smoke_records() -> Vec<AuditRecord> {
    let output = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--",
            "/bin/sh",
            "-lc",
            "ip tuntap add dev foxprox0 mode tun && ip addr add 10.0.2.2/24 dev foxprox0 && ip link set foxprox0 up && ip -o addr show dev foxprox0",
        ])
        .output();

    command_record(
        "tun-smoke",
        output,
        "bwrap namespace TUN setup command succeeded",
        "bwrap namespace TUN setup command failed",
        "failed to execute bwrap TUN smoke",
    )
}

fn setup_smoke_records() -> Vec<AuditRecord> {
    let helper = match setup_helper_path() {
        Ok(path) => path,
        Err(err) => {
            return vec![AuditRecord::new(
                EventKind::TunConfigured,
                "setup-smoke",
                Decision::FailClosed,
                err,
            )
            .with_frontend(Frontend::Harness)
            .with_protocol(Protocol::Unsupported)]
        }
    };
    let target_dir = match helper.parent().and_then(|path| path.parent()) {
        Some(path) => path.to_path_buf(),
        None => {
            return vec![AuditRecord::new(
                EventKind::TunConfigured,
                "setup-smoke",
                Decision::FailClosed,
                format!(
                    "could not derive target directory from {}",
                    helper.display()
                ),
            )
            .with_frontend(Frontend::Harness)
            .with_protocol(Protocol::Unsupported)]
        }
    };
    let output = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
        ])
        .arg(&target_dir)
        .arg(&target_dir)
        .args(["--proc", "/proc", "--"])
        .arg(&helper)
        .arg("--configure-only")
        .output();

    command_record(
        "setup-smoke",
        output,
        "foxproxsetup direct TUN setup succeeded inside bwrap",
        "foxproxsetup direct TUN setup failed inside bwrap",
        "failed to execute foxproxsetup setup smoke",
    )
}

#[cfg(unix)]
fn handoff_smoke_records() -> Vec<AuditRecord> {
    match run_handoff_smoke() {
        Ok(mut record) => {
            record = record.with_metadata("fd_valid_after_helper_exit", "true");
            vec![record]
        }
        Err(err) => vec![AuditRecord::new(
            EventKind::TunConfigured,
            "handoff-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Unsupported)],
    }
}

#[cfg(not(unix))]
fn handoff_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::TunConfigured,
        "handoff-smoke",
        Decision::FailClosed,
        "handoff smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Unsupported)]
}

#[cfg(unix)]
fn run_handoff_smoke() -> Result<AuditRecord, String> {
    use std::os::fd::AsRawFd;

    let helper = setup_helper_path()?;
    let target_dir = helper
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| {
            format!(
                "could not derive target directory from {}",
                helper.display()
            )
        })?
        .to_path_buf();
    let socket_dir = target_dir.join(format!("foxprox-handoff-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create handoff smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind handoff smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make handoff listener nonblocking: {err}"))?;

    let mut child = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
        ])
        .arg(&target_dir)
        .arg(&target_dir)
        .args(["--bind"])
        .arg(&socket_dir)
        .arg(&socket_dir)
        .args(["--proc", "/proc", "--"])
        .env("FOXPROX_SETUP_SOCKET", &socket_path)
        .arg(&helper)
        .args(["--", "/usr/bin/true"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap handoff smoke: {err}"))?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received_fd = None;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _addr)) => {
                received_fd = Some(fd_handoff::recv_fd(stream.as_raw_fd())?);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(format!("handoff socket accept failed: {err}")),
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap handoff smoke: {err}"))?
        {
            return Err(format!(
                "foxproxsetup exited before sending TUN fd: {status}"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let fd = received_fd.ok_or_else(|| "timed out waiting for TUN fd handoff".to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap handoff smoke: {err}"))?;
    let fd_valid = fd_handoff::fd_is_valid(fd);
    fd_handoff::close_fd(fd);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);

    let decision = if output.status.success() && fd_valid {
        Decision::Allow
    } else {
        Decision::FailClosed
    };
    let reason = if output.status.success() && fd_valid {
        "foxproxsetup handed off a live TUN fd and target exited"
    } else if !output.status.success() {
        "foxproxsetup handoff bwrap command failed"
    } else {
        "received TUN fd was invalid after helper exit"
    };
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(EventKind::TunConfigured, "handoff-smoke", decision, reason)
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Unsupported)
        .with_metadata("status", output.status.to_string());
    if !stdout.is_empty() {
        record = record.with_metadata("stdout", stdout);
    }
    if !stderr.is_empty() {
        record = record.with_metadata("stderr", stderr);
    }
    Ok(record)
}

#[cfg(unix)]
fn writeback_smoke_records() -> Vec<AuditRecord> {
    match run_writeback_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::UdpFlowCreated,
            "writeback-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Udp)],
    }
}

#[cfg(not(unix))]
fn writeback_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::UdpFlowCreated,
        "writeback-smoke",
        Decision::FailClosed,
        "write-back smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)]
}

#[cfg(unix)]
fn run_writeback_smoke() -> Result<AuditRecord, String> {
    let helper = setup_helper_path()?;
    let target_dir = helper
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| {
            format!(
                "could not derive target directory from {}",
                helper.display()
            )
        })?
        .to_path_buf();
    let socket_dir = target_dir.join(format!("foxprox-writeback-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create write-back smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind write-back smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make write-back listener nonblocking: {err}"))?;

    let mut child = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
        ])
        .arg(&target_dir)
        .arg(&target_dir)
        .args(["--bind"])
        .arg(&socket_dir)
        .arg(&socket_dir)
        .args(["--proc", "/proc", "--"])
        .env("FOXPROX_SETUP_SOCKET", &socket_path)
        .arg(&helper)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'probe',('10.0.2.1',5353)); data,_=s.recvfrom(64); sys.exit(0 if data==b'foxprox' else 3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap write-back smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd_handoff::set_nonblocking(fd)?;
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut replied = false;
    while Instant::now() < deadline {
        match fd_handoff::read_fd(fd, &mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                if let Ok(reply) = synthesize_udp_echo_reply(packet, b"foxprox") {
                    fd_handoff::write_all_fd(fd, &reply)?;
                    replied = true;
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during write-back smoke: {err}"
                ))
            }
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap write-back smoke: {err}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|err| format!("failed to collect early ping output: {err}"))?;
            return Err(format!(
                "UDP probe target exited before synthetic reply: {}; stdout={:?}; stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !replied {
        return Err("timed out waiting for UDP probe packet on handed-off TUN fd".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap write-back smoke: {err}"))?;
    fd_handoff::close_fd(fd);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::UdpFlowCreated,
        "writeback-smoke",
        if output.status.success() {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if output.status.success() {
            "sandbox UDP probe received synthetic reply through handed-off TUN fd"
        } else {
            "synthetic UDP reply was written but sandbox probe command failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("reply_written", replied.to_string());
    if !stdout.is_empty() {
        record = record.with_metadata("stdout", stdout);
    }
    if !stderr.is_empty() {
        record = record.with_metadata("stderr", stderr);
    }
    Ok(record)
}

fn synthesize_udp_echo_reply(request_packet: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let parsed = foxprox_core::packet::parse_ipv4(request_packet)?;
    let udp = foxprox_core::packet::parse_udp(parsed.payload)?;
    if !matches!(udp.destination_port, 5353 | 5354) || udp.payload != b"probe" {
        return Err("not a harness UDP probe".to_string());
    }
    foxprox_core::packet::synthesize_udp_reply(request_packet, payload)
}

#[cfg(unix)]
fn udp_forward_smoke_records() -> Vec<AuditRecord> {
    match run_udp_forward_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::UdpFlowCreated,
            "udp-forward-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Udp)],
    }
}

#[cfg(not(unix))]
fn udp_forward_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::UdpFlowCreated,
        "udp-forward-smoke",
        Decision::FailClosed,
        "UDP forward smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)]
}

#[cfg(unix)]
fn run_udp_forward_smoke() -> Result<AuditRecord, String> {
    let echo = UdpSocket::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind host UDP echo fixture: {err}"))?;
    let echo_addr = echo
        .local_addr()
        .map_err(|err| format!("failed to inspect host UDP echo fixture: {err}"))?;
    echo.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("failed to set host UDP echo timeout: {err}"))?;
    let echo_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut buf = [0_u8; 2048];
        let (n, peer) = echo.recv_from(&mut buf).map_err(|err| {
            format!("host UDP echo fixture did not receive egress datagram: {err}")
        })?;
        let mut response = b"egress:".to_vec();
        response.extend_from_slice(&buf[..n]);
        echo.send_to(&response, peer)
            .map_err(|err| format!("host UDP echo fixture failed to reply: {err}"))?;
        Ok(())
    });

    let helper = setup_helper_path()?;
    let target_dir = helper
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| {
            format!(
                "could not derive target directory from {}",
                helper.display()
            )
        })?
        .to_path_buf();
    let socket_dir = target_dir.join(format!("foxprox-udp-forward-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create UDP forward smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind UDP forward smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make UDP forward listener nonblocking: {err}"))?;

    let mut child = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
        ])
        .arg(&target_dir)
        .arg(&target_dir)
        .args(["--bind"])
        .arg(&socket_dir)
        .arg(&socket_dir)
        .args(["--proc", "/proc", "--"])
        .env("FOXPROX_SETUP_SOCKET", &socket_path)
        .arg(&helper)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b'probe',('203.0.113.10',5354)); data,_=s.recvfrom(64); sys.exit(0 if data==b'egress:probe' else 3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap UDP forward smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd_handoff::set_nonblocking(fd)?;
    let destination_ip = "203.0.113.10"
        .parse()
        .map_err(|err| format!("invalid UDP smoke destination IP: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-udp-forward-smoke", RuleAction::Allow)
                .protocol(Protocol::Udp)
                .destination(Cidr::host(destination_ip))
                .port(5354),
        ),
    );
    let mut runtime = TransparentUdpRuntime::new(policy, LocalUdpEgress::new(echo_addr)?);
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut forwarded = false;
    while Instant::now() < deadline {
        match fd_handoff::read_fd(fd, &mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                if let Some(reply) = runtime.handle_ipv4_packet("udp-forward-smoke", packet)? {
                    fd_handoff::write_all_fd(fd, &reply)?;
                    forwarded = true;
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during UDP forward smoke: {err}"
                ))
            }
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap UDP forward smoke: {err}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|err| format!("failed to collect early UDP forward output: {err}"))?;
            return Err(format!(
                "UDP forward target exited before reply: {}; stdout={:?}; stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !forwarded {
        return Err(
            "timed out waiting for UDP forward probe packet on handed-off TUN fd".to_string(),
        );
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap UDP forward smoke: {err}"))?;
    fd_handoff::close_fd(fd);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let echo_result = echo_thread
        .join()
        .map_err(|_| "host UDP echo fixture thread panicked".to_string())?;
    echo_result?;

    let runtime_audit = runtime.audit.last().cloned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::UdpFlowCreated,
        "udp-forward-smoke",
        if output.status.success() {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if output.status.success() {
            "sandbox UDP probe was forwarded through host UDP egress and returned over TUN"
        } else {
            "host UDP egress forwarded a reply but sandbox probe command failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("forwarded", forwarded.to_string())
    .with_metadata("egress_fixture", echo_addr.to_string());
    if let Some(audit) = runtime_audit {
        let runtime_audit_json = audit.to_json_line();
        record = record
            .with_metadata("policy_decision", audit.decision.as_str())
            .with_metadata("policy_reason", audit.reason.clone())
            .with_metadata("runtime_audit", runtime_audit_json);
        if let Some(rule_id) = audit.rule_id {
            record = record.with_metadata("rule_id", rule_id);
        }
    }
    if !stdout.is_empty() {
        record = record.with_metadata("stdout", stdout);
    }
    if !stderr.is_empty() {
        record = record.with_metadata("stderr", stderr);
    }
    Ok(record)
}

#[cfg(unix)]
fn udp_deny_smoke_records() -> Vec<AuditRecord> {
    match run_udp_deny_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::UdpFlowCreated,
            "udp-deny-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Udp)],
    }
}

#[cfg(not(unix))]
fn udp_deny_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::UdpFlowCreated,
        "udp-deny-smoke",
        Decision::FailClosed,
        "UDP deny smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)]
}

#[cfg(unix)]
fn run_udp_deny_smoke() -> Result<AuditRecord, String> {
    let echo = UdpSocket::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind denied UDP echo fixture: {err}"))?;
    let echo_addr = echo
        .local_addr()
        .map_err(|err| format!("failed to inspect denied UDP echo fixture: {err}"))?;
    let helper = setup_helper_path()?;
    let target_dir = helper
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| {
            format!(
                "could not derive target directory from {}",
                helper.display()
            )
        })?
        .to_path_buf();
    let socket_dir = target_dir.join(format!("foxprox-udp-deny-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create UDP deny smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind UDP deny smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make UDP deny listener nonblocking: {err}"))?;

    let mut child = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
        ])
        .arg(&target_dir)
        .arg(&target_dir)
        .args(["--bind"])
        .arg(&socket_dir)
        .arg(&socket_dir)
        .args(["--proc", "/proc", "--"])
        .env("FOXPROX_SETUP_SOCKET", &socket_path)
        .arg(&helper)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b'probe',('203.0.113.11',5354));\ntry:\n data,_=s.recvfrom(64); sys.exit(4)\nexcept socket.timeout:\n sys.exit(0)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap UDP deny smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd_handoff::set_nonblocking(fd)?;
    let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
    let mut runtime = TransparentUdpRuntime::new(policy, LocalUdpEgress::new(echo_addr)?);
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut denied = false;
    while Instant::now() < deadline {
        match fd_handoff::read_fd(fd, &mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                if runtime
                    .handle_ipv4_packet("udp-deny-smoke", packet)?
                    .is_some()
                {
                    return Err("denied UDP smoke unexpectedly produced a reply".to_string());
                }
                denied = runtime
                    .audit
                    .last()
                    .is_some_and(|audit| audit.decision == Decision::DenyDrop);
                if denied {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during UDP deny smoke: {err}"
                ))
            }
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap UDP deny smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !denied {
        return Err("timed out waiting for denied UDP packet audit".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap UDP deny smoke: {err}"))?;
    fd_handoff::close_fd(fd);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let runtime_audit = runtime.audit.last().cloned();
    let egress_calls = runtime.egress.calls;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let success = output.status.success() && egress_calls == 0;
    let mut record = AuditRecord::new(
        EventKind::UdpFlowCreated,
        "udp-deny-smoke",
        if success {
            Decision::DenyDrop
        } else {
            Decision::FailClosed
        },
        if success {
            "sandbox UDP probe was denied, no egress call occurred, and target timed out"
        } else {
            "denied UDP smoke did not fail closed as expected"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("denied", denied.to_string())
    .with_metadata("egress_calls", egress_calls.to_string());
    if let Some(audit) = runtime_audit {
        let runtime_audit_json = audit.to_json_line();
        record = record
            .with_metadata("policy_decision", audit.decision.as_str())
            .with_metadata("policy_reason", audit.reason.clone())
            .with_metadata("runtime_audit", runtime_audit_json);
    }
    if !stdout.is_empty() {
        record = record.with_metadata("stdout", stdout);
    }
    if !stderr.is_empty() {
        record = record.with_metadata("stderr", stderr);
    }
    Ok(record)
}

#[cfg(unix)]
struct LocalUdpEgress {
    socket: UdpSocket,
    fixture: std::net::SocketAddr,
    calls: usize,
}

#[cfg(unix)]
impl LocalUdpEgress {
    fn new(fixture: std::net::SocketAddr) -> Result<Self, String> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .map_err(|err| format!("failed to bind host UDP egress socket: {err}"))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("failed to set host UDP egress timeout: {err}"))?;
        Ok(Self {
            socket,
            fixture,
            calls: 0,
        })
    }
}

#[cfg(unix)]
impl EgressBackend for LocalUdpEgress {
    fn execute(&mut self, request: &EgressRequest) -> Result<EgressOutcome, String> {
        let EgressRequest::UdpDatagram { bytes, .. } = request else {
            return Err("local UDP egress only supports UDP datagrams".to_string());
        };
        self.calls += 1;
        self.socket
            .send_to(bytes, self.fixture)
            .map_err(|err| format!("host UDP egress send failed: {err}"))?;
        let mut reply_payload = [0_u8; 2048];
        let (reply_len, _) = self
            .socket
            .recv_from(&mut reply_payload)
            .map_err(|err| format!("host UDP egress receive failed: {err}"))?;
        Ok(EgressOutcome {
            connected: true,
            bytes_sent: bytes.len() as u64,
            bytes_received: reply_len as u64,
            message: "local UDP fixture egress".to_string(),
            response_payload: reply_payload[..reply_len].to_vec(),
        })
    }
}

#[cfg(unix)]
fn accept_handoff_fd(
    listener: &UnixListener,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<i32, String> {
    use std::os::fd::AsRawFd;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _addr)) => return fd_handoff::recv_fd(stream.as_raw_fd()),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(format!("handoff socket accept failed: {err}")),
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap setup helper: {err}"))?
        {
            return Err(format!(
                "foxproxsetup exited before sending TUN fd: {status}"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for TUN fd handoff".to_string())
}

fn setup_helper_path() -> Result<std::path::PathBuf, String> {
    if let Ok(path) = env::var("FOXPROX_SETUP_HELPER") {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "FOXPROX_SETUP_HELPER points to missing helper {}",
            path.display()
        ));
    }
    let mut path =
        env::current_exe().map_err(|err| format!("could not find current exe: {err}"))?;
    path.set_file_name("foxproxsetup");
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "foxproxsetup helper not found at {}; build it first or set FOXPROX_SETUP_HELPER",
            path.display()
        ))
    }
}

fn command_record(
    sandbox_id: &str,
    output: std::io::Result<std::process::Output>,
    success_reason: &str,
    failure_reason: &str,
    exec_failure_prefix: &str,
) -> Vec<AuditRecord> {
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let mut record = AuditRecord::new(
                EventKind::TunConfigured,
                sandbox_id,
                if output.status.success() {
                    Decision::Allow
                } else {
                    Decision::FailClosed
                },
                if output.status.success() {
                    success_reason
                } else {
                    failure_reason
                },
            )
            .with_frontend(Frontend::Harness)
            .with_protocol(Protocol::Unsupported)
            .with_metadata("status", output.status.to_string());
            if !stdout.is_empty() {
                record = record.with_metadata("stdout", stdout);
            }
            if !stderr.is_empty() {
                record = record.with_metadata("stderr", stderr);
            }
            vec![record]
        }
        Err(err) => vec![AuditRecord::new(
            EventKind::TunConfigured,
            sandbox_id,
            Decision::FailClosed,
            format!("{exec_failure_prefix}: {err}"),
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Unsupported)],
    }
}

#[cfg(unix)]
mod fd_handoff {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::RawFd;
    use std::os::raw::{c_int, c_void};

    const SOL_SOCKET: c_int = 1;
    const SCM_RIGHTS: c_int = 1;
    const F_GETFD: c_int = 1;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x800;

    #[repr(C)]
    struct Iovec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    #[repr(C)]
    struct Msghdr {
        msg_name: *mut c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut c_void,
        msg_controllen: usize,
        msg_flags: c_int,
    }

    #[repr(C)]
    struct Cmsghdr {
        cmsg_len: usize,
        cmsg_level: c_int,
        cmsg_type: c_int,
    }

    extern "C" {
        fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    pub(super) fn recv_fd(socket_fd: RawFd) -> Result<RawFd, String> {
        let mut byte = [0_u8];
        let mut iov = Iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        let mut control = vec![0_u8; cmsg_space(size_of::<RawFd>())];
        let mut msg = Msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let received = unsafe { recvmsg(socket_fd, &mut msg, 0) };
        if received < 0 {
            return Err(format!(
                "failed to receive TUN fd over handoff socket: {}",
                io::Error::last_os_error()
            ));
        }
        if received == 0 {
            return Err("handoff socket closed without fd".to_string());
        }
        let header = control.as_ptr().cast::<Cmsghdr>();
        let valid_header = unsafe {
            (*header).cmsg_len >= cmsg_len(size_of::<RawFd>())
                && (*header).cmsg_level == SOL_SOCKET
                && (*header).cmsg_type == SCM_RIGHTS
        };
        if !valid_header {
            return Err("handoff message did not contain SCM_RIGHTS fd".to_string());
        }
        let data = unsafe {
            control
                .as_ptr()
                .add(cmsg_align(size_of::<Cmsghdr>()))
                .cast::<RawFd>()
        };
        Ok(unsafe { *data })
    }

    pub(super) fn fd_is_valid(fd: RawFd) -> bool {
        unsafe { fcntl(fd, F_GETFD) >= 0 }
    }

    pub(super) fn set_nonblocking(fd: RawFd) -> Result<(), String> {
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(format!(
                "failed to read fd flags: {}",
                io::Error::last_os_error()
            ));
        }
        let rc = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "failed to set fd nonblocking: {}",
                io::Error::last_os_error()
            ))
        }
    }

    pub(super) fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let rc = unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if rc >= 0 {
            Ok(rc as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), String> {
        while !buf.is_empty() {
            let rc = unsafe { write(fd, buf.as_ptr().cast(), buf.len()) };
            if rc > 0 {
                buf = &buf[rc as usize..];
            } else if rc == 0 {
                return Err("short write to TUN fd".to_string());
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("failed to write TUN fd: {err}"));
            }
        }
        Ok(())
    }

    pub(super) fn close_fd(fd: RawFd) {
        unsafe {
            close(fd);
        }
    }

    fn cmsg_align(len: usize) -> usize {
        let align = size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    fn cmsg_len(payload_len: usize) -> usize {
        cmsg_align(size_of::<Cmsghdr>()) + payload_len
    }

    fn cmsg_space(payload_len: usize) -> usize {
        cmsg_align(size_of::<Cmsghdr>()) + cmsg_align(payload_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_command() {
        assert!(run(vec!["list".to_string()]).is_ok());
    }

    #[test]
    fn rejects_unknown_scenario() {
        assert!(run(vec!["run".to_string(), "missing".to_string()]).is_err());
    }
}
