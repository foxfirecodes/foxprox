use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(unix)]
use foxprox_device::fd as fd_handoff;

use foxprox_broker::TransparentBroker;
use foxprox_core::audit::{AuditRecord, Decision, EventKind, Frontend, Protocol};
use foxprox_core::egress::{EgressBackend, EgressRequest, MockEgressBackend};
use foxprox_core::frontend::{
    build_http_origin_request, parse_socks5_no_auth_greeting, read_http_headers,
    socks5_connect_success_response, HTTP_CONNECT_ESTABLISHED_RESPONSE,
    HTTP_FORBIDDEN_CLOSE_RESPONSE, SOCKS5_NO_AUTH_RESPONSE,
};
use foxprox_core::origin::parse_socks5_connect_request;
use foxprox_core::policy::{Cidr, PolicyConfig, PolicyEngine, PolicyRule, RuleAction};
use foxprox_core::runtime::{
    ExplicitProxyRuntime, TransparentDnsRuntime, TransparentTcpBridgeRuntime, TransparentTcpRuntime,
};
use foxprox_core::scenario::{run_scenario, ScenarioName};
use foxprox_core::smoltcp_gate::feed_tcp_syn_to_smoltcp_listener;
use foxprox_egress::{LocalTcpConnectEgress, LocalTcpStreamEgress, LocalUdpEgress};

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
            println!("ping-smoke");
            println!("udp-forward-smoke");
            println!("udp-deny-smoke");
            println!("quic-smoke");
            println!("dns-smoke");
            println!("dns-attribution-smoke");
            println!("tcp-syn-smoke");
            println!("tcp-synack-smoke");
            println!("tcp-bridge-smoke");
            println!("tcp-bridge-http-deny-smoke");
            println!("tls-sni-deny-smoke");
            println!("tcp-bridge-deny-smoke");
            println!("http-proxy-smoke");
            println!("https-connect-smoke");
            println!("socks5-smoke");
            println!("proxy-deny-smoke");
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
    } else if scenario == "ping-smoke" {
        ping_smoke_records()
    } else if scenario == "udp-forward-smoke" {
        udp_forward_smoke_records()
    } else if scenario == "udp-deny-smoke" {
        udp_deny_smoke_records()
    } else if scenario == "quic-smoke" {
        quic_smoke_records()
    } else if scenario == "dns-smoke" {
        dns_smoke_records()
    } else if scenario == "dns-attribution-smoke" {
        dns_attribution_smoke_records()
    } else if scenario == "tcp-syn-smoke" {
        tcp_syn_smoke_records()
    } else if scenario == "tcp-synack-smoke" {
        tcp_synack_smoke_records()
    } else if scenario == "tcp-bridge-smoke" {
        tcp_bridge_smoke_records()
    } else if scenario == "tcp-bridge-http-deny-smoke" {
        tcp_bridge_http_deny_smoke_records()
    } else if scenario == "tls-sni-deny-smoke" {
        tls_sni_deny_smoke_records()
    } else if scenario == "tcp-bridge-deny-smoke" {
        tcp_bridge_deny_smoke_records()
    } else if scenario == "http-proxy-smoke" {
        http_proxy_smoke_records()
    } else if scenario == "https-connect-smoke" {
        https_connect_smoke_records()
    } else if scenario == "socks5-smoke" {
        socks5_smoke_records()
    } else if scenario == "proxy-deny-smoke" {
        proxy_deny_smoke_records()
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
        "usage: foxprox-lab list | run [--scenario] <{}|env-smoke|tun-smoke|setup-smoke|handoff-smoke|writeback-smoke|udp-forward-smoke|udp-deny-smoke|dns-smoke|dns-attribution-smoke|tcp-syn-smoke|tcp-synack-smoke|tcp-bridge-smoke|tcp-bridge-deny-smoke|http-proxy-smoke|https-connect-smoke|socks5-smoke|proxy-deny-smoke>",
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
                received_fd = Some(fd_handoff::recv_device_fd(stream.as_raw_fd())?);
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
    let fd_valid = fd.is_valid();
    fd.close();
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
    fd.set_nonblocking()?;
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut replied = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                if let Ok(reply) = synthesize_udp_echo_reply(packet, b"foxprox") {
                    fd.write_packet(&reply)?;
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
    fd.close();
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

#[cfg(unix)]
fn ping_smoke_records() -> Vec<AuditRecord> {
    match run_ping_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::IcmpMessage,
            "ping-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Icmp)],
    }
}

#[cfg(not(unix))]
fn ping_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::IcmpMessage,
        "ping-smoke",
        Decision::FailClosed,
        "ping smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Icmp)]
}

#[cfg(unix)]
fn run_ping_smoke() -> Result<AuditRecord, String> {
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
    let socket_dir = target_dir.join(format!("foxprox-ping-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create ping smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind ping smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make ping listener nonblocking: {err}"))?;

    let mut child = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--cap-add",
            "CAP_NET_RAW",
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
        .args(["--", "/usr/bin/ping", "-c", "1", "-W", "3", "10.0.2.1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap ping smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let mut broker = TransparentBroker::new(
        "10.0.2.1:53".parse().expect("static broker DNS addr valid"),
        [],
        PolicyEngine::new(PolicyConfig::deny_by_default()),
        MockEgressBackend::new(),
        PolicyEngine::new(PolicyConfig::deny_by_default()),
        MockEgressBackend::new(),
        PolicyEngine::new(PolicyConfig::deny_by_default().allow_ping(true)),
    );
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut reply_written = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let step = broker.handle_ipv4_packet("ping-smoke", &buf[..n])?;
                for reply in step.packets_to_device {
                    fd.write_packet(&reply)?;
                    reply_written = true;
                }
                if reply_written {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(format!("failed to read TUN fd during ping smoke: {err}")),
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap ping smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !reply_written {
        return Err("timed out waiting for ICMP echo request on handed-off TUN fd".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap ping smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let runtime_audit = broker
        .audit
        .iter()
        .rev()
        .find(|audit| audit.kind == EventKind::IcmpMessage)
        .cloned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::IcmpMessage,
        "ping-smoke",
        if output.status.success() {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if output.status.success() {
            "sandbox ping received a synthetic ICMP echo reply through handed-off TUN fd"
        } else {
            "ICMP echo reply was written but sandbox ping command failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Icmp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("reply_written", reply_written.to_string());
    if let Some(audit) = runtime_audit {
        record = record
            .with_metadata("policy_decision", audit.decision.as_str())
            .with_metadata("policy_reason", audit.reason.clone())
            .with_metadata("runtime_audit", audit.to_json_line());
    }
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
    fd.set_nonblocking()?;
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
    let mut broker = TransparentBroker::new(
        "10.0.2.1:53".parse().expect("static broker DNS addr valid"),
        [],
        policy,
        LocalUdpEgress::new(echo_addr)?,
        PolicyEngine::new(PolicyConfig::deny_by_default()),
        MockEgressBackend::new(),
        PolicyEngine::new(PolicyConfig::deny_by_default()),
    );
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut forwarded = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let step = broker.handle_ipv4_packet("udp-forward-smoke", packet)?;
                for reply in step.packets_to_device {
                    fd.write_packet(&reply)?;
                    forwarded = true;
                }
                if forwarded {
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
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let echo_result = echo_thread
        .join()
        .map_err(|_| "host UDP echo fixture thread panicked".to_string())?;
    echo_result?;

    let runtime_audit = broker
        .audit
        .iter()
        .rev()
        .find(|audit| audit.kind == EventKind::UdpFlowCreated)
        .cloned();
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
fn quic_smoke_records() -> Vec<AuditRecord> {
    match run_quic_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::QuicCandidateFlow,
            "quic-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Quic)],
    }
}

#[cfg(not(unix))]
fn quic_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::QuicCandidateFlow,
        "quic-smoke",
        Decision::FailClosed,
        "QUIC smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Quic)]
}

#[cfg(unix)]
fn run_quic_smoke() -> Result<AuditRecord, String> {
    let echo = UdpSocket::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind QUIC UDP fixture: {err}"))?;
    let echo_addr = echo
        .local_addr()
        .map_err(|err| format!("failed to inspect QUIC UDP fixture: {err}"))?;
    echo.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("failed to set QUIC fixture timeout: {err}"))?;
    let echo_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut buf = [0_u8; 1500];
        let (n, peer) = echo
            .recv_from(&mut buf)
            .map_err(|err| format!("QUIC UDP fixture failed to receive datagram: {err}"))?;
        if n == 0 || buf[0] & 0x80 == 0 {
            return Err("QUIC fixture received a non-QUIC-candidate datagram".to_string());
        }
        echo.send_to(b"quic-reply", peer)
            .map_err(|err| format!("QUIC UDP fixture failed to send reply: {err}"))?;
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
    let socket_dir = target_dir.join(format!("foxprox-quic-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create QUIC smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind QUIC smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make QUIC listener nonblocking: {err}"))?;

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
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b'\\xc3\\x00\\x00\\x00probe',('203.0.113.30',443)); data,_=s.recvfrom(64); sys.exit(0 if data==b'quic-reply' else 3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap QUIC smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().allow_quic(true).with_rule(
            PolicyRule::new("allow-quic-smoke", RuleAction::Allow)
                .protocol(Protocol::Quic)
                .port(443),
        ),
    );
    let mut broker = TransparentBroker::new(
        "10.0.2.1:53".parse().expect("static broker DNS addr valid"),
        [],
        policy,
        LocalUdpEgress::new(echo_addr)?,
        PolicyEngine::new(PolicyConfig::deny_by_default()),
        MockEgressBackend::new(),
        PolicyEngine::new(PolicyConfig::deny_by_default()),
    );
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut forwarded = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let step = broker.handle_ipv4_packet("quic-smoke", &buf[..n])?;
                for reply in step.packets_to_device {
                    fd.write_packet(&reply)?;
                    forwarded = true;
                }
                if forwarded {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(format!("failed to read TUN fd during QUIC smoke: {err}")),
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap QUIC smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !forwarded {
        return Err("timed out waiting for QUIC candidate flow".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap QUIC smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    echo_thread
        .join()
        .map_err(|_| "QUIC UDP fixture thread panicked".to_string())??;
    let runtime_audit = broker
        .audit
        .iter()
        .rev()
        .find(|audit| audit.kind == EventKind::QuicCandidateFlow)
        .cloned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::QuicCandidateFlow,
        "quic-smoke",
        if output.status.success() {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if output.status.success() {
            "sandbox UDP/443 QUIC candidate was allowed, forwarded, and returned over TUN"
        } else {
            "QUIC candidate reply was written but sandbox command failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Quic)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("forwarded", forwarded.to_string())
    .with_metadata("egress_fixture", echo_addr.to_string())
    .with_metadata("egress_calls", broker.udp.egress.calls().to_string());
    if let Some(audit) = runtime_audit {
        record = record
            .with_metadata("policy_decision", audit.decision.as_str())
            .with_metadata("policy_reason", audit.reason.clone())
            .with_metadata("runtime_audit", audit.to_json_line());
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
fn dns_smoke_records() -> Vec<AuditRecord> {
    match run_dns_smoke() {
        Ok(record) => vec![record],
        Err(err) => {
            vec![
                AuditRecord::new(EventKind::DnsQuery, "dns-smoke", Decision::FailClosed, err)
                    .with_frontend(Frontend::Harness)
                    .with_protocol(Protocol::Dns),
            ]
        }
    }
}

#[cfg(not(unix))]
fn dns_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::DnsQuery,
        "dns-smoke",
        Decision::FailClosed,
        "DNS smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Dns)]
}

#[cfg(unix)]
fn run_dns_smoke() -> Result<AuditRecord, String> {
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
    let socket_dir = target_dir.join(format!("foxprox-dns-smoke-{}", std::process::id()));
    let socket_path = socket_dir.join("setup.sock");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create DNS smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind DNS smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make DNS listener nonblocking: {err}"))?;

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
            "import socket,sys; q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + b'\\x03lab\\x07example\\x00' + b'\\x00\\x01\\x00\\x01'; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(q,('10.0.2.1',53)); data,_=s.recvfrom(512); sys.exit(0 if data[:2]==b'\\x12\\x34' and b'\\xcb\\x00\\x71\\x4d' in data else 3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap DNS smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let answer_ip = "203.0.113.77"
        .parse()
        .map_err(|err| format!("invalid DNS smoke answer IP: {err}"))?;
    let mut runtime = TransparentDnsRuntime::new([("lab.example".to_string(), answer_ip)]);
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut answered = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                if let Some(reply) = runtime.handle_ipv4_packet("dns-smoke", packet)? {
                    fd.write_packet(&reply)?;
                    answered = true;
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(format!("failed to read TUN fd during DNS smoke: {err}")),
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap DNS smoke: {err}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|err| format!("failed to collect early DNS output: {err}"))?;
            return Err(format!(
                "DNS target exited before reply: {}; stdout={:?}; stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !answered {
        return Err("timed out waiting for DNS query on handed-off TUN fd".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap DNS smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let runtime_audit = runtime.audit.last().cloned();
    let hostname = runtime_audit
        .as_ref()
        .and_then(|audit| audit.hostname.clone())
        .unwrap_or_else(|| "lab.example".to_string());
    let attribution = runtime
        .dns_cache
        .attribution_for(std::net::IpAddr::V4(answer_ip), 2);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::DnsQuery,
        "dns-smoke",
        if output.status.success() {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if output.status.success() {
            "sandbox DNS A query was answered locally and cached for attribution"
        } else {
            "DNS response was written but sandbox query command failed"
        },
    )
    .with_frontend(Frontend::Tun)
    .with_protocol(Protocol::Dns)
    .with_hostname(
        Some(hostname),
        foxprox_core::audit::AttributionSource::DnsCache,
        foxprox_core::audit::AttributionConfidence::Medium,
    )
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("answer", answer_ip.to_string())
    .with_metadata("attribution_cached", attribution.is_some().to_string());
    if !stdout.is_empty() {
        record = record.with_metadata("stdout", stdout);
    }
    if !stderr.is_empty() {
        record = record.with_metadata("stderr", stderr);
    }
    Ok(record)
}

#[cfg(unix)]
fn dns_attribution_smoke_records() -> Vec<AuditRecord> {
    match run_dns_attribution_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::UdpFlowCreated,
            "dns-attribution-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Udp)],
    }
}

#[cfg(not(unix))]
fn dns_attribution_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::UdpFlowCreated,
        "dns-attribution-smoke",
        Decision::FailClosed,
        "DNS attribution smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)]
}

#[cfg(unix)]
fn run_dns_attribution_smoke() -> Result<AuditRecord, String> {
    let echo = UdpSocket::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind DNS attribution echo fixture: {err}"))?;
    let echo_addr = echo
        .local_addr()
        .map_err(|err| format!("failed to inspect DNS attribution echo fixture: {err}"))?;
    echo.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("failed to set DNS attribution echo timeout: {err}"))?;
    let echo_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut buf = [0_u8; 2048];
        let (n, peer) = echo.recv_from(&mut buf).map_err(|err| {
            format!("DNS attribution echo fixture did not receive egress datagram: {err}")
        })?;
        let mut response = b"egress:".to_vec();
        response.extend_from_slice(&buf[..n]);
        echo.send_to(&response, peer)
            .map_err(|err| format!("DNS attribution echo fixture failed to reply: {err}"))?;
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
    let socket_dir = target_dir.join(format!("fxdns-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create DNS attribution smoke socket dir: {err}"))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind DNS attribution smoke socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make DNS attribution listener nonblocking: {err}"))?;

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
            "import socket,sys; q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + b'\\x03lab\\x07example\\x00' + b'\\x00\\x01\\x00\\x01'; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(q,('10.0.2.1',53)); data,_=s.recvfrom(512);\nassert data[:2]==b'\\x12\\x34' and b'\\xcb\\x00\\x71\\x4d' in data\ns.sendto(b'probe',('203.0.113.77',5354)); data,_=s.recvfrom(64); sys.exit(0 if data==b'egress:probe' else 3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap DNS attribution smoke: {err}"))?;

    let fd = accept_handoff_fd(&listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let answer_ip = "203.0.113.77"
        .parse()
        .map_err(|err| format!("invalid DNS attribution answer IP: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-dns-attributed-example", RuleAction::Allow)
                .protocol(Protocol::Udp)
                .domain_suffix("example")
                .port(5354)
                .require_hostname_attribution(),
        ),
    );
    let mut broker = TransparentBroker::new(
        "10.0.2.1:53".parse().expect("static broker DNS addr valid"),
        [("lab.example".to_string(), answer_ip)],
        policy,
        LocalUdpEgress::new(echo_addr)?,
        PolicyEngine::new(PolicyConfig::deny_by_default()),
        MockEgressBackend::new(),
        PolicyEngine::new(PolicyConfig::deny_by_default()),
    );
    broker.set_tick(2);
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut dns_answered = false;
    let mut forwarded = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let step = broker.handle_ipv4_packet("dns-attribution-smoke", packet)?;
                for reply in step.packets_to_device {
                    fd.write_packet(&reply)?;
                }
                if let Some(audit) = broker.audit.last() {
                    if audit.kind == EventKind::DnsQuery && audit.decision.is_allow() {
                        dns_answered = true;
                    }
                    if audit.kind == EventKind::UdpFlowCreated && audit.decision.is_allow() {
                        forwarded = true;
                        break;
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during DNS attribution smoke: {err}"
                ))
            }
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap DNS attribution smoke: {err}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|err| format!("failed to collect early DNS attribution output: {err}"))?;
            return Err(format!(
                "DNS attribution target exited before UDP reply: {}; stdout={:?}; stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !forwarded {
        return Err("timed out waiting for DNS-attributed UDP flow".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap DNS attribution smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let echo_result = echo_thread
        .join()
        .map_err(|_| "DNS attribution echo fixture thread panicked".to_string())?;
    echo_result?;
    let runtime_audit = broker
        .audit
        .iter()
        .rev()
        .find(|audit| audit.kind == EventKind::UdpFlowCreated)
        .cloned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::UdpFlowCreated,
        "dns-attribution-smoke",
        if output.status.success() {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if output.status.success() {
            "DNS cache attribution allowed subsequent sandbox UDP flow"
        } else {
            "DNS-attributed UDP reply was written but sandbox command failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Udp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("dns_answered", dns_answered.to_string())
    .with_metadata("forwarded", forwarded.to_string());
    if let Some(audit) = runtime_audit {
        let runtime_audit_json = audit.to_json_line();
        record = record
            .with_metadata("policy_decision", audit.decision.as_str())
            .with_metadata("policy_reason", audit.reason.clone())
            .with_metadata("runtime_audit", runtime_audit_json);
        if let Some(hostname) = audit.hostname {
            record = record.with_metadata("attributed_hostname", hostname);
        }
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
fn tcp_syn_smoke_records() -> Vec<AuditRecord> {
    match run_tcp_syn_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::TcpConnectAttempt,
            "tcp-syn-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Tcp)],
    }
}

#[cfg(not(unix))]
fn tcp_syn_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "tcp-syn-smoke",
        Decision::FailClosed,
        "TCP SYN smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)]
}

#[cfg(unix)]
fn run_tcp_syn_smoke() -> Result<AuditRecord, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind TCP connect fixture: {err}"))?;
    let fixture_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect TCP connect fixture: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make TCP fixture nonblocking: {err}"))?;
    let tcp_fixture_thread = std::thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((_stream, _peer)) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(format!("TCP connect fixture accept failed: {err}")),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("TCP connect fixture did not receive egress connect".to_string())
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
    let socket_dir = target_dir.join(format!("fxtcp-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create TCP SYN smoke socket dir: {err}"))?;
    let handoff_listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind TCP SYN smoke handoff socket: {err}"))?;
    handoff_listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make TCP SYN handoff listener nonblocking: {err}"))?;

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
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(1);\ntry:\n s.connect(('203.0.113.20',8080)); sys.exit(4)\nexcept (socket.timeout,OSError):\n sys.exit(0)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap TCP SYN smoke: {err}"))?;

    let fd = accept_handoff_fd(&handoff_listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let destination_ip = "203.0.113.20"
        .parse()
        .map_err(|err| format!("invalid TCP SYN smoke destination IP: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-tcp-syn-smoke", RuleAction::Allow)
                .protocol(Protocol::Tcp)
                .destination(Cidr::host(destination_ip))
                .port(8080),
        ),
    );
    let mut runtime = TransparentTcpRuntime::new(policy, LocalTcpConnectEgress::new(fixture_addr));
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut syn_observed = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let parsed = match foxprox_core::packet::parse_ipv4(packet) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                if parsed.protocol_number != 6 {
                    continue;
                }
                let tcp = match foxprox_core::packet::parse_tcp(parsed.payload) {
                    Ok(tcp) => tcp,
                    Err(_) => continue,
                };
                if tcp.destination_port != 8080 || !tcp.syn {
                    continue;
                }
                runtime.handle_ipv4_packet("tcp-syn-smoke", packet)?;
                syn_observed = runtime
                    .audit
                    .last()
                    .is_some_and(|audit| audit.decision == Decision::Allow);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(format!("failed to read TUN fd during TCP SYN smoke: {err}")),
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap TCP SYN smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !syn_observed {
        return Err("timed out waiting for allowed TCP SYN on handed-off TUN fd".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap TCP SYN smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let egress_calls = runtime.egress.calls();
    let fixture_result = if egress_calls > 0 {
        Some(
            tcp_fixture_thread
                .join()
                .map_err(|_| "TCP connect fixture thread panicked".to_string())?,
        )
    } else {
        None
    };
    if let Some(result) = fixture_result {
        result?;
    }
    let runtime_audit = runtime.audit.last().cloned();
    let success = output.status.success() && syn_observed && egress_calls == 1;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "tcp-syn-smoke",
        if success {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if success {
            "sandbox TCP SYN reached the handed-off TUN fd and invoked policy-gated egress"
        } else {
            "TCP SYN was observed but the sandbox target or egress fixture failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("syn_observed", syn_observed.to_string())
    .with_metadata("egress_calls", egress_calls.to_string())
    .with_metadata("egress_fixture", fixture_addr.to_string());
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
fn tcp_synack_smoke_records() -> Vec<AuditRecord> {
    match run_tcp_synack_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::TcpConnectAttempt,
            "tcp-synack-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Tcp)],
    }
}

#[cfg(not(unix))]
fn tcp_synack_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "tcp-synack-smoke",
        Decision::FailClosed,
        "TCP SYN-ACK smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)]
}

#[cfg(unix)]
fn run_tcp_synack_smoke() -> Result<AuditRecord, String> {
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
    let socket_dir = target_dir.join(format!("fxsak-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create TCP SYN-ACK smoke socket dir: {err}"))?;
    let handoff_listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind TCP SYN-ACK smoke handoff socket: {err}"))?;
    handoff_listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make TCP SYN-ACK handoff listener nonblocking: {err}"))?;

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
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3);\ntry:\n s.connect(('203.0.113.21',8081)); s.close(); sys.exit(0)\nexcept Exception as e:\n print(repr(e)); sys.exit(3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap TCP SYN-ACK smoke: {err}"))?;

    let fd = accept_handoff_fd(&handoff_listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut emitted_packets = 0_usize;
    let mut syn_ack_written = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let parsed = match foxprox_core::packet::parse_ipv4(packet) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                if parsed.protocol_number != 6 {
                    continue;
                }
                let tcp = match foxprox_core::packet::parse_tcp(parsed.payload) {
                    Ok(tcp) => tcp,
                    Err(_) => continue,
                };
                if tcp.destination_port != 8081 || !tcp.syn || tcp.ack {
                    continue;
                }
                let result = feed_tcp_syn_to_smoltcp_listener(
                    packet.to_vec(),
                    parsed.destination,
                    tcp.destination_port,
                )?;
                emitted_packets = result.emitted_packets.len();
                for emitted in &result.emitted_packets {
                    if let Ok(reply_ip) = foxprox_core::packet::parse_ipv4(emitted) {
                        if let Ok(reply_tcp) = foxprox_core::packet::parse_tcp(reply_ip.payload) {
                            if reply_ip.source == parsed.destination
                                && reply_ip.destination == parsed.source
                                && reply_tcp.source_port == tcp.destination_port
                                && reply_tcp.destination_port == tcp.source_port
                                && reply_tcp.syn
                                && reply_tcp.ack
                            {
                                syn_ack_written = true;
                            }
                        }
                    }
                    fd.write_packet(emitted)?;
                }
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during TCP SYN-ACK smoke: {err}"
                ))
            }
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap TCP SYN-ACK smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !syn_ack_written {
        return Err(
            "timed out before writing a smoltcp SYN-ACK to the handed-off TUN fd".to_string(),
        );
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap TCP SYN-ACK smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let success = output.status.success() && syn_ack_written;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "tcp-synack-smoke",
        if success {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if success {
            "smoltcp SYN-ACK written to TUN completed the sandbox TCP connect"
        } else {
            "smoltcp SYN-ACK was written but the sandbox TCP connect failed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("emitted_packets", emitted_packets.to_string())
    .with_metadata("syn_ack_written", syn_ack_written.to_string());
    if !stdout.is_empty() {
        record = record.with_metadata("stdout", stdout);
    }
    if !stderr.is_empty() {
        record = record.with_metadata("stderr", stderr);
    }
    Ok(record)
}

#[cfg(unix)]
fn tcp_bridge_smoke_records() -> Vec<AuditRecord> {
    match run_tcp_bridge_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::TcpFlowClosed,
            "tcp-bridge-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Tcp)],
    }
}

#[cfg(not(unix))]
fn tcp_bridge_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::TcpFlowClosed,
        "tcp-bridge-smoke",
        Decision::FailClosed,
        "TCP bridge smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)]
}

#[cfg(unix)]
fn run_tcp_bridge_smoke() -> Result<AuditRecord, String> {
    let echo = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind TCP bridge echo fixture: {err}"))?;
    let echo_addr = echo
        .local_addr()
        .map_err(|err| format!("failed to inspect TCP bridge echo fixture: {err}"))?;
    echo.set_nonblocking(true)
        .map_err(|err| format!("failed to make TCP bridge fixture nonblocking: {err}"))?;
    let echo_thread = std::thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match echo.accept() {
                Ok((mut stream, _peer)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .map_err(|err| format!("failed to set TCP fixture read timeout: {err}"))?;
                    let mut buf = [0_u8; 1024];
                    let n = stream.read(&mut buf).map_err(|err| {
                        format!("TCP fixture failed to read bridged bytes: {err}")
                    })?;
                    if n == 0 {
                        return Err("TCP fixture received empty stream".to_string());
                    }
                    let mut reply = b"egress:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    stream
                        .write_all(&reply)
                        .map_err(|err| format!("TCP fixture failed to write reply: {err}"))?;
                    return Ok(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(format!("TCP bridge fixture accept failed: {err}")),
            }
            if Instant::now() >= deadline {
                return Err(
                    "TCP bridge fixture did not receive a host egress connection".to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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
    let socket_dir = target_dir.join(format!("fxbrg-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create TCP bridge smoke socket dir: {err}"))?;
    let handoff_listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind TCP bridge smoke handoff socket: {err}"))?;
    handoff_listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make TCP bridge handoff listener nonblocking: {err}"))?;

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
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(5); s.connect(('203.0.113.22',80)); req=b'GET /public HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'; s.sendall(req); data=s.recv(128); s.close(); sys.exit(0 if data.startswith(b'egress:GET /public') else 4)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap TCP bridge smoke: {err}"))?;

    let fd = accept_handoff_fd(&handoff_listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let bridge_destination: std::net::Ipv4Addr = "203.0.113.22"
        .parse()
        .map_err(|err| format!("invalid TCP bridge destination IP: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-tcp-bridge-smoke", RuleAction::Allow)
                .protocol(Protocol::Tcp)
                .destination(Cidr::host(std::net::IpAddr::V4(bridge_destination)))
                .port(80),
        ),
    );
    let inspect_policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-transparent-http-bridge", RuleAction::Allow)
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_path_prefix("/public"),
        ),
    );
    let inspection = foxprox_core::runtime::TransparentInspectionRuntime::new(inspect_policy);
    let mut bridge_runtime = TransparentTcpBridgeRuntime::listen(bridge_destination, 80, policy)?
        .with_inspection(inspection);
    let mut bridge_egress = LocalTcpStreamEgress::new(echo_addr);
    let mut buf = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut packets_read = 0_u64;
    let mut emitted_packets = 0_u64;
    let mut bridged_bytes = 0_usize;
    let mut response_written = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let step = bridge_runtime.handle_ipv4_packet("tcp-bridge-smoke", packet)?;
                for emitted in step.emitted_packets {
                    emitted_packets += 1;
                    fd.write_packet(&emitted)?;
                }
                if let Some(data) = step.egress_payload {
                    if !data.is_empty() && !response_written {
                        bridged_bytes = data.len();
                        let outcome = bridge_egress.execute(&EgressRequest::TcpStreamData {
                            destination: echo_addr,
                            bytes: data,
                        })?;
                        for emitted in
                            bridge_runtime.send_egress_response(&outcome.response_payload)?
                        {
                            emitted_packets += 1;
                            fd.write_packet(&emitted)?;
                        }
                        response_written = true;
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during TCP bridge smoke: {err}"
                ))
            }
        }
        for emitted in bridge_runtime.poll()? {
            emitted_packets += 1;
            fd.write_packet(&emitted)?;
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap TCP bridge smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap TCP bridge smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let echo_result = echo_thread
        .join()
        .map_err(|_| "TCP bridge echo fixture thread panicked".to_string())?;
    echo_result?;
    let runtime_audit = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::TcpConnectAttempt)
        .cloned();
    let inspect_audit = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::HttpRequest)
        .cloned();
    let policy_allowed = runtime_audit
        .as_ref()
        .is_some_and(|audit| audit.decision.is_allow());
    let success = output.status.success()
        && response_written
        && bridged_bytes == b"GET /public HTTP/1.1\r\nHost: example.com\r\n\r\n".len()
        && policy_allowed
        && inspect_audit
            .as_ref()
            .is_some_and(|audit| audit.decision.is_allow());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::TcpFlowClosed,
        "tcp-bridge-smoke",
        if success {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if success {
            "sandbox TCP bytes were bridged through smoltcp to a host TCP fixture and back"
        } else {
            "TCP bridge smoke failed before sandbox received the host fixture response"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("emitted_packets", emitted_packets.to_string())
    .with_metadata("bridged_bytes", bridged_bytes.to_string())
    .with_metadata("response_written", response_written.to_string())
    .with_metadata("policy_allowed", policy_allowed.to_string())
    .with_metadata("egress_calls", bridge_egress.calls().to_string())
    .with_metadata("egress_fixture", echo_addr.to_string());
    if let Some(audit) = runtime_audit {
        record = record
            .with_metadata("policy_decision", audit.decision.as_str())
            .with_metadata("policy_reason", audit.reason.clone())
            .with_metadata("runtime_audit", audit.to_json_line());
        if let Some(rule_id) = audit.rule_id {
            record = record.with_metadata("rule_id", rule_id);
        }
    }
    if let Some(audit) = inspect_audit {
        record = record
            .with_metadata("inspection_decision", audit.decision.as_str())
            .with_metadata("inspection_reason", audit.reason.clone())
            .with_metadata("inspection_audit", audit.to_json_line());
        if let Some(rule_id) = audit.rule_id {
            record = record.with_metadata("inspection_rule_id", rule_id);
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
fn tcp_bridge_http_deny_smoke_records() -> Vec<AuditRecord> {
    match run_tcp_bridge_http_deny_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::HttpRequest,
            "tcp-bridge-http-deny-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Http)],
    }
}

#[cfg(not(unix))]
fn tcp_bridge_http_deny_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::HttpRequest,
        "tcp-bridge-http-deny-smoke",
        Decision::FailClosed,
        "TCP bridge HTTP deny smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Http)]
}

#[cfg(unix)]
fn run_tcp_bridge_http_deny_smoke() -> Result<AuditRecord, String> {
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
    let socket_dir = target_dir.join(format!("fxhttpdeny-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create TCP bridge HTTP deny socket dir: {err}"))?;
    let handoff_listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind TCP bridge HTTP deny handoff socket: {err}"))?;
    handoff_listener.set_nonblocking(true).map_err(|err| {
        format!("failed to make TCP bridge HTTP deny handoff listener nonblocking: {err}")
    })?;

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
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(5); s.connect(('203.0.113.24',80)); s.sendall(b'GET /admin HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n');\ntry:\n data=s.recv(128); print(data); sys.exit(4 if data else 0)\nexcept (ConnectionResetError, socket.timeout, OSError) as e:\n print(repr(e)); sys.exit(0)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap TCP bridge HTTP deny smoke: {err}"))?;

    let fd = accept_handoff_fd(&handoff_listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let bridge_destination: std::net::Ipv4Addr = "203.0.113.24"
        .parse()
        .map_err(|err| format!("invalid TCP bridge HTTP deny destination IP: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-tcp-http-deny-smoke", RuleAction::Allow)
                .protocol(Protocol::Tcp)
                .destination(Cidr::host(std::net::IpAddr::V4(bridge_destination)))
                .port(80),
        ),
    );
    let inspect_policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("deny-transparent-http-admin", RuleAction::DenyReset)
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_path_prefix("/admin"),
        ),
    );
    let inspection = foxprox_core::runtime::TransparentInspectionRuntime::new(inspect_policy);
    let mut bridge_runtime = TransparentTcpBridgeRuntime::listen(bridge_destination, 80, policy)?
        .with_inspection(inspection);
    let mut buf = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut packets_read = 0_u64;
    let mut emitted_packets = 0_u64;
    let mut rst_written = false;
    let mut denied = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let step =
                    bridge_runtime.handle_ipv4_packet("tcp-bridge-http-deny-smoke", &buf[..n])?;
                for emitted in step.emitted_packets {
                    emitted_packets += 1;
                    if let Ok(ip) = foxprox_core::packet::parse_ipv4(&emitted) {
                        if let Ok(tcp) = foxprox_core::packet::parse_tcp(ip.payload) {
                            if tcp.rst {
                                rst_written = true;
                            }
                        }
                    }
                    fd.write_packet(&emitted)?;
                }
                if step.egress_payload.is_some() {
                    return Err(
                        "HTTP-denied TCP bridge unexpectedly produced host egress payload"
                            .to_string(),
                    );
                }
                denied = bridge_runtime.audit.iter().any(|audit| {
                    audit.kind == EventKind::HttpRequest && !audit.decision.is_allow()
                });
                if denied && rst_written {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during TCP bridge HTTP deny smoke: {err}"
                ))
            }
        }
        for emitted in bridge_runtime.poll()? {
            emitted_packets += 1;
            fd.write_packet(&emitted)?;
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll TCP bridge HTTP deny smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !denied {
        return Err("timed out waiting for transparent HTTP deny audit".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for TCP bridge HTTP deny smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let connect_audit = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::TcpConnectAttempt)
        .cloned();
    let inspect_audit = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::HttpRequest)
        .cloned();
    let success = output.status.success()
        && rst_written
        && inspect_audit
            .as_ref()
            .is_some_and(|audit| !audit.decision.is_allow());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::HttpRequest,
        "tcp-bridge-http-deny-smoke",
        if success {
            Decision::DenyReset
        } else {
            Decision::FailClosed
        },
        if success {
            "transparent HTTP /admin request was denied by inspection before host egress"
        } else {
            "transparent HTTP deny smoke failed before reset/no-egress proof completed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Http)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("emitted_packets", emitted_packets.to_string())
    .with_metadata("rst_written", rst_written.to_string())
    .with_metadata("denied", denied.to_string())
    .with_metadata("egress_calls", "0");
    if let Some(audit) = connect_audit {
        record = record
            .with_metadata("connect_decision", audit.decision.as_str())
            .with_metadata("connect_audit", audit.to_json_line());
    }
    if let Some(audit) = inspect_audit {
        record = record
            .with_metadata("inspection_decision", audit.decision.as_str())
            .with_metadata("inspection_reason", audit.reason.clone())
            .with_metadata("inspection_audit", audit.to_json_line());
        if let Some(rule_id) = audit.rule_id {
            record = record.with_metadata("inspection_rule_id", rule_id);
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
fn tls_sni_deny_smoke_records() -> Vec<AuditRecord> {
    match run_tls_sni_deny_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::TlsClientHello,
            "tls-sni-deny-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Tls)],
    }
}

#[cfg(not(unix))]
fn tls_sni_deny_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::TlsClientHello,
        "tls-sni-deny-smoke",
        Decision::FailClosed,
        "TLS SNI deny smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tls)]
}

#[cfg(unix)]
fn run_tls_sni_deny_smoke() -> Result<AuditRecord, String> {
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
    let socket_dir = target_dir.join(format!("fxtlsdeny-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create TLS SNI deny socket dir: {err}"))?;
    let handoff_listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind TLS SNI deny handoff socket: {err}"))?;
    handoff_listener.set_nonblocking(true).map_err(|err| {
        format!("failed to make TLS SNI deny handoff listener nonblocking: {err}")
    })?;

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
            "import socket,sys; host=b'blocked.example'; sni=bytes([0])+len(host).to_bytes(2,'big')+host; sni_list=len(sni).to_bytes(2,'big')+sni; ext=(0).to_bytes(2,'big')+len(sni_list).to_bytes(2,'big')+sni_list; exts=len(ext).to_bytes(2,'big')+ext; hello=bytes([3,3])+bytes(32)+bytes([0])+(2).to_bytes(2,'big')+bytes([0x13,0x01])+bytes([1,0])+exts; hs=bytes([1])+len(hello).to_bytes(3,'big')+hello; rec=bytes([0x16,3,1])+len(hs).to_bytes(2,'big')+hs; sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM); sock.settimeout(5); sock.connect(('203.0.113.25',443)); sock.sendall(rec)\ntry:\n data=sock.recv(128); print(data); sys.exit(4 if data else 0)\nexcept (ConnectionResetError, TimeoutError, OSError) as e:\n print(repr(e)); sys.exit(0)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap TLS SNI deny smoke: {err}"))?;

    let fd = accept_handoff_fd(&handoff_listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let bridge_destination: std::net::Ipv4Addr = "203.0.113.25"
        .parse()
        .map_err(|err| format!("invalid TLS SNI deny destination IP: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-tcp-tls-sni-deny-smoke", RuleAction::Allow)
                .protocol(Protocol::Tcp)
                .destination(Cidr::host(std::net::IpAddr::V4(bridge_destination)))
                .port(443),
        ),
    );
    let inspect_policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("deny-tls-blocked-example", RuleAction::DenyReset)
                .protocol(Protocol::Tls)
                .hostname("blocked.example"),
        ),
    );
    let inspection = foxprox_core::runtime::TransparentInspectionRuntime::new(inspect_policy);
    let mut bridge_runtime = TransparentTcpBridgeRuntime::listen(bridge_destination, 443, policy)?
        .with_inspection(inspection);
    let mut buf = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut packets_read = 0_u64;
    let mut emitted_packets = 0_u64;
    let mut rst_written = false;
    let mut denied = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let step = bridge_runtime.handle_ipv4_packet("tls-sni-deny-smoke", &buf[..n])?;
                for emitted in step.emitted_packets {
                    emitted_packets += 1;
                    if let Ok(ip) = foxprox_core::packet::parse_ipv4(&emitted) {
                        if let Ok(tcp) = foxprox_core::packet::parse_tcp(ip.payload) {
                            if tcp.rst {
                                rst_written = true;
                            }
                        }
                    }
                    fd.write_packet(&emitted)?;
                }
                if step.egress_payload.is_some() {
                    return Err(
                        "TLS-denied bridge unexpectedly produced host egress payload".to_string(),
                    );
                }
                denied = bridge_runtime.audit.iter().any(|audit| {
                    audit.kind == EventKind::TlsClientHello && !audit.decision.is_allow()
                });
                if denied && rst_written {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during TLS SNI deny smoke: {err}"
                ))
            }
        }
        for emitted in bridge_runtime.poll()? {
            emitted_packets += 1;
            fd.write_packet(&emitted)?;
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll TLS SNI deny smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !denied {
        return Err("timed out waiting for TLS SNI deny audit".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for TLS SNI deny smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let connect_audit = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::TcpConnectAttempt)
        .cloned();
    let tls_audit = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::TlsClientHello)
        .cloned();
    let success = output.status.success()
        && rst_written
        && tls_audit
            .as_ref()
            .is_some_and(|audit| !audit.decision.is_allow());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::TlsClientHello,
        "tls-sni-deny-smoke",
        if success {
            Decision::DenyReset
        } else {
            Decision::FailClosed
        },
        if success {
            "transparent TLS ClientHello SNI was denied before host egress"
        } else {
            "TLS SNI deny smoke failed before reset/no-egress proof completed"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tls)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("emitted_packets", emitted_packets.to_string())
    .with_metadata("rst_written", rst_written.to_string())
    .with_metadata("denied", denied.to_string())
    .with_metadata("egress_calls", "0");
    if let Some(audit) = connect_audit {
        record = record
            .with_metadata("connect_decision", audit.decision.as_str())
            .with_metadata("connect_audit", audit.to_json_line());
    }
    if let Some(audit) = tls_audit {
        record = record
            .with_metadata("tls_decision", audit.decision.as_str())
            .with_metadata("tls_reason", audit.reason.clone())
            .with_metadata("tls_audit", audit.to_json_line());
        if let Some(hostname) = audit.hostname {
            record = record.with_metadata("sni_hostname", hostname);
        }
        if let Some(rule_id) = audit.rule_id {
            record = record.with_metadata("tls_rule_id", rule_id);
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
fn tcp_bridge_deny_smoke_records() -> Vec<AuditRecord> {
    match run_tcp_bridge_deny_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::TcpConnectAttempt,
            "tcp-bridge-deny-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Tcp)],
    }
}

#[cfg(not(unix))]
fn tcp_bridge_deny_smoke_records() -> Vec<AuditRecord> {
    vec![AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "tcp-bridge-deny-smoke",
        Decision::FailClosed,
        "TCP bridge deny smoke is only supported on Unix",
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)]
}

#[cfg(unix)]
fn run_tcp_bridge_deny_smoke() -> Result<AuditRecord, String> {
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
    let socket_dir = target_dir.join(format!("fxbdn-{}", std::process::id()));
    let socket_path = socket_dir.join("s");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::create_dir_all(&socket_dir)
        .map_err(|err| format!("failed to create TCP bridge deny smoke socket dir: {err}"))?;
    let handoff_listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind TCP bridge deny smoke handoff socket: {err}"))?;
    handoff_listener.set_nonblocking(true).map_err(|err| {
        format!("failed to make TCP bridge deny handoff listener nonblocking: {err}")
    })?;

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
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(1);\ntry:\n s.connect(('203.0.113.23',8083)); sys.exit(4)\nexcept (socket.timeout,OSError):\n sys.exit(0)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn bwrap TCP bridge deny smoke: {err}"))?;

    let fd = accept_handoff_fd(&handoff_listener, &mut child, Duration::from_secs(10))?;
    fd.set_nonblocking()?;
    let bridge_destination: std::net::Ipv4Addr = "203.0.113.23"
        .parse()
        .map_err(|err| format!("invalid TCP bridge deny destination IP: {err}"))?;
    let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
    let mut bridge_runtime = TransparentTcpBridgeRuntime::listen(bridge_destination, 8083, policy)?;
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut rst_written = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let step = bridge_runtime.handle_ipv4_packet("tcp-bridge-deny-smoke", packet)?;
                for emitted in step.emitted_packets {
                    fd.write_packet(&emitted)?;
                    rst_written = true;
                }
                if rst_written {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(format!(
                    "failed to read TUN fd during TCP bridge deny smoke: {err}"
                ))
            }
        }
        if child
            .try_wait()
            .map_err(|err| format!("failed to poll bwrap TCP bridge deny smoke: {err}"))?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let Some(audit) = bridge_runtime
        .audit
        .iter()
        .find(|audit| audit.kind == EventKind::TcpConnectAttempt)
        .cloned()
    else {
        return Err("timed out waiting for TCP SYN to deny".to_string());
    };
    if audit.decision.is_allow() {
        return Err("TCP bridge deny smoke unexpectedly allowed the SYN".to_string());
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for bwrap TCP bridge deny smoke: {err}"))?;
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let success = output.status.success() && rst_written;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut record = AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "tcp-bridge-deny-smoke",
        if success {
            audit.decision
        } else {
            Decision::FailClosed
        },
        if success {
            "sandbox TCP SYN was denied before smoltcp or host egress and reset"
        } else {
            "TCP deny was audited but the sandbox target did not observe a closed path"
        },
    )
    .with_frontend(Frontend::Harness)
    .with_protocol(Protocol::Tcp)
    .with_metadata("status", output.status.to_string())
    .with_metadata("packets_read", packets_read.to_string())
    .with_metadata("egress_calls", "0")
    .with_metadata("rst_written", rst_written.to_string())
    .with_metadata("policy_decision", audit.decision.as_str())
    .with_metadata("policy_reason", audit.reason.clone())
    .with_metadata("runtime_audit", audit.to_json_line());
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
    fd.set_nonblocking()?;
    let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
    let mut broker = TransparentBroker::new(
        "10.0.2.1:53".parse().expect("static broker DNS addr valid"),
        [],
        policy,
        LocalUdpEgress::new(echo_addr)?,
        PolicyEngine::new(PolicyConfig::deny_by_default()),
        MockEgressBackend::new(),
        PolicyEngine::new(PolicyConfig::deny_by_default()),
    );
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets_read = 0_u64;
    let mut denied = false;
    while Instant::now() < deadline {
        match fd.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                packets_read += 1;
                let packet = &buf[..n];
                let step = broker.handle_ipv4_packet("udp-deny-smoke", packet)?;
                if !step.packets_to_device.is_empty() {
                    return Err("denied UDP smoke unexpectedly produced a reply".to_string());
                }
                denied = broker
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
    fd.close();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);
    let runtime_audit = broker
        .audit
        .iter()
        .rev()
        .find(|audit| audit.kind == EventKind::UdpFlowCreated)
        .cloned();
    let egress_calls = broker.udp.egress.calls();
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

fn http_proxy_smoke_records() -> Vec<AuditRecord> {
    match run_http_proxy_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::HttpRequest,
            "http-proxy-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::Http)],
    }
}

fn https_connect_smoke_records() -> Vec<AuditRecord> {
    match run_https_connect_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::HttpsConnect,
            "https-connect-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::HttpsConnect)],
    }
}

fn socks5_smoke_records() -> Vec<AuditRecord> {
    match run_socks5_smoke() {
        Ok(record) => vec![record],
        Err(err) => vec![AuditRecord::new(
            EventKind::SocksConnect,
            "socks5-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::Socks5)
        .with_protocol(Protocol::Socks)],
    }
}

fn run_http_proxy_smoke() -> Result<AuditRecord, String> {
    let origin = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind HTTP origin fixture: {err}"))?;
    let origin_addr = origin
        .local_addr()
        .map_err(|err| format!("failed to inspect HTTP origin fixture: {err}"))?;
    let origin_thread = std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _peer) = origin
            .accept()
            .map_err(|err| format!("HTTP origin fixture accept failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("HTTP origin timeout setup failed: {err}"))?;
        let mut buf = [0_u8; 1024];
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("HTTP origin fixture read failed: {err}"))?;
        let request = String::from_utf8_lossy(&buf[..n]);
        if !request.starts_with("GET /ok HTTP/1.1") {
            return Err(format!(
                "HTTP origin received unexpected request: {request:?}"
            ));
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nfoxprox")
            .map_err(|err| format!("HTTP origin fixture write failed: {err}"))?;
        Ok(())
    });

    let proxy = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind HTTP proxy smoke listener: {err}"))?;
    let proxy_addr = proxy
        .local_addr()
        .map_err(|err| format!("failed to inspect HTTP proxy smoke listener: {err}"))?;
    let client_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(5))
            .map_err(|err| format!("HTTP proxy smoke client connect failed: {err}"))?;
        stream
            .write_all(b"GET http://example.com/ok HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .map_err(|err| format!("HTTP proxy smoke client write failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("HTTP proxy smoke client timeout setup failed: {err}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|err| format!("HTTP proxy smoke client read failed: {err}"))?;
        if !response.ends_with(b"foxprox") {
            return Err(format!(
                "HTTP proxy smoke client received unexpected response: {:?}",
                String::from_utf8_lossy(&response)
            ));
        }
        Ok(())
    });

    let (mut client, _peer) = proxy
        .accept()
        .map_err(|err| format!("HTTP proxy smoke accept failed: {err}"))?;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("HTTP proxy smoke client timeout setup failed: {err}"))?;
    let mut request_bytes = [0_u8; 2048];
    let n = client
        .read(&mut request_bytes)
        .map_err(|err| format!("HTTP proxy smoke read failed: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-http-proxy-example", RuleAction::Allow)
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_path_prefix("/ok"),
        ),
    );
    let mut proxy_runtime = ExplicitProxyRuntime::new(policy);
    let parsed = proxy_runtime
        .evaluate_http_request("http-proxy-smoke", &request_bytes[..n], origin_addr)?
        .ok_or_else(|| "HTTP proxy smoke policy denied request".to_string())?;
    let proxy_audit = proxy_runtime
        .audit
        .last()
        .cloned()
        .ok_or_else(|| "HTTP proxy runtime did not emit audit".to_string())?;

    let mut origin_egress = LocalTcpStreamEgress::new(origin_addr);
    let origin_outcome = origin_egress.execute(&EgressRequest::TcpStreamData {
        destination: origin_addr,
        bytes: build_http_origin_request(&parsed),
    })?;
    client
        .write_all(&origin_outcome.response_payload)
        .map_err(|err| format!("HTTP proxy smoke client response write failed: {err}"))?;
    drop(client);

    origin_thread
        .join()
        .map_err(|_| "HTTP origin fixture thread panicked".to_string())??;
    client_thread
        .join()
        .map_err(|_| "HTTP proxy smoke client thread panicked".to_string())??;

    Ok(AuditRecord::new(
        EventKind::HttpRequest,
        "http-proxy-smoke",
        Decision::Allow,
        "HTTP proxy request was policy-allowed and forwarded to a local origin fixture",
    )
    .with_frontend(Frontend::HttpProxy)
    .with_protocol(Protocol::Http)
    .with_addresses(None, Some(origin_addr))
    .with_hostname(
        Some(parsed.host),
        foxprox_core::audit::AttributionSource::ExplicitProxy,
        foxprox_core::audit::AttributionConfidence::High,
    )
    .with_rule(proxy_audit.rule_id.clone())
    .with_metadata("method", parsed.method)
    .with_metadata("path", parsed.path)
    .with_metadata("policy_decision", proxy_audit.decision.as_str())
    .with_metadata("policy_reason", proxy_audit.reason.clone())
    .with_metadata("runtime_audit", proxy_audit.to_json_line())
    .with_metadata("origin_fixture", origin_addr.to_string())
    .with_metadata("egress_calls", origin_egress.calls().to_string())
    .with_bytes(n as u64, origin_outcome.bytes_received))
}

fn proxy_deny_smoke_records() -> Vec<AuditRecord> {
    let mut records = Vec::new();
    records.push(match run_http_proxy_deny_smoke() {
        Ok(record) => record,
        Err(err) => AuditRecord::new(
            EventKind::HttpRequest,
            "proxy-deny-smoke",
            Decision::FailClosed,
            err,
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::Http),
    });

    let mut connect_runtime =
        ExplicitProxyRuntime::new(PolicyEngine::new(PolicyConfig::deny_by_default()));
    let _ = connect_runtime.evaluate_https_connect_request(
        "proxy-deny-smoke",
        b"GET / HTTP/1.1\r\n\r\n",
        "127.0.0.1:0".parse().expect("static socket valid"),
    );
    let connect_audit = connect_runtime.audit.last().cloned().unwrap_or_else(|| {
        AuditRecord::new(
            EventKind::HttpsConnect,
            "proxy-deny-smoke",
            Decision::FailClosed,
            "malformed CONNECT request denied before egress: missing audit",
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::HttpsConnect)
    });
    records.push(
        AuditRecord::new(
            EventKind::HttpsConnect,
            "proxy-deny-smoke",
            connect_audit.decision,
            format!(
                "malformed CONNECT request denied before egress: {}",
                connect_audit.reason
            ),
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::HttpsConnect)
        .with_metadata("egress_calls", "0")
        .with_metadata("runtime_audit", connect_audit.to_json_line()),
    );

    let socks_err = parse_socks5_connect_request(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53])
        .expect_err("SOCKS UDP ASSOCIATE fixture should fail");
    records.push(
        AuditRecord::new(
            EventKind::SocksConnect,
            "proxy-deny-smoke",
            Decision::FailClosed,
            format!("unsupported SOCKS request denied before egress: {socks_err}"),
        )
        .with_frontend(Frontend::Socks5)
        .with_protocol(Protocol::Socks)
        .with_metadata("egress_calls", "0"),
    );
    records
}

fn run_http_proxy_deny_smoke() -> Result<AuditRecord, String> {
    let proxy = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind HTTP deny proxy listener: {err}"))?;
    let proxy_addr = proxy
        .local_addr()
        .map_err(|err| format!("failed to inspect HTTP deny proxy listener: {err}"))?;
    let client_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(5))
            .map_err(|err| format!("HTTP deny client connect failed: {err}"))?;
        stream
            .write_all(b"GET http://example.com/admin HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .map_err(|err| format!("HTTP deny client write failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("HTTP deny client timeout setup failed: {err}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|err| format!("HTTP deny client read failed: {err}"))?;
        let response_text = String::from_utf8_lossy(&response);
        if !response_text.starts_with("HTTP/1.1 403") {
            return Err(format!(
                "HTTP deny client received unexpected response: {response_text:?}"
            ));
        }
        Ok(())
    });

    let (mut client, _peer) = proxy
        .accept()
        .map_err(|err| format!("HTTP deny proxy accept failed: {err}"))?;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("HTTP deny proxy timeout setup failed: {err}"))?;
    let mut request_bytes = [0_u8; 2048];
    let n = client
        .read(&mut request_bytes)
        .map_err(|err| format!("HTTP deny proxy read failed: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("deny-http-admin", RuleAction::DenyReset)
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_path_prefix("/admin"),
        ),
    );
    let mut proxy_runtime = ExplicitProxyRuntime::new(policy);
    let allowed = proxy_runtime.evaluate_http_request(
        "proxy-deny-smoke",
        &request_bytes[..n],
        "127.0.0.1:0".parse().expect("static socket valid"),
    )?;
    let proxy_audit = proxy_runtime
        .audit
        .last()
        .cloned()
        .ok_or_else(|| "HTTP deny proxy runtime did not emit audit".to_string())?;
    if allowed.is_some() || proxy_audit.decision.is_allow() {
        return Err("HTTP deny smoke policy unexpectedly allowed request".to_string());
    }
    client
        .write_all(HTTP_FORBIDDEN_CLOSE_RESPONSE)
        .map_err(|err| format!("HTTP deny response write failed: {err}"))?;
    drop(client);
    client_thread
        .join()
        .map_err(|_| "HTTP deny client thread panicked".to_string())??;

    Ok(AuditRecord::new(
        EventKind::HttpRequest,
        "proxy-deny-smoke",
        proxy_audit.decision,
        "HTTP proxy request was denied before host egress",
    )
    .with_frontend(Frontend::HttpProxy)
    .with_protocol(Protocol::Http)
    .with_hostname(
        proxy_audit.hostname.clone(),
        foxprox_core::audit::AttributionSource::ExplicitProxy,
        foxprox_core::audit::AttributionConfidence::High,
    )
    .with_rule(proxy_audit.rule_id.clone())
    .with_metadata(
        "method",
        proxy_audit
            .metadata
            .get("method")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
    )
    .with_metadata(
        "path",
        proxy_audit
            .metadata
            .get("path")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
    )
    .with_metadata("policy_decision", proxy_audit.decision.as_str())
    .with_metadata("policy_reason", proxy_audit.reason.clone())
    .with_metadata("runtime_audit", proxy_audit.to_json_line())
    .with_metadata("egress_calls", "0")
    .with_bytes(n as u64, 0))
}

fn run_https_connect_smoke() -> Result<AuditRecord, String> {
    let origin = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind HTTPS CONNECT origin fixture: {err}"))?;
    let origin_addr = origin
        .local_addr()
        .map_err(|err| format!("failed to inspect HTTPS CONNECT origin fixture: {err}"))?;
    let origin_thread = std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _peer) = origin
            .accept()
            .map_err(|err| format!("HTTPS CONNECT origin accept failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("HTTPS CONNECT origin timeout setup failed: {err}"))?;
        let mut buf = [0_u8; 64];
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("HTTPS CONNECT origin read failed: {err}"))?;
        if &buf[..n] != b"ping" {
            return Err(format!(
                "HTTPS CONNECT origin received unexpected bytes: {:?}",
                &buf[..n]
            ));
        }
        stream
            .write_all(b"pong")
            .map_err(|err| format!("HTTPS CONNECT origin write failed: {err}"))?;
        Ok(())
    });

    let proxy = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind HTTPS CONNECT proxy listener: {err}"))?;
    let proxy_addr = proxy
        .local_addr()
        .map_err(|err| format!("failed to inspect HTTPS CONNECT proxy listener: {err}"))?;
    let client_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(5))
            .map_err(|err| format!("HTTPS CONNECT client connect failed: {err}"))?;
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .map_err(|err| format!("HTTPS CONNECT client write failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("HTTPS CONNECT client timeout setup failed: {err}"))?;
        let mut response = [0_u8; 128];
        let n = stream
            .read(&mut response)
            .map_err(|err| format!("HTTPS CONNECT client response read failed: {err}"))?;
        let response_text = String::from_utf8_lossy(&response[..n]);
        if !response_text.starts_with("HTTP/1.1 200") {
            return Err(format!(
                "HTTPS CONNECT client received unexpected connect response: {response_text:?}"
            ));
        }
        stream
            .write_all(b"ping")
            .map_err(|err| format!("HTTPS CONNECT client tunnel write failed: {err}"))?;
        let n = stream
            .read(&mut response)
            .map_err(|err| format!("HTTPS CONNECT client tunnel read failed: {err}"))?;
        if &response[..n] != b"pong" {
            return Err(format!(
                "HTTPS CONNECT client received unexpected tunnel bytes: {:?}",
                &response[..n]
            ));
        }
        Ok(())
    });

    let (mut client, _peer) = proxy
        .accept()
        .map_err(|err| format!("HTTPS CONNECT proxy accept failed: {err}"))?;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("HTTPS CONNECT proxy timeout setup failed: {err}"))?;
    let request = read_http_headers(&mut client, 8192)?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-https-connect-example", RuleAction::Allow)
                .protocol(Protocol::HttpsConnect)
                .hostname("example.com")
                .port(443),
        ),
    );
    let mut proxy_runtime = ExplicitProxyRuntime::new(policy);
    let parsed = proxy_runtime
        .evaluate_https_connect_request("https-connect-smoke", &request, origin_addr)?
        .ok_or_else(|| "HTTPS CONNECT smoke policy denied request".to_string())?;
    let proxy_audit = proxy_runtime
        .audit
        .last()
        .cloned()
        .ok_or_else(|| "HTTPS CONNECT runtime did not emit audit".to_string())?;

    client
        .write_all(HTTP_CONNECT_ESTABLISHED_RESPONSE)
        .map_err(|err| format!("HTTPS CONNECT response write failed: {err}"))?;
    let mut tunnel_buf = [0_u8; 64];
    let n = client
        .read(&mut tunnel_buf)
        .map_err(|err| format!("HTTPS CONNECT tunnel client read failed: {err}"))?;
    let mut tunnel_egress = LocalTcpStreamEgress::new(origin_addr);
    let tunnel_outcome = tunnel_egress.execute(&EgressRequest::TcpStreamData {
        destination: origin_addr,
        bytes: tunnel_buf[..n].to_vec(),
    })?;
    client
        .write_all(&tunnel_outcome.response_payload)
        .map_err(|err| format!("HTTPS CONNECT tunnel client write failed: {err}"))?;
    drop(client);

    origin_thread
        .join()
        .map_err(|_| "HTTPS CONNECT origin fixture thread panicked".to_string())??;
    client_thread
        .join()
        .map_err(|_| "HTTPS CONNECT client thread panicked".to_string())??;

    Ok(AuditRecord::new(
        EventKind::HttpsConnect,
        "https-connect-smoke",
        Decision::Allow,
        "HTTPS CONNECT request was policy-allowed and tunneled to a local TCP fixture",
    )
    .with_frontend(Frontend::HttpProxy)
    .with_protocol(Protocol::HttpsConnect)
    .with_addresses(None, Some(origin_addr))
    .with_hostname(
        Some(parsed.host),
        foxprox_core::audit::AttributionSource::ExplicitProxy,
        foxprox_core::audit::AttributionConfidence::High,
    )
    .with_rule(proxy_audit.rule_id.clone())
    .with_metadata("connect_port", parsed.port.to_string())
    .with_metadata("policy_decision", proxy_audit.decision.as_str())
    .with_metadata("policy_reason", proxy_audit.reason.clone())
    .with_metadata("runtime_audit", proxy_audit.to_json_line())
    .with_metadata("origin_fixture", origin_addr.to_string())
    .with_metadata("egress_calls", tunnel_egress.calls().to_string())
    .with_bytes(n as u64, tunnel_outcome.bytes_received))
}

fn run_socks5_smoke() -> Result<AuditRecord, String> {
    let origin = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind SOCKS5 origin fixture: {err}"))?;
    let origin_addr = origin
        .local_addr()
        .map_err(|err| format!("failed to inspect SOCKS5 origin fixture: {err}"))?;
    let origin_thread = std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _peer) = origin
            .accept()
            .map_err(|err| format!("SOCKS5 origin accept failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("SOCKS5 origin timeout setup failed: {err}"))?;
        let mut buf = [0_u8; 64];
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("SOCKS5 origin read failed: {err}"))?;
        if &buf[..n] != b"ping" {
            return Err(format!(
                "SOCKS5 origin received unexpected bytes: {:?}",
                &buf[..n]
            ));
        }
        stream
            .write_all(b"pong")
            .map_err(|err| format!("SOCKS5 origin write failed: {err}"))?;
        Ok(())
    });

    let proxy = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind SOCKS5 proxy listener: {err}"))?;
    let proxy_addr = proxy
        .local_addr()
        .map_err(|err| format!("failed to inspect SOCKS5 proxy listener: {err}"))?;
    let client_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(5))
            .map_err(|err| format!("SOCKS5 client connect failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("SOCKS5 client timeout setup failed: {err}"))?;
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .map_err(|err| format!("SOCKS5 client greeting write failed: {err}"))?;
        let mut buf = [0_u8; 64];
        stream
            .read_exact(&mut buf[..2])
            .map_err(|err| format!("SOCKS5 client greeting read failed: {err}"))?;
        if &buf[..2] != [0x05, 0x00] {
            return Err(format!(
                "SOCKS5 client received bad greeting: {:?}",
                &buf[..2]
            ));
        }
        let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443_u16.to_be_bytes());
        stream
            .write_all(&request)
            .map_err(|err| format!("SOCKS5 client CONNECT write failed: {err}"))?;
        stream
            .read_exact(&mut buf[..10])
            .map_err(|err| format!("SOCKS5 client CONNECT response read failed: {err}"))?;
        if buf[0] != 0x05 || buf[1] != 0x00 {
            return Err(format!(
                "SOCKS5 client received failed CONNECT response: {:?}",
                &buf[..10]
            ));
        }
        stream
            .write_all(b"ping")
            .map_err(|err| format!("SOCKS5 client tunnel write failed: {err}"))?;
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("SOCKS5 client tunnel read failed: {err}"))?;
        if &buf[..n] != b"pong" {
            return Err(format!(
                "SOCKS5 client received unexpected tunnel bytes: {:?}",
                &buf[..n]
            ));
        }
        Ok(())
    });

    let (mut client, _peer) = proxy
        .accept()
        .map_err(|err| format!("SOCKS5 proxy accept failed: {err}"))?;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("SOCKS5 proxy timeout setup failed: {err}"))?;
    let mut greeting = [0_u8; 3];
    client
        .read_exact(&mut greeting)
        .map_err(|err| format!("SOCKS5 proxy greeting read failed: {err}"))?;
    parse_socks5_no_auth_greeting(&greeting)?;
    client
        .write_all(SOCKS5_NO_AUTH_RESPONSE)
        .map_err(|err| format!("SOCKS5 proxy greeting write failed: {err}"))?;
    let mut request_bytes = [0_u8; 512];
    let n = client
        .read(&mut request_bytes)
        .map_err(|err| format!("SOCKS5 proxy CONNECT read failed: {err}"))?;
    let policy = PolicyEngine::new(
        PolicyConfig::deny_by_default().with_rule(
            PolicyRule::new("allow-socks5-example", RuleAction::Allow)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .port(443),
        ),
    );
    let mut proxy_runtime = ExplicitProxyRuntime::new(policy);
    let parsed = proxy_runtime
        .evaluate_socks5_connect("socks5-smoke", &request_bytes[..n], origin_addr)?
        .ok_or_else(|| "SOCKS5 smoke policy denied request".to_string())?;
    let proxy_audit = proxy_runtime
        .audit
        .last()
        .cloned()
        .ok_or_else(|| "SOCKS5 runtime did not emit audit".to_string())?;

    let connect_response = socks5_connect_success_response(origin_addr);
    client
        .write_all(&connect_response)
        .map_err(|err| format!("SOCKS5 proxy CONNECT response write failed: {err}"))?;
    let mut tunnel_buf = [0_u8; 64];
    let read_n = client
        .read(&mut tunnel_buf)
        .map_err(|err| format!("SOCKS5 tunnel client read failed: {err}"))?;
    let mut tunnel_egress = LocalTcpStreamEgress::new(origin_addr);
    let tunnel_outcome = tunnel_egress.execute(&EgressRequest::TcpStreamData {
        destination: origin_addr,
        bytes: tunnel_buf[..read_n].to_vec(),
    })?;
    client
        .write_all(&tunnel_outcome.response_payload)
        .map_err(|err| format!("SOCKS5 tunnel client write failed: {err}"))?;
    drop(client);

    origin_thread
        .join()
        .map_err(|_| "SOCKS5 origin fixture thread panicked".to_string())??;
    client_thread
        .join()
        .map_err(|_| "SOCKS5 client thread panicked".to_string())??;

    Ok(AuditRecord::new(
        EventKind::SocksConnect,
        "socks5-smoke",
        Decision::Allow,
        "SOCKS5 TCP CONNECT was policy-allowed and tunneled to a local TCP fixture",
    )
    .with_frontend(Frontend::Socks5)
    .with_protocol(Protocol::Socks)
    .with_addresses(None, Some(origin_addr))
    .with_hostname(
        Some(parsed.destination_host),
        foxprox_core::audit::AttributionSource::ExplicitProxy,
        foxprox_core::audit::AttributionConfidence::High,
    )
    .with_rule(proxy_audit.rule_id.clone())
    .with_metadata("connect_port", parsed.destination_port.to_string())
    .with_metadata("policy_decision", proxy_audit.decision.as_str())
    .with_metadata("policy_reason", proxy_audit.reason.clone())
    .with_metadata("runtime_audit", proxy_audit.to_json_line())
    .with_metadata("origin_fixture", origin_addr.to_string())
    .with_metadata("egress_calls", tunnel_egress.calls().to_string())
    .with_bytes(read_n as u64, tunnel_outcome.bytes_received))
}

#[cfg(unix)]
fn accept_handoff_fd(
    listener: &UnixListener,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<fd_handoff::DeviceFd, String> {
    use std::os::fd::AsRawFd;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _addr)) => return fd_handoff::recv_device_fd(stream.as_raw_fd()),
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
