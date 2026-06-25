use foxprox_core::{parse_ip_packet, synthesize_udpv4_response, ParsedIpPacket, SandboxId};
use foxprox_integrations::{SetupPlan, TunDeviceConfig};
use foxprox_launcher::prepare_bwrap_launch_with_socket_path;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let setup_bin = std::env::var("FOXPROX_SETUP_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/debug/foxproxsetup"));
    if !setup_bin.exists() {
        return Err(format!(
            "setup binary not found at {}; run `cargo build -p foxprox-setup --bin foxproxsetup` or set FOXPROX_SETUP_BIN",
            setup_bin.display()
        )
        .into());
    }

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let socket_dir = std::env::temp_dir().join(format!("foxprox-live-{unique}"));
    std::fs::create_dir_all(&socket_dir)?;
    let socket_path = socket_dir.join("handoff.sock");
    let tun_name = format!("fpx{}", &unique[unique.len().saturating_sub(8)..]);

    let plan = SetupPlan {
        sandbox_id: SandboxId::new("live-udp-smoke")
            .map_err(|error| format!("invalid sandbox id: {error:?}"))?,
        tun: TunDeviceConfig {
            name: tun_name.clone(),
            sandbox_ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
            broker_ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
            mtu: 1500,
        },
        dns_resolver: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
        proxy_listener: None,
        tun_handoff_fd: 0,
    };
    let target_python = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'ping',('10.66.0.1',9999)); print(s.recv(16).decode())";
    let prepared = prepare_bwrap_launch_with_socket_path(
        plan,
        &[
            "/usr/bin/python3".to_string(),
            "-c".to_string(),
            target_python.to_string(),
        ],
        &socket_path,
    )
    .map_err(|error| format!("prepare bwrap launch: {error:?}"))?;

    let mut args = vec![
        "--unshare-user".to_string(),
        "--unshare-net".to_string(),
        "--uid".to_string(),
        "0".to_string(),
        "--gid".to_string(),
        "0".to_string(),
        "--cap-add".to_string(),
        "CAP_NET_ADMIN".to_string(),
        "--ro-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--dev-bind".to_string(),
        "/dev/net/tun".to_string(),
        "/dev/net/tun".to_string(),
        "--bind".to_string(),
        socket_dir.to_string_lossy().into_owned(),
        socket_dir.to_string_lossy().into_owned(),
        "--tmpfs".to_string(),
        "/etc".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        setup_bin.to_string_lossy().into_owned(),
    ];
    let setup_args_start = prepared
        .command
        .args
        .iter()
        .position(|arg| arg == "--sandbox-id")
        .ok_or("prepared command missing setup args")?;
    args.extend(prepared.command.args[setup_args_start..].iter().cloned());

    let child = Command::new("bwrap")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut tun = prepared
        .receive_tun_file()
        .map_err(|error| format!("receive TUN fd: {error:?}"))?;

    let mut buffer = vec![0u8; 2000];
    loop {
        let count = tun.read(&mut buffer)?;
        match parse_ip_packet(&buffer[..count]) {
            Ok(ParsedIpPacket::Udpv4Packet(packet)) => {
                let reply = synthesize_udpv4_response(&packet, b"pong");
                tun.write_all(&reply)?;
                break;
            }
            Ok(_) | Err(_) => continue,
        }
    }

    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() || !stdout.contains("pong") {
        return Err(format!(
            "live bwrap UDP smoke failed: status={:?}\nstdout={stdout}\nstderr={stderr}",
            output.status.code()
        )
        .into());
    }
    println!("live bwrap UDP smoke passed: {}", stdout.trim());
    Ok(())
}
