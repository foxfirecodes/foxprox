use foxprox_core::{
    DecisionAction, Endpoint, FrontendKind, NormalizedEvent, PolicyConfig, PolicyEngine,
    PolicyRule, Protocol, RuleSet, SandboxId, SniStatus, VecAuditSink, VerificationKernel,
};
use foxprox_device::{set_file_nonblocking, SetupControlSocketListener};
use foxprox_runtime::{build_runtime_components, BrokerRuntimeConfig, TcpStackAdapter};
use foxprox_smoltcp::{
    SmoltcpIpConfig, SmoltcpTcpBridgeIoSession, SmoltcpTcpBridgeSession,
    SmoltcpTcpBridgeSessionError, TcpConnectReportMode,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let suffix = &unique[unique.len().saturating_sub(8)..];
    let socket_dir = std::env::temp_dir().join(format!("foxprox-live-tcp-{suffix}"));
    std::fs::create_dir_all(&socket_dir)?;
    let socket_path = socket_dir.join("handoff.sock");
    let control = SetupControlSocketListener::bind(&socket_path)?;
    let tun_name = format!("ftcp{suffix}");

    let host_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let host_addr = host_listener.local_addr()?;
    let host = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let (mut stream, _) = host_listener.accept()?;
        let mut received = vec![0; b"live-tcp".len()];
        stream.read_exact(&mut received)?;
        stream.write_all(b"live-reply")?;
        Ok(received)
    });

    let target_python = "import socket; s=socket.create_connection(('10.66.0.1',8080), timeout=5); s.sendall(b'live-tcp'); print(s.recv(32).decode())";
    let mut child = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--uid",
            "0",
            "--gid",
            "0",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--bind",
            &socket_dir.to_string_lossy(),
            &socket_dir.to_string_lossy(),
            "--tmpfs",
            "/etc",
            "--proc",
            "/proc",
            &setup_bin.to_string_lossy(),
            "--sandbox-id",
            "live-tcp-smoke",
            "--tun-name",
            &tun_name,
            "--sandbox-ip",
            "10.66.0.2",
            "--broker-ip",
            "10.66.0.1",
            "--mtu",
            "1500",
            "--dns",
            "10.66.0.1",
            "--handoff-socket",
            &socket_path.to_string_lossy(),
            "--",
            "/usr/bin/python3",
            "-c",
            target_python,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let tun = control.receive_file()?;
    let mut tun_reader = tun.try_clone()?;
    let mut tun_writer = tun.try_clone()?;

    let mut adapter = foxprox_smoltcp::SmoltcpIpLoopback::new(
        SmoltcpIpConfig {
            address: Ipv4Addr::new(10, 66, 0, 1),
            prefix_len: 24,
        },
        0,
    )
    .map_err(|error| format!("create smoltcp adapter: {error:?}"))?;
    adapter.set_packet_loopback(false);
    adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
    adapter
        .listen_tcp(8080, 4096, 4096)
        .map_err(|error| format!("listen smoltcp TCP: {error:?}"))?;

    let mut rule = PolicyRule::allow("allow-live-tcp");
    rule.protocol = Some(Protocol::Tcp);
    let mut rules = RuleSet::default();
    rules.push(rule);
    let mut kernel = VerificationKernel::new(
        PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        }),
        VecAuditSink::bounded(16),
    );
    let components = build_runtime_components(BrokerRuntimeConfig {
        sandbox_id: SandboxId::new("live-tcp-components")
            .map_err(|e| format!("sandbox id: {e:?}"))?,
        policy: PolicyConfig::default(),
        static_dns_ttl_secs: 30,
        static_dns_records: Vec::new(),
        tcp_max_open_flows: 16,
        tcp_metadata_buffer_bytes: 4096,
    })
    .map_err(|error| format!("build runtime components: {error:?}"))?;
    let mut buffer = vec![0; 2000];

    let (session, flow) = loop {
        foxprox_smoltcp::pump_one_tun_packet(
            &mut adapter,
            &mut tun_reader,
            &mut tun_writer,
            &mut buffer,
            1,
        )?;
        let Some(attempt) = adapter.next_connect_attempt() else {
            continue;
        };
        let event = NormalizedEvent::TcpConnectAttempt {
            sandbox_id: SandboxId::new("live-tcp").map_err(|e| format!("sandbox id: {e:?}"))?,
            frontend: FrontendKind::Tun,
            source: Some(Endpoint::new(attempt.source.ip, attempt.source.port)),
            destination: Endpoint::new(attempt.destination.ip, attempt.destination.port),
            hostname: None,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
        };
        let decision = kernel.decide_and_audit(&event, 1);
        if decision.action != DecisionAction::Allow {
            return Err(format!("live TCP policy denied: {decision:?}").into());
        }
        adapter.mark_connect_opened(&attempt);
        break SmoltcpTcpBridgeSession::connect_allowed_host_session(
            adapter,
            &components,
            &attempt,
            host_addr,
        )
        .map_err(|error| format!("open live TCP session: {error:?}"))?;
    };
    set_file_nonblocking(&tun, true)?;

    let mut io_session = SmoltcpTcpBridgeIoSession::new(session, tun, 2000, flow, 8080, 4096, 4096);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut tick_millis = 2;
    while Instant::now() < deadline {
        match io_session.run_tick(tick_millis) {
            Ok(_) => {}
            Err(SmoltcpTcpBridgeSessionError::TunWrite) => {}
            Err(error) => return Err(format!("live TCP tick failed: {error:?}").into()),
        }
        if child.try_wait()?.is_some() {
            break;
        }
        tick_millis += 1;
        thread::sleep(Duration::from_millis(5));
    }

    let output = child.wait_with_output()?;
    let host_received = host.join().map_err(|_| "host thread panicked")??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() || !stdout.contains("live-reply") || host_received != b"live-tcp" {
        return Err(format!(
            "live bwrap TCP smoke failed: status={:?} host={host_received:?}\nstdout={stdout}\nstderr={stderr}",
            output.status.code()
        )
        .into());
    }
    println!("live bwrap TCP smoke passed: {}", stdout.trim());
    Ok(())
}
