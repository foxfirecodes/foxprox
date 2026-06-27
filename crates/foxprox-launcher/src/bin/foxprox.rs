use foxprox_core::{
    DecisionAction, Endpoint, FrontendKind, NormalizedEvent, PolicyConfig, PolicyEngine,
    PolicyRule, Protocol, RuleSet, SandboxId, SniStatus, VecAuditSink, VerificationKernel,
};
use foxprox_device::set_file_nonblocking;
use foxprox_integrations::{SetupPlan, TunDeviceConfig};
use foxprox_launcher::prepare_bwrap_launch_with_socket_path;
use foxprox_runtime::{build_runtime_components, BrokerRuntimeConfig, TcpStackAdapter};
use foxprox_smoltcp::{
    SmoltcpIpConfig, SmoltcpTcpBridgeIoSession, SmoltcpTcpBridgeSession,
    SmoltcpTcpBridgeSessionError, TcpConnectReportMode,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(error) = real_main() {
        eprintln!("foxprox: {error}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), String> {
    let config = CliConfig::parse(std::env::args().skip(1))?;
    run(config)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliConfig {
    setup_bin: PathBuf,
    sandbox_id: String,
    tun_name: String,
    sandbox_ip: Ipv4Addr,
    broker_ip: Ipv4Addr,
    mtu: u16,
    dns: Ipv4Addr,
    tcp_listen: u16,
    tcp_host: SocketAddr,
    target: Vec<String>,
}

impl CliConfig {
    fn parse<I, S>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut setup_bin = std::env::var("FOXPROX_SETUP_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("foxproxsetup"));
        let mut sandbox_id = "foxprox-alpha".to_string();
        let mut tun_name = "foxprox0".to_string();
        let mut sandbox_ip = Ipv4Addr::new(10, 66, 0, 2);
        let mut broker_ip = Ipv4Addr::new(10, 66, 0, 1);
        let mut mtu = 1500u16;
        let mut dns = None;
        let mut tcp_listen = None;
        let mut tcp_host = None;
        let mut target = Vec::new();

        let mut iter = args.into_iter().map(Into::into).peekable();
        match iter.next().as_deref() {
            Some("run") => {}
            Some("--help") | Some("-h") | None => return Err(usage()),
            Some(other) => return Err(format!("unknown subcommand `{other}`\n{}", usage())),
        }

        while let Some(arg) = iter.next() {
            if arg == "--" {
                target.extend(iter);
                break;
            }
            match arg.as_str() {
                "--setup-bin" => setup_bin = PathBuf::from(next_value(&arg, &mut iter)?),
                "--sandbox-id" => sandbox_id = next_value(&arg, &mut iter)?,
                "--tun-name" => tun_name = next_value(&arg, &mut iter)?,
                "--sandbox-ip" => sandbox_ip = parse_ipv4(&arg, next_value(&arg, &mut iter)?)?,
                "--broker-ip" => broker_ip = parse_ipv4(&arg, next_value(&arg, &mut iter)?)?,
                "--mtu" => mtu = parse_u16(&arg, next_value(&arg, &mut iter)?)?,
                "--dns" => dns = Some(parse_ipv4(&arg, next_value(&arg, &mut iter)?)?),
                "--tcp-listen" => tcp_listen = Some(parse_u16(&arg, next_value(&arg, &mut iter)?)?),
                "--tcp-host" => {
                    tcp_host = Some(
                        next_value(&arg, &mut iter)?
                            .parse::<SocketAddr>()
                            .map_err(|_| "invalid --tcp-host socket address".to_string())?,
                    );
                }
                "--help" | "-h" => return Err(usage()),
                other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
                other => {
                    return Err(format!(
                        "unexpected argument `{other}`; use -- before target"
                    ))
                }
            }
        }

        if target.is_empty() {
            return Err("missing target command after --".to_string());
        }
        let tcp_listen = tcp_listen.ok_or("missing required --tcp-listen PORT".to_string())?;
        let tcp_host = tcp_host.ok_or("missing required --tcp-host ADDR:PORT".to_string())?;

        Ok(Self {
            setup_bin,
            sandbox_id,
            tun_name,
            sandbox_ip,
            broker_ip,
            mtu,
            dns: dns.unwrap_or(broker_ip),
            tcp_listen,
            tcp_host,
            target,
        })
    }
}

fn run(config: CliConfig) -> Result<(), String> {
    let sandbox_id = SandboxId::new(config.sandbox_id.clone())
        .map_err(|error| format!("invalid sandbox id: {error:?}"))?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before epoch: {error}"))?
        .as_nanos();
    let socket_dir = std::env::temp_dir().join(format!("foxprox-{}-{unique}", config.sandbox_id));
    std::fs::create_dir_all(&socket_dir)
        .map_err(|error| format!("create socket directory {}: {error}", socket_dir.display()))?;
    let socket_path = socket_dir.join("handoff.sock");

    let plan = SetupPlan {
        sandbox_id: sandbox_id.clone(),
        tun: TunDeviceConfig {
            name: config.tun_name.clone(),
            sandbox_ip: IpAddr::V4(config.sandbox_ip),
            broker_ip: IpAddr::V4(config.broker_ip),
            mtu: config.mtu,
        },
        dns_resolver: IpAddr::V4(config.dns),
        proxy_listener: None,
        tun_handoff_fd: 0,
    };
    let prepared = prepare_bwrap_launch_with_socket_path(plan, &config.target, &socket_path)
        .map_err(|error| format!("prepare bwrap launch: {error:?}"))?;
    let mut child = spawn_bwrap(&config, &prepared.command.args)
        .map_err(|error| format!("spawn bwrap: {error}"))?;
    let tun = match prepared.receive_tun_file() {
        Ok(tun) => tun,
        Err(error) => {
            let _ = child.kill();
            return Err(format!("receive TUN fd: {error:?}"));
        }
    };
    set_file_nonblocking(&tun, false).map_err(|error| format!("set blocking TUN fd: {error:?}"))?;

    let mut tun_reader = tun
        .try_clone()
        .map_err(|error| format!("clone TUN reader fd: {error}"))?;
    let mut tun_writer = tun
        .try_clone()
        .map_err(|error| format!("clone TUN writer fd: {error}"))?;
    let mut adapter = foxprox_smoltcp::SmoltcpIpLoopback::new(
        SmoltcpIpConfig {
            address: config.broker_ip,
            prefix_len: 24,
        },
        0,
    )
    .map_err(|error| format!("create smoltcp adapter: {error:?}"))?;
    adapter.set_packet_loopback(false);
    adapter.set_connect_report_mode(TcpConnectReportMode::AcceptedListenerSockets);
    adapter
        .listen_tcp(config.tcp_listen, 8192, 8192)
        .map_err(|error| {
            format!(
                "listen on sandbox TCP port {}: {error:?}",
                config.tcp_listen
            )
        })?;

    let mut rule = PolicyRule::allow("alpha-cli-allow-tcp");
    rule.protocol = Some(Protocol::Tcp);
    let mut rules = RuleSet::default();
    rules.push(rule);
    let mut kernel = VerificationKernel::new(
        PolicyEngine::new(PolicyConfig {
            rules,
            broker_dns: vec![IpAddr::V4(config.broker_ip)],
            ..PolicyConfig::default()
        }),
        VecAuditSink::bounded(1024),
    );
    let components = build_runtime_components(BrokerRuntimeConfig {
        sandbox_id: sandbox_id.clone(),
        policy: PolicyConfig::default(),
        static_dns_ttl_secs: 30,
        static_dns_records: Vec::new(),
        tcp_max_open_flows: 64,
        tcp_metadata_buffer_bytes: 8192,
    })
    .map_err(|error| format!("build runtime components: {error:?}"))?;
    let mut buffer = vec![0; config.mtu as usize + 128];

    let (session, flow) = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child: {error}"))?
        {
            return child_result(status);
        }
        foxprox_smoltcp::pump_one_tun_packet(
            &mut adapter,
            &mut tun_reader,
            &mut tun_writer,
            &mut buffer,
            1,
        )
        .map_err(|error| format!("pump initial TUN packet: {error}"))?;
        let Some(attempt) = adapter.next_connect_attempt() else {
            continue;
        };
        let event = NormalizedEvent::TcpConnectAttempt {
            sandbox_id: sandbox_id.clone(),
            frontend: FrontendKind::Tun,
            source: Some(Endpoint::new(attempt.source.ip, attempt.source.port)),
            destination: Endpoint::new(attempt.destination.ip, attempt.destination.port),
            hostname: None,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
        };
        let decision = kernel.decide_and_audit(&event, 1);
        if decision.action != DecisionAction::Allow {
            adapter.reset_connect(&attempt);
            return Err(format!("policy denied TCP connect: {decision:?}"));
        }
        adapter.mark_connect_opened(&attempt);
        break SmoltcpTcpBridgeSession::connect_allowed_host_session(
            adapter,
            &components,
            &attempt,
            config.tcp_host,
        )
        .map_err(|error| format!("connect host TCP {}: {error:?}", config.tcp_host))?;
    };

    set_file_nonblocking(&tun, true)
        .map_err(|error| format!("set nonblocking TUN fd: {error:?}"))?;
    let mut io_session = SmoltcpTcpBridgeIoSession::new(
        session,
        tun,
        config.mtu as usize + 128,
        flow,
        config.tcp_listen,
        8192,
        8192,
    );
    let mut tick_millis = 2i64;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child: {error}"))?
        {
            return child_result(status);
        }
        match io_session.run_tick(tick_millis) {
            Ok(_) => {}
            Err(SmoltcpTcpBridgeSessionError::TunWrite) => {
                return Err("TUN write failed during broker loop".to_string());
            }
            Err(error) => return Err(format!("broker TCP tick failed: {error:?}")),
        }
        tick_millis = tick_millis.saturating_add(1);
        thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_bwrap(config: &CliConfig, prepared_args: &[String]) -> std::io::Result<Child> {
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
    ];
    let setup_args_start = prepared_args
        .iter()
        .position(|arg| arg == "--sandbox-id")
        .unwrap_or(prepared_args.len());
    if let Some(socket_index) = prepared_args
        .iter()
        .position(|arg| arg == "--handoff-socket")
    {
        if let Some(socket_path) = prepared_args.get(socket_index + 1) {
            if let Some(parent) = std::path::Path::new(socket_path).parent() {
                args.push("--bind".to_string());
                args.push(parent.to_string_lossy().into_owned());
                args.push(parent.to_string_lossy().into_owned());
            }
        }
    }
    args.extend([
        "--tmpfs".to_string(),
        "/etc".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        config.setup_bin.to_string_lossy().into_owned(),
    ]);
    args.extend(prepared_args[setup_args_start..].iter().cloned());
    Command::new("bwrap")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

fn child_result(status: ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("sandbox target exited with status {status}"))
    }
}

fn next_value<I>(flag: &str, iter: &mut std::iter::Peekable<I>) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_ipv4(flag: &str, value: String) -> Result<Ipv4Addr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid IPv4 value for {flag}: {value}"))
}

fn parse_u16(flag: &str, value: String) -> Result<u16, String> {
    value
        .parse()
        .map_err(|_| format!("invalid u16 value for {flag}: {value}"))
}

fn usage() -> String {
    "usage: foxprox run [--setup-bin PATH] [--sandbox-id ID] [--tun-name NAME] \
     [--sandbox-ip 10.66.0.2] [--broker-ip 10.66.0.1] [--dns 10.66.0.1] \
     --tcp-listen PORT --tcp-host HOST:PORT -- COMMAND [ARGS...]"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_tcp_run_command() {
        let parsed = CliConfig::parse([
            "run",
            "--tcp-listen",
            "8080",
            "--tcp-host",
            "127.0.0.1:18080",
            "--",
            "python3",
            "app.py",
        ])
        .unwrap();

        assert_eq!(parsed.tcp_listen, 8080);
        assert_eq!(parsed.tcp_host, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(parsed.broker_ip, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(parsed.dns, parsed.broker_ip);
        assert_eq!(parsed.target, ["python3", "app.py"]);
    }

    #[test]
    fn rejects_missing_required_tcp_mapping() {
        let error = CliConfig::parse(["run", "--", "true"]).unwrap_err();
        assert!(error.contains("--tcp-listen"));
    }

    #[test]
    fn rejects_target_without_separator() {
        let error = CliConfig::parse([
            "run",
            "--tcp-listen",
            "8080",
            "--tcp-host",
            "127.0.0.1:18080",
            "true",
        ])
        .unwrap_err();
        assert!(error.contains("unexpected argument"));
    }
}
