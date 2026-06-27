use foxprox_core::{
    parse_ip_packet, synthesize_udpv4_response, DecisionAction, DnsCache, Endpoint, FrontendKind,
    Hostname, HostnameAttribution, LineAuditSink, NormalizedEvent, ParsedIpPacket, PolicyConfig,
    PolicyEngine, PolicyRule, Protocol, QuicStatus, RuleSet, SandboxId, SniStatus,
    StaticDnsResolver, VerificationKernel,
};
use foxprox_device::set_file_nonblocking;
use foxprox_integrations::{SetupPlan, TunDeviceConfig};
use foxprox_launcher::prepare_bwrap_launch_with_socket_path;
use foxprox_runtime::{
    build_runtime_components, handle_broker_dns_udp_packet, BrokerRuntimeConfig, TcpStackAdapter,
};
use foxprox_smoltcp::{
    SmoltcpIpConfig, SmoltcpTcpBridgeIoSession, SmoltcpTcpBridgeSession,
    SmoltcpTcpBridgeSessionError, TcpConnectReportMode,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
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
    dns_aliases: Vec<String>,
    mode: BrokerMode,
    target: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BrokerMode {
    Tcp { listen: u16, host: SocketAddr },
    TcpDomain { hostname: String, port: u16 },
    Udp { listen: u16, host: SocketAddr },
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
        let mut dns_aliases = Vec::new();
        let mut tcp_listen = None;
        let mut tcp_host = None;
        let mut udp_listen = None;
        let mut udp_host = None;
        let mut tcp_domain = None;
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
                "--dns-alias" => dns_aliases.push(next_value(&arg, &mut iter)?),
                "--tcp-listen" => tcp_listen = Some(parse_u16(&arg, next_value(&arg, &mut iter)?)?),
                "--tcp-host" => {
                    tcp_host = Some(
                        next_value(&arg, &mut iter)?
                            .parse::<SocketAddr>()
                            .map_err(|_| "invalid --tcp-host socket address".to_string())?,
                    );
                }
                "--tcp-domain" => {
                    tcp_domain = Some(parse_host_port(&arg, next_value(&arg, &mut iter)?)?)
                }
                "--udp-listen" => udp_listen = Some(parse_u16(&arg, next_value(&arg, &mut iter)?)?),
                "--udp-host" => {
                    udp_host = Some(
                        next_value(&arg, &mut iter)?
                            .parse::<SocketAddr>()
                            .map_err(|_| "invalid --udp-host socket address".to_string())?,
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
        let mode = match (tcp_listen, tcp_host, tcp_domain, udp_listen, udp_host) {
            (Some(listen), Some(host), None, None, None) => BrokerMode::Tcp { listen, host },
            (None, None, Some((hostname, port)), None, None) => {
                dns_aliases.push(hostname.clone());
                BrokerMode::TcpDomain { hostname, port }
            }
            (None, None, None, Some(listen), Some(host)) => BrokerMode::Udp { listen, host },
            (Some(_), None, None, _, _) => {
                return Err("missing required --tcp-host ADDR:PORT".to_string())
            }
            (None, Some(_), None, _, _) => {
                return Err("missing required --tcp-listen PORT".to_string())
            }
            (_, _, _, Some(_), None) => {
                return Err("missing required --udp-host ADDR:PORT".to_string())
            }
            (_, _, _, None, Some(_)) => {
                return Err("missing required --udp-listen PORT".to_string())
            }
            (None, None, None, None, None) => {
                return Err("missing required TCP or UDP mapping".to_string());
            }
            _ => {
                return Err(
                    "TCP, TCP-domain, and UDP modes are mutually exclusive in this alpha CLI"
                        .to_string(),
                )
            }
        };

        Ok(Self {
            setup_bin,
            sandbox_id,
            tun_name,
            sandbox_ip,
            broker_ip,
            mtu,
            dns: dns.unwrap_or(broker_ip),
            dns_aliases,
            mode,
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

    match config.mode.clone() {
        BrokerMode::Tcp { listen, host } => {
            run_tcp_mode(tun, &mut child, &config, sandbox_id, listen, host)
        }
        BrokerMode::TcpDomain { hostname, port } => {
            let host = resolve_host(&hostname, port)?;
            run_tcp_mode(tun, &mut child, &config, sandbox_id, port, host)
        }
        BrokerMode::Udp { listen, host } => {
            run_udp_mode(tun, &mut child, &config, sandbox_id, listen, host)
        }
    }
}

fn run_tcp_mode(
    tun: std::fs::File,
    child: &mut Child,
    config: &CliConfig,
    sandbox_id: SandboxId,
    listen: u16,
    host: SocketAddr,
) -> Result<(), String> {
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
        .listen_tcp(listen, 8192, 8192)
        .map_err(|error| format!("listen on sandbox TCP port {listen}: {error:?}"))?;

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
        LineAuditSink::new(std::io::stderr()),
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
    let mut dns_resolver = StaticDnsResolver::new(30);
    for alias in &config.dns_aliases {
        dns_resolver.insert(
            Hostname::normalize(alias)
                .map_err(|error| format!("invalid --dns-alias hostname `{alias}`: {error:?}"))?,
            vec![IpAddr::V4(config.broker_ip)],
        );
    }
    let mut dns_cache = DnsCache::new();
    let mut buffer = vec![0; config.mtu as usize + 128];

    let (session, flow) = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child: {error}"))?
        {
            return child_result(status);
        }
        pump_dns_or_smoltcp_packet(
            &mut adapter,
            &mut tun_reader,
            &mut tun_writer,
            &mut buffer,
            &dns_resolver,
            &mut dns_cache,
            config.broker_ip,
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
            hostname: tcp_event_hostname(config, listen)?,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
        };
        let decision = kernel.decide_and_audit(&event, 1);
        if decision.action != DecisionAction::Allow {
            adapter.reset_connect(&attempt);
            drain_adapter_packets(&mut adapter, &mut tun_writer, 1)
                .map_err(|error| format!("write TCP denial reset to TUN: {error}"))?;
            return Err(format!("policy denied TCP connect: {decision:?}"));
        }
        let host_stream = match TcpStream::connect(host) {
            Ok(stream) => stream,
            Err(error) => {
                adapter.reset_connect(&attempt);
                drain_adapter_packets(&mut adapter, &mut tun_writer, 1)
                    .map_err(|error| format!("write host-connect failure reset to TUN: {error}"))?;
                return Err(format!("connect host TCP {host}: {error}"));
            }
        };
        if let Err(error) = host_stream.set_nonblocking(true) {
            adapter.reset_connect(&attempt);
            drain_adapter_packets(&mut adapter, &mut tun_writer, 1)
                .map_err(|error| format!("write host-connect failure reset to TUN: {error}"))?;
            return Err(format!("set host TCP {host} nonblocking: {error}"));
        }
        adapter.mark_connect_opened(&attempt);
        break SmoltcpTcpBridgeSession::from_allowed_connect(
            adapter,
            &components,
            &attempt,
            host_stream,
        )
        .map_err(|error| format!("open host TCP bridge {host}: {error:?}"))?;
    };

    set_file_nonblocking(&tun, true)
        .map_err(|error| format!("set nonblocking TUN fd: {error:?}"))?;
    let mut io_session = SmoltcpTcpBridgeIoSession::new(
        session,
        tun,
        config.mtu as usize + 128,
        flow,
        listen,
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

fn run_udp_mode(
    mut tun: std::fs::File,
    child: &mut Child,
    config: &CliConfig,
    sandbox_id: SandboxId,
    listen: u16,
    host: SocketAddr,
) -> Result<(), String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("bind host UDP socket: {error}"))?;
    socket
        .connect(host)
        .map_err(|error| format!("connect host UDP {host}: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("set host UDP read timeout: {error}"))?;
    let mut rule = PolicyRule::allow("alpha-cli-allow-udp");
    rule.protocol = Some(Protocol::Udp);
    let mut rules = RuleSet::default();
    rules.push(rule);
    let mut kernel = VerificationKernel::new(
        PolicyEngine::new(PolicyConfig {
            rules,
            broker_dns: vec![IpAddr::V4(config.broker_ip)],
            ..PolicyConfig::default()
        }),
        LineAuditSink::new(std::io::stderr()),
    );
    let mut buffer = vec![0; config.mtu as usize + 128];
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child: {error}"))?
        {
            return child_result(status);
        }
        let count = tun
            .read(&mut buffer)
            .map_err(|error| format!("read TUN packet: {error}"))?;
        let packet = match parse_ip_packet(&buffer[..count]) {
            Ok(ParsedIpPacket::Udpv4Packet(packet)) => packet,
            Ok(_) | Err(_) => continue,
        };
        if packet.destination != config.broker_ip || packet.destination_port != listen {
            continue;
        }
        let event = NormalizedEvent::UdpFlowAttempt {
            sandbox_id: sandbox_id.clone(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(IpAddr::V4(packet.source), packet.source_port),
            destination: Endpoint::new(IpAddr::V4(packet.destination), packet.destination_port),
            hostname: None,
            quic_status: QuicStatus::NotQuic,
        };
        let decision = kernel.decide_and_audit(&event, 1);
        if decision.action != DecisionAction::Allow {
            continue;
        }
        socket
            .send(packet.payload)
            .map_err(|error| format!("send host UDP payload: {error}"))?;
        let mut reply = vec![0; config.mtu as usize];
        let reply_len = socket
            .recv(&mut reply)
            .map_err(|error| format!("receive host UDP reply: {error}"))?;
        let response = synthesize_udpv4_response(&packet, &reply[..reply_len]);
        tun.write_all(&response)
            .map_err(|error| format!("write UDP response to TUN: {error}"))?;
    }
}

fn tcp_event_hostname(
    config: &CliConfig,
    listen: u16,
) -> Result<Option<HostnameAttribution>, String> {
    match &config.mode {
        BrokerMode::TcpDomain { hostname, port } if *port == listen => Ok(Some(
            HostnameAttribution::broker_dns(Hostname::normalize(hostname).map_err(|error| {
                format!("invalid --tcp-domain hostname `{hostname}`: {error:?}")
            })?),
        )),
        _ => Ok(None),
    }
}

fn drain_adapter_packets<W: Write>(
    adapter: &mut foxprox_smoltcp::SmoltcpIpLoopback,
    writer: &mut W,
    now_millis: i64,
) -> std::io::Result<()> {
    adapter.poll_once(now_millis);
    while let Some(packet) = adapter.next_outbound_ip_packet() {
        writer.write_all(&packet)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pump_dns_or_smoltcp_packet<R: Read, W: Write>(
    adapter: &mut foxprox_smoltcp::SmoltcpIpLoopback,
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    dns_resolver: &StaticDnsResolver,
    dns_cache: &mut DnsCache,
    broker_ip: Ipv4Addr,
    now_millis: i64,
) -> std::io::Result<()> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    if let Ok(ParsedIpPacket::Udpv4Packet(udp)) = parse_ip_packet(packet) {
        if udp.destination == broker_ip && udp.destination_port == 53 {
            if let Ok(response) = handle_broker_dns_udp_packet(
                &udp,
                dns_resolver,
                dns_cache,
                now_millis.max(0) as u128,
            ) {
                writer.write_all(&response.packet)?;
            }
            return Ok(());
        }
    }
    adapter.ingest_ip_packet(packet.to_vec()).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{error:?}"))
    })?;
    adapter.poll_once(now_millis);
    while let Some(packet) = adapter.next_outbound_ip_packet() {
        writer.write_all(&packet)?;
    }
    Ok(())
}

fn resolve_host(hostname: &str, port: u16) -> Result<SocketAddr, String> {
    (hostname, port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve {hostname}:{port}: {error}"))?
        .find(|address| address.is_ipv4())
        .ok_or_else(|| format!("no IPv4 address resolved for {hostname}:{port}"))
}

fn parse_host_port(flag: &str, value: String) -> Result<(String, u16), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("{flag} must be HOST:PORT"))?;
    if host.is_empty() {
        return Err(format!("{flag} host must not be empty"));
    }
    Ok((host.to_string(), parse_u16(flag, port.to_string())?))
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
     [--dns-alias HOST] \
     (--tcp-listen PORT --tcp-host ADDR:PORT | --tcp-domain HOST:PORT | \
      --udp-listen PORT --udp-host ADDR:PORT) -- COMMAND [ARGS...]"
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

        assert_eq!(
            parsed.mode,
            BrokerMode::Tcp {
                listen: 8080,
                host: "127.0.0.1:18080".parse().unwrap()
            }
        );
        assert_eq!(parsed.broker_ip, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(parsed.dns, parsed.broker_ip);
        assert_eq!(parsed.target, ["python3", "app.py"]);
    }

    #[test]
    fn parses_minimal_udp_run_command() {
        let parsed = CliConfig::parse([
            "run",
            "--udp-listen",
            "5353",
            "--udp-host",
            "127.0.0.1:15353",
            "--",
            "python3",
            "app.py",
        ])
        .unwrap();

        assert_eq!(
            parsed.mode,
            BrokerMode::Udp {
                listen: 5353,
                host: "127.0.0.1:15353".parse().unwrap()
            }
        );
    }

    #[test]
    fn rejects_missing_required_mapping() {
        let error = CliConfig::parse(["run", "--", "true"]).unwrap_err();
        assert!(error.contains("TCP or UDP mapping"));
    }

    #[test]
    fn parses_tcp_domain_mode_and_adds_dns_alias() {
        let parsed = CliConfig::parse([
            "run",
            "--tcp-domain",
            "example.com:80",
            "--",
            "curl",
            "http://example.com",
        ])
        .unwrap();

        assert_eq!(
            parsed.mode,
            BrokerMode::TcpDomain {
                hostname: "example.com".to_string(),
                port: 80,
            }
        );
        assert_eq!(parsed.dns_aliases, ["example.com".to_string()]);
    }

    #[test]
    fn rejects_mixed_tcp_and_udp_modes() {
        let error = CliConfig::parse([
            "run",
            "--tcp-listen",
            "8080",
            "--tcp-host",
            "127.0.0.1:18080",
            "--udp-listen",
            "5353",
            "--udp-host",
            "127.0.0.1:15353",
            "--",
            "true",
        ])
        .unwrap_err();
        assert!(error.contains("mutually exclusive"));
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
