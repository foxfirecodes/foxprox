use foxprox_core::{
    classify_udp_candidate, AuditBackpressure, AuditBuffer, AuditEvent, AuditEventKind, Cidr,
    Decision, DecisionAction, Frontend, NetworkEvent, PolicyRule, PortRange, Protocol, RuleEffect,
    SandboxId, TransportEndpoint,
};
use foxprox_device::{
    icmp_event, parse_icmpv4_metadata, parse_ipv4_metadata, synthesize_icmpv4_echo_reply,
    unsupported_event_for_drop,
};
use foxprox_net::{
    run_combined_transparent_proof_with_ready, run_tcp_proof_with_ready,
    run_udp_dns_proof_with_ready, CombinedTransparentProofConfig, ExplicitHttpProxyBridgeConfig,
    TcpProofConfig, UdpDnsProofConfig,
};
use foxprox_proxy::{
    run_http_proxy_proof, run_http_proxy_proof_with_ready, run_socks5_proxy_proof,
    HttpProxyProofConfig, Socks5ProxyProofConfig,
};
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use std::env;
use std::fs::{self, File};
use std::io::{self, IoSliceMut, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("foxprox: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("proof-icmp") => proof_icmp(args),
        Some("proof-tcp") => proof_tcp(args),
        Some("proof-udp-dns") => proof_udp_dns(args),
        Some("proof-transparent") => proof_transparent(args),
        Some("proof-http-proxy") => proof_http_proxy(args),
        Some("proof-socks5-proxy") => proof_socks5_proxy(args),
        Some("--help" | "-h") | None => Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command {other:?}\n{}", usage()),
        )),
    }
}

fn usage() -> &'static str {
    "usage: foxprox proof-icmp --setup-socket PATH [--local-ip 10.255.0.1] [--audit-queue-capacity N]\n       foxprox proof-tcp --setup-socket PATH [--broker-ip 10.255.0.1] [--prefix-len 24] [--mtu 1500] [--tcp-port 80] [--audit-queue-capacity N]\n       foxprox proof-udp-dns --setup-socket PATH [--broker-ip 10.255.0.1] [--prefix-len 24] [--mtu 1500] [--upstream-dns 1.1.1.1:53] [--udp-forward-port PORT]... [--audit-queue-capacity N] [--max-workers N] [--max-udp-flows N]\n       foxprox proof-transparent --setup-socket PATH [--broker-ip 10.255.0.1] [--prefix-len 24] [--mtu 1500] [--tcp-port 80] [--upstream-dns 1.1.1.1:53] [--udp-forward-port PORT]... [--audit-queue-capacity N] [--max-workers N] [--max-udp-flows N] [--http-proxy-port PORT] [--http-proxy-allow-port PORT]... [--http-proxy-backend-listen 127.0.0.1:0]\n       foxprox proof-http-proxy [--listen 10.255.0.1:8080] [--allow-port PORT]... [--request-head-limit BYTES] [--request-head-timeout-ms MS] [--connect-timeout-ms MS] [--audit-queue-capacity N] [--max-connections N]\n       foxprox proof-socks5-proxy [--listen 10.255.0.1:1080] [--allow-port PORT]... [--request-timeout-ms MS] [--connect-timeout-ms MS] [--audit-queue-capacity N] [--max-connections N]"
}

fn proof_icmp<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut local_ip = Ipv4Addr::new(10, 255, 0, 1);
    let mut audit = audit_buffer(8192)?;
    let sandbox_id = SandboxId::new("proof-icmp").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox id: {error}"),
        )
    })?;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--local-ip" => local_ip = parse_value(&required_value(&mut args, "--local-ip")?)?,
            "--audit-queue-capacity" => {
                audit = audit_buffer(parse_nonzero_usize(&required_value(
                    &mut args,
                    "--audit-queue-capacity",
                )?)?)?
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = BoundSetupListener::bind(&setup_socket)?;
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    stream.write_all(b"ready\n")?;
    eprintln!("foxprox: received TUN fd; local ICMP proof address is {local_ip}");

    let mut tun = unsafe { File::from_raw_fd(tun_fd.into_raw_fd()) };
    let mut buffer = vec![0_u8; 4096];
    loop {
        let len = tun.read(&mut buffer)?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN fd reached EOF",
            ));
        }
        let packet = &buffer[..len];
        let parsed_ipv4 = parse_ipv4_metadata(packet);
        if let Ok(ipv4) = parsed_ipv4 {
            eprintln!(
                "foxprox: packet len={} src={} dst={} proto={}",
                ipv4.total_len, ipv4.source, ipv4.destination, ipv4.protocol
            );
            if let Ok(icmp) = parse_icmpv4_metadata(packet, ipv4) {
                eprintln!("foxprox: icmp type={} code={}", icmp.ty, icmp.code);
            }
        }

        match synthesize_icmpv4_echo_reply(packet, local_ip) {
            Ok(reply) => {
                if let Ok(ipv4) = parsed_ipv4 {
                    if let Ok(icmp) = parse_icmpv4_metadata(packet, ipv4) {
                        if let Err(error) = emit_icmp_audit(
                            &mut audit,
                            &icmp_event(sandbox_id.clone(), ipv4, icmp),
                            Decision::allow("proof-icmp-echo"),
                        ) {
                            eprintln!("foxprox: ICMP audit backpressure: {error}");
                            continue;
                        }
                    }
                }
                tun.write_all(&reply)?;
                eprintln!("foxprox: wrote ICMP echo reply len={}", reply.len());
            }
            Err(reason) => {
                let event = unsupported_event_for_drop(Some(sandbox_id.clone()), reason.clone());
                if let Err(error) = emit_icmp_audit(
                    &mut audit,
                    &event,
                    Decision::default_deny(DecisionAction::FailClosed),
                ) {
                    eprintln!("foxprox: unsupported packet audit backpressure: {error}");
                    continue;
                }
                eprintln!("foxprox: no reply: {reason:?} event={event:?}");
            }
        }
    }
}

fn proof_tcp<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut config = TcpProofConfig::new(SandboxId::new("proof-tcp").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox id: {error}"),
        )
    })?);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--broker-ip" => {
                config.broker_ip = parse_value(&required_value(&mut args, "--broker-ip")?)?
            }
            "--prefix-len" => {
                config.prefix_len = parse_value(&required_value(&mut args, "--prefix-len")?)?
            }
            "--mtu" => config.mtu = parse_value(&required_value(&mut args, "--mtu")?)?,
            "--tcp-port" => {
                config.tcp_port = parse_value(&required_value(&mut args, "--tcp-port")?)?
            }
            "--audit-queue-capacity" => {
                config.audit_queue_capacity =
                    parse_nonzero_usize(&required_value(&mut args, "--audit-queue-capacity")?)?
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    config
        .policy
        .rules
        .push(allow_tcp_forward_rule(config.tcp_port));
    if config.tcp_port == 80 {
        config
            .policy
            .rules
            .push(allow_http_forward_rule(config.tcp_port));
    }
    if config.tcp_port == 443 {
        config
            .policy
            .rules
            .push(allow_tls_forward_rule(config.tcp_port));
    }

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = BoundSetupListener::bind(&setup_socket)?;
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    eprintln!(
        "foxprox: received TUN fd; starting TCP proof on port {}",
        config.tcp_port
    );
    run_tcp_proof_with_ready(tun_fd, config, || stream.write_all(b"ready\n"))
}

fn proof_udp_dns<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut config = UdpDnsProofConfig::new(SandboxId::new("proof-udp-dns").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox id: {error}"),
        )
    })?);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--broker-ip" => {
                config.broker_ip = parse_value(&required_value(&mut args, "--broker-ip")?)?
            }
            "--prefix-len" => {
                config.prefix_len = parse_value(&required_value(&mut args, "--prefix-len")?)?
            }
            "--mtu" => config.mtu = parse_value(&required_value(&mut args, "--mtu")?)?,
            "--upstream-dns" => {
                config.upstream_dns =
                    parse_socket_addr(&required_value(&mut args, "--upstream-dns")?)?
            }
            "--udp-forward-port" => {
                let port = parse_value(&required_value(&mut args, "--udp-forward-port")?)?;
                config.udp_forward_ports.push(port);
                config.policy.rules.push(allow_udp_forward_rule(port));
            }
            "--audit-queue-capacity" => {
                config.audit_queue_capacity =
                    parse_nonzero_usize(&required_value(&mut args, "--audit-queue-capacity")?)?
            }
            "--max-workers" => {
                config.max_worker_threads =
                    parse_nonzero_usize(&required_value(&mut args, "--max-workers")?)?
            }
            "--max-udp-flows" => {
                config.max_udp_flows =
                    parse_nonzero_usize(&required_value(&mut args, "--max-udp-flows")?)?
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = BoundSetupListener::bind(&setup_socket)?;
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    eprintln!(
        "foxprox: received TUN fd; starting UDP/DNS proof broker_dns={}:{} upstream={}",
        config.broker_ip, config.dns_port, config.upstream_dns
    );
    run_udp_dns_proof_with_ready(tun_fd, config, || stream.write_all(b"ready\n"))
}

fn proof_transparent<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let sandbox_id = SandboxId::new("proof-transparent").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox id: {error}"),
        )
    })?;
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut config = CombinedTransparentProofConfig::new(sandbox_id.clone());
    let mut http_proxy_port = None;
    let mut http_proxy_config =
        HttpProxyProofConfig::new(sandbox_id, SocketAddr::from(([127, 0, 0, 1], 0)));

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--broker-ip" => {
                config.broker_ip = parse_value(&required_value(&mut args, "--broker-ip")?)?
            }
            "--prefix-len" => {
                config.prefix_len = parse_value(&required_value(&mut args, "--prefix-len")?)?
            }
            "--mtu" => config.mtu = parse_value(&required_value(&mut args, "--mtu")?)?,
            "--tcp-port" => {
                config.tcp_port = parse_value(&required_value(&mut args, "--tcp-port")?)?
            }
            "--upstream-dns" => {
                config.upstream_dns =
                    parse_socket_addr(&required_value(&mut args, "--upstream-dns")?)?
            }
            "--udp-forward-port" => {
                let port = parse_value(&required_value(&mut args, "--udp-forward-port")?)?;
                config.udp_forward_ports.push(port);
                config.policy.rules.push(allow_udp_forward_rule(port));
            }
            "--audit-queue-capacity" => {
                config.audit_queue_capacity =
                    parse_nonzero_usize(&required_value(&mut args, "--audit-queue-capacity")?)?
            }
            "--max-workers" => {
                config.max_worker_threads =
                    parse_nonzero_usize(&required_value(&mut args, "--max-workers")?)?
            }
            "--max-udp-flows" => {
                config.max_udp_flows =
                    parse_nonzero_usize(&required_value(&mut args, "--max-udp-flows")?)?
            }
            "--http-proxy-port" => {
                http_proxy_port = Some(parse_nonzero_u16(&required_value(
                    &mut args,
                    "--http-proxy-port",
                )?)?)
            }
            "--http-proxy-allow-port" => {
                let port = parse_value(&required_value(&mut args, "--http-proxy-allow-port")?)?;
                http_proxy_config
                    .policy
                    .rules
                    .push(allow_http_proxy_rule(port));
                http_proxy_config
                    .policy
                    .rules
                    .push(allow_connect_proxy_rule(port));
            }
            "--http-proxy-backend-listen" => {
                http_proxy_config.listen_addr =
                    parse_socket_addr(&required_value(&mut args, "--http-proxy-backend-listen")?)?
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    config
        .policy
        .rules
        .push(allow_tcp_forward_rule(config.tcp_port));
    if config.tcp_port == 80 {
        config
            .policy
            .rules
            .push(allow_http_forward_rule(config.tcp_port));
    }
    if config.tcp_port == 443 {
        config
            .policy
            .rules
            .push(allow_tls_forward_rule(config.tcp_port));
    }

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = BoundSetupListener::bind(&setup_socket)?;
    if let Some(proxy_port) = http_proxy_port {
        if proxy_port == config.tcp_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP proxy port must differ from transparent TCP port",
            ));
        }
        validate_http_proxy_backend_loopback(http_proxy_config.listen_addr)?;
        let backend_addr = start_http_proxy_backend(http_proxy_config)?;
        validate_http_proxy_backend_loopback(backend_addr)?;
        config.http_proxy_bridge = Some(ExplicitHttpProxyBridgeConfig {
            sandbox_port: proxy_port,
            backend_addr,
        });
        config
            .policy
            .rules
            .push(allow_proxy_bridge_rule(config.broker_ip, proxy_port));
        eprintln!(
            "foxprox: transparent HTTP proxy reachable as HTTP_PROXY=http://{}:{} (backend {backend_addr})",
            config.broker_ip, proxy_port
        );
    }
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    eprintln!(
        "foxprox: received TUN fd; starting combined transparent proof tcp_port={} broker_dns={}:{} upstream={}",
        config.tcp_port, config.broker_ip, config.dns_port, config.upstream_dns
    );
    run_combined_transparent_proof_with_ready(tun_fd, config, || stream.write_all(b"ready\n"))
}

fn validate_http_proxy_backend_loopback(addr: SocketAddr) -> io::Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("HTTP proxy backend listen address must be loopback-only, got {addr}"),
        ))
    }
}

fn start_http_proxy_backend(config: HttpProxyProofConfig) -> io::Result<SocketAddr> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reported = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reported_for_thread = std::sync::Arc::clone(&reported);
    std::thread::spawn(move || {
        let error_tx = ready_tx.clone();
        let result = run_http_proxy_proof_with_ready(config, move |addr| {
            reported_for_thread.store(true, std::sync::atomic::Ordering::Release);
            ready_tx
                .send(Ok(addr))
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))
        });
        if !reported.load(std::sync::atomic::Ordering::Acquire) {
            let _ = error_tx.send(result.map(|_| SocketAddr::from(([127, 0, 0, 1], 0))));
        } else if let Err(error) = result {
            eprintln!("foxprox: HTTP proxy backend exited: {error}");
        }
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("HTTP proxy backend did not become ready: {error}"),
            )
        })?
}

fn proof_http_proxy<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut config = HttpProxyProofConfig::new(
        SandboxId::new("proof-http-proxy").map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid sandbox id: {error}"),
            )
        })?,
        SocketAddr::from(([10, 255, 0, 1], 8080)),
    );

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                config.listen_addr = parse_socket_addr(&required_value(&mut args, "--listen")?)?
            }
            "--allow-port" => {
                let port = parse_value(&required_value(&mut args, "--allow-port")?)?;
                config.policy.rules.push(allow_http_proxy_rule(port));
                config.policy.rules.push(allow_connect_proxy_rule(port));
            }
            "--request-head-limit" => {
                config.request_head_limit =
                    parse_value(&required_value(&mut args, "--request-head-limit")?)?
            }
            "--request-head-timeout-ms" => {
                config.request_head_timeout =
                    parse_millis(&required_value(&mut args, "--request-head-timeout-ms")?)?
            }
            "--connect-timeout-ms" => {
                config.connect_timeout =
                    parse_millis(&required_value(&mut args, "--connect-timeout-ms")?)?
            }
            "--audit-queue-capacity" => {
                config.audit_queue_capacity =
                    parse_nonzero_usize(&required_value(&mut args, "--audit-queue-capacity")?)?
            }
            "--max-connections" => {
                config.max_connections =
                    parse_nonzero_usize(&required_value(&mut args, "--max-connections")?)?
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    eprintln!(
        "foxprox: starting HTTP/CONNECT proxy proof on {}",
        config.listen_addr
    );
    run_http_proxy_proof(config)
}

fn proof_socks5_proxy<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut config = Socks5ProxyProofConfig::new(
        SandboxId::new("proof-socks5-proxy").map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid sandbox id: {error}"),
            )
        })?,
        SocketAddr::from(([10, 255, 0, 1], 1080)),
    );

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                config.listen_addr = parse_socket_addr(&required_value(&mut args, "--listen")?)?
            }
            "--allow-port" => {
                let port = parse_value(&required_value(&mut args, "--allow-port")?)?;
                config.policy.rules.push(allow_socks_proxy_rule(port));
            }
            "--request-timeout-ms" => {
                config.request_timeout =
                    parse_millis(&required_value(&mut args, "--request-timeout-ms")?)?
            }
            "--connect-timeout-ms" => {
                config.connect_timeout =
                    parse_millis(&required_value(&mut args, "--connect-timeout-ms")?)?
            }
            "--audit-queue-capacity" => {
                config.audit_queue_capacity =
                    parse_nonzero_usize(&required_value(&mut args, "--audit-queue-capacity")?)?
            }
            "--max-connections" => {
                config.max_connections =
                    parse_nonzero_usize(&required_value(&mut args, "--max-connections")?)?
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    eprintln!(
        "foxprox: starting SOCKS5 proxy proof on {}",
        config.listen_addr
    );
    run_socks5_proxy_proof(config)
}

fn allow_tcp_forward_rule(port: u16) -> PolicyRule {
    PolicyRule::new(format!("proof-allow-tcp-{port}"), RuleEffect::Allow)
        .with_protocol(Protocol::Tcp)
        .with_destination_ports(PortRange::single(port))
}

fn allow_proxy_bridge_rule(broker_ip: Ipv4Addr, port: u16) -> PolicyRule {
    PolicyRule::new(
        format!("proof-allow-http-proxy-bridge-{port}"),
        RuleEffect::Allow,
    )
    .with_protocol(Protocol::Tcp)
    .with_destination_cidr(Cidr::v4(broker_ip, 32).expect("valid IPv4 /32"))
    .with_destination_ports(PortRange::single(port))
}

fn allow_http_forward_rule(port: u16) -> PolicyRule {
    PolicyRule::new(format!("proof-allow-http-{port}"), RuleEffect::Allow)
        .with_protocol(Protocol::Http)
        .with_destination_ports(PortRange::single(port))
}

fn allow_tls_forward_rule(port: u16) -> PolicyRule {
    PolicyRule::new(format!("proof-allow-tls-{port}"), RuleEffect::Allow)
        .with_protocol(Protocol::Tls)
        .with_destination_ports(PortRange::single(port))
}

fn allow_udp_forward_rule(port: u16) -> PolicyRule {
    let protocol = if classify_udp_candidate(port) == Protocol::Quic {
        Protocol::Quic
    } else {
        Protocol::Udp
    };
    PolicyRule::new(format!("proof-allow-udp-{port}"), RuleEffect::Allow)
        .with_protocol(protocol)
        .with_destination_ports(PortRange::single(port))
}

fn allow_http_proxy_rule(port: u16) -> PolicyRule {
    PolicyRule::new(format!("proof-allow-http-proxy-{port}"), RuleEffect::Allow)
        .with_protocol(Protocol::Http)
        .with_destination_ports(PortRange::single(port))
}

fn allow_connect_proxy_rule(port: u16) -> PolicyRule {
    PolicyRule::new(
        format!("proof-allow-connect-proxy-{port}"),
        RuleEffect::Allow,
    )
    .with_protocol(Protocol::HttpsConnect)
    .with_destination_ports(PortRange::single(port))
}

fn allow_socks_proxy_rule(port: u16) -> PolicyRule {
    PolicyRule::new(format!("proof-allow-socks-proxy-{port}"), RuleEffect::Allow)
        .with_protocol(Protocol::Socks)
        .with_destination_ports(PortRange::single(port))
}

fn required_value<I>(args: &mut I, flag: &str) -> io::Result<String>
where
    I: Iterator<Item = String>,
{
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn parse_value<T>(value: &str) -> io::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid value {value:?}: {error}"),
        )
    })
}

fn parse_socket_addr(value: &str) -> io::Result<SocketAddr> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid socket address {value:?}: {error}"),
        )
    })
}

fn parse_millis(value: &str) -> io::Result<std::time::Duration> {
    let millis = parse_value(value)?;
    Ok(std::time::Duration::from_millis(millis))
}

fn parse_nonzero_usize(value: &str) -> io::Result<usize> {
    let parsed = parse_value(value)?;
    if parsed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value must be greater than zero",
        ));
    }
    Ok(parsed)
}

fn parse_nonzero_u16(value: &str) -> io::Result<u16> {
    let parsed = parse_value(value)?;
    if parsed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value must be greater than zero",
        ));
    }
    Ok(parsed)
}

fn audit_buffer(capacity: usize) -> io::Result<AuditBuffer> {
    if capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit queue capacity must be non-zero",
        ));
    }
    Ok(AuditBuffer::new(capacity))
}

fn emit_icmp_audit(
    audit: &mut AuditBuffer,
    event: &NetworkEvent,
    decision: Decision,
) -> io::Result<()> {
    let audit_event = icmp_audit_event(event, decision);
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(audit_event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox: ICMP audit event={audit_event:?}");
    Ok(())
}

#[cfg(not(test))]
fn drain_audit_to_stderr(audit: &mut AuditBuffer) -> io::Result<()> {
    let mut stderr = io::stderr();
    foxprox_core::drain_audit_buffer_to_json_lines(audit, &mut stderr)
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("audit sink write failed: {error}")))
}

#[cfg(test)]
fn drain_audit_to_stderr(_audit: &mut AuditBuffer) -> io::Result<()> {
    Ok(())
}

fn audit_backpressure_error(error: AuditBackpressure) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!("audit queue backpressure: {error:?}"),
    )
}

fn icmp_audit_event(event: &NetworkEvent, decision: Decision) -> AuditEvent {
    let kind = match event {
        NetworkEvent::IcmpMessage { .. } => AuditEventKind::IcmpMessage,
        NetworkEvent::Unsupported { .. } => AuditEventKind::UnsupportedDenied,
        _ => AuditEventKind::BrokerError,
    };
    let mut audit = AuditEvent::new(Frontend::Tun, kind).with_decision(decision);
    if let Some(sandbox_id) = event.sandbox_id() {
        audit = audit.with_sandbox_id(sandbox_id.clone());
    }
    audit.protocol = Some(event.protocol());
    match event {
        NetworkEvent::IcmpMessage {
            source,
            destination,
            ty,
            code,
            ..
        } => {
            audit.source = Some(TransportEndpoint::new(*source, 0));
            audit.destination = Some(TransportEndpoint::new(*destination, 0));
            audit.detail = Some(format!("icmp type={ty} code={code}"));
        }
        NetworkEvent::Unsupported { reason, .. } => {
            audit.detail = Some(format!("{reason:?}"));
        }
        _ => {}
    }
    audit
}

struct BoundSetupListener {
    listener: UnixListener,
    path: PathBuf,
    identity: FileIdentity,
}

impl BoundSetupListener {
    fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&path)?;
        let identity = FileIdentity::from_metadata(&metadata);
        Ok(Self {
            listener,
            path,
            identity,
        })
    }

    fn accept(&self) -> io::Result<(UnixStream, std::os::unix::net::SocketAddr)> {
        self.listener.accept()
    }
}

impl Drop for BoundSetupListener {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && FileIdentity::from_metadata(&metadata) == self.identity =>
            {
                let _ = fs::remove_file(&self.path);
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn verify_peer_credentials(stream: &UnixStream) -> io::Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let uid = unsafe { libc::geteuid() };
    if credentials.uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "setup peer uid {} did not match broker uid {uid}",
                credentials.uid
            ),
        ));
    }
    Ok(())
}

fn recv_fd(socket_fd: RawFd) -> io::Result<OwnedFd> {
    let mut data = [0_u8; 64];
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        socket_fd,
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )
    .map_err(io::Error::other)?;
    for cmsg in msg.cmsgs().map_err(io::Error::other)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if fds.len() != 1 {
                for fd in fds {
                    unsafe {
                        libc::close(fd);
                    }
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SCM_RIGHTS message did not contain exactly one fd",
                ));
            }
            return Ok(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "setup message did not contain a TUN fd",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_socket_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "foxprox-{name}-{}-{nanos}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn usage_mentions_combined_transparent_proof() {
        assert!(usage().contains("proof-transparent"));
        assert!(usage().contains("--max-workers"));
        assert!(usage().contains("--udp-forward-port"));
        assert!(usage().contains("--http-proxy-port"));
    }

    #[test]
    fn http_proxy_backend_loopback_validation_accepts_loopback_only() {
        validate_http_proxy_backend_loopback(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        validate_http_proxy_backend_loopback("[::1]:0".parse().unwrap()).unwrap();

        let error =
            validate_http_proxy_backend_loopback(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("loopback-only"));
    }

    #[test]
    fn icmp_audit_event_records_message_metadata() {
        let event = NetworkEvent::IcmpMessage {
            sandbox_id: SandboxId::new("test").unwrap(),
            source: "10.255.0.2".parse().unwrap(),
            destination: "10.255.0.1".parse().unwrap(),
            ty: 8,
            code: 0,
        };
        let audit = icmp_audit_event(&event, Decision::allow("allow-icmp"));

        assert_eq!(audit.kind, AuditEventKind::IcmpMessage);
        assert_eq!(audit.protocol, Some(Protocol::Icmp));
        assert_eq!(audit.source.unwrap().ip.to_string(), "10.255.0.2");
        assert_eq!(audit.destination.unwrap().ip.to_string(), "10.255.0.1");
        assert!(audit.detail.unwrap().contains("type=8"));
        assert!(audit.decision.unwrap().is_allowed());
    }

    #[test]
    fn icmp_audit_enqueue_reports_backpressure() {
        let event = NetworkEvent::Unsupported {
            sandbox_id: Some(SandboxId::new("test").unwrap()),
            frontend: Frontend::Tun,
            reason: foxprox_core::UnsupportedReason::Malformed("bad packet".to_string()),
        };
        let mut audit = audit_buffer(1).unwrap();

        emit_icmp_audit(
            &mut audit,
            &event,
            Decision::default_deny(DecisionAction::FailClosed),
        )
        .unwrap();
        let error = emit_icmp_audit(
            &mut audit,
            &event,
            Decision::default_deny(DecisionAction::FailClosed),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn icmp_audit_rejects_zero_capacity() {
        assert_eq!(
            audit_buffer(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn bound_setup_listener_removes_socket_on_drop() {
        let path = unique_socket_path("cleanup");
        {
            let _listener = BoundSetupListener::bind(&path).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.file_type().is_socket());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        assert!(!path.exists());
    }

    #[test]
    fn bound_setup_listener_does_not_preunlink_existing_file() {
        let path = unique_socket_path("existing");
        fs::write(&path, b"not a socket").unwrap();
        let result = BoundSetupListener::bind(&path);
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not a socket");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bound_setup_listener_does_not_remove_replaced_non_socket() {
        let path = unique_socket_path("replaced");
        let listener = BoundSetupListener::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        drop(listener);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bound_setup_listener_does_not_remove_replaced_socket() {
        let path = unique_socket_path("replaced-socket");
        let listener = BoundSetupListener::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        drop(listener);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        drop(replacement);
        let _ = fs::remove_file(path);
    }
}
