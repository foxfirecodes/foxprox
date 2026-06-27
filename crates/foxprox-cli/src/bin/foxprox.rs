use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use foxprox_core::{Cidr, HostMatcher, PolicyConfig, PolicyRule, SandboxId};
use foxprox_device::TunDevice;
use foxprox_integrations::{receive_fd, validate_peer_uid};
use foxprox_net::{run_alpha_broker, AlphaBrokerConfig};

fn main() {
    if let Err(error) = run(env::args_os().skip(1).collect()) {
        eprintln!("foxprox: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    let config = CliConfig::parse(args)?;
    let paths = RuntimePaths::new()?;
    std::fs::write(
        &paths.resolv_conf,
        "nameserver 10.0.0.2\noptions attempts:1 timeout:1\n",
    )
    .map_err(|error| format!("write resolv.conf: {error}"))?;
    let resolv_conf = File::open(&paths.resolv_conf)
        .map_err(|error| format!("open generated resolv.conf: {error}"))?;
    clear_cloexec(resolv_conf.as_raw_fd())?;
    let _ = std::fs::remove_file(&paths.control_socket);
    let listener = UnixListener::bind(&paths.control_socket)
        .map_err(|error| format!("bind control socket: {error}"))?;

    let mut child = Command::new(&config.bwrap_program)
        .args([
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/run",
            "--dir",
            "/run/systemd",
            "--dir",
            "/run/systemd/resolve",
            "--ro-bind-data",
            &resolv_conf.as_raw_fd().to_string(),
            "/run/systemd/resolve/stub-resolv.conf",
            "--unsetenv",
            "HTTP_PROXY",
            "--unsetenv",
            "HTTPS_PROXY",
            "--unsetenv",
            "ALL_PROXY",
            "--unsetenv",
            "NO_PROXY",
            "--unsetenv",
            "http_proxy",
            "--unsetenv",
            "https_proxy",
            "--unsetenv",
            "all_proxy",
            "--unsetenv",
            "no_proxy",
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--",
        ])
        .arg(&config.setup_helper)
        .args([
            "--control-socket",
            paths
                .control_socket
                .to_str()
                .ok_or("non-utf8 control socket path")?,
            "--tun-name",
            "fp0",
            "--address",
            "10.0.0.1/24",
            "--route",
            "0.0.0.0/0",
            "--mtu",
            "1300",
            "--",
        ])
        .args(&config.target)
        .spawn()
        .map_err(|error| format!("spawn bwrap: {error}"))?;

    let (control, _) = listener
        .accept()
        .map_err(|error| format!("accept setup control socket: {error}"))?;
    // SAFETY: geteuid has no preconditions and reads process credentials only.
    let uid = unsafe { libc::geteuid() };
    validate_peer_uid(&control, uid)
        .map_err(|error| format!("setup peer credentials: {error:?}"))?;
    let tun_fd = receive_fd(&control).map_err(|error| format!("receive tun fd: {error:?}"))?;
    let tun = TunDevice::from_file("fp0", File::from(tun_fd))
        .map_err(|error| format!("wrap tun fd: {error:?}"))?;
    let mut broker = AlphaBrokerConfig::new(
        config.policy,
        SandboxId::new(config.sandbox_id),
        config.broker_ip,
    );
    broker.tcp_listen_ports = config.tcp_listen_ports;
    broker.tcp_destinations = config.tcp_destinations;
    broker.udp_listen_ports = config.udp_listen_ports;
    broker.udp_destinations = config.udp_destinations;
    broker.dns_upstream = config.dns_upstream;
    broker.max_runtime = config.max_runtime;
    broker.audit_stdout = true;

    let broker_result = run_alpha_broker(tun, broker, || child.try_wait().ok().flatten().is_some());
    let status = child
        .wait()
        .map_err(|error| format!("wait target: {error}"))?;
    let _ = std::fs::remove_file(&paths.control_socket);
    let _ = std::fs::remove_file(&paths.resolv_conf);
    broker_result.map_err(|error| format!("broker runtime: {error:?}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("sandbox target exited with {status}"))
    }
}

struct RuntimePaths {
    control_socket: PathBuf,
    resolv_conf: PathBuf,
}

impl RuntimePaths {
    fn new() -> Result<Self, String> {
        let dir = env::temp_dir();
        let unique = format!("foxprox-alpha-{}", std::process::id());
        Ok(Self {
            control_socket: dir.join(format!("{unique}.sock")),
            resolv_conf: dir.join(format!("{unique}-resolv.conf")),
        })
    }
}

struct CliConfig {
    bwrap_program: OsString,
    setup_helper: OsString,
    target: Vec<OsString>,
    sandbox_id: String,
    broker_ip: IpAddr,
    policy: PolicyConfig,
    tcp_listen_ports: Vec<u16>,
    tcp_destinations: HashMap<(IpAddr, u16), SocketAddr>,
    udp_listen_ports: Vec<u16>,
    udp_destinations: HashMap<(IpAddr, u16), SocketAddr>,
    dns_upstream: Option<SocketAddr>,
    max_runtime: Option<Duration>,
}

impl CliConfig {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut bwrap_program = OsString::from("bwrap");
        let mut setup_helper = default_setup_helper()?;
        let mut sandbox_id = "alpha".to_string();
        let broker_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let mut policy = PolicyConfig::default();
        policy.broker_dns_servers.push(broker_ip);
        let mut tcp_listen_ports = Vec::new();
        let mut tcp_destinations = HashMap::new();
        let mut udp_listen_ports = Vec::new();
        let mut udp_destinations = HashMap::new();
        let mut dns_upstream = None;
        let mut max_runtime = None;
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].to_string_lossy();
            if arg == "--" {
                let target = args[index + 1..].to_vec();
                if target.is_empty() {
                    return Err("missing target after --".into());
                }
                return Ok(Self {
                    bwrap_program,
                    setup_helper,
                    target,
                    sandbox_id,
                    broker_ip,
                    policy,
                    tcp_listen_ports,
                    tcp_destinations,
                    udp_listen_ports,
                    udp_destinations,
                    dns_upstream,
                    max_runtime,
                });
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_ref() {
                "--bwrap" => bwrap_program = value.clone(),
                "--setup-helper" => setup_helper = value.clone(),
                "--sandbox-id" => sandbox_id = value.to_string_lossy().into_owned(),
                "--allow-tcp" => {
                    let (ip, port) = parse_ip_port(value)?;
                    tcp_listen_ports.push(port);
                    policy.rules.push(PolicyRule::allow_ip(
                        format!("allow-tcp-{ip}-{port}"),
                        Cidr::host(ip),
                        Some(port),
                    ));
                }
                "--allow-udp" => {
                    let (ip, port) = parse_ip_port(value)?;
                    udp_listen_ports.push(port);
                    policy.rules.push(PolicyRule::allow_ip(
                        format!("allow-udp-{ip}-{port}"),
                        Cidr::host(ip),
                        Some(port),
                    ));
                }
                "--tcp-map" => {
                    let value = value.to_string_lossy();
                    let (left, right) = value
                        .split_once('=')
                        .ok_or("--tcp-map must be SANDBOX_IP:PORT=HOST_IP:PORT")?;
                    let (sandbox_ip, sandbox_port) = parse_ip_port_str(left)?;
                    let host: SocketAddr = right
                        .parse()
                        .map_err(|_| "--tcp-map host endpoint must be IP:PORT".to_string())?;
                    tcp_listen_ports.push(sandbox_port);
                    tcp_destinations.insert((sandbox_ip, sandbox_port), host);
                    policy.rules.push(PolicyRule::allow_ip(
                        format!("allow-map-{sandbox_ip}-{sandbox_port}"),
                        Cidr::host(host.ip()),
                        Some(host.port()),
                    ));
                }
                "--udp-map" => {
                    let value = value.to_string_lossy();
                    let (left, right) = value
                        .split_once('=')
                        .ok_or("--udp-map must be SANDBOX_IP:PORT=HOST_IP:PORT")?;
                    let (sandbox_ip, sandbox_port) = parse_ip_port_str(left)?;
                    let host: SocketAddr = right
                        .parse()
                        .map_err(|_| "--udp-map host endpoint must be IP:PORT".to_string())?;
                    udp_listen_ports.push(sandbox_port);
                    udp_destinations.insert((sandbox_ip, sandbox_port), host);
                    policy.rules.push(PolicyRule::allow_ip(
                        format!("allow-udp-map-{sandbox_ip}-{sandbox_port}"),
                        Cidr::host(host.ip()),
                        Some(host.port()),
                    ));
                }
                "--allow-domain" => {
                    let (host, port) = parse_host_port(value)?;
                    let matcher = HostMatcher::exact(&host)
                        .map_err(|error| format!("invalid domain: {error:?}"))?;
                    policy.rules.push(PolicyRule::allow_domain(
                        format!("allow-domain-{host}"),
                        matcher.clone(),
                        port,
                    ));
                    if port.is_some() && port != Some(53) {
                        policy.rules.push(PolicyRule::allow_domain(
                            format!("allow-domain-dns-{host}"),
                            matcher,
                            Some(53),
                        ));
                    }
                    match port {
                        Some(53) => {}
                        Some(port) => tcp_listen_ports.push(port),
                        None => tcp_listen_ports.extend([80, 443]),
                    }
                }
                "--dns-upstream" => {
                    dns_upstream = Some(
                        value
                            .to_string_lossy()
                            .parse()
                            .map_err(|_| "--dns-upstream must be IP:PORT".to_string())?,
                    );
                }
                "--max-runtime-ms" => {
                    let millis: u64 = value
                        .to_string_lossy()
                        .parse()
                        .map_err(|_| "invalid --max-runtime-ms".to_string())?;
                    max_runtime = Some(Duration::from_millis(millis));
                }
                "--help" => return Err(usage()),
                _ => return Err(format!("unknown argument {arg}\n{}", usage())),
            }
            index += 2;
        }
        Err(format!("missing -- target separator\n{}", usage()))
    }
}

fn clear_cloexec(fd: i32) -> Result<(), String> {
    // SAFETY: fcntl only reads/modifies descriptor flags for an fd owned by
    // this process; the fd remains open for bwrap to consume.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return Err(format!(
                "read fd flags: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
            return Err(format!(
                "clear close-on-exec: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn default_setup_helper() -> Result<OsString, String> {
    let exe = env::current_exe().map_err(|error| format!("current exe: {error}"))?;
    Ok(exe.with_file_name("foxproxsetup").into_os_string())
}

fn parse_ip_port(value: &OsString) -> Result<(IpAddr, u16), String> {
    parse_ip_port_str(&value.to_string_lossy())
}

fn parse_ip_port_str(value: &str) -> Result<(IpAddr, u16), String> {
    let socket: SocketAddr = value
        .parse()
        .map_err(|_| format!("expected IP:PORT, got {value}"))?;
    Ok((socket.ip(), socket.port()))
}

fn parse_host_port(value: &OsString) -> Result<(String, Option<u16>), String> {
    let value = value.to_string_lossy();
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return Ok((host.to_string(), Some(port)));
        }
    }
    Ok((value.into_owned(), None))
}

fn usage() -> String {
    "usage: foxprox [--allow-tcp IP:PORT] [--tcp-map SANDBOX_IP:PORT=HOST_IP:PORT] [--allow-udp IP:PORT] [--udp-map SANDBOX_IP:PORT=HOST_IP:PORT] [--allow-domain HOST[:PORT] --dns-upstream IP:PORT] -- COMMAND [ARGS...]".into()
}
