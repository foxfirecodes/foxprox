use std::env;
use std::fmt;
use std::net::{IpAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use foxprox_core::{FrontendKind, RuntimeConfig, SandboxId};
use foxprox_integrations::{NetworkSetupRequest, ProxyExposure, TunDeviceConfig};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherArgs {
    pub setup_helper: PathBuf,
    pub target: Vec<String>,
    pub sandbox_id: SandboxId,
    pub tun_name: String,
    pub sandbox_ip: IpAddr,
    pub broker_ip: IpAddr,
    pub mtu: u16,
    pub dns: IpAddr,
    pub proxy: Option<ProxyExposure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupArgs {
    pub target: Vec<String>,
    pub tun_name: String,
    pub sandbox_ip: IpAddr,
    pub broker_ip: IpAddr,
    pub mtu: u16,
    pub dns: IpAddr,
    pub handoff_fd: i32,
}

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Io(std::io::Error),
    Integration(foxprox_integrations::IntegrationError),
    Device(foxprox_device::DeviceError),
    Runtime(foxprox_runtime::RuntimeError),
    Stack(foxprox_net::StackError),
    Nix(nix::Error),
    Unsupported(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Integration(error) => write!(f, "integration error: {error}"),
            Self::Device(error) => write!(f, "device error: {error}"),
            Self::Runtime(error) => write!(f, "runtime error: {error}"),
            Self::Stack(error) => write!(f, "stack error: {error}"),
            Self::Nix(error) => write!(f, "nix error: {error}"),
            Self::Unsupported(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<foxprox_integrations::IntegrationError> for CliError {
    fn from(error: foxprox_integrations::IntegrationError) -> Self {
        Self::Integration(error)
    }
}

impl From<foxprox_device::DeviceError> for CliError {
    fn from(error: foxprox_device::DeviceError) -> Self {
        Self::Device(error)
    }
}

impl From<foxprox_runtime::RuntimeError> for CliError {
    fn from(error: foxprox_runtime::RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<foxprox_net::StackError> for CliError {
    fn from(error: foxprox_net::StackError) -> Self {
        Self::Stack(error)
    }
}

impl From<nix::Error> for CliError {
    fn from(error: nix::Error) -> Self {
        Self::Nix(error)
    }
}

impl LauncherArgs {
    fn default_setup_helper() -> Result<PathBuf, CliError> {
        let mut path = env::current_exe()?;
        path.set_file_name("foxproxsetup");
        Ok(path)
    }
}

pub fn parse_launcher_args(
    args: impl IntoIterator<Item = String>,
) -> Result<LauncherArgs, CliError> {
    let mut setup_helper = LauncherArgs::default_setup_helper()?;
    let mut sandbox_id =
        SandboxId::new("alpha").map_err(|error| CliError::Usage(error.to_string()))?;
    let mut tun_name = "foxprox0".to_string();
    let mut sandbox_ip: IpAddr = "10.255.0.2".parse().expect("static IP is valid");
    let mut broker_ip: IpAddr = "10.255.0.1".parse().expect("static IP is valid");
    let mut mtu = 1500_u16;
    let mut dns = broker_ip;
    let mut target = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                target.extend(iter);
                break;
            }
            "--setup-helper" => {
                setup_helper = PathBuf::from(next_value(&mut iter, "--setup-helper")?)
            }
            "--sandbox-id" => {
                sandbox_id = SandboxId::new(next_value(&mut iter, "--sandbox-id")?)
                    .map_err(|error| CliError::Usage(error.to_string()))?;
            }
            "--tun-name" => tun_name = next_value(&mut iter, "--tun-name")?,
            "--sandbox-ip" => sandbox_ip = parse_ip(next_value(&mut iter, "--sandbox-ip")?)?,
            "--broker-ip" => {
                broker_ip = parse_ip(next_value(&mut iter, "--broker-ip")?)?;
                dns = broker_ip;
            }
            "--dns" => dns = parse_ip(next_value(&mut iter, "--dns")?)?,
            "--mtu" => {
                mtu = next_value(&mut iter, "--mtu")?
                    .parse()
                    .map_err(|_| CliError::Usage("invalid --mtu".into()))?
            }
            "--help" | "-h" => return Err(CliError::Usage(launcher_usage())),
            value if value.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "unknown foxprox option: {value}\n{}",
                    launcher_usage()
                )))
            }
            value => {
                target.push(value.to_string());
                target.extend(iter);
                break;
            }
        }
    }

    if target.is_empty() {
        return Err(CliError::Usage(format!(
            "missing target command\n{}",
            launcher_usage()
        )));
    }

    Ok(LauncherArgs {
        setup_helper,
        target,
        sandbox_id,
        tun_name,
        sandbox_ip,
        broker_ip,
        mtu,
        dns,
        proxy: None,
    })
}

pub fn parse_setup_args(args: impl IntoIterator<Item = String>) -> Result<SetupArgs, CliError> {
    let mut tun_name = None;
    let mut sandbox_ip = None;
    let mut broker_ip = None;
    let mut mtu = None;
    let mut dns = None;
    let mut handoff_fd = None;
    let mut target = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                target.extend(iter);
                break;
            }
            "--tun-name" => tun_name = Some(next_value(&mut iter, "--tun-name")?),
            "--sandbox-ip" => sandbox_ip = Some(parse_ip(next_value(&mut iter, "--sandbox-ip")?)?),
            "--broker-ip" => broker_ip = Some(parse_ip(next_value(&mut iter, "--broker-ip")?)?),
            "--dns" => dns = Some(parse_ip(next_value(&mut iter, "--dns")?)?),
            "--mtu" => {
                mtu = Some(
                    next_value(&mut iter, "--mtu")?
                        .parse()
                        .map_err(|_| CliError::Usage("invalid --mtu".into()))?,
                )
            }
            "--handoff-fd" => {
                handoff_fd = Some(
                    next_value(&mut iter, "--handoff-fd")?
                        .parse()
                        .map_err(|_| CliError::Usage("invalid --handoff-fd".into()))?,
                )
            }
            "--help" | "-h" => return Err(CliError::Usage(setup_usage())),
            value => {
                return Err(CliError::Usage(format!(
                    "unknown foxproxsetup option: {value}\n{}",
                    setup_usage()
                )))
            }
        }
    }

    if target.is_empty() {
        return Err(CliError::Usage(format!(
            "missing target command\n{}",
            setup_usage()
        )));
    }

    Ok(SetupArgs {
        target,
        tun_name: tun_name.ok_or_else(|| CliError::Usage("missing --tun-name".into()))?,
        sandbox_ip: sandbox_ip.ok_or_else(|| CliError::Usage("missing --sandbox-ip".into()))?,
        broker_ip: broker_ip.ok_or_else(|| CliError::Usage("missing --broker-ip".into()))?,
        mtu: mtu.ok_or_else(|| CliError::Usage("missing --mtu".into()))?,
        dns: dns.ok_or_else(|| CliError::Usage("missing --dns".into()))?,
        handoff_fd: handoff_fd.ok_or_else(|| CliError::Usage("missing --handoff-fd".into()))?,
    })
}

fn next_value(iter: &mut impl Iterator<Item = String>, option: &str) -> Result<String, CliError> {
    iter.next()
        .ok_or_else(|| CliError::Usage(format!("missing value for {option}")))
}

fn parse_ip(value: String) -> Result<IpAddr, CliError> {
    value
        .parse()
        .map_err(|_| CliError::Usage(format!("invalid IP address: {value}")))
}

pub fn launcher_usage() -> String {
    "usage: foxprox [--setup-helper PATH] [--sandbox-id ID] [--tun-name NAME] [--sandbox-ip IP] [--broker-ip IP] [--dns IP] [--mtu MTU] -- COMMAND [ARGS...]".into()
}

pub fn setup_usage() -> String {
    "usage: foxproxsetup --tun-name NAME --sandbox-ip IP --broker-ip IP --dns IP --mtu MTU --handoff-fd FD -- COMMAND [ARGS...]".into()
}

pub fn request_from_launcher(args: &LauncherArgs) -> NetworkSetupRequest {
    NetworkSetupRequest {
        sandbox_id: args.sandbox_id.clone(),
        tun: TunDeviceConfig {
            name: args.tun_name.clone(),
            sandbox_ip: args.sandbox_ip,
            broker_ip: args.broker_ip,
            mtu: args.mtu,
        },
        broker_dns: args.dns,
        proxy: args.proxy.clone(),
    }
}

pub fn request_from_setup(args: &SetupArgs) -> NetworkSetupRequest {
    NetworkSetupRequest {
        sandbox_id: SandboxId::new("setup").expect("static sandbox id is valid"),
        tun: TunDeviceConfig {
            name: args.tun_name.clone(),
            sandbox_ip: args.sandbox_ip,
            broker_ip: args.broker_ip,
            mtu: args.mtu,
        },
        broker_dns: args.dns,
        proxy: None,
    }
}

#[cfg(target_os = "linux")]
pub fn run_launcher(args: LauncherArgs) -> Result<i32, CliError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;

    use foxprox_audit::JsonLineAuditSink;
    use foxprox_device::{PreopenedTunDevice, DEFAULT_ALPHA_MTU};
    use foxprox_egress::StdHostEgress;
    use foxprox_integrations::recv_tun_fd;
    use foxprox_net::DnsAttributionCache;
    use foxprox_policy::PolicyEngine;
    use foxprox_runtime::{
        run_stack_runtime_loop, BridgeMaintenanceBudget, StackRuntimeLoopConfig,
        StackRuntimeLoopStep, StackTcpBridgeTable, UdpBridgeTable,
    };
    use foxprox_smoltcp::{SmoltcpAdapterConfig, SmoltcpStackAdapter};

    let (host_socket, helper_socket) = UnixDatagram::pair()?;
    host_socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    make_inheritable(helper_socket.as_raw_fd())?;

    let mut child = spawn_bwrap(&args, helper_socket.as_raw_fd())?;
    drop(helper_socket);

    let tun_fd = match recv_tun_fd(&host_socket) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = child.kill();
            return Err(error.into());
        }
    };
    set_nonblocking(tun_fd)?;

    let mtu = usize::from(args.mtu).max(DEFAULT_ALPHA_MTU.min(usize::from(args.mtu)));
    let mut device = unsafe { PreopenedTunDevice::from_raw_fd(tun_fd, mtu)? };
    let ipv4_addr = match args.broker_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(CliError::Unsupported(
                "foxprox alpha launcher currently requires IPv4 broker IP".into(),
            ))
        }
    };
    let mut adapter = SmoltcpStackAdapter::new(
        SmoltcpAdapterConfig::new(
            args.sandbox_id.clone(),
            FrontendKind::Tun,
            ipv4_addr,
            24,
            mtu,
        )?
        .with_tcp_listener(80)
        .with_tcp_listener(443)
        .with_tcp_listener(8080)
        .with_tcp_listener(1080),
    )?;
    let policy = PolicyEngine::new(RuntimeConfig::allow_by_default());
    let mut egress = StdHostEgress;
    let mut audit = JsonLineAuditSink::new(std::io::stderr());
    let mut tcp_bridges = StackTcpBridgeTable::default();
    let mut udp_bridges = UdpBridgeTable::<UdpSocket>::default();
    let mut dns_cache = DnsAttributionCache::default();
    let mut sequence = 1_u64;
    let mut timestamp_millis = current_millis();
    let mut now_millis = 0_u64;

    loop {
        let outcome = run_stack_runtime_loop(
            &mut device,
            StackRuntimeLoopStep {
                adapter: &mut adapter,
                policy: &policy,
                egress: &mut egress,
                audit: &mut audit,
                tcp_bridges: &mut tcp_bridges,
                udp_bridges: &mut udp_bridges,
                dns_attribution: Some(foxprox_runtime::StackDnsAttribution {
                    cache: &mut dns_cache,
                    now: Instant::now(),
                }),
                config: StackRuntimeLoopConfig {
                    max_ticks: 64,
                    max_idle_ticks: Some(4),
                    tick_millis: 10,
                    max_tcp_read_bytes_per_stream: 16 * 1024,
                    max_udp_read_bytes_per_flow: 2048,
                    budget: BridgeMaintenanceBudget::default(),
                },
                sequence_start: sequence,
                timestamp_millis,
                now_millis,
            },
        )?;
        sequence = outcome.next_sequence;
        timestamp_millis = outcome.next_timestamp_millis;
        now_millis = outcome.next_now_millis;

        if let Some(status) = child.try_wait()? {
            return Ok(status.code().unwrap_or(1));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run_launcher(_args: LauncherArgs) -> Result<i32, CliError> {
    Err(CliError::Unsupported(
        "foxprox launcher currently requires Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
pub fn run_setup(args: SetupArgs) -> Result<(), CliError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixDatagram;
    use std::os::unix::process::CommandExt;

    use foxprox_device::PreopenedTunDevice;
    use foxprox_integrations::{
        drop_linux_setup_privileges, execute_tun_setup_plan, send_tun_fd, LinuxCapability,
        LinuxIpTunSetup, StdTunSetupExecutor,
    };

    let request = request_from_setup(&args);
    let plan = LinuxIpTunSetup::plan_commands(&request)?;
    let mut executor = StdTunSetupExecutor;
    execute_tun_setup_plan(&plan, &mut executor)?;

    let tun = PreopenedTunDevice::open_linux_tun(&args.tun_name, usize::from(args.mtu))?;
    let tun_file = tun.into_inner();
    let socket = unsafe { UnixDatagram::from_raw_fd(args.handoff_fd) };
    send_tun_fd(&socket, tun_file.as_raw_fd())?;
    drop(socket);
    drop(tun_file);

    drop_linux_setup_privileges(&[LinuxCapability::NetAdmin])?;
    let error = Command::new(&args.target[0]).args(&args.target[1..]).exec();
    Err(CliError::Integration(
        foxprox_integrations::IntegrationError::ExecFailed {
            program: args.target[0].clone(),
            reason: error.to_string(),
        },
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn run_setup(_args: SetupArgs) -> Result<(), CliError> {
    Err(CliError::Unsupported(
        "foxproxsetup currently requires Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
fn spawn_bwrap(args: &LauncherArgs, handoff_fd: i32) -> Result<Child, CliError> {
    let mut command = Command::new("bwrap");
    command.args([
        "--unshare-user",
        "--unshare-net",
        "--cap-add",
        "CAP_NET_ADMIN",
        "--dev-bind",
        "/",
        "/",
        "--tmpfs",
        "/etc",
        "--ro-bind-try",
        "/etc/ssl",
        "/etc/ssl",
        "--ro-bind-try",
        "/etc/hosts",
        "/etc/hosts",
        "--ro-bind-try",
        "/etc/nsswitch.conf",
        "/etc/nsswitch.conf",
        "--dev-bind",
        "/dev/net/tun",
        "/dev/net/tun",
    ]);
    command.arg(&args.setup_helper);
    command.args([
        "--tun-name",
        &args.tun_name,
        "--sandbox-ip",
        &args.sandbox_ip.to_string(),
        "--broker-ip",
        &args.broker_ip.to_string(),
        "--dns",
        &args.dns.to_string(),
        "--mtu",
        &args.mtu.to_string(),
        "--handoff-fd",
        &handoff_fd.to_string(),
        "--",
    ]);
    command.args(&args.target);
    command.spawn().map_err(CliError::Io)
}

#[cfg(target_os = "linux")]
fn make_inheritable(fd: i32) -> Result<(), CliError> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD)?);
    let mut updated = flags;
    updated.remove(FdFlag::FD_CLOEXEC);
    fcntl(fd, FcntlArg::F_SETFD(updated))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: i32) -> Result<(), CliError> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_launcher_target_after_separator() {
        let args = parse_launcher_args([
            "--sandbox-id".to_string(),
            "s1".to_string(),
            "--".to_string(),
            "curl".to_string(),
            "http://example.com".to_string(),
        ])
        .unwrap();

        assert_eq!(args.sandbox_id.as_str(), "s1");
        assert_eq!(args.target, vec!["curl", "http://example.com"]);
        assert_eq!(args.broker_ip, "10.255.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_setup_handoff_fd_and_target() {
        let args = parse_setup_args([
            "--tun-name".to_string(),
            "foxprox0".to_string(),
            "--sandbox-ip".to_string(),
            "10.255.0.2".to_string(),
            "--broker-ip".to_string(),
            "10.255.0.1".to_string(),
            "--dns".to_string(),
            "10.255.0.1".to_string(),
            "--mtu".to_string(),
            "1500".to_string(),
            "--handoff-fd".to_string(),
            "7".to_string(),
            "--".to_string(),
            "true".to_string(),
        ])
        .unwrap();

        assert_eq!(args.handoff_fd, 7);
        assert_eq!(args.target, vec!["true"]);
    }
}
