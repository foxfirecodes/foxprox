//! User-facing runtime harnesses for foxprox.
//!
//! This crate intentionally starts with a narrow, testable command path:
//! process one IP packet using a TOML policy config and emit structured audit
//! JSON. It is a process-boundary proof for the future long-running TUN runtime.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::Command;

use foxprox_audit::{audit_record_to_json_line, AuditSinkError};
use foxprox_broker::IpPacketBroker;
use foxprox_config::{policy_config_from_toml, ConfigError};
use foxprox_core::{FrontendKind, PolicyEngine, SandboxId};
use foxprox_device::{TunIoError, TunPacketIo};
use foxprox_packet::PacketContext;

#[cfg(unix)]
use foxprox_integrations::{
    fd_handoff::{run_setup_sequence, SetupSequenceConfig, SetupSequenceError},
    ResolverConfig, TunInterfaceSetupConfig,
};

/// CLI/runtime errors reported to users.
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Io {
        context: String,
        error: io::Error,
    },
    Config(ConfigError),
    Core(String),
    Audit(AuditSinkError),
    Reply(String),
    TunIo(TunIoError),
    #[cfg(unix)]
    SetupSequence(SetupSequenceError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::Io { context, error } => write!(f, "{context}: {error}"),
            Self::Config(error) => write!(f, "{error}"),
            Self::Core(error) => write!(f, "{error}"),
            Self::Audit(error) => write!(f, "{error}"),
            Self::Reply(error) => write!(f, "packet-reply-error: {error}"),
            Self::TunIo(error) => write!(f, "{error}"),
            #[cfg(unix)]
            Self::SetupSequence(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::Config(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::TunIo(error) => Some(error),
            #[cfg(unix)]
            Self::SetupSequence(error) => Some(error),
            Self::Usage(_) | Self::Core(_) | Self::Reply(_) => None,
        }
    }
}

impl From<ConfigError> for CliError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<AuditSinkError> for CliError {
    fn from(value: AuditSinkError) -> Self {
        Self::Audit(value)
    }
}

impl From<TunIoError> for CliError {
    fn from(value: TunIoError) -> Self {
        Self::TunIo(value)
    }
}

#[cfg(unix)]
impl From<SetupSequenceError> for CliError {
    fn from(value: SetupSequenceError) -> Self {
        Self::SetupSequence(value)
    }
}

/// Result of one packet-once processing run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketOnceSummary {
    pub audit_json_line: String,
    pub outbound_packet_count: usize,
    pub outbound_byte_count: usize,
}

/// Parsed `foxproxsetup` command configuration.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupCommandConfig {
    pub broker_socket: PathBuf,
    pub tun_name: String,
    pub tun_device: PathBuf,
    pub address_cidr: String,
    pub mtu: u16,
    pub resolv_conf: PathBuf,
    pub broker_dns: IpAddr,
    pub ip_program: PathBuf,
    pub target_argv: Vec<String>,
}

#[cfg(unix)]
impl SetupCommandConfig {
    fn sequence_config(&self) -> SetupSequenceConfig {
        SetupSequenceConfig {
            interface: TunInterfaceSetupConfig::new(
                self.tun_name.clone(),
                self.address_cidr.clone(),
                self.mtu,
            )
            .with_ip_program(self.ip_program.clone()),
            resolver: ResolverConfig::new(self.resolv_conf.clone(), self.broker_dns),
        }
    }
}

/// Evidence returned after setup command work completes before target exec.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupCommandSummary {
    pub interface_name: String,
    pub resolver_path: PathBuf,
    pub target_argv: Vec<String>,
}

/// Process one packet using TOML policy configuration.
///
/// The returned JSON line is suitable for stdout. Any synthesized outbound
/// packet bytes are appended to `outbound`, allowing callers to write them to a
/// file or future TUN fd without mixing binary data into audit stdout.
pub fn process_packet_once(
    config_toml: &str,
    sandbox_id: &str,
    packet: &[u8],
    outbound: &mut Vec<u8>,
) -> Result<PacketOnceSummary, CliError> {
    let config = policy_config_from_toml(config_toml)?;
    let sandbox_id =
        SandboxId::new(sandbox_id).map_err(|error| CliError::Core(error.to_string()))?;
    let context = PacketContext::new(sandbox_id, FrontendKind::Tun);
    let broker = IpPacketBroker::new(PolicyEngine::new(config));
    let result = broker.process_packet(&context, packet);

    if let Some(error) = result.reply_error {
        return Err(CliError::Reply(error));
    }

    let outbound_packet_count = result.outbound_packets.len();
    let outbound_byte_count = result.outbound_packets.iter().map(Vec::len).sum::<usize>();
    for packet in result.outbound_packets {
        outbound.extend_from_slice(&packet);
    }

    Ok(PacketOnceSummary {
        audit_json_line: audit_record_to_json_line(&result.evaluation.audit)?,
        outbound_packet_count,
        outbound_byte_count,
    })
}

/// Process one packet directly from a TUN-like fd and write synthesized replies
/// back to the same fd.
pub fn process_tun_io_once(
    config_toml: &str,
    sandbox_id: &str,
    tun: &mut TunPacketIo,
) -> Result<PacketOnceSummary, CliError> {
    process_tun_io_packets(config_toml, sandbox_id, tun, 1).and_then(|mut summaries| {
        summaries
            .pop()
            .ok_or_else(|| CliError::Core("tun-io-no-packet-read".to_owned()))
    })
}

/// Process up to `packet_limit` packets from a TUN-like fd.
pub fn process_tun_io_packets(
    config_toml: &str,
    sandbox_id: &str,
    tun: &mut TunPacketIo,
    packet_limit: usize,
) -> Result<Vec<PacketOnceSummary>, CliError> {
    let mut summaries = Vec::new();
    for _ in 0..packet_limit {
        let packet = tun.read_packet()?;
        if packet.is_empty() {
            break;
        }
        let mut outbound = Vec::new();
        let summary = process_packet_once(config_toml, sandbox_id, &packet, &mut outbound)?;
        if !outbound.is_empty() {
            tun.write_packet(&outbound)?;
        }
        summaries.push(summary);
    }
    Ok(summaries)
}

/// Run setup command work with an already-created TUN-like fd.
#[cfg(unix)]
pub fn run_setup_command_with_existing_fd(
    config: &SetupCommandConfig,
    setup_fd: RawFd,
) -> Result<SetupCommandSummary, CliError> {
    let broker_socket =
        UnixStream::connect(&config.broker_socket).map_err(|error| CliError::Io {
            context: format!("connect-broker-socket {}", config.broker_socket.display()),
            error,
        })?;
    let result = run_setup_sequence(&broker_socket, setup_fd, &config.sequence_config())?;
    Ok(SetupCommandSummary {
        interface_name: result.interface_name,
        resolver_path: result.resolver_path,
        target_argv: config.target_argv.clone(),
    })
}

/// Run the production Linux setup command path, then exec the target process.
#[cfg(all(unix, target_os = "linux"))]
pub fn run_linux_setup_command(config: &SetupCommandConfig) -> Result<(), CliError> {
    let tun = foxprox_device::create_tun(
        &foxprox_device::TunCreateConfig::new(config.tun_name.clone())
            .with_device_path(config.tun_device.clone()),
    )
    .map_err(|error| CliError::Core(error.to_string()))?;
    run_setup_command_with_existing_fd(config, tun.fd.as_raw_fd())?;
    drop(tun);
    exec_setup_target(&config.target_argv)
}

#[cfg(unix)]
fn exec_setup_target(target_argv: &[String]) -> Result<(), CliError> {
    let Some(program) = target_argv.first() else {
        return Err(CliError::Usage(setup_usage_text().to_owned()));
    };
    if program.trim().is_empty() {
        return Err(CliError::Usage(setup_usage_text().to_owned()));
    }
    let error = Command::new(program).args(&target_argv[1..]).exec();
    Err(CliError::Io {
        context: format!("exec-target {program}"),
        error,
    })
}

/// Execute a command using process stdin/stdout semantics.
pub fn run_from_env() -> Result<(), CliError> {
    run_with_args(std::env::args_os().map(PathBuf::from))
}

/// Execute the standalone `foxproxsetup` helper.
pub fn run_foxproxsetup_from_env() -> Result<(), CliError> {
    #[cfg(all(unix, target_os = "linux"))]
    {
        let mut args = std::env::args_os().map(PathBuf::from);
        let _program = args.next();
        let config = parse_setup_args(args)?;
        run_linux_setup_command(&config)
    }
    #[cfg(not(all(unix, target_os = "linux")))]
    {
        Err(CliError::Usage(
            "foxproxsetup is only supported on Linux".to_owned(),
        ))
    }
}

fn run_with_args<I>(mut args: I) -> Result<(), CliError>
where
    I: Iterator<Item = PathBuf>,
{
    let _program = args.next();
    let Some(command) = args.next() else {
        return Err(usage());
    };
    if command.as_os_str() == "packet-once" {
        return run_packet_once_args(args);
    }
    if command.as_os_str() == "setup" {
        #[cfg(all(unix, target_os = "linux"))]
        {
            let config = parse_setup_args(args)?;
            return run_linux_setup_command(&config);
        }
        #[cfg(not(all(unix, target_os = "linux")))]
        {
            return Err(CliError::Usage(
                "setup command is only supported on Linux".to_owned(),
            ));
        }
    }
    Err(usage())
}

#[cfg(unix)]
fn parse_setup_args<I>(mut args: I) -> Result<SetupCommandConfig, CliError>
where
    I: Iterator<Item = PathBuf>,
{
    let mut broker_socket = None;
    let mut tun_name = None;
    let mut tun_device = PathBuf::from("/dev/net/tun");
    let mut address_cidr = None;
    let mut mtu = None;
    let mut resolv_conf = None;
    let mut broker_dns = None;
    let mut ip_program = PathBuf::from("ip");
    let mut target_argv = Vec::new();

    while let Some(flag) = args.next() {
        if flag.as_os_str() == "--" {
            target_argv.extend(args.map(|value| value.to_string_lossy().into_owned()));
            break;
        }
        match flag.to_string_lossy().as_ref() {
            "--broker-socket" => broker_socket = args.next(),
            "--tun-name" => tun_name = args.next().map(path_to_string),
            "--tun-device" => {
                tun_device = args.next().ok_or_else(setup_usage)?.to_path_buf();
            }
            "--address-cidr" => address_cidr = args.next().map(path_to_string),
            "--mtu" => {
                let value = args.next().ok_or_else(setup_usage)?;
                mtu = Some(parse_u16_arg("--mtu", &value)?);
            }
            "--resolv-conf" => resolv_conf = args.next(),
            "--broker-dns" => {
                let value = args.next().ok_or_else(setup_usage)?;
                broker_dns = Some(parse_ip_arg("--broker-dns", &value)?);
            }
            "--ip-program" => {
                ip_program = args.next().ok_or_else(setup_usage)?.to_path_buf();
            }
            _ => return Err(setup_usage()),
        }
    }

    if target_argv.is_empty() || target_argv[0].trim().is_empty() {
        return Err(setup_usage());
    }

    Ok(SetupCommandConfig {
        broker_socket: broker_socket.ok_or_else(setup_usage)?,
        tun_name: tun_name.ok_or_else(setup_usage)?,
        tun_device,
        address_cidr: address_cidr.ok_or_else(setup_usage)?,
        mtu: mtu.ok_or_else(setup_usage)?,
        resolv_conf: resolv_conf.ok_or_else(setup_usage)?,
        broker_dns: broker_dns.ok_or_else(setup_usage)?,
        ip_program,
        target_argv,
    })
}

#[cfg(unix)]
fn path_to_string(value: PathBuf) -> String {
    value.to_string_lossy().into_owned()
}

#[cfg(unix)]
fn parse_u16_arg(flag: &str, value: &Path) -> Result<u16, CliError> {
    value
        .to_string_lossy()
        .parse::<u16>()
        .map_err(|error| CliError::Usage(format!("invalid {flag}: {error}")))
}

#[cfg(unix)]
fn parse_ip_arg(flag: &str, value: &Path) -> Result<IpAddr, CliError> {
    value
        .to_string_lossy()
        .parse::<IpAddr>()
        .map_err(|error| CliError::Usage(format!("invalid {flag}: {error}")))
}

#[cfg(unix)]
fn setup_usage() -> CliError {
    CliError::Usage(setup_usage_text().to_owned())
}

#[cfg(unix)]
fn setup_usage_text() -> &'static str {
    "usage: foxproxsetup --broker-socket PATH --tun-name NAME --address-cidr CIDR --mtu MTU --resolv-conf PATH --broker-dns IP [--tun-device PATH] [--ip-program PATH] -- TARGET [ARGS...]"
}

fn run_packet_once_args<I>(mut args: I) -> Result<(), CliError>
where
    I: Iterator<Item = PathBuf>,
{
    let mut config_path = None;
    let mut sandbox_id = None;
    let mut outbound_path = None;

    while let Some(flag) = args.next() {
        match flag.to_string_lossy().as_ref() {
            "--config" => config_path = args.next(),
            "--sandbox" => {
                sandbox_id = args
                    .next()
                    .map(|value| value.to_string_lossy().into_owned())
            }
            "--outbound" => outbound_path = args.next(),
            _ => return Err(usage()),
        }
    }

    let config_path = config_path.ok_or_else(usage)?;
    let sandbox_id = sandbox_id.ok_or_else(usage)?;
    run_packet_once_command(&config_path, &sandbox_id, outbound_path.as_deref())
}

fn run_packet_once_command(
    config_path: &Path,
    sandbox_id: &str,
    outbound_path: Option<&Path>,
) -> Result<(), CliError> {
    let config = fs::read_to_string(config_path).map_err(|error| CliError::Io {
        context: format!("read-config {}", config_path.display()),
        error,
    })?;
    let mut packet = Vec::new();
    io::stdin()
        .read_to_end(&mut packet)
        .map_err(|error| CliError::Io {
            context: "read-stdin-packet".to_owned(),
            error,
        })?;

    let mut outbound = Vec::new();
    let summary = process_packet_once(&config, sandbox_id, &packet, &mut outbound)?;
    io::stdout()
        .write_all(summary.audit_json_line.as_bytes())
        .map_err(|error| CliError::Io {
            context: "write-audit-stdout".to_owned(),
            error,
        })?;

    if let Some(path) = outbound_path {
        fs::write(path, outbound).map_err(|error| CliError::Io {
            context: format!("write-outbound {}", path.display()),
            error,
        })?;
    }

    Ok(())
}

fn usage() -> CliError {
    CliError::Usage(
        "usage: foxprox-cli packet-once --config <policy.toml> --sandbox <id> [--outbound <packet.bin>] < packet.bin\n       foxprox-cli setup --broker-socket PATH --tun-name NAME --address-cidr CIDR --mtu MTU --resolv-conf PATH --broker-dns IP [--tun-device PATH] [--ip-program PATH] -- TARGET [ARGS...]"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_length = 20 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn echo_request_packet() -> Vec<u8> {
        ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            b"\x08\x00\x00\x00\x12\x34\x00\x01payload",
        )
    }

    fn icmpv6_destination_unreachable_packet() -> Vec<u8> {
        let payload = [1, 0, 0, 0, 0, 0, 0, 0];
        let mut packet = vec![0_u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        packet[24..40]
            .copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[40..].copy_from_slice(&payload);
        packet
    }

    #[test]
    fn tun_io_once_reads_packet_emits_audit_and_writes_reply_to_fd() {
        use std::io::{Read, Write};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let (mut peer, broker_side) = UnixStream::pair().unwrap();
        let owned: OwnedFd = broker_side.into();
        let mut tun = TunPacketIo::from_owned_fd(owned, 4096).unwrap();
        let packet = echo_request_packet();
        peer.write_all(&packet).unwrap();

        let summary = process_tun_io_once(
            r#"
            default_policy = "deny"

            [icmp]
            allow_echo = true
            "#,
            "tun-io-test",
            &mut tun,
        )
        .unwrap();

        let mut reply = vec![0_u8; packet.len()];
        peer.read_exact(&mut reply).unwrap();
        let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();
        assert_eq!(audit["kind"], "icmp_message");
        assert_eq!(audit["decision"], "allowed");
        assert_eq!(summary.outbound_packet_count, 1);
        assert_eq!(summary.outbound_byte_count, packet.len());
        assert_eq!(reply[20], 0);
    }

    #[test]
    fn tun_io_packet_loop_processes_multiple_datagrams_with_audit_and_replies() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;

        let (peer, broker_side) = UnixDatagram::pair().unwrap();
        let owned: OwnedFd = broker_side.into();
        let mut tun = TunPacketIo::from_owned_fd(owned, 4096).unwrap();
        let packet = echo_request_packet();
        peer.send(&packet).unwrap();
        peer.send(&packet).unwrap();

        let summaries = process_tun_io_packets(
            r#"
            default_policy = "deny"

            [icmp]
            allow_echo = true
            "#,
            "tun-loop-test",
            &mut tun,
            2,
        )
        .unwrap();

        assert_eq!(summaries.len(), 2);
        for summary in &summaries {
            let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();
            assert_eq!(audit["kind"], "icmp_message");
            assert_eq!(audit["decision"], "allowed");
            assert_eq!(summary.outbound_packet_count, 1);
        }
        for _ in 0..2 {
            let mut reply = vec![0_u8; packet.len()];
            let length = peer.recv(&mut reply).unwrap();
            reply.truncate(length);
            assert_eq!(reply.len(), packet.len());
            assert_eq!(reply[20], 0);
        }
    }

    #[cfg(unix)]
    fn unique_test_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "foxprox-cli-{prefix}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn write_fake_ip_program(dir: &Path, log: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let program = dir.join("ip");
        std::fs::write(
            &program,
            format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();
        program
    }

    #[cfg(unix)]
    #[test]
    fn setup_command_configures_network_writes_resolver_and_hands_fd_to_broker() {
        use foxprox_device::TunPacketIo;
        use foxprox_integrations::fd_handoff::receive_setup_fd;
        use std::io::{Read, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::thread;

        let dir = unique_test_dir("setup-command");
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("broker.sock");
        let ip_log = dir.join("ip.log");
        let ip_program = write_fake_ip_program(&dir, &ip_log);
        let resolv_conf = dir.join("resolv.conf");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let broker_thread = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            receive_setup_fd(&socket).unwrap()
        });
        let (mut peer, setup_fd) = UnixStream::pair().unwrap();
        let config = SetupCommandConfig {
            broker_socket: socket_path,
            tun_name: "foxprox0".to_owned(),
            tun_device: PathBuf::from("/dev/net/tun"),
            address_cidr: "10.0.0.2/24".to_owned(),
            mtu: 1500,
            resolv_conf: resolv_conf.clone(),
            broker_dns: "10.0.0.1".parse().unwrap(),
            ip_program,
            target_argv: vec!["/bin/true".to_owned()],
        };

        let summary = run_setup_command_with_existing_fd(&config, setup_fd.as_raw_fd()).unwrap();
        drop(setup_fd);
        let received = broker_thread.join().unwrap();
        assert_eq!(received.marker, b"foxprox-fd".to_vec());
        assert_eq!(summary.interface_name, "foxprox0");
        assert_eq!(summary.resolver_path, resolv_conf);
        assert_eq!(summary.target_argv, vec!["/bin/true".to_owned()]);
        assert_eq!(
            std::fs::read_to_string(&summary.resolver_path).unwrap(),
            "# generated by foxproxsetup\nnameserver 10.0.0.1\noptions ndots:0\n"
        );
        assert_eq!(
            std::fs::read_to_string(&ip_log).unwrap(),
            "link set dev foxprox0 mtu 1500 up\naddr add 10.0.0.2/24 dev foxprox0\nroute add default dev foxprox0\n"
        );

        let mut broker_tun = TunPacketIo::from_owned_fd(received.fd, 64).unwrap();
        peer.write_all(b"packet-from-sandbox").unwrap();
        assert_eq!(broker_tun.read_packet().unwrap(), b"packet-from-sandbox");
        broker_tun.write_packet(b"packet-to-sandbox").unwrap();
        let mut reply = [0_u8; 17];
        peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"packet-to-sandbox");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn setup_arg_parser_accepts_documented_foxproxsetup_shape() {
        let config = parse_setup_args(
            [
                "--broker-socket",
                "/tmp/broker.sock",
                "--tun-name",
                "foxprox0",
                "--tun-device",
                "/tmp/not-real-tun",
                "--address-cidr",
                "10.0.0.2/24",
                "--mtu",
                "1400",
                "--resolv-conf",
                "/tmp/resolv.conf",
                "--broker-dns",
                "10.0.0.1",
                "--ip-program",
                "/sbin/ip",
                "--",
                "curl",
                "http://example.com",
            ]
            .into_iter()
            .map(PathBuf::from),
        )
        .unwrap();

        assert_eq!(config.broker_socket, PathBuf::from("/tmp/broker.sock"));
        assert_eq!(config.tun_name, "foxprox0");
        assert_eq!(config.tun_device, PathBuf::from("/tmp/not-real-tun"));
        assert_eq!(config.address_cidr, "10.0.0.2/24");
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.resolv_conf, PathBuf::from("/tmp/resolv.conf"));
        assert_eq!(config.broker_dns, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.ip_program, PathBuf::from("/sbin/ip"));
        assert_eq!(
            config.target_argv,
            vec!["curl".to_owned(), "http://example.com".to_owned()]
        );
    }

    #[test]
    fn packet_once_loads_config_and_emits_allowed_audit_with_reply_bytes() {
        let config = r#"
            default_policy = "deny"

            [[rules]]
            id = "allow-icmp"
            action = "allow"
            protocol = "icmp"
            "#;
        let mut outbound = Vec::new();

        let summary =
            process_packet_once(config, "cli-test", &echo_request_packet(), &mut outbound)
                .expect("packet-once succeeds");
        let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();

        assert_eq!(audit["sandbox_id"], "cli-test");
        assert_eq!(audit["protocol"], "icmp");
        assert_eq!(audit["decision"], "allowed");
        assert_eq!(audit["rule_id"], "allow-icmp");
        assert_eq!(summary.outbound_packet_count, 1);
        assert_eq!(summary.outbound_byte_count, outbound.len());
        assert!(!outbound.is_empty());
    }

    #[test]
    fn packet_once_default_deny_emits_audit_without_reply_bytes() {
        let mut outbound = Vec::new();

        let summary = process_packet_once("", "cli-test", &echo_request_packet(), &mut outbound)
            .expect("default-deny packet-once succeeds");
        let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();

        assert_eq!(audit["decision"], "denied");
        assert_eq!(audit["reason"], "icmp-default-deny");
        assert_eq!(summary.outbound_packet_count, 0);
        assert_eq!(summary.outbound_byte_count, 0);
        assert!(outbound.is_empty());
    }

    #[test]
    fn packet_once_dispatches_ipv6_packet_to_policy_audit_without_reply_bytes() {
        let mut outbound = Vec::new();

        let summary = process_packet_once(
            "",
            "cli-test",
            &icmpv6_destination_unreachable_packet(),
            &mut outbound,
        )
        .expect("IPv6 packet-once succeeds");
        let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();

        assert_eq!(audit["sandbox_id"], "cli-test");
        assert_eq!(audit["protocol"], "icmp");
        assert_eq!(audit["decision"], "allowed");
        assert_eq!(audit["source"]["ip"], "::1");
        assert_eq!(summary.outbound_packet_count, 0);
        assert_eq!(summary.outbound_byte_count, 0);
        assert!(outbound.is_empty());
    }

    #[test]
    fn packet_once_rejects_empty_sandbox_id() {
        let mut outbound = Vec::new();
        let error = process_packet_once("", "  ", &echo_request_packet(), &mut outbound)
            .expect_err("empty sandbox id is invalid");

        assert_eq!(error.to_string(), "sandbox id must not be empty");
    }
}
