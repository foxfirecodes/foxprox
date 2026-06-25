use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::process::Command;

const DEV_NET_TUN: &str = "/dev/net/tun";
const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunConfig {
    pub name: String,
}

impl TunConfig {
    pub fn new(name: impl Into<String>) -> Result<Self, CreateTunError> {
        let name = name.into();
        validate_interface_name(&name)?;
        Ok(Self { name })
    }
}

#[derive(Debug)]
pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[derive(Debug)]
pub enum CreateTunError {
    EmptyName,
    NameTooLong,
    InvalidName,
    Open(io::Error),
    Ioctl(io::Error),
}

impl PartialEq for CreateTunError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::EmptyName, Self::EmptyName)
                | (Self::NameTooLong, Self::NameTooLong)
                | (Self::InvalidName, Self::InvalidName)
                | (Self::Open(_), Self::Open(_))
                | (Self::Ioctl(_), Self::Ioctl(_))
        )
    }
}

impl Eq for CreateTunError {}

pub fn create_tun(config: &TunConfig) -> Result<TunDevice, CreateTunError> {
    validate_interface_name(&config.name)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEV_NET_TUN)
        .map_err(CreateTunError::Open)?;
    tun_set_iff(file.as_raw_fd(), &config.name)?;
    Ok(TunDevice {
        file,
        name: config.name.clone(),
    })
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 40 - IFNAMSIZ - std::mem::size_of::<libc::c_short>()],
}

fn tun_set_iff(fd: RawFd, name: &str) -> Result<(), CreateTunError> {
    let mut ifreq = IfReq {
        name: [0; IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        padding: [0; 40 - IFNAMSIZ - std::mem::size_of::<libc::c_short>()],
    };
    for (index, byte) in name.bytes().enumerate() {
        ifreq.name[index] = byte as libc::c_char;
    }

    // SAFETY: `fd` is an open `/dev/net/tun` descriptor owned by `file` above,
    // `ifreq` is a C-compatible buffer initialized with a NUL-terminated Linux
    // interface name and IFF_TUN/IFF_NO_PI flags, and the pointer remains valid
    // for the duration of the ioctl call.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifreq) };
    if rc < 0 {
        Err(CreateTunError::Ioctl(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn validate_interface_name(name: &str) -> Result<(), CreateTunError> {
    if name.is_empty() {
        return Err(CreateTunError::EmptyName);
    }
    if name.len() >= IFNAMSIZ {
        return Err(CreateTunError::NameTooLong);
    }
    if name.bytes().any(|byte| {
        byte == 0
            || byte == b'/'
            || byte.is_ascii_whitespace()
            || !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    }) {
        return Err(CreateTunError::InvalidName);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunSetup {
    pub name: String,
    pub address_cidr: String,
    pub route_cidr: String,
    pub mtu: u16,
}

impl TunSetup {
    pub fn new(
        name: impl Into<String>,
        address_cidr: impl Into<String>,
        route_cidr: impl Into<String>,
        mtu: u16,
    ) -> Result<Self, TunSetupError> {
        let setup = Self {
            name: name.into(),
            address_cidr: address_cidr.into(),
            route_cidr: route_cidr.into(),
            mtu,
        };
        setup.validate()?;
        Ok(setup)
    }

    fn validate(&self) -> Result<(), TunSetupError> {
        validate_interface_name(&self.name).map_err(|_| TunSetupError::InvalidInterfaceName)?;
        validate_ip_arg(&self.address_cidr)?;
        validate_ip_arg(&self.route_cidr)?;
        if self.mtu < 576 {
            return Err(TunSetupError::InvalidMtu);
        }
        Ok(())
    }

    pub fn commands(&self) -> Vec<Vec<OsString>> {
        vec![
            vec![
                "addr".into(),
                "add".into(),
                self.address_cidr.clone().into(),
                "dev".into(),
                self.name.clone().into(),
            ],
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                self.name.clone().into(),
                "mtu".into(),
                self.mtu.to_string().into(),
                "up".into(),
            ],
            vec![
                "route".into(),
                "add".into(),
                self.route_cidr.clone().into(),
                "dev".into(),
                self.name.clone().into(),
            ],
        ]
    }
}

#[derive(Debug)]
pub enum TunSetupError {
    InvalidInterfaceName,
    InvalidAddress,
    InvalidMtu,
    CommandFailed {
        args: Vec<OsString>,
        source: io::Error,
    },
    NonZeroExit {
        args: Vec<OsString>,
        code: Option<i32>,
    },
}

impl PartialEq for TunSetupError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::InvalidInterfaceName, Self::InvalidInterfaceName)
                | (Self::InvalidAddress, Self::InvalidAddress)
                | (Self::InvalidMtu, Self::InvalidMtu)
                | (Self::CommandFailed { .. }, Self::CommandFailed { .. })
                | (Self::NonZeroExit { .. }, Self::NonZeroExit { .. })
        )
    }
}

impl Eq for TunSetupError {}

fn validate_ip_arg(value: &str) -> Result<(), TunSetupError> {
    if value.is_empty()
        || value.contains('\0')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        Err(TunSetupError::InvalidAddress)
    } else {
        Ok(())
    }
}

pub trait CommandRunner {
    fn run_ip(&mut self, args: &[OsString]) -> Result<(), TunSetupError>;
}

#[derive(Default)]
pub struct IpCommandRunner;

impl CommandRunner for IpCommandRunner {
    fn run_ip(&mut self, args: &[OsString]) -> Result<(), TunSetupError> {
        let status = Command::new("ip").args(args).status().map_err(|source| {
            TunSetupError::CommandFailed {
                args: args.to_vec(),
                source,
            }
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(TunSetupError::NonZeroExit {
                args: args.to_vec(),
                code: status.code(),
            })
        }
    }
}

pub fn configure_tun_interface(
    setup: &TunSetup,
    runner: &mut impl CommandRunner,
) -> Result<(), TunSetupError> {
    setup.validate()?;
    for args in setup.commands() {
        runner.run_ip(&args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::process::Command;
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct RecordingRunner {
        calls: Vec<Vec<OsString>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run_ip(&mut self, args: &[OsString]) -> Result<(), TunSetupError> {
            self.calls.push(args.to_vec());
            Ok(())
        }
    }

    #[test]
    fn tun_config_rejects_invalid_interface_names() {
        assert_eq!(TunConfig::new(""), Err(CreateTunError::EmptyName));
        assert_eq!(
            TunConfig::new("0123456789abcdef"),
            Err(CreateTunError::NameTooLong)
        );
        assert_eq!(TunConfig::new("bad/name"), Err(CreateTunError::InvalidName));
        assert_eq!(TunConfig::new("bad name"), Err(CreateTunError::InvalidName));
        assert!(TunConfig::new("fp0").is_ok());
        assert!(TunConfig::new("foxprox-0").is_ok());
    }

    #[test]
    fn tun_setup_builds_deterministic_ip_commands() {
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1500).unwrap();
        let mut runner = RecordingRunner::default();

        configure_tun_interface(&setup, &mut runner).unwrap();

        assert_eq!(
            runner.calls,
            vec![
                vec!["addr", "add", "10.0.0.1/24", "dev", "fp0"],
                vec!["link", "set", "dev", "fp0", "mtu", "1500", "up"],
                vec!["route", "add", "0.0.0.0/0", "dev", "fp0"],
            ]
        );
    }

    #[test]
    fn tun_setup_rejects_ambiguous_ip_arguments_and_tiny_mtu() {
        assert_eq!(
            TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 575),
            Err(TunSetupError::InvalidMtu)
        );
        assert_eq!(
            TunSetup::new("fp0", "10.0.0.1/24\0", "0.0.0.0/0", 1500),
            Err(TunSetupError::InvalidAddress)
        );
        assert_eq!(
            TunSetup::new("fp0", "10.0.0.1/24", "bad route", 1500),
            Err(TunSetupError::InvalidAddress)
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn writes_policy_gated_icmp_reply_to_real_tun() {
        let config = TunConfig::new("fp0").unwrap();
        let mut device = create_tun(&config).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();
        set_nonblocking(device.raw_fd()).unwrap();

        let mut ping = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.0.0.2"])
            .spawn()
            .unwrap();
        let mut packet = [0_u8; 2048];
        let mut wrote_reply = false;
        for _ in 0..20 {
            match device.file.read(&mut packet) {
                Ok(n) if n > 0 => {
                    let outcome = foxprox_core::handle_tun_packet(
                        &packet[..n],
                        &foxprox_core::PolicyConfig {
                            allow_ping: true,
                            ..foxprox_core::PolicyConfig::default()
                        },
                        foxprox_core::TunPacketContext {
                            timestamp_millis: 1,
                            sandbox_id: foxprox_core::SandboxId::new("tun-e2e"),
                            dns_attribution: None,
                        },
                    );
                    if let foxprox_core::TunPacketOutcome::WriteBack {
                        response, audit, ..
                    } = outcome
                    {
                        assert_eq!(audit.decision, Some(foxprox_core::AuditDecision::Allow));
                        device.file.write_all(&response).unwrap();
                        wrote_reply = true;
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                other => panic!("unexpected TUN read result: {other:?}"),
            }
        }

        assert!(
            wrote_reply,
            "expected ping to produce an inbound TUN packet"
        );
        let status = ping.wait().unwrap();
        assert!(status.success(), "ping should receive the synthetic reply");
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn creates_and_configures_tun_in_network_namespace() {
        let config = TunConfig::new("fp0").unwrap();
        let mut device = create_tun(&config).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let output = Command::new("ip")
            .args(["addr", "show", "dev", "fp0"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("10.0.0.1/24"));
        assert!(text.contains("mtu 1300"));

        set_nonblocking(device.raw_fd()).unwrap();
        let mut ping = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.0.0.2"])
            .spawn()
            .unwrap();
        let mut packet = [0_u8; 2048];
        let mut observed = false;
        for _ in 0..20 {
            match device.file.read(&mut packet) {
                Ok(n) if n > 0 => {
                    observed = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                other => panic!("unexpected TUN read result: {other:?}"),
            }
        }
        let _ = ping.wait();
        assert!(observed, "expected ping to produce an inbound TUN packet");
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: `fd` is an open TUN file descriptor owned by the test device;
        // F_GETFL reads descriptor flags and does not mutate Rust-managed memory.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` remains open and F_SETFL updates kernel descriptor flags
        // only. The bit-or preserves existing flags while adding O_NONBLOCK.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
