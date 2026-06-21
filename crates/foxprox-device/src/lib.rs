//! Linux device setup boundary for foxprox.
//!
//! This crate owns OS-facing TUN creation/configuration. Policy and audit code
//! must not import this crate. The public API validates plans before touching
//! the system and exposes command execution through a trait so setup behavior is
//! deterministic in tests.

#![deny(unsafe_op_in_unsafe_fn)]

use foxprox_integrations::{IntegrationError, TunDeviceConfig};
use std::fmt;
use std::io;
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceError {
    InvalidConfig(IntegrationError),
    InvalidTunName(TunNameError),
    Io {
        operation: &'static str,
        message: String,
    },
    CommandFailed {
        program: String,
        args: Vec<String>,
        status: Option<i32>,
        stderr: String,
    },
    UnsupportedPlatform,
}

impl From<IntegrationError> for DeviceError {
    fn from(error: IntegrationError) -> Self {
        Self::InvalidConfig(error)
    }
}

impl From<TunNameError> for DeviceError {
    fn from(error: TunNameError) -> Self {
        Self::InvalidTunName(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunNameError {
    Empty,
    ContainsNul,
    TooLong {
        max_bytes: usize,
        actual_bytes: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success() -> Self {
        Self {
            status: Some(0),
            stderr: String::new(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == Some(0)
    }
}

pub trait CommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<CommandOutput, DeviceError>;
}

#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<CommandOutput, DeviceError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| io_error("execute setup command", error))?;
        Ok(CommandOutput {
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn validate_tun_name(name: &str) -> Result<(), TunNameError> {
    const IFNAMSIZ: usize = 16;
    if name.is_empty() {
        return Err(TunNameError::Empty);
    }
    if name.as_bytes().contains(&0) {
        return Err(TunNameError::ContainsNul);
    }
    if name.len() >= IFNAMSIZ {
        return Err(TunNameError::TooLong {
            max_bytes: IFNAMSIZ - 1,
            actual_bytes: name.len(),
        });
    }
    Ok(())
}

/// Configure an already-created TUN interface in the current network namespace.
///
/// The alpha bwrap setup helper runs this inside the sandbox namespace after
/// creating the TUN fd. The command sequence uses point-to-point addressing so
/// the sandbox address and broker address are explicit and auditable.
pub fn configure_tun_interface<R: CommandRunner>(
    config: &TunDeviceConfig,
    runner: &mut R,
) -> Result<(), DeviceError> {
    config.validate()?;
    validate_tun_name(&config.name)?;

    run_checked(
        runner,
        "ip",
        vec![
            "addr".to_string(),
            "add".to_string(),
            config.sandbox_ip.to_string(),
            "peer".to_string(),
            config.broker_ip.to_string(),
            "dev".to_string(),
            config.name.clone(),
        ],
    )?;
    run_checked(
        runner,
        "ip",
        vec![
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            config.name.clone(),
            "mtu".to_string(),
            config.mtu.to_string(),
            "up".to_string(),
        ],
    )?;
    run_checked(
        runner,
        "ip",
        vec![
            "route".to_string(),
            "replace".to_string(),
            "default".to_string(),
            "dev".to_string(),
            config.name.clone(),
        ],
    )
}

fn run_checked<R: CommandRunner>(
    runner: &mut R,
    program: &str,
    args: Vec<String>,
) -> Result<(), DeviceError> {
    let output = runner.run(program, &args)?;
    if output.is_success() {
        return Ok(());
    }
    Err(DeviceError::CommandFailed {
        program: program.to_string(),
        args,
        status: output.status,
        stderr: output.stderr,
    })
}

fn io_error(operation: &'static str, error: io::Error) -> DeviceError {
    DeviceError::Io {
        operation,
        message: error.to_string(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{io_error, validate_tun_name, DeviceError};
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::raw::{c_int, c_short, c_ulong};

    const IFNAMSIZ: usize = 16;
    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;
    const TUNSETIFF: c_ulong = 0x4004_54ca;

    #[repr(C)]
    struct IfReq {
        name: [u8; IFNAMSIZ],
        flags: c_short,
        padding: [u8; 22],
    }

    unsafe extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    #[derive(Debug)]
    pub struct TunDevice {
        file: File,
        name: String,
    }

    impl TunDevice {
        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }

        pub fn into_file(self) -> File {
            self.file
        }
    }

    /// Create a TUN device in the current network namespace and retain its fd.
    ///
    /// # Safety boundary
    ///
    /// This safe wrapper contains the Linux `TUNSETIFF` ioctl. The interface
    /// name is validated to fit `ifreq.ifr_name`, the struct is fully
    /// initialized, and the fd is owned by `File` for automatic close-on-drop.
    pub fn create_tun(name: &str) -> Result<TunDevice, DeviceError> {
        validate_tun_name(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|error| io_error("open /dev/net/tun", error))?;

        let mut ifreq = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        ifreq.name[..name.len()].copy_from_slice(name.as_bytes());

        // SAFETY: `file` is a valid open fd for `/dev/net/tun`; `ifreq` points
        // to a live, initialized C-compatible buffer for the duration of the
        // ioctl; the validated name is NUL-terminated by the zeroed tail.
        let result = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifreq) };
        if result < 0 {
            return Err(io_error("ioctl TUNSETIFF", std::io::Error::last_os_error()));
        }

        Ok(TunDevice {
            file,
            name: name.to_string(),
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{create_tun, TunDevice};

#[cfg(not(target_os = "linux"))]
pub struct TunDevice;

#[cfg(not(target_os = "linux"))]
pub fn create_tun(_name: &str) -> Result<TunDevice, DeviceError> {
    Err(DeviceError::UnsupportedPlatform)
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DeviceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_integrations::TunDeviceConfig;
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Default)]
    struct FakeRunner {
        calls: Vec<(String, Vec<String>)>,
        fail_at: Option<usize>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<CommandOutput, DeviceError> {
            self.calls.push((program.to_string(), args.to_vec()));
            if self.fail_at == Some(self.calls.len()) {
                return Ok(CommandOutput {
                    status: Some(2),
                    stderr: "simulated failure".to_string(),
                });
            }
            Ok(CommandOutput::success())
        }
    }

    fn config() -> TunDeviceConfig {
        TunDeviceConfig {
            name: "foxprox0".to_string(),
            sandbox_ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
            broker_ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
            mtu: 1500,
        }
    }

    #[test]
    fn tun_name_must_fit_linux_ifreq() {
        assert_eq!(validate_tun_name(""), Err(TunNameError::Empty));
        assert_eq!(
            validate_tun_name("bad\0name"),
            Err(TunNameError::ContainsNul)
        );
        assert_eq!(
            validate_tun_name("sixteen-byte-iface"),
            Err(TunNameError::TooLong {
                max_bytes: 15,
                actual_bytes: 18,
            })
        );
    }

    #[test]
    fn configure_tun_runs_point_to_point_setup_sequence() {
        let mut runner = FakeRunner::default();
        configure_tun_interface(&config(), &mut runner).unwrap();

        assert_eq!(runner.calls.len(), 3);
        assert_eq!(
            runner.calls[0],
            (
                "ip".to_string(),
                vec![
                    "addr".to_string(),
                    "add".to_string(),
                    "10.66.0.2".to_string(),
                    "peer".to_string(),
                    "10.66.0.1".to_string(),
                    "dev".to_string(),
                    "foxprox0".to_string(),
                ]
            )
        );
        assert!(runner.calls[1]
            .1
            .windows(2)
            .any(|pair| pair == ["mtu", "1500"]));
        assert_eq!(
            runner.calls[2].1,
            vec!["route", "replace", "default", "dev", "foxprox0"]
        );
    }

    #[test]
    fn configure_tun_fails_before_commands_for_invalid_config() {
        let mut invalid = config();
        invalid.mtu = 128;
        let mut runner = FakeRunner::default();

        assert_eq!(
            configure_tun_interface(&invalid, &mut runner),
            Err(DeviceError::InvalidConfig(IntegrationError::MtuTooSmall {
                mtu: 128
            }))
        );
        assert!(runner.calls.is_empty());
    }

    #[test]
    fn configure_tun_stops_on_command_failure() {
        let mut runner = FakeRunner {
            fail_at: Some(2),
            ..FakeRunner::default()
        };

        let error = configure_tun_interface(&config(), &mut runner).unwrap_err();
        assert!(matches!(
            error,
            DeviceError::CommandFailed {
                status: Some(2),
                ..
            }
        ));
        assert_eq!(runner.calls.len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_tun_rejects_invalid_name_before_opening_device() {
        let error = create_tun("sixteen-byte-iface").unwrap_err();
        assert_eq!(
            error,
            DeviceError::InvalidTunName(TunNameError::TooLong {
                max_bytes: 15,
                actual_bytes: 18,
            })
        );
    }
}
