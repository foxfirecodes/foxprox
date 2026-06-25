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

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::{Path, PathBuf};

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

#[cfg(unix)]
#[derive(Debug)]
pub struct SetupControlSocket {
    broker: UnixStream,
    helper: UnixStream,
}

#[cfg(unix)]
#[derive(Debug)]
pub struct SetupControlSocketListener {
    listener: UnixListener,
    path: PathBuf,
}

#[cfg(unix)]
impl SetupControlSocket {
    pub fn pair() -> Result<Self, DeviceError> {
        let (broker, helper) = UnixStream::pair()
            .map_err(|error| io_error("create setup control socket pair", error))?;
        Ok(Self { broker, helper })
    }

    pub fn helper_fd(&self) -> RawFd {
        self.helper.as_raw_fd()
    }

    pub fn receive_file(&self) -> Result<File, DeviceError> {
        receive_file_from_socket_fd(self.broker.as_raw_fd())
    }
}

#[cfg(unix)]
impl SetupControlSocketListener {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, DeviceError> {
        let path = path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&path)
            .map_err(|error| io_error("bind setup control socket path", error))?;
        Ok(Self { listener, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn receive_file(&self) -> Result<File, DeviceError> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|error| io_error("accept setup control socket path", error))?;
        receive_file_from_socket_fd(stream.as_raw_fd())
    }
}

#[cfg(unix)]
impl Drop for SetupControlSocketListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn receive_file_from_socket_fd(socket_fd: RawFd) -> Result<File, DeviceError> {
    let fd = unix_fd_receive::recv_fd(socket_fd)
        .map_err(|error| io_error("receive TUN fd over setup control socket", error))?;
    // SAFETY: `recv_fd` returns a new descriptor owned by this process.
    Ok(unsafe { File::from_raw_fd(fd) })
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

#[cfg(unix)]
mod unix_fd_receive {
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::RawFd;
    use std::os::raw::{c_int, c_void};
    use std::ptr;

    const SOL_SOCKET: c_int = 1;
    const SCM_RIGHTS: c_int = 1;

    #[repr(C)]
    struct Iovec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    #[repr(C)]
    struct Msghdr {
        msg_name: *mut c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut c_void,
        msg_controllen: usize,
        msg_flags: c_int,
    }

    #[repr(C)]
    struct Cmsghdr {
        cmsg_len: usize,
        cmsg_level: c_int,
        cmsg_type: c_int,
    }

    unsafe extern "C" {
        fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
        #[cfg(test)]
        fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) -> isize;
    }

    const fn cmsg_align(len: usize) -> usize {
        let align = size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    const fn cmsg_len(data_len: usize) -> usize {
        cmsg_align(size_of::<Cmsghdr>()) + data_len
    }

    const fn cmsg_space(data_len: usize) -> usize {
        cmsg_align(size_of::<Cmsghdr>()) + cmsg_align(data_len)
    }

    pub fn recv_fd(socket_fd: RawFd) -> io::Result<RawFd> {
        let mut byte = [0u8];
        let mut iov = Iovec {
            iov_base: byte.as_mut_ptr().cast::<c_void>(),
            iov_len: byte.len(),
        };
        let control_len = cmsg_space(size_of::<RawFd>());
        let mut control = vec![0usize; control_len.div_ceil(size_of::<usize>())];
        let control_ptr = control.as_mut_ptr().cast::<u8>();

        // SAFETY: zeroed `msghdr` is immediately populated with valid pointers
        // to stack-owned buffers that outlive the `recvmsg` call.
        let mut message: Msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control_ptr.cast::<c_void>();
        message.msg_controllen = control_len;

        // SAFETY: `message` points to initialized receive buffers above. If the
        // socket fd is invalid, the kernel reports an error.
        let received = unsafe { recvmsg(socket_fd, &mut message, 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `recvmsg` initialized the aligned control buffer; validation
        // checks for an SCM_RIGHTS RawFd before reading it.
        unsafe {
            let header = control_ptr.cast::<Cmsghdr>();
            if (*header).cmsg_level != SOL_SOCKET || (*header).cmsg_type != SCM_RIGHTS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing SCM_RIGHTS control message",
                ));
            }
            if (*header).cmsg_len < cmsg_len(size_of::<RawFd>()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated SCM_RIGHTS control message",
                ));
            }
            let data = control_ptr
                .add(cmsg_align(size_of::<Cmsghdr>()))
                .cast::<RawFd>();
            Ok(ptr::read(data))
        }
    }

    #[cfg(test)]
    pub fn send_fd_for_test(socket_fd: RawFd, fd_to_send: RawFd) -> io::Result<()> {
        let mut byte = [0u8];
        let mut iov = Iovec {
            iov_base: byte.as_mut_ptr().cast::<c_void>(),
            iov_len: byte.len(),
        };
        let control_len = cmsg_space(size_of::<RawFd>());
        let mut control = vec![0usize; control_len.div_ceil(size_of::<usize>())];
        let control_ptr = control.as_mut_ptr().cast::<u8>();

        // SAFETY: `control` is aligned and large enough for one RawFd message.
        unsafe {
            let header = control_ptr.cast::<Cmsghdr>();
            ptr::write(
                header,
                Cmsghdr {
                    cmsg_len: cmsg_len(size_of::<RawFd>()),
                    cmsg_level: SOL_SOCKET,
                    cmsg_type: SCM_RIGHTS,
                },
            );
            let data = control_ptr
                .add(cmsg_align(size_of::<Cmsghdr>()))
                .cast::<RawFd>();
            ptr::write(data, fd_to_send);
        }

        // SAFETY: zeroed `msghdr` is immediately populated with valid pointers
        // to stack-owned buffers that outlive the `sendmsg` call.
        let mut message: Msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control_ptr.cast::<c_void>();
        message.msg_controllen = control_len;

        // SAFETY: `message` points to initialized send buffers above.
        let sent = unsafe { sendmsg(socket_fd, &message, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
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

    #[cfg(unix)]
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

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

    #[cfg(unix)]
    #[test]
    fn setup_control_socket_receives_handed_off_fd() {
        let control = SetupControlSocket::pair().unwrap();
        let (payload_tx, mut payload_rx) = UnixStream::pair().unwrap();

        unix_fd_receive::send_fd_for_test(control.helper_fd(), payload_tx.as_raw_fd()).unwrap();
        let mut received = control.receive_file().unwrap();
        received.write_all(b"ok").unwrap();

        let mut buf = [0u8; 2];
        payload_rx.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");
    }

    #[cfg(unix)]
    #[test]
    fn setup_control_socket_path_receives_handed_off_fd() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-handoff-{}-{}.sock",
            std::process::id(),
            "device-test"
        ));
        let control = SetupControlSocketListener::bind(&path).unwrap();
        let (payload_tx, mut payload_rx) = UnixStream::pair().unwrap();
        let sender_path = path.clone();
        let sender = std::thread::spawn(move || {
            let stream = UnixStream::connect(sender_path).unwrap();
            unix_fd_receive::send_fd_for_test(stream.as_raw_fd(), payload_tx.as_raw_fd()).unwrap();
        });

        let mut received = control.receive_file().unwrap();
        sender.join().unwrap();
        received.write_all(b"ok").unwrap();

        let mut buf = [0u8; 2];
        payload_rx.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");
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
    fn effective_cap_net_admin() -> bool {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        let Some(line) = status.lines().find(|line| line.starts_with("CapEff:\t")) else {
            return false;
        };
        let Some(hex) = line.split_whitespace().nth(1) else {
            return false;
        };
        let Ok(bits) = u64::from_str_radix(hex, 16) else {
            return false;
        };
        bits & (1 << 12) != 0
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_tun_create_smoke_runs_only_when_cap_net_admin_is_available() {
        if !std::path::Path::new("/dev/net/tun").exists() {
            eprintln!("skipping live TUN smoke: /dev/net/tun is not available");
            return;
        }
        if !effective_cap_net_admin() {
            eprintln!("skipping live TUN smoke: CAP_NET_ADMIN is not effective");
            return;
        }

        let _tun = create_tun("fpxsmoke0").unwrap();
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
