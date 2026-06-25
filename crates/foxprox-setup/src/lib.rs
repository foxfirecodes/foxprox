//! `foxproxsetup` helper logic.
//!
//! The helper is intended to run as the initial bwrap command inside the sandbox
//! network namespace. It must fail before target exec if TUN creation,
//! configuration, fd handoff, or validation fails.

#![deny(unsafe_op_in_unsafe_fn)]

use foxprox_core::{SandboxId, ValidationError};
use foxprox_device::{configure_tun_interface, create_tun, DeviceError, SystemCommandRunner};
use foxprox_integrations::{IntegrationError, ProxyListenerConfig, SetupPlan, TunDeviceConfig};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupArgs {
    pub sandbox_id: SandboxId,
    pub tun: TunDeviceConfig,
    pub dns_resolver: IpAddr,
    pub proxy_listener: Option<ProxyListenerConfig>,
    pub handoff: SetupHandoff,
    pub target: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupHandoff {
    Fd(RawFd),
    UnixSocket(PathBuf),
}

impl SetupArgs {
    pub fn setup_plan(&self) -> SetupPlan {
        SetupPlan {
            sandbox_id: self.sandbox_id.clone(),
            tun: self.tun.clone(),
            dns_resolver: self.dns_resolver,
            proxy_listener: self.proxy_listener.clone(),
            tun_handoff_fd: match &self.handoff {
                SetupHandoff::Fd(fd) => *fd as u32,
                SetupHandoff::UnixSocket(_) => 0,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    Parse(ParseError),
    InvalidPlan(IntegrationError),
    Device(DeviceError),
    Handoff(String),
    DnsConfig(String),
    PrivilegeDrop(String),
    Exec(String),
}

impl From<ParseError> for SetupError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<IntegrationError> for SetupError {
    fn from(error: IntegrationError) -> Self {
        Self::InvalidPlan(error)
    }
}

impl From<DeviceError> for SetupError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    MissingValue { flag: String },
    UnknownFlag { flag: String },
    MissingRequired { field: &'static str },
    InvalidSandboxId(ValidationError),
    InvalidIp { flag: String, value: String },
    InvalidU16 { flag: String, value: String },
    InvalidFd { value: String },
    ConflictingHandoff,
    TargetMissing,
}

pub fn parse_setup_args<I, S>(args: I) -> Result<SetupArgs, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut sandbox_id = None;
    let mut tun_name = None;
    let mut sandbox_ip = None;
    let mut broker_ip = None;
    let mut mtu = None;
    let mut dns_resolver = None;
    let mut proxy_ip = None;
    let mut http_proxy_port = None;
    let mut socks_proxy_port = None;
    let mut handoff_fd = None;
    let mut handoff_socket = None;
    let mut target = Vec::new();

    let mut iter = args.into_iter().map(Into::into).peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            target.extend(iter);
            break;
        }
        match arg.as_str() {
            "--sandbox-id" => {
                let value = next_value(&arg, &mut iter)?;
                sandbox_id = Some(SandboxId::new(value).map_err(ParseError::InvalidSandboxId)?);
            }
            "--tun-name" => tun_name = Some(next_value(&arg, &mut iter)?),
            "--sandbox-ip" => sandbox_ip = Some(parse_ip(&arg, next_value(&arg, &mut iter)?)?),
            "--broker-ip" => broker_ip = Some(parse_ip(&arg, next_value(&arg, &mut iter)?)?),
            "--mtu" => mtu = Some(parse_u16(&arg, next_value(&arg, &mut iter)?)?),
            "--dns" => dns_resolver = Some(parse_ip(&arg, next_value(&arg, &mut iter)?)?),
            "--proxy-ip" => proxy_ip = Some(parse_ip(&arg, next_value(&arg, &mut iter)?)?),
            "--http-proxy-port" => {
                http_proxy_port = Some(parse_u16(&arg, next_value(&arg, &mut iter)?)?)
            }
            "--socks-proxy-port" => {
                socks_proxy_port = Some(parse_u16(&arg, next_value(&arg, &mut iter)?)?)
            }
            "--handoff-fd" => {
                let value = next_value(&arg, &mut iter)?;
                handoff_fd = Some(
                    value
                        .parse::<RawFd>()
                        .map_err(|_| ParseError::InvalidFd { value })?,
                );
            }
            "--handoff-socket" => {
                handoff_socket = Some(PathBuf::from(next_value(&arg, &mut iter)?));
            }
            flag if flag.starts_with('-') => {
                return Err(ParseError::UnknownFlag {
                    flag: flag.to_string(),
                });
            }
            other => {
                return Err(ParseError::UnknownFlag {
                    flag: other.to_string(),
                });
            }
        }
    }

    if target.is_empty() {
        return Err(ParseError::TargetMissing);
    }

    let proxy_listener = match (proxy_ip, http_proxy_port, socks_proxy_port) {
        (Some(ip), http_port, socks_port) => Some(ProxyListenerConfig {
            ip,
            http_port,
            socks_port,
        }),
        (None, None, None) => None,
        (None, Some(_), _) | (None, _, Some(_)) => {
            return Err(ParseError::MissingRequired { field: "proxy-ip" })
        }
    };

    Ok(SetupArgs {
        sandbox_id: sandbox_id.ok_or(ParseError::MissingRequired {
            field: "sandbox-id",
        })?,
        tun: TunDeviceConfig {
            name: tun_name.ok_or(ParseError::MissingRequired { field: "tun-name" })?,
            sandbox_ip: sandbox_ip.ok_or(ParseError::MissingRequired {
                field: "sandbox-ip",
            })?,
            broker_ip: broker_ip.ok_or(ParseError::MissingRequired { field: "broker-ip" })?,
            mtu: mtu.ok_or(ParseError::MissingRequired { field: "mtu" })?,
        },
        dns_resolver: dns_resolver.ok_or(ParseError::MissingRequired { field: "dns" })?,
        proxy_listener,
        handoff: match (handoff_fd, handoff_socket) {
            (Some(fd), None) => SetupHandoff::Fd(fd),
            (None, Some(path)) => SetupHandoff::UnixSocket(path),
            (Some(_), Some(_)) => return Err(ParseError::ConflictingHandoff),
            (None, None) => {
                return Err(ParseError::MissingRequired { field: "handoff" });
            }
        },
        target,
    })
}

fn next_value<I>(flag: &str, iter: &mut std::iter::Peekable<I>) -> Result<String, ParseError>
where
    I: Iterator<Item = String>,
{
    iter.next().ok_or_else(|| ParseError::MissingValue {
        flag: flag.to_string(),
    })
}

fn parse_ip(flag: &str, value: String) -> Result<IpAddr, ParseError> {
    value.parse().map_err(|_| ParseError::InvalidIp {
        flag: flag.to_string(),
        value,
    })
}

fn parse_u16(flag: &str, value: String) -> Result<u16, ParseError> {
    value.parse().map_err(|_| ParseError::InvalidU16 {
        flag: flag.to_string(),
        value,
    })
}

pub trait SetupBackend {
    fn create_tun(&mut self, name: &str) -> Result<RawFd, SetupError>;
    fn configure_tun(&mut self, config: &TunDeviceConfig) -> Result<(), SetupError>;
    fn configure_dns(&mut self, resolver: IpAddr) -> Result<(), SetupError>;
    fn handoff_tun_fd(&mut self, handoff_fd: RawFd, tun_fd: RawFd) -> Result<(), SetupError>;
    fn handoff_tun_socket(&mut self, path: &Path, tun_fd: RawFd) -> Result<(), SetupError>;
    fn drop_setup_privileges(&mut self) -> Result<(), SetupError>;
    fn exec_target(&mut self, target: &[String]) -> Result<(), SetupError>;
}

pub fn run_setup<B: SetupBackend>(args: &SetupArgs, backend: &mut B) -> Result<(), SetupError> {
    args.setup_plan().validate()?;
    let tun_fd = backend.create_tun(&args.tun.name)?;
    backend.configure_tun(&args.tun)?;
    backend.configure_dns(args.dns_resolver)?;
    match &args.handoff {
        SetupHandoff::Fd(fd) => backend.handoff_tun_fd(*fd, tun_fd)?,
        SetupHandoff::UnixSocket(path) => backend.handoff_tun_socket(path, tun_fd)?,
    }
    backend.drop_setup_privileges()?;
    backend.exec_target(&args.target)
}

pub fn write_resolver_config(path: &Path, resolver: IpAddr) -> Result<(), SetupError> {
    let contents = format!("# generated by foxproxsetup\nnameserver {resolver}\noptions ndots:0\n");
    fs::write(path, contents).map_err(|error| SetupError::DnsConfig(error.to_string()))
}

#[cfg(unix)]
pub struct RealSetupBackend {
    tun: Option<foxprox_device::TunDevice>,
}

#[cfg(unix)]
impl RealSetupBackend {
    pub fn new() -> Self {
        Self { tun: None }
    }
}

#[cfg(unix)]
impl Default for RealSetupBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl SetupBackend for RealSetupBackend {
    fn create_tun(&mut self, name: &str) -> Result<RawFd, SetupError> {
        let tun = create_tun(name)?;
        let fd = tun.as_raw_fd();
        self.tun = Some(tun);
        Ok(fd)
    }

    fn configure_tun(&mut self, config: &TunDeviceConfig) -> Result<(), SetupError> {
        configure_tun_interface(config, &mut SystemCommandRunner).map_err(SetupError::Device)
    }

    fn configure_dns(&mut self, resolver: IpAddr) -> Result<(), SetupError> {
        write_resolver_config(Path::new("/etc/resolv.conf"), resolver)
    }

    fn handoff_tun_fd(&mut self, handoff_fd: RawFd, tun_fd: RawFd) -> Result<(), SetupError> {
        send_fd(handoff_fd, tun_fd)?;
        self.tun.take();
        Ok(())
    }

    fn handoff_tun_socket(&mut self, path: &Path, tun_fd: RawFd) -> Result<(), SetupError> {
        send_fd_to_socket_path(path, tun_fd)?;
        self.tun.take();
        Ok(())
    }

    fn drop_setup_privileges(&mut self) -> Result<(), SetupError> {
        linux_privileges::drop_cap_net_admin()
            .map_err(|error| SetupError::PrivilegeDrop(error.to_string()))
    }

    fn exec_target(&mut self, target: &[String]) -> Result<(), SetupError> {
        use std::os::unix::process::CommandExt;
        let (program, args) = target
            .split_first()
            .ok_or(SetupError::Parse(ParseError::TargetMissing))?;
        let error = std::process::Command::new(program).args(args).exec();
        Err(SetupError::Exec(error.to_string()))
    }
}

#[cfg(unix)]
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<(), SetupError> {
    unix_fd_handoff::send_fd(socket_fd, fd_to_send)
        .map_err(|error| SetupError::Handoff(error.to_string()))
}

#[cfg(unix)]
fn send_fd_to_socket_path(path: &Path, fd_to_send: RawFd) -> Result<(), SetupError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let stream =
        UnixStream::connect(path).map_err(|error| SetupError::Handoff(error.to_string()))?;
    send_fd(stream.as_raw_fd(), fd_to_send)
}

#[cfg(target_os = "linux")]
mod linux_privileges {
    use std::io;
    use std::mem::zeroed;
    use std::os::raw::{c_int, c_ulong};

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_NET_ADMIN: usize = 12;
    const PR_CAPBSET_DROP: c_int = 24;
    const PR_CAP_AMBIENT: c_int = 47;
    const PR_CAP_AMBIENT_LOWER: c_ulong = 3;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    unsafe extern "C" {
        fn capget(header: *mut CapHeader, data: *mut CapData) -> c_int;
        fn capset(header: *mut CapHeader, data: *const CapData) -> c_int;
        fn prctl(
            option: c_int,
            arg2: c_ulong,
            arg3: c_ulong,
            arg4: c_ulong,
            arg5: c_ulong,
        ) -> c_int;
    }

    pub fn drop_cap_net_admin() -> io::Result<()> {
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: zeroed capability data is a valid output buffer for capget.
        let mut data: [CapData; 2] = unsafe { zeroed() };

        // SAFETY: header and data are valid pointers to initialized storage.
        if unsafe { capget(&mut header, data.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }

        clear_capability(&mut data, CAP_NET_ADMIN);

        // SAFETY: header and data are valid pointers; the data was obtained via
        // capget and only the CAP_NET_ADMIN bits were cleared.
        if unsafe { capset(&mut header, data.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Re-read and verify the target will not exec with CAP_NET_ADMIN in
        // any process capability set. This is the fail-closed invariant.
        // Rootless user namespaces can reject bounding/ambient prctl changes
        // even after capset succeeds, so those calls are best-effort below.
        // SAFETY: header and data are valid pointers to initialized storage.
        if unsafe { capget(&mut header, data.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if capability_present(&data, CAP_NET_ADMIN) {
            return Err(io::Error::other("CAP_NET_ADMIN remained after capset"));
        }

        // SAFETY: prctl is called with documented scalar arguments. Some
        // rootless user namespaces reject bounding-set changes with EPERM; this
        // is acceptable only after the verified capset removal above.
        let _ = unsafe { prctl(PR_CAPBSET_DROP, CAP_NET_ADMIN as c_ulong, 0, 0, 0) };

        // SAFETY: lowers CAP_NET_ADMIN from the ambient set when supported.
        // Kernels/user namespaces may return EINVAL/EPERM when the capability is
        // absent or ambient capabilities are unavailable; the verified capset
        // removal above remains the enforced invariant.
        let _ = unsafe {
            prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_LOWER,
                CAP_NET_ADMIN as c_ulong,
                0,
                0,
            )
        };

        Ok(())
    }

    fn clear_capability(data: &mut [CapData; 2], capability: usize) {
        let index = capability / 32;
        let mask = !(1u32 << (capability % 32));
        data[index].effective &= mask;
        data[index].permitted &= mask;
        data[index].inheritable &= mask;
    }

    fn capability_present(data: &[CapData; 2], capability: usize) -> bool {
        let index = capability / 32;
        let mask = 1u32 << (capability % 32);
        data[index].effective & mask != 0
            || data[index].permitted & mask != 0
            || data[index].inheritable & mask != 0
    }

    #[cfg(test)]
    mod tests {
        use super::{capability_present, clear_capability, CapData, CAP_NET_ADMIN};

        #[test]
        fn clears_cap_net_admin_from_all_sets() {
            let bit = 1u32 << CAP_NET_ADMIN;
            let mut data = [
                CapData {
                    effective: bit,
                    permitted: bit,
                    inheritable: bit,
                },
                CapData {
                    effective: u32::MAX,
                    permitted: u32::MAX,
                    inheritable: u32::MAX,
                },
            ];

            clear_capability(&mut data, CAP_NET_ADMIN);

            assert_eq!(data[0].effective & bit, 0);
            assert_eq!(data[0].permitted & bit, 0);
            assert_eq!(data[0].inheritable & bit, 0);
            assert_eq!(data[1].effective, u32::MAX);
            assert!(!capability_present(&data, CAP_NET_ADMIN));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux_privileges {
    use std::io;

    pub fn drop_cap_net_admin() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "CAP_NET_ADMIN drop is only implemented on Linux",
        ))
    }
}

#[cfg(unix)]
mod unix_fd_handoff {
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
        fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) -> isize;
        #[cfg(test)]
        fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
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

    pub fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> io::Result<()> {
        let mut byte = [0u8];
        let mut iov = Iovec {
            iov_base: byte.as_mut_ptr().cast::<c_void>(),
            iov_len: byte.len(),
        };
        let control_len = cmsg_space(size_of::<RawFd>());
        let mut control = vec![0usize; control_len.div_ceil(size_of::<usize>())];
        let control_ptr = control.as_mut_ptr().cast::<u8>();

        // SAFETY: `control` is usize-aligned and large enough for one
        // `cmsghdr` plus one RawFd before the kernel reads it through sendmsg.
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

        // SAFETY: `socket_fd` is provided by the launcher as an inherited Unix
        // domain socket, and `message` points to initialized buffers above. If
        // the fd is invalid, the kernel reports an error and setup fails closed.
        let sent = unsafe { sendmsg(socket_fd, &message, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    fn recv_fd(socket_fd: RawFd) -> io::Result<RawFd> {
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

        // SAFETY: `recvmsg` initialized the control buffer; validation below
        // checks that it contains a single SCM_RIGHTS RawFd before reading it.
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
    mod tests {
        use super::{recv_fd, send_fd};
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::net::UnixStream;

        #[test]
        fn fd_handoff_round_trips_over_unix_socket() {
            let (control_tx, control_rx) = UnixStream::pair().unwrap();
            let (payload_tx, mut payload_rx) = UnixStream::pair().unwrap();

            send_fd(control_tx.as_raw_fd(), payload_tx.as_raw_fd()).unwrap();
            let received_fd = recv_fd(control_rx.as_raw_fd()).unwrap();

            // SAFETY: `received_fd` is a fresh descriptor returned by recvmsg
            // and is owned by this test from this point forward.
            let mut received_stream = unsafe { UnixStream::from_raw_fd(received_fd) };
            received_stream.write_all(b"ok").unwrap();

            let mut buf = [0u8; 2];
            payload_rx.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ok");
        }
    }
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SetupError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        calls: Vec<String>,
        fail_handoff: bool,
    }

    impl SetupBackend for FakeBackend {
        fn create_tun(&mut self, name: &str) -> Result<RawFd, SetupError> {
            self.calls.push(format!("create:{name}"));
            Ok(9)
        }

        fn configure_tun(&mut self, config: &TunDeviceConfig) -> Result<(), SetupError> {
            self.calls.push(format!("configure:{}", config.name));
            Ok(())
        }

        fn configure_dns(&mut self, resolver: IpAddr) -> Result<(), SetupError> {
            self.calls.push(format!("dns:{resolver}"));
            Ok(())
        }

        fn handoff_tun_fd(&mut self, handoff_fd: RawFd, tun_fd: RawFd) -> Result<(), SetupError> {
            self.calls.push(format!("handoff:{handoff_fd}:{tun_fd}"));
            if self.fail_handoff {
                return Err(SetupError::Handoff("simulated".to_string()));
            }
            Ok(())
        }

        fn handoff_tun_socket(&mut self, path: &Path, tun_fd: RawFd) -> Result<(), SetupError> {
            self.calls
                .push(format!("handoff-socket:{}:{tun_fd}", path.display()));
            if self.fail_handoff {
                return Err(SetupError::Handoff("simulated".to_string()));
            }
            Ok(())
        }

        fn drop_setup_privileges(&mut self) -> Result<(), SetupError> {
            self.calls.push("drop-caps".to_string());
            Ok(())
        }

        fn exec_target(&mut self, target: &[String]) -> Result<(), SetupError> {
            self.calls.push(format!("exec:{}", target.join(" ")));
            Ok(())
        }
    }

    fn valid_args() -> Vec<String> {
        [
            "--sandbox-id",
            "setup-test",
            "--tun-name",
            "foxprox0",
            "--sandbox-ip",
            "10.66.0.2",
            "--broker-ip",
            "10.66.0.1",
            "--mtu",
            "1500",
            "--dns",
            "10.66.0.1",
            "--proxy-ip",
            "10.66.0.1",
            "--http-proxy-port",
            "3128",
            "--socks-proxy-port",
            "1080",
            "--handoff-fd",
            "3",
            "--",
            "curl",
            "http://example.com",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn parses_bwrap_planned_setup_arguments() {
        let parsed = parse_setup_args(valid_args()).unwrap();
        assert_eq!(parsed.sandbox_id.as_str(), "setup-test");
        assert_eq!(parsed.tun.name, "foxprox0");
        assert_eq!(parsed.handoff, SetupHandoff::Fd(3));
        assert_eq!(parsed.target, ["curl", "http://example.com"]);
        assert_eq!(parsed.proxy_listener.unwrap().http_port, Some(3128));
    }

    #[test]
    fn parses_socket_handoff_arguments_for_bwrap_without_fd_preservation() {
        let mut args = valid_args();
        args.retain(|arg| arg != "--handoff-fd" && arg != "3");
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        args.splice(
            separator..separator,
            [
                "--handoff-socket".to_string(),
                "/tmp/foxprox.sock".to_string(),
            ],
        );

        let parsed = parse_setup_args(args).unwrap();

        assert_eq!(
            parsed.handoff,
            SetupHandoff::UnixSocket(PathBuf::from("/tmp/foxprox.sock"))
        );
        assert_eq!(parsed.setup_plan().tun_handoff_fd, 0);
    }

    #[test]
    fn parser_rejects_conflicting_handoff_arguments() {
        let mut args = valid_args();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        args.splice(
            separator..separator,
            [
                "--handoff-socket".to_string(),
                "/tmp/foxprox.sock".to_string(),
            ],
        );

        assert_eq!(parse_setup_args(args), Err(ParseError::ConflictingHandoff));
    }

    #[test]
    fn parser_requires_target_separator_and_handoff_fd() {
        let mut args = valid_args();
        args.retain(|arg| arg != "--handoff-fd" && arg != "3");
        assert_eq!(
            parse_setup_args(args),
            Err(ParseError::MissingRequired { field: "handoff" })
        );
    }

    #[test]
    fn resolver_config_is_line_oriented_and_broker_controlled() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-resolv-{}-{}.conf",
            std::process::id(),
            "unit"
        ));
        write_resolver_config(&path, "10.66.0.1".parse().unwrap()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            contents,
            "# generated by foxproxsetup\nnameserver 10.66.0.1\noptions ndots:0\n"
        );
    }

    #[test]
    fn run_setup_orders_create_configure_handoff_before_exec() {
        let args = parse_setup_args(valid_args()).unwrap();
        let mut backend = FakeBackend::default();
        run_setup(&args, &mut backend).unwrap();

        assert_eq!(
            backend.calls,
            [
                "create:foxprox0",
                "configure:foxprox0",
                "dns:10.66.0.1",
                "handoff:3:9",
                "drop-caps",
                "exec:curl http://example.com"
            ]
        );
    }

    #[test]
    fn run_setup_can_handoff_to_socket_path_before_dropping_caps() {
        let mut args = valid_args();
        args.retain(|arg| arg != "--handoff-fd" && arg != "3");
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        args.splice(
            separator..separator,
            [
                "--handoff-socket".to_string(),
                "/tmp/foxprox.sock".to_string(),
            ],
        );
        let args = parse_setup_args(args).unwrap();
        let mut backend = FakeBackend::default();

        run_setup(&args, &mut backend).unwrap();

        assert_eq!(
            backend.calls,
            [
                "create:foxprox0",
                "configure:foxprox0",
                "dns:10.66.0.1",
                "handoff-socket:/tmp/foxprox.sock:9",
                "drop-caps",
                "exec:curl http://example.com"
            ]
        );
    }

    #[test]
    fn run_setup_does_not_exec_when_handoff_fails() {
        let args = parse_setup_args(valid_args()).unwrap();
        let mut backend = FakeBackend {
            fail_handoff: true,
            ..FakeBackend::default()
        };
        assert!(matches!(
            run_setup(&args, &mut backend),
            Err(SetupError::Handoff(_))
        ));
        assert_eq!(
            backend.calls.last().map(String::as_str),
            Some("handoff:3:9")
        );
    }
}
