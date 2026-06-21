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
use std::net::IpAddr;
use std::os::fd::RawFd;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupArgs {
    pub sandbox_id: SandboxId,
    pub tun: TunDeviceConfig,
    pub dns_resolver: IpAddr,
    pub proxy_listener: Option<ProxyListenerConfig>,
    pub handoff_fd: RawFd,
    pub target: Vec<String>,
}

impl SetupArgs {
    pub fn setup_plan(&self) -> SetupPlan {
        SetupPlan {
            sandbox_id: self.sandbox_id.clone(),
            tun: self.tun.clone(),
            dns_resolver: self.dns_resolver,
            proxy_listener: self.proxy_listener.clone(),
            tun_handoff_fd: self.handoff_fd as u32,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    Parse(ParseError),
    InvalidPlan(IntegrationError),
    Device(DeviceError),
    Handoff(String),
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
        handoff_fd: handoff_fd.ok_or(ParseError::MissingRequired {
            field: "handoff-fd",
        })?,
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
    fn handoff_tun_fd(&mut self, handoff_fd: RawFd, tun_fd: RawFd) -> Result<(), SetupError>;
    fn exec_target(&mut self, target: &[String]) -> Result<(), SetupError>;
}

pub fn run_setup<B: SetupBackend>(args: &SetupArgs, backend: &mut B) -> Result<(), SetupError> {
    args.setup_plan().validate()?;
    let tun_fd = backend.create_tun(&args.tun.name)?;
    backend.configure_tun(&args.tun)?;
    backend.handoff_tun_fd(args.handoff_fd, tun_fd)?;
    backend.exec_target(&args.target)
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

    fn handoff_tun_fd(&mut self, handoff_fd: RawFd, tun_fd: RawFd) -> Result<(), SetupError> {
        send_fd(handoff_fd, tun_fd)?;
        self.tun.take();
        Ok(())
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

        fn handoff_tun_fd(&mut self, handoff_fd: RawFd, tun_fd: RawFd) -> Result<(), SetupError> {
            self.calls.push(format!("handoff:{handoff_fd}:{tun_fd}"));
            if self.fail_handoff {
                return Err(SetupError::Handoff("simulated".to_string()));
            }
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
        assert_eq!(parsed.handoff_fd, 3);
        assert_eq!(parsed.target, ["curl", "http://example.com"]);
        assert_eq!(parsed.proxy_listener.unwrap().http_port, Some(3128));
    }

    #[test]
    fn parser_requires_target_separator_and_handoff_fd() {
        let mut args = valid_args();
        args.retain(|arg| arg != "--handoff-fd" && arg != "3");
        assert_eq!(
            parse_setup_args(args),
            Err(ParseError::MissingRequired {
                field: "handoff-fd"
            })
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
                "handoff:3:9",
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
