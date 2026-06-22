//! Integration backend helpers for foxprox.
//!
//! This crate owns launcher/setup command contracts such as the bwrap-compatible
//! `foxproxsetup` wrapper shape. It does not execute commands or import broker
//! core internals.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Proxy listener addresses that callers can inject into the sandbox process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEnvironment {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub all_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

impl ProxyEnvironment {
    pub fn none() -> Self {
        Self {
            http_proxy: None,
            https_proxy: None,
            all_proxy: None,
            no_proxy: None,
        }
    }

    pub fn loopback_http_socks(
        http_addr: impl Into<String>,
        socks_addr: impl Into<String>,
    ) -> Self {
        let http_addr = http_addr.into();
        let socks_addr = socks_addr.into();
        Self {
            http_proxy: Some(format!("http://{http_addr}")),
            https_proxy: Some(format!("http://{http_addr}")),
            all_proxy: Some(format!("socks5://{socks_addr}")),
            no_proxy: Some("localhost,127.0.0.1,::1".to_owned()),
        }
    }

    fn append_bwrap_env_args(&self, args: &mut Vec<String>) {
        for (name, value) in [
            ("HTTP_PROXY", self.http_proxy.as_ref()),
            ("HTTPS_PROXY", self.https_proxy.as_ref()),
            ("ALL_PROXY", self.all_proxy.as_ref()),
            ("NO_PROXY", self.no_proxy.as_ref()),
        ] {
            if let Some(value) = value {
                args.push("--setenv".to_owned());
                args.push(name.to_owned());
                args.push(value.clone());
            }
        }
    }
}

/// Inputs for a bwrap-compatible foxprox network setup launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwrapSetupConfig {
    pub bwrap_program: PathBuf,
    pub setup_program: PathBuf,
    pub target_argv: Vec<String>,
    pub proxy_environment: ProxyEnvironment,
}

impl BwrapSetupConfig {
    pub fn new(
        bwrap_program: impl Into<PathBuf>,
        setup_program: impl Into<PathBuf>,
        target_argv: Vec<String>,
    ) -> Self {
        Self {
            bwrap_program: bwrap_program.into(),
            setup_program: setup_program.into(),
            target_argv,
            proxy_environment: ProxyEnvironment::none(),
        }
    }

    pub fn with_proxy_environment(mut self, proxy_environment: ProxyEnvironment) -> Self {
        self.proxy_environment = proxy_environment;
        self
    }
}

/// A validated command plan. `program` is executed with `args` by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl CommandPlan {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.display().to_string());
        argv.extend(self.args.clone());
        argv
    }
}

/// Integration planning errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrationPlanError {
    EmptyProgram { field: &'static str },
    EmptyTarget,
}

impl fmt::Display for IntegrationPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProgram { field } => write!(f, "integration-empty-program: {field}"),
            Self::EmptyTarget => f.write_str("integration-empty-target"),
        }
    }
}

impl std::error::Error for IntegrationPlanError {}

/// Build the documented bwrap command shape for alpha network setup.
pub fn plan_bwrap_setup(config: &BwrapSetupConfig) -> Result<CommandPlan, IntegrationPlanError> {
    validate_program("bwrap_program", &config.bwrap_program)?;
    validate_program("setup_program", &config.setup_program)?;
    if config.target_argv.is_empty() || config.target_argv[0].trim().is_empty() {
        return Err(IntegrationPlanError::EmptyTarget);
    }

    let mut args = vec![
        "--unshare-user".to_owned(),
        "--unshare-net".to_owned(),
        "--cap-add".to_owned(),
        "CAP_NET_ADMIN".to_owned(),
        "--dev-bind".to_owned(),
        "/dev/net/tun".to_owned(),
        "/dev/net/tun".to_owned(),
    ];
    config.proxy_environment.append_bwrap_env_args(&mut args);
    args.push(config.setup_program.display().to_string());
    args.push("--".to_owned());
    args.extend(config.target_argv.clone());

    Ok(CommandPlan {
        program: config.bwrap_program.clone(),
        args,
    })
}

/// Sandbox-side TUN interface configuration performed by `foxproxsetup`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunInterfaceSetupConfig {
    pub ip_program: PathBuf,
    pub interface_name: String,
    pub address_cidr: String,
    pub mtu: u16,
}

impl TunInterfaceSetupConfig {
    pub fn new(
        interface_name: impl Into<String>,
        address_cidr: impl Into<String>,
        mtu: u16,
    ) -> Self {
        Self {
            ip_program: PathBuf::from("ip"),
            interface_name: interface_name.into(),
            address_cidr: address_cidr.into(),
            mtu,
        }
    }

    pub fn with_ip_program(mut self, ip_program: impl Into<PathBuf>) -> Self {
        self.ip_program = ip_program.into();
        self
    }
}

/// Setup-helper interface configuration errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunInterfaceSetupError {
    InvalidInterfaceName(String),
    InvalidAddress(String),
    InvalidMtu,
    EmptyIpProgram,
    CommandFailed {
        command: Vec<String>,
        status: Option<i32>,
        stderr: String,
    },
    Io {
        command: Vec<String>,
        error: String,
    },
}

impl fmt::Display for TunInterfaceSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInterfaceName(reason) => {
                write!(f, "tun-setup-invalid-interface: {reason}")
            }
            Self::InvalidAddress(reason) => write!(f, "tun-setup-invalid-address: {reason}"),
            Self::InvalidMtu => f.write_str("tun-setup-invalid-mtu"),
            Self::EmptyIpProgram => f.write_str("tun-setup-empty-ip-program"),
            Self::CommandFailed {
                command,
                status,
                stderr,
            } => write!(
                f,
                "tun-setup-command-failed: {:?}: status={status:?}: {stderr}",
                command
            ),
            Self::Io { command, error } => {
                write!(f, "tun-setup-command-io-error: {:?}: {error}", command)
            }
        }
    }
}

impl std::error::Error for TunInterfaceSetupError {}

/// Configure a TUN interface inside the current network namespace using `ip`.
pub fn configure_tun_interface(
    config: &TunInterfaceSetupConfig,
) -> Result<(), TunInterfaceSetupError> {
    validate_tun_interface_setup(config)?;
    run_ip_command(
        config,
        &[
            "link",
            "set",
            "dev",
            &config.interface_name,
            "mtu",
            &config.mtu.to_string(),
            "up",
        ],
    )?;
    run_ip_command(
        config,
        &[
            "addr",
            "add",
            &config.address_cidr,
            "dev",
            &config.interface_name,
        ],
    )?;
    run_ip_command(
        config,
        &["route", "add", "default", "dev", &config.interface_name],
    )?;
    Ok(())
}

fn validate_tun_interface_setup(
    config: &TunInterfaceSetupConfig,
) -> Result<(), TunInterfaceSetupError> {
    if config.ip_program.as_os_str().is_empty() {
        return Err(TunInterfaceSetupError::EmptyIpProgram);
    }
    if config.interface_name.trim().is_empty() {
        return Err(TunInterfaceSetupError::InvalidInterfaceName(
            "interface name must not be empty".to_owned(),
        ));
    }
    if config.interface_name.contains('/') || config.interface_name.contains('\0') {
        return Err(TunInterfaceSetupError::InvalidInterfaceName(
            "interface name must not contain path separators or NUL".to_owned(),
        ));
    }
    if config.address_cidr.trim().is_empty() || !config.address_cidr.contains('/') {
        return Err(TunInterfaceSetupError::InvalidAddress(
            "address must be CIDR notation".to_owned(),
        ));
    }
    if config.mtu == 0 {
        return Err(TunInterfaceSetupError::InvalidMtu);
    }
    Ok(())
}

fn run_ip_command(
    config: &TunInterfaceSetupConfig,
    args: &[&str],
) -> Result<(), TunInterfaceSetupError> {
    let mut command_vec = Vec::with_capacity(args.len() + 1);
    command_vec.push(config.ip_program.display().to_string());
    command_vec.extend(args.iter().map(|arg| (*arg).to_owned()));
    let output = Command::new(&config.ip_program)
        .args(args)
        .output()
        .map_err(|error| TunInterfaceSetupError::Io {
            command: command_vec.clone(),
            error: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(TunInterfaceSetupError::CommandFailed {
            command: command_vec,
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

/// DNS resolver file configuration for the setup helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverConfig {
    pub resolv_conf_path: PathBuf,
    pub broker_resolver_ip: IpAddr,
}

impl ResolverConfig {
    pub fn new(resolv_conf_path: impl Into<PathBuf>, broker_resolver_ip: IpAddr) -> Self {
        Self {
            resolv_conf_path: resolv_conf_path.into(),
            broker_resolver_ip,
        }
    }
}

/// Resolver configuration write errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolverConfigError {
    EmptyPath,
    Write { path: PathBuf, error: String },
}

impl fmt::Display for ResolverConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("resolver-config-empty-path"),
            Self::Write { path, error } => {
                write!(
                    f,
                    "resolver-config-write-failed: {}: {error}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ResolverConfigError {}

/// Write a minimal resolv.conf that forces sandbox DNS to the broker resolver.
pub fn write_broker_resolv_conf(config: &ResolverConfig) -> Result<(), ResolverConfigError> {
    if config.resolv_conf_path.as_os_str().is_empty() {
        return Err(ResolverConfigError::EmptyPath);
    }
    let body = format!(
        "# generated by foxproxsetup\nnameserver {}\noptions ndots:0\n",
        config.broker_resolver_ip
    );
    fs::write(&config.resolv_conf_path, body).map_err(|error| ResolverConfigError::Write {
        path: config.resolv_conf_path.clone(),
        error: error.to_string(),
    })
}

fn validate_program(field: &'static str, path: &Path) -> Result<(), IntegrationPlanError> {
    if path.as_os_str().is_empty() {
        return Err(IntegrationPlanError::EmptyProgram { field });
    }
    Ok(())
}

#[cfg(unix)]
pub mod fd_handoff {
    //! Unix fd handoff helpers for `foxproxsetup` → broker control channels.

    use std::fmt;
    use std::io::{IoSlice, IoSliceMut};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;

    use nix::cmsg_space;
    use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};

    const HANDOFF_MARKER: &[u8] = b"foxprox-fd";

    /// File descriptor received by the broker side of the setup handoff.
    #[derive(Debug)]
    pub struct ReceivedFd {
        pub marker: Vec<u8>,
        pub fd: OwnedFd,
    }

    /// Errors from SCM_RIGHTS setup fd handoff.
    #[derive(Debug)]
    pub enum FdHandoffError {
        Send(String),
        Receive(String),
        TruncatedControlMessage,
        MissingFileDescriptor,
        UnexpectedMarker(Vec<u8>),
    }

    impl fmt::Display for FdHandoffError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Send(error) => write!(f, "fd-handoff-send-error: {error}"),
                Self::Receive(error) => write!(f, "fd-handoff-receive-error: {error}"),
                Self::TruncatedControlMessage => {
                    f.write_str("fd-handoff-truncated-control-message")
                }
                Self::MissingFileDescriptor => f.write_str("fd-handoff-missing-file-descriptor"),
                Self::UnexpectedMarker(marker) => {
                    write!(f, "fd-handoff-unexpected-marker: {:?}", marker)
                }
            }
        }
    }

    impl std::error::Error for FdHandoffError {}

    /// Send one fd from setup-helper side to broker side over a Unix stream.
    pub fn send_setup_fd(socket: &UnixStream, fd: RawFd) -> Result<(), FdHandoffError> {
        let iov = [IoSlice::new(HANDOFF_MARKER)];
        let fds = [fd];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg::<()>(socket.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)
            .map_err(|error| FdHandoffError::Send(error.to_string()))?;
        Ok(())
    }

    /// Receive one setup fd on the broker side as an owned descriptor.
    pub fn receive_setup_fd(socket: &UnixStream) -> Result<ReceivedFd, FdHandoffError> {
        let mut marker = [0_u8; HANDOFF_MARKER.len()];
        let (bytes, flags, received_fds) = {
            let mut iov = [IoSliceMut::new(&mut marker)];
            let mut cmsgspace = cmsg_space!([RawFd; 1]);
            let msg = recvmsg::<()>(
                socket.as_raw_fd(),
                &mut iov,
                Some(&mut cmsgspace),
                MsgFlags::empty(),
            )
            .map_err(|error| FdHandoffError::Receive(error.to_string()))?;

            let mut received_fds = Vec::new();
            for cmsg in msg
                .cmsgs()
                .map_err(|error| FdHandoffError::Receive(error.to_string()))?
            {
                if let ControlMessageOwned::ScmRights(fds) = cmsg {
                    received_fds.extend(fds);
                }
            }
            (msg.bytes, msg.flags, received_fds)
        };

        if flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(FdHandoffError::TruncatedControlMessage);
        }

        let received_marker = marker[..bytes].to_vec();
        if received_marker != HANDOFF_MARKER {
            return Err(FdHandoffError::UnexpectedMarker(received_marker));
        }

        let Some(first_fd) = received_fds.first().copied() else {
            return Err(FdHandoffError::MissingFileDescriptor);
        };
        let mut owned_fds: Vec<OwnedFd> = received_fds.into_iter().map(raw_fd_to_owned).collect();
        let first = owned_fds.remove(
            owned_fds
                .iter()
                .position(|fd| fd.as_raw_fd() == first_fd)
                .unwrap_or(0),
        );
        drop(owned_fds);

        Ok(ReceivedFd {
            marker: received_marker,
            fd: first,
        })
    }

    fn raw_fd_to_owned(fd: RawFd) -> OwnedFd {
        // SAFETY: `recvmsg` with SCM_RIGHTS returns fresh file descriptors owned
        // by this process. This function immediately wraps each raw descriptor
        // exactly once in `OwnedFd` so it will be closed on drop.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn configure_tun_interface_runs_link_address_and_route_commands() {
        use std::fs::{create_dir_all, read_to_string, remove_dir_all, write};
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("foxprox-ip-script-{}-ok", std::process::id()));
        create_dir_all(&dir).unwrap();
        let script = dir.join("ip");
        let log = dir.join("ip.log");
        write(
            &script,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let config =
            TunInterfaceSetupConfig::new("fpx0", "10.0.0.2/24", 1500).with_ip_program(&script);

        configure_tun_interface(&config).unwrap();

        let calls = read_to_string(&log).unwrap();
        assert_eq!(
            calls,
            "link set dev fpx0 mtu 1500 up\naddr add 10.0.0.2/24 dev fpx0\nroute add default dev fpx0\n"
        );
        remove_dir_all(dir).unwrap();
    }

    #[test]
    fn configure_tun_interface_validates_inputs_before_running_commands() {
        assert!(matches!(
            configure_tun_interface(&TunInterfaceSetupConfig::new("", "10.0.0.2/24", 1500)),
            Err(TunInterfaceSetupError::InvalidInterfaceName(_))
        ));
        assert!(matches!(
            configure_tun_interface(&TunInterfaceSetupConfig::new("fpx0", "10.0.0.2", 1500)),
            Err(TunInterfaceSetupError::InvalidAddress(_))
        ));
        assert_eq!(
            configure_tun_interface(&TunInterfaceSetupConfig::new("fpx0", "10.0.0.2/24", 0))
                .unwrap_err(),
            TunInterfaceSetupError::InvalidMtu
        );
    }

    #[cfg(unix)]
    #[test]
    fn configure_tun_interface_reports_command_failure() {
        use std::fs::{create_dir_all, remove_dir_all, write};
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("foxprox-ip-script-{}-fail", std::process::id()));
        create_dir_all(&dir).unwrap();
        let script = dir.join("ip");
        write(&script, "#!/bin/sh\necho boom >&2\nexit 7\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let config =
            TunInterfaceSetupConfig::new("fpx0", "10.0.0.2/24", 1500).with_ip_program(&script);

        let error = configure_tun_interface(&config).unwrap_err();

        assert!(matches!(
            error,
            TunInterfaceSetupError::CommandFailed { .. }
        ));
        assert!(error.to_string().contains("boom"));
        remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_broker_resolv_conf_points_dns_at_broker_resolver() {
        use std::fs::{read_to_string, remove_file, write};
        use std::net::Ipv4Addr;

        let path = std::env::temp_dir().join(format!("foxprox-resolv-conf-{}", std::process::id()));
        write(&path, "nameserver 8.8.8.8\n").unwrap();
        let config = ResolverConfig::new(&path, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        write_broker_resolv_conf(&config).unwrap();

        assert_eq!(
            read_to_string(&path).unwrap(),
            "# generated by foxproxsetup\nnameserver 10.0.0.1\noptions ndots:0\n"
        );
        remove_file(path).unwrap();
    }

    #[test]
    fn write_broker_resolv_conf_reports_invalid_path() {
        use std::net::Ipv6Addr;

        let empty = ResolverConfig::new("", IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            write_broker_resolv_conf(&empty).unwrap_err(),
            ResolverConfigError::EmptyPath
        );

        let directory_path = std::env::temp_dir();
        let directory = ResolverConfig::new(directory_path, IpAddr::V6(Ipv6Addr::LOCALHOST));
        let error = write_broker_resolv_conf(&directory).unwrap_err();
        assert!(matches!(error, ResolverConfigError::Write { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn setup_fd_handoff_transfers_readable_descriptor_to_broker_side() {
        use std::fs::{remove_file, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let path = std::env::temp_dir().join(format!(
            "foxprox-fd-handoff-{}-{}",
            std::process::id(),
            "proof"
        ));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(b"tun-fd-proof").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let (setup_side, broker_side) = UnixStream::pair().unwrap();

        fd_handoff::send_setup_fd(&setup_side, file.as_raw_fd()).unwrap();
        let received = fd_handoff::receive_setup_fd(&broker_side).unwrap();
        let mut received_file = std::fs::File::from(received.fd);
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();

        assert_eq!(received.marker, b"foxprox-fd".to_vec());
        assert_eq!(contents, "tun-fd-proof");
        remove_file(path).unwrap();
    }

    #[test]
    fn bwrap_plan_uses_foxproxsetup_with_temporary_net_admin_and_tun_access() {
        let config = BwrapSetupConfig::new(
            "bwrap",
            "/usr/libexec/foxproxsetup",
            vec!["curl".to_owned(), "http://example.com".to_owned()],
        )
        .with_proxy_environment(ProxyEnvironment::loopback_http_socks(
            "10.0.2.1:18080",
            "10.0.2.1:18081",
        ));

        let plan = plan_bwrap_setup(&config).expect("bwrap plan is valid");
        let argv = plan.argv();

        assert_eq!(plan.program, PathBuf::from("bwrap"));
        assert!(argv.windows(1).any(|window| window == ["--unshare-user"]));
        assert!(argv.windows(1).any(|window| window == ["--unshare-net"]));
        assert!(argv
            .windows(2)
            .any(|window| window == ["--cap-add", "CAP_NET_ADMIN"]));
        assert!(argv
            .windows(3)
            .any(|window| window == ["--dev-bind", "/dev/net/tun", "/dev/net/tun"]));
        assert!(argv
            .windows(3)
            .any(|window| window == ["--setenv", "HTTP_PROXY", "http://10.0.2.1:18080"]));
        assert!(argv
            .windows(3)
            .any(|window| window == ["--setenv", "ALL_PROXY", "socks5://10.0.2.1:18081"]));
        assert!(argv.windows(4).any(|window| window
            == [
                "/usr/libexec/foxproxsetup",
                "--",
                "curl",
                "http://example.com"
            ]));
    }

    #[test]
    fn bwrap_plan_rejects_missing_target_or_program() {
        let missing_target = BwrapSetupConfig::new("bwrap", "foxproxsetup", Vec::new());
        assert_eq!(
            plan_bwrap_setup(&missing_target).unwrap_err(),
            IntegrationPlanError::EmptyTarget
        );

        let missing_bwrap = BwrapSetupConfig::new("", "foxproxsetup", vec!["true".to_owned()]);
        assert_eq!(
            plan_bwrap_setup(&missing_bwrap).unwrap_err(),
            IntegrationPlanError::EmptyProgram {
                field: "bwrap_program"
            }
        );
    }
}
