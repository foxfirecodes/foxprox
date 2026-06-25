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

/// Arguments passed to the `foxproxsetup` command inside the sandbox namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupHelperArgs {
    pub broker_socket: PathBuf,
    pub tun_name: String,
    pub tun_device: PathBuf,
    pub address_cidr: String,
    pub mtu: u16,
    pub resolv_conf: PathBuf,
    pub broker_dns: IpAddr,
    pub ip_program: PathBuf,
}

impl SetupHelperArgs {
    pub fn new(
        broker_socket: impl Into<PathBuf>,
        tun_name: impl Into<String>,
        address_cidr: impl Into<String>,
        mtu: u16,
        resolv_conf: impl Into<PathBuf>,
        broker_dns: IpAddr,
    ) -> Self {
        Self {
            broker_socket: broker_socket.into(),
            tun_name: tun_name.into(),
            tun_device: PathBuf::from("/dev/net/tun"),
            address_cidr: address_cidr.into(),
            mtu,
            resolv_conf: resolv_conf.into(),
            broker_dns,
            ip_program: PathBuf::from("ip"),
        }
    }

    pub fn with_tun_device(mut self, tun_device: impl Into<PathBuf>) -> Self {
        self.tun_device = tun_device.into();
        self
    }

    pub fn with_ip_program(mut self, ip_program: impl Into<PathBuf>) -> Self {
        self.ip_program = ip_program.into();
        self
    }

    fn append_argv(&self, args: &mut Vec<String>) {
        args.extend([
            "--broker-socket".to_owned(),
            self.broker_socket.display().to_string(),
            "--tun-name".to_owned(),
            self.tun_name.clone(),
            "--tun-device".to_owned(),
            self.tun_device.display().to_string(),
            "--address-cidr".to_owned(),
            self.address_cidr.clone(),
            "--mtu".to_owned(),
            self.mtu.to_string(),
            "--resolv-conf".to_owned(),
            self.resolv_conf.display().to_string(),
            "--broker-dns".to_owned(),
            self.broker_dns.to_string(),
            "--ip-program".to_owned(),
            self.ip_program.display().to_string(),
        ]);
    }
}

/// Inputs for a bwrap-compatible foxprox network setup launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwrapSetupConfig {
    pub bwrap_program: PathBuf,
    pub setup_program: PathBuf,
    pub target_argv: Vec<String>,
    pub proxy_environment: ProxyEnvironment,
    pub setup_helper_args: Option<SetupHelperArgs>,
    pub extra_bwrap_args: Vec<String>,
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
            setup_helper_args: None,
            extra_bwrap_args: Vec::new(),
        }
    }

    pub fn with_setup_helper_args(mut self, setup_helper_args: SetupHelperArgs) -> Self {
        self.setup_helper_args = Some(setup_helper_args);
        self
    }

    pub fn with_proxy_environment(mut self, proxy_environment: ProxyEnvironment) -> Self {
        self.proxy_environment = proxy_environment;
        self
    }

    pub fn with_extra_bwrap_args(mut self, extra_bwrap_args: Vec<String>) -> Self {
        self.extra_bwrap_args = extra_bwrap_args;
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
    args.extend(config.extra_bwrap_args.clone());
    config.proxy_environment.append_bwrap_env_args(&mut args);
    args.push(config.setup_program.display().to_string());
    if let Some(setup_helper_args) = &config.setup_helper_args {
        setup_helper_args.append_argv(&mut args);
    }
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

#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
#[cfg(target_os = "linux")]
const CAP_NET_ADMIN_U32: u32 = 12;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxCapHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Evidence that setup-only Linux capabilities were removed before target exec.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDropResult {
    pub capability: u32,
    pub was_present: bool,
    pub is_present_after_drop: bool,
}

/// Linux capability drop errors.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityDropError {
    CapGet(String),
    CapSet(String),
    StillPresent { capability: u32 },
}

#[cfg(target_os = "linux")]
impl fmt::Display for CapabilityDropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapGet(error) => write!(f, "capability-drop-capget-error: {error}"),
            Self::CapSet(error) => write!(f, "capability-drop-capset-error: {error}"),
            Self::StillPresent { capability } => {
                write!(f, "capability-drop-still-present: capability={capability}")
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for CapabilityDropError {}

/// Drop `CAP_NET_ADMIN` from the current process before execing the target app.
#[cfg(target_os = "linux")]
pub fn drop_net_admin_capability() -> Result<CapabilityDropResult, CapabilityDropError> {
    let mut sets = read_current_capabilities()?;
    let was_present = sets.contains(CAP_NET_ADMIN_U32);
    sets.clear(CAP_NET_ADMIN_U32);
    write_current_capabilities(&sets)?;
    let verified = read_current_capabilities()?;
    let is_present_after_drop = verified.contains(CAP_NET_ADMIN_U32);
    if is_present_after_drop {
        return Err(CapabilityDropError::StillPresent {
            capability: CAP_NET_ADMIN_U32,
        });
    }
    Ok(CapabilityDropResult {
        capability: CAP_NET_ADMIN_U32,
        was_present,
        is_present_after_drop,
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxCapabilitySets {
    data: [LinuxCapData; 2],
}

#[cfg(target_os = "linux")]
impl LinuxCapabilitySets {
    fn contains(&self, capability: u32) -> bool {
        let index = (capability / 32) as usize;
        let mask = 1_u32 << (capability % 32);
        self.data
            .get(index)
            .is_some_and(|set| (set.effective | set.permitted | set.inheritable) & mask != 0)
    }

    fn clear(&mut self, capability: u32) {
        let index = (capability / 32) as usize;
        let mask = !(1_u32 << (capability % 32));
        if let Some(set) = self.data.get_mut(index) {
            set.effective &= mask;
            set.permitted &= mask;
            set.inheritable &= mask;
        }
    }
}

#[cfg(target_os = "linux")]
fn read_current_capabilities() -> Result<LinuxCapabilitySets, CapabilityDropError> {
    let mut header = LinuxCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [
        LinuxCapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        LinuxCapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let result = unsafe_capget(&mut header, data.as_mut_ptr());
    if result != 0 {
        return Err(CapabilityDropError::CapGet(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(LinuxCapabilitySets { data })
}

#[cfg(target_os = "linux")]
fn write_current_capabilities(sets: &LinuxCapabilitySets) -> Result<(), CapabilityDropError> {
    let mut header = LinuxCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = sets.data;
    let result = unsafe_capset(&mut header, data.as_mut_ptr());
    if result != 0 {
        return Err(CapabilityDropError::CapSet(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unsafe_capget(header: *mut LinuxCapHeader, data: *mut LinuxCapData) -> libc::c_long {
    // SAFETY: `header` and `data` point to initialized local structs with the
    // Linux capability v3 layout expected by `capget(2)`.
    unsafe { libc::syscall(libc::SYS_capget, header, data) }
}

#[cfg(target_os = "linux")]
fn unsafe_capset(header: *mut LinuxCapHeader, data: *mut LinuxCapData) -> libc::c_long {
    // SAFETY: `header` and `data` point to initialized local structs with the
    // Linux capability v3 layout expected by `capset(2)`.
    unsafe { libc::syscall(libc::SYS_capset, header, data) }
}

#[cfg(unix)]
pub mod fd_handoff {
    //! Unix fd handoff helpers for `foxproxsetup` → broker control channels.

    use std::fmt;
    use std::io::{IoSlice, IoSliceMut};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};

    use nix::cmsg_space;
    use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};

    const HANDOFF_MARKER: &[u8] = b"foxprox-fd";

    /// Setup sequence inputs after a TUN-like fd has been created.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SetupSequenceConfig {
        pub interface: super::TunInterfaceSetupConfig,
        pub resolver: super::ResolverConfig,
    }

    /// Evidence returned after setup configuration and fd handoff complete.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SetupSequenceResult {
        pub interface_name: String,
        pub resolver_path: std::path::PathBuf,
    }

    /// Setup sequence errors.
    #[derive(Debug)]
    pub enum SetupSequenceError {
        #[cfg(target_os = "linux")]
        TunCreate(foxprox_device::TunCreateError),
        Interface(super::TunInterfaceSetupError),
        Resolver(super::ResolverConfigError),
        Handoff(FdHandoffError),
    }

    impl fmt::Display for SetupSequenceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                #[cfg(target_os = "linux")]
                Self::TunCreate(error) => write!(f, "setup-sequence-tun-create-error: {error}"),
                Self::Interface(error) => write!(f, "setup-sequence-interface-error: {error}"),
                Self::Resolver(error) => write!(f, "setup-sequence-resolver-error: {error}"),
                Self::Handoff(error) => write!(f, "setup-sequence-handoff-error: {error}"),
            }
        }
    }

    impl std::error::Error for SetupSequenceError {}

    /// File descriptor received by the broker side of the setup handoff.
    #[derive(Debug)]
    pub struct ReceivedFd {
        pub marker: Vec<u8>,
        pub fd: OwnedFd,
    }

    /// Host-side broker control listener for setup-helper fd handoff.
    #[derive(Debug)]
    pub struct BrokerControlListener {
        path: PathBuf,
        listener: UnixListener,
    }

    impl BrokerControlListener {
        pub fn bind(path: impl Into<PathBuf>) -> Result<Self, BrokerControlError> {
            let path = path.into();
            let listener = UnixListener::bind(&path).map_err(|error| BrokerControlError::Bind {
                path: path.clone(),
                error: error.to_string(),
            })?;
            Ok(Self { path, listener })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn accept_setup_fd(&self) -> Result<ReceivedFd, BrokerControlError> {
            let (socket, _) =
                self.listener
                    .accept()
                    .map_err(|error| BrokerControlError::Accept {
                        path: self.path.clone(),
                        error: error.to_string(),
                    })?;
            receive_setup_fd(&socket).map_err(BrokerControlError::Handoff)
        }
    }

    /// Host-side broker control listener errors.
    #[derive(Debug)]
    pub enum BrokerControlError {
        Bind { path: PathBuf, error: String },
        Accept { path: PathBuf, error: String },
        Handoff(FdHandoffError),
    }

    impl fmt::Display for BrokerControlError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Bind { path, error } => {
                    write!(f, "broker-control-bind-error: {}: {error}", path.display())
                }
                Self::Accept { path, error } => {
                    write!(
                        f,
                        "broker-control-accept-error: {}: {error}",
                        path.display()
                    )
                }
                Self::Handoff(error) => write!(f, "broker-control-handoff-error: {error}"),
            }
        }
    }

    impl std::error::Error for BrokerControlError {}

    /// Live setup child plus the fd it handed to the broker.
    #[derive(Debug)]
    pub struct SetupCommandChild {
        pub child: Child,
        pub received: ReceivedFd,
    }

    /// Result of spawning a setup command and receiving its fd handoff.
    #[derive(Debug)]
    pub struct SetupCommandRunResult {
        pub received: ReceivedFd,
        pub status_code: Option<i32>,
        pub status_success: bool,
    }

    /// Errors while spawning or waiting for a setup command.
    #[derive(Debug)]
    pub enum SetupCommandRunError {
        Spawn(String),
        Broker(BrokerControlError),
        Wait(String),
    }

    impl fmt::Display for SetupCommandRunError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Spawn(error) => write!(f, "setup-command-spawn-error: {error}"),
                Self::Broker(error) => write!(f, "setup-command-broker-error: {error}"),
                Self::Wait(error) => write!(f, "setup-command-wait-error: {error}"),
            }
        }
    }

    impl std::error::Error for SetupCommandRunError {}

    /// Spawn a setup command while accepting one setup fd on the broker listener.
    ///
    /// The returned child is still live. Callers can process traffic on the
    /// received fd before waiting for the target process to exit.
    pub fn spawn_setup_command_and_accept_fd(
        listener: BrokerControlListener,
        mut command: Command,
    ) -> Result<SetupCommandChild, SetupCommandRunError> {
        let child = command
            .spawn()
            .map_err(|error| SetupCommandRunError::Spawn(error.to_string()))?;
        let received = listener
            .accept_setup_fd()
            .map_err(SetupCommandRunError::Broker)?;
        Ok(SetupCommandChild { child, received })
    }

    /// Spawn a setup command, accept one setup fd, then wait for process exit.
    pub fn run_setup_command_and_receive_fd(
        listener: BrokerControlListener,
        command: Command,
    ) -> Result<SetupCommandRunResult, SetupCommandRunError> {
        let SetupCommandChild {
            mut child,
            received,
        } = spawn_setup_command_and_accept_fd(listener, command)?;
        let status = child
            .wait()
            .map_err(|error| SetupCommandRunError::Wait(error.to_string()))?;
        Ok(SetupCommandRunResult {
            received,
            status_code: status.code(),
            status_success: status.success(),
        })
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

    /// Run the setup-helper sequence after a TUN-like fd has been created:
    /// configure interface, write resolver config, then hand the fd to broker.
    pub fn run_setup_sequence(
        broker_socket: &UnixStream,
        setup_fd: RawFd,
        config: &SetupSequenceConfig,
    ) -> Result<SetupSequenceResult, SetupSequenceError> {
        super::configure_tun_interface(&config.interface).map_err(SetupSequenceError::Interface)?;
        super::write_broker_resolv_conf(&config.resolver).map_err(SetupSequenceError::Resolver)?;
        send_setup_fd(broker_socket, setup_fd).map_err(SetupSequenceError::Handoff)?;
        Ok(SetupSequenceResult {
            interface_name: config.interface.interface_name.clone(),
            resolver_path: config.resolver.resolv_conf_path.clone(),
        })
    }

    /// Create a real Linux TUN fd, configure sandbox networking, and hand the
    /// resulting fd to the broker. This is the production-shaped setup path for
    /// `foxproxsetup` once it is executing with `CAP_NET_ADMIN`.
    #[cfg(target_os = "linux")]
    pub fn run_linux_tun_setup_sequence(
        broker_socket: &UnixStream,
        tun: &foxprox_device::TunCreateConfig,
        config: &SetupSequenceConfig,
    ) -> Result<SetupSequenceResult, SetupSequenceError> {
        let tun_device = foxprox_device::create_tun(tun).map_err(SetupSequenceError::TunCreate)?;
        run_setup_sequence(broker_socket, tun_device.fd.as_raw_fd(), config)
    }

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

    fn unique_test_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("foxprox-{prefix}-{}-{nanos}", std::process::id()))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_sets_clear_net_admin_from_all_current_process_sets() {
        let mask = 1_u32 << (CAP_NET_ADMIN_U32 % 32);
        let mut sets = LinuxCapabilitySets {
            data: [
                LinuxCapData {
                    effective: mask,
                    permitted: mask,
                    inheritable: mask,
                },
                LinuxCapData {
                    effective: u32::MAX,
                    permitted: u32::MAX,
                    inheritable: u32::MAX,
                },
            ],
        };

        assert!(sets.contains(CAP_NET_ADMIN_U32));
        sets.clear(CAP_NET_ADMIN_U32);
        assert!(!sets.contains(CAP_NET_ADMIN_U32));
        assert_eq!(sets.data[0].effective & mask, 0);
        assert_eq!(sets.data[0].permitted & mask, 0);
        assert_eq!(sets.data[0].inheritable & mask, 0);
        assert_eq!(sets.data[1].effective, u32::MAX);
    }

    #[cfg(unix)]
    #[test]
    fn configure_tun_interface_runs_link_address_and_route_commands() {
        use std::fs::{create_dir_all, read_to_string, remove_dir_all, write};
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir("ip-script-ok");
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

        let dir = unique_test_dir("ip-script-fail");
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

        let path = unique_test_dir("resolv-conf");
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
    fn setup_sequence_configures_resolver_and_hands_fd_to_broker() {
        use std::fs::{create_dir_all, read_to_string, remove_dir_all, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::net::{IpAddr, Ipv4Addr};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let dir = unique_test_dir("setup-sequence-ok");
        create_dir_all(&dir).unwrap();
        let script = dir.join("ip");
        let ip_log = dir.join("ip.log");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
                ip_log.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let resolv_conf = dir.join("resolv.conf");
        let fd_path = dir.join("tun-fd-standin");
        let mut fd_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&fd_path)
            .unwrap();
        fd_file.write_all(b"setup-sequence-fd").unwrap();
        fd_file.seek(SeekFrom::Start(0)).unwrap();
        let (setup_socket, broker_socket) = UnixStream::pair().unwrap();
        let config = fd_handoff::SetupSequenceConfig {
            interface: TunInterfaceSetupConfig::new("fpx0", "10.0.0.2/24", 1500)
                .with_ip_program(&script),
            resolver: ResolverConfig::new(&resolv_conf, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        };

        let result = fd_handoff::run_setup_sequence(&setup_socket, fd_file.as_raw_fd(), &config)
            .expect("setup sequence succeeds");
        let received = fd_handoff::receive_setup_fd(&broker_socket).unwrap();
        let mut received_file = std::fs::File::from(received.fd);
        let mut fd_contents = String::new();
        received_file.read_to_string(&mut fd_contents).unwrap();

        assert_eq!(result.interface_name, "fpx0");
        assert_eq!(result.resolver_path, resolv_conf);
        assert_eq!(
            read_to_string(&ip_log).unwrap(),
            "link set dev fpx0 mtu 1500 up\naddr add 10.0.0.2/24 dev fpx0\nroute add default dev fpx0\n"
        );
        assert_eq!(
            read_to_string(&resolv_conf).unwrap(),
            "# generated by foxproxsetup\nnameserver 10.0.0.1\noptions ndots:0\n"
        );
        assert_eq!(fd_contents, "setup-sequence-fd");
        remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_setup_sequence_stops_before_commands_when_tun_create_fails() {
        use std::fs::{create_dir_all, remove_dir_all, write};
        use std::net::{IpAddr, Ipv4Addr};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let dir = unique_test_dir("linux-tun-setup-fail");
        create_dir_all(&dir).unwrap();
        let script = dir.join("ip");
        let ip_log = dir.join("ip.log");
        write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
                ip_log.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let (setup_socket, broker_socket) = UnixStream::pair().unwrap();
        broker_socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let sequence = fd_handoff::SetupSequenceConfig {
            interface: TunInterfaceSetupConfig::new("fpx0", "10.0.0.2/24", 1500)
                .with_ip_program(&script),
            resolver: ResolverConfig::new(
                dir.join("resolv.conf"),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ),
        };
        let tun =
            foxprox_device::TunCreateConfig::new("fpx0").with_device_path(dir.join("missing-tun"));

        let error =
            fd_handoff::run_linux_tun_setup_sequence(&setup_socket, &tun, &sequence).unwrap_err();

        assert!(matches!(
            error,
            fd_handoff::SetupSequenceError::TunCreate(_)
        ));
        assert!(!ip_log.exists());
        assert!(!sequence.resolver.resolv_conf_path.exists());
        assert!(fd_handoff::receive_setup_fd(&broker_socket).is_err());
        remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn setup_sequence_stops_before_resolver_and_handoff_on_interface_failure() {
        use std::fs::{create_dir_all, remove_dir_all, OpenOptions};
        use std::io::Write;
        use std::net::{IpAddr, Ipv4Addr};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let dir = unique_test_dir("setup-sequence-fail");
        create_dir_all(&dir).unwrap();
        let script = dir.join("ip");
        std::fs::write(&script, "#!/bin/sh\necho setup failed >&2\nexit 9\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let resolv_conf = dir.join("resolv.conf");
        let fd_path = dir.join("tun-fd-standin");
        let mut fd_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&fd_path)
            .unwrap();
        fd_file.write_all(b"setup-sequence-fd").unwrap();
        let (setup_socket, broker_socket) = UnixStream::pair().unwrap();
        broker_socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let config = fd_handoff::SetupSequenceConfig {
            interface: TunInterfaceSetupConfig::new("fpx0", "10.0.0.2/24", 1500)
                .with_ip_program(&script),
            resolver: ResolverConfig::new(&resolv_conf, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        };

        let error = fd_handoff::run_setup_sequence(&setup_socket, fd_file.as_raw_fd(), &config)
            .unwrap_err();

        assert!(matches!(
            error,
            fd_handoff::SetupSequenceError::Interface(_)
        ));
        assert!(!resolv_conf.exists());
        assert!(fd_handoff::receive_setup_fd(&broker_socket).is_err());
        remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn launcher_returns_child_after_fd_handoff_before_waiting() {
        use std::fs::{create_dir_all, remove_dir_all, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::process::Command;

        let Some(python) = ["/usr/bin/python3", "/bin/python3"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
        else {
            eprintln!("skipping live-child fd test: python3 missing");
            return;
        };
        let dir = unique_test_dir("launcher-live-child");
        create_dir_all(&dir).unwrap();
        let socket_path = dir.join("setup.sock");
        let fd_path = dir.join("tun-fd-standin");
        let mut fd_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&fd_path)
            .unwrap();
        fd_file.write_all(b"live-child-fd").unwrap();
        fd_file.seek(SeekFrom::Start(0)).unwrap();
        drop(fd_file);
        let listener = fd_handoff::BrokerControlListener::bind(&socket_path).unwrap();
        let script = r#"
import array, os, socket, sys, time
sock_path, fd_path = sys.argv[1], sys.argv[2]
fd = os.open(fd_path, os.O_RDWR)
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
fds = array.array('i', [fd])
sock.sendmsg([b'foxprox-fd'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
sock.close()
os.close(fd)
time.sleep(0.2)
"#;
        let mut command = Command::new(python);
        command
            .arg("-c")
            .arg(script)
            .arg(&socket_path)
            .arg(&fd_path);

        let mut child = fd_handoff::spawn_setup_command_and_accept_fd(listener, command).unwrap();
        let mut received_file = std::fs::File::from(child.received.fd);
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();
        let status = child.child.wait().unwrap();

        assert_eq!(child.received.marker, b"foxprox-fd".to_vec());
        assert_eq!(contents, "live-child-fd");
        assert!(status.success());
        remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn launcher_spawns_setup_command_and_receives_fd_handoff() {
        use std::fs::{create_dir_all, remove_dir_all, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::process::Command;

        let Some(python) = ["/usr/bin/python3", "/bin/python3"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
        else {
            eprintln!("skipping launcher fd test: python3 missing");
            return;
        };
        let dir = unique_test_dir("launcher-fd");
        create_dir_all(&dir).unwrap();
        let socket_path = dir.join("setup.sock");
        let fd_path = dir.join("tun-fd-standin");
        let mut fd_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&fd_path)
            .unwrap();
        fd_file.write_all(b"launcher-fd").unwrap();
        fd_file.seek(SeekFrom::Start(0)).unwrap();
        drop(fd_file);
        let listener = fd_handoff::BrokerControlListener::bind(&socket_path).unwrap();
        let script = r#"
import array, os, socket, sys
sock_path, fd_path = sys.argv[1], sys.argv[2]
fd = os.open(fd_path, os.O_RDWR)
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
fds = array.array('i', [fd])
sock.sendmsg([b'foxprox-fd'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
sock.close()
os.close(fd)
"#;
        let mut command = Command::new(python);
        command
            .arg("-c")
            .arg(script)
            .arg(&socket_path)
            .arg(&fd_path);

        let result = fd_handoff::run_setup_command_and_receive_fd(listener, command).unwrap();
        let mut received_file = std::fs::File::from(result.received.fd);
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();

        assert!(result.status_success);
        assert_eq!(result.status_code, Some(0));
        assert_eq!(result.received.marker, b"foxprox-fd".to_vec());
        assert_eq!(contents, "launcher-fd");
        remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn broker_control_listener_accepts_setup_fd_handoff() {
        use std::fs::{create_dir_all, remove_dir_all, File, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::thread;

        let dir = unique_test_dir("broker-control");
        create_dir_all(&dir).unwrap();
        let socket_path = dir.join("setup.sock");
        let listener = fd_handoff::BrokerControlListener::bind(&socket_path).unwrap();
        assert_eq!(listener.path(), socket_path.as_path());
        let path_for_setup = socket_path.clone();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(dir.join("tun-fd-standin"))
            .unwrap();
        file.write_all(b"broker-control-fd").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let setup_thread = thread::spawn(move || {
            let socket = UnixStream::connect(path_for_setup).unwrap();
            fd_handoff::send_setup_fd(&socket, file.as_raw_fd()).unwrap();
        });

        let received = listener.accept_setup_fd().unwrap();
        setup_thread.join().unwrap();
        let mut received_file = File::from(received.fd);
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();

        assert_eq!(received.marker, b"foxprox-fd".to_vec());
        assert_eq!(contents, "broker-control-fd");
        remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn setup_fd_handoff_transfers_readable_descriptor_to_broker_side() {
        use std::fs::{remove_file, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let path = unique_test_dir("fd-handoff-proof");
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
    fn bwrap_plan_accepts_caller_supplied_sandbox_args_before_setup() {
        let config = BwrapSetupConfig::new(
            "bwrap",
            "/usr/libexec/foxproxsetup",
            vec!["python3".to_owned()],
        )
        .with_extra_bwrap_args(vec![
            "--dev-bind".to_owned(),
            "/".to_owned(),
            "/".to_owned(),
            "--ro-bind".to_owned(),
            "/etc/ssl".to_owned(),
            "/etc/ssl".to_owned(),
        ]);

        let argv = plan_bwrap_setup(&config).unwrap().argv();
        let setup_index = argv
            .iter()
            .position(|arg| arg == "/usr/libexec/foxproxsetup")
            .unwrap();
        let pre_setup_args = &argv[..setup_index];

        assert!(pre_setup_args
            .windows(3)
            .any(|window| window == ["--dev-bind", "/", "/"]));
        assert!(pre_setup_args
            .windows(3)
            .any(|window| window == ["--ro-bind", "/etc/ssl", "/etc/ssl"]));
    }

    #[test]
    fn bwrap_plan_passes_setup_helper_arguments_before_target_separator() {
        use std::net::Ipv4Addr;

        let config = BwrapSetupConfig::new(
            "bwrap",
            "/usr/libexec/foxproxsetup",
            vec!["curl".to_owned(), "http://example.com".to_owned()],
        )
        .with_setup_helper_args(
            SetupHelperArgs::new(
                "/run/foxprox/broker.sock",
                "foxprox0",
                "10.0.0.2/24",
                1400,
                "/etc/resolv.conf",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .with_tun_device("/dev/net/tun")
            .with_ip_program("/sbin/ip"),
        );

        let argv = plan_bwrap_setup(&config).unwrap().argv();
        let setup_index = argv
            .iter()
            .position(|arg| arg == "/usr/libexec/foxproxsetup")
            .unwrap();
        let separator_index = argv.iter().position(|arg| arg == "--").unwrap();
        let setup_args = &argv[setup_index + 1..separator_index];

        assert_eq!(
            setup_args,
            [
                "--broker-socket",
                "/run/foxprox/broker.sock",
                "--tun-name",
                "foxprox0",
                "--tun-device",
                "/dev/net/tun",
                "--address-cidr",
                "10.0.0.2/24",
                "--mtu",
                "1400",
                "--resolv-conf",
                "/etc/resolv.conf",
                "--broker-dns",
                "10.0.0.1",
                "--ip-program",
                "/sbin/ip",
            ]
        );
        assert_eq!(&argv[separator_index + 1..], ["curl", "http://example.com"]);
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
