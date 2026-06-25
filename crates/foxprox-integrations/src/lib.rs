//! Integration backend contracts for sandbox/network setup.
//!
//! bwrap and other launchers belong here, not in broker core. This crate returns
//! typed setup plans and leaves actual process/syscall execution to backend
//! implementations.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use foxprox_core::SandboxId;

/// Backend-neutral network setup request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSetupRequest {
    pub sandbox_id: SandboxId,
    pub tun: TunDeviceConfig,
    pub broker_dns: IpAddr,
    pub proxy: Option<ProxyExposure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunDeviceConfig {
    pub name: String,
    pub sandbox_ip: IpAddr,
    pub broker_ip: IpAddr,
    pub mtu: u16,
}

impl TunDeviceConfig {
    pub fn alpha_default() -> Self {
        Self {
            name: "foxprox0".to_string(),
            sandbox_ip: "10.255.0.2".parse().unwrap(),
            broker_ip: "10.255.0.1".parse().unwrap(),
            mtu: 1500,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyExposure {
    pub http_proxy: String,
    pub https_proxy: String,
    pub all_proxy: String,
    pub no_proxy: String,
}

/// Backend-neutral setup plan consumed by a launcher/runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSetupPlan {
    pub sandbox_id: SandboxId,
    pub required_capabilities: Vec<SetupCapability>,
    pub required_devices: Vec<PathBuf>,
    pub setup_helper: Option<SetupHelperPlan>,
    pub proxy_environment: Option<ProxyExposure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SetupCapability {
    CapNetAdmin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupHelperPlan {
    pub program: String,
    pub args_before_target: Vec<String>,
}

/// Integration backend contract. Implementations own launcher details and must
/// return only broker-neutral setup plans to the core runtime.
pub trait IntegrationBackend {
    fn plan(&self, request: NetworkSetupRequest) -> Result<NetworkSetupPlan, IntegrationError>;
}

/// One privileged helper command needed to configure a TUN device. The command
/// plan is intentionally data-only so tests can validate the Linux boundary
/// without executing privileged operations in broker core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunSetupCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Concrete Linux helper-side command plan for creating/configuring TUN.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunSetupCommandPlan {
    pub commands: Vec<TunSetupCommand>,
    pub file_writes: Vec<TunSetupFileWrite>,
    pub broker_dns: IpAddr,
    pub proxy_environment: Option<ProxyExposure>,
}

/// One setup-helper file write needed inside the sandbox network namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunSetupFileWrite {
    pub path: PathBuf,
    pub contents: String,
}

/// Linux `ip`-based TUN setup planner for the privileged `foxproxsetup` helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxIpTunSetup;

impl LinuxIpTunSetup {
    pub fn plan_commands(
        request: &NetworkSetupRequest,
    ) -> Result<TunSetupCommandPlan, IntegrationError> {
        validate_request(request)?;
        let family_flag = if request.tun.broker_ip.is_ipv6() {
            Some("-6")
        } else {
            None
        };
        if request.tun.broker_ip.is_ipv4() != request.tun.sandbox_ip.is_ipv4() {
            return Err(IntegrationError::MismatchedTunAddressFamilies);
        }

        let mut addr_args = Vec::new();
        if let Some(flag) = family_flag {
            addr_args.push(flag.to_string());
        }
        addr_args.extend([
            "addr".to_string(),
            "add".to_string(),
            request.tun.broker_ip.to_string(),
            "peer".to_string(),
            request.tun.sandbox_ip.to_string(),
            "dev".to_string(),
            request.tun.name.clone(),
        ]);

        let mut route_args = Vec::new();
        if let Some(flag) = family_flag {
            route_args.push(flag.to_string());
        }
        route_args.extend([
            "route".to_string(),
            "replace".to_string(),
            "default".to_string(),
            "dev".to_string(),
            request.tun.name.clone(),
        ]);

        Ok(TunSetupCommandPlan {
            broker_dns: request.broker_dns,
            proxy_environment: request.proxy.clone(),
            file_writes: vec![TunSetupFileWrite {
                path: PathBuf::from("/etc/resolv.conf"),
                contents: format!("nameserver {}\n", request.broker_dns),
            }],
            commands: vec![
                TunSetupCommand {
                    program: "ip".to_string(),
                    args: vec![
                        "tuntap".to_string(),
                        "add".to_string(),
                        "dev".to_string(),
                        request.tun.name.clone(),
                        "mode".to_string(),
                        "tun".to_string(),
                    ],
                },
                TunSetupCommand {
                    program: "ip".to_string(),
                    args: addr_args,
                },
                TunSetupCommand {
                    program: "ip".to_string(),
                    args: vec![
                        "link".to_string(),
                        "set".to_string(),
                        "dev".to_string(),
                        request.tun.name.clone(),
                        "mtu".to_string(),
                        request.tun.mtu.to_string(),
                        "up".to_string(),
                    ],
                },
                TunSetupCommand {
                    program: "ip".to_string(),
                    args: route_args,
                },
            ],
        })
    }
}

/// bwrap-compatible alpha backend. It constructs the command convention where
/// bwrap runs `foxproxsetup -- target args...` with temporary CAP_NET_ADMIN.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwrapBackend {
    foxproxsetup_program: String,
}

impl BwrapBackend {
    pub fn new(foxproxsetup_program: impl Into<String>) -> Self {
        Self {
            foxproxsetup_program: foxproxsetup_program.into(),
        }
    }

    pub fn bwrap_prefix_args(&self) -> Vec<String> {
        vec![
            "--unshare-user".to_string(),
            "--unshare-net".to_string(),
            "--cap-add".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--dev-bind".to_string(),
            "/dev/net/tun".to_string(),
            "/dev/net/tun".to_string(),
        ]
    }
}

impl IntegrationBackend for BwrapBackend {
    fn plan(&self, request: NetworkSetupRequest) -> Result<NetworkSetupPlan, IntegrationError> {
        validate_request(&request)?;
        Ok(NetworkSetupPlan {
            sandbox_id: request.sandbox_id,
            required_capabilities: vec![SetupCapability::CapNetAdmin],
            required_devices: vec![PathBuf::from("/dev/net/tun")],
            setup_helper: Some(SetupHelperPlan {
                program: self.foxproxsetup_program.clone(),
                args_before_target: vec![
                    "--tun-name".to_string(),
                    request.tun.name,
                    "--sandbox-ip".to_string(),
                    request.tun.sandbox_ip.to_string(),
                    "--broker-ip".to_string(),
                    request.tun.broker_ip.to_string(),
                    "--mtu".to_string(),
                    request.tun.mtu.to_string(),
                    "--dns".to_string(),
                    request.broker_dns.to_string(),
                    "--".to_string(),
                ],
            }),
            proxy_environment: request.proxy,
        })
    }
}

/// Backend for callers that provide an already-created namespace/setup path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalNamespaceBackend;

impl IntegrationBackend for ExternalNamespaceBackend {
    fn plan(&self, request: NetworkSetupRequest) -> Result<NetworkSetupPlan, IntegrationError> {
        validate_request(&request)?;
        Ok(NetworkSetupPlan {
            sandbox_id: request.sandbox_id,
            required_capabilities: Vec::new(),
            required_devices: Vec::new(),
            setup_helper: None,
            proxy_environment: request.proxy,
        })
    }
}

/// Executor boundary for a trusted setup helper applying a data-only TUN plan.
pub trait TunSetupExecutor {
    fn run_command(&mut self, command: &TunSetupCommand) -> Result<(), IntegrationError>;
    fn write_file(&mut self, file: &TunSetupFileWrite) -> Result<(), IntegrationError>;
}

/// Apply setup-helper file writes and commands in deterministic order.
pub fn execute_tun_setup_plan<E>(
    plan: &TunSetupCommandPlan,
    executor: &mut E,
) -> Result<(), IntegrationError>
where
    E: TunSetupExecutor,
{
    for file in &plan.file_writes {
        executor.write_file(file)?;
    }
    for command in &plan.commands {
        executor.run_command(command)?;
    }
    Ok(())
}

/// Standard setup-helper executor. It is intentionally in integrations, not in
/// runtime or broker core.
#[derive(Clone, Debug, Default)]
pub struct StdTunSetupExecutor;

impl TunSetupExecutor for StdTunSetupExecutor {
    fn run_command(&mut self, command: &TunSetupCommand) -> Result<(), IntegrationError> {
        let status = Command::new(&command.program)
            .args(&command.args)
            .status()
            .map_err(|error| IntegrationError::CommandFailed {
                program: command.program.clone(),
                status: error.to_string(),
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(IntegrationError::CommandFailed {
                program: command.program.clone(),
                status: status.to_string(),
            })
        }
    }

    fn write_file(&mut self, file: &TunSetupFileWrite) -> Result<(), IntegrationError> {
        std::fs::write(&file.path, file.contents.as_bytes()).map_err(|error| {
            IntegrationError::FileWriteFailed {
                path: file.path.clone(),
                reason: error.to_string(),
            }
        })
    }
}

fn validate_request(request: &NetworkSetupRequest) -> Result<(), IntegrationError> {
    if request.tun.name.trim().is_empty() {
        return Err(IntegrationError::InvalidTunName);
    }
    if request.tun.mtu < 576 {
        return Err(IntegrationError::InvalidMtu(request.tun.mtu));
    }
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IntegrationError {
    InvalidTunName,
    InvalidMtu(u16),
    MismatchedTunAddressFamilies,
    CommandFailed { program: String, status: String },
    FileWriteFailed { path: PathBuf, reason: String },
}

impl fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTunName => f.write_str("TUN name must not be empty"),
            Self::InvalidMtu(mtu) => write!(f, "invalid MTU {mtu}"),
            Self::MismatchedTunAddressFamilies => {
                f.write_str("TUN broker and sandbox address families must match")
            }
            Self::CommandFailed { program, status } => {
                write!(f, "setup command {program} failed: {status}")
            }
            Self::FileWriteFailed { path, reason } => {
                write!(f, "setup file write {} failed: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for IntegrationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingExecutor {
        operations: Vec<String>,
        fail_program: Option<String>,
    }

    impl TunSetupExecutor for RecordingExecutor {
        fn run_command(&mut self, command: &TunSetupCommand) -> Result<(), IntegrationError> {
            self.operations.push(format!(
                "cmd:{} {}",
                command.program,
                command.args.join(" ")
            ));
            if self.fail_program.as_deref() == Some(command.program.as_str()) {
                Err(IntegrationError::CommandFailed {
                    program: command.program.clone(),
                    status: "mock failure".to_string(),
                })
            } else {
                Ok(())
            }
        }

        fn write_file(&mut self, file: &TunSetupFileWrite) -> Result<(), IntegrationError> {
            self.operations.push(format!(
                "file:{}={}",
                file.path.display(),
                file.contents.trim_end()
            ));
            Ok(())
        }
    }

    fn request() -> NetworkSetupRequest {
        NetworkSetupRequest {
            sandbox_id: SandboxId::new("s1").unwrap(),
            tun: TunDeviceConfig::alpha_default(),
            broker_dns: "10.255.0.1".parse().unwrap(),
            proxy: Some(ProxyExposure {
                http_proxy: "http://10.255.0.1:8080".to_string(),
                https_proxy: "http://10.255.0.1:8080".to_string(),
                all_proxy: "socks5://10.255.0.1:1080".to_string(),
                no_proxy: "localhost,127.0.0.1".to_string(),
            }),
        }
    }

    #[test]
    fn bwrap_plan_owns_bwrap_specific_details() {
        let backend = BwrapBackend::new("foxproxsetup");
        let plan = backend.plan(request()).unwrap();
        let helper = plan.setup_helper.unwrap();

        assert_eq!(
            plan.required_capabilities,
            vec![SetupCapability::CapNetAdmin]
        );
        assert_eq!(plan.required_devices, vec![PathBuf::from("/dev/net/tun")]);
        assert_eq!(helper.program, "foxproxsetup");
        assert!(helper.args_before_target.contains(&"--".to_string()));
        assert!(backend
            .bwrap_prefix_args()
            .contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn linux_tun_setup_plan_owns_privileged_ip_commands() {
        let plan = LinuxIpTunSetup::plan_commands(&request()).unwrap();

        assert_eq!(plan.broker_dns, "10.255.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(plan.commands[0].program, "ip");
        assert_eq!(
            plan.commands[0].args,
            vec!["tuntap", "add", "dev", "foxprox0", "mode", "tun"]
        );
        assert_eq!(
            plan.commands[1].args,
            vec![
                "addr",
                "add",
                "10.255.0.1",
                "peer",
                "10.255.0.2",
                "dev",
                "foxprox0"
            ]
        );
        assert_eq!(
            plan.commands[2].args,
            vec!["link", "set", "dev", "foxprox0", "mtu", "1500", "up"]
        );
        assert_eq!(
            plan.commands[3].args,
            vec!["route", "replace", "default", "dev", "foxprox0"]
        );
        assert_eq!(plan.file_writes[0].path, PathBuf::from("/etc/resolv.conf"));
        assert_eq!(plan.file_writes[0].contents, "nameserver 10.255.0.1\n");
        assert!(plan.proxy_environment.is_some());
    }

    #[test]
    fn setup_executor_applies_files_before_commands_and_translates_errors() {
        let plan = LinuxIpTunSetup::plan_commands(&request()).unwrap();
        let mut executor = RecordingExecutor::default();

        execute_tun_setup_plan(&plan, &mut executor).unwrap();

        assert!(executor.operations[0].starts_with("file:/etc/resolv.conf"));
        assert!(executor.operations[1].starts_with("cmd:ip tuntap add"));

        let mut failing = RecordingExecutor {
            fail_program: Some("ip".to_string()),
            ..RecordingExecutor::default()
        };
        let error = execute_tun_setup_plan(&plan, &mut failing).unwrap_err();
        assert!(matches!(error, IntegrationError::CommandFailed { .. }));
    }

    #[test]
    fn linux_tun_setup_rejects_mismatched_address_families() {
        let mut request = request();
        request.tun.sandbox_ip = "2001:db8::2".parse().unwrap();

        assert_eq!(
            LinuxIpTunSetup::plan_commands(&request).unwrap_err(),
            IntegrationError::MismatchedTunAddressFamilies
        );
    }

    #[test]
    fn external_namespace_plan_is_backend_neutral() {
        let plan = ExternalNamespaceBackend.plan(request()).unwrap();
        assert!(plan.required_capabilities.is_empty());
        assert!(plan.setup_helper.is_none());
        assert!(plan.proxy_environment.is_some());
    }
}
