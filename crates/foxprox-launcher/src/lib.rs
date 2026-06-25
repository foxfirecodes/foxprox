//! Host-side launcher preparation for bwrap-compatible network setup.
//!
//! This crate joins integration planning with the host-side setup control
//! socket. It still does not execute bwrap; process spawning must preserve the
//! helper fd and fail closed if handoff does not complete.

#![forbid(unsafe_code)]

use foxprox_device::{DeviceError, SetupControlSocket, SetupControlSocketListener};
use foxprox_integrations::{BwrapSetupCommand, IntegrationError, SetupPlan};
use foxprox_runtime::{
    build_runtime_components, BrokerRuntimeComponents, BrokerRuntimeConfig, RuntimeConfigError,
};
use std::fs::File;
use std::path::Path;

#[derive(Debug)]
pub struct PreparedBwrapLaunch {
    pub command: BwrapSetupCommand,
    control: SetupControlSocket,
}

#[derive(Debug)]
pub struct PreparedBwrapSocketLaunch {
    pub command: BwrapSetupCommand,
    control: SetupControlSocketListener,
}

impl PreparedBwrapLaunch {
    pub fn helper_fd(&self) -> u32 {
        self.control.helper_fd() as u32
    }

    pub fn spawn_spec(&self) -> BwrapSpawnSpec {
        BwrapSpawnSpec {
            program: self.command.program.clone(),
            args: self.command.args.clone(),
            preserve_fds: vec![self.helper_fd()],
        }
    }

    pub fn receive_tun_file(&self) -> Result<File, LauncherError> {
        self.control.receive_file().map_err(LauncherError::Device)
    }
}

impl PreparedBwrapSocketLaunch {
    pub fn socket_path(&self) -> &Path {
        self.control.path()
    }

    pub fn spawn_spec(&self) -> BwrapSpawnSpec {
        BwrapSpawnSpec {
            program: self.command.program.clone(),
            args: self.command.args.clone(),
            preserve_fds: Vec::new(),
        }
    }

    pub fn receive_tun_file(&self) -> Result<File, LauncherError> {
        self.control.receive_file().map_err(LauncherError::Device)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwrapSpawnSpec {
    pub program: String,
    pub args: Vec<String>,
    pub preserve_fds: Vec<u32>,
}

impl BwrapSpawnSpec {
    pub fn preserves_helper_fd_referenced_by_args(&self) -> bool {
        self.preserve_fds.iter().any(|fd| {
            self.args
                .windows(2)
                .any(|pair| pair[0] == "--handoff-fd" && pair[1] == fd.to_string())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LauncherError {
    Device(DeviceError),
    Integration(IntegrationError),
    RuntimeConfig(RuntimeConfigError),
    InvalidHelperFd { fd: i32 },
}

impl From<DeviceError> for LauncherError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

impl From<IntegrationError> for LauncherError {
    fn from(error: IntegrationError) -> Self {
        Self::Integration(error)
    }
}

pub struct PreparedBrokerSession {
    pub launch: PreparedBwrapLaunch,
    pub runtime: BrokerRuntimeComponents,
}

pub fn prepare_bwrap_broker_session(
    setup_plan: SetupPlan,
    target: &[String],
    runtime_config: BrokerRuntimeConfig,
) -> Result<PreparedBrokerSession, LauncherError> {
    let runtime = build_runtime_components(runtime_config).map_err(LauncherError::RuntimeConfig)?;
    let launch = prepare_bwrap_launch(setup_plan, target)?;
    Ok(PreparedBrokerSession { launch, runtime })
}

pub fn prepare_bwrap_launch(
    mut plan: SetupPlan,
    target: &[String],
) -> Result<PreparedBwrapLaunch, LauncherError> {
    let control = SetupControlSocket::pair()?;
    let helper_fd = control.helper_fd();
    if helper_fd < 0 {
        return Err(LauncherError::InvalidHelperFd { fd: helper_fd });
    }
    plan.tun_handoff_fd = helper_fd as u32;
    let command = BwrapSetupCommand::build(&plan, target)?;
    Ok(PreparedBwrapLaunch { command, control })
}

pub fn prepare_bwrap_launch_with_socket_path(
    mut plan: SetupPlan,
    target: &[String],
    socket_path: impl AsRef<Path>,
) -> Result<PreparedBwrapSocketLaunch, LauncherError> {
    let socket_path = socket_path.as_ref();
    let control = SetupControlSocketListener::bind(socket_path)?;
    plan.tun_handoff_fd = 0;
    let command = BwrapSetupCommand::build_with_handoff_socket(&plan, target, socket_path)?;
    Ok(PreparedBwrapSocketLaunch { command, control })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{PolicyConfig, PolicyRule, SandboxId, StaticDnsRecord};
    use foxprox_integrations::{ProxyListenerConfig, TunDeviceConfig};
    use std::net::{IpAddr, Ipv4Addr};

    fn plan() -> SetupPlan {
        SetupPlan {
            sandbox_id: SandboxId::new("launcher-test").unwrap(),
            tun: TunDeviceConfig {
                name: "foxprox0".to_string(),
                sandbox_ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
                broker_ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
                mtu: 1500,
            },
            dns_resolver: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
            proxy_listener: Some(ProxyListenerConfig {
                ip: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
                http_port: Some(3128),
                socks_port: Some(1080),
            }),
            tun_handoff_fd: 0,
        }
    }

    fn runtime_config() -> BrokerRuntimeConfig {
        BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("launcher-runtime").unwrap(),
            policy: PolicyConfig {
                broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
                ..PolicyConfig::default()
            },
            static_dns_ttl_secs: 30,
            static_dns_records: vec![StaticDnsRecord {
                hostname: foxprox_core::Hostname::normalize("example.com").unwrap(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            }],
            tcp_max_open_flows: 64,
            tcp_metadata_buffer_bytes: 4096,
        }
    }

    #[test]
    fn prepared_broker_session_combines_launch_and_runtime_components() {
        let prepared =
            prepare_bwrap_broker_session(plan(), &["curl".to_string()], runtime_config()).unwrap();

        assert!(prepared
            .launch
            .command
            .contains_required_network_isolation());
        assert_eq!(prepared.runtime.sandbox_id.as_str(), "launcher-runtime");
        assert_eq!(
            prepared.runtime.broker_dns,
            vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))]
        );
        assert_eq!(prepared.runtime.tcp_max_open_flows, 64);
    }

    #[test]
    fn broker_session_rejects_runtime_config_before_launch_preparation() {
        let mut invalid_runtime = runtime_config();
        let mut rules = foxprox_core::RuleSet::default();
        rules.push(PolicyRule::allow("same"));
        rules.push(PolicyRule::deny_drop("same"));
        invalid_runtime.policy.rules = rules;

        assert!(matches!(
            prepare_bwrap_broker_session(plan(), &["curl".to_string()], invalid_runtime),
            Err(LauncherError::RuntimeConfig(
                RuntimeConfigError::InvalidPolicy(_)
            ))
        ));
    }

    #[test]
    fn bwrap_spawn_spec_records_helper_fd_preservation_requirement() {
        let prepared = prepare_bwrap_launch(plan(), &["curl".to_string()]).unwrap();
        let spec = prepared.spawn_spec();

        assert_eq!(spec.program, "bwrap");
        assert_eq!(spec.preserve_fds, vec![prepared.helper_fd()]);
        assert!(spec.preserves_helper_fd_referenced_by_args());
    }

    #[test]
    fn prepared_bwrap_launch_injects_live_handoff_fd() {
        let prepared = prepare_bwrap_launch(plan(), &["curl".to_string()]).unwrap();
        let helper_fd = prepared.helper_fd().to_string();

        assert!(prepared
            .command
            .args
            .windows(2)
            .any(|pair| pair == ["--handoff-fd", helper_fd.as_str()]));
        assert_eq!(
            prepared.command.args.last().map(String::as_str),
            Some("curl")
        );
    }

    #[test]
    fn prepared_bwrap_socket_launch_uses_path_handoff_without_preserved_fds() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-launcher-{}-socket.sock",
            std::process::id()
        ));
        let prepared =
            prepare_bwrap_launch_with_socket_path(plan(), &["true".to_string()], &path).unwrap();
        let spec = prepared.spawn_spec();

        assert_eq!(prepared.socket_path(), path.as_path());
        assert!(spec.preserve_fds.is_empty());
        assert!(spec
            .args
            .windows(2)
            .any(|pair| pair == ["--handoff-socket", path.to_string_lossy().as_ref()]));
        assert!(!spec.args.iter().any(|arg| arg == "--handoff-fd"));
        assert!(prepared.command.contains_required_network_isolation());
    }

    #[test]
    fn prepared_bwrap_launch_preserves_network_isolation_shape() {
        let prepared = prepare_bwrap_launch(plan(), &["true".to_string()]).unwrap();
        assert!(prepared.command.contains_required_network_isolation());
        assert!(prepared
            .command
            .args
            .iter()
            .any(|arg| arg == "foxproxsetup"));
    }

    #[test]
    fn prepared_bwrap_launch_rejects_invalid_plan_before_command() {
        let mut plan = plan();
        plan.tun.mtu = 42;
        assert!(matches!(
            prepare_bwrap_launch(plan, &["true".to_string()]),
            Err(LauncherError::Integration(IntegrationError::MtuTooSmall {
                mtu: 42
            }))
        ));
    }
}
