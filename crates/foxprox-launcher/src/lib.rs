//! Host-side launcher preparation for bwrap-compatible network setup.
//!
//! This crate joins integration planning with the host-side setup control
//! socket. It still does not execute bwrap; process spawning must preserve the
//! helper fd and fail closed if handoff does not complete.

#![forbid(unsafe_code)]

use foxprox_device::{DeviceError, SetupControlSocket};
use foxprox_integrations::{BwrapSetupCommand, IntegrationError, SetupPlan};
use std::fs::File;

#[derive(Debug)]
pub struct PreparedBwrapLaunch {
    pub command: BwrapSetupCommand,
    control: SetupControlSocket,
}

impl PreparedBwrapLaunch {
    pub fn helper_fd(&self) -> u32 {
        self.control.helper_fd() as u32
    }

    pub fn receive_tun_file(&self) -> Result<File, LauncherError> {
        self.control.receive_file().map_err(LauncherError::Device)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LauncherError {
    Device(DeviceError),
    Integration(IntegrationError),
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

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::SandboxId;
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
