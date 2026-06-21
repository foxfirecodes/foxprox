//! Platform integration planning types.
//!
//! This crate builds auditable setup plans for launchers. It does not execute
//! bwrap or configure Linux networking yet; execution backends must fail early
//! if any required plan item cannot be applied.

#![forbid(unsafe_code)]

use foxprox_core::SandboxId;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunDeviceConfig {
    pub name: String,
    pub sandbox_ip: IpAddr,
    pub broker_ip: IpAddr,
    pub mtu: u16,
}

impl TunDeviceConfig {
    pub fn validate(&self) -> Result<(), IntegrationError> {
        if self.name.trim().is_empty() {
            return Err(IntegrationError::EmptyTunName);
        }
        if self.mtu < 576 {
            return Err(IntegrationError::MtuTooSmall { mtu: self.mtu });
        }
        if std::mem::discriminant(&self.sandbox_ip) != std::mem::discriminant(&self.broker_ip) {
            return Err(IntegrationError::AddressFamilyMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupPlan {
    pub sandbox_id: SandboxId,
    pub tun: TunDeviceConfig,
    pub dns_resolver: IpAddr,
    pub proxy_listener: Option<ProxyListenerConfig>,
    pub tun_handoff_fd: u32,
}

impl SetupPlan {
    pub fn validate(&self) -> Result<(), IntegrationError> {
        self.tun.validate()?;
        if std::mem::discriminant(&self.dns_resolver) != std::mem::discriminant(&self.tun.broker_ip)
        {
            return Err(IntegrationError::AddressFamilyMismatch);
        }
        if let Some(proxy) = &self.proxy_listener {
            proxy.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyListenerConfig {
    pub ip: IpAddr,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
}

impl ProxyListenerConfig {
    pub fn validate(&self) -> Result<(), IntegrationError> {
        if self.http_port == Some(0) || self.socks_port == Some(0) {
            return Err(IntegrationError::InvalidProxyPort);
        }
        if self.http_port.is_none() && self.socks_port.is_none() {
            return Err(IntegrationError::NoProxyPorts);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwrapSetupCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl BwrapSetupCommand {
    pub fn build(plan: &SetupPlan, target: &[String]) -> Result<Self, IntegrationError> {
        plan.validate()?;
        if target.is_empty() {
            return Err(IntegrationError::MissingTarget);
        }
        let mut args = vec![
            "--unshare-user".to_string(),
            "--unshare-net".to_string(),
            "--cap-add".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--dev-bind".to_string(),
            "/dev/net/tun".to_string(),
            "/dev/net/tun".to_string(),
            "foxproxsetup".to_string(),
            "--sandbox-id".to_string(),
            plan.sandbox_id.to_string(),
            "--tun-name".to_string(),
            plan.tun.name.clone(),
            "--sandbox-ip".to_string(),
            plan.tun.sandbox_ip.to_string(),
            "--broker-ip".to_string(),
            plan.tun.broker_ip.to_string(),
            "--mtu".to_string(),
            plan.tun.mtu.to_string(),
            "--dns".to_string(),
            plan.dns_resolver.to_string(),
            "--handoff-fd".to_string(),
            plan.tun_handoff_fd.to_string(),
        ];
        if let Some(proxy) = &plan.proxy_listener {
            args.push("--proxy-ip".to_string());
            args.push(proxy.ip.to_string());
            if let Some(port) = proxy.http_port {
                args.push("--http-proxy-port".to_string());
                args.push(port.to_string());
            }
            if let Some(port) = proxy.socks_port {
                args.push("--socks-proxy-port".to_string());
                args.push(port.to_string());
            }
        }
        args.push("--".to_string());
        args.extend(target.iter().cloned());
        Ok(Self {
            program: "bwrap".to_string(),
            args,
        })
    }

    pub fn contains_required_network_isolation(&self) -> bool {
        self.args.iter().any(|arg| arg == "--unshare-net")
            && self
                .args
                .windows(2)
                .any(|pair| pair == ["--cap-add", "CAP_NET_ADMIN"])
            && self
                .args
                .windows(3)
                .any(|triple| triple == ["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrationError {
    EmptyTunName,
    MtuTooSmall { mtu: u16 },
    AddressFamilyMismatch,
    InvalidProxyPort,
    NoProxyPorts,
    MissingTarget,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn plan() -> SetupPlan {
        SetupPlan {
            sandbox_id: SandboxId::new("bwrap-test").unwrap(),
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
            tun_handoff_fd: 3,
        }
    }

    #[test]
    fn bwrap_command_contains_required_network_setup_shape() {
        let command = BwrapSetupCommand::build(&plan(), &["curl".to_string()]).unwrap();
        assert_eq!(command.program, "bwrap");
        assert!(command.contains_required_network_isolation());
        assert!(command.args.iter().any(|arg| arg == "foxproxsetup"));
        assert!(command
            .args
            .windows(2)
            .any(|pair| pair == ["--handoff-fd", "3"]));
        assert_eq!(command.args.last().map(String::as_str), Some("curl"));
    }

    #[test]
    fn setup_plan_rejects_missing_target() {
        assert_eq!(
            BwrapSetupCommand::build(&plan(), &[]).unwrap_err(),
            IntegrationError::MissingTarget
        );
    }

    #[test]
    fn setup_plan_rejects_too_small_mtu() {
        let mut plan = plan();
        plan.tun.mtu = 128;
        assert_eq!(
            BwrapSetupCommand::build(&plan, &["true".to_string()]).unwrap_err(),
            IntegrationError::MtuTooSmall { mtu: 128 }
        );
    }
}
