use crate::audit::AuditRecord;
use crate::policy::{PolicyConfig, PolicyConfigError};
use crate::setup::NetworkSetupConfig;
use crate::types::{AuditKind, Decision, DenialReason, Frontend};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRuntimeConfig {
    pub setup: NetworkSetupConfig,
    pub policy: PolicyConfig,
    pub audit_capacity: usize,
    pub dns_upstream: SocketAddr,
    pub proxy_listeners: ProxyListenerConfig,
    pub resource_limits: ResourceLimitConfig,
}

impl BrokerRuntimeConfig {
    pub fn alpha_default(sandbox_id: impl Into<String>) -> Self {
        Self {
            setup: NetworkSetupConfig::alpha_default(sandbox_id),
            policy: PolicyConfig::default(),
            audit_capacity: 1024,
            dns_upstream: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            proxy_listeners: ProxyListenerConfig::default(),
            resource_limits: ResourceLimitConfig::default(),
        }
    }

    pub fn validate(&self) -> Result<(), Vec<RuntimeConfigError>> {
        let mut errors = Vec::new();
        if self.setup.sandbox_id.trim().is_empty() {
            errors.push(RuntimeConfigError::new(
                "sandbox_id_empty",
                "setup.sandbox_id",
                "sandbox ID is required for audit attribution",
            ));
        }
        if self.setup.tun_name.trim().is_empty() {
            errors.push(RuntimeConfigError::new(
                "tun_name_empty",
                "setup.tun_name",
                "TUN name must be non-empty",
            ));
        }
        if self.setup.mtu < 576 {
            errors.push(RuntimeConfigError::new(
                "mtu_too_small",
                "setup.mtu",
                "MTU must be at least the IPv4 minimum reassembly size",
            ));
        }
        if self.setup.http_proxy_port == 0 {
            errors.push(RuntimeConfigError::new(
                "http_proxy_port_zero",
                "setup.http_proxy_port",
                "HTTP proxy port must be non-zero",
            ));
        }
        if self.setup.socks_proxy_port == 0 {
            errors.push(RuntimeConfigError::new(
                "socks_proxy_port_zero",
                "setup.socks_proxy_port",
                "SOCKS proxy port must be non-zero",
            ));
        }
        if self.setup.setup_control_fd.is_some_and(|fd| fd < 0) {
            errors.push(RuntimeConfigError::new(
                "setup_control_fd_negative",
                "setup.setup_control_fd",
                "setup control fd must be a non-negative inherited descriptor",
            ));
        }
        if self.audit_capacity == 0 {
            errors.push(RuntimeConfigError::new(
                "audit_capacity_zero",
                "audit_capacity",
                "audit capacity must be greater than zero",
            ));
        }
        if self.dns_upstream.port() == 0 {
            errors.push(RuntimeConfigError::new(
                "dns_upstream_port_zero",
                "dns_upstream",
                "DNS upstream socket address must include a non-zero port",
            ));
        }
        if self.proxy_listeners.http_enabled
            && self.setup.http_proxy_port == self.setup.socks_proxy_port
        {
            errors.push(RuntimeConfigError::new(
                "proxy_port_conflict",
                "setup.http_proxy_port",
                "HTTP and SOCKS proxy listeners must not share the same port when enabled",
            ));
        }
        if self.resource_limits.udp_max_active_flows == Some(0) {
            errors.push(RuntimeConfigError::new(
                "udp_flow_limit_zero",
                "resource_limits.udp_max_active_flows",
                "UDP active-flow limit must be omitted or greater than zero",
            ));
        }
        if let Err(policy_errors) = self.policy.validate() {
            errors.extend(policy_errors.into_iter().map(RuntimeConfigError::from));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn validation_audit(&self) -> AuditRecord {
        match self.validate() {
            Ok(()) => AuditRecord::new(AuditKind::BrokerStarted, self.setup.sandbox_id.clone())
                .with_frontend(Frontend::Core)
                .with_decision(Decision::Allow, None)
                .with_detail("audit_capacity", self.audit_capacity.to_string())
                .with_detail("dns_upstream", self.dns_upstream.to_string())
                .with_detail(
                    "http_proxy_enabled",
                    self.proxy_listeners.http_enabled.to_string(),
                )
                .with_detail(
                    "socks_proxy_enabled",
                    self.proxy_listeners.socks_enabled.to_string(),
                )
                .with_detail(
                    "udp_max_active_flows",
                    self.resource_limits
                        .udp_max_active_flows
                        .map(|limit| limit.to_string())
                        .unwrap_or_else(|| "unlimited".to_string()),
                ),
            Err(errors) => AuditRecord::new(AuditKind::BrokerError, self.setup.sandbox_id.clone())
                .with_frontend(Frontend::Core)
                .with_decision(Decision::FailClosed, Some(DenialReason::PolicyConfig))
                .with_detail("error_count", errors.len().to_string())
                .with_detail(
                    "error_codes",
                    errors
                        .iter()
                        .map(|error| error.code.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyListenerConfig {
    pub http_enabled: bool,
    pub socks_enabled: bool,
}

impl Default for ProxyListenerConfig {
    fn default() -> Self {
        Self {
            http_enabled: true,
            socks_enabled: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimitConfig {
    pub udp_max_active_flows: Option<usize>,
}

impl Default for ResourceLimitConfig {
    fn default() -> Self {
        Self {
            udp_max_active_flows: Some(1024),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfigError {
    pub code: String,
    pub field: String,
    pub detail: String,
}

impl RuntimeConfigError {
    fn new(code: impl Into<String>, field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            field: field.into(),
            detail: detail.into(),
        }
    }
}

impl From<PolicyConfigError> for RuntimeConfigError {
    fn from(error: PolicyConfigError) -> Self {
        Self {
            code: format!("policy_{}", error.code),
            field: format!("policy.{}", error.field),
            detail: error.detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn runtime_config_serializes_stable_alpha_fields_and_audit() {
        let config = BrokerRuntimeConfig::alpha_default("s1");
        config.validate().unwrap();
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(value["setup"]["sandbox_id"], "s1");
        assert_eq!(value["audit_capacity"], 1024);
        assert_eq!(value["dns_upstream"], "1.1.1.1:53");
        assert_eq!(value["proxy_listeners"]["http_enabled"], true);
        assert_eq!(value["resource_limits"]["udp_max_active_flows"], 1024);

        let audit = config.validation_audit();
        assert_eq!(audit.kind, AuditKind::BrokerStarted);
        assert_eq!(audit.decision, Some(Decision::Allow));
        assert_eq!(audit.details["audit_capacity"], "1024");
        assert_eq!(audit.details["dns_upstream"], "1.1.1.1:53");
        assert_eq!(audit.details["udp_max_active_flows"], "1024");
    }

    #[test]
    fn runtime_config_validation_reports_setup_policy_and_limit_errors() {
        let mut config = BrokerRuntimeConfig::alpha_default("s1");
        config.setup.sandbox_id = " ".to_string();
        config.setup.tun_name.clear();
        config.setup.mtu = 500;
        config.setup.http_proxy_port = 1080;
        config.setup.socks_proxy_port = 1080;
        config.setup.setup_control_fd = Some(-1);
        config.audit_capacity = 0;
        config.dns_upstream = "1.1.1.1:0".parse().unwrap();
        config.resource_limits.udp_max_active_flows = Some(0);
        config.policy.broker_dns.clear();

        let errors = config.validate().unwrap_err();
        let codes: Vec<_> = errors.iter().map(|error| error.code.as_str()).collect();
        assert!(codes.contains(&"sandbox_id_empty"));
        assert!(codes.contains(&"tun_name_empty"));
        assert!(codes.contains(&"mtu_too_small"));
        assert!(codes.contains(&"proxy_port_conflict"));
        assert!(codes.contains(&"setup_control_fd_negative"));
        assert!(codes.contains(&"audit_capacity_zero"));
        assert!(codes.contains(&"dns_upstream_port_zero"));
        assert!(codes.contains(&"udp_flow_limit_zero"));
        assert!(codes.contains(&"policy_broker_dns_empty"));

        let audit = config.validation_audit();
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::PolicyConfig));
        assert!(audit.details["error_codes"].contains("policy_broker_dns_empty"));
    }
}
