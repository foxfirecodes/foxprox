//! Platform-independent broker configuration data.

use crate::audit::AuditSinkConfig;
use crate::event::SandboxId;
use crate::flow::FlowTimeoutClass;
use crate::policy::PolicyRuleSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Top-level broker configuration shared by future frontends/backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConfig {
    /// Sandbox/session identifier.
    pub sandbox_id: SandboxId,
    /// TUN-facing network configuration.
    pub tun: TunConfig,
    /// DNS configuration.
    pub dns: DnsConfig,
    /// Explicit proxy listener configuration.
    pub proxy: ProxyConfig,
    /// UDP pseudo-flow timeout configuration.
    pub udp_timeouts: UdpTimeoutConfig,
    /// Policy rules and default behavior.
    pub policy: PolicyRuleSet,
    /// Audit sink configuration.
    pub audit: AuditSinkConfig,
    /// Resource limits for bounded alpha runtime behavior.
    pub resource_limits: ResourceLimitConfig,
}

impl BrokerConfig {
    /// Creates a broker config with safe defaults for a sandbox identifier.
    pub fn new(sandbox_id: SandboxId) -> Self {
        let tun = TunConfig::default();
        let mut policy = PolicyRuleSet::default();
        if let Some(broadcast) = tun.directed_broadcast() {
            policy.broadcast_addresses.push(broadcast);
        }
        Self {
            sandbox_id,
            tun,
            dns: DnsConfig::default(),
            proxy: ProxyConfig::default(),
            udp_timeouts: UdpTimeoutConfig::default(),
            policy,
            audit: AuditSinkConfig::default(),
            resource_limits: ResourceLimitConfig::default(),
        }
    }
}

/// TUN-facing network settings as data only.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TunConfig {
    /// Sandbox-side interface address.
    pub sandbox_ip: IpAddr,
    /// Broker/gateway address reachable from the sandbox.
    pub broker_ip: IpAddr,
    /// Prefix length for the sandbox network.
    pub prefix_len: u8,
    /// Interface MTU.
    pub mtu: u16,
}

impl TunConfig {
    /// Returns the IPv4 directed broadcast address for this TUN network, when applicable.
    pub fn directed_broadcast(&self) -> Option<IpAddr> {
        let IpAddr::V4(ip) = self.sandbox_ip else {
            return None;
        };
        if self.prefix_len > 32 {
            return None;
        }
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        Some(IpAddr::V4((u32::from(ip) | !mask).into()))
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            sandbox_ip: IpAddr::from([10, 255, 0, 2]),
            broker_ip: IpAddr::from([10, 255, 0, 1]),
            prefix_len: 24,
            mtu: 1500,
        }
    }
}

/// DNS resolver configuration.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsConfig {
    /// Resolver address exposed to the sandbox.
    pub broker_resolver: SocketAddr,
    /// Upstream resolver used by the broker.
    pub upstream_resolver: SocketAddr,
    /// Deny direct external DNS by default.
    pub deny_direct_external_dns: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            broker_resolver: SocketAddr::from(([10, 255, 0, 1], 53)),
            upstream_resolver: SocketAddr::from(([1, 1, 1, 1], 53)),
            deny_direct_external_dns: true,
        }
    }
}

/// Explicit proxy listener configuration.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProxyConfig {
    /// HTTP proxy listener reachable from the sandbox.
    pub http_proxy: Option<SocketAddr>,
    /// HTTPS CONNECT proxy listener reachable from the sandbox.
    pub https_proxy: Option<SocketAddr>,
    /// SOCKS5 listener reachable from the sandbox.
    pub socks5_proxy: Option<SocketAddr>,
    /// NO_PROXY value to inject when desired.
    pub no_proxy: Vec<String>,
}

impl ProxyConfig {
    /// Returns proxy environment variable values for sandbox injection.
    pub fn environment(&self) -> ProxyEnvironment {
        ProxyEnvironment {
            http_proxy: self.http_proxy.map(|addr| format!("http://{addr}")),
            https_proxy: self.https_proxy.map(|addr| format!("http://{addr}")),
            all_proxy: self.socks5_proxy.map(|addr| format!("socks5://{addr}")),
            no_proxy: (!self.no_proxy.is_empty()).then(|| self.no_proxy.join(",")),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            http_proxy: Some(SocketAddr::from(([10, 255, 0, 1], 8080))),
            https_proxy: Some(SocketAddr::from(([10, 255, 0, 1], 8080))),
            socks5_proxy: Some(SocketAddr::from(([10, 255, 0, 1], 1080))),
            no_proxy: Vec::new(),
        }
    }
}

/// Proxy environment variables for a sandboxed application.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProxyEnvironment {
    /// `HTTP_PROXY` value.
    pub http_proxy: Option<String>,
    /// `HTTPS_PROXY` value.
    pub https_proxy: Option<String>,
    /// `ALL_PROXY` value.
    pub all_proxy: Option<String>,
    /// `NO_PROXY` value.
    pub no_proxy: Option<String>,
}

/// Runtime resource limits used by proof and production backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ResourceLimitConfig {
    /// Maximum simultaneous TCP flows.
    pub max_tcp_flows: usize,
    /// Maximum simultaneous UDP pseudo-flows.
    pub max_udp_flows: usize,
    /// Maximum simultaneous explicit proxy connections.
    pub max_proxy_connections: usize,
    /// Maximum buffered bytes per flow direction.
    pub max_buffered_bytes_per_flow: usize,
    /// Maximum queued audit events before backpressure is reported.
    pub audit_queue_capacity: usize,
}

impl ResourceLimitConfig {
    /// Validates that all limits are non-zero.
    pub const fn validate(self) -> Result<(), ResourceLimitError> {
        if self.max_tcp_flows == 0 {
            return Err(ResourceLimitError::ZeroLimit("max_tcp_flows"));
        }
        if self.max_udp_flows == 0 {
            return Err(ResourceLimitError::ZeroLimit("max_udp_flows"));
        }
        if self.max_proxy_connections == 0 {
            return Err(ResourceLimitError::ZeroLimit("max_proxy_connections"));
        }
        if self.max_buffered_bytes_per_flow == 0 {
            return Err(ResourceLimitError::ZeroLimit("max_buffered_bytes_per_flow"));
        }
        if self.audit_queue_capacity == 0 {
            return Err(ResourceLimitError::ZeroLimit("audit_queue_capacity"));
        }
        Ok(())
    }
}

impl Default for ResourceLimitConfig {
    fn default() -> Self {
        Self {
            max_tcp_flows: 1024,
            max_udp_flows: 4096,
            max_proxy_connections: 1024,
            max_buffered_bytes_per_flow: 256 * 1024,
            audit_queue_capacity: 8192,
        }
    }
}

/// Resource limit validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResourceLimitError {
    /// A required limit was zero.
    ZeroLimit(&'static str),
}

/// UDP pseudo-flow timeout settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UdpTimeoutConfig {
    /// Broker DNS timeout.
    pub dns: Duration,
    /// Generic UDP timeout.
    pub generic: Duration,
    /// QUIC candidate timeout.
    pub quic: Duration,
    /// NTP-like one-shot timeout.
    pub one_shot: Duration,
}

impl UdpTimeoutConfig {
    /// Returns timeout for a class.
    pub const fn for_class(self, class: FlowTimeoutClass) -> Duration {
        match class {
            FlowTimeoutClass::Dns => self.dns,
            FlowTimeoutClass::GenericUdp => self.generic,
            FlowTimeoutClass::Quic => self.quic,
            FlowTimeoutClass::OneShot => self.one_shot,
        }
    }
}

impl Default for UdpTimeoutConfig {
    fn default() -> Self {
        Self {
            dns: FlowTimeoutClass::Dns.default_duration(),
            generic: FlowTimeoutClass::GenericUdp.default_duration(),
            quic: FlowTimeoutClass::Quic.default_duration(),
            one_shot: FlowTimeoutClass::OneShot.default_duration(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_config_defaults_are_fail_closed() {
        let config = BrokerConfig::new(SandboxId::new("alpha").unwrap());
        assert!(config.dns.deny_direct_external_dns);
        assert!(config.policy.deny_direct_dns);
        assert!(config.policy.deny_multicast_broadcast);
        assert!(config
            .policy
            .broadcast_addresses
            .contains(&IpAddr::from([10, 255, 0, 255])));
        assert_eq!(config.resource_limits.validate(), Ok(()));
    }

    #[test]
    fn resource_limits_reject_zero_values() {
        let invalid = ResourceLimitConfig {
            max_tcp_flows: 0,
            ..ResourceLimitConfig::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(ResourceLimitError::ZeroLimit("max_tcp_flows"))
        );
    }

    #[test]
    fn proxy_environment_uses_sandbox_reachable_addresses() {
        let env = ProxyConfig::default().environment();
        assert_eq!(env.http_proxy.as_deref(), Some("http://10.255.0.1:8080"));
        assert_eq!(env.all_proxy.as_deref(), Some("socks5://10.255.0.1:1080"));
    }
}
