//! Core, platform-independent types for foxprox.
//!
//! This crate owns the architectural boundary between packet/device specific
//! code and policy/audit decisions. It must not depend on Linux, TUN, bwrap,
//! smoltcp, or any concrete frontend/backend implementation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod audit;
pub mod config;
pub mod event;
pub mod flow;
pub mod policy;

pub use audit::{AuditEvent, AuditEventKind, AuditSinkConfig};
pub use config::{
    BrokerConfig, DnsConfig, ProxyConfig, ProxyEnvironment, TunConfig, UdpTimeoutConfig,
};
pub use event::{
    Attribution, AttributionConfidence, AttributionSource, Frontend, Hostname, HttpMethod,
    NetworkEvent, Origin, Protocol, SandboxId, SocksDestination, TransportEndpoint,
    UnsupportedReason,
};
pub use flow::{FlowKey, FlowProtocol, FlowTimeoutClass};
pub use policy::{
    Cidr, Decision, DecisionAction, DenialReason, PolicyEngine, PolicyRule, PolicyRuleSet,
    PortRange, RuleEffect,
};

/// Stable crate marker used by scaffold tests and downstream workspace checks.
pub const CRATE_NAME: &str = "foxprox-core";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_core_crate_marker() {
        assert_eq!(CRATE_NAME, "foxprox-core");
    }
}
