//! Core, platform-independent types for foxprox.
//!
//! This crate is the home for broker concepts that must not depend on Linux,
//! TUN, bwrap, smoltcp, or any concrete frontend/backend implementation.

#![forbid(unsafe_code)]

pub mod attribution;
pub mod audit;
pub mod config;
pub mod dns;
pub mod packet;
pub mod policy;
pub mod types;

pub use attribution::{HostAttribution, Hostname, HostnameError};
pub use audit::{
    AuditDecision, AuditEvent, AuditEventKind, AuditPolicyContext, BoundedAuditBuffer, PushOutcome,
};
pub use config::{Cidr, ConfigError, HostMatcher, PolicyConfig, PolicyRule, RuleAction};
pub use dns::{DnsAttributionCache, DnsAttributionEntry, ObserveOutcome};
pub use packet::{parse_ip_packet, PacketParseError, PacketSummary};
pub use policy::{Decision, DenialReason, DenyBehavior, PolicyEngine, PolicyRequest};
pub use types::{
    Endpoint, Frontend, HostnameConfidence, HostnameSource, IcmpMessage, Protocol, SandboxId,
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
