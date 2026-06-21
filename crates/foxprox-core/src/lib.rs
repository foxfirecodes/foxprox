//! Core, platform-independent types for foxprox.
//!
//! This crate holds the broker contracts that must stay independent from Linux,
//! TUN, bwrap, smoltcp, or any concrete frontend/backend implementation. The
//! alpha implementation intentionally makes policy, packet handling, flow state,
//! setup planning, and audit output observable before privileged runtime pieces
//! are wired in.

#![forbid(unsafe_code)]

pub mod audit;
pub mod broker;
pub mod dns;
pub mod flow;
pub mod inspect;
pub mod packet;
pub mod policy;
pub mod setup;
pub mod types;

pub use audit::{AuditError, AuditRecord, BoundedAuditLedger};
pub use broker::BrokerCore;
pub use dns::{
    build_refused_response, parse_dns_query, DnsParseError, DnsQueryMetadata, DnsQueryType,
};
pub use flow::{DnsCache, FlowKey, FlowProtocol, UdpFlowManager};
pub use packet::{IpParseError, ParsedIpPacket};
pub use policy::{Cidr, PolicyConfig, PolicyDecision, PolicyEngine, PolicyRequest, PolicyRule};
pub use setup::{BwrapSetupPlan, NetworkSetupConfig, ProxyEnvironment};
pub use types::*;

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
