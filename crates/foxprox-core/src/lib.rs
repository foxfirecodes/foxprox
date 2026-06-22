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
pub mod config;
pub mod dns;
pub mod dns_handler;
pub mod flow;
pub mod inspect;
pub mod packet;
pub mod policy;
pub mod proxy;
pub mod proxy_frontend;
pub mod runtime;
pub mod setup;
pub mod tcp;
pub mod tun;
pub mod types;
pub mod udp;

pub use audit::{AuditError, AuditRecord, AuditSinkError, BoundedAuditLedger, JsonLineAuditSink};
pub use broker::BrokerCore;
pub use config::{
    BrokerRuntimeConfig, ProxyListenerConfig, ResourceLimitConfig, RuntimeConfigError,
};
pub use dns::{
    build_refused_response, parse_dns_query, DnsParseError, DnsQueryMetadata, DnsQueryType,
};
pub use dns_handler::{
    parse_dns_response_addresses, DnsAnswerSummary, DnsBrokerHandler, DnsHandlerResult,
    DnsUpstream, DnsUpstreamError,
};
pub use flow::{
    DnsCache, DnsResolution, FlowKey, FlowProtocol, SharedDnsCache, UdpFlowManager,
    UdpTimeoutConfig,
};
pub use packet::{checksum, IpParseError, ParsedIpPacket};
pub use policy::{
    Cidr, PolicyConfig, PolicyConfigError, PolicyDecision, PolicyEngine, PolicyRequest, PolicyRule,
};
pub use proxy::{
    malformed_proxy_request, parse_http_proxy_request, parse_socks5_connect_request,
    HttpProxyRequestMetadata, ProxyParseError, SocksConnectMetadata,
};
pub use proxy_frontend::{
    ExplicitProxyEgress, ExplicitProxyFrontend, ExplicitProxyResult, InMemoryExplicitProxyEgress,
    ProxyEgressError,
};
pub use runtime::{
    RuntimeCleanupAction, RuntimeCleanupReport, RuntimeComponent, RuntimeExitStatus,
    RuntimeLifecycleError, RuntimeLifecycleHarness,
};
pub use setup::{
    BwrapSetupPlan, NetworkSetupConfig, ProxyEnvironment, SetupExecutionReport, SetupHelperPlan,
    SetupHelperStep, SetupStepRunError, SetupStepRunner,
};
pub use tcp::{InMemoryTcpEgress, TcpEgress, TcpEgressError, TcpForwardResult, TcpForwarder};
pub use tun::{DeviceIoError, InMemoryPacketDevice, PacketDevice, TunPacketHarness};
pub use types::*;
pub use udp::{InMemoryUdpEgress, UdpEgress, UdpEgressError, UdpForwardResult, UdpForwarder};

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
