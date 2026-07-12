//! Core, platform-independent types for foxprox.
//!
//! This crate owns the architectural boundary between packet/device specific
//! code and policy/audit decisions. It must not depend on Linux, TUN, bwrap,
//! smoltcp, or any concrete frontend/backend implementation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod audit;
pub mod config;
pub mod dns;
pub mod egress;
pub mod event;
pub mod flow;
pub mod frontend;
pub mod inspection;
pub mod policy;

pub use audit::{
    audit_event_json_line, drain_audit_buffer_to_json_lines, AuditBackpressure, AuditBuffer,
    AuditEvent, AuditEventKind, AuditSinkConfig,
};
pub use config::{
    BrokerConfig, DnsConfig, ProxyConfig, ProxyEnvironment, ResourceLimitConfig,
    ResourceLimitError, TunConfig, UdpTimeoutConfig,
};
pub use dns::{
    parse_dns_query, parse_dns_response, DnsAddressRecord, DnsCache, DnsCacheEntry, DnsObservation,
    DnsParseError, DnsQueryType, DnsQuestion, DnsResponseObservation,
};
pub use egress::{
    DnsEgress, DnsEgressRequest, EgressContext, EgressError, EgressErrorKind, EgressOutcome,
    TcpEgress, TcpEgressRequest, UdpEgress, UdpEgressRequest,
};
pub use event::{
    Attribution, AttributionConfidence, AttributionSource, Frontend, Hostname, HttpMethod,
    NetworkEvent, Origin, Protocol, SandboxId, SocksDestination, TransportEndpoint,
    UnsupportedReason,
};
pub use flow::{FlowKey, FlowProtocol, FlowTimeoutClass, UdpFlowRecord, UdpFlowTable};
pub use frontend::{FrontendContext, FrontendError, FrontendErrorKind, NetworkFrontend};
pub use inspection::{
    classify_udp_candidate, parse_http_request_head, parse_tls_client_hello, HttpInspection,
    InspectionError, TlsClientHelloInspection,
};
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
