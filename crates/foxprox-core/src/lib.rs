//! Core, platform-independent types for foxprox.
//!
//! This crate is the home for broker concepts that must not depend on Linux,
//! TUN, bwrap, smoltcp, or any concrete frontend/backend implementation.

#![forbid(unsafe_code)]

pub mod attribution;
pub mod audit;
pub mod config;
pub mod dns;
pub mod dns_handler;
pub mod flow;
pub mod http;
pub mod packet;
pub mod policy;
pub mod quic;
pub mod socks;
pub mod tls;
pub mod types;

pub use attribution::{HostAttribution, Hostname, HostnameError};
pub use audit::{
    AuditDecision, AuditDrainBatch, AuditEvent, AuditEventKind, AuditPolicyContext,
    BoundedAuditBuffer, PushOutcome,
};
pub use config::{Cidr, ConfigError, HostMatcher, PolicyConfig, PolicyRule, RuleAction};
pub use dns::{
    build_dns_address_response, build_dns_empty_response, parse_dns_address_response,
    parse_dns_query, DnsAddressResponseMetadata, DnsAttributionCache, DnsAttributionEntry,
    DnsBuildError, DnsParseError, DnsQueryMetadata, DnsQueryType, DnsResponseCode,
    DnsResponseObserveOutcome, DnsTransactionError, ObserveOutcome, PendingDnsObserveOutcome,
    PendingDnsObserveStatus, PendingDnsQuery, PendingDnsQueryTable,
};
pub use dns_handler::{
    handle_broker_dns_query, handle_broker_dns_query_with_pending, BrokerDnsQueryContext,
    BrokerDnsQueryOutcome,
};
pub use flow::{
    UdpFlowClass, UdpFlowEntry, UdpFlowKey, UdpFlowObserveOutcome, UdpFlowObserveStatus,
    UdpFlowTable, UdpFlowTimeouts,
};
pub use http::{
    parse_http_request_head, parse_https_connect_head, HttpParseError, HttpRequestMetadata,
    HttpsConnectMetadata,
};
pub use packet::{parse_ip_packet, PacketParseError, PacketSummary};
pub use policy::{Decision, DenialReason, DenyBehavior, PolicyEngine, PolicyRequest};
pub use quic::{
    parse_quic_candidate, QuicHeaderForm, QuicLongPacketType, QuicPacketMetadata, QuicParseError,
};
pub use socks::{
    parse_socks5_connect_request, parse_socks5_greeting, Socks5AuthMethod, Socks5ConnectMetadata,
    Socks5Destination, Socks5Greeting, Socks5ParseError,
};
pub use tls::{parse_tls_client_hello, TlsClientHelloMetadata, TlsParseError};
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
