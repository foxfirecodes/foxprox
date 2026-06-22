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
pub mod egress;
pub mod flow;
pub mod http;
pub mod http_handler;
pub mod icmp;
pub mod packet;
pub mod packet_handler;
pub mod policy;
pub mod proxy_handler;
pub mod quic;
pub mod quic_handler;
pub mod socks;
pub mod socks_handler;
pub mod tls;
pub mod tls_handler;
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
    DnsAttributionLookup, DnsBuildError, DnsParseError, DnsQueryMetadata, DnsQueryType,
    DnsResponseCode, DnsResponseObserveOutcome, DnsTransactionError, ObserveOutcome,
    PendingDnsObserveOutcome, PendingDnsObserveStatus, PendingDnsQuery, PendingDnsQueryTable,
};
pub use dns_handler::{
    handle_broker_dns_query, handle_broker_dns_query_with_pending, handle_broker_dns_response,
    BrokerDnsQueryContext, BrokerDnsQueryOutcome, BrokerDnsResponseContext,
    BrokerDnsResponseOutcome,
};
pub use egress::{EgressDestination, EgressPermit, EgressPermitError};
pub use flow::{
    TcpFlowEntry, TcpFlowKey, TcpFlowObserveOutcome, TcpFlowObserveStatus, TcpFlowTable,
    UdpFlowClass, UdpFlowEntry, UdpFlowKey, UdpFlowObserveOutcome, UdpFlowObserveStatus,
    UdpFlowTable, UdpFlowTimeouts,
};
pub use http::{
    parse_http_request_head, parse_https_connect_head, HttpParseError, HttpRequestMetadata,
    HttpsConnectMetadata,
};
pub use http_handler::{
    handle_transparent_http_request, TransparentHttpContext, TransparentHttpOutcome,
};
pub use icmp::{synthesize_icmpv4_echo_reply, IcmpSynthesisError};
pub use packet::{parse_ip_packet, PacketParseError, PacketSummary};
pub use packet_handler::{handle_tun_packet, TunPacketContext, TunPacketOutcome};
pub use policy::{Decision, DenialReason, DenyBehavior, PolicyEngine, PolicyRequest};
pub use proxy_handler::{
    handle_http_proxy_request, HttpProxyRequestContext, HttpProxyRequestOutcome,
    HttpProxyResponseError,
};
pub use quic::{
    parse_quic_candidate, QuicHeaderForm, QuicLongPacketType, QuicPacketMetadata, QuicParseError,
};
pub use quic_handler::{handle_quic_candidate, QuicInspectionContext, QuicInspectionOutcome};
pub use socks::{
    parse_socks5_connect_request, parse_socks5_greeting, Socks5AuthMethod, Socks5ConnectMetadata,
    Socks5Destination, Socks5Greeting, Socks5ParseError,
};
pub use socks_handler::{
    handle_socks5_connect, handle_socks5_greeting, Socks5ConnectOutcome, Socks5Context,
    Socks5GreetingOutcome, Socks5ResponseError,
};
pub use tls::{parse_tls_client_hello, TlsClientHelloMetadata, TlsParseError};
pub use tls_handler::{handle_tls_client_hello, TlsInspectionContext, TlsInspectionOutcome};
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
