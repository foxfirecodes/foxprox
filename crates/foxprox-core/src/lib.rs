//! Core, platform-independent types for foxprox.
//!
//! This crate is the verification kernel for broker behavior that must not
//! depend on Linux, TUN, bwrap, smoltcp, or any concrete frontend/backend
//! implementation. Packet adapters and proxy frontends should translate their
//! input into these normalized types before policy or audit decisions are made.

#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod dns;
pub mod event;
pub mod flow;
pub mod frontend;
pub mod inspect;
pub mod kernel;
pub mod origin;
pub mod packet;
pub mod policy;
pub mod types;

pub use audit::{
    format_audit_line, AuditError, AuditEvent, AuditEventKind, AuditSink, LineAuditSink,
    VecAuditSink,
};
pub use config::{validate_policy_config, ConfigError};
pub use dns::{
    parse_dns_query, parse_dns_response_observation, DnsCache, DnsObservation, DnsParseError,
    DnsQuestion, DnsRecordType,
};
pub use event::{explicit_proxy_attribution, NormalizedEvent};
pub use flow::{classify_udp, FlowTable, UdpClass, UdpFlow, UdpTimeouts};
pub use frontend::{
    parse_http_proxy_request_line, parse_socks5_connect, parse_socks5_greeting,
    protocol_for_http_proxy_line, HttpProxyRequestLine, ProxyParseError, SocksConnectRequest,
    SocksDestination, SocksGreeting,
};
pub use inspect::{parse_http_request, parse_tls_client_hello_sni, InspectError, TlsClientHello};
pub use kernel::VerificationKernel;
pub use origin::{parse_connect_target, parse_http_origin, OriginError};
pub use packet::{
    packet_addrs, parse_ip_packet, synthesize_icmpv4_echo_reply, Icmpv4EchoRequest, PacketError,
    ParsedIpPacket, Udpv4Packet, UnsupportedIpv4Protocol,
};
pub use policy::{IpCidr, IpMatcher, PolicyConfig, PolicyEngine, PolicyRule, PortMatcher, RuleSet};
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
