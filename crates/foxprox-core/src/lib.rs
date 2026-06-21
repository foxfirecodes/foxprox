//! Core, platform-independent types for foxprox.
//!
//! This crate is the verification kernel for broker behavior that must not
//! depend on Linux, TUN, bwrap, smoltcp, or any concrete frontend/backend
//! implementation. Packet adapters and proxy frontends should translate their
//! input into these normalized types before policy or audit decisions are made.

#![forbid(unsafe_code)]

pub mod audit;
pub mod dns;
pub mod flow;
pub mod inspect;
pub mod origin;
pub mod packet;
pub mod policy;
pub mod types;

pub use audit::{AuditError, AuditEvent, AuditEventKind, AuditSink, VecAuditSink};
pub use dns::{DnsCache, DnsObservation};
pub use flow::{FlowTable, UdpClass, UdpFlow, UdpTimeouts};
pub use inspect::{parse_http_request, parse_tls_client_hello_sni, InspectError, TlsClientHello};
pub use origin::{parse_connect_target, parse_http_origin, OriginError};
pub use packet::{
    packet_addrs, parse_ip_packet, synthesize_icmpv4_echo_reply, Icmpv4EchoRequest, PacketError,
    ParsedIpPacket, UnsupportedIpv4Protocol,
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
