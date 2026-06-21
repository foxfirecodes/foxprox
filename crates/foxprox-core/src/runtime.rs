use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::audit::{AuditRecord, Decision, EventKind, Frontend, Protocol};
use crate::dns::DnsCache;
use crate::egress::{EgressBackend, EgressRequest};
use crate::packet::{parse_ipv4, parse_udp, synthesize_udp_reply};
use crate::policy::{PolicyEngine, PolicyRequest};

/// Minimal transparent TUN UDP runtime boundary used by the harness and future broker runtime.
///
/// This adapter owns the policy-before-egress sequence for one IPv4/UDP packet and returns an
/// optional packet to write back to the TUN frontend. It deliberately stays independent of Linux fd
/// handling so the behavior can be unit-tested without namespaces.
#[derive(Debug)]
pub struct TransparentUdpRuntime<B> {
    pub policy: PolicyEngine,
    pub egress: B,
    pub audit: Vec<AuditRecord>,
    pub dns_cache: DnsCache,
    pub now_tick: u64,
}

impl<B: EgressBackend> TransparentUdpRuntime<B> {
    pub fn new(policy: PolicyEngine, egress: B) -> Self {
        Self {
            policy,
            egress,
            audit: Vec::new(),
            dns_cache: DnsCache::new(),
            now_tick: 0,
        }
    }

    pub fn with_dns_cache(mut self, dns_cache: DnsCache, now_tick: u64) -> Self {
        self.dns_cache = dns_cache;
        self.now_tick = now_tick;
        self
    }

    pub fn handle_ipv4_packet(
        &mut self,
        sandbox_id: impl Into<String>,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        let sandbox_id = sandbox_id.into();
        let parsed = match parse_ipv4(packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::UnsupportedNetworkEvent,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed IPv4 packet fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Unsupported),
                );
                return Ok(None);
            }
        };
        if parsed.protocol_number != 17 {
            self.audit.push(
                AuditRecord::new(
                    EventKind::UnsupportedNetworkEvent,
                    sandbox_id,
                    Decision::FailClosed,
                    "transparent UDP runtime received non-UDP packet",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol()),
            );
            return Ok(None);
        }
        let udp = match parse_udp(parsed.payload) {
            Ok(udp) => udp,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::UdpFlowCreated,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed UDP packet fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Udp),
                );
                return Ok(None);
            }
        };

        let destination = SocketAddr::new(IpAddr::V4(parsed.destination), udp.destination_port);
        let source = SocketAddr::new(IpAddr::V4(parsed.source), udp.source_port);
        let mut request = PolicyRequest::new(&sandbox_id, Frontend::Tun, Protocol::Udp)
            .with_source(source.ip(), source.port())
            .with_destination(destination.ip(), destination.port());
        let attribution = self
            .dns_cache
            .attribution_for(destination.ip(), self.now_tick);
        if let Some(attr) = &attribution {
            request = request.with_hostname(&attr.hostname, attr.confidence);
        }
        request.is_multicast_or_broadcast = is_multicast_or_broadcast(parsed.destination);
        request.quic_candidate = udp.class == crate::flow::UdpClass::QuicCandidate;

        let outcome = self.policy.evaluate(&request);
        let mut record = AuditRecord::new(
            EventKind::UdpFlowCreated,
            &sandbox_id,
            outcome.decision,
            &outcome.reason,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Udp)
        .with_addresses(Some(source), Some(destination))
        .with_rule(outcome.rule_id.clone());
        if let Some(attr) = attribution {
            record = record.with_hostname(Some(attr.hostname), attr.source, attr.confidence);
        }

        if !outcome.decision.is_allow() {
            self.audit.push(record);
            return Ok(None);
        }

        let egress_request = EgressRequest::UdpDatagram {
            destination,
            bytes: udp.payload.to_vec(),
        };
        match self.egress.execute(&egress_request) {
            Ok(egress) => {
                record = record
                    .with_bytes(egress.bytes_sent, egress.bytes_received)
                    .with_metadata("egress", egress.message);
                let reply = if egress.response_payload.is_empty() {
                    None
                } else {
                    Some(synthesize_udp_reply(packet, &egress.response_payload)?)
                };
                self.audit.push(record);
                Ok(reply)
            }
            Err(err) => {
                record.decision = Decision::FailClosed;
                record.reason = format!("egress failed closed: {err}");
                self.audit.push(record);
                Ok(None)
            }
        }
    }
}

fn is_multicast_or_broadcast(ip: Ipv4Addr) -> bool {
    ip.is_multicast() || ip == Ipv4Addr::BROADCAST || ip.octets()[3] == 255
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::egress::{EgressOutcome, MockEgressBackend};
    use crate::packet::{checksum, parse_ipv4, parse_udp};
    use crate::policy::{Cidr, PolicyConfig, PolicyRule, RuleAction};

    use super::*;

    #[test]
    fn allowed_udp_packet_reaches_egress_and_returns_tun_reply() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5354);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-local-udp-smoke", RuleAction::Allow)
                    .protocol(Protocol::Udp)
                    .destination(Cidr::host(destination.ip()))
                    .port(destination.port()),
            ),
        );
        let egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 5,
                bytes_received: 12,
                message: "mock UDP forwarded".to_string(),
                response_payload: b"egress:probe".to_vec(),
            },
        );
        let mut runtime = TransparentUdpRuntime::new(policy, egress);
        let packet = udp_probe_packet(destination.ip(), destination.port(), b"probe");
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap().unwrap();
        let parsed = parse_ipv4(&reply).unwrap();
        let udp = parse_udp(parsed.payload).unwrap();
        assert_eq!(parsed.source, Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(parsed.destination, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(udp.destination_port, 49152);
        assert_eq!(udp.payload, b"egress:probe");
        assert_eq!(runtime.egress.requests.len(), 1);
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(runtime.audit[0].bytes_out, 12);
    }

    #[test]
    fn dns_cache_attribution_can_allow_domain_udp_rule() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 5354);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-attributed-example", RuleAction::Allow)
                    .protocol(Protocol::Udp)
                    .domain_suffix("example")
                    .port(destination.port())
                    .require_hostname_attribution(),
            ),
        );
        let egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 5,
                bytes_received: 12,
                message: "mock UDP forwarded".to_string(),
                response_payload: b"egress:probe".to_vec(),
            },
        );
        let mut cache = DnsCache::new();
        cache
            .observe_response("lab.example", [destination.ip()], 1, 60)
            .unwrap();
        let mut runtime = TransparentUdpRuntime::new(policy, egress).with_dns_cache(cache, 2);
        let packet = udp_probe_packet(destination.ip(), destination.port(), b"probe");
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert!(reply.is_some());
        assert_eq!(runtime.audit[0].hostname.as_deref(), Some("lab.example"));
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(
            runtime.audit[0].rule_id.as_deref(),
            Some("allow-attributed-example")
        );
    }

    #[test]
    fn denied_udp_packet_never_reaches_egress() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5354);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let egress = MockEgressBackend::new();
        let mut runtime = TransparentUdpRuntime::new(policy, egress);
        let packet = udp_probe_packet(destination.ip(), destination.port(), b"probe");
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert!(reply.is_none());
        assert!(runtime.egress.requests.is_empty());
        assert_eq!(runtime.audit[0].decision, Decision::DenyDrop);
    }

    fn udp_probe_packet(destination: IpAddr, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let IpAddr::V4(destination) = destination else {
            panic!("test destination must be IPv4");
        };
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 2, 2]);
        packet[16..20].copy_from_slice(&destination.octets());
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet[20..22].copy_from_slice(&49152_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }
}
