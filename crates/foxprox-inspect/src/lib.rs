//! Transparent inspection and attribution helpers for foxprox.
//!
//! This crate enriches normalized TUN events with metadata discovered by other
//! broker subsystems. It does not own raw packet parsing or policy decisions.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use foxprox_core::{
    AttributionConfidence, AttributionSource, HostnameAttribution, NormalizedEvent,
};

/// Expiring DNS answer cache used for medium-confidence transparent flow
/// attribution.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DnsAttributionCache {
    entries: Vec<DnsAttributionEntry>,
}

impl DnsAttributionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DNS answer mapping one hostname to one or more IP addresses.
    pub fn record_answer(
        &mut self,
        hostname: impl Into<String> + Clone,
        addresses: impl IntoIterator<Item = IpAddr>,
        observed_at: SystemTime,
        ttl: Duration,
    ) {
        let expires_at = observed_at
            .checked_add(ttl)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        for address in addresses {
            self.entries.push(DnsAttributionEntry {
                address,
                attribution: HostnameAttribution::new(
                    hostname.clone(),
                    AttributionSource::DnsCache,
                    AttributionConfidence::Medium,
                ),
                expires_at,
            });
        }
    }

    /// Enrich TCP/UDP flow attempts with DNS hostname attribution when the
    /// destination IP has a non-expired DNS answer. Existing attribution is not
    /// overwritten because HTTP Host, TLS SNI, and explicit proxy metadata have
    /// higher confidence.
    pub fn enrich_event(&self, event: NormalizedEvent, now: SystemTime) -> NormalizedEvent {
        match event {
            NormalizedEvent::TcpConnectAttempt(mut tcp) => {
                if tcp.attribution.is_none() {
                    tcp.attribution = self.lookup(tcp.destination.ip, now);
                }
                NormalizedEvent::TcpConnectAttempt(tcp)
            }
            NormalizedEvent::UdpFlowAttempt(mut udp) => {
                if udp.attribution.is_none() {
                    udp.attribution = self.lookup(udp.destination.ip, now);
                }
                NormalizedEvent::UdpFlowAttempt(udp)
            }
            other => other,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn lookup(&self, address: IpAddr, now: SystemTime) -> Option<HostnameAttribution> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.address == address && now <= entry.expires_at)
            .map(|entry| entry.attribution.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsAttributionEntry {
    address: IpAddr,
    attribution: HostnameAttribution,
    expires_at: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        AuditDecision, Endpoint, FrontendKind, HostnamePattern, PolicyConfig, PolicyDecision,
        PolicyEngine, PolicyRule, Protocol, RuleAction, SandboxId,
    };
    use foxprox_packet::{parse_ipv4_packet, PacketContext};
    use std::net::Ipv4Addr;

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("inspect-test").unwrap(), FrontendKind::Tun)
    }

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_length = 20 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn tcp_syn_payload(source_port: u16, destination_port: u16) -> [u8; 20] {
        let mut payload = [0_u8; 20];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[12] = 5 << 4;
        payload[13] = 0x02;
        payload
    }

    fn domain_policy() -> PolicyEngine {
        let rule = PolicyRule::new("allow-example-https", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Tcp)
            .with_destination_port(443)
            .with_hostname(HostnamePattern::new(".example.com").unwrap());
        PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
    }

    fn tcp_connect_event() -> NormalizedEvent {
        let packet = ipv4_packet(
            6,
            [10, 0, 0, 2],
            [93, 184, 216, 34],
            &tcp_syn_payload(49152, 443),
        );
        parse_ipv4_packet(&context(), &packet).unwrap()
    }

    #[test]
    fn dns_cache_enriches_tcp_flow_for_domain_policy_and_audit() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let event = tcp_connect_event();
        let engine = domain_policy();
        assert_eq!(
            engine.evaluate(&event).decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );

        let mut cache = DnsAttributionCache::new();
        cache.record_answer(
            "WWW.EXAMPLE.COM.",
            [Ipv4Addr::new(93, 184, 216, 34).into()],
            now,
            Duration::from_secs(60),
        );
        let enriched = cache.enrich_event(event, now + Duration::from_secs(1));
        let evaluation = engine.evaluate(&enriched);

        assert_eq!(enriched.hostname(), Some("www.example.com"));
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-example-https".to_owned())
            }
        );
        assert_eq!(evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(
            evaluation.audit.hostname.as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            evaluation.audit.hostname_confidence,
            Some(AttributionConfidence::Medium)
        );
    }

    #[test]
    fn expired_dns_answer_does_not_enrich_flow() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut cache = DnsAttributionCache::new();
        cache.record_answer(
            "www.example.com",
            [Ipv4Addr::new(93, 184, 216, 34).into()],
            now,
            Duration::from_secs(5),
        );

        let enriched = cache.enrich_event(tcp_connect_event(), now + Duration::from_secs(6));

        assert_eq!(enriched.hostname(), None);
    }

    #[test]
    fn dns_cache_does_not_overwrite_existing_high_confidence_attribution() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut cache = DnsAttributionCache::new();
        cache.record_answer(
            "dns.example.com",
            [Ipv4Addr::new(93, 184, 216, 34).into()],
            now,
            Duration::from_secs(60),
        );
        let mut event = tcp_connect_event();
        match &mut event {
            NormalizedEvent::TcpConnectAttempt(tcp) => {
                tcp.attribution = Some(HostnameAttribution::new(
                    "sni.example.com",
                    AttributionSource::TlsSni,
                    AttributionConfidence::High,
                ));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let enriched = cache.enrich_event(event, now + Duration::from_secs(1));

        assert_eq!(enriched.hostname(), Some("sni.example.com"));
        assert_eq!(
            enriched.attribution_confidence(),
            Some(AttributionConfidence::High)
        );
    }

    #[test]
    fn newest_dns_answer_wins_when_addresses_are_reused() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut cache = DnsAttributionCache::new();
        let shared_ip = Ipv4Addr::new(93, 184, 216, 34);
        cache.record_answer(
            "old.example.com",
            [shared_ip.into()],
            now,
            Duration::from_secs(60),
        );
        cache.record_answer(
            "new.example.com",
            [shared_ip.into()],
            now + Duration::from_secs(1),
            Duration::from_secs(60),
        );

        let enriched = cache.enrich_event(tcp_connect_event(), now + Duration::from_secs(2));

        assert_eq!(cache.len(), 2);
        assert_eq!(enriched.hostname(), Some("new.example.com"));
        assert_eq!(
            enriched.destination(),
            Some(Endpoint::tcp(shared_ip.into(), 443))
        );
    }
}
