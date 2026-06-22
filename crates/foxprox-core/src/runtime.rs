use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::audit::{
    AttributionConfidence, AttributionSource, AuditRecord, Decision, EventKind, Frontend, Protocol,
};
use crate::dns::DnsCache;
use crate::egress::{EgressBackend, EgressRequest};
use crate::origin::{parse_http_request, parse_tls_client_hello};
use crate::packet::{
    parse_icmp_echo_request, parse_ipv4, parse_tcp, parse_udp, synthesize_icmp_echo_reply,
    synthesize_udp_reply,
};
use crate::policy::{PolicyEngine, PolicyRequest};
use crate::smoltcp_gate::SmoltcpTcpServerHarness;

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
        let policy_protocol = if udp.class == crate::flow::UdpClass::QuicCandidate {
            Protocol::Quic
        } else {
            Protocol::Udp
        };
        let mut request = PolicyRequest::new(&sandbox_id, Frontend::Tun, policy_protocol)
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
        let event_kind = if policy_protocol == Protocol::Quic {
            EventKind::QuicCandidateFlow
        } else {
            EventKind::UdpFlowCreated
        };
        let mut record =
            AuditRecord::new(event_kind, &sandbox_id, outcome.decision, &outcome.reason)
                .with_frontend(Frontend::Tun)
                .with_protocol(policy_protocol)
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

/// Minimal transparent TUN TCP connect runtime boundary.
///
/// This is not a TCP stack. It proves the policy/audit/egress boundary for TCP SYN connect
/// attempts before the smoltcp forwarding gate is wired in.
#[derive(Debug)]
pub struct TransparentTcpRuntime<B> {
    pub policy: PolicyEngine,
    pub egress: B,
    pub audit: Vec<AuditRecord>,
    pub dns_cache: DnsCache,
    pub now_tick: u64,
}

impl<B: EgressBackend> TransparentTcpRuntime<B> {
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
    ) -> Result<(), String> {
        let sandbox_id = sandbox_id.into();
        let parsed = parse_ipv4(packet).map_err(|err| format!("malformed IPv4 packet: {err}"))?;
        if parsed.protocol_number != 6 {
            self.audit.push(
                AuditRecord::new(
                    EventKind::UnsupportedNetworkEvent,
                    sandbox_id,
                    Decision::FailClosed,
                    "transparent TCP runtime received non-TCP packet",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol()),
            );
            return Ok(());
        }
        let tcp =
            parse_tcp(parsed.payload).map_err(|err| format!("malformed TCP segment: {err}"))?;
        let destination = SocketAddr::new(IpAddr::V4(parsed.destination), tcp.destination_port);
        let source = SocketAddr::new(IpAddr::V4(parsed.source), tcp.source_port);
        if !tcp.syn || tcp.rst {
            self.audit.push(
                AuditRecord::new(
                    EventKind::UnsupportedNetworkEvent,
                    sandbox_id,
                    Decision::FailClosed,
                    "only TCP SYN connect attempts are supported by the alpha TCP runtime",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(Protocol::Tcp)
                .with_addresses(Some(source), Some(destination)),
            );
            return Ok(());
        }

        let mut request = PolicyRequest::new(&sandbox_id, Frontend::Tun, Protocol::Tcp)
            .with_source(source.ip(), source.port())
            .with_destination(destination.ip(), destination.port());
        let attribution = self
            .dns_cache
            .attribution_for(destination.ip(), self.now_tick);
        if let Some(attr) = &attribution {
            request = request.with_hostname(&attr.hostname, attr.confidence);
        }
        let outcome = self.policy.evaluate(&request);
        let mut record = AuditRecord::new(
            EventKind::TcpConnectAttempt,
            &sandbox_id,
            outcome.decision,
            &outcome.reason,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Tcp)
        .with_addresses(Some(source), Some(destination))
        .with_rule(outcome.rule_id.clone());
        if let Some(attr) = attribution {
            record = record.with_hostname(Some(attr.hostname), attr.source, attr.confidence);
        }

        if outcome.decision.is_allow() {
            match self
                .egress
                .execute(&EgressRequest::TcpConnect { destination })
            {
                Ok(egress) => {
                    record = record
                        .with_bytes(egress.bytes_sent, egress.bytes_received)
                        .with_metadata("egress", egress.message);
                }
                Err(err) => {
                    record.decision = Decision::FailClosed;
                    record.reason = format!("egress failed closed: {err}");
                }
            }
        }
        self.audit.push(record);
        Ok(())
    }
}

/// Result of processing one sandbox TCP packet through the reusable bridge runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpBridgeStep {
    pub emitted_packets: Vec<Vec<u8>>,
    pub egress_payload: Option<Vec<u8>>,
}

/// Reusable transparent TCP bridge runtime boundary.
///
/// This owns policy-before-smoltcp enforcement, optional transparent inspection, smoltcp packet
/// state, audit records, and outbound packet emission. Device fd IO and host socket egress remain in
/// the caller so the core stays platform-independent.
pub struct TransparentTcpBridgeRuntime {
    policy: PolicyEngine,
    inspection: Option<TransparentInspectionRuntime>,
    stack: SmoltcpTcpServerHarness,
    connect_allowed: bool,
    connect_audited: bool,
    payload_inspected: bool,
    pub audit: Vec<AuditRecord>,
}

impl TransparentTcpBridgeRuntime {
    pub fn listen(
        listen_ip: Ipv4Addr,
        listen_port: u16,
        policy: PolicyEngine,
    ) -> Result<Self, String> {
        Ok(Self {
            policy,
            inspection: None,
            stack: SmoltcpTcpServerHarness::listen(listen_ip, listen_port)?,
            connect_allowed: false,
            connect_audited: false,
            payload_inspected: false,
            audit: Vec::new(),
        })
    }

    pub fn with_inspection(mut self, inspection: TransparentInspectionRuntime) -> Self {
        self.inspection = Some(inspection);
        self
    }

    pub fn handle_ipv4_packet(
        &mut self,
        sandbox_id: impl Into<String>,
        packet: &[u8],
    ) -> Result<TcpBridgeStep, String> {
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
                return Ok(TcpBridgeStep {
                    emitted_packets: Vec::new(),
                    egress_payload: None,
                });
            }
        };
        if parsed.protocol_number != 6 {
            self.audit.push(
                AuditRecord::new(
                    EventKind::UnsupportedNetworkEvent,
                    sandbox_id,
                    Decision::FailClosed,
                    "TCP bridge runtime received non-TCP packet",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol()),
            );
            return Ok(TcpBridgeStep {
                emitted_packets: Vec::new(),
                egress_payload: None,
            });
        }
        let tcp =
            parse_tcp(parsed.payload).map_err(|err| format!("malformed TCP segment: {err}"))?;
        let source = SocketAddr::new(IpAddr::V4(parsed.source), tcp.source_port);
        let destination = SocketAddr::new(IpAddr::V4(parsed.destination), tcp.destination_port);

        if !self.connect_audited && tcp.syn && !tcp.ack {
            let request = PolicyRequest::new(&sandbox_id, Frontend::Tun, Protocol::Tcp)
                .with_source(source.ip(), source.port())
                .with_destination(destination.ip(), destination.port());
            let outcome = self.policy.evaluate(&request);
            self.connect_allowed = outcome.decision.is_allow();
            self.connect_audited = true;
            self.audit.push(
                AuditRecord::new(
                    EventKind::TcpConnectAttempt,
                    &sandbox_id,
                    outcome.decision,
                    outcome.reason,
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(Protocol::Tcp)
                .with_addresses(Some(source), Some(destination))
                .with_rule(outcome.rule_id),
            );
            if !self.connect_allowed {
                return Ok(TcpBridgeStep {
                    emitted_packets: vec![crate::packet::synthesize_tcp_rst(packet)?],
                    egress_payload: None,
                });
            }
        }

        if !self.connect_allowed {
            return Ok(TcpBridgeStep {
                emitted_packets: Vec::new(),
                egress_payload: None,
            });
        }

        if !tcp.payload.is_empty() && !self.payload_inspected {
            if let Some(inspection) = self.inspection.as_mut() {
                inspection.inspect_ipv4_tcp_payload(&sandbox_id, packet)?;
                if let Some(record) = inspection.audit.last().cloned() {
                    let allow = record.decision.is_allow();
                    self.audit.push(record);
                    self.payload_inspected = true;
                    if !allow {
                        return Ok(TcpBridgeStep {
                            emitted_packets: vec![crate::packet::synthesize_tcp_rst(packet)?],
                            egress_payload: None,
                        });
                    }
                }
            }
        }

        self.stack.receive_packet(packet.to_vec())?;
        let mut emitted_packets = self.stack.drain_emitted_packets();
        self.stack.poll()?;
        emitted_packets.extend(self.stack.drain_emitted_packets());
        let egress_payload = self.stack.recv_available()?;
        Ok(TcpBridgeStep {
            emitted_packets,
            egress_payload,
        })
    }

    pub fn send_egress_response(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.stack.send_slice(bytes)?;
        Ok(self.stack.drain_emitted_packets())
    }

    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.stack.poll()?;
        Ok(self.stack.drain_emitted_packets())
    }
}

/// Minimal transparent ICMP runtime for echo-request policy and write-back.
#[derive(Debug)]
pub struct TransparentIcmpRuntime {
    pub policy: PolicyEngine,
    pub audit: Vec<AuditRecord>,
}

impl TransparentIcmpRuntime {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            audit: Vec::new(),
        }
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
        if parsed.protocol_number != 1 {
            self.audit.push(
                AuditRecord::new(
                    EventKind::UnsupportedNetworkEvent,
                    sandbox_id,
                    Decision::FailClosed,
                    "transparent ICMP runtime received non-ICMP packet",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol()),
            );
            return Ok(None);
        }
        let echo = match parse_icmp_echo_request(parsed.payload) {
            Ok(echo) => echo,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::IcmpMessage,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("unsupported ICMP message fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Icmp),
                );
                return Ok(None);
            }
        };
        let source = SocketAddr::new(IpAddr::V4(parsed.source), 0);
        let destination = SocketAddr::new(IpAddr::V4(parsed.destination), 0);
        let request = PolicyRequest::new(&sandbox_id, Frontend::Tun, Protocol::Icmp)
            .with_source(source.ip(), source.port())
            .with_destination(destination.ip(), destination.port());
        let outcome = self.policy.evaluate(&request);
        let record = AuditRecord::new(
            EventKind::IcmpMessage,
            &sandbox_id,
            outcome.decision,
            &outcome.reason,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Icmp)
        .with_addresses(Some(source), Some(destination))
        .with_rule(outcome.rule_id)
        .with_metadata("icmp_type", "echo_request")
        .with_metadata("identifier", echo.identifier.to_string())
        .with_metadata("sequence", echo.sequence.to_string())
        .with_bytes(parsed.payload.len() as u64, 0);
        if !outcome.decision.is_allow() {
            self.audit.push(record);
            return Ok(None);
        }
        let reply = synthesize_icmp_echo_reply(packet)?;
        self.audit
            .push(record.with_bytes(parsed.payload.len() as u64, reply.len() as u64));
        Ok(Some(reply))
    }
}

/// Transparent TCP payload inspection for HTTP and TLS metadata.
///
/// This runtime proves the normalized inspection/policy/audit boundary without owning TCP stream
/// reassembly. The smoltcp adapter or flow manager can call this once request bytes are available.
#[derive(Debug)]
pub struct TransparentInspectionRuntime {
    pub policy: PolicyEngine,
    pub audit: Vec<AuditRecord>,
    pub dns_cache: DnsCache,
    pub now_tick: u64,
}

impl TransparentInspectionRuntime {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
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

    pub fn inspect_ipv4_tcp_payload(
        &mut self,
        sandbox_id: impl Into<String>,
        packet: &[u8],
    ) -> Result<(), String> {
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
                return Ok(());
            }
        };
        if parsed.protocol_number != 6 {
            self.audit.push(
                AuditRecord::new(
                    EventKind::UnsupportedNetworkEvent,
                    sandbox_id,
                    Decision::FailClosed,
                    "transparent inspection runtime received non-TCP packet",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol()),
            );
            return Ok(());
        }
        let tcp = match parse_tcp(parsed.payload) {
            Ok(tcp) => tcp,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::UnsupportedNetworkEvent,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed TCP segment fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Tcp),
                );
                return Ok(());
            }
        };
        let source = SocketAddr::new(IpAddr::V4(parsed.source), tcp.source_port);
        let destination = SocketAddr::new(IpAddr::V4(parsed.destination), tcp.destination_port);
        match tcp.destination_port {
            80 => self.inspect_http(&sandbox_id, source, destination, tcp.payload),
            443 => self.inspect_tls(&sandbox_id, source, destination, tcp.payload),
            _ => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::UnsupportedNetworkEvent,
                        sandbox_id,
                        Decision::FailClosed,
                        "no transparent inspector for TCP destination port",
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Unsupported)
                    .with_addresses(Some(source), Some(destination)),
                );
                Ok(())
            }
        }
    }

    fn inspect_http(
        &mut self,
        sandbox_id: &str,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), String> {
        let parsed = match parse_http_request(payload) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::HttpRequest,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed transparent HTTP request fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Http)
                    .with_addresses(Some(source), Some(destination)),
                );
                return Ok(());
            }
        };
        let request = PolicyRequest::new(sandbox_id, Frontend::Tun, Protocol::Http)
            .with_source(source.ip(), source.port())
            .with_destination(destination.ip(), destination.port())
            .with_hostname(&parsed.host, AttributionConfidence::High)
            .with_http(&parsed.method, &parsed.path);
        let outcome = self.policy.evaluate(&request);
        self.audit.push(
            AuditRecord::new(
                EventKind::HttpRequest,
                sandbox_id,
                outcome.decision,
                outcome.reason,
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Http)
            .with_addresses(Some(source), Some(destination))
            .with_hostname(
                Some(parsed.host),
                AttributionSource::HttpHost,
                AttributionConfidence::High,
            )
            .with_rule(outcome.rule_id)
            .with_metadata("method", parsed.method)
            .with_metadata("path", parsed.path),
        );
        Ok(())
    }

    fn inspect_tls(
        &mut self,
        sandbox_id: &str,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), String> {
        let dns_attr = self
            .dns_cache
            .attribution_for(destination.ip(), self.now_tick);
        let parsed = match parse_tls_client_hello(payload) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::TlsClientHello,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed TLS ClientHello fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Tls)
                    .with_addresses(Some(source), Some(destination)),
                );
                return Ok(());
            }
        };
        let hostname = parsed
            .sni
            .clone()
            .or_else(|| dns_attr.as_ref().map(|attr| attr.hostname.clone()));
        let confidence = if parsed.sni.is_some() {
            AttributionConfidence::High
        } else {
            dns_attr
                .as_ref()
                .map(|attr| attr.confidence)
                .unwrap_or(AttributionConfidence::None)
        };
        let attribution_source = if parsed.sni.is_some() {
            AttributionSource::TlsSni
        } else {
            dns_attr
                .as_ref()
                .map(|attr| attr.source)
                .unwrap_or(AttributionSource::None)
        };
        let mismatch = match (parsed.sni.as_deref(), dns_attr.as_ref()) {
            (Some(sni), Some(attr)) => sni != attr.hostname,
            _ => false,
        };

        let mut request = PolicyRequest::new(sandbox_id, Frontend::Tun, Protocol::Tls)
            .with_source(source.ip(), source.port())
            .with_destination(destination.ip(), destination.port());
        if let Some(hostname) = &hostname {
            request = request.with_hostname(hostname, confidence);
        }
        request.sni_dns_mismatch = mismatch;
        request.hidden_sni = parsed.hidden_sni;
        let outcome = self.policy.evaluate(&request);
        self.audit.push(
            AuditRecord::new(
                EventKind::TlsClientHello,
                sandbox_id,
                outcome.decision,
                outcome.reason,
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Tls)
            .with_addresses(Some(source), Some(destination))
            .with_hostname(hostname, attribution_source, confidence)
            .with_rule(outcome.rule_id)
            .with_metadata("hidden_sni", parsed.hidden_sni.to_string())
            .with_metadata("sni_dns_mismatch", mismatch.to_string()),
        );
        Ok(())
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
    fn quic_candidate_uses_quic_policy_and_audit_event() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 443);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().allow_quic(true).with_rule(
                PolicyRule::new("allow-attributed-quic", RuleAction::Allow)
                    .protocol(Protocol::Quic)
                    .domain_suffix("example")
                    .port(443)
                    .require_hostname_attribution(),
            ),
        );
        let egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 5,
                bytes_received: 10,
                message: "mock QUIC UDP forwarded".to_string(),
                response_payload: b"quic-reply".to_vec(),
            },
        );
        let mut cache = DnsCache::new();
        cache
            .observe_response("lab.example", [destination.ip()], 1, 60)
            .unwrap();
        let mut runtime = TransparentUdpRuntime::new(policy, egress).with_dns_cache(cache, 2);
        let packet = udp_probe_packet(destination.ip(), destination.port(), &[0xc3, 1, 2, 3, 4]);
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert!(reply.is_some());
        assert_eq!(runtime.audit[0].kind, EventKind::QuicCandidateFlow);
        assert_eq!(runtime.audit[0].protocol, Some(Protocol::Quic));
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(
            runtime.audit[0].rule_id.as_deref(),
            Some("allow-attributed-quic")
        );
        assert_eq!(runtime.egress.requests.len(), 1);
    }

    #[test]
    fn tcp_syn_connect_attempt_uses_policy_before_egress() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-example-tcp", RuleAction::Allow)
                    .protocol(Protocol::Tcp)
                    .domain_suffix("example.com")
                    .port(443)
                    .require_hostname_attribution(),
            ),
        );
        let egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 0,
                bytes_received: 0,
                message: "mock TCP connected".to_string(),
                response_payload: Vec::new(),
            },
        );
        let mut cache = DnsCache::new();
        cache
            .observe_response("www.example.com", [destination.ip()], 1, 60)
            .unwrap();
        let mut runtime = TransparentTcpRuntime::new(policy, egress).with_dns_cache(cache, 2);
        let packet = tcp_syn_packet(destination.ip(), destination.port());
        runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert_eq!(runtime.egress.requests.len(), 1);
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(
            runtime.audit[0].hostname.as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            runtime.audit[0].rule_id.as_deref(),
            Some("allow-example-tcp")
        );
    }

    #[test]
    fn denied_tcp_syn_never_reaches_egress() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)), 443);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let egress = MockEgressBackend::new();
        let mut runtime = TransparentTcpRuntime::new(policy, egress);
        let packet = tcp_syn_packet(destination.ip(), destination.port());
        runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert!(runtime.egress.requests.is_empty());
        assert_eq!(runtime.audit[0].decision, Decision::DenyReset);
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

    #[test]
    fn tcp_bridge_runtime_denied_syn_emits_rst_before_stack() {
        let destination = Ipv4Addr::new(203, 0, 113, 22);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut runtime = TransparentTcpBridgeRuntime::listen(destination, 80, policy).unwrap();
        let packet = tcp_syn_packet(IpAddr::V4(destination), 80);
        let step = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert_eq!(runtime.audit[0].decision, Decision::DenyReset);
        assert_eq!(step.emitted_packets.len(), 1);
        let rst_ip = parse_ipv4(&step.emitted_packets[0]).unwrap();
        let rst_tcp = parse_tcp(rst_ip.payload).unwrap();
        assert!(rst_tcp.rst);
        assert!(step.egress_payload.is_none());
    }

    #[test]
    fn tcp_bridge_runtime_allowed_syn_enters_smoltcp() {
        let destination = Ipv4Addr::new(203, 0, 113, 22);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-bridge", RuleAction::Allow)
                    .protocol(Protocol::Tcp)
                    .destination(Cidr::host(IpAddr::V4(destination)))
                    .port(80),
            ),
        );
        let mut runtime = TransparentTcpBridgeRuntime::listen(destination, 80, policy).unwrap();
        let packet = tcp_syn_packet(IpAddr::V4(destination), 80);
        let step = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert!(step.emitted_packets.iter().any(|packet| {
            let Ok(ipv4) = parse_ipv4(packet) else {
                return false;
            };
            let Ok(tcp) = parse_tcp(ipv4.payload) else {
                return false;
            };
            tcp.syn && tcp.ack
        }));
    }

    #[test]
    fn icmp_echo_reply_requires_ping_policy() {
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default().allow_ping(true));
        let mut runtime = TransparentIcmpRuntime::new(policy);
        let packet = icmp_echo_packet();
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap().unwrap();
        let parsed = parse_ipv4(&reply).unwrap();
        assert_eq!(parsed.source, Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(parsed.destination, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(runtime.audit[0].kind, EventKind::IcmpMessage);
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(runtime.audit[0].bytes_out, reply.len() as u64);
    }

    #[test]
    fn icmp_echo_denied_without_ping_policy() {
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut runtime = TransparentIcmpRuntime::new(policy);
        let packet = icmp_echo_packet();
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert!(reply.is_none());
        assert_eq!(runtime.audit[0].decision, Decision::DenyIcmpUnreachable);
    }

    #[test]
    fn transparent_http_host_path_rule_is_audited() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80)), 80);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-transparent-http-public", RuleAction::Allow)
                    .protocol(Protocol::Http)
                    .hostname("example.com")
                    .http_path_prefix("/public"),
            ),
        );
        let mut runtime = TransparentInspectionRuntime::new(policy);
        let packet = tcp_payload_packet(
            destination.ip(),
            destination.port(),
            b"GET /public?q=1 HTTP/1.1\r\nHost: Example.COM\r\n\r\n",
        );
        runtime.inspect_ipv4_tcp_payload("lab", &packet).unwrap();
        assert_eq!(runtime.audit[0].kind, EventKind::HttpRequest);
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(runtime.audit[0].hostname.as_deref(), Some("example.com"));
        assert_eq!(
            runtime.audit[0].metadata.get("path").map(String::as_str),
            Some("/public?q=1")
        );
    }

    #[test]
    fn tls_sni_dns_mismatch_fails_closed() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44)), 443);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-example-tls", RuleAction::Allow)
                    .protocol(Protocol::Tls)
                    .hostname("example.com")
                    .port(443),
            ),
        );
        let mut cache = DnsCache::new();
        cache
            .observe_response("other.example", [destination.ip()], 1, 60)
            .unwrap();
        let mut runtime = TransparentInspectionRuntime::new(policy).with_dns_cache(cache, 2);
        let packet = tcp_payload_packet(
            destination.ip(),
            destination.port(),
            &tls_client_hello_fixture(Some("example.com")),
        );
        runtime.inspect_ipv4_tcp_payload("lab", &packet).unwrap();
        assert_eq!(runtime.audit[0].kind, EventKind::TlsClientHello);
        assert_eq!(runtime.audit[0].decision, Decision::FailClosed);
        assert_eq!(
            runtime.audit[0]
                .metadata
                .get("sni_dns_mismatch")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn hidden_sni_requires_explicit_ip_allow_in_inspection_runtime() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45)), 443);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut runtime = TransparentInspectionRuntime::new(policy);
        let packet = tcp_payload_packet(
            destination.ip(),
            destination.port(),
            &tls_client_hello_fixture(None),
        );
        runtime.inspect_ipv4_tcp_payload("lab", &packet).unwrap();
        assert_eq!(runtime.audit[0].kind, EventKind::TlsClientHello);
        assert_eq!(runtime.audit[0].decision, Decision::FailClosed);
        assert_eq!(
            runtime.audit[0]
                .metadata
                .get("hidden_sni")
                .map(String::as_str),
            Some("true")
        );
    }

    fn tcp_syn_packet(destination: IpAddr, destination_port: u16) -> Vec<u8> {
        let IpAddr::V4(destination) = destination else {
            panic!("test destination must be IPv4");
        };
        let total_len = 40;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 2, 2]);
        packet[16..20].copy_from_slice(&destination.octets());
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet[20..22].copy_from_slice(&49152_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x02;
        packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
        let tcp_sum = tcp_checksum_ipv4(Ipv4Addr::new(10, 0, 2, 2), destination, &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    fn tcp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp_segment);
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }
        checksum(&pseudo)
    }

    fn icmp_echo_packet() -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'];
        let icmp_sum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_sum.to_be_bytes());
        let total_len = 20 + icmp.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 2, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 2, 1]);
        packet[20..].copy_from_slice(&icmp);
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn tcp_payload_packet(destination: IpAddr, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let IpAddr::V4(destination) = destination else {
            panic!("test destination must be IPv4");
        };
        let total_len = 40 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 2, 2]);
        packet[16..20].copy_from_slice(&destination.octets());
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet[20..22].copy_from_slice(&49152_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
        packet[28..32].copy_from_slice(&1_u32.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn tls_client_hello_fixture(host: Option<&str>) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);

        let mut extensions = Vec::new();
        if let Some(host) = host {
            let host_bytes = host.as_bytes();
            let mut sni = Vec::new();
            let list_len = 1 + 2 + host_bytes.len();
            sni.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni.push(0);
            sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            sni.extend_from_slice(host_bytes);
            extensions.extend_from_slice(&0u16.to_be_bytes());
            extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni);
        }
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = hello.len();
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
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
