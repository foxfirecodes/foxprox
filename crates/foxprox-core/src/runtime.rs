use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::audit::{
    AttributionConfidence, AttributionSource, AuditRecord, BoundedAuditBuffer, Decision, EventKind,
    Frontend, Protocol,
};
use crate::dns::{a_response_addresses, parse_dns_query, synthesize_a_response, DnsCache};
use crate::egress::{EgressBackend, EgressRequest};
use crate::origin::{
    parse_connect_request, parse_connect_target, parse_http_request, parse_socks5_connect_request,
    parse_tls_client_hello, ConnectTarget, HttpRequestMeta, SocksConnectRequest,
};
use crate::packet::{
    parse_icmp_echo_request, parse_ipv4, parse_tcp, parse_udp, synthesize_icmp_echo_reply,
    synthesize_udp_reply,
};
use crate::policy::{PolicyEngine, PolicyRequest};
use crate::smoltcp_gate::SmoltcpTcpServerHarness;

/// Flush pending runtime audit records into a bounded sink.
///
/// If the sink is full, the rejected record is preserved in `records` and callers can fail closed
/// without losing audit evidence or allocating an unbounded queue.
pub fn flush_audit_to_buffer(
    records: &mut Vec<AuditRecord>,
    sink: &mut BoundedAuditBuffer,
) -> Result<usize, String> {
    let mut flushed = 0;
    while !records.is_empty() {
        let record = records.remove(0);
        match sink.push(record) {
            Ok(()) => flushed += 1,
            Err(record) => {
                records.insert(0, record);
                return Err(format!(
                    "audit buffer full after flushing {flushed} record(s); capacity={}, queued={}",
                    sink.capacity(),
                    sink.len()
                ));
            }
        }
    }
    Ok(flushed)
}

/// Packet-level route used by long-lived transparent broker loops to dispatch a TUN IPv4 packet
/// into the appropriate reusable runtime boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentPacketRoute {
    BrokerDns,
    DirectDns,
    Udp,
    Tcp,
    Icmp,
    Unsupported(Protocol),
}

pub fn route_transparent_ipv4_packet(
    packet: &[u8],
    broker_dns: SocketAddr,
) -> Result<TransparentPacketRoute, String> {
    let parsed = parse_ipv4(packet).map_err(|err| {
        if err == "not an IPv4 packet" {
            "non-IPv4 packet denied in alpha TUN path".to_string()
        } else {
            format!("malformed IPv4 packet: {err}")
        }
    })?;
    match parsed.protocol_number {
        17 => {
            let udp =
                parse_udp(parsed.payload).map_err(|err| format!("malformed UDP packet: {err}"))?;
            let destination = SocketAddr::new(IpAddr::V4(parsed.destination), udp.destination_port);
            if destination == broker_dns {
                Ok(TransparentPacketRoute::BrokerDns)
            } else if udp.destination_port == 53 {
                Ok(TransparentPacketRoute::DirectDns)
            } else {
                Ok(TransparentPacketRoute::Udp)
            }
        }
        6 => Ok(TransparentPacketRoute::Tcp),
        1 => Ok(TransparentPacketRoute::Icmp),
        _ => Ok(TransparentPacketRoute::Unsupported(parsed.protocol())),
    }
}

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

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
    }
}

/// Reusable explicit proxy policy/audit runtime.
///
/// This runtime parses explicit HTTP, HTTPS CONNECT, and SOCKS5 TCP CONNECT requests, applies the
/// shared policy engine, and records normalized audit. Socket tunneling remains in the caller or a
/// future egress crate.
#[derive(Debug)]
pub struct ExplicitProxyRuntime {
    pub policy: PolicyEngine,
    pub audit: Vec<AuditRecord>,
}

impl ExplicitProxyRuntime {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            audit: Vec::new(),
        }
    }

    pub fn evaluate_http_request(
        &mut self,
        sandbox_id: impl Into<String>,
        bytes: &[u8],
        egress_destination: SocketAddr,
    ) -> Result<Option<HttpRequestMeta>, String> {
        let sandbox_id = sandbox_id.into();
        let parsed = match parse_http_request(bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::HttpRequest,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed HTTP proxy request fails closed: {err}"),
                    )
                    .with_frontend(Frontend::HttpProxy)
                    .with_protocol(Protocol::Http),
                );
                return Ok(None);
            }
        };
        let request = PolicyRequest::new(&sandbox_id, Frontend::HttpProxy, Protocol::Http)
            .with_destination(egress_destination.ip(), parsed.port)
            .with_hostname(&parsed.host, AttributionConfidence::High)
            .with_http(&parsed.method, &parsed.path);
        let outcome = self.policy.evaluate(&request);
        let allowed = outcome.decision.is_allow();
        self.audit.push(
            AuditRecord::new(
                EventKind::HttpRequest,
                sandbox_id,
                outcome.decision,
                outcome.reason,
            )
            .with_frontend(Frontend::HttpProxy)
            .with_protocol(Protocol::Http)
            .with_addresses(None, Some(egress_destination))
            .with_hostname(
                Some(parsed.host.clone()),
                AttributionSource::ExplicitProxy,
                AttributionConfidence::High,
            )
            .with_rule(outcome.rule_id)
            .with_metadata("method", parsed.method.clone())
            .with_metadata("path", parsed.path.clone()),
        );
        Ok(allowed.then_some(parsed))
    }

    pub fn evaluate_https_connect_request(
        &mut self,
        sandbox_id: impl Into<String>,
        bytes: &[u8],
        egress_destination: SocketAddr,
    ) -> Result<Option<ConnectTarget>, String> {
        let sandbox_id = sandbox_id.into();
        let parsed = match parse_connect_request(bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::HttpsConnect,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed CONNECT request fails closed: {err}"),
                    )
                    .with_frontend(Frontend::HttpProxy)
                    .with_protocol(Protocol::HttpsConnect),
                );
                return Ok(None);
            }
        };
        self.evaluate_https_connect_target(sandbox_id, parsed, egress_destination)
    }

    pub fn evaluate_https_connect(
        &mut self,
        sandbox_id: impl Into<String>,
        target: &str,
        egress_destination: SocketAddr,
    ) -> Result<Option<ConnectTarget>, String> {
        let sandbox_id = sandbox_id.into();
        let parsed = match parse_connect_target(target) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::HttpsConnect,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed CONNECT target fails closed: {err}"),
                    )
                    .with_frontend(Frontend::HttpProxy)
                    .with_protocol(Protocol::HttpsConnect),
                );
                return Ok(None);
            }
        };
        self.evaluate_https_connect_target(sandbox_id, parsed, egress_destination)
    }

    fn evaluate_https_connect_target(
        &mut self,
        sandbox_id: String,
        parsed: ConnectTarget,
        egress_destination: SocketAddr,
    ) -> Result<Option<ConnectTarget>, String> {
        let request = PolicyRequest::new(&sandbox_id, Frontend::HttpProxy, Protocol::HttpsConnect)
            .with_destination(egress_destination.ip(), parsed.port)
            .with_hostname(&parsed.host, AttributionConfidence::High);
        let outcome = self.policy.evaluate(&request);
        let allowed = outcome.decision.is_allow();
        self.audit.push(
            AuditRecord::new(
                EventKind::HttpsConnect,
                sandbox_id,
                outcome.decision,
                outcome.reason,
            )
            .with_frontend(Frontend::HttpProxy)
            .with_protocol(Protocol::HttpsConnect)
            .with_addresses(None, Some(egress_destination))
            .with_hostname(
                Some(parsed.host.clone()),
                AttributionSource::ExplicitProxy,
                AttributionConfidence::High,
            )
            .with_rule(outcome.rule_id)
            .with_metadata("connect_port", parsed.port.to_string()),
        );
        Ok(allowed.then_some(parsed))
    }

    pub fn evaluate_socks5_connect(
        &mut self,
        sandbox_id: impl Into<String>,
        bytes: &[u8],
        egress_destination: SocketAddr,
    ) -> Result<Option<SocksConnectRequest>, String> {
        let sandbox_id = sandbox_id.into();
        let parsed = match parse_socks5_connect_request(bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::SocksConnect,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed or unsupported SOCKS5 request fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Socks5)
                    .with_protocol(Protocol::Socks),
                );
                return Ok(None);
            }
        };
        let request = PolicyRequest::new(&sandbox_id, Frontend::Socks5, Protocol::Socks)
            .with_destination(egress_destination.ip(), parsed.destination_port)
            .with_hostname(&parsed.destination_host, AttributionConfidence::High);
        let outcome = self.policy.evaluate(&request);
        let allowed = outcome.decision.is_allow();
        self.audit.push(
            AuditRecord::new(
                EventKind::SocksConnect,
                sandbox_id,
                outcome.decision,
                outcome.reason,
            )
            .with_frontend(Frontend::Socks5)
            .with_protocol(Protocol::Socks)
            .with_addresses(None, Some(egress_destination))
            .with_hostname(
                Some(parsed.destination_host.clone()),
                AttributionSource::ExplicitProxy,
                AttributionConfidence::High,
            )
            .with_rule(outcome.rule_id)
            .with_metadata("connect_port", parsed.destination_port.to_string()),
        );
        Ok(allowed.then_some(parsed))
    }

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
    }
}

/// Minimal broker-local DNS runtime for transparent UDP/53 packets.
#[derive(Debug)]
pub struct TransparentDnsRuntime {
    answers: BTreeMap<String, Ipv4Addr>,
    pub audit: Vec<AuditRecord>,
    pub dns_cache: DnsCache,
    pub now_tick: u64,
    pub ttl_ticks: u64,
    pub upstream_dns: Option<SocketAddr>,
}

impl TransparentDnsRuntime {
    pub fn new(answers: impl IntoIterator<Item = (String, Ipv4Addr)>) -> Self {
        Self {
            answers: answers.into_iter().collect(),
            audit: Vec::new(),
            dns_cache: DnsCache::new(),
            now_tick: 1,
            ttl_ticks: 60,
            upstream_dns: None,
        }
    }

    pub fn with_upstream_dns(mut self, upstream_dns: SocketAddr) -> Self {
        self.upstream_dns = Some(upstream_dns);
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
                    "DNS runtime received non-UDP packet",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(parsed.protocol()),
            );
            return Ok(None);
        }
        let udp =
            parse_udp(parsed.payload).map_err(|err| format!("malformed UDP packet: {err}"))?;
        let source = SocketAddr::new(IpAddr::V4(parsed.source), udp.source_port);
        let destination = SocketAddr::new(IpAddr::V4(parsed.destination), udp.destination_port);
        if udp.destination_port != 53 {
            self.audit.push(
                AuditRecord::new(
                    EventKind::DnsQuery,
                    sandbox_id,
                    Decision::FailClosed,
                    "DNS runtime received UDP packet not addressed to broker DNS port",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(Protocol::Dns)
                .with_addresses(Some(source), Some(destination)),
            );
            return Ok(None);
        }
        let query = match parse_dns_query(udp.payload) {
            Ok(query) => query,
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::DnsQuery,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("malformed DNS query fails closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Dns)
                    .with_addresses(Some(source), Some(destination)),
                );
                return Ok(None);
            }
        };
        let Some(answer) = self.answers.get(&query.hostname).copied() else {
            if let Some(upstream) = self.upstream_dns {
                return self.forward_upstream_dns(
                    &sandbox_id,
                    packet,
                    udp.payload,
                    &query.hostname,
                    query.query_type.as_str(),
                    source,
                    destination,
                    upstream,
                );
            }
            self.audit.push(
                AuditRecord::new(
                    EventKind::DnsQuery,
                    sandbox_id,
                    Decision::DenyDrop,
                    "DNS hostname has no local alpha answer",
                )
                .with_frontend(Frontend::Tun)
                .with_protocol(Protocol::Dns)
                .with_addresses(Some(source), Some(destination))
                .with_hostname(
                    Some(query.hostname),
                    AttributionSource::DnsCache,
                    AttributionConfidence::Medium,
                )
                .with_metadata("query_type", query.query_type.as_str()),
            );
            return Ok(None);
        };
        let dns_response = synthesize_a_response(udp.payload, answer, self.ttl_ticks as u32)?;
        let reply = synthesize_udp_reply(packet, &dns_response)?;
        self.dns_cache.observe_response(
            &query.hostname,
            [IpAddr::V4(answer)],
            self.now_tick,
            self.ttl_ticks,
        )?;
        self.audit.push(
            AuditRecord::new(
                EventKind::DnsQuery,
                sandbox_id,
                Decision::Allow,
                "broker DNS query answered locally",
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Dns)
            .with_addresses(Some(source), Some(destination))
            .with_hostname(
                Some(query.hostname),
                AttributionSource::DnsCache,
                AttributionConfidence::Medium,
            )
            .with_metadata("query_type", query.query_type.as_str())
            .with_metadata("answer", answer.to_string()),
        );
        Ok(Some(reply))
    }

    fn forward_upstream_dns(
        &mut self,
        sandbox_id: &str,
        original_packet: &[u8],
        wire_query: &[u8],
        hostname: &str,
        query_type: String,
        source: SocketAddr,
        destination: SocketAddr,
        upstream: SocketAddr,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut record = AuditRecord::new(
            EventKind::DnsQuery,
            sandbox_id,
            Decision::Allow,
            "broker DNS query forwarded upstream",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Dns)
        .with_addresses(Some(source), Some(destination))
        .with_hostname(
            Some(hostname.to_string()),
            AttributionSource::DnsCache,
            AttributionConfidence::Medium,
        )
        .with_metadata("query_type", query_type)
        .with_metadata("upstream", upstream.to_string());

        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|err| format!("upstream DNS socket bind failed: {err}"))?;
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .map_err(|err| format!("upstream DNS timeout setup failed: {err}"))?;
        match socket.send_to(wire_query, upstream) {
            Ok(sent) => record.bytes_in = sent as u64,
            Err(err) => {
                record.decision = Decision::FailClosed;
                record.reason = format!("upstream DNS send failed closed: {err}");
                self.audit.push(record);
                return Ok(None);
            }
        }
        let mut response = [0_u8; 4096];
        let received = match socket.recv_from(&mut response) {
            Ok((received, _)) => received,
            Err(err) => {
                record.decision = Decision::FailClosed;
                record.reason = format!("upstream DNS receive failed closed: {err}");
                self.audit.push(record);
                return Ok(None);
            }
        };
        let response = &response[..received];
        let addresses = a_response_addresses(response).unwrap_or_default();
        if !addresses.is_empty() {
            let ips = addresses
                .iter()
                .copied()
                .map(IpAddr::V4)
                .collect::<Vec<_>>();
            self.dns_cache
                .observe_response(hostname, ips, self.now_tick, self.ttl_ticks)?;
            record = record.with_metadata(
                "answers",
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        record.bytes_out = received as u64;
        let reply = synthesize_udp_reply(original_packet, response)?;
        self.audit.push(record);
        Ok(Some(reply))
    }

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
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

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
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

    pub fn try_send_egress_response(
        &mut self,
        bytes: &[u8],
    ) -> Result<(usize, Vec<Vec<u8>>), String> {
        let sent = self.stack.send_available(bytes)?;
        Ok((sent, self.stack.drain_emitted_packets()))
    }

    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.stack.poll()?;
        Ok(self.stack.drain_emitted_packets())
    }

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
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

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
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

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
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
    fn routes_transparent_packets_to_runtime_boundaries() {
        let broker_dns = "10.0.2.1:53".parse().unwrap();
        let dns = udp_probe_packet(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 53, b"dns");
        let direct_dns = udp_probe_packet(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53, b"dns");
        let udp = udp_probe_packet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5354, b"probe");
        let tcp = tcp_syn_packet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22)), 80);
        let icmp = icmp_echo_packet();

        assert_eq!(
            route_transparent_ipv4_packet(&dns, broker_dns).unwrap(),
            TransparentPacketRoute::BrokerDns
        );
        assert_eq!(
            route_transparent_ipv4_packet(&direct_dns, broker_dns).unwrap(),
            TransparentPacketRoute::DirectDns
        );
        assert_eq!(
            route_transparent_ipv4_packet(&udp, broker_dns).unwrap(),
            TransparentPacketRoute::Udp
        );
        assert_eq!(
            route_transparent_ipv4_packet(&tcp, broker_dns).unwrap(),
            TransparentPacketRoute::Tcp
        );
        assert_eq!(
            route_transparent_ipv4_packet(&icmp, broker_dns).unwrap(),
            TransparentPacketRoute::Icmp
        );
    }

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
    fn explicit_proxy_runtime_allows_http_request_by_host_path() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-http-proxy", RuleAction::Allow)
                    .protocol(Protocol::Http)
                    .hostname("example.com")
                    .http_path_prefix("/ok"),
            ),
        );
        let mut runtime = ExplicitProxyRuntime::new(policy);
        let parsed = runtime
            .evaluate_http_request(
                "lab",
                b"GET http://example.com/ok HTTP/1.1\r\nHost: example.com\r\n\r\n",
                destination,
            )
            .unwrap()
            .unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(
            runtime.audit[0].rule_id.as_deref(),
            Some("allow-http-proxy")
        );
    }

    #[test]
    fn explicit_proxy_runtime_denies_malformed_socks_before_egress() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut runtime = ExplicitProxyRuntime::new(policy);
        let parsed = runtime
            .evaluate_socks5_connect(
                "lab",
                &[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53],
                destination,
            )
            .unwrap();
        assert!(parsed.is_none());
        assert_eq!(runtime.audit[0].decision, Decision::FailClosed);
        assert!(runtime.audit[0].reason.contains("SOCKS5"));
    }

    #[test]
    fn dns_runtime_answers_and_caches_local_a_record() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 53);
        let mut runtime = TransparentDnsRuntime::new([(
            "lab.example".to_string(),
            Ipv4Addr::new(203, 0, 113, 77),
        )]);
        let packet = udp_probe_packet(
            destination.ip(),
            destination.port(),
            &dns_a_query("lab.example"),
        );
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap().unwrap();
        assert!(reply.ends_with(&[203, 0, 113, 77]));
        assert_eq!(runtime.audit[0].kind, EventKind::DnsQuery);
        assert_eq!(runtime.audit[0].decision, Decision::Allow);
        assert_eq!(runtime.audit[0].hostname.as_deref(), Some("lab.example"));
        assert!(runtime
            .dns_cache
            .attribution_for(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 2)
            .is_some());
    }

    #[test]
    fn dns_runtime_denies_unknown_local_name_without_reply() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 53);
        let mut runtime = TransparentDnsRuntime::new([]);
        let packet = udp_probe_packet(
            destination.ip(),
            destination.port(),
            &dns_a_query("blocked.example"),
        );
        let reply = runtime.handle_ipv4_packet("lab", &packet).unwrap();
        assert!(reply.is_none());
        assert_eq!(runtime.audit[0].decision, Decision::DenyDrop);
        assert_eq!(
            runtime.audit[0].hostname.as_deref(),
            Some("blocked.example")
        );
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
    fn udp_runtime_flushes_audit_to_bounded_sink() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5354);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let egress = MockEgressBackend::new();
        let mut runtime = TransparentUdpRuntime::new(policy, egress);
        let packet = udp_probe_packet(destination.ip(), destination.port(), b"probe");
        runtime.handle_ipv4_packet("lab", &packet).unwrap();
        let mut sink = BoundedAuditBuffer::new(1);
        assert_eq!(runtime.flush_audit_to(&mut sink).unwrap(), 1);
        assert_eq!(runtime.audit.len(), 0);
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn explicit_proxy_runtime_flushes_audit_to_bounded_sink() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut runtime = ExplicitProxyRuntime::new(policy);
        runtime
            .evaluate_http_request(
                "lab",
                b"GET /blocked HTTP/1.1\r\nHost: example.com\r\n\r\n",
                destination,
            )
            .unwrap();
        let mut sink = BoundedAuditBuffer::new(1);
        assert_eq!(runtime.flush_audit_to(&mut sink).unwrap(), 1);
        assert_eq!(runtime.audit.len(), 0);
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn audit_flush_preserves_record_when_bounded_sink_is_full() {
        let mut records = vec![
            AuditRecord::new(EventKind::BrokerStarted, "lab", Decision::Allow, "started"),
            AuditRecord::new(
                EventKind::BrokerError,
                "lab",
                Decision::FailClosed,
                "second",
            ),
        ];
        let mut sink = BoundedAuditBuffer::new(1);
        let err = flush_audit_to_buffer(&mut records, &mut sink).unwrap_err();
        assert!(err.contains("audit buffer full"));
        assert_eq!(sink.len(), 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, "second");
    }

    #[test]
    fn tcp_bridge_runtime_flushes_audit_to_bounded_sink() {
        let destination = Ipv4Addr::new(203, 0, 113, 22);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut runtime = TransparentTcpBridgeRuntime::listen(destination, 80, policy).unwrap();
        let packet = tcp_syn_packet(IpAddr::V4(destination), 80);
        runtime.handle_ipv4_packet("lab", &packet).unwrap();
        let mut sink = BoundedAuditBuffer::new(2);
        let flushed = runtime.flush_audit_to(&mut sink).unwrap();
        assert_eq!(flushed, 1);
        assert_eq!(runtime.audit.len(), 0);
        assert_eq!(sink.len(), 1);
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

    fn dns_a_query(hostname: &str) -> Vec<u8> {
        let mut wire = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in hostname.split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire
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
