use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::attribution::Hostname;
use crate::dns::{DnsQueryMetadata, DnsQueryType};
use crate::policy::{Decision, DenialReason, DenyBehavior, PolicyRequest};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};

/// Structured audit event. Serialization is intentionally left to outer crates;
/// the core owns a stable schema and required fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub kind: AuditEventKind,
    pub frontend: Option<Frontend>,
    pub protocol: Option<Protocol>,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub requested_port: Option<u16>,
    pub hostname: Option<Hostname>,
    pub hostname_source: HostnameSource,
    pub hostname_confidence: HostnameConfidence,
    pub dns_query_type: Option<DnsQueryType>,
    pub decision: Option<AuditDecision>,
    pub rule_id: Option<String>,
    pub reason: Option<DenialReason>,
    pub http_method: Option<String>,
    pub http_path_query: Option<String>,
    pub byte_count: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPolicyContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub kind: AuditEventKind,
    pub frontend: Frontend,
    pub protocol: Protocol,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub requested_port: Option<u16>,
    pub hostname: Option<Hostname>,
    pub hostname_source: HostnameSource,
    pub hostname_confidence: HostnameConfidence,
    pub http_method: Option<String>,
    pub http_path_query: Option<String>,
}

impl AuditPolicyContext {
    pub fn from_request(
        timestamp_millis: u64,
        kind: AuditEventKind,
        request: &PolicyRequest,
    ) -> Self {
        Self {
            timestamp_millis,
            sandbox_id: request.sandbox_id.clone(),
            kind,
            frontend: request.frontend,
            protocol: request.protocol,
            source: request.source,
            destination: request.destination,
            requested_port: request.requested_port,
            hostname: request.attribution.hostname.clone(),
            hostname_source: request.attribution.source,
            hostname_confidence: request.attribution.confidence,
            http_method: request.http_method.clone(),
            http_path_query: request.http_path_query.clone(),
        }
    }
}

impl AuditEvent {
    pub fn from_policy_decision(context: AuditPolicyContext, decision: &Decision) -> Self {
        let (audit_decision, rule_id, reason) = audit_decision_fields(decision);

        Self {
            timestamp_millis: context.timestamp_millis,
            sandbox_id: context.sandbox_id,
            kind: context.kind,
            frontend: Some(context.frontend),
            protocol: Some(context.protocol),
            source: context.source,
            destination: context.destination,
            requested_port: context.requested_port,
            hostname: context.hostname,
            hostname_source: context.hostname_source,
            hostname_confidence: context.hostname_confidence,
            dns_query_type: None,
            decision: audit_decision,
            rule_id,
            reason,
            http_method: context.http_method,
            http_path_query: context.http_path_query,
            byte_count: None,
        }
    }

    pub fn from_dns_query_metadata(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        frontend: Frontend,
        source: Option<Endpoint>,
        destination: Option<Endpoint>,
        metadata: &DnsQueryMetadata,
        decision: &Decision,
    ) -> Self {
        let (audit_decision, rule_id, reason) = audit_decision_fields(decision);

        Self {
            timestamp_millis,
            sandbox_id,
            kind: AuditEventKind::DnsQuery,
            frontend: Some(frontend),
            protocol: Some(Protocol::Dns),
            source,
            destination,
            requested_port: destination.and_then(|endpoint| endpoint.port),
            hostname: Some(metadata.hostname.clone()),
            hostname_source: HostnameSource::BrokerDnsQuery,
            hostname_confidence: HostnameConfidence::High,
            dns_query_type: Some(metadata.query_type),
            decision: audit_decision,
            rule_id,
            reason,
            http_method: None,
            http_path_query: None,
            byte_count: None,
        }
    }

    pub fn to_json_line(&self) -> String {
        let mut out = String::new();
        out.push('{');
        push_json_u64_field(&mut out, "timestamp_millis", self.timestamp_millis, true);
        push_json_string_field(&mut out, "sandbox_id", self.sandbox_id.as_str(), false);
        push_json_string_field(&mut out, "kind", audit_event_kind_name(self.kind), false);
        push_json_option_string_field(
            &mut out,
            "frontend",
            self.frontend.map(frontend_name),
            false,
        );
        push_json_protocol_field(&mut out, "protocol", self.protocol, false);
        push_json_endpoint_field(&mut out, "source", self.source, false);
        push_json_endpoint_field(&mut out, "destination", self.destination, false);
        push_json_option_u16_field(&mut out, "requested_port", self.requested_port, false);
        push_json_option_string_field(
            &mut out,
            "hostname",
            self.hostname.as_ref().map(|hostname| hostname.as_str()),
            false,
        );
        push_json_string_field(
            &mut out,
            "hostname_source",
            hostname_source_name(self.hostname_source),
            false,
        );
        push_json_string_field(
            &mut out,
            "hostname_confidence",
            hostname_confidence_name(self.hostname_confidence),
            false,
        );
        push_json_option_string_field(
            &mut out,
            "dns_query_type",
            self.dns_query_type.map(dns_query_type_name),
            false,
        );
        push_json_option_string_field(
            &mut out,
            "decision",
            self.decision.map(audit_decision_name),
            false,
        );
        push_json_option_string_field(
            &mut out,
            "deny_behavior",
            self.decision.and_then(audit_deny_behavior_name),
            false,
        );
        push_json_option_string_field(&mut out, "rule_id", self.rule_id.as_deref(), false);
        push_json_option_string_field(
            &mut out,
            "reason",
            self.reason.map(denial_reason_name),
            false,
        );
        push_json_option_string_field(&mut out, "http_method", self.http_method.as_deref(), false);
        push_json_option_string_field(
            &mut out,
            "http_path_query",
            self.http_path_query.as_deref(),
            false,
        );
        push_json_option_u64_field(&mut out, "byte_count", self.byte_count, false);
        out.push('}');
        out
    }
}

fn audit_decision_fields(
    decision: &Decision,
) -> (Option<AuditDecision>, Option<String>, Option<DenialReason>) {
    match decision {
        Decision::Allow { rule_id } => (Some(AuditDecision::Allow), rule_id.clone(), None),
        Decision::Deny {
            behavior,
            reason,
            rule_id,
        } => (
            Some(AuditDecision::Deny {
                behavior: *behavior,
            }),
            rule_id.clone(),
            Some(*reason),
        ),
        Decision::FailClosed { reason } => (Some(AuditDecision::FailClosed), None, Some(*reason)),
    }
}

fn push_json_u64_field(out: &mut String, key: &str, value: u64, first: bool) {
    push_json_key(out, key, first);
    write!(out, "{value}").expect("writing to String cannot fail");
}

fn push_json_option_u64_field(out: &mut String, key: &str, value: Option<u64>, first: bool) {
    push_json_key(out, key, first);
    if let Some(value) = value {
        write!(out, "{value}").expect("writing to String cannot fail");
    } else {
        out.push_str("null");
    }
}

fn push_json_option_u16_field(out: &mut String, key: &str, value: Option<u16>, first: bool) {
    push_json_key(out, key, first);
    if let Some(value) = value {
        write!(out, "{value}").expect("writing to String cannot fail");
    } else {
        out.push_str("null");
    }
}

fn push_json_string_field(out: &mut String, key: &str, value: &str, first: bool) {
    push_json_key(out, key, first);
    push_json_string(out, value);
}

fn push_json_option_string_field(out: &mut String, key: &str, value: Option<&str>, first: bool) {
    push_json_key(out, key, first);
    if let Some(value) = value {
        push_json_string(out, value);
    } else {
        out.push_str("null");
    }
}

fn push_json_endpoint_field(out: &mut String, key: &str, endpoint: Option<Endpoint>, first: bool) {
    push_json_key(out, key, first);
    let Some(endpoint) = endpoint else {
        out.push_str("null");
        return;
    };

    out.push('{');
    push_json_string_field(out, "ip", &endpoint.ip.to_string(), true);
    push_json_option_u16_field(out, "port", endpoint.port, false);
    out.push('}');
}

fn push_json_protocol_field(out: &mut String, key: &str, protocol: Option<Protocol>, first: bool) {
    push_json_key(out, key, first);
    let Some(protocol) = protocol else {
        out.push_str("null");
        return;
    };

    match protocol {
        Protocol::Unsupported(number) => push_json_string(out, &format!("unsupported:{number}")),
        protocol => push_json_string(out, protocol_name(protocol)),
    }
}

fn push_json_key(out: &mut String, key: &str, first: bool) {
    if !first {
        out.push(',');
    }
    push_json_string(out, key);
    out.push(':');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                write!(out, "\\u{:04x}", ch as u32).expect("writing to String cannot fail");
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn audit_event_kind_name(kind: AuditEventKind) -> &'static str {
    match kind {
        AuditEventKind::NetworkSessionStart => "network_session_start",
        AuditEventKind::BrokerStart => "broker_start",
        AuditEventKind::TunConfigured => "tun_configured",
        AuditEventKind::ProxyListenerConfigured => "proxy_listener_configured",
        AuditEventKind::DnsQuery => "dns_query",
        AuditEventKind::TcpConnect => "tcp_connect",
        AuditEventKind::TcpFlowClosed => "tcp_flow_closed",
        AuditEventKind::UdpFlowCreated => "udp_flow_created",
        AuditEventKind::UdpPacket => "udp_packet",
        AuditEventKind::UdpFlowExpired => "udp_flow_expired",
        AuditEventKind::QuicCandidateFlowCreated => "quic_candidate_flow_created",
        AuditEventKind::IcmpMessage => "icmp_message",
        AuditEventKind::HttpRequest => "http_request",
        AuditEventKind::HttpsConnect => "https_connect",
        AuditEventKind::SocksConnect => "socks_connect",
        AuditEventKind::TlsClientHello => "tls_client_hello",
        AuditEventKind::UnsupportedNetworkEvent => "unsupported_network_event",
        AuditEventKind::PolicyReload => "policy_reload",
        AuditEventKind::BrokerError => "broker_error",
        AuditEventKind::NetworkSessionExit => "network_session_exit",
    }
}

fn frontend_name(frontend: Frontend) -> &'static str {
    match frontend {
        Frontend::Tun => "tun",
        Frontend::HttpProxy => "http_proxy",
        Frontend::Socks5 => "socks5",
        Frontend::SetupHelper => "setup_helper",
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Dns => "dns",
        Protocol::Icmp => "icmp",
        Protocol::Http => "http",
        Protocol::HttpsConnect => "https_connect",
        Protocol::TlsSni => "tls_sni",
        Protocol::Socks => "socks",
        Protocol::QuicCandidate => "quic_candidate",
        Protocol::Unsupported(_) => "unsupported",
    }
}

fn hostname_source_name(source: HostnameSource) -> &'static str {
    match source {
        HostnameSource::None => "none",
        HostnameSource::IpOnly => "ip_only",
        HostnameSource::BrokerDnsQuery => "broker_dns_query",
        HostnameSource::DnsCache => "dns_cache",
        HostnameSource::PlaintextHttpHost => "plaintext_http_host",
        HostnameSource::TlsSni => "tls_sni",
        HostnameSource::QuicTls => "quic_tls",
        HostnameSource::ExplicitProxy => "explicit_proxy",
    }
}

fn hostname_confidence_name(confidence: HostnameConfidence) -> &'static str {
    match confidence {
        HostnameConfidence::None => "none",
        HostnameConfidence::Low => "low",
        HostnameConfidence::Medium => "medium",
        HostnameConfidence::High => "high",
    }
}

fn dns_query_type_name(query_type: DnsQueryType) -> &'static str {
    match query_type {
        DnsQueryType::A => "A",
        DnsQueryType::Aaaa => "AAAA",
        DnsQueryType::Cname => "CNAME",
        DnsQueryType::Mx => "MX",
        DnsQueryType::Txt => "TXT",
        DnsQueryType::Srv => "SRV",
        DnsQueryType::Ptr => "PTR",
        DnsQueryType::Other(_) => "OTHER",
    }
}

fn audit_decision_name(decision: AuditDecision) -> &'static str {
    match decision {
        AuditDecision::Allow => "allow",
        AuditDecision::Deny { .. } => "deny",
        AuditDecision::FailClosed => "fail_closed",
    }
}

fn audit_deny_behavior_name(decision: AuditDecision) -> Option<&'static str> {
    match decision {
        AuditDecision::Deny { behavior } => Some(deny_behavior_name(behavior)),
        AuditDecision::Allow | AuditDecision::FailClosed => None,
    }
}

fn deny_behavior_name(behavior: DenyBehavior) -> &'static str {
    match behavior {
        DenyBehavior::Drop => "drop",
        DenyBehavior::Reset => "reset",
        DenyBehavior::IcmpUnreachable => "icmp_unreachable",
    }
}

fn denial_reason_name(reason: DenialReason) -> &'static str {
    match reason {
        DenialReason::DefaultDeny => "default_deny",
        DenialReason::RuleDeny => "rule_deny",
        DenialReason::MalformedInput => "malformed_input",
        DenialReason::UnsupportedProtocol => "unsupported_protocol",
        DenialReason::DirectDnsBypass => "direct_dns_bypass",
        DenialReason::MulticastOrBroadcast => "multicast_or_broadcast",
        DenialReason::AttributionRequired => "attribution_required",
        DenialReason::AttributionMismatch => "attribution_mismatch",
        DenialReason::HiddenSni => "hidden_sni",
        DenialReason::IcmpTypeDenied => "icmp_type_denied",
        DenialReason::InvalidConfig => "invalid_config",
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuditEventKind {
    NetworkSessionStart,
    BrokerStart,
    TunConfigured,
    ProxyListenerConfigured,
    DnsQuery,
    TcpConnect,
    TcpFlowClosed,
    UdpFlowCreated,
    UdpPacket,
    UdpFlowExpired,
    QuicCandidateFlowCreated,
    IcmpMessage,
    HttpRequest,
    HttpsConnect,
    SocksConnect,
    TlsClientHello,
    UnsupportedNetworkEvent,
    PolicyReload,
    BrokerError,
    NetworkSessionExit,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuditDecision {
    Allow,
    Deny { behavior: DenyBehavior },
    FailClosed,
}

/// Fixed-size audit queue. Pushing to a full queue reports backpressure and does
/// not allocate beyond the configured capacity.
#[derive(Clone, Debug)]
pub struct BoundedAuditBuffer {
    capacity: usize,
    queue: VecDeque<AuditEvent>,
}

impl BoundedAuditBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, event: AuditEvent) -> PushOutcome {
        if self.capacity == 0 || self.queue.len() == self.capacity {
            return PushOutcome::Backpressure {
                event: Box::new(event),
            };
        }
        self.queue.push_back(event);
        PushOutcome::Accepted
    }

    pub fn pop(&mut self) -> Option<AuditEvent> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PushOutcome {
    Accepted,
    Backpressure { event: Box<AuditEvent> },
}

/// Utility for audit callers that need to record a destination IP without a
/// port, such as unsupported packet events.
pub fn ip_endpoint(ip: IpAddr) -> Endpoint {
    Endpoint::new(ip, None)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::policy::{Decision, DenialReason, DenyBehavior};

    fn event(decision: Decision) -> AuditEvent {
        AuditEvent::from_policy_decision(
            AuditPolicyContext {
                timestamp_millis: 1,
                sandbox_id: SandboxId::new("sandbox-a"),
                kind: AuditEventKind::TcpConnect,
                frontend: Frontend::Tun,
                protocol: Protocol::Tcp,
                source: None,
                destination: Some(Endpoint::tcp(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    443,
                )),
                requested_port: Some(443),
                hostname: None,
                hostname_source: HostnameSource::None,
                hostname_confidence: HostnameConfidence::None,
                http_method: None,
                http_path_query: None,
            },
            &decision,
        )
    }

    #[test]
    fn audit_event_preserves_structured_denial_reason_and_behavior() {
        let audit = event(Decision::Deny {
            behavior: DenyBehavior::Reset,
            reason: DenialReason::DefaultDeny,
            rule_id: Some("default".into()),
        });

        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Reset,
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DefaultDeny));
        assert_eq!(audit.rule_id.as_deref(), Some("default"));
        assert_eq!(audit.protocol, Some(Protocol::Tcp));
        assert_eq!(audit.frontend, Some(Frontend::Tun));
    }

    #[test]
    fn audit_buffer_reports_backpressure_instead_of_growing_unbounded() {
        let mut buffer = BoundedAuditBuffer::new(1);
        assert_eq!(
            buffer.push(event(Decision::Allow { rule_id: None })),
            PushOutcome::Accepted
        );
        let rejected = event(Decision::FailClosed {
            reason: DenialReason::MalformedInput,
        });
        assert_eq!(
            buffer.push(rejected.clone()),
            PushOutcome::Backpressure {
                event: Box::new(rejected)
            }
        );
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.capacity(), 1);
    }

    #[test]
    fn audit_context_from_policy_request_preserves_source_and_http_metadata() {
        let request = PolicyRequest::new(Protocol::Http)
            .with_destination(Endpoint::tcp(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                80,
            ))
            .with_attribution(crate::attribution::HostAttribution::plaintext_http(
                Hostname::parse("www.example.com").unwrap(),
            ))
            .with_http_metadata("GET", "/v1/resource?debug=false");
        let request = PolicyRequest {
            sandbox_id: SandboxId::new("sandbox-http"),
            source: Some(Endpoint::tcp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 43210)),
            ..request
        };

        let event = AuditEvent::from_policy_decision(
            AuditPolicyContext::from_request(42, AuditEventKind::HttpRequest, &request),
            &Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::RuleDeny,
                rule_id: Some("deny-debug".into()),
            },
        );

        assert_eq!(event.timestamp_millis, 42);
        assert_eq!(event.sandbox_id.as_str(), "sandbox-http");
        assert_eq!(event.kind, AuditEventKind::HttpRequest);
        assert_eq!(event.source, request.source);
        assert_eq!(event.destination, request.destination);
        assert_eq!(event.requested_port, Some(80));
        assert_eq!(event.hostname.as_ref().unwrap().as_str(), "www.example.com");
        assert_eq!(event.hostname_source, HostnameSource::PlaintextHttpHost);
        assert_eq!(event.hostname_confidence, HostnameConfidence::High);
        assert_eq!(event.dns_query_type, None);
        assert_eq!(event.http_method.as_deref(), Some("GET"));
        assert_eq!(
            event.http_path_query.as_deref(),
            Some("/v1/resource?debug=false")
        );
        assert_eq!(event.reason, Some(DenialReason::RuleDeny));
        assert_eq!(event.rule_id.as_deref(), Some("deny-debug"));
    }

    #[test]
    fn dns_query_audit_preserves_query_type_and_endpoints() {
        let metadata = crate::dns::parse_dns_query(
            &[
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
                0x01,
            ],
            512,
        )
        .unwrap();
        let source = Endpoint::udp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000);
        let destination = Endpoint::udp(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3)), 53);

        let event = AuditEvent::from_dns_query_metadata(
            99,
            SandboxId::new("sandbox-dns"),
            Frontend::Tun,
            Some(source),
            Some(destination),
            &metadata,
            &Decision::Allow { rule_id: None },
        );

        assert_eq!(event.timestamp_millis, 99);
        assert_eq!(event.sandbox_id.as_str(), "sandbox-dns");
        assert_eq!(event.kind, AuditEventKind::DnsQuery);
        assert_eq!(event.protocol, Some(Protocol::Dns));
        assert_eq!(event.source, Some(source));
        assert_eq!(event.destination, Some(destination));
        assert_eq!(event.requested_port, Some(53));
        assert_eq!(event.hostname.as_ref().unwrap().as_str(), "example.com");
        assert_eq!(event.hostname_source, HostnameSource::BrokerDnsQuery);
        assert_eq!(event.hostname_confidence, HostnameConfidence::High);
        assert_eq!(event.dns_query_type, Some(crate::dns::DnsQueryType::Aaaa));
        assert_eq!(event.decision, Some(AuditDecision::Allow));
        assert_eq!(event.reason, None);
    }

    #[test]
    fn audit_json_line_preserves_denial_context_and_escapes_strings() {
        let request = PolicyRequest {
            sandbox_id: SandboxId::new("sandbox-json"),
            source: Some(Endpoint::tcp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 43210)),
            ..PolicyRequest::new(Protocol::Http)
                .with_destination(Endpoint::tcp(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    80,
                ))
                .with_attribution(crate::attribution::HostAttribution::plaintext_http(
                    Hostname::parse("www.example.com").unwrap(),
                ))
                .with_http_metadata("GET", "/deny?x=\"quoted\"")
        };
        let event = AuditEvent::from_policy_decision(
            AuditPolicyContext::from_request(7, AuditEventKind::HttpRequest, &request),
            &Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::RuleDeny,
                rule_id: Some("deny \"quoted\"".into()),
            },
        );

        let line = event.to_json_line();
        assert!(line.starts_with('{'));
        assert!(line.ends_with('}'));
        assert!(line.contains("\"kind\":\"http_request\""));
        assert!(line.contains("\"source\":{\"ip\":\"10.0.0.2\",\"port\":43210}"));
        assert!(line.contains("\"destination\":{\"ip\":\"203.0.113.10\",\"port\":80}"));
        assert!(line.contains("\"requested_port\":80"));
        assert!(line.contains("\"hostname\":\"www.example.com\""));
        assert!(line.contains("\"decision\":\"deny\""));
        assert!(line.contains("\"deny_behavior\":\"drop\""));
        assert!(line.contains("\"reason\":\"rule_deny\""));
        assert!(line.contains("\"rule_id\":\"deny \\\"quoted\\\"\""));
        assert!(line.contains("\"http_path_query\":\"/deny?x=\\\"quoted\\\"\""));
        assert!(line.contains("\"dns_query_type\":null"));
    }

    #[test]
    fn audit_json_line_preserves_dns_and_fail_closed_fields() {
        let metadata = crate::dns::parse_dns_query(
            &[
                0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'n', b'e', b't', 0x00, 0x00, 0x01, 0x00,
                0x01,
            ],
            512,
        )
        .unwrap();
        let event = AuditEvent::from_dns_query_metadata(
            8,
            SandboxId::new("sandbox-dns"),
            Frontend::Tun,
            None,
            None,
            &metadata,
            &Decision::FailClosed {
                reason: DenialReason::MalformedInput,
            },
        );

        let line = event.to_json_line();
        assert!(line.contains("\"kind\":\"dns_query\""));
        assert!(line.contains("\"source\":null"));
        assert!(line.contains("\"destination\":null"));
        assert!(line.contains("\"hostname_source\":\"broker_dns_query\""));
        assert!(line.contains("\"dns_query_type\":\"A\""));
        assert!(line.contains("\"decision\":\"fail_closed\""));
        assert!(line.contains("\"deny_behavior\":null"));
        assert!(line.contains("\"reason\":\"malformed_input\""));
    }

    #[test]
    fn audit_json_line_preserves_unsupported_protocol_number() {
        let event = AuditEvent::from_policy_decision(
            AuditPolicyContext {
                timestamp_millis: 10,
                sandbox_id: SandboxId::new("sandbox-unsupported"),
                kind: AuditEventKind::UnsupportedNetworkEvent,
                frontend: Frontend::Tun,
                protocol: Protocol::Unsupported(99),
                source: None,
                destination: None,
                requested_port: None,
                hostname: None,
                hostname_source: HostnameSource::None,
                hostname_confidence: HostnameConfidence::None,
                http_method: None,
                http_path_query: None,
            },
            &Decision::FailClosed {
                reason: DenialReason::UnsupportedProtocol,
            },
        );

        assert!(event
            .to_json_line()
            .contains("\"protocol\":\"unsupported:99\""));
    }
}
