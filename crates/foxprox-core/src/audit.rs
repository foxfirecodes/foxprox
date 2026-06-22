use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::attribution::Hostname;
use crate::dns::{DnsAddressResponseMetadata, DnsQueryMetadata, DnsQueryType, DnsResponseCode};
use crate::flow::{TcpFlowEntry, UdpFlowClass, UdpFlowEntry};
use crate::packet::PacketParseError;
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
    pub presented_hostname: Option<Hostname>,
    pub dns_attribution: Option<Hostname>,
    pub hidden_sni: bool,
    pub hostname_source: HostnameSource,
    pub hostname_confidence: HostnameConfidence,
    pub dns_query_type: Option<DnsQueryType>,
    pub dns_response_code: Option<DnsResponseCode>,
    pub dns_answer_count: Option<usize>,
    pub dns_min_ttl_seconds: Option<u32>,
    pub decision: Option<AuditDecision>,
    pub rule_id: Option<String>,
    pub reason: Option<DenialReason>,
    pub http_method: Option<String>,
    pub http_path_query: Option<String>,
    pub byte_count: Option<u64>,
    pub flow_duration_millis: Option<u64>,
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
    pub presented_hostname: Option<Hostname>,
    pub dns_attribution: Option<Hostname>,
    pub hidden_sni: bool,
    pub hostname_source: HostnameSource,
    pub hostname_confidence: HostnameConfidence,
    pub dns_query_type: Option<DnsQueryType>,
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
            presented_hostname: request.presented_hostname.clone(),
            dns_attribution: request.dns_attribution.clone(),
            hidden_sni: request.hidden_sni,
            hostname_source: request.attribution.source,
            hostname_confidence: request.attribution.confidence,
            dns_query_type: request.dns_query_type,
            http_method: request.http_method.clone(),
            http_path_query: request.http_path_query.clone(),
        }
    }
}

impl AuditEvent {
    pub fn lifecycle(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        kind: AuditEventKind,
        frontend: Option<Frontend>,
    ) -> Self {
        Self {
            timestamp_millis,
            sandbox_id,
            kind,
            frontend,
            protocol: None,
            source: None,
            destination: None,
            requested_port: None,
            hostname: None,
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::None,
            hostname_confidence: HostnameConfidence::None,
            dns_query_type: None,
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: None,
            rule_id: None,
            reason: None,
            http_method: None,
            http_path_query: None,
            byte_count: None,
            flow_duration_millis: None,
        }
    }

    pub fn broker_error(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        frontend: Option<Frontend>,
        protocol: Option<Protocol>,
        reason: DenialReason,
    ) -> Self {
        Self {
            timestamp_millis,
            sandbox_id,
            kind: AuditEventKind::BrokerError,
            frontend,
            protocol,
            source: None,
            destination: None,
            requested_port: None,
            hostname: None,
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::None,
            hostname_confidence: HostnameConfidence::None,
            dns_query_type: None,
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: Some(AuditDecision::FailClosed),
            rule_id: None,
            reason: Some(reason),
            http_method: None,
            http_path_query: None,
            byte_count: None,
            flow_duration_millis: None,
        }
    }

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
            presented_hostname: context.presented_hostname,
            dns_attribution: context.dns_attribution,
            hidden_sni: context.hidden_sni,
            hostname_source: context.hostname_source,
            hostname_confidence: context.hostname_confidence,
            dns_query_type: context.dns_query_type,
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: audit_decision,
            rule_id,
            reason,
            http_method: context.http_method,
            http_path_query: context.http_path_query,
            byte_count: None,
            flow_duration_millis: None,
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
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::BrokerDnsQuery,
            hostname_confidence: HostnameConfidence::High,
            dns_query_type: Some(metadata.query_type),
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: audit_decision,
            rule_id,
            reason,
            http_method: None,
            http_path_query: None,
            byte_count: None,
            flow_duration_millis: None,
        }
    }

    pub fn from_dns_response_metadata(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        frontend: Frontend,
        source: Option<Endpoint>,
        destination: Option<Endpoint>,
        metadata: &DnsAddressResponseMetadata,
        decision: &Decision,
    ) -> Self {
        let (audit_decision, rule_id, reason) = audit_decision_fields(decision);

        Self {
            timestamp_millis,
            sandbox_id,
            kind: AuditEventKind::DnsResponse,
            frontend: Some(frontend),
            protocol: Some(Protocol::Dns),
            source,
            destination,
            requested_port: destination.and_then(|endpoint| endpoint.port),
            hostname: Some(metadata.hostname.clone()),
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::DnsCache,
            hostname_confidence: HostnameConfidence::Medium,
            dns_query_type: Some(metadata.query_type),
            dns_response_code: Some(metadata.response_code),
            dns_answer_count: Some(metadata.addresses.len()),
            dns_min_ttl_seconds: metadata.min_ttl_seconds,
            decision: audit_decision,
            rule_id,
            reason,
            http_method: None,
            http_path_query: None,
            byte_count: None,
            flow_duration_millis: None,
        }
    }

    pub fn from_packet_parse_error(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        frontend: Frontend,
        error: PacketParseError,
    ) -> Self {
        let protocol = match error {
            PacketParseError::UnsupportedProtocol(number) => Some(Protocol::Unsupported(number)),
            _ => None,
        };
        let reason = packet_parse_error_reason(error);

        Self {
            timestamp_millis,
            sandbox_id,
            kind: AuditEventKind::UnsupportedNetworkEvent,
            frontend: Some(frontend),
            protocol,
            source: None,
            destination: None,
            requested_port: None,
            hostname: None,
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::None,
            hostname_confidence: HostnameConfidence::None,
            dns_query_type: None,
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: Some(AuditDecision::FailClosed),
            rule_id: None,
            reason: Some(reason),
            http_method: None,
            http_path_query: None,
            byte_count: None,
            flow_duration_millis: None,
        }
    }

    pub fn from_tcp_flow_entry(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        kind: AuditEventKind,
        entry: &TcpFlowEntry,
    ) -> Self {
        Self {
            timestamp_millis,
            sandbox_id,
            kind,
            frontend: Some(Frontend::Tun),
            protocol: Some(Protocol::Tcp),
            source: Some(entry.key.source),
            destination: Some(entry.key.destination),
            requested_port: entry.key.destination.port,
            hostname: None,
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::None,
            hostname_confidence: HostnameConfidence::None,
            dns_query_type: None,
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: None,
            rule_id: None,
            reason: None,
            http_method: None,
            http_path_query: None,
            byte_count: Some(
                entry
                    .bytes_from_sandbox
                    .saturating_add(entry.bytes_from_host),
            ),
            flow_duration_millis: Some(timestamp_millis.saturating_sub(entry.created_at_millis)),
        }
    }

    pub fn from_udp_flow_entry(
        timestamp_millis: u64,
        sandbox_id: SandboxId,
        kind: AuditEventKind,
        entry: &UdpFlowEntry,
    ) -> Self {
        Self {
            timestamp_millis,
            sandbox_id,
            kind,
            frontend: Some(Frontend::Tun),
            protocol: Some(protocol_for_udp_flow_class(entry.class)),
            source: Some(entry.key.source),
            destination: Some(entry.key.destination),
            requested_port: entry.key.destination.port,
            hostname: None,
            presented_hostname: None,
            dns_attribution: None,
            hidden_sni: false,
            hostname_source: HostnameSource::None,
            hostname_confidence: HostnameConfidence::None,
            dns_query_type: None,
            dns_response_code: None,
            dns_answer_count: None,
            dns_min_ttl_seconds: None,
            decision: None,
            rule_id: None,
            reason: None,
            http_method: None,
            http_path_query: None,
            byte_count: Some(entry.bytes_from_sandbox),
            flow_duration_millis: Some(timestamp_millis.saturating_sub(entry.created_at_millis)),
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
        push_json_option_string_field(
            &mut out,
            "presented_hostname",
            self.presented_hostname
                .as_ref()
                .map(|hostname| hostname.as_str()),
            false,
        );
        push_json_option_string_field(
            &mut out,
            "dns_attribution",
            self.dns_attribution
                .as_ref()
                .map(|hostname| hostname.as_str()),
            false,
        );
        push_json_bool_field(&mut out, "hidden_sni", self.hidden_sni, false);
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
            "dns_response_code",
            self.dns_response_code.map(dns_response_code_name),
            false,
        );
        push_json_option_usize_field(&mut out, "dns_answer_count", self.dns_answer_count, false);
        push_json_option_u32_field(
            &mut out,
            "dns_min_ttl_seconds",
            self.dns_min_ttl_seconds,
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
        push_json_option_u64_field(
            &mut out,
            "flow_duration_millis",
            self.flow_duration_millis,
            false,
        );
        out.push('}');
        out
    }
}

fn packet_parse_error_reason(error: PacketParseError) -> DenialReason {
    match error {
        PacketParseError::UnsupportedIpVersion(_)
        | PacketParseError::UnsupportedIpv4Fragmentation
        | PacketParseError::UnsupportedIpv6ExtensionHeader(_)
        | PacketParseError::UnsupportedProtocol(_) => DenialReason::UnsupportedProtocol,
        PacketParseError::Empty
        | PacketParseError::TruncatedIpHeader
        | PacketParseError::InvalidIpv4HeaderLength
        | PacketParseError::InvalidIpv4TotalLength
        | PacketParseError::InvalidIpv4HeaderChecksum
        | PacketParseError::TruncatedTransportHeader
        | PacketParseError::InvalidTcpHeaderLength
        | PacketParseError::InvalidUdpLength
        | PacketParseError::InvalidTransportChecksum => DenialReason::MalformedInput,
    }
}

fn protocol_for_udp_flow_class(class: UdpFlowClass) -> Protocol {
    match class {
        UdpFlowClass::Dns => Protocol::Dns,
        UdpFlowClass::QuicCandidate => Protocol::QuicCandidate,
        UdpFlowClass::NtpLike | UdpFlowClass::Generic => Protocol::Udp,
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

fn push_json_option_u32_field(out: &mut String, key: &str, value: Option<u32>, first: bool) {
    push_json_key(out, key, first);
    if let Some(value) = value {
        write!(out, "{value}").expect("writing to String cannot fail");
    } else {
        out.push_str("null");
    }
}

fn push_json_option_usize_field(out: &mut String, key: &str, value: Option<usize>, first: bool) {
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

fn push_json_bool_field(out: &mut String, key: &str, value: bool, first: bool) {
    push_json_key(out, key, first);
    out.push_str(if value { "true" } else { "false" });
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
        AuditEventKind::DnsResponse => "dns_response",
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

fn dns_response_code_name(response_code: DnsResponseCode) -> &'static str {
    match response_code {
        DnsResponseCode::NoError => "NOERROR",
        DnsResponseCode::FormErr => "FORMERR",
        DnsResponseCode::ServFail => "SERVFAIL",
        DnsResponseCode::NxDomain => "NXDOMAIN",
        DnsResponseCode::NotImp => "NOTIMP",
        DnsResponseCode::Refused => "REFUSED",
        DnsResponseCode::Other(_) => "OTHER",
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
    DnsResponse,
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

    pub fn drain_json_lines(&mut self, max_events: usize) -> AuditDrainBatch {
        let limit = max_events.min(self.queue.len());
        let mut lines = Vec::with_capacity(limit);
        for _ in 0..limit {
            let event = self
                .queue
                .pop_front()
                .expect("limit is bounded by queue length");
            lines.push(event.to_json_line());
        }
        AuditDrainBatch {
            drained: lines.len(),
            remaining: self.queue.len(),
            lines,
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditDrainBatch {
    pub lines: Vec<String>,
    pub drained: usize,
    pub remaining: usize,
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
                presented_hostname: None,
                dns_attribution: None,
                hidden_sni: false,
                hostname_source: HostnameSource::None,
                hostname_confidence: HostnameConfidence::None,
                dns_query_type: None,
                http_method: None,
                http_path_query: None,
            },
            &decision,
        )
    }

    #[test]
    fn lifecycle_and_broker_error_events_preserve_structured_context() {
        let lifecycle = AuditEvent::lifecycle(
            7,
            SandboxId::new("sandbox-life"),
            AuditEventKind::TunConfigured,
            Some(Frontend::SetupHelper),
        );
        assert_eq!(lifecycle.timestamp_millis, 7);
        assert_eq!(lifecycle.sandbox_id.as_str(), "sandbox-life");
        assert_eq!(lifecycle.kind, AuditEventKind::TunConfigured);
        assert_eq!(lifecycle.frontend, Some(Frontend::SetupHelper));
        assert_eq!(lifecycle.decision, None);
        assert_eq!(lifecycle.reason, None);
        let line = lifecycle.to_json_line();
        assert!(line.contains("\"kind\":\"tun_configured\""));
        assert!(line.contains("\"frontend\":\"setup_helper\""));
        assert!(line.contains("\"decision\":null"));

        let error = AuditEvent::broker_error(
            8,
            SandboxId::new("sandbox-life"),
            Some(Frontend::Tun),
            Some(Protocol::Dns),
            DenialReason::InvalidConfig,
        );
        assert_eq!(error.kind, AuditEventKind::BrokerError);
        assert_eq!(error.frontend, Some(Frontend::Tun));
        assert_eq!(error.protocol, Some(Protocol::Dns));
        assert_eq!(error.decision, Some(AuditDecision::FailClosed));
        assert_eq!(error.reason, Some(DenialReason::InvalidConfig));
        let line = error.to_json_line();
        assert!(line.contains("\"kind\":\"broker_error\""));
        assert!(line.contains("\"decision\":\"fail_closed\""));
        assert!(line.contains("\"reason\":\"invalid_config\""));
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
    fn audit_buffer_drains_json_lines_in_bounded_fifo_batches() {
        let mut buffer = BoundedAuditBuffer::new(3);
        assert_eq!(
            buffer.push(event(Decision::Allow {
                rule_id: Some("first".into()),
            })),
            PushOutcome::Accepted
        );
        assert_eq!(
            buffer.push(event(Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::DefaultDeny,
                rule_id: Some("second".into()),
            })),
            PushOutcome::Accepted
        );
        assert_eq!(
            buffer.push(event(Decision::FailClosed {
                reason: DenialReason::MalformedInput,
            })),
            PushOutcome::Accepted
        );

        let batch = buffer.drain_json_lines(2);
        assert_eq!(batch.drained, 2);
        assert_eq!(batch.remaining, 1);
        assert_eq!(buffer.len(), 1);
        assert_eq!(batch.lines.len(), 2);
        assert!(batch.lines[0].contains("\"rule_id\":\"first\""));
        assert!(batch.lines[1].contains("\"rule_id\":\"second\""));

        let empty = buffer.drain_json_lines(0);
        assert_eq!(empty.drained, 0);
        assert_eq!(empty.remaining, 1);
        assert!(empty.lines.is_empty());

        let rest = buffer.drain_json_lines(usize::MAX);
        assert_eq!(rest.drained, 1);
        assert_eq!(rest.remaining, 0);
        assert!(buffer.is_empty());
        assert!(rest.lines[0].contains("\"decision\":\"fail_closed\""));
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
    fn policy_derived_dns_audit_preserves_query_type() {
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
        let request = PolicyRequest::from_dns_query_metadata(
            Frontend::Tun,
            Some(source),
            Some(destination),
            metadata,
        );

        let event = AuditEvent::from_policy_decision(
            AuditPolicyContext::from_request(98, AuditEventKind::DnsQuery, &request),
            &Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::RuleDeny,
                rule_id: Some("deny-dns".into()),
            },
        );

        assert_eq!(event.kind, AuditEventKind::DnsQuery);
        assert_eq!(event.source, Some(source));
        assert_eq!(event.destination, Some(destination));
        assert_eq!(event.requested_port, Some(53));
        assert_eq!(event.hostname.as_ref().unwrap().as_str(), "example.com");
        assert_eq!(event.hostname_source, HostnameSource::BrokerDnsQuery);
        assert_eq!(event.hostname_confidence, HostnameConfidence::High);
        assert_eq!(event.dns_query_type, Some(crate::dns::DnsQueryType::Aaaa));
        assert_eq!(event.reason, Some(DenialReason::RuleDeny));
        assert_eq!(event.rule_id.as_deref(), Some("deny-dns"));
    }

    #[test]
    fn audit_context_preserves_hostname_mismatch_evidence() {
        let sni = Hostname::parse("evil.example").unwrap();
        let dns = Hostname::parse("good.example").unwrap();
        let request = PolicyRequest::new(Protocol::TlsSni)
            .with_destination(Endpoint::tcp(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                443,
            ))
            .with_attribution(crate::attribution::HostAttribution::tls_sni(sni.clone()))
            .with_presented_hostname(sni.clone())
            .with_dns_attribution(dns.clone());

        let event = AuditEvent::from_policy_decision(
            AuditPolicyContext::from_request(101, AuditEventKind::TlsClientHello, &request),
            &Decision::Deny {
                behavior: DenyBehavior::Drop,
                reason: DenialReason::AttributionMismatch,
                rule_id: None,
            },
        );

        assert_eq!(event.hostname.as_ref(), Some(&sni));
        assert_eq!(event.presented_hostname.as_ref(), Some(&sni));
        assert_eq!(event.dns_attribution.as_ref(), Some(&dns));
        assert_eq!(event.reason, Some(DenialReason::AttributionMismatch));
        let line = event.to_json_line();
        assert!(line.contains("\"hostname\":\"evil.example\""));
        assert!(line.contains("\"presented_hostname\":\"evil.example\""));
        assert!(line.contains("\"dns_attribution\":\"good.example\""));
        assert!(line.contains("\"reason\":\"attribution_mismatch\""));
    }

    #[test]
    fn audit_context_preserves_hidden_sni_even_when_ip_rule_allows() {
        let request = PolicyRequest {
            hidden_sni: true,
            ..PolicyRequest::new(Protocol::TlsSni).with_destination(Endpoint::tcp(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                443,
            ))
        };

        let event = AuditEvent::from_policy_decision(
            AuditPolicyContext::from_request(102, AuditEventKind::TlsClientHello, &request),
            &Decision::Allow {
                rule_id: Some("allow-hidden-ip".into()),
            },
        );

        assert!(event.hidden_sni);
        assert_eq!(event.decision, Some(AuditDecision::Allow));
        assert_eq!(event.rule_id.as_deref(), Some("allow-hidden-ip"));
        let line = event.to_json_line();
        assert!(line.contains("\"hidden_sni\":true"));
        assert!(line.contains("\"decision\":\"allow\""));
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
    fn dns_response_audit_preserves_response_code_ttl_and_answer_count() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let metadata = crate::dns::parse_dns_address_response(&response, 512, 8).unwrap();
        let source = Endpoint::udp(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let destination = Endpoint::udp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000);

        let event = AuditEvent::from_dns_response_metadata(
            100,
            SandboxId::new("sandbox-dns"),
            Frontend::Tun,
            Some(source),
            Some(destination),
            &metadata,
            &Decision::Allow { rule_id: None },
        );

        assert_eq!(event.kind, AuditEventKind::DnsResponse);
        assert_eq!(event.protocol, Some(Protocol::Dns));
        assert_eq!(event.source, Some(source));
        assert_eq!(event.destination, Some(destination));
        assert_eq!(event.requested_port, Some(40000));
        assert_eq!(event.hostname.as_ref().unwrap().as_str(), "example.com");
        assert_eq!(event.hostname_source, HostnameSource::DnsCache);
        assert_eq!(event.hostname_confidence, HostnameConfidence::Medium);
        assert_eq!(event.dns_query_type, Some(crate::dns::DnsQueryType::A));
        assert_eq!(
            event.dns_response_code,
            Some(crate::dns::DnsResponseCode::NoError)
        );
        assert_eq!(event.dns_answer_count, Some(1));
        assert_eq!(event.dns_min_ttl_seconds, Some(30));

        let line = event.to_json_line();
        assert!(line.contains("\"kind\":\"dns_response\""));
        assert!(line.contains("\"dns_response_code\":\"NOERROR\""));
        assert!(line.contains("\"dns_answer_count\":1"));
        assert!(line.contains("\"dns_min_ttl_seconds\":30"));
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
                presented_hostname: None,
                dns_attribution: None,
                hidden_sni: false,
                hostname_source: HostnameSource::None,
                hostname_confidence: HostnameConfidence::None,
                dns_query_type: None,
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

    #[test]
    fn packet_parse_errors_build_fail_closed_audit_events() {
        let malformed = AuditEvent::from_packet_parse_error(
            500,
            SandboxId::new("sandbox-packet"),
            Frontend::Tun,
            PacketParseError::InvalidTransportChecksum,
        );
        assert_eq!(malformed.kind, AuditEventKind::UnsupportedNetworkEvent);
        assert_eq!(malformed.decision, Some(AuditDecision::FailClosed));
        assert_eq!(malformed.reason, Some(DenialReason::MalformedInput));
        assert_eq!(malformed.protocol, None);

        let unsupported = AuditEvent::from_packet_parse_error(
            501,
            SandboxId::new("sandbox-packet"),
            Frontend::Tun,
            PacketParseError::UnsupportedProtocol(99),
        );
        assert_eq!(unsupported.reason, Some(DenialReason::UnsupportedProtocol));
        assert_eq!(unsupported.protocol, Some(Protocol::Unsupported(99)));
        let line = unsupported.to_json_line();
        assert!(line.contains("\"kind\":\"unsupported_network_event\""));
        assert!(line.contains("\"decision\":\"fail_closed\""));
        assert!(line.contains("\"protocol\":\"unsupported:99\""));
        assert!(line.contains("\"reason\":\"unsupported_protocol\""));
    }

    #[test]
    fn tcp_flow_audit_preserves_lifecycle_counters_and_duration() {
        let key = crate::flow::TcpFlowKey::new(
            Endpoint::tcp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000),
            Endpoint::tcp(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443),
        );
        let entry = crate::flow::TcpFlowEntry {
            key,
            created_at_millis: 1_000,
            last_seen_millis: 1_500,
            expires_at_millis: 31_500,
            bytes_from_sandbox: u64::MAX,
            bytes_from_host: 10,
        };

        let event = AuditEvent::from_tcp_flow_entry(
            2_000,
            SandboxId::new("sandbox-tcp"),
            AuditEventKind::TcpFlowClosed,
            &entry,
        );

        assert_eq!(event.kind, AuditEventKind::TcpFlowClosed);
        assert_eq!(event.protocol, Some(Protocol::Tcp));
        assert_eq!(event.source, Some(key.source));
        assert_eq!(event.destination, Some(key.destination));
        assert_eq!(event.requested_port, Some(443));
        assert_eq!(event.byte_count, Some(u64::MAX));
        assert_eq!(event.flow_duration_millis, Some(1_000));
        let line = event.to_json_line();
        assert!(line.contains("\"kind\":\"tcp_flow_closed\""));
        assert!(line.contains("\"byte_count\":18446744073709551615"));
        assert!(line.contains("\"flow_duration_millis\":1000"));
    }

    #[test]
    fn udp_flow_audit_preserves_lifecycle_counters_and_classification() {
        let entry = UdpFlowEntry {
            key: crate::flow::UdpFlowKey::new(
                Endpoint::udp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000),
                Endpoint::udp(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)), 443),
            ),
            class: UdpFlowClass::QuicCandidate,
            created_at_millis: 1_000,
            last_seen_millis: 1_100,
            expires_at_millis: 181_100,
            bytes_from_sandbox: 42,
        };

        let event = AuditEvent::from_udp_flow_entry(
            1_250,
            SandboxId::new("sandbox-udp"),
            AuditEventKind::QuicCandidateFlowCreated,
            &entry,
        );

        assert_eq!(event.protocol, Some(Protocol::QuicCandidate));
        assert_eq!(event.source, Some(entry.key.source));
        assert_eq!(event.destination, Some(entry.key.destination));
        assert_eq!(event.requested_port, Some(443));
        assert_eq!(event.byte_count, Some(42));
        assert_eq!(event.flow_duration_millis, Some(250));
        let line = event.to_json_line();
        assert!(line.contains("\"kind\":\"quic_candidate_flow_created\""));
        assert!(line.contains("\"protocol\":\"quic_candidate\""));
        assert!(line.contains("\"byte_count\":42"));
        assert!(line.contains("\"flow_duration_millis\":250"));
    }

    #[test]
    fn udp_expiration_audit_uses_udp_protocol_for_generic_flows() {
        let entry = UdpFlowEntry {
            key: crate::flow::UdpFlowKey::new(
                Endpoint::udp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40001),
                Endpoint::udp(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 9999),
            ),
            class: UdpFlowClass::Generic,
            created_at_millis: 500,
            last_seen_millis: 550,
            expires_at_millis: 1_000,
            bytes_from_sandbox: u64::MAX,
        };

        let event = AuditEvent::from_udp_flow_entry(
            1_000,
            SandboxId::new("sandbox-udp"),
            AuditEventKind::UdpFlowExpired,
            &entry,
        );

        assert_eq!(event.protocol, Some(Protocol::Udp));
        assert_eq!(event.flow_duration_millis, Some(500));
        let line = event.to_json_line();
        assert!(line.contains("\"kind\":\"udp_flow_expired\""));
        assert!(line.contains("\"byte_count\":18446744073709551615"));
        assert!(line.contains("\"flow_duration_millis\":500"));
    }
}
