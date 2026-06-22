//! DNS forwarding helpers for foxprox.
//!
//! The DNS subsystem owns upstream DNS exchange and feeds successful responses
//! into the transparent attribution cache. Policy decisions still happen before
//! this layer; this crate focuses on shared UDP egress and response recording.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::SystemTime;

use foxprox_core::{
    AuditDecision, DnsQuery, Endpoint, FrontendKind, NormalizedEvent, PolicyEngine,
    PolicyEvaluation, SandboxId, UnsupportedNetworkEvent,
};
use foxprox_egress::{EgressError, UdpEgress, UdpTarget};
use foxprox_inspect::{DnsAttributionCache, DnsResponseError};

/// Result of handling one DNS datagram received by the broker resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsDatagramResult {
    pub evaluation: PolicyEvaluation,
    pub response: Option<Vec<u8>>,
    pub forwarded: bool,
    pub recorded_answers: usize,
    pub upstream_error: Option<DnsForwardError>,
}

/// DNS broker request handler for one datagram at a time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsBrokerDatagramHandler {
    policy: PolicyEngine,
    forwarder: UdpDnsForwarder,
    resolver: Endpoint,
}

impl DnsBrokerDatagramHandler {
    pub fn new(policy: PolicyEngine, forwarder: UdpDnsForwarder, resolver: Endpoint) -> Self {
        Self {
            policy,
            forwarder,
            resolver,
        }
    }

    pub fn resolver(&self) -> Endpoint {
        self.resolver
    }

    pub fn forwarder(&self) -> &UdpDnsForwarder {
        &self.forwarder
    }

    /// Parse, authorize, and either forward or reject one broker DNS datagram.
    ///
    /// Denied queries receive DNS REFUSED when a response can be synthesized.
    /// Malformed queries fail closed and receive FORMERR when the DNS header is
    /// present. Allowed upstream failures receive SERVFAIL and retain the
    /// egress/parse error for diagnostics.
    pub fn handle_query<E: UdpEgress>(
        &self,
        egress: &E,
        sandbox_id: SandboxId,
        source: Endpoint,
        query: &[u8],
        cache: &mut DnsAttributionCache,
        observed_at: SystemTime,
    ) -> DnsDatagramResult {
        let event = parse_dns_query_event(sandbox_id.clone(), source, self.resolver, query)
            .unwrap_or_else(|error| {
                malformed_dns_query_event(sandbox_id, source, self.resolver, error)
            });
        let evaluation = self.policy.evaluate(&event);

        if evaluation.audit.decision != AuditDecision::Allowed {
            let rcode = if evaluation.audit.decision == AuditDecision::FailClosed {
                DnsResponseCode::FormErr
            } else {
                DnsResponseCode::Refused
            };
            return DnsDatagramResult {
                evaluation,
                response: dns_error_response(query, rcode),
                forwarded: false,
                recorded_answers: 0,
                upstream_error: None,
            };
        }

        match self
            .forwarder
            .forward_query(egress, query, cache, observed_at)
        {
            Ok(result) => DnsDatagramResult {
                evaluation,
                response: Some(result.response),
                forwarded: true,
                recorded_answers: result.recorded_answers,
                upstream_error: None,
            },
            Err(error) => DnsDatagramResult {
                evaluation,
                response: dns_error_response(query, DnsResponseCode::ServFail),
                forwarded: false,
                recorded_answers: 0,
                upstream_error: Some(error),
            },
        }
    }
}

/// Result of forwarding one DNS query upstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsForwardResult {
    pub response: Vec<u8>,
    pub recorded_answers: usize,
}

/// UDP DNS forwarder backed by shared host UDP egress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDnsForwarder {
    upstream: UdpTarget,
    max_response_len: usize,
}

impl UdpDnsForwarder {
    pub fn new(upstream: UdpTarget) -> Self {
        Self {
            upstream,
            max_response_len: 1232,
        }
    }

    pub fn with_max_response_len(
        mut self,
        max_response_len: usize,
    ) -> Result<Self, DnsForwardError> {
        if max_response_len < 12 {
            return Err(DnsForwardError::InvalidResponseLimit { max_response_len });
        }
        self.max_response_len = max_response_len;
        Ok(self)
    }

    pub fn upstream(&self) -> &UdpTarget {
        &self.upstream
    }

    /// Send one DNS query to the configured upstream, receive one response, and
    /// record A/AAAA answers into the supplied attribution cache.
    pub fn forward_query<E: UdpEgress>(
        &self,
        egress: &E,
        query: &[u8],
        cache: &mut DnsAttributionCache,
        observed_at: SystemTime,
    ) -> Result<DnsForwardResult, DnsForwardError> {
        if query.len() < 12 {
            return Err(DnsForwardError::QueryTooShort {
                actual: query.len(),
            });
        }
        let session = egress
            .connect(&self.upstream)
            .map_err(DnsForwardError::Egress)?;
        session
            .socket()
            .send(query)
            .map_err(DnsForwardError::from)?;
        let mut response = vec![0_u8; self.max_response_len];
        let length = session
            .socket()
            .recv(&mut response)
            .map_err(DnsForwardError::from)?;
        response.truncate(length);
        let recorded_answers = cache
            .record_response(&response, observed_at)
            .map_err(DnsForwardError::ResponseParse)?;
        Ok(DnsForwardResult {
            response,
            recorded_answers,
        })
    }
}

/// DNS forwarding errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsForwardError {
    InvalidResponseLimit { max_response_len: usize },
    QueryTooShort { actual: usize },
    Egress(EgressError),
    Io(String),
    ResponseParse(DnsResponseError),
}

impl fmt::Display for DnsForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResponseLimit { max_response_len } => write!(
                f,
                "dns-forward-invalid-response-limit: max_response_len={max_response_len}"
            ),
            Self::QueryTooShort { actual } => {
                write!(f, "dns-forward-query-too-short: actual={actual}")
            }
            Self::Egress(error) => write!(f, "dns-forward-egress-error: {error}"),
            Self::Io(error) => write!(f, "dns-forward-io-error: {error}"),
            Self::ResponseParse(error) => write!(f, "dns-forward-response-parse-error: {error}"),
        }
    }
}

impl std::error::Error for DnsForwardError {}

impl From<std::io::Error> for DnsForwardError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsResponseCode {
    FormErr,
    ServFail,
    Refused,
}

impl DnsResponseCode {
    const fn rcode(self) -> u8 {
        match self {
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::Refused => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedDnsQuestion {
    hostname: String,
    query_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DnsQueryParseError {
    HeaderTooShort { actual: usize },
    QuestionCountZero,
    NameTooLong,
    NameTruncated,
    CompressionPointerUnsupported,
    QuestionTooShort { remaining: usize },
}

impl fmt::Display for DnsQueryParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort { actual } => write!(f, "dns-header-too-short: actual={actual}"),
            Self::QuestionCountZero => f.write_str("dns-question-count-zero"),
            Self::NameTooLong => f.write_str("dns-name-too-long"),
            Self::NameTruncated => f.write_str("dns-name-truncated"),
            Self::CompressionPointerUnsupported => {
                f.write_str("dns-compression-pointer-unsupported")
            }
            Self::QuestionTooShort { remaining } => {
                write!(f, "dns-question-too-short: remaining={remaining}")
            }
        }
    }
}

fn parse_dns_query_event(
    sandbox_id: SandboxId,
    source: Endpoint,
    resolver: Endpoint,
    query: &[u8],
) -> Result<NormalizedEvent, DnsQueryParseError> {
    let parsed = parse_dns_question(query)?;
    Ok(NormalizedEvent::DnsQuery(DnsQuery {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source: Some(source),
        resolver,
        hostname: parsed.hostname,
        query_type: parsed.query_type,
    }))
}

fn malformed_dns_query_event(
    sandbox_id: SandboxId,
    source: Endpoint,
    resolver: Endpoint,
    error: DnsQueryParseError,
) -> NormalizedEvent {
    NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source: Some(source),
        destination: Some(resolver),
        reason: format!("malformed-dns-query: {error}"),
    })
}

fn parse_dns_question(payload: &[u8]) -> Result<ParsedDnsQuestion, DnsQueryParseError> {
    if payload.len() < 12 {
        return Err(DnsQueryParseError::HeaderTooShort {
            actual: payload.len(),
        });
    }

    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    if question_count == 0 {
        return Err(DnsQueryParseError::QuestionCountZero);
    }

    let question_end = dns_question_end(payload)?;
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < question_end - 4 {
        let length = usize::from(payload[offset]);
        offset += 1;
        if length == 0 {
            break;
        }
        let label = std::str::from_utf8(&payload[offset..offset + length])
            .map_err(|_| DnsQueryParseError::NameTruncated)?;
        labels.push(label.to_ascii_lowercase());
        offset += length;
    }
    let qtype = u16::from_be_bytes([payload[question_end - 4], payload[question_end - 3]]);

    Ok(ParsedDnsQuestion {
        hostname: labels.join("."),
        query_type: dns_query_type(qtype).to_owned(),
    })
}

fn dns_question_end(payload: &[u8]) -> Result<usize, DnsQueryParseError> {
    let mut offset = 12;
    loop {
        if offset >= payload.len() {
            return Err(DnsQueryParseError::NameTruncated);
        }
        let length = payload[offset];
        offset += 1;

        if length & 0xc0 != 0 {
            return Err(DnsQueryParseError::CompressionPointerUnsupported);
        }
        if length == 0 {
            break;
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(DnsQueryParseError::NameTooLong);
        }
        if offset + length > payload.len() {
            return Err(DnsQueryParseError::NameTruncated);
        }
        offset += length;
    }

    if payload.len() - offset < 4 {
        return Err(DnsQueryParseError::QuestionTooShort {
            remaining: payload.len() - offset,
        });
    }
    Ok(offset + 4)
}

fn dns_query_type(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        65 => "HTTPS",
        _ => "UNKNOWN",
    }
}

fn dns_error_response(query: &[u8], code: DnsResponseCode) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let question_end = dns_question_end(query).ok();
    let include_question = question_end.is_some();
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.push(0x80 | (query[2] & 0x01));
    response.push(0x80 | code.rcode());
    if include_question {
        response.extend_from_slice(&1_u16.to_be_bytes());
    } else {
        response.extend_from_slice(&0_u16.to_be_bytes());
    }
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    if let Some(end) = question_end {
        response.extend_from_slice(&query[12..end]);
    }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        AuditDecision, DefaultPolicy, DnsPolicy, Endpoint, FrontendKind, HostnamePattern,
        NormalizedEvent, PolicyConfig, PolicyDecision, PolicyEngine, PolicyRule, Protocol,
        RuleAction, SandboxId, TcpConnectAttempt,
    };
    use foxprox_egress::{HostUdpEgress, UdpEgress, UdpTarget};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::thread;
    use std::time::{Duration, SystemTime};

    fn dns_a_query(hostname: &str) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    fn dns_a_response(query: &[u8], address: [u8; 4], ttl_seconds: u32) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x01;
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }

    fn sandbox_id() -> SandboxId {
        SandboxId::new("dns-broker-test").unwrap()
    }

    fn sandbox_source() -> Endpoint {
        Endpoint::udp(Ipv4Addr::new(10, 0, 0, 2).into(), 53000)
    }

    fn broker_resolver() -> Endpoint {
        Endpoint::udp(Ipv4Addr::new(10, 0, 0, 1).into(), 53)
    }

    fn allow_example_dns_policy() -> PolicyEngine {
        let rule = PolicyRule::new("allow-example-dns", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Dns)
            .with_hostname(HostnamePattern::new(".example.com").unwrap())
            .with_destination_port(53);
        PolicyEngine::new(PolicyConfig {
            dns: DnsPolicy {
                broker_resolvers: vec![broker_resolver()],
                deny_direct_external_dns: true,
            },
            rules: vec![rule],
            ..PolicyConfig::default()
        })
    }

    #[test]
    fn dns_broker_handler_allows_forwards_and_records_response_answers() {
        let query = dns_a_query("dns.example.com");
        let response = dns_a_response(&query, [93, 184, 216, 34], 60);
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let expected_query = query.clone();
        let server_response = response.clone();
        let server = thread::spawn(move || {
            let mut received = vec![0_u8; 512];
            let (length, peer) = server_socket.recv_from(&mut received).unwrap();
            received.truncate(length);
            assert_eq!(received, expected_query);
            server_socket.send_to(&server_response, peer).unwrap();
        });
        let egress = HostUdpEgress::new(Duration::from_secs(1)).unwrap();
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(server_addr.ip(), server_addr.port()).unwrap());
        let handler =
            DnsBrokerDatagramHandler::new(allow_example_dns_policy(), forwarder, broker_resolver());
        let mut cache = DnsAttributionCache::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        let result = handler.handle_query(
            &egress,
            sandbox_id(),
            sandbox_source(),
            &query,
            &mut cache,
            now,
        );
        server.join().unwrap();

        assert_eq!(result.evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(
            result.evaluation.audit.hostname.as_deref(),
            Some("dns.example.com")
        );
        assert_eq!(result.response, Some(response));
        assert!(result.forwarded);
        assert_eq!(result.recorded_answers, 1);
        assert_eq!(result.upstream_error, None);
        let flow = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: FrontendKind::Tun,
            source: Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152),
            destination: Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            attribution: None,
        });
        assert_eq!(
            cache.enrich_event(flow, now).hostname(),
            Some("dns.example.com")
        );
    }

    #[test]
    fn dns_broker_handler_denies_with_refused_response_without_egress() {
        struct PanicUdpEgress;
        impl UdpEgress for PanicUdpEgress {
            fn connect(
                &self,
                _target: &UdpTarget,
            ) -> Result<foxprox_egress::UdpEgressSession, foxprox_egress::EgressError> {
                panic!("egress must not be called for denied DNS query")
            }
        }

        let query = dns_a_query("blocked.invalid");
        let policy = PolicyEngine::new(PolicyConfig {
            dns: DnsPolicy {
                broker_resolvers: vec![broker_resolver()],
                deny_direct_external_dns: true,
            },
            default_policy: DefaultPolicy::Deny(foxprox_core::DenyReason::drop("dns-denied")),
            ..PolicyConfig::default()
        });
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(Ipv4Addr::LOCALHOST.into(), 53).unwrap());
        let handler = DnsBrokerDatagramHandler::new(policy, forwarder, broker_resolver());
        let mut cache = DnsAttributionCache::new();

        let result = handler.handle_query(
            &PanicUdpEgress,
            sandbox_id(),
            sandbox_source(),
            &query,
            &mut cache,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Drop,
                reason: "dns-denied".to_owned(),
                rule_id: None,
            }
        );
        assert!(!result.forwarded);
        assert_eq!(result.recorded_answers, 0);
        let response = result.response.expect("REFUSED response is synthesized");
        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(response[3] & 0x0f, 5);
        assert!(cache.is_empty());
    }

    #[test]
    fn dns_broker_handler_malformed_query_fails_closed_with_formerr_without_egress() {
        struct PanicUdpEgress;
        impl UdpEgress for PanicUdpEgress {
            fn connect(
                &self,
                _target: &UdpTarget,
            ) -> Result<foxprox_egress::UdpEgressSession, foxprox_egress::EgressError> {
                panic!("egress must not be called for malformed DNS query")
            }
        }

        let malformed = vec![0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(Ipv4Addr::LOCALHOST.into(), 53).unwrap());
        let handler = DnsBrokerDatagramHandler::new(
            PolicyEngine::new(PolicyConfig {
                default_policy: DefaultPolicy::Allow,
                ..PolicyConfig::default()
            }),
            forwarder,
            broker_resolver(),
        );
        let mut cache = DnsAttributionCache::new();

        let result = handler.handle_query(
            &PanicUdpEgress,
            sandbox_id(),
            sandbox_source(),
            &malformed,
            &mut cache,
            SystemTime::UNIX_EPOCH,
        );

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::FailClosed { .. }
        ));
        assert_eq!(result.evaluation.audit.decision, AuditDecision::FailClosed);
        assert!(result
            .evaluation
            .audit
            .reason
            .as_deref()
            .unwrap()
            .contains("malformed-dns-query: dns-question-count-zero"));
        let response = result.response.expect("FORMERR response is synthesized");
        assert_eq!(&response[0..2], &malformed[0..2]);
        assert_eq!(response[3] & 0x0f, 1);
        assert!(!result.forwarded);
        assert!(cache.is_empty());
    }

    #[test]
    fn udp_dns_forwarder_records_response_answers_for_later_attribution() {
        let query = dns_a_query("dns.example.com");
        let response = dns_a_response(&query, [93, 184, 216, 34], 60);
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let expected_query = query.clone();
        let server_response = response.clone();
        let server = thread::spawn(move || {
            let mut received = vec![0_u8; 512];
            let (length, peer) = server_socket.recv_from(&mut received).unwrap();
            received.truncate(length);
            assert_eq!(received, expected_query);
            server_socket.send_to(&server_response, peer).unwrap();
        });
        let egress = HostUdpEgress::new(Duration::from_secs(1)).unwrap();
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(server_addr.ip(), server_addr.port()).unwrap());
        let mut cache = DnsAttributionCache::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        let result = forwarder
            .forward_query(&egress, &query, &mut cache, now)
            .expect("DNS forward succeeds");
        server.join().unwrap();

        assert_eq!(result.response, response);
        assert_eq!(result.recorded_answers, 1);
        let flow = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: SandboxId::new("dns-forward-test").unwrap(),
            frontend: FrontendKind::Tun,
            source: Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152),
            destination: Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            attribution: None,
        });
        let enriched = cache.enrich_event(flow, now + Duration::from_secs(1));
        assert_eq!(enriched.hostname(), Some("dns.example.com"));
    }

    #[test]
    fn udp_dns_forwarder_rejects_too_short_queries_before_egress() {
        let egress = HostUdpEgress::new(Duration::from_secs(1)).unwrap();
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(Ipv4Addr::LOCALHOST.into(), 53).unwrap());
        let mut cache = DnsAttributionCache::new();

        let error = forwarder
            .forward_query(&egress, &[0_u8; 11], &mut cache, SystemTime::UNIX_EPOCH)
            .expect_err("short DNS query is rejected");

        assert_eq!(error, DnsForwardError::QueryTooShort { actual: 11 });
        assert!(cache.is_empty());
    }
}
