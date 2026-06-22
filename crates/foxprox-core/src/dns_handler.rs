use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::dns::{
    build_refused_response, parse_dns_query, DnsParseError, DnsQueryMetadata, DnsQueryType,
};
use crate::flow::{DnsCache, DnsObservation, SharedDnsCache};
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::types::{
    normalize_hostname, AuditKind, Decision, DenialReason, Frontend, NetworkEndpoint, Protocol,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsHandlerResult {
    pub response: Option<Vec<u8>>,
    pub decision: PolicyDecision,
    pub observed_addresses: Vec<IpAddr>,
    pub observation: Option<DnsObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsUpstreamError {
    Unavailable,
    SourceMismatch,
    MalformedResponse,
}

pub trait DnsUpstream {
    fn exchange(
        &mut self,
        query: &DnsQueryMetadata,
        packet: &[u8],
    ) -> Result<Vec<u8>, DnsUpstreamError>;
}

#[derive(Clone, Debug)]
pub struct DnsBrokerHandler<U> {
    broker: BrokerCore,
    cache: SharedDnsCache,
    upstream: U,
    broker_dns_ip: IpAddr,
    fallback_ttl_ms: u64,
}

impl<U: DnsUpstream> DnsBrokerHandler<U> {
    pub fn new(broker: BrokerCore, upstream: U, broker_dns_ip: IpAddr) -> Self {
        Self {
            broker,
            cache: SharedDnsCache::default(),
            upstream,
            broker_dns_ip,
            fallback_ttl_ms: 60_000,
        }
    }

    pub fn handle_query(
        &mut self,
        sandbox_id: impl Into<String>,
        packet: &[u8],
        now_ms: u64,
    ) -> DnsHandlerResult {
        let sandbox_id = sandbox_id.into();
        let destination = NetworkEndpoint::socket(self.broker_dns_ip, 53);
        let metadata = match parse_dns_query(packet) {
            Ok(metadata) => metadata,
            Err(error) => {
                let request = PolicyRequest::unsupported(
                    sandbox_id,
                    Frontend::Tun,
                    DenialReason::MalformedPacket,
                )
                .with_destination(destination)
                .with_detail("dns_parse_error", dns_parse_error_detail(&error));
                let decision = self.broker.evaluate(&request);
                return DnsHandlerResult {
                    response: None,
                    decision,
                    observed_addresses: Vec::new(),
                    observation: None,
                };
            }
        };

        let request = PolicyRequest::dns_query(
            sandbox_id,
            destination,
            metadata.hostname.clone(),
            dns_query_type_name(metadata.query_type),
        );
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return DnsHandlerResult {
                response: build_refused_response(packet).ok(),
                decision,
                observed_addresses: Vec::new(),
                observation: None,
            };
        }

        let response = match self.upstream.exchange(&metadata, packet) {
            Ok(response) => response,
            Err(error) => {
                return self.fail_closed_upstream_error(&request, &metadata, packet, error)
            }
        };

        let answers = match parse_dns_response_addresses_for(&metadata, &response) {
            Ok(answers) => answers,
            Err(error) => {
                return self.fail_closed_upstream_error(&request, &metadata, packet, error)
            }
        };
        let ttl_ms = answers.ttl_ms.unwrap_or(self.fallback_ttl_ms);
        let observation = DnsObservation::new(
            metadata.hostname,
            dns_query_type_name(metadata.query_type),
            answers.addresses.clone(),
            now_ms,
            ttl_ms,
        );
        let observation_audit =
            DnsCache::observation_audit(request.sandbox.session_id.clone(), &observation);
        if let Err(decision) = self.broker.append_audit_for(&request, observation_audit) {
            return DnsHandlerResult {
                response: build_refused_response(packet).ok(),
                decision,
                observed_addresses: Vec::new(),
                observation: None,
            };
        }
        self.cache.commit_observation(observation.clone());

        DnsHandlerResult {
            response: Some(response),
            decision,
            observed_addresses: answers.addresses,
            observation: Some(observation),
        }
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn broker_mut(&mut self) -> &mut BrokerCore {
        &mut self.broker
    }

    pub fn with_shared_cache(mut self, cache: SharedDnsCache) -> Self {
        self.cache = cache;
        self
    }

    pub fn shared_cache(&self) -> SharedDnsCache {
        self.cache.clone()
    }

    pub fn cache(&self) -> DnsCache {
        self.cache.snapshot()
    }

    pub fn rollback_observation(&mut self, observation: &DnsObservation) {
        self.cache.rollback_observation(observation);
    }

    pub fn into_parts(self) -> (BrokerCore, DnsCache, U) {
        (self.broker, self.cache.snapshot(), self.upstream)
    }

    fn fail_closed_upstream_error(
        &mut self,
        request: &PolicyRequest,
        metadata: &DnsQueryMetadata,
        query_packet: &[u8],
        error: DnsUpstreamError,
    ) -> DnsHandlerResult {
        let request = request
            .clone()
            .with_detail("dns_upstream_error", dns_upstream_error_detail(&error));
        let decision = PolicyDecision {
            decision: Decision::FailClosed,
            reason: Some(DenialReason::DnsDenied),
            rule_id: None,
            audit_kind: AuditKind::DnsQueryDecision,
        };
        let audit = AuditRecord::new(
            AuditKind::DnsQueryDecision,
            request.sandbox.session_id.clone(),
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Dns)
        .with_destination(request.destination.clone())
        .with_hostname(metadata.hostname.clone())
        .with_decision(Decision::FailClosed, Some(DenialReason::DnsDenied))
        .with_detail("dns_upstream_error", dns_upstream_error_detail(&error));
        let decision = match self.broker.append_audit_for(&request, audit) {
            Ok(_) => decision,
            Err(decision) => decision,
        };
        DnsHandlerResult {
            response: build_refused_response(query_packet).ok(),
            decision,
            observed_addresses: Vec::new(),
            observation: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsAnswerSummary {
    pub addresses: Vec<IpAddr>,
    pub ttl_ms: Option<u64>,
}

pub fn parse_dns_response_addresses(packet: &[u8]) -> Result<DnsAnswerSummary, DnsParseError> {
    parse_dns_response_addresses_inner(None, packet).map_err(|error| match error {
        DnsResponseValidationError::Parse(error) => error,
        DnsResponseValidationError::Mismatch => DnsParseError::NotQuery,
    })
}

fn parse_dns_response_addresses_for(
    query: &DnsQueryMetadata,
    packet: &[u8],
) -> Result<DnsAnswerSummary, DnsUpstreamError> {
    parse_dns_response_addresses_inner(Some(query), packet)
        .map_err(|_| DnsUpstreamError::MalformedResponse)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DnsResponseValidationError {
    Parse(DnsParseError),
    Mismatch,
}

fn parse_dns_response_addresses_inner(
    expected_query: Option<&DnsQueryMetadata>,
    packet: &[u8],
) -> Result<DnsAnswerSummary, DnsResponseValidationError> {
    if packet.len() < 12 {
        return Err(DnsResponseValidationError::Parse(
            DnsParseError::ShortHeader,
        ));
    }
    if let Some(query) = expected_query {
        let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
        if transaction_id != query.transaction_id {
            return Err(DnsResponseValidationError::Mismatch);
        }
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsResponseValidationError::Parse(DnsParseError::NotQuery));
    }
    if flags & 0x000f != 0 {
        return Err(DnsResponseValidationError::Mismatch);
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
        return Err(DnsResponseValidationError::Mismatch);
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let mut cursor = 12usize;
    let question_name =
        read_dns_name(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
    let question_type = read_u16(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
    let question_class =
        read_u16(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
    if let Some(query) = expected_query {
        if question_name != query.hostname
            || question_type != query.query_type.code()
            || question_class != query.query_class
        {
            return Err(DnsResponseValidationError::Mismatch);
        }
    }

    let mut addresses = Vec::new();
    let mut min_ttl_ms: Option<u64> = None;
    for _ in 0..ancount {
        let answer_name =
            read_dns_name(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
        if expected_query.is_some() && answer_name != question_name {
            return Err(DnsResponseValidationError::Mismatch);
        }
        let answer_type =
            read_u16(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
        let answer_class =
            read_u16(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
        if expected_query.is_some() && answer_class != question_class {
            return Err(DnsResponseValidationError::Mismatch);
        }
        let ttl_seconds =
            read_u32(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)?;
        let rdlen =
            read_u16(packet, &mut cursor).map_err(DnsResponseValidationError::Parse)? as usize;
        let rdata = take(packet, &mut cursor, rdlen).map_err(DnsResponseValidationError::Parse)?;
        min_ttl_ms = Some(
            min_ttl_ms
                .unwrap_or(u64::MAX)
                .min(u64::from(ttl_seconds).saturating_mul(1_000)),
        );
        match (answer_type, rdlen) {
            (1, 4) => {
                if !answer_type_matches_expected_query(DnsQueryType::A, expected_query) {
                    return Err(DnsResponseValidationError::Mismatch);
                }
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            (28, 16) => {
                if !answer_type_matches_expected_query(DnsQueryType::Aaaa, expected_query) {
                    return Err(DnsResponseValidationError::Mismatch);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }

    Ok(DnsAnswerSummary {
        addresses,
        ttl_ms: min_ttl_ms,
    })
}

fn answer_type_matches_expected_query(
    answer_query_type: DnsQueryType,
    expected_query: Option<&DnsQueryMetadata>,
) -> bool {
    match expected_query {
        Some(query) => query.query_type == answer_query_type,
        None => true,
    }
}

fn read_dns_name(packet: &[u8], cursor: &mut usize) -> Result<String, DnsParseError> {
    let mut labels = Vec::new();
    let mut local_cursor = *cursor;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        let Some(&len) = packet.get(local_cursor) else {
            return Err(DnsParseError::TruncatedQuestion);
        };
        local_cursor += 1;
        if len == 0 {
            if !jumped {
                *cursor = local_cursor;
            }
            return Ok(normalize_hostname(&labels.join(".")));
        }
        if len & 0b1100_0000 == 0b1100_0000 {
            let Some(&next) = packet.get(local_cursor) else {
                return Err(DnsParseError::TruncatedQuestion);
            };
            let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
            if pointer >= packet.len() || jumps > 8 {
                return Err(DnsParseError::TruncatedQuestion);
            }
            if !jumped {
                *cursor = local_cursor + 1;
            }
            local_cursor = pointer;
            jumped = true;
            jumps += 1;
            continue;
        }
        if len & 0b1100_0000 != 0 || len > 63 {
            return Err(DnsParseError::LabelTooLong);
        }
        let label = take(packet, &mut local_cursor, len as usize)?;
        let label = std::str::from_utf8(label).map_err(|_| DnsParseError::TruncatedQuestion)?;
        labels.push(label.to_string());
        if !jumped {
            *cursor = local_cursor;
        }
    }
}

fn read_u16(packet: &[u8], cursor: &mut usize) -> Result<u16, DnsParseError> {
    let bytes = take(packet, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], cursor: &mut usize) -> Result<u32, DnsParseError> {
    let bytes = take(packet, cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], DnsParseError> {
    if packet.len().saturating_sub(*cursor) < len {
        return Err(DnsParseError::TruncatedQuestion);
    }
    let start = *cursor;
    *cursor += len;
    Ok(&packet[start..start + len])
}

fn dns_query_type_name(query_type: DnsQueryType) -> String {
    match query_type {
        DnsQueryType::A => "A".to_string(),
        DnsQueryType::Aaaa => "AAAA".to_string(),
        DnsQueryType::Https => "HTTPS".to_string(),
        DnsQueryType::Svcb => "SVCB".to_string(),
        DnsQueryType::Other(code) => format!("TYPE{code}"),
    }
}

fn dns_parse_error_detail(error: &DnsParseError) -> &'static str {
    match error {
        DnsParseError::ShortHeader => "short_header",
        DnsParseError::NotQuery => "not_query",
        DnsParseError::UnsupportedQuestionCount(_) => "unsupported_question_count",
        DnsParseError::NameCompressionInQuestion => "name_compression_in_question",
        DnsParseError::LabelTooLong => "label_too_long",
        DnsParseError::TruncatedQuestion => "truncated_question",
        DnsParseError::MissingQuestionType => "missing_question_type",
    }
}

fn dns_upstream_error_detail(error: &DnsUpstreamError) -> &'static str {
    match error {
        DnsUpstreamError::Unavailable => "unavailable",
        DnsUpstreamError::SourceMismatch => "source_mismatch",
        DnsUpstreamError::MalformedResponse => "malformed_response",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyConfig, PolicyEngine, PolicyRule};
    use crate::proxy_frontend::{ExplicitProxyFrontend, InMemoryExplicitProxyEgress};
    use crate::types::{AuditKind, Protocol};
    use pretty_assertions::assert_eq;

    #[derive(Clone, Debug)]
    struct MockUpstream {
        response: Vec<u8>,
        calls: usize,
    }

    impl DnsUpstream for MockUpstream {
        fn exchange(
            &mut self,
            _query: &DnsQueryMetadata,
            _packet: &[u8],
        ) -> Result<Vec<u8>, DnsUpstreamError> {
            self.calls += 1;
            Ok(self.response.clone())
        }
    }

    #[test]
    fn allowed_query_returns_upstream_response_and_observes_addresses() {
        let query = dns_query(0x1234, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream {
                response: response.clone(),
                calls: 0,
            },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::Allow);
        assert_eq!(result.response.as_deref(), Some(response.as_slice()));
        assert_eq!(
            result.observed_addresses,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_some());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::DnsQueryDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[0].details["dns_query_type"], "A");
        assert_eq!(records[1].kind, AuditKind::DnsQueryDecision);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        let (_, _, upstream) = handler.into_parts();
        assert_eq!(upstream.calls, 1);
    }

    #[test]
    fn shared_dns_cache_feeds_proxy_resolution_after_delivered_query() {
        let query = dns_query(0x1234, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let shared_cache = SharedDnsCache::default();
        let mut dns_config = PolicyConfig::default();
        dns_config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let dns_broker = BrokerCore::new(PolicyEngine::new(dns_config), 8);
        let mut handler = DnsBrokerHandler::new(
            dns_broker,
            MockUpstream {
                response: response.clone(),
                calls: 0,
            },
            "10.0.2.3".parse().unwrap(),
        )
        .with_shared_cache(shared_cache.clone());
        let result = handler.handle_query("s1", &query, 1_000);
        assert!(result.observation.is_some());

        let mut proxy_config = PolicyConfig::default();
        proxy_config.rules.push(
            PolicyRule::allow("allow-example-http")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let proxy_broker = BrokerCore::new(PolicyEngine::new(proxy_config), 8);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", proxy_broker, InMemoryExplicitProxyEgress::default())
                .with_shared_dns_cache(shared_cache);

        let result = frontend
            .handle_http_proxy_bytes_at(
                b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
                1_100,
            )
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.forwarded);
        assert_eq!(
            frontend.egress().forwarded_http()[0]
                .0
                .resolved_destination_ip,
            Some("93.184.216.34".parse().unwrap())
        );
        let records: Vec<_> = frontend.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(records[0].details["resolution_source"], "broker_dns");
        assert_eq!(records[0].details["selected_ip"], "93.184.216.34");
        assert_eq!(records[1].kind, AuditKind::HttpRequestDecision);
    }

    #[test]
    fn denied_query_returns_refused_without_upstream() {
        let query = dns_query(0x2222, "blocked.test", 1);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream {
                response: Vec::new(),
                calls: 0,
            },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::DenyDrop);
        let response = result.response.unwrap();
        assert_eq!(response[3] & 0x0f, 5);
        let (_, _, upstream) = handler.into_parts();
        assert_eq!(upstream.calls, 0);
    }

    #[test]
    fn malformed_query_fails_closed_with_parse_detail() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream {
                response: Vec::new(),
                calls: 0,
            },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &[0; 11], 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response, None);
        let record = handler.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::UnsupportedDenied);
        assert_eq!(record.reason, Some(DenialReason::MalformedPacket));
        assert_eq!(record.details["dns_parse_error"], "short_header");
    }

    #[test]
    fn mismatched_upstream_response_fails_closed_without_cache_update() {
        let query = dns_query(0x5555, "Example.COM", 1);
        let mut response = dns_a_response(&query, [93, 184, 216, 34], 30);
        response[1] = 0x56;
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream { response, calls: 0 },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.decision.reason, Some(DenialReason::DnsDenied));
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::DnsQueryDecision);
        assert_eq!(
            records[1].details["dns_upstream_error"],
            "malformed_response"
        );
    }

    #[test]
    fn wrong_answer_class_fails_closed_without_cache_update() {
        let query = dns_query(0x7777, "Example.COM", 1);
        let mut response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let answer_class_offset = response.len() - 12;
        response[answer_class_offset..answer_class_offset + 2].copy_from_slice(&3u16.to_be_bytes());
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream { response, calls: 0 },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(
            records[1].details["dns_upstream_error"],
            "malformed_response"
        );
    }

    #[test]
    fn wrong_answer_type_fails_closed_without_cache_update() {
        let query = dns_query(0x8888, "Example.COM", 28);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream { response, calls: 0 },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.decision.reason, Some(DenialReason::DnsDenied));
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(result.observed_addresses.is_empty());
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(
            records[1].details["dns_upstream_error"],
            "malformed_response"
        );
    }

    #[test]
    fn malformed_upstream_response_fails_closed_without_release() {
        let query = dns_query(0x6666, "Example.COM", 1);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream {
                response: vec![0; 11],
                calls: 0,
            },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(result.observed_addresses.is_empty());
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(
            records[1].details["dns_upstream_error"],
            "malformed_response"
        );
    }

    #[test]
    fn address_observation_backpressure_blocks_upstream_response_release() {
        let query = dns_query(0x3333, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 1);
        let mut handler = DnsBrokerHandler::new(
            broker,
            MockUpstream { response, calls: 0 },
            "10.0.2.3".parse().unwrap(),
        );

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(result.observed_addresses.is_empty());
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
        assert_eq!(records[0].reason, Some(DenialReason::AuditBackpressure));
    }

    #[test]
    fn response_address_parser_extracts_a_answers_and_ttl() {
        let query = dns_query(0x4444, "example.com", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let summary = parse_dns_response_addresses(&response).unwrap();
        assert_eq!(
            summary.addresses,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(summary.ttl_ms, Some(30_000));
    }

    fn dns_query(transaction_id: u16, hostname: &str, query_type: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&query_type.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn dns_a_response(query: &[u8], address: [u8; 4], ttl_seconds: u32) -> Vec<u8> {
        let metadata = parse_dns_query(query).unwrap();
        let mut response = query[..metadata.question_end].to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }
}
