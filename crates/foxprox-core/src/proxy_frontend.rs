use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::flow::{DnsCache, DnsResolution};
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::proxy::{
    malformed_proxy_request, parse_http_proxy_request, parse_socks5_connect_request,
    HttpProxyRequestMetadata, SocksConnectMetadata,
};
use crate::types::{
    AttributionConfidence, AttributionSource, AuditKind, Decision, DenialReason, Frontend,
    HostnameAttribution, NetworkEndpoint,
};
use serde::{Deserialize, Serialize};

pub trait ExplicitProxyEgress {
    fn forward_http(
        &mut self,
        request: &HttpProxyRequestMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError>;

    fn connect_socks(
        &mut self,
        request: &SocksConnectMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyEgressError {
    SendFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitProxyResult {
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub forwarded: bool,
}

#[derive(Clone, Debug)]
pub struct ExplicitProxyFrontend<E> {
    sandbox_id: String,
    broker: BrokerCore,
    egress: E,
    dns_cache: Option<DnsCache>,
}

impl<E: ExplicitProxyEgress> ExplicitProxyFrontend<E> {
    pub fn new(sandbox_id: impl Into<String>, broker: BrokerCore, egress: E) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            broker,
            egress,
            dns_cache: None,
        }
    }

    pub fn with_dns_cache(mut self, dns_cache: DnsCache) -> Self {
        self.dns_cache = Some(dns_cache);
        self
    }

    pub fn handle_http_proxy_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        self.handle_http_proxy_bytes_inner(bytes, None)
    }

    pub fn handle_http_proxy_bytes_at(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        self.handle_http_proxy_bytes_inner(bytes, Some(now_ms))
    }

    fn handle_http_proxy_bytes_inner(
        &mut self,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        let mut metadata = match parse_http_proxy_request(bytes) {
            Ok(metadata) => metadata,
            Err(error) => {
                let request =
                    malformed_proxy_request(self.sandbox_id.clone(), Frontend::HttpProxy, error);
                let decision = self.broker.evaluate(&request);
                return Ok(result_from_decision(decision, false));
            }
        };
        let resolution = self.resolve_http_destination(&mut metadata, now_ms);
        let request = metadata
            .clone()
            .into_policy_request(self.sandbox_id.clone());
        if let Some(resolution) = resolution {
            if let Some(result) =
                self.append_resolution_audit(&request, Frontend::HttpProxy, resolution)
            {
                return Ok(result);
            }
        }
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false));
        }
        if let Err(error) = self.egress.forward_http(&metadata, bytes) {
            let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                .with_frontend(Frontend::HttpProxy)
                .with_protocol(request.protocol)
                .with_destination(request.destination.clone())
                .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                .with_detail("error", proxy_egress_error_detail(&error));
            let _ = self.broker.append_audit_for(&request, audit);
            return Err(error);
        }
        Ok(ExplicitProxyResult {
            decision: decision.decision,
            reason: decision.reason,
            forwarded: true,
        })
    }

    pub fn handle_socks5_connect_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        self.handle_socks5_connect_bytes_inner(bytes, None)
    }

    pub fn handle_socks5_connect_bytes_at(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        self.handle_socks5_connect_bytes_inner(bytes, Some(now_ms))
    }

    fn handle_socks5_connect_bytes_inner(
        &mut self,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        let mut metadata = match parse_socks5_connect_request(bytes) {
            Ok(metadata) => metadata,
            Err(error) => {
                let request =
                    malformed_proxy_request(self.sandbox_id.clone(), Frontend::Socks5Proxy, error);
                let decision = self.broker.evaluate(&request);
                return Ok(result_from_decision(decision, false));
            }
        };
        let resolution = self.resolve_socks_destination(&mut metadata, now_ms);
        let request = metadata
            .clone()
            .into_policy_request(self.sandbox_id.clone());
        if let Some(resolution) = resolution {
            if let Some(result) =
                self.append_resolution_audit(&request, Frontend::Socks5Proxy, resolution)
            {
                return Ok(result);
            }
        }
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false));
        }
        if let Err(error) = self.egress.connect_socks(&metadata, bytes) {
            let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                .with_frontend(Frontend::Socks5Proxy)
                .with_protocol(request.protocol)
                .with_destination(request.destination.clone())
                .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                .with_detail("error", proxy_egress_error_detail(&error));
            let _ = self.broker.append_audit_for(&request, audit);
            return Err(error);
        }
        Ok(ExplicitProxyResult {
            decision: decision.decision,
            reason: decision.reason,
            forwarded: true,
        })
    }

    fn resolve_http_destination(
        &self,
        metadata: &mut HttpProxyRequestMetadata,
        now_ms: Option<u64>,
    ) -> Option<DnsResolution> {
        if metadata.host.parse::<std::net::IpAddr>().is_ok()
            || metadata.resolved_destination_ip.is_some()
        {
            return None;
        }
        let resolution = self
            .dns_cache
            .as_ref()
            .zip(now_ms)
            .and_then(|(cache, now_ms)| cache.resolve_hostname(&metadata.host, now_ms))?;
        metadata.resolved_destination_ip = Some(resolution.address);
        Some(resolution)
    }

    fn resolve_socks_destination(
        &self,
        metadata: &mut SocksConnectMetadata,
        now_ms: Option<u64>,
    ) -> Option<DnsResolution> {
        if metadata.destination_ip.is_some() {
            return None;
        }
        let host = metadata.destination_host.as_deref()?;
        let resolution = self
            .dns_cache
            .as_ref()
            .zip(now_ms)
            .and_then(|(cache, now_ms)| cache.resolve_hostname(host, now_ms))?;
        metadata.destination_ip = Some(resolution.address);
        Some(resolution)
    }

    fn append_resolution_audit(
        &mut self,
        request: &PolicyRequest,
        frontend: Frontend,
        resolution: DnsResolution,
    ) -> Option<ExplicitProxyResult> {
        let audit = AuditRecord::new(AuditKind::ProxyDestinationResolved, self.sandbox_id.clone())
            .with_frontend(frontend)
            .with_protocol(request.protocol)
            .with_destination(NetworkEndpoint::socket(
                resolution.address,
                request.destination.port.unwrap_or_default(),
            ))
            .with_attribution(HostnameAttribution::new(
                resolution.hostname,
                AttributionSource::BrokerDns,
                AttributionConfidence::Medium,
            ))
            .with_decision(Decision::Allow, None)
            .with_detail("resolution_source", "broker_dns")
            .with_detail("selected_ip", resolution.address.to_string())
            .with_detail("dns_query_type", resolution.query_type)
            .with_detail("ttl_remaining_ms", resolution.ttl_remaining_ms.to_string());
        self.broker
            .append_audit_for(request, audit)
            .err()
            .map(|decision| result_from_decision(decision, false))
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn broker_mut(&mut self) -> &mut BrokerCore {
        &mut self.broker
    }

    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (BrokerCore, E) {
        (self.broker, self.egress)
    }
}

fn proxy_egress_error_detail(error: &ProxyEgressError) -> &'static str {
    match error {
        ProxyEgressError::SendFailed => "proxy_egress_send_failed",
    }
}

fn result_from_decision(decision: PolicyDecision, forwarded: bool) -> ExplicitProxyResult {
    ExplicitProxyResult {
        decision: decision.decision,
        reason: decision.reason,
        forwarded,
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryExplicitProxyEgress {
    forwarded_http: Vec<(HttpProxyRequestMetadata, Vec<u8>)>,
    connected_socks: Vec<(SocksConnectMetadata, Vec<u8>)>,
}

impl InMemoryExplicitProxyEgress {
    pub fn forwarded_http(&self) -> &[(HttpProxyRequestMetadata, Vec<u8>)] {
        &self.forwarded_http
    }

    pub fn connected_socks(&self) -> &[(SocksConnectMetadata, Vec<u8>)] {
        &self.connected_socks
    }
}

impl ExplicitProxyEgress for InMemoryExplicitProxyEgress {
    fn forward_http(
        &mut self,
        request: &HttpProxyRequestMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError> {
        self.forwarded_http.push((request.clone(), bytes.to_vec()));
        Ok(())
    }

    fn connect_socks(
        &mut self,
        request: &SocksConnectMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError> {
        self.connected_socks.push((request.clone(), bytes.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyConfig, PolicyEngine, PolicyRule};
    use crate::types::{AuditKind, Protocol};
    use pretty_assertions::assert_eq;

    #[test]
    fn allowed_http_proxy_request_forwards_after_shared_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());

        let result = frontend
            .handle_http_proxy_bytes(
                b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.forwarded);
        assert_eq!(frontend.egress().forwarded_http().len(), 1);
        assert_eq!(frontend.egress().forwarded_http()[0].0.host, "example.com");
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HttpRequestDecision);
        assert_eq!(record.decision, Some(Decision::Allow));
        assert_eq!(record.rule_id.as_deref(), Some("allow-http-proxy"));
    }

    #[test]
    fn denied_https_connect_does_not_forward() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());

        let result = frontend
            .handle_http_proxy_bytes(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::DefaultDeny));
        assert!(frontend.egress().forwarded_http().is_empty());
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HttpsConnectDecision);
        assert_eq!(record.reason, Some(DenialReason::DefaultDeny));
    }

    #[test]
    fn malformed_http_proxy_request_fails_closed_without_forwarding() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());

        let result = frontend
            .handle_http_proxy_bytes(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::ProxyMalformed));
        assert!(frontend.egress().forwarded_http().is_empty());
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::UnsupportedDenied);
        assert_eq!(record.frontend, Some(Frontend::HttpProxy));
        assert_eq!(record.details["proxy_parse_error"], "missing_host");
    }

    #[derive(Clone, Debug, Default)]
    struct FailingProxyEgress;

    impl ExplicitProxyEgress for FailingProxyEgress {
        fn forward_http(
            &mut self,
            _request: &HttpProxyRequestMetadata,
            _bytes: &[u8],
        ) -> Result<(), ProxyEgressError> {
            Err(ProxyEgressError::SendFailed)
        }

        fn connect_socks(
            &mut self,
            _request: &SocksConnectMetadata,
            _bytes: &[u8],
        ) -> Result<(), ProxyEgressError> {
            Err(ProxyEgressError::SendFailed)
        }
    }

    #[test]
    fn proxy_egress_error_is_audited_after_allow() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut frontend = ExplicitProxyFrontend::new("s1", broker, FailingProxyEgress);

        let error = frontend
            .handle_http_proxy_bytes(
                b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(error, ProxyEgressError::SendFailed);
        let records: Vec<_> = frontend.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].details["error"], "proxy_egress_send_failed");
    }

    #[test]
    fn http_proxy_domain_resolution_is_audited_before_egress() {
        let mut cache = DnsCache::default();
        cache.commit_observation(crate::flow::DnsObservation::new(
            "example.com",
            "A",
            vec!["93.184.216.34".parse().unwrap()],
            1_000,
            500,
        ));
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default())
                .with_dns_cache(cache);

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
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(records[0].details["resolution_source"], "broker_dns");
        assert_eq!(records[0].details["selected_ip"], "93.184.216.34");
        assert_eq!(records[0].details["ttl_remaining_ms"], "400");
        assert_eq!(
            records[0].destination.as_ref().unwrap().ip,
            Some("93.184.216.34".parse().unwrap())
        );
        assert_eq!(records[1].kind, AuditKind::HttpRequestDecision);
        assert_eq!(
            records[1].destination.as_ref().unwrap().ip,
            Some("93.184.216.34".parse().unwrap())
        );
    }

    #[test]
    fn socks_domain_resolution_is_audited_before_egress() {
        let mut cache = DnsCache::default();
        cache.commit_observation(crate::flow::DnsObservation::new(
            "example.com",
            "A",
            vec!["93.184.216.34".parse().unwrap()],
            2_000,
            1_000,
        ));
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .destination_port(443),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default())
                .with_dns_cache(cache);
        let request = [
            0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x01, 0xbb,
        ];

        let result = frontend
            .handle_socks5_connect_bytes_at(&request, 2_250)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.forwarded);
        assert_eq!(
            frontend.egress().connected_socks()[0].0.destination_ip,
            Some("93.184.216.34".parse().unwrap())
        );
        let records: Vec<_> = frontend.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(records[0].frontend, Some(Frontend::Socks5Proxy));
        assert_eq!(records[0].details["resolution_source"], "broker_dns");
        assert_eq!(records[0].details["selected_ip"], "93.184.216.34");
        assert_eq!(records[0].details["ttl_remaining_ms"], "750");
        assert_eq!(records[1].kind, AuditKind::SocksConnectDecision);
        assert_eq!(
            records[1].destination.as_ref().unwrap().ip,
            Some("93.184.216.34".parse().unwrap())
        );
    }

    #[test]
    fn allowed_socks_connect_forwards_after_shared_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .destination_port(443),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let request = [
            0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x01, 0xbb,
        ];

        let result = frontend.handle_socks5_connect_bytes(&request).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.forwarded);
        assert_eq!(frontend.egress().connected_socks().len(), 1);
        assert_eq!(
            frontend.egress().connected_socks()[0]
                .0
                .destination_host
                .as_deref(),
            Some("example.com")
        );
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::SocksConnectDecision);
        assert_eq!(record.rule_id.as_deref(), Some("allow-socks"));
    }
}
