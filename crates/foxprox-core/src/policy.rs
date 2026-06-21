use crate::audit::{unix_timestamp_ms, AuditRecord};
use crate::types::{
    normalize_hostname, AttributionConfidence, AttributionSource, AuditKind, Decision,
    DenialReason, Frontend, HostnameAttribution, NetworkEndpoint, Origin, Protocol,
    SandboxIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cidr {
    pub network: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(network: IpAddr, prefix: u8) -> Self {
        Self { network, prefix }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) if self.prefix <= 32 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) if self.prefix <= 128 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub action: RuleAction,
    pub protocol: Option<Protocol>,
    pub frontend: Option<Frontend>,
    pub destination_cidr: Option<Cidr>,
    pub destination_port: Option<u16>,
    pub hostname: Option<String>,
    pub domain_suffix: Option<String>,
    pub origin_scheme: Option<String>,
    pub origin_host: Option<String>,
    pub origin_port: Option<u16>,
    pub http_method: Option<String>,
    pub http_path_prefix: Option<String>,
    pub sandbox_profile: Option<String>,
    pub min_attribution_confidence: Option<AttributionConfidence>,
}

impl PolicyRule {
    pub fn allow(id: impl Into<String>) -> Self {
        Self::new(id, RuleAction::Allow)
    }

    pub fn deny(id: impl Into<String>) -> Self {
        Self::new(id, RuleAction::Deny)
    }

    fn new(id: impl Into<String>, action: RuleAction) -> Self {
        Self {
            id: id.into(),
            action,
            protocol: None,
            frontend: None,
            destination_cidr: None,
            destination_port: None,
            hostname: None,
            domain_suffix: None,
            origin_scheme: None,
            origin_host: None,
            origin_port: None,
            http_method: None,
            http_path_prefix: None,
            sandbox_profile: None,
            min_attribution_confidence: None,
        }
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn frontend(mut self, frontend: Frontend) -> Self {
        self.frontend = Some(frontend);
        self
    }

    pub fn destination_cidr(mut self, cidr: Cidr) -> Self {
        self.destination_cidr = Some(cidr);
        self
    }

    pub fn destination_port(mut self, port: u16) -> Self {
        self.destination_port = Some(port);
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(normalize_hostname(&hostname.into()));
        self
    }

    pub fn domain_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.domain_suffix = Some(normalize_hostname(&suffix.into()));
        self
    }

    pub fn origin(mut self, scheme: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        self.origin_scheme = Some(scheme.into().to_ascii_lowercase());
        self.origin_host = Some(normalize_hostname(&host.into()));
        self.origin_port = Some(port);
        self
    }

    pub fn http_method(mut self, method: impl Into<String>) -> Self {
        self.http_method = Some(method.into().to_ascii_uppercase());
        self
    }

    pub fn http_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.http_path_prefix = Some(prefix.into());
        self
    }

    pub fn sandbox_profile(mut self, profile: impl Into<String>) -> Self {
        self.sandbox_profile = Some(profile.into());
        self
    }

    pub fn min_attribution_confidence(mut self, confidence: AttributionConfidence) -> Self {
        self.min_attribution_confidence = Some(confidence);
        self
    }

    fn matches_scope_without_hostname(&self, request: &PolicyRequest) -> bool {
        if self
            .protocol
            .is_some_and(|protocol| protocol != request.protocol)
        {
            return false;
        }
        if self
            .frontend
            .is_some_and(|frontend| frontend != request.frontend)
        {
            return false;
        }
        if self
            .destination_port
            .is_some_and(|port| request.destination.port != Some(port))
        {
            return false;
        }
        if let Some(cidr) = &self.destination_cidr {
            let Some(destination_ip) = request.destination.ip else {
                return false;
            };
            if !cidr.contains(destination_ip) {
                return false;
            }
        }
        if self
            .sandbox_profile
            .as_ref()
            .is_some_and(|profile| request.sandbox.profile.as_ref() != Some(profile))
        {
            return false;
        }
        true
    }

    fn requires_hostname_context(&self, request: &PolicyRequest) -> bool {
        (self.hostname.is_some() || self.domain_suffix.is_some() || self.origin_host.is_some())
            && self.matches_scope_without_hostname(request)
    }

    fn matches(&self, request: &PolicyRequest) -> bool {
        if !self.matches_scope_without_hostname(request) {
            return false;
        }
        if let Some(confidence) = self.min_attribution_confidence {
            let actual = request
                .hostname_attribution
                .as_ref()
                .map(|a| a.confidence)
                .unwrap_or(AttributionConfidence::None);
            if actual < confidence {
                return false;
            }
        }
        if let Some(hostname) = &self.hostname {
            if request.hostname().as_deref() != Some(hostname.as_str()) {
                return false;
            }
        }
        if let Some(suffix) = &self.domain_suffix {
            let Some(hostname) = request.hostname() else {
                return false;
            };
            if hostname != *suffix && !hostname.ends_with(&format!(".{suffix}")) {
                return false;
            }
        }
        if self.origin_scheme.is_some() || self.origin_host.is_some() || self.origin_port.is_some()
        {
            let Some(origin) = &request.origin else {
                return false;
            };
            if self
                .origin_scheme
                .as_ref()
                .is_some_and(|scheme| origin.scheme != *scheme)
            {
                return false;
            }
            if self
                .origin_host
                .as_ref()
                .is_some_and(|host| origin.host != *host)
            {
                return false;
            }
            if self.origin_port.is_some_and(|port| origin.port != port) {
                return false;
            }
        }
        if let Some(method) = &self.http_method {
            let Some(actual) = request.http_method.as_deref() else {
                return false;
            };
            if actual.to_ascii_uppercase() != *method {
                return false;
            }
        }
        if let Some(prefix) = &self.http_path_prefix {
            let Some(path) = request.http_path.as_deref() else {
                return false;
            };
            if !path.starts_with(prefix) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpTimeouts {
    pub dns_ms: u64,
    pub generic_ms: u64,
    pub quic_ms: u64,
    pub one_shot_ms: u64,
}

impl Default for UdpTimeouts {
    fn default() -> Self {
        Self {
            dns_ms: 10_000,
            generic_ms: 60_000,
            quic_ms: 180_000,
            one_shot_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub default_decision: Decision,
    pub broker_dns: Vec<IpAddr>,
    pub allow_ping: bool,
    pub allow_quic: bool,
    pub require_hostname_for_domain_rules: bool,
    pub udp_timeouts: UdpTimeouts,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfigError {
    pub code: String,
    pub field: String,
    pub detail: String,
}

impl PolicyConfigError {
    fn new(code: impl Into<String>, field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            field: field.into(),
            detail: detail.into(),
        }
    }
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<(), Vec<PolicyConfigError>> {
        let mut errors = Vec::new();
        if self.broker_dns.is_empty() {
            errors.push(PolicyConfigError::new(
                "broker_dns_empty",
                "broker_dns",
                "at least one broker DNS resolver address is required",
            ));
        }
        if self.default_decision == Decision::RequireBrokerDns {
            errors.push(PolicyConfigError::new(
                "invalid_default_decision",
                "default_decision",
                "require_broker_dns is not a terminal default policy decision",
            ));
        }
        for (field, value) in [
            ("udp_timeouts.dns_ms", self.udp_timeouts.dns_ms),
            ("udp_timeouts.generic_ms", self.udp_timeouts.generic_ms),
            ("udp_timeouts.quic_ms", self.udp_timeouts.quic_ms),
            ("udp_timeouts.one_shot_ms", self.udp_timeouts.one_shot_ms),
        ] {
            if value == 0 {
                errors.push(PolicyConfigError::new(
                    "udp_timeout_zero",
                    field,
                    "UDP timeout must be greater than zero milliseconds",
                ));
            }
        }
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.id.trim().is_empty() {
                errors.push(PolicyConfigError::new(
                    "rule_id_empty",
                    format!("rules[{index}].id"),
                    "policy rule IDs must be stable non-empty audit identifiers",
                ));
            }
            if let Some(cidr) = &rule.destination_cidr {
                let valid = match cidr.network {
                    IpAddr::V4(_) => cidr.prefix <= 32,
                    IpAddr::V6(_) => cidr.prefix <= 128,
                };
                if !valid {
                    errors.push(PolicyConfigError::new(
                        "cidr_prefix_invalid",
                        format!("rules[{index}].destination_cidr.prefix"),
                        format!("prefix {} is invalid for {}", cidr.prefix, cidr.network),
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn reload_audit(&self, sandbox_id: impl Into<String>) -> AuditRecord {
        let sandbox_id = sandbox_id.into();
        match self.validate() {
            Ok(()) => AuditRecord::new(AuditKind::PolicyReload, sandbox_id)
                .with_frontend(Frontend::Core)
                .with_decision(Decision::Allow, None)
                .with_detail("rule_count", self.rules.len().to_string())
                .with_detail("default_decision", decision_name(self.default_decision))
                .with_detail("allow_quic", self.allow_quic.to_string())
                .with_detail("broker_dns_count", self.broker_dns.len().to_string()),
            Err(errors) => AuditRecord::new(AuditKind::PolicyReload, sandbox_id)
                .with_frontend(Frontend::Core)
                .with_decision(Decision::FailClosed, Some(DenialReason::PolicyConfig))
                .with_detail(
                    "error_codes",
                    errors
                        .iter()
                        .map(|error| error.code.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .with_detail("error_count", errors.len().to_string()),
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_decision: Decision::DenyDrop,
            broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3))],
            allow_ping: false,
            allow_quic: true,
            require_hostname_for_domain_rules: true,
            udp_timeouts: UdpTimeouts::default(),
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRequest {
    pub sandbox: SandboxIdentity,
    pub frontend: Frontend,
    pub protocol: Protocol,
    pub source: NetworkEndpoint,
    pub destination: NetworkEndpoint,
    pub hostname_attribution: Option<HostnameAttribution>,
    pub origin: Option<Origin>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub dns_query_type: Option<String>,
    pub tls_sni: Option<String>,
    pub dns_correlated_hostname: Option<String>,
    pub sni_dns_mismatch: bool,
    pub hidden_sni: bool,
    pub unsupported_reason: Option<DenialReason>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub details: BTreeMap<String, String>,
}

impl PolicyRequest {
    pub fn new(sandbox_id: impl Into<String>, frontend: Frontend, protocol: Protocol) -> Self {
        Self {
            sandbox: SandboxIdentity::new(sandbox_id),
            frontend,
            protocol,
            source: NetworkEndpoint::default(),
            destination: NetworkEndpoint::default(),
            hostname_attribution: None,
            origin: None,
            http_method: None,
            http_path: None,
            dns_query_type: None,
            tls_sni: None,
            dns_correlated_hostname: None,
            sni_dns_mismatch: false,
            hidden_sni: false,
            unsupported_reason: None,
            icmp_type: None,
            icmp_code: None,
            details: BTreeMap::new(),
        }
    }

    pub fn tcp_connect(
        sandbox_id: impl Into<String>,
        frontend: Frontend,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
    ) -> Self {
        let mut request = Self::new(sandbox_id, frontend, Protocol::Tcp);
        request.source = source;
        request.destination = destination;
        request
    }

    pub fn udp_flow(
        sandbox_id: impl Into<String>,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
    ) -> Self {
        let mut request = Self::new(sandbox_id, Frontend::Tun, Protocol::Udp);
        request.source = source;
        request.destination = destination;
        request
    }

    pub fn dns_query(
        sandbox_id: impl Into<String>,
        destination: NetworkEndpoint,
        hostname: impl Into<String>,
        query_type: impl Into<String>,
    ) -> Self {
        let hostname = normalize_hostname(&hostname.into());
        let mut request = Self::new(sandbox_id, Frontend::Tun, Protocol::Dns);
        request.destination = destination;
        request.hostname_attribution = Some(HostnameAttribution::new(
            hostname,
            AttributionSource::BrokerDns,
            AttributionConfidence::High,
        ));
        request.dns_query_type = Some(query_type.into());
        request
    }

    pub fn unsupported(
        sandbox_id: impl Into<String>,
        frontend: Frontend,
        reason: DenialReason,
    ) -> Self {
        let mut request = Self::new(sandbox_id, frontend, Protocol::Unsupported);
        request.unsupported_reason = Some(reason);
        request
    }

    pub fn with_destination(mut self, destination: NetworkEndpoint) -> Self {
        self.destination = destination;
        self
    }

    pub fn with_attribution(mut self, attribution: HostnameAttribution) -> Self {
        self.hostname_attribution = Some(attribution);
        self
    }

    pub fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }

    pub fn with_http(mut self, method: impl Into<String>, path: impl Into<String>) -> Self {
        self.http_method = Some(method.into());
        self.http_path = Some(path.into());
        self.protocol = Protocol::Http;
        self
    }

    pub fn with_tls_sni(mut self, sni: impl Into<String>) -> Self {
        self.tls_sni = Some(normalize_hostname(&sni.into()));
        self
    }

    pub fn with_dns_correlated_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.dns_correlated_hostname = Some(normalize_hostname(&hostname.into()));
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn hostname(&self) -> Option<String> {
        self.hostname_attribution
            .as_ref()
            .map(|a| a.hostname.clone())
            .or_else(|| self.origin.as_ref().map(|o| o.host.clone()))
            .or_else(|| self.tls_sni.clone())
            .or_else(|| self.dns_correlated_hostname.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub rule_id: Option<String>,
    pub audit_kind: AuditKind,
}

impl PolicyDecision {
    fn allow(audit_kind: AuditKind, rule_id: Option<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: None,
            rule_id,
            audit_kind,
        }
    }

    fn deny(decision: Decision, reason: DenialReason, audit_kind: AuditKind) -> Self {
        Self {
            decision,
            reason: Some(reason),
            rule_id: None,
            audit_kind,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn decide(&self, request: &PolicyRequest) -> PolicyDecision {
        let audit_kind = audit_kind_for(request);

        if let Some(reason) = request.unsupported_reason {
            return PolicyDecision::deny(Decision::FailClosed, reason, audit_kind);
        }
        if request.protocol == Protocol::Unsupported {
            return PolicyDecision::deny(
                Decision::FailClosed,
                DenialReason::UnsupportedProtocol,
                audit_kind,
            );
        }
        if is_multicast(request.destination.ip) {
            return PolicyDecision::deny(
                Decision::DenyDrop,
                DenialReason::MulticastDenied,
                audit_kind,
            );
        }
        if is_limited_broadcast(request.destination.ip) {
            return PolicyDecision::deny(
                Decision::DenyDrop,
                DenialReason::BroadcastDenied,
                audit_kind,
            );
        }
        if self.is_direct_dns_bypass(request) {
            return PolicyDecision::deny(
                Decision::DenyDrop,
                DenialReason::DirectDnsBypass,
                AuditKind::DnsQueryDecision,
            );
        }
        if request.sni_dns_mismatch {
            return PolicyDecision::deny(
                Decision::DenyReset,
                DenialReason::SniDnsMismatch,
                AuditKind::SniDnsMismatchDenied,
            );
        }
        if request.hidden_sni {
            return PolicyDecision::deny(
                Decision::DenyReset,
                DenialReason::HiddenSni,
                AuditKind::HiddenSniDenied,
            );
        }
        if request.protocol == Protocol::Quic && !self.config.allow_quic {
            return PolicyDecision::deny(
                Decision::DenyDrop,
                DenialReason::QuicDisabled,
                audit_kind,
            );
        }
        if request.protocol == Protocol::Icmp {
            if !self.icmp_allowed(request) {
                return PolicyDecision::deny(
                    Decision::DenyDrop,
                    DenialReason::IcmpUnsupported,
                    audit_kind,
                );
            }
            return PolicyDecision::allow(audit_kind, None);
        }

        for rule in &self.config.rules {
            if rule.matches(request) {
                return match rule.action {
                    RuleAction::Allow => PolicyDecision::allow(audit_kind, Some(rule.id.clone())),
                    RuleAction::Deny => PolicyDecision {
                        decision: Decision::DenyDrop,
                        reason: Some(DenialReason::RuleDenied),
                        rule_id: Some(rule.id.clone()),
                        audit_kind,
                    },
                };
            }
        }

        if request.destination.port == Some(853) {
            return PolicyDecision::deny(Decision::DenyDrop, DenialReason::DnsDenied, audit_kind);
        }

        if self.config.require_hostname_for_domain_rules
            && request.hostname().is_none()
            && self
                .config
                .rules
                .iter()
                .any(|rule| rule.requires_hostname_context(request))
        {
            return PolicyDecision::deny(
                Decision::DenyDrop,
                DenialReason::HostnameAttributionRequired,
                audit_kind,
            );
        }

        if self.config.default_decision == Decision::Allow {
            PolicyDecision::allow(audit_kind, None)
        } else {
            PolicyDecision::deny(
                self.config.default_decision,
                DenialReason::DefaultDeny,
                audit_kind,
            )
        }
    }

    pub fn decide_with_audit(&self, request: &PolicyRequest) -> (PolicyDecision, AuditRecord) {
        self.decide_with_audit_at(request, unix_timestamp_ms())
    }

    pub fn decide_with_audit_at(
        &self,
        request: &PolicyRequest,
        timestamp_ms: u128,
    ) -> (PolicyDecision, AuditRecord) {
        let decision = self.decide(request);
        let mut audit = AuditRecord::new_at(
            decision.audit_kind,
            request.sandbox.session_id.clone(),
            timestamp_ms,
        )
        .with_frontend(request.frontend)
        .with_protocol(request.protocol)
        .with_source(request.source.clone())
        .with_destination(request.destination.clone())
        .with_decision(decision.decision, decision.reason);
        audit.process_id = request.sandbox.process_id;
        if let Some(attribution) = &request.hostname_attribution {
            audit = audit.with_attribution(attribution.clone());
        } else if let Some(hostname) = request.hostname() {
            audit = audit.with_hostname(hostname);
        }
        if let Some(origin) = &request.origin {
            audit = audit.with_origin(origin.clone());
        }
        if let Some(rule_id) = &decision.rule_id {
            audit = audit.with_rule(rule_id.clone());
        }
        if let Some(method) = &request.http_method {
            audit = audit.with_detail("http_method", method);
        }
        if let Some(path) = &request.http_path {
            audit = audit.with_detail("http_path", path);
        }
        if let Some(query_type) = &request.dns_query_type {
            audit = audit.with_detail("dns_query_type", query_type);
        }
        if let Some(icmp_type) = request.icmp_type {
            audit = audit.with_detail("icmp_type", icmp_type.to_string());
        }
        if let Some(icmp_code) = request.icmp_code {
            audit = audit.with_detail("icmp_code", icmp_code.to_string());
        }
        for (key, value) in &request.details {
            audit = audit.with_detail(key, value);
        }
        (decision, audit)
    }

    fn is_direct_dns_bypass(&self, request: &PolicyRequest) -> bool {
        let is_dns_port = request.destination.port == Some(53) || request.protocol == Protocol::Dns;
        if !is_dns_port {
            return false;
        }
        match request.destination.ip {
            Some(ip) => !self.config.broker_dns.contains(&ip),
            None => true,
        }
    }

    fn icmp_allowed(&self, request: &PolicyRequest) -> bool {
        match request.icmp_type {
            // Destination unreachable and time exceeded are needed for normal networking.
            Some(3 | 11) => true,
            // Echo request/reply depends on ping support.
            Some(0 | 8) => self.config.allow_ping,
            _ => false,
        }
    }
}

fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::DenyDrop => "deny_drop",
        Decision::DenyReset => "deny_reset",
        Decision::DenyIcmpUnreachable => "deny_icmp_unreachable",
        Decision::RequireBrokerDns => "require_broker_dns",
        Decision::FailClosed => "fail_closed",
    }
}

fn audit_kind_for(request: &PolicyRequest) -> AuditKind {
    match (request.frontend, request.protocol) {
        (_, Protocol::Dns) => AuditKind::DnsQueryDecision,
        (_, Protocol::Tcp) => AuditKind::TcpConnectDecision,
        (_, Protocol::Udp) => AuditKind::UdpPacketDecision,
        (_, Protocol::Quic) => AuditKind::QuicCandidateFlowCreated,
        (_, Protocol::Icmp) => AuditKind::IcmpDecision,
        (Frontend::HttpProxy, Protocol::Http) => AuditKind::HttpRequestDecision,
        (Frontend::HttpProxy, Protocol::Https) => AuditKind::HttpsConnectDecision,
        (Frontend::Socks5Proxy, Protocol::Socks) => AuditKind::SocksConnectDecision,
        (Frontend::Tun, Protocol::Http) => AuditKind::TransparentHttpDecision,
        (_, Protocol::Unsupported) => AuditKind::UnsupportedDenied,
        _ => AuditKind::TcpConnectDecision,
    }
}

fn is_multicast(ip: Option<IpAddr>) -> bool {
    match ip {
        Some(IpAddr::V4(ip)) => ip.is_multicast(),
        Some(IpAddr::V6(ip)) => ip.is_multicast(),
        None => false,
    }
}

fn is_limited_broadcast(ip: Option<IpAddr>) -> bool {
    matches!(ip, Some(IpAddr::V4(ip)) if ip == Ipv4Addr::BROADCAST)
}

#[allow(dead_code)]
fn _ipv6_unspecified() -> IpAddr {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttributionConfidence, AttributionSource};
    use pretty_assertions::assert_eq;

    fn socket(ip: &str, port: u16) -> NetworkEndpoint {
        NetworkEndpoint::socket(ip.parse().unwrap(), port)
    }

    #[test]
    fn policy_config_validation_reports_structured_errors() {
        let mut config = PolicyConfig {
            broker_dns: Vec::new(),
            default_decision: Decision::RequireBrokerDns,
            ..PolicyConfig::default()
        };
        config.udp_timeouts.quic_ms = 0;
        config.rules.push(
            PolicyRule::allow("").destination_cidr(Cidr::new("2001:db8::".parse().unwrap(), 129)),
        );

        let errors = config.validate().unwrap_err();
        let codes: Vec<_> = errors.iter().map(|error| error.code.as_str()).collect();
        assert!(codes.contains(&"broker_dns_empty"));
        assert!(codes.contains(&"invalid_default_decision"));
        assert!(codes.contains(&"udp_timeout_zero"));
        assert!(codes.contains(&"rule_id_empty"));
        assert!(codes.contains(&"cidr_prefix_invalid"));

        let audit = config.reload_audit("s1");
        assert_eq!(audit.kind, AuditKind::PolicyReload);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.reason, Some(DenialReason::PolicyConfig));
        assert!(audit.details["error_codes"].contains("broker_dns_empty"));
    }

    #[test]
    fn valid_policy_config_reload_audit_summarizes_runtime_settings() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow("allow-doc"));
        config.validate().unwrap();
        let audit = config.reload_audit("s1");
        assert_eq!(audit.kind, AuditKind::PolicyReload);
        assert_eq!(audit.frontend, Some(Frontend::Core));
        assert_eq!(audit.decision, Some(Decision::Allow));
        assert_eq!(audit.details["rule_count"], "1");
        assert_eq!(audit.details["default_decision"], "deny_drop");
        assert_eq!(audit.details["allow_quic"], "true");
        assert_eq!(audit.details["broker_dns_count"], "1");
    }

    #[test]
    fn direct_external_dns_fails_closed_with_audit_context() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let request = PolicyRequest::dns_query("s1", socket("8.8.8.8", 53), "example.com", "A");
        let (decision, audit) = engine.decide_with_audit(&request);

        assert_eq!(decision.decision, Decision::DenyDrop);
        assert_eq!(decision.reason, Some(DenialReason::DirectDnsBypass));
        assert_eq!(audit.kind, AuditKind::DnsQueryDecision);
        assert_eq!(audit.reason, Some(DenialReason::DirectDnsBypass));
        assert_eq!(audit.hostname.as_deref(), Some("example.com"));
        assert_eq!(audit.details["dns_query_type"], "A");
    }

    #[test]
    fn broker_dns_query_can_be_allowed_by_hostname_rule() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com")
                .min_attribution_confidence(AttributionConfidence::High),
        );
        let engine = PolicyEngine::new(config);
        let request = PolicyRequest::dns_query("s1", socket("10.0.2.3", 53), "example.com", "AAAA");

        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("allow-example-dns"));
        assert_eq!(audit.decision, Some(Decision::Allow));
        assert_eq!(audit.rule_id.as_deref(), Some("allow-example-dns"));
    }

    #[test]
    fn sni_dns_mismatch_is_denied_with_specific_event() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let mut request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            socket("10.0.2.15", 40000),
            socket("93.184.216.34", 443),
        )
        .with_tls_sni("evil.test")
        .with_dns_correlated_hostname("example.com");
        request.sni_dns_mismatch = true;

        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::DenyReset);
        assert_eq!(audit.kind, AuditKind::SniDnsMismatchDenied);
        assert_eq!(audit.reason, Some(DenialReason::SniDnsMismatch));
        assert_eq!(audit.hostname.as_deref(), Some("evil.test"));
    }

    #[test]
    fn transparent_http_path_rule_uses_host_attribution() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-api")
                .protocol(Protocol::Http)
                .hostname("api.example.test")
                .http_path_prefix("/v1/")
                .min_attribution_confidence(AttributionConfidence::High),
        );
        let engine = PolicyEngine::new(config);
        let request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            socket("10.0.2.15", 41000),
            socket("198.51.100.5", 80),
        )
        .with_attribution(HostnameAttribution::new(
            "api.example.test",
            AttributionSource::PlaintextHttpHost,
            AttributionConfidence::High,
        ))
        .with_http("GET", "/v1/resource");

        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(audit.kind, AuditKind::TransparentHttpDecision);
        assert_eq!(audit.details["http_method"], "GET");
        assert_eq!(audit.details["http_path"], "/v1/resource");
    }

    #[test]
    fn http_method_rule_distinguishes_methods_with_audit_details() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-get-api")
                .protocol(Protocol::Http)
                .hostname("api.example.test")
                .http_method("GET")
                .http_path_prefix("/v1/"),
        );
        let engine = PolicyEngine::new(config);
        let post = PolicyRequest::new("s1", Frontend::HttpProxy, Protocol::Http)
            .with_attribution(HostnameAttribution::new(
                "api.example.test",
                AttributionSource::ExplicitProxyHost,
                AttributionConfidence::High,
            ))
            .with_http("POST", "/v1/resource");

        let (decision, audit) = engine.decide_with_audit(&post);
        assert_eq!(decision.decision, Decision::DenyDrop);
        assert_eq!(decision.reason, Some(DenialReason::DefaultDeny));
        assert_eq!(audit.details["http_method"], "POST");
        assert_eq!(audit.details["http_path"], "/v1/resource");

        let get = PolicyRequest::new("s1", Frontend::HttpProxy, Protocol::Http)
            .with_attribution(HostnameAttribution::new(
                "api.example.test",
                AttributionSource::ExplicitProxyHost,
                AttributionConfidence::High,
            ))
            .with_http("GET", "/v1/resource");
        assert_eq!(engine.decide(&get).decision, Decision::Allow);
    }

    #[test]
    fn origin_tuple_rule_matches_explicit_proxy_origin() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-origin")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Https)
                .origin("https", "Example.COM", 443),
        );
        let engine = PolicyEngine::new(config);
        let request = PolicyRequest::new("s1", Frontend::HttpProxy, Protocol::Https)
            .with_origin(Origin::new("https", "example.com", 443));

        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("allow-origin"));
        assert_eq!(audit.origin.as_ref().unwrap().host, "example.com");
        assert_eq!(audit.rule_id.as_deref(), Some("allow-origin"));
    }

    #[test]
    fn sandbox_profile_rule_scopes_policy() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-dev-profile")
                .protocol(Protocol::Tcp)
                .destination_port(443)
                .sandbox_profile("dev"),
        );
        let engine = PolicyEngine::new(config);
        let mut request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            socket("10.0.2.15", 41000),
            socket("203.0.113.10", 443),
        );
        assert_eq!(engine.decide(&request).decision, Decision::DenyDrop);
        request.sandbox.profile = Some("dev".to_string());
        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(audit.rule_id.as_deref(), Some("allow-dev-profile"));
    }

    #[test]
    fn socks_connect_uses_same_policy_engine() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks-dest")
                .protocol(Protocol::Socks)
                .hostname("repo.example")
                .destination_port(22),
        );
        let engine = PolicyEngine::new(config);
        let request = PolicyRequest::new("s1", Frontend::Socks5Proxy, Protocol::Socks)
            .with_destination(socket("203.0.113.10", 22))
            .with_attribution(HostnameAttribution::new(
                "repo.example",
                AttributionSource::SocksDestination,
                AttributionConfidence::High,
            ));

        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(audit.kind, AuditKind::SocksConnectDecision);
        assert_eq!(audit.hostname.as_deref(), Some("repo.example"));
    }

    #[test]
    fn multicast_udp_is_denied_before_default_policy() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config);
        let request =
            PolicyRequest::udp_flow("s1", socket("10.0.2.15", 5555), socket("224.0.0.251", 5353));
        let decision = engine.decide(&request);
        assert_eq!(decision.decision, Decision::DenyDrop);
        assert_eq!(decision.reason, Some(DenialReason::MulticastDenied));
    }

    #[test]
    fn domain_rule_without_hostname_has_specific_denial_reason() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-domain")
                .protocol(Protocol::Tcp)
                .destination_port(443)
                .domain_suffix("example.com")
                .min_attribution_confidence(AttributionConfidence::Medium),
        );
        let engine = PolicyEngine::new(config);
        let request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            socket("10.0.2.15", 50001),
            socket("93.184.216.34", 443),
        );

        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::DenyDrop);
        assert_eq!(
            decision.reason,
            Some(DenialReason::HostnameAttributionRequired)
        );
        assert_eq!(
            audit.reason,
            Some(DenialReason::HostnameAttributionRequired)
        );
    }

    #[test]
    fn dot_is_denied_by_default_but_can_be_explicitly_allowed() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            socket("10.0.2.15", 50002),
            socket("1.1.1.1", 853),
        );
        assert_eq!(
            engine.decide(&request).reason,
            Some(DenialReason::DnsDenied)
        );

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-dot-test")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("1.1.1.1".parse().unwrap(), 32))
                .destination_port(853),
        );
        let engine = PolicyEngine::new(config);
        assert_eq!(engine.decide(&request).decision, Decision::Allow);
    }

    #[test]
    fn essential_icmp_errors_are_allowed_by_default() {
        let mut request = PolicyRequest::new("s1", Frontend::Tun, Protocol::Icmp)
            .with_destination(NetworkEndpoint::ip("10.0.2.15".parse().unwrap()));
        request.icmp_type = Some(3);
        request.icmp_code = Some(1);
        let decision = PolicyEngine::new(PolicyConfig::default()).decide(&request);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn icmp_ping_requires_explicit_config() {
        let mut request = PolicyRequest::new("s1", Frontend::Tun, Protocol::Icmp)
            .with_destination(NetworkEndpoint::ip("8.8.8.8".parse().unwrap()));
        request.icmp_type = Some(8);
        request.icmp_code = Some(0);
        assert_eq!(
            PolicyEngine::new(PolicyConfig::default())
                .decide(&request)
                .reason,
            Some(DenialReason::IcmpUnsupported)
        );

        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        assert_eq!(
            PolicyEngine::new(config).decide(&request).decision,
            Decision::Allow
        );
    }

    #[test]
    fn quic_can_be_disabled_with_visible_reason() {
        let config = PolicyConfig {
            allow_quic: false,
            ..PolicyConfig::default()
        };
        let request = PolicyRequest::new("s1", Frontend::Tun, Protocol::Quic)
            .with_destination(socket("93.184.216.34", 443));
        let decision = PolicyEngine::new(config).decide(&request);
        assert_eq!(decision.decision, Decision::DenyDrop);
        assert_eq!(decision.reason, Some(DenialReason::QuicDisabled));
    }

    #[test]
    fn unsupported_event_fails_closed() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let request =
            PolicyRequest::unsupported("s1", Frontend::Tun, DenialReason::UnsupportedProtocol);
        let (decision, audit) = engine.decide_with_audit(&request);
        assert_eq!(decision.decision, Decision::FailClosed);
        assert_eq!(audit.kind, AuditKind::UnsupportedDenied);
        assert_eq!(audit.reason, Some(DenialReason::UnsupportedProtocol));
    }

    #[test]
    fn cidr_rule_allows_ip_port() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-doc-net")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("203.0.113.0".parse().unwrap(), 24))
                .destination_port(443),
        );
        let engine = PolicyEngine::new(config);
        let request = PolicyRequest::tcp_connect(
            "s1",
            Frontend::Tun,
            socket("10.0.2.15", 50000),
            socket("203.0.113.42", 443),
        );
        assert_eq!(engine.decide(&request).decision, Decision::Allow);
    }
}
