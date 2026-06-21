//! Deterministic platform-independent policy model.

use crate::event::{
    AttributionConfidence, Hostname, HttpMethod, NetworkEvent, Origin, Protocol, SocksDestination,
    TransportEndpoint,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Action selected by the policy engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DecisionAction {
    /// Permit the request or flow.
    Allow,
    /// Deny by silently dropping traffic.
    DenyDrop,
    /// Deny by resetting a TCP flow where possible.
    DenyReset,
    /// Deny by synthesizing ICMP unreachable where useful.
    DenyIcmpUnreachable,
    /// Fail closed because the input or path is unsupported.
    FailClosed,
    /// Require the request to use the broker DNS resolver path.
    RequireBrokerDns,
}

/// Structured denial reason for auditability.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DenialReason {
    /// No policy rule allowed the event.
    DefaultDeny,
    /// A deny rule matched the event.
    RuleDenied(String),
    /// The event is unsupported and must fail closed.
    Unsupported(String),
    /// Direct DNS bypass is not allowed.
    DirectDnsBypass,
    /// Hostname attribution was missing or too weak.
    MissingRequiredAttribution,
    /// Multicast or broadcast is denied by default.
    MulticastOrBroadcast,
    /// TLS SNI and DNS attribution mismatch is denied by default.
    SniDnsMismatch,
    /// Hidden or missing SNI is denied without an explicit IP/CIDR allow rule.
    HiddenSni,
}

/// Policy decision plus the matching rule/reason.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Decision {
    /// Selected action.
    pub action: DecisionAction,
    /// Matching rule identifier, if any.
    pub rule_id: Option<String>,
    /// Denial reason for non-allow decisions.
    pub reason: Option<DenialReason>,
}

impl Decision {
    /// Creates an allow decision.
    pub fn allow(rule_id: impl Into<String>) -> Self {
        Self {
            action: DecisionAction::Allow,
            rule_id: Some(rule_id.into()),
            reason: None,
        }
    }

    /// Creates a default deny decision.
    pub const fn default_deny(action: DecisionAction) -> Self {
        Self {
            action,
            rule_id: None,
            reason: Some(DenialReason::DefaultDeny),
        }
    }

    /// Returns true when the event is allowed.
    pub const fn is_allowed(&self) -> bool {
        matches!(self.action, DecisionAction::Allow)
    }
}

/// Allow/deny effect for a rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RuleEffect {
    /// Allow matching events.
    Allow,
    /// Deny matching events.
    Deny,
}

/// Inclusive transport port range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PortRange {
    /// First allowed port.
    pub start: u16,
    /// Last allowed port.
    pub end: u16,
}

impl PortRange {
    /// Creates an inclusive port range if `start <= end`.
    pub const fn new(start: u16, end: u16) -> Option<Self> {
        if start <= end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Creates a single-port range.
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Returns true when `port` is within the inclusive range.
    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// IP network with prefix length.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Cidr {
    /// IPv4 network.
    V4 {
        /// Network address.
        network: Ipv4Addr,
        /// Prefix length, 0-32.
        prefix: u8,
    },
    /// IPv6 network.
    V6 {
        /// Network address.
        network: Ipv6Addr,
        /// Prefix length, 0-128.
        prefix: u8,
    },
}

impl Cidr {
    /// Creates an IPv4 CIDR if the prefix length is valid.
    pub const fn v4(network: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix <= 32 {
            Some(Self::V4 { network, prefix })
        } else {
            None
        }
    }

    /// Creates an IPv6 CIDR if the prefix length is valid.
    pub const fn v6(network: Ipv6Addr, prefix: u8) -> Option<Self> {
        if prefix <= 128 {
            Some(Self::V6 { network, prefix })
        } else {
            None
        }
    }

    /// Returns true when the address is inside this network.
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(ip)) => {
                let mask = prefix_mask_v4(prefix);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (Self::V6 { network, prefix }, IpAddr::V6(ip)) => {
                let mask = prefix_mask_v6(prefix);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

const fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// A deterministic policy rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    /// Stable rule identifier for audit output.
    pub id: String,
    /// Allow or deny effect.
    pub effect: RuleEffect,
    /// Optional protocol match.
    pub protocol: Option<Protocol>,
    /// Optional destination CIDR match.
    pub destination_cidr: Option<Cidr>,
    /// Optional destination port match.
    pub destination_ports: Option<PortRange>,
    /// Optional exact hostname match.
    pub hostname: Option<Hostname>,
    /// Optional domain suffix match.
    pub domain_suffix: Option<Hostname>,
    /// Optional origin scheme match, such as `http` or `https`.
    pub origin_scheme: Option<String>,
    /// Optional HTTP method allow-list match.
    pub http_methods: Vec<HttpMethod>,
    /// Optional HTTP request path/query prefix match.
    pub http_path_prefix: Option<String>,
    /// Minimum hostname attribution confidence required for hostname/domain rules.
    pub min_attribution: AttributionConfidence,
}

impl PolicyRule {
    /// Creates a rule with no match constraints.
    pub fn new(id: impl Into<String>, effect: RuleEffect) -> Self {
        Self {
            id: id.into(),
            effect,
            protocol: None,
            destination_cidr: None,
            destination_ports: None,
            hostname: None,
            domain_suffix: None,
            origin_scheme: None,
            http_methods: Vec::new(),
            http_path_prefix: None,
            min_attribution: AttributionConfidence::Low,
        }
    }

    /// Returns a copy matching a protocol.
    pub const fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Returns a copy matching a destination CIDR.
    pub const fn with_destination_cidr(mut self, cidr: Cidr) -> Self {
        self.destination_cidr = Some(cidr);
        self
    }

    /// Returns a copy matching a destination port or range.
    pub const fn with_destination_ports(mut self, ports: PortRange) -> Self {
        self.destination_ports = Some(ports);
        self
    }

    /// Returns a copy matching an exact hostname.
    pub fn with_hostname(mut self, hostname: Hostname) -> Self {
        self.hostname = Some(hostname);
        self.min_attribution = AttributionConfidence::Medium;
        self
    }

    /// Returns a copy matching a domain suffix.
    pub fn with_domain_suffix(mut self, domain_suffix: Hostname) -> Self {
        self.domain_suffix = Some(domain_suffix);
        self.min_attribution = AttributionConfidence::Medium;
        self
    }

    /// Returns a copy matching an origin scheme.
    pub fn with_origin_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.origin_scheme = Some(scheme.into().to_ascii_lowercase());
        self
    }

    /// Returns a copy matching an HTTP method.
    pub fn with_http_method(mut self, method: HttpMethod) -> Self {
        self.http_methods.push(method);
        self
    }

    /// Returns a copy matching a plaintext HTTP path/query prefix.
    pub fn with_http_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.http_path_prefix = Some(prefix.into());
        self
    }

    /// Returns a copy requiring a minimum attribution confidence.
    pub const fn with_min_attribution(mut self, confidence: AttributionConfidence) -> Self {
        self.min_attribution = confidence;
        self
    }

    fn matches(&self, event: &NetworkEvent) -> bool {
        if self
            .protocol
            .is_some_and(|protocol| protocol != event.protocol())
        {
            return false;
        }

        let destination = event_destination(event);
        if self.destination_cidr.is_some() {
            let Some(destination) = destination else {
                return false;
            };
            if self
                .destination_cidr
                .is_some_and(|cidr| !cidr.contains(destination.ip))
            {
                return false;
            }
        }
        if self.destination_ports.is_some() {
            let Some(port) = event_destination_port(event) else {
                return false;
            };
            if self
                .destination_ports
                .is_some_and(|ports| !ports.contains(port))
            {
                return false;
            }
        }

        if self.hostname.is_some() || self.domain_suffix.is_some() {
            let Some((hostname, confidence)) = event_hostname(event) else {
                return false;
            };
            if confidence < self.min_attribution {
                return false;
            }
            if self
                .hostname
                .as_ref()
                .is_some_and(|expected| hostname != expected)
            {
                return false;
            }
            if self
                .domain_suffix
                .as_ref()
                .is_some_and(|expected| !hostname.matches_domain_suffix(expected))
            {
                return false;
            }
        }

        if self.origin_scheme.is_some() {
            let Some(scheme) = event_origin_scheme(event) else {
                return false;
            };
            if self
                .origin_scheme
                .as_ref()
                .is_some_and(|expected| !scheme.eq_ignore_ascii_case(expected))
            {
                return false;
            }
        }

        if !self.http_methods.is_empty() {
            let Some(method) = event_http_method(event) else {
                return false;
            };
            if !self.http_methods.iter().any(|expected| expected == method) {
                return false;
            }
        }

        if self.http_path_prefix.is_some() {
            let Some(path) = event_http_path(event) else {
                return false;
            };
            if self
                .http_path_prefix
                .as_ref()
                .is_some_and(|prefix| !path.starts_with(prefix))
            {
                return false;
            }
        }

        true
    }
}

/// Ordered policy rule set and default behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRuleSet {
    /// Ordered rules. First match wins.
    pub rules: Vec<PolicyRule>,
    /// Default action when no rule matches.
    pub default_action: DecisionAction,
    /// Whether direct DNS to external resolvers is denied by default.
    pub deny_direct_dns: bool,
    /// Whether multicast/broadcast traffic is denied by default.
    pub deny_multicast_broadcast: bool,
    /// Additional directed broadcast addresses that should fail closed.
    pub broadcast_addresses: Vec<IpAddr>,
    /// Whether TLS SNI/DNS mismatch is denied before allow rules.
    pub deny_sni_dns_mismatch: bool,
    /// Whether hidden/missing SNI is denied unless an explicit IP/CIDR allow rule matches.
    pub deny_hidden_sni: bool,
}

impl Default for PolicyRuleSet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_action: DecisionAction::DenyDrop,
            deny_direct_dns: true,
            deny_multicast_broadcast: true,
            broadcast_addresses: vec![IpAddr::V4(Ipv4Addr::BROADCAST)],
            deny_sni_dns_mismatch: true,
            deny_hidden_sni: true,
        }
    }
}

/// Stateless deterministic policy evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEngine {
    rules: PolicyRuleSet,
}

impl PolicyEngine {
    /// Creates a policy engine from a rule set.
    pub const fn new(rules: PolicyRuleSet) -> Self {
        Self { rules }
    }

    /// Returns the configured rule set.
    pub const fn rules(&self) -> &PolicyRuleSet {
        &self.rules
    }

    /// Evaluates a normalized event.
    pub fn evaluate(&self, event: &NetworkEvent) -> Decision {
        if let Some(decision) = fail_closed_precheck(event, &self.rules) {
            return decision;
        }

        for rule in &self.rules.rules {
            if rule.matches(event) {
                return match rule.effect {
                    RuleEffect::Allow => Decision::allow(rule.id.clone()),
                    RuleEffect::Deny => Decision {
                        action: deny_action_for(event.protocol()),
                        rule_id: Some(rule.id.clone()),
                        reason: Some(DenialReason::RuleDenied(rule.id.clone())),
                    },
                };
            }
        }

        Decision::default_deny(self.rules.default_action)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyRuleSet::default())
    }
}

fn fail_closed_precheck(event: &NetworkEvent, rules: &PolicyRuleSet) -> Option<Decision> {
    match event {
        NetworkEvent::Unsupported { reason, .. } => Some(Decision {
            action: DecisionAction::FailClosed,
            rule_id: None,
            reason: Some(DenialReason::Unsupported(format!("{reason:?}"))),
        }),
        NetworkEvent::TcpConnectAttempt { destination, .. }
        | NetworkEvent::UdpFlowAttempt { destination, .. }
            if rules.deny_direct_dns && destination.port == 53 =>
        {
            // Broker DNS frontend emits DnsQuery. TCP/UDP port 53 reaching a host resolver
            // through TUN is treated as a bypass attempt until a later subsystem explicitly
            // marks it broker-owned.
            Some(Decision {
                action: DecisionAction::RequireBrokerDns,
                rule_id: None,
                reason: Some(DenialReason::DirectDnsBypass),
            })
        }
        NetworkEvent::TlsClientHello {
            sni,
            dns_hostname,
            mismatch,
            ..
        } if rules.deny_sni_dns_mismatch
            && tls_names_mismatch(sni.as_ref(), dns_hostname.as_ref(), *mismatch) =>
        {
            Some(Decision {
                action: DecisionAction::FailClosed,
                rule_id: None,
                reason: Some(DenialReason::SniDnsMismatch),
            })
        }
        NetworkEvent::TlsClientHello {
            sni,
            ech_present,
            destination,
            ..
        } if rules.deny_hidden_sni
            && (sni.is_none() || *ech_present)
            && !has_explicit_ip_allow(rules, *destination, Protocol::Tls) =>
        {
            Some(Decision {
                action: DecisionAction::FailClosed,
                rule_id: None,
                reason: Some(DenialReason::HiddenSni),
            })
        }
        NetworkEvent::TcpConnectAttempt { destination, .. }
        | NetworkEvent::UdpFlowAttempt { destination, .. }
            if rules.deny_multicast_broadcast
                && is_multicast_or_broadcast(destination.ip, rules) =>
        {
            Some(Decision {
                action: DecisionAction::FailClosed,
                rule_id: None,
                reason: Some(DenialReason::MulticastOrBroadcast),
            })
        }
        _ => None,
    }
}

fn deny_action_for(protocol: Protocol) -> DecisionAction {
    match protocol {
        Protocol::Tcp | Protocol::Http | Protocol::HttpsConnect | Protocol::Socks => {
            DecisionAction::DenyReset
        }
        Protocol::Icmp => DecisionAction::DenyDrop,
        Protocol::Unsupported => DecisionAction::FailClosed,
        _ => DecisionAction::DenyDrop,
    }
}

fn event_destination(event: &NetworkEvent) -> Option<TransportEndpoint> {
    match event {
        NetworkEvent::TcpConnectAttempt { destination, .. }
        | NetworkEvent::UdpFlowAttempt { destination, .. }
        | NetworkEvent::TlsClientHello { destination, .. } => Some(*destination),
        NetworkEvent::SocksConnect {
            target: SocksDestination::Ip(destination),
            ..
        } => Some(*destination),
        _ => None,
    }
}

fn event_destination_port(event: &NetworkEvent) -> Option<u16> {
    match event {
        NetworkEvent::TcpConnectAttempt { destination, .. }
        | NetworkEvent::UdpFlowAttempt { destination, .. }
        | NetworkEvent::TlsClientHello { destination, .. } => Some(destination.port),
        NetworkEvent::HttpRequest {
            origin: Origin { port, .. },
            ..
        }
        | NetworkEvent::HttpsConnect { port, .. } => Some(*port),
        NetworkEvent::SocksConnect { target, .. } => Some(target.port()),
        _ => None,
    }
}

fn event_hostname(event: &NetworkEvent) -> Option<(&Hostname, AttributionConfidence)> {
    match event {
        NetworkEvent::TcpConnectAttempt { attribution, .. }
        | NetworkEvent::UdpFlowAttempt { attribution, .. } => attribution
            .hostname
            .as_ref()
            .map(|hostname| (hostname, attribution.confidence)),
        NetworkEvent::DnsQuery { hostname, .. } => Some((hostname, AttributionConfidence::High)),
        NetworkEvent::HttpRequest { origin, .. } => {
            Some((&origin.host, AttributionConfidence::High))
        }
        NetworkEvent::HttpsConnect { host, .. } => Some((host, AttributionConfidence::High)),
        NetworkEvent::TlsClientHello { sni: Some(sni), .. } => {
            Some((sni, AttributionConfidence::High))
        }
        NetworkEvent::SocksConnect { target, .. } => target
            .host()
            .map(|host| (host, AttributionConfidence::High)),
        _ => None,
    }
}

fn event_origin_scheme(event: &NetworkEvent) -> Option<&str> {
    match event {
        NetworkEvent::HttpRequest { origin, .. } => Some(origin.scheme.as_str()),
        NetworkEvent::HttpsConnect { .. } => Some("https"),
        _ => None,
    }
}

fn event_http_method(event: &NetworkEvent) -> Option<&HttpMethod> {
    match event {
        NetworkEvent::HttpRequest { method, .. } => Some(method),
        _ => None,
    }
}

fn event_http_path(event: &NetworkEvent) -> Option<&str> {
    match event {
        NetworkEvent::HttpRequest { path_and_query, .. } => Some(path_and_query.as_str()),
        _ => None,
    }
}

fn tls_names_mismatch(
    sni: Option<&Hostname>,
    dns_hostname: Option<&Hostname>,
    caller_reported_mismatch: bool,
) -> bool {
    caller_reported_mismatch || matches!((sni, dns_hostname), (Some(sni), Some(dns)) if sni != dns)
}

fn has_explicit_ip_allow(
    rules: &PolicyRuleSet,
    destination: TransportEndpoint,
    protocol: Protocol,
) -> bool {
    rules.rules.iter().any(|rule| {
        rule.effect == RuleEffect::Allow
            && rule.hostname.is_none()
            && rule.domain_suffix.is_none()
            && rule.origin_scheme.is_none()
            && rule.http_methods.is_empty()
            && rule.http_path_prefix.is_none()
            && rule
                .protocol
                .map_or(true, |rule_protocol| rule_protocol == protocol)
            && rule
                .destination_cidr
                .is_some_and(|cidr| cidr.contains(destination.ip))
            && rule
                .destination_ports
                .map_or(true, |ports| ports.contains(destination.port))
    })
}

fn is_multicast_or_broadcast(ip: IpAddr, rules: &PolicyRuleSet) -> bool {
    if rules.broadcast_addresses.contains(&ip) {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => ip.is_multicast() || ip == Ipv4Addr::BROADCAST,
        IpAddr::V6(ip) => ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Attribution, Frontend, HttpMethod, Origin, SandboxId, SocksDestination};

    fn sandbox_id() -> SandboxId {
        SandboxId::new("alpha").unwrap()
    }

    #[test]
    fn cidr_matches_ipv4_prefix() {
        let cidr = Cidr::v4(Ipv4Addr::new(192, 0, 2, 0), 24).unwrap();
        assert!(cidr.contains(IpAddr::from([192, 0, 2, 55])));
        assert!(!cidr.contains(IpAddr::from([192, 0, 3, 1])));
    }

    #[test]
    fn default_policy_denies() {
        let event = NetworkEvent::TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: None,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 80),
            attribution: Attribution::ip_only(),
        };
        let decision = PolicyEngine::default().evaluate(&event);
        assert_eq!(decision.action, DecisionAction::DenyDrop);
        assert_eq!(decision.reason, Some(DenialReason::DefaultDeny));
    }

    #[test]
    fn allow_rule_matches_ip_port_protocol() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-example-http", RuleEffect::Allow)
                .with_protocol(Protocol::Tcp)
                .with_destination_cidr(Cidr::v4(Ipv4Addr::new(93, 184, 216, 0), 24).unwrap())
                .with_destination_ports(PortRange::single(80))],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: None,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 80),
            attribution: Attribution::ip_only(),
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert!(decision.is_allowed());
        assert_eq!(decision.rule_id.as_deref(), Some("allow-example-http"));
    }

    #[test]
    fn http_origin_port_rule_matches_without_ip_endpoint() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-http-origin", RuleEffect::Allow)
                .with_protocol(Protocol::Http)
                .with_origin_scheme("http")
                .with_domain_suffix(Hostname::parse("example.com").unwrap())
                .with_destination_ports(PortRange::single(8080))],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::HttpRequest {
            sandbox_id: sandbox_id(),
            frontend: Frontend::HttpProxy,
            method: HttpMethod::parse("GET").unwrap(),
            origin: Origin {
                scheme: "http".to_string(),
                host: Hostname::parse("www.example.com").unwrap(),
                port: 8080,
            },
            path_and_query: "/".to_string(),
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert!(decision.is_allowed());
    }

    #[test]
    fn http_method_and_path_prefix_rules_match_plaintext_requests() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-public-get", RuleEffect::Allow)
                .with_protocol(Protocol::Http)
                .with_hostname(Hostname::parse("api.example.com").unwrap())
                .with_http_method(HttpMethod::parse("GET").unwrap())
                .with_http_path_prefix("/public/")],
            ..PolicyRuleSet::default()
        };
        let engine = PolicyEngine::new(rules);
        let allowed = NetworkEvent::HttpRequest {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            method: HttpMethod::parse("GET").unwrap(),
            origin: Origin {
                scheme: "http".to_string(),
                host: Hostname::parse("api.example.com").unwrap(),
                port: 80,
            },
            path_and_query: "/public/items?limit=1".to_string(),
        };
        assert!(engine.evaluate(&allowed).is_allowed());

        let wrong_method = NetworkEvent::HttpRequest {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            method: HttpMethod::parse("POST").unwrap(),
            origin: Origin {
                scheme: "http".to_string(),
                host: Hostname::parse("api.example.com").unwrap(),
                port: 80,
            },
            path_and_query: "/public/items?limit=1".to_string(),
        };
        assert_eq!(
            engine.evaluate(&wrong_method).reason,
            Some(DenialReason::DefaultDeny)
        );

        let wrong_path = NetworkEvent::HttpRequest {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            method: HttpMethod::parse("GET").unwrap(),
            origin: Origin {
                scheme: "http".to_string(),
                host: Hostname::parse("api.example.com").unwrap(),
                port: 80,
            },
            path_and_query: "/private/items".to_string(),
        };
        assert_eq!(
            engine.evaluate(&wrong_path).reason,
            Some(DenialReason::DefaultDeny)
        );
    }

    #[test]
    fn socks_host_destination_port_rule_matches() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-socks-host", RuleEffect::Allow)
                .with_protocol(Protocol::Socks)
                .with_hostname(Hostname::parse("example.com").unwrap())
                .with_destination_ports(PortRange::single(443))],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::SocksConnect {
            sandbox_id: sandbox_id(),
            target: SocksDestination::Host {
                host: Hostname::parse("example.com").unwrap(),
                port: 443,
            },
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert!(decision.is_allowed());
    }

    #[test]
    fn domain_rule_requires_attribution() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-example", RuleEffect::Allow)
                .with_protocol(Protocol::Tcp)
                .with_domain_suffix(Hostname::parse("example.com").unwrap())],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::TcpConnectAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: None,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            attribution: Attribution::ip_only(),
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn unsupported_event_fails_closed() {
        let event = NetworkEvent::Unsupported {
            sandbox_id: Some(sandbox_id()),
            frontend: Frontend::Tun,
            reason: crate::event::UnsupportedReason::UnsupportedFragmentation,
        };
        let decision = PolicyEngine::default().evaluate(&event);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert!(matches!(
            decision.reason,
            Some(DenialReason::Unsupported(_))
        ));
    }

    #[test]
    fn invalid_port_range_is_rejected() {
        assert!(PortRange::new(20, 10).is_none());
    }

    #[test]
    fn direct_dns_bypass_requires_broker_dns() {
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::from([10, 0, 0, 2]), 40_000),
            destination: TransportEndpoint::new(IpAddr::from([8, 8, 8, 8]), 53),
            attribution: Attribution::ip_only(),
            classification: Protocol::Dns,
        };
        let decision = PolicyEngine::default().evaluate(&event);
        assert_eq!(decision.action, DecisionAction::RequireBrokerDns);
        assert_eq!(decision.reason, Some(DenialReason::DirectDnsBypass));
    }

    #[test]
    fn broad_allow_cannot_override_generic_udp_port_53_bypass() {
        let rules = PolicyRuleSet {
            rules: vec![
                PolicyRule::new("allow-all-udp", RuleEffect::Allow).with_protocol(Protocol::Udp)
            ],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::from([10, 0, 0, 2]), 40_000),
            destination: TransportEndpoint::new(IpAddr::from([8, 8, 8, 8]), 53),
            attribution: Attribution::ip_only(),
            classification: Protocol::Udp,
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert_eq!(decision.action, DecisionAction::RequireBrokerDns);
    }

    #[test]
    fn configured_directed_broadcast_fails_closed_before_broad_allow() {
        let mut rules = PolicyRuleSet {
            rules: vec![
                PolicyRule::new("allow-all-udp", RuleEffect::Allow).with_protocol(Protocol::Udp)
            ],
            ..PolicyRuleSet::default()
        };
        rules
            .broadcast_addresses
            .push(IpAddr::from([10, 255, 0, 255]));
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::from([10, 255, 0, 2]), 40_000),
            destination: TransportEndpoint::new(IpAddr::from([10, 255, 0, 255]), 123),
            attribution: Attribution::ip_only(),
            classification: Protocol::Udp,
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, Some(DenialReason::MulticastOrBroadcast));
    }

    #[test]
    fn tls_mismatch_fails_closed() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            sni: Some(Hostname::parse("evil.example").unwrap()),
            ech_present: false,
            dns_hostname: Some(Hostname::parse("example.com").unwrap()),
            mismatch: true,
        };
        let decision = PolicyEngine::default().evaluate(&event);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, Some(DenialReason::SniDnsMismatch));
    }

    #[test]
    fn tls_mismatch_is_derived_even_if_caller_flag_is_false() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            sni: Some(Hostname::parse("evil.example").unwrap()),
            ech_present: false,
            dns_hostname: Some(Hostname::parse("example.com").unwrap()),
            mismatch: false,
        };
        let decision = PolicyEngine::default().evaluate(&event);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, Some(DenialReason::SniDnsMismatch));
    }

    #[test]
    fn hidden_sni_requires_explicit_ip_allow() {
        let destination = TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443);
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            destination,
            sni: None,
            ech_present: false,
            dns_hostname: Some(Hostname::parse("example.com").unwrap()),
            mismatch: false,
        };
        assert_eq!(
            PolicyEngine::default().evaluate(&event).reason,
            Some(DenialReason::HiddenSni)
        );

        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-explicit-ip", RuleEffect::Allow)
                .with_protocol(Protocol::Tls)
                .with_destination_cidr(Cidr::v4(Ipv4Addr::new(93, 184, 216, 0), 24).unwrap())
                .with_destination_ports(PortRange::single(443))],
            ..PolicyRuleSet::default()
        };
        assert!(PolicyEngine::new(rules).evaluate(&event).is_allowed());
    }

    #[test]
    fn ech_presence_is_hidden_sni_even_when_sni_is_visible() {
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            sni: Some(Hostname::parse("example.com").unwrap()),
            ech_present: true,
            dns_hostname: Some(Hostname::parse("example.com").unwrap()),
            mismatch: false,
        };
        let decision = PolicyEngine::default().evaluate(&event);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, Some(DenialReason::HiddenSni));

        let explicit_ip_allow = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-ech-ip", RuleEffect::Allow)
                .with_protocol(Protocol::Tls)
                .with_destination_cidr(Cidr::v4(Ipv4Addr::new(93, 184, 216, 0), 24).unwrap())
                .with_destination_ports(PortRange::single(443))],
            ..PolicyRuleSet::default()
        };
        assert!(PolicyEngine::new(explicit_ip_allow)
            .evaluate(&event)
            .is_allowed());
    }

    #[test]
    fn http_constrained_ip_allow_does_not_bypass_hidden_sni() {
        let rules = PolicyRuleSet {
            rules: vec![
                PolicyRule::new("allow-ip-but-only-http-origin", RuleEffect::Allow)
                    .with_protocol(Protocol::Tls)
                    .with_destination_cidr(Cidr::v4(Ipv4Addr::new(93, 184, 216, 0), 24).unwrap())
                    .with_destination_ports(PortRange::single(443))
                    .with_origin_scheme("https"),
            ],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            sni: None,
            ech_present: false,
            dns_hostname: None,
            mismatch: false,
        };
        let decision = PolicyEngine::new(rules).evaluate(&event);
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, Some(DenialReason::HiddenSni));
    }

    #[test]
    fn tls_sni_domain_rule_allows_visible_matching_sni() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-visible-sni", RuleEffect::Allow)
                .with_protocol(Protocol::Tls)
                .with_domain_suffix(Hostname::parse("example.com").unwrap())
                .with_destination_ports(PortRange::single(443))],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::TlsClientHello {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            sni: Some(Hostname::parse("www.example.com").unwrap()),
            ech_present: false,
            dns_hostname: Some(Hostname::parse("www.example.com").unwrap()),
            mismatch: false,
        };
        assert!(PolicyEngine::new(rules).evaluate(&event).is_allowed());
    }

    #[test]
    fn quic_domain_rule_uses_dns_attribution_and_protocol_class() {
        let rules = PolicyRuleSet {
            rules: vec![PolicyRule::new("allow-quic-example", RuleEffect::Allow)
                .with_protocol(Protocol::Quic)
                .with_domain_suffix(Hostname::parse("example.com").unwrap())
                .with_destination_ports(PortRange::single(443))],
            ..PolicyRuleSet::default()
        };
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: sandbox_id(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::from([10, 255, 0, 2]), 44_444),
            destination: TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 443),
            attribution: Attribution {
                hostname: Some(Hostname::parse("video.example.com").unwrap()),
                source: crate::event::AttributionSource::DnsCache,
                confidence: AttributionConfidence::Medium,
            },
            classification: Protocol::Quic,
        };
        assert!(PolicyEngine::new(rules).evaluate(&event).is_allowed());
    }
}
