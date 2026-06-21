//! User-facing configuration loading for foxprox policy.
//!
//! This crate converts serde-compatible configuration into `foxprox-core`
//! policy types. Runtime/frontends should consume validated core config rather
//! than raw config strings.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use foxprox_core::{
    AttributionConfidence, DefaultPolicy, DenialBehavior, DenyReason, DnsPolicy, Endpoint, IpCidr,
    PolicyConfig, PolicyRule, PortRange, Protocol, RuleAction,
};
use serde::Deserialize;

/// Configuration load/validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Toml(String),
    InvalidDefaultPolicy(String),
    InvalidAction(String),
    InvalidDenialBehavior(String),
    InvalidProtocol(String),
    InvalidConfidence(String),
    InvalidEndpoint(String),
    InvalidCidr(String),
    InvalidCore(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(error) => write!(f, "config-toml-error: {error}"),
            Self::InvalidDefaultPolicy(value) => write!(f, "invalid-default-policy: {value}"),
            Self::InvalidAction(value) => write!(f, "invalid-rule-action: {value}"),
            Self::InvalidDenialBehavior(value) => write!(f, "invalid-denial-behavior: {value}"),
            Self::InvalidProtocol(value) => write!(f, "invalid-protocol: {value}"),
            Self::InvalidConfidence(value) => write!(f, "invalid-confidence: {value}"),
            Self::InvalidEndpoint(value) => write!(f, "invalid-endpoint: {value}"),
            Self::InvalidCidr(value) => write!(f, "invalid-cidr: {value}"),
            Self::InvalidCore(value) => write!(f, "invalid-core-policy: {value}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse TOML policy configuration into validated core policy config.
pub fn policy_config_from_toml(input: &str) -> Result<PolicyConfig, ConfigError> {
    let raw: RawPolicyConfig =
        toml::from_str(input).map_err(|error| ConfigError::Toml(error.to_string()))?;
    raw.try_into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyConfig {
    #[serde(default)]
    default_policy: Option<String>,
    #[serde(default)]
    default_deny_behavior: Option<String>,
    #[serde(default)]
    dns: RawDnsPolicy,
    #[serde(default)]
    rules: Vec<RawPolicyRule>,
}

impl TryFrom<RawPolicyConfig> for PolicyConfig {
    type Error = ConfigError;

    fn try_from(value: RawPolicyConfig) -> Result<Self, Self::Error> {
        let default_policy = parse_default_policy(
            value.default_policy.as_deref().unwrap_or("deny"),
            value.default_deny_behavior.as_deref().unwrap_or("drop"),
        )?;
        let dns = DnsPolicy {
            broker_resolvers: value
                .dns
                .broker_resolvers
                .iter()
                .map(|resolver| parse_endpoint(resolver))
                .collect::<Result<Vec<_>, _>>()?,
            deny_direct_external_dns: value.dns.deny_direct_external_dns.unwrap_or(true),
        };
        let rules = value
            .rules
            .into_iter()
            .map(PolicyRule::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            default_policy,
            dns,
            rules,
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsPolicy {
    #[serde(default)]
    broker_resolvers: Vec<String>,
    #[serde(default)]
    deny_direct_external_dns: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyRule {
    id: String,
    action: String,
    #[serde(default)]
    deny_behavior: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    destination_cidrs: Vec<String>,
    #[serde(default)]
    destination_ports: Vec<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    minimum_hostname_confidence: Option<String>,
    #[serde(default)]
    http_methods: Vec<String>,
    #[serde(default)]
    http_path_prefixes: Vec<String>,
}

impl TryFrom<RawPolicyRule> for PolicyRule {
    type Error = ConfigError;

    fn try_from(value: RawPolicyRule) -> Result<Self, Self::Error> {
        let action = parse_rule_action(&value.action, value.deny_behavior.as_deref())?;
        let mut rule = PolicyRule::new(value.id, action)
            .map_err(|error| ConfigError::InvalidCore(error.to_string()))?;

        if let Some(protocol) = value.protocol {
            rule = rule.with_protocol(parse_protocol(&protocol)?);
        }
        for cidr in value.destination_cidrs {
            rule = rule.with_destination_cidr(parse_cidr(&cidr)?);
        }
        for port in value.destination_ports {
            rule.destination_ports.push(
                PortRange::new(port, port)
                    .map_err(|error| ConfigError::InvalidCore(error.to_string()))?,
            );
        }
        for hostname in value.hostnames {
            rule = rule.with_hostname(
                foxprox_core::HostnamePattern::new(hostname)
                    .map_err(|error| ConfigError::InvalidCore(error.to_string()))?,
            );
        }
        if let Some(confidence) = value.minimum_hostname_confidence {
            rule = rule.with_minimum_hostname_confidence(parse_confidence(&confidence)?);
        }
        for method in value.http_methods {
            rule = rule.with_http_method(method);
        }
        for prefix in value.http_path_prefixes {
            rule = rule.with_http_path_prefix(prefix);
        }

        Ok(rule)
    }
}

fn parse_default_policy(value: &str, deny_behavior: &str) -> Result<DefaultPolicy, ConfigError> {
    match value {
        "allow" => Ok(DefaultPolicy::Allow),
        "deny" => Ok(DefaultPolicy::Deny(DenyReason {
            behavior: parse_denial_behavior(deny_behavior)?,
            message: "default-deny".to_owned(),
        })),
        other => Err(ConfigError::InvalidDefaultPolicy(other.to_owned())),
    }
}

fn parse_rule_action(value: &str, deny_behavior: Option<&str>) -> Result<RuleAction, ConfigError> {
    match value {
        "allow" => Ok(RuleAction::Allow),
        "deny" => Ok(RuleAction::Deny(DenyReason {
            behavior: parse_denial_behavior(deny_behavior.unwrap_or("drop"))?,
            message: "rule-deny".to_owned(),
        })),
        other => Err(ConfigError::InvalidAction(other.to_owned())),
    }
}

fn parse_denial_behavior(value: &str) -> Result<DenialBehavior, ConfigError> {
    match value {
        "drop" => Ok(DenialBehavior::Drop),
        "reset" => Ok(DenialBehavior::Reset),
        "icmp_unreachable" => Ok(DenialBehavior::IcmpUnreachable),
        other => Err(ConfigError::InvalidDenialBehavior(other.to_owned())),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol, ConfigError> {
    match value {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "dns" => Ok(Protocol::Dns),
        "icmp" => Ok(Protocol::Icmp),
        "http" => Ok(Protocol::Http),
        "https_connect" => Ok(Protocol::HttpsConnect),
        "tls_client_hello" => Ok(Protocol::TlsClientHello),
        "socks" => Ok(Protocol::Socks),
        "quic_candidate" => Ok(Protocol::QuicCandidate),
        "unsupported" => Ok(Protocol::Unsupported),
        other => Err(ConfigError::InvalidProtocol(other.to_owned())),
    }
}

fn parse_confidence(value: &str) -> Result<AttributionConfidence, ConfigError> {
    match value {
        "low" => Ok(AttributionConfidence::Low),
        "medium" => Ok(AttributionConfidence::Medium),
        "high" => Ok(AttributionConfidence::High),
        other => Err(ConfigError::InvalidConfidence(other.to_owned())),
    }
}

fn parse_endpoint(value: &str) -> Result<Endpoint, ConfigError> {
    let socket =
        SocketAddr::from_str(value).map_err(|_| ConfigError::InvalidEndpoint(value.to_owned()))?;
    Ok(Endpoint::new(socket.ip(), Some(socket.port())))
}

fn parse_cidr(value: &str) -> Result<IpCidr, ConfigError> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let addr =
            IpAddr::from_str(addr).map_err(|_| ConfigError::InvalidCidr(value.to_owned()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| ConfigError::InvalidCidr(value.to_owned()))?;
        IpCidr::new(addr, prefix).map_err(|error| ConfigError::InvalidCore(error.to_string()))
    } else {
        let addr =
            IpAddr::from_str(value).map_err(|_| ConfigError::InvalidCidr(value.to_owned()))?;
        Ok(IpCidr::single(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_broker::Ipv4PacketBroker;
    use foxprox_core::{
        AuditDecision, Endpoint, FrontendKind, HttpRequest, NormalizedEvent, PolicyDecision,
        PolicyEngine, Protocol, SandboxId,
    };
    use foxprox_packet::PacketContext;

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("config-test").unwrap(), FrontendKind::Tun)
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

    fn udp_payload_with_body(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
        let udp_length = 8 + body.len();
        let mut payload = vec![0_u8; udp_length];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
        payload[8..].copy_from_slice(body);
        payload
    }

    fn dns_query_body(hostname: &str) -> Vec<u8> {
        let mut body = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in hostname.split('.') {
            body.push(label.len() as u8);
            body.extend_from_slice(label.as_bytes());
        }
        body.push(0);
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&1_u16.to_be_bytes());
        body
    }

    #[test]
    fn loaded_icmp_rule_allows_broker_echo_reply() {
        let config = policy_config_from_toml(
            r#"
            default_policy = "deny"

            [[rules]]
            id = "allow-icmp"
            action = "allow"
            protocol = "icmp"
            "#,
        )
        .unwrap();
        let broker = Ipv4PacketBroker::new(PolicyEngine::new(config));
        let packet = ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            b"\x08\x00\x00\x00\x12\x34\x00\x01payload",
        );

        let result = broker.process_packet(&context(), &packet);

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-icmp".to_owned())
            }
        );
        assert_eq!(result.evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(result.outbound_packets.len(), 1);
    }

    #[test]
    fn loaded_dns_resolver_preserves_direct_dns_bypass_denial() {
        let config = policy_config_from_toml(
            r#"
            default_policy = "allow"

            [dns]
            broker_resolvers = ["10.0.0.1:53"]
            deny_direct_external_dns = true
            "#,
        )
        .unwrap();
        let broker = Ipv4PacketBroker::new(PolicyEngine::new(config));
        let udp_dns_payload = udp_payload_with_body(50000, 53, &dns_query_body("example.com"));
        let packet = ipv4_packet(17, [10, 0, 0, 2], [8, 8, 8, 8], &udp_dns_payload);

        let result = broker.process_packet(&context(), &packet);

        assert_eq!(result.evaluation.audit.protocol, Protocol::Dns);
        assert_eq!(result.evaluation.audit.decision, AuditDecision::Denied);
        assert!(result.outbound_packets.is_empty());
    }

    #[test]
    fn loaded_http_method_and_path_rule_controls_http_request() {
        let config = policy_config_from_toml(
            r#"
            default_policy = "deny"

            [[rules]]
            id = "allow-public-get"
            action = "allow"
            protocol = "http"
            hostnames = ["example.com"]
            destination_ports = [80]
            http_methods = ["GET"]
            http_path_prefixes = ["/public"]
            "#,
        )
        .unwrap();
        let event = NormalizedEvent::HttpRequest(HttpRequest {
            sandbox_id: SandboxId::new("config-http-test").unwrap(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: Some(Endpoint::tcp("93.184.216.34".parse().unwrap(), 80)),
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.com".to_owned(),
            port: 80,
            path_query: "/public/index.html".to_owned(),
        });

        let evaluation = PolicyEngine::new(config).evaluate(&event);

        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-public-get".to_owned())
            }
        );
        assert_eq!(evaluation.audit.http_method.as_deref(), Some("GET"));
        assert_eq!(
            evaluation.audit.http_path_query.as_deref(),
            Some("/public/index.html")
        );
    }

    #[test]
    fn invalid_protocol_is_rejected() {
        let error = policy_config_from_toml(
            r#"
            [[rules]]
            id = "bad"
            action = "allow"
            protocol = "ftp"
            "#,
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::InvalidProtocol("ftp".to_owned()));
    }
}
