//! Typed alpha configuration validation for foxprox.
//!
//! This crate owns user-facing config shapes and converts them into
//! `foxprox-core` runtime contracts. Policy code receives only validated,
//! normalized `RuntimeConfig` values and never parses raw config strings.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use foxprox_core::{
    DefaultPolicy, DenialAction, DestinationMatcher, DirectDnsPolicy, DomainSuffix,
    HostnameConfidence, HttpMethod, HttpMethodMatcher, HttpPathMatcher, HttpScheme,
    HttpSchemeMatcher, IpCidr, ParserLimits, PolicyRule, PortMatcher, Protocol, ProtocolMatcher,
    QuicPolicy, ResourceLimits, RuleId, RuntimeConfig, UdpTimeouts,
};

/// User-facing alpha policy config document.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigDocument {
    pub default_policy: Option<DefaultPolicyConfig>,
    pub direct_dns_policy: Option<DirectDnsPolicyConfig>,
    pub allow_ping: Option<bool>,
    pub quic_policy: Option<QuicPolicyConfig>,
    pub broker_dns_addrs: Vec<IpAddr>,
    pub udp_timeouts: Option<UdpTimeoutsConfig>,
    pub resource_limits: Option<ResourceLimitsConfig>,
    pub parser_limits: Option<ParserLimitsConfig>,
    pub rules: Vec<RuleConfig>,
}

impl ConfigDocument {
    /// Validate and normalize this document into the runtime config consumed by
    /// the policy engine.
    pub fn validate(self) -> Result<RuntimeConfig, ConfigError> {
        let mut runtime = RuntimeConfig::deny_by_default();
        if let Some(default_policy) = self.default_policy {
            runtime.default_policy = match default_policy {
                DefaultPolicyConfig::Allow => DefaultPolicy::Allow,
                DefaultPolicyConfig::Deny => DefaultPolicy::Deny,
            };
        }
        if let Some(direct_dns_policy) = self.direct_dns_policy {
            runtime.direct_dns_policy = match direct_dns_policy {
                DirectDnsPolicyConfig::DenyExternal => DirectDnsPolicy::DenyExternal,
                DirectDnsPolicyConfig::AllowExternal => DirectDnsPolicy::AllowExternal,
            };
        }
        if let Some(allow_ping) = self.allow_ping {
            runtime.allow_ping = allow_ping;
        }
        if let Some(quic_policy) = self.quic_policy {
            runtime.quic_policy = match quic_policy {
                QuicPolicyConfig::DenyByDefault => QuicPolicy::DenyByDefault,
                QuicPolicyConfig::AllowCandidates => QuicPolicy::AllowCandidates,
            };
        }
        runtime.broker_dns_addrs = self.broker_dns_addrs;
        if let Some(timeouts) = self.udp_timeouts {
            runtime.udp_timeouts = timeouts.validate()?;
        }
        if let Some(resource_limits) = self.resource_limits {
            runtime.resource_limits = resource_limits.validate()?;
        }
        if let Some(parser_limits) = self.parser_limits {
            runtime.parser_limits = parser_limits.validate()?;
        }
        runtime.rules = self
            .rules
            .into_iter()
            .map(RuleConfig::validate)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(runtime)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DefaultPolicyConfig {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DirectDnsPolicyConfig {
    DenyExternal,
    AllowExternal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum QuicPolicyConfig {
    DenyByDefault,
    AllowCandidates,
}

/// User-facing UDP timeout configuration in whole seconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTimeoutsConfig {
    pub dns_seconds: u64,
    pub generic_seconds: u64,
    pub quic_seconds: u64,
    pub ntp_like_seconds: u64,
}

impl Default for UdpTimeoutsConfig {
    fn default() -> Self {
        let defaults = UdpTimeouts::default();
        Self {
            dns_seconds: defaults.dns.as_secs(),
            generic_seconds: defaults.generic.as_secs(),
            quic_seconds: defaults.quic.as_secs(),
            ntp_like_seconds: defaults.ntp_like.as_secs(),
        }
    }
}

impl UdpTimeoutsConfig {
    fn validate(self) -> Result<UdpTimeouts, ConfigError> {
        Ok(UdpTimeouts {
            dns: nonzero_duration(self.dns_seconds, "udp_timeouts.dns_seconds")?,
            generic: nonzero_duration(self.generic_seconds, "udp_timeouts.generic_seconds")?,
            quic: nonzero_duration(self.quic_seconds, "udp_timeouts.quic_seconds")?,
            ntp_like: nonzero_duration(self.ntp_like_seconds, "udp_timeouts.ntp_like_seconds")?,
        })
    }
}

fn nonzero_duration(seconds: u64, field: &'static str) -> Result<Duration, ConfigError> {
    if seconds == 0 {
        return Err(ConfigError::InvalidTimeout { field });
    }
    Ok(Duration::from_secs(seconds))
}

/// User-facing resource limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLimitsConfig {
    pub max_flows: usize,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        let defaults = ResourceLimits::default();
        Self {
            max_flows: defaults.max_flows,
        }
    }
}

impl ResourceLimitsConfig {
    fn validate(self) -> Result<ResourceLimits, ConfigError> {
        if self.max_flows == 0 {
            return Err(ConfigError::InvalidResourceLimit {
                field: "resource_limits.max_flows",
            });
        }
        Ok(ResourceLimits {
            max_flows: self.max_flows,
        })
    }
}

/// User-facing parser limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserLimitsConfig {
    pub max_http_request_head_bytes: usize,
    pub max_socks5_message_bytes: usize,
}

impl Default for ParserLimitsConfig {
    fn default() -> Self {
        let defaults = ParserLimits::default();
        Self {
            max_http_request_head_bytes: defaults.max_http_request_head_bytes,
            max_socks5_message_bytes: defaults.max_socks5_message_bytes,
        }
    }
}

impl ParserLimitsConfig {
    fn validate(self) -> Result<ParserLimits, ConfigError> {
        if self.max_http_request_head_bytes == 0 {
            return Err(ConfigError::InvalidParserLimit {
                field: "parser_limits.max_http_request_head_bytes",
            });
        }
        if self.max_socks5_message_bytes == 0 {
            return Err(ConfigError::InvalidParserLimit {
                field: "parser_limits.max_socks5_message_bytes",
            });
        }
        Ok(ParserLimits {
            max_http_request_head_bytes: self.max_http_request_head_bytes,
            max_socks5_message_bytes: self.max_socks5_message_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleConfig {
    pub id: String,
    pub action: RuleActionConfig,
    pub protocol: Option<ProtocolConfig>,
    pub destination: Option<DestinationConfig>,
    pub port: Option<PortConfig>,
    pub http_scheme: Option<HttpSchemeConfig>,
    pub http_method: Option<HttpMethodConfig>,
    pub http_path: Option<HttpPathConfig>,
    pub minimum_hostname_confidence: Option<HostnameConfidence>,
    pub timeout_override_seconds: Option<u64>,
}

impl RuleConfig {
    fn validate(self) -> Result<PolicyRule, ConfigError> {
        let id = RuleId::new(self.id).map_err(ConfigError::Contract)?;
        let mut rule = match self.action {
            RuleActionConfig::Allow => PolicyRule::allow(id),
            RuleActionConfig::Deny { action } => PolicyRule::deny(id, action),
        };
        if let Some(protocol) = self.protocol {
            rule.protocol = protocol.validate();
        }
        if let Some(destination) = self.destination {
            rule.destination = destination.validate()?;
        }
        if let Some(port) = self.port {
            rule.port = port.validate()?;
        }
        if let Some(scheme) = self.http_scheme {
            rule.http_scheme = scheme.validate();
        }
        if let Some(method) = self.http_method {
            rule.http_method = method.validate();
        }
        if let Some(path) = self.http_path {
            rule.http_path = path.validate()?;
        }
        if let Some(confidence) = self.minimum_hostname_confidence {
            rule.minimum_hostname_confidence = confidence;
        }
        if let Some(seconds) = self.timeout_override_seconds {
            rule.timeout_override =
                Some(nonzero_duration(seconds, "rules.timeout_override_seconds")?);
        }
        Ok(rule)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RuleActionConfig {
    Allow,
    Deny { action: DenialAction },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProtocolConfig {
    Any,
    Tcp,
    Udp,
    Dns,
    Icmp,
    Http,
    HttpsConnect,
    TlsClientHello,
    SocksConnect,
    QuicCandidate,
}

impl ProtocolConfig {
    fn validate(self) -> ProtocolMatcher {
        match self {
            Self::Any => ProtocolMatcher::Any,
            Self::Tcp => ProtocolMatcher::Exact(Protocol::Tcp),
            Self::Udp => ProtocolMatcher::Exact(Protocol::Udp),
            Self::Dns => ProtocolMatcher::Exact(Protocol::Dns),
            Self::Icmp => ProtocolMatcher::Exact(Protocol::Icmp),
            Self::Http => ProtocolMatcher::Exact(Protocol::Http),
            Self::HttpsConnect => ProtocolMatcher::Exact(Protocol::HttpsConnect),
            Self::TlsClientHello => ProtocolMatcher::Exact(Protocol::TlsClientHello),
            Self::SocksConnect => ProtocolMatcher::Exact(Protocol::SocksConnect),
            Self::QuicCandidate => ProtocolMatcher::Exact(Protocol::QuicCandidate),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationConfig {
    Any,
    Ip(IpAddr),
    Cidr(String),
    Hostname(String),
    DomainSuffix(String),
}

impl DestinationConfig {
    fn validate(self) -> Result<DestinationMatcher, ConfigError> {
        match self {
            Self::Any => Ok(DestinationMatcher::Any),
            Self::Ip(ip) => Ok(DestinationMatcher::Ip(ip)),
            Self::Cidr(cidr) => cidr
                .parse::<IpCidr>()
                .map(DestinationMatcher::Cidr)
                .map_err(ConfigError::Contract),
            Self::Hostname(hostname) => foxprox_core::Hostname::new(hostname)
                .map(DestinationMatcher::Hostname)
                .map_err(ConfigError::Contract),
            Self::DomainSuffix(suffix) => DomainSuffix::new(suffix)
                .map(DestinationMatcher::DomainSuffix)
                .map_err(ConfigError::Contract),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PortConfig {
    Any,
    Exact(u16),
    Range { start: u16, end: u16 },
}

impl PortConfig {
    fn validate(self) -> Result<PortMatcher, ConfigError> {
        match self {
            Self::Any => Ok(PortMatcher::Any),
            Self::Exact(port) => Ok(PortMatcher::Exact(port)),
            Self::Range { start, end } if start <= end => Ok(PortMatcher::Range { start, end }),
            Self::Range { start, end } => Err(ConfigError::InvalidPortRange { start, end }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HttpSchemeConfig {
    Any,
    Http,
    Https,
}

impl HttpSchemeConfig {
    fn validate(self) -> HttpSchemeMatcher {
        match self {
            Self::Any => HttpSchemeMatcher::Any,
            Self::Http => HttpSchemeMatcher::Exact(HttpScheme::Http),
            Self::Https => HttpSchemeMatcher::Exact(HttpScheme::Https),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HttpMethodConfig {
    Any,
    Exact(String),
}

impl HttpMethodConfig {
    fn validate(self) -> HttpMethodMatcher {
        match self {
            Self::Any => HttpMethodMatcher::Any,
            Self::Exact(method) => HttpMethodMatcher::Exact(HttpMethod::parse(&method)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HttpPathConfig {
    Any,
    Exact(String),
    Prefix(String),
}

impl HttpPathConfig {
    fn validate(self) -> Result<HttpPathMatcher, ConfigError> {
        match self {
            Self::Any => Ok(HttpPathMatcher::Any),
            Self::Exact(path) if path.starts_with('/') => Ok(HttpPathMatcher::Exact(path)),
            Self::Prefix(path) if path.starts_with('/') => Ok(HttpPathMatcher::Prefix(path)),
            Self::Exact(_) | Self::Prefix(_) => Err(ConfigError::InvalidHttpPath),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConfigError {
    Contract(foxprox_core::ContractError),
    InvalidTimeout { field: &'static str },
    InvalidPortRange { start: u16, end: u16 },
    InvalidHttpPath,
    InvalidResourceLimit { field: &'static str },
    InvalidParserLimit { field: &'static str },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "contract error: {error}"),
            Self::InvalidTimeout { field } => write!(f, "{field} must be greater than zero"),
            Self::InvalidPortRange { start, end } => {
                write!(f, "invalid port range {start}-{end}: start exceeds end")
            }
            Self::InvalidHttpPath => f.write_str("HTTP path matchers must start with '/'"),
            Self::InvalidResourceLimit { field } => write!(f, "{field} must be greater than zero"),
            Self::InvalidParserLimit { field } => write!(f, "{field} must be greater than zero"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{DefaultPolicy, PortMatcher};

    #[test]
    fn validates_domain_http_rule_into_runtime_contracts() {
        let config = ConfigDocument {
            default_policy: Some(DefaultPolicyConfig::Deny),
            direct_dns_policy: Some(DirectDnsPolicyConfig::DenyExternal),
            allow_ping: Some(false),
            quic_policy: Some(QuicPolicyConfig::DenyByDefault),
            broker_dns_addrs: vec!["10.255.0.1".parse().unwrap()],
            udp_timeouts: Some(UdpTimeoutsConfig::default()),
            resource_limits: Some(ResourceLimitsConfig { max_flows: 128 }),
            parser_limits: Some(ParserLimitsConfig {
                max_http_request_head_bytes: 4096,
                max_socks5_message_bytes: 256,
            }),
            rules: vec![RuleConfig {
                id: "allow-api".to_string(),
                action: RuleActionConfig::Allow,
                protocol: Some(ProtocolConfig::Http),
                destination: Some(DestinationConfig::DomainSuffix("Example.COM".to_string())),
                port: Some(PortConfig::Exact(80)),
                http_scheme: Some(HttpSchemeConfig::Http),
                http_method: Some(HttpMethodConfig::Exact("GET".to_string())),
                http_path: Some(HttpPathConfig::Prefix("/api/".to_string())),
                minimum_hostname_confidence: Some(HostnameConfidence::High),
                timeout_override_seconds: Some(30),
            }],
        };

        let runtime = config.validate().unwrap();
        assert_eq!(runtime.default_policy, DefaultPolicy::Deny);
        assert_eq!(
            runtime.broker_dns_addrs,
            vec!["10.255.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(runtime.resource_limits.max_flows, 128);
        assert_eq!(runtime.parser_limits.max_http_request_head_bytes, 4096);
        assert_eq!(runtime.parser_limits.max_socks5_message_bytes, 256);
        assert_eq!(runtime.rules.len(), 1);
        assert_eq!(
            runtime.rules[0].protocol,
            ProtocolMatcher::Exact(Protocol::Http)
        );
        assert_eq!(runtime.rules[0].port, PortMatcher::Exact(80));
        assert_eq!(
            runtime.rules[0].http_scheme,
            HttpSchemeMatcher::Exact(HttpScheme::Http)
        );
        assert_eq!(
            runtime.rules[0].http_method,
            HttpMethodMatcher::Exact(HttpMethod::Get)
        );
        assert_eq!(
            runtime.rules[0].http_path,
            HttpPathMatcher::Prefix("/api/".to_string())
        );
        assert_eq!(
            runtime.rules[0].timeout_override,
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn rejects_invalid_values_before_policy_receives_config() {
        let bad_port = ConfigDocument {
            rules: vec![RuleConfig {
                id: "bad".to_string(),
                action: RuleActionConfig::Allow,
                protocol: None,
                destination: None,
                port: Some(PortConfig::Range {
                    start: 100,
                    end: 10,
                }),
                http_scheme: None,
                http_method: None,
                http_path: None,
                minimum_hostname_confidence: None,
                timeout_override_seconds: None,
            }],
            ..ConfigDocument::default()
        };
        assert!(matches!(
            bad_port.validate(),
            Err(ConfigError::InvalidPortRange {
                start: 100,
                end: 10
            })
        ));

        let bad_timeout = ConfigDocument {
            udp_timeouts: Some(UdpTimeoutsConfig {
                dns_seconds: 0,
                ..UdpTimeoutsConfig::default()
            }),
            ..ConfigDocument::default()
        };
        assert!(matches!(
            bad_timeout.validate(),
            Err(ConfigError::InvalidTimeout {
                field: "udp_timeouts.dns_seconds"
            })
        ));

        let bad_resource_limit = ConfigDocument {
            resource_limits: Some(ResourceLimitsConfig { max_flows: 0 }),
            ..ConfigDocument::default()
        };
        assert!(matches!(
            bad_resource_limit.validate(),
            Err(ConfigError::InvalidResourceLimit {
                field: "resource_limits.max_flows"
            })
        ));

        let bad_parser_limit = ConfigDocument {
            parser_limits: Some(ParserLimitsConfig {
                max_http_request_head_bytes: 0,
                ..ParserLimitsConfig::default()
            }),
            ..ConfigDocument::default()
        };
        assert!(matches!(
            bad_parser_limit.validate(),
            Err(ConfigError::InvalidParserLimit {
                field: "parser_limits.max_http_request_head_bytes"
            })
        ));

        let bad_socks_parser_limit = ConfigDocument {
            parser_limits: Some(ParserLimitsConfig {
                max_socks5_message_bytes: 0,
                ..ParserLimitsConfig::default()
            }),
            ..ConfigDocument::default()
        };
        assert!(matches!(
            bad_socks_parser_limit.validate(),
            Err(ConfigError::InvalidParserLimit {
                field: "parser_limits.max_socks5_message_bytes"
            })
        ));
    }
}
