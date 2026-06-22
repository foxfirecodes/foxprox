use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::attribution::{Hostname, HostnameError};
use crate::policy::DenyBehavior;
use crate::types::Protocol;

/// Validated policy configuration. Defaults intentionally deny network access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub default_action: RuleAction,
    pub rules: Vec<PolicyRule>,
    pub broker_dns_servers: Vec<IpAddr>,
    pub allow_direct_dns: bool,
    pub allow_multicast_broadcast: bool,
    pub allow_ping: bool,
    pub deny_attribution_mismatch: bool,
    pub quic_default: RuleAction,
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for broker_dns_server in &self.broker_dns_servers {
            if is_invalid_broker_dns_server(*broker_dns_server) {
                return Err(ConfigError::InvalidBrokerDnsServer);
            }
        }

        for (index, rule) in self.rules.iter().enumerate() {
            if rule.id.trim().is_empty() {
                return Err(ConfigError::EmptyRuleId);
            }
            if self.rules[..index]
                .iter()
                .any(|previous| previous.id == rule.id)
            {
                return Err(ConfigError::DuplicateRuleId);
            }
            if rule
                .request
                .http_method
                .as_ref()
                .is_some_and(|method| !is_valid_http_method(method))
            {
                return Err(ConfigError::InvalidHttpMethodMatcher);
            }
            if rule
                .request
                .http_path_prefix
                .as_ref()
                .is_some_and(|prefix| !is_valid_http_path_prefix(prefix))
            {
                return Err(ConfigError::InvalidHttpPathPrefixMatcher);
            }
        }
        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: RuleAction::Deny(DenyBehavior::Drop),
            rules: Vec::new(),
            broker_dns_servers: Vec::new(),
            allow_direct_dns: false,
            allow_multicast_broadcast: false,
            allow_ping: false,
            deny_attribution_mismatch: true,
            quic_default: RuleAction::Deny(DenyBehavior::Drop),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RuleAction {
    Allow,
    Deny(DenyBehavior),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub id: String,
    pub action: RuleAction,
    pub protocol: ProtocolMatcher,
    pub destination: DestinationMatcher,
    pub request: RequestMatcher,
}

impl PolicyRule {
    pub fn allow_ip(id: impl Into<String>, cidr: Cidr, port: Option<u16>) -> Self {
        Self {
            id: id.into(),
            action: RuleAction::Allow,
            protocol: ProtocolMatcher::Any,
            destination: DestinationMatcher::Ip { cidr, port },
            request: RequestMatcher::default(),
        }
    }

    pub fn allow_domain(id: impl Into<String>, host: HostMatcher, port: Option<u16>) -> Self {
        Self {
            id: id.into(),
            action: RuleAction::Allow,
            protocol: ProtocolMatcher::Any,
            destination: DestinationMatcher::Host { host, port },
            request: RequestMatcher::default(),
        }
    }

    pub fn with_http_method(mut self, method: impl Into<String>) -> Self {
        self.request.http_method = Some(method.into());
        self
    }

    pub fn with_http_path_prefix(mut self, path_prefix: impl Into<String>) -> Self {
        self.request.http_path_prefix = Some(path_prefix.into());
        self
    }

    pub fn matches_protocol(&self, protocol: Protocol) -> bool {
        self.protocol.matches(protocol)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestMatcher {
    pub http_method: Option<String>,
    pub http_path_prefix: Option<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProtocolMatcher {
    Any,
    Exact(Protocol),
}

impl ProtocolMatcher {
    pub fn matches(self, protocol: Protocol) -> bool {
        match self {
            ProtocolMatcher::Any => true,
            ProtocolMatcher::Exact(expected) => expected == protocol,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationMatcher {
    Any,
    Ip {
        cidr: Cidr,
        port: Option<u16>,
    },
    Host {
        host: HostMatcher,
        port: Option<u16>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostMatcher {
    Exact(Hostname),
    DomainSuffix(Hostname),
}

impl HostMatcher {
    pub fn exact(value: &str) -> Result<Self, HostnameError> {
        Ok(Self::Exact(Hostname::parse(value)?))
    }

    pub fn suffix(value: &str) -> Result<Self, HostnameError> {
        Ok(Self::DomainSuffix(Hostname::parse(value)?))
    }

    pub fn matches(&self, hostname: &Hostname) -> bool {
        match self {
            HostMatcher::Exact(expected) => hostname == expected,
            HostMatcher::DomainSuffix(suffix) => hostname.matches_domain_suffix(suffix),
        }
    }
}

/// Small dependency-free CIDR matcher used by the core policy engine.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, ConfigError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(ConfigError::InvalidCidrPrefix { prefix, max });
        }
        Ok(Self {
            network: mask_ip(network, prefix),
            prefix,
        })
    }

    pub fn host(ip: IpAddr) -> Self {
        Self {
            network: ip,
            prefix: match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        matches!(
            (self.network, ip),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        ) && mask_ip(ip, self.prefix) == self.network
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

impl FromStr for Cidr {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = match value.split_once('/') {
            Some((ip, prefix)) => {
                let ip = ip.parse().map_err(|_| ConfigError::InvalidCidrAddress)?;
                let prefix = prefix
                    .parse()
                    .map_err(|_| ConfigError::InvalidCidrPrefixText)?;
                (ip, prefix)
            }
            None => {
                let ip: IpAddr = value.parse().map_err(|_| ConfigError::InvalidCidrAddress)?;
                let prefix = match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                (ip, prefix)
            }
        };
        Self::new(ip, prefix)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    EmptyRuleId,
    DuplicateRuleId,
    InvalidCidrAddress,
    InvalidCidrPrefixText,
    InvalidCidrPrefix { prefix: u8, max: u8 },
    InvalidHttpMethodMatcher,
    InvalidHttpPathPrefixMatcher,
    InvalidBrokerDnsServer,
}

fn is_invalid_broker_dns_server(ip: IpAddr) -> bool {
    ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST || ip.octets()[3] == 255)
}

fn is_valid_http_method(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn is_valid_http_path_prefix(prefix: &str) -> bool {
    prefix.starts_with('/') && !prefix.bytes().any(|byte| byte.is_ascii_control())
}

fn mask_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(mask_ipv4(ip, prefix)),
        IpAddr::V6(ip) => IpAddr::V6(mask_ipv6(ip, prefix)),
    }
}

fn mask_ipv4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let value = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(value & mask)
}

fn mask_ipv6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let value = u128::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(value & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_deny_by_default() {
        let config = PolicyConfig::default();
        assert_eq!(config.default_action, RuleAction::Deny(DenyBehavior::Drop));
        assert!(!config.allow_direct_dns);
        assert!(!config.allow_multicast_broadcast);
        assert!(!config.allow_ping);
        assert!(config.deny_attribution_mismatch);
    }

    #[test]
    fn cidr_matching_is_family_specific_and_prefix_aware() {
        let cidr: Cidr = "192.0.2.0/24".parse().unwrap();
        assert!(cidr.contains("192.0.2.45".parse().unwrap()));
        assert!(!cidr.contains("192.0.3.1".parse().unwrap()));
        assert!(!cidr.contains("2001:db8::1".parse().unwrap()));

        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8::beef".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn invalid_cidr_prefixes_are_rejected() {
        assert!("192.0.2.0/33".parse::<Cidr>().is_err());
        assert!("2001:db8::/129".parse::<Cidr>().is_err());
    }

    #[test]
    fn invalid_http_request_matchers_are_rejected() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow_domain(
                "bad-method",
                HostMatcher::exact("example.com").unwrap(),
                Some(80),
            )
            .with_http_method("get"),
        );
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHttpMethodMatcher)
        );

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow_domain(
                "bad-path",
                HostMatcher::exact("example.com").unwrap(),
                Some(80),
            )
            .with_http_path_prefix("admin"),
        );
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHttpPathPrefixMatcher)
        );
    }

    #[test]
    fn invalid_broker_dns_servers_are_rejected() {
        for invalid in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255)),
            "224.0.0.251".parse().unwrap(),
            Ipv6Addr::UNSPECIFIED.into(),
            "ff02::fb".parse().unwrap(),
        ] {
            let config = PolicyConfig {
                broker_dns_servers: vec![invalid],
                ..PolicyConfig::default()
            };
            assert_eq!(config.validate(), Err(ConfigError::InvalidBrokerDnsServer));
        }
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRule::allow_ip(
            "duplicate",
            "192.0.2.0/24".parse().unwrap(),
            Some(80),
        ));
        config.rules.push(PolicyRule::allow_domain(
            "duplicate",
            HostMatcher::exact("example.com").unwrap(),
            Some(80),
        ));

        assert_eq!(config.validate(), Err(ConfigError::DuplicateRuleId));
    }
}
