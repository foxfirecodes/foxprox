use std::fmt;
use std::str::FromStr;

use crate::types::{HostnameConfidence, HostnameSource};

/// Lowercase, absolute-hostname-free form used for deterministic policy checks.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Hostname(String);

impl Hostname {
    pub fn parse(value: &str) -> Result<Self, HostnameError> {
        let trimmed = value.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(HostnameError::Empty);
        }
        if trimmed.len() > 253 {
            return Err(HostnameError::TooLong);
        }
        if trimmed.starts_with('.') || trimmed.ends_with('.') || trimmed.contains("..") {
            return Err(HostnameError::InvalidLabel);
        }

        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(HostnameError::InvalidLabel);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HostnameError::InvalidLabel);
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(HostnameError::InvalidCharacter);
            }
        }

        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches_domain_suffix(&self, suffix: &Hostname) -> bool {
        self == suffix
            || self
                .0
                .strip_suffix(suffix.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

impl FromStr for Hostname {
    type Err = HostnameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HostnameError {
    Empty,
    TooLong,
    InvalidLabel,
    InvalidCharacter,
}

/// Hostname evidence attached to a normalized policy event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAttribution {
    pub hostname: Option<Hostname>,
    pub source: HostnameSource,
    pub confidence: HostnameConfidence,
}

impl HostAttribution {
    pub fn none() -> Self {
        Self {
            hostname: None,
            source: HostnameSource::None,
            confidence: HostnameConfidence::None,
        }
    }

    pub fn ip_only() -> Self {
        Self {
            hostname: None,
            source: HostnameSource::IpOnly,
            confidence: HostnameConfidence::Low,
        }
    }

    pub fn new(hostname: Hostname, source: HostnameSource, confidence: HostnameConfidence) -> Self {
        Self {
            hostname: Some(hostname),
            source,
            confidence,
        }
    }

    pub fn dns(hostname: Hostname) -> Self {
        Self::new(
            hostname,
            HostnameSource::DnsCache,
            HostnameConfidence::Medium,
        )
    }

    pub fn plaintext_http(hostname: Hostname) -> Self {
        Self::new(
            hostname,
            HostnameSource::PlaintextHttpHost,
            HostnameConfidence::High,
        )
    }

    pub fn tls_sni(hostname: Hostname) -> Self {
        Self::new(hostname, HostnameSource::TlsSni, HostnameConfidence::High)
    }

    pub fn explicit_proxy(hostname: Hostname) -> Self {
        Self::new(
            hostname,
            HostnameSource::ExplicitProxy,
            HostnameConfidence::High,
        )
    }

    pub fn is_sufficient_for_domain_rules(&self) -> bool {
        self.hostname.is_some() && self.confidence >= HostnameConfidence::Medium
    }
}

impl Default for HostAttribution {
    fn default() -> Self {
        Self::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_normalized_for_deterministic_matching() {
        let hostname = Hostname::parse("Example.COM.").unwrap();
        assert_eq!(hostname.as_str(), "example.com");
        assert!(hostname.matches_domain_suffix(&Hostname::parse("com").unwrap()));
        assert!(hostname.matches_domain_suffix(&Hostname::parse("example.com").unwrap()));
        assert!(!hostname.matches_domain_suffix(&Hostname::parse("ample.com").unwrap()));
    }

    #[test]
    fn invalid_hostnames_are_rejected_early() {
        for value in [
            "",
            ".example.com",
            "example..com",
            "-example.com",
            "exa_mple.com",
        ] {
            assert!(
                Hostname::parse(value).is_err(),
                "{value:?} should be invalid"
            );
        }
    }
}
