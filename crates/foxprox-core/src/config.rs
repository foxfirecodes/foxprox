use crate::policy::{PolicyConfig, PortMatcher};
use crate::types::{DecisionAction, FrontendKind};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    InvalidDefaultAction(DecisionAction),
    EmptyRuleId,
    DuplicateRuleId(String),
    InvalidPortRange { start: u16, end: u16 },
    DomainRuleWithoutMinimumConfidence { rule_id: String },
    BrokerDnsIsMulticast,
    UnknownFrontendPolicy,
}

pub fn validate_policy_config(config: &PolicyConfig) -> Result<(), ConfigError> {
    match config.default_action {
        DecisionAction::Allow
        | DecisionAction::DenyDrop
        | DecisionAction::DenyReset
        | DecisionAction::DenyIcmpUnreachable
        | DecisionAction::FailClosed => {}
        DecisionAction::RequireBrokerDns => {
            return Err(ConfigError::InvalidDefaultAction(config.default_action));
        }
    }

    if config.broker_dns.iter().any(|ip| match ip {
        std::net::IpAddr::V4(ip) => ip.is_multicast() || ip.octets() == [255, 255, 255, 255],
        std::net::IpAddr::V6(ip) => ip.is_multicast(),
    }) {
        return Err(ConfigError::BrokerDnsIsMulticast);
    }

    let mut ids = HashSet::new();
    for rule in config.rules.iter() {
        if rule.id.trim().is_empty() {
            return Err(ConfigError::EmptyRuleId);
        }
        if !ids.insert(rule.id.clone()) {
            return Err(ConfigError::DuplicateRuleId(rule.id.clone()));
        }
        if let Some(PortMatcher::Range { start, end }) = rule.destination_port {
            if start > end {
                return Err(ConfigError::InvalidPortRange { start, end });
            }
        }
        if config.require_hostname_for_domain_rules
            && rule.domain_suffix.is_some()
            && rule.minimum_confidence.is_none()
        {
            return Err(ConfigError::DomainRuleWithoutMinimumConfidence {
                rule_id: rule.id.clone(),
            });
        }
        if matches!(rule.frontend, Some(FrontendKind::Unknown)) {
            return Err(ConfigError::UnknownFrontendPolicy);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyRule, RuleSet};
    use crate::types::{AttributionConfidence, Hostname};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let mut rules = RuleSet::default();
        rules.push(PolicyRule::allow("same"));
        rules.push(PolicyRule::deny_drop("same"));
        let err = validate_policy_config(&PolicyConfig {
            rules,
            ..PolicyConfig::default()
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::DuplicateRuleId("same".to_string()));
    }

    #[test]
    fn domain_rules_must_declare_attribution_confidence() {
        let mut rule = PolicyRule::allow("domain");
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        let mut rules = RuleSet::default();
        rules.push(rule);
        let err = validate_policy_config(&PolicyConfig {
            rules,
            ..PolicyConfig::default()
        })
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::DomainRuleWithoutMinimumConfidence {
                rule_id: "domain".to_string()
            }
        );
    }

    #[test]
    fn valid_domain_rule_with_confidence_passes() {
        let mut rule = PolicyRule::allow("domain");
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::Medium);
        let mut rules = RuleSet::default();
        rules.push(rule);
        validate_policy_config(&PolicyConfig {
            broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            rules,
            ..PolicyConfig::default()
        })
        .unwrap();
    }

    #[test]
    fn require_broker_dns_is_not_valid_as_global_default() {
        let err = validate_policy_config(&PolicyConfig {
            default_action: DecisionAction::RequireBrokerDns,
            ..PolicyConfig::default()
        })
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::InvalidDefaultAction(DecisionAction::RequireBrokerDns)
        );
    }
}
