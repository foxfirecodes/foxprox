use foxprox_core::{
    AttributionConfidence, Cidr, DecisionAction, Hostname, HttpMethod, PolicyRule, PolicyRuleSet,
    PortRange, Protocol, RuleEffect, SandboxId,
};
use serde::Deserialize;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct LauncherConfig {
    pub sandbox_id: SandboxId,
    pub ifname: String,
    pub setup_socket_host: Option<PathBuf>,
    pub setup_socket_sandbox: Option<String>,
    pub setup_helper_host: Option<PathBuf>,
    pub resolv_conf: String,
    pub keep_cap_net_raw: bool,
    pub sandbox_ip: Ipv4Addr,
    pub broker_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub upstream_dns: SocketAddr,
    pub transparent_tcp_ports: Vec<u16>,
    pub udp_forward_ports: Vec<u16>,
    pub audit_queue_capacity: usize,
    pub max_worker_threads: usize,
    pub max_udp_flows: usize,
    pub http_proxy_port: Option<u16>,
    pub socks5_proxy_port: Option<u16>,
    pub inject_proxy_env: bool,
    pub no_proxy: Option<String>,
    pub bwrap_program: String,
    pub bwrap_args: Option<Vec<String>>,
    pub policy: PolicyRuleSet,
}

pub(crate) fn load_launcher_config(path: &Path) -> io::Result<LauncherConfig> {
    let contents = fs::read_to_string(path)?;
    parse_launcher_config(&contents)
}

pub(crate) fn parse_launcher_config(contents: &str) -> io::Result<LauncherConfig> {
    let raw: RawConfig = toml::from_str(contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid foxprox config TOML: {error}"),
        )
    })?;
    raw.try_into_launcher()
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    sandbox: RawSandbox,
    network: RawNetwork,
    proxy: RawProxy,
    bwrap: RawBwrap,
    policy: RawPolicy,
}

impl RawConfig {
    fn try_into_launcher(self) -> io::Result<LauncherConfig> {
        let sandbox_id = SandboxId::new(self.sandbox.id).map_err(invalid_value)?;
        let transparent_tcp_ports = dedupe_ports(self.network.transparent_tcp_ports);
        if transparent_tcp_ports.is_empty() {
            return Err(invalid("network.transparent_tcp_ports must not be empty"));
        }
        if self.network.prefix_len > 32 {
            return Err(invalid("network.prefix_len must be <= 32"));
        }
        if self.network.mtu == 0 {
            return Err(invalid("network.mtu must be non-zero"));
        }
        if self.network.sandbox_ip == self.network.broker_ip {
            return Err(invalid(
                "network.sandbox_ip must differ from network.broker_ip",
            ));
        }
        if transparent_tcp_ports.contains(&0) || self.network.udp_forward_ports.contains(&0) {
            return Err(invalid("configured ports must be non-zero"));
        }
        if self.proxy.http_port == Some(0) || self.proxy.socks5_port == Some(0) {
            return Err(invalid("proxy ports must be non-zero"));
        }
        let policy = self.policy.try_into_policy()?;
        Ok(LauncherConfig {
            sandbox_id,
            ifname: self.sandbox.ifname,
            setup_socket_host: self.sandbox.setup_socket_host,
            setup_socket_sandbox: self.sandbox.setup_socket_sandbox,
            setup_helper_host: self.sandbox.setup_helper_host,
            resolv_conf: self.sandbox.resolv_conf,
            keep_cap_net_raw: self.sandbox.keep_cap_net_raw,
            sandbox_ip: self.network.sandbox_ip,
            broker_ip: self.network.broker_ip,
            prefix_len: self.network.prefix_len,
            mtu: self.network.mtu,
            upstream_dns: self.network.upstream_dns,
            transparent_tcp_ports,
            udp_forward_ports: dedupe_ports(self.network.udp_forward_ports),
            audit_queue_capacity: nonzero_usize(
                self.network.audit_queue_capacity,
                "network.audit_queue_capacity",
            )?,
            max_worker_threads: nonzero_usize(
                self.network.max_worker_threads,
                "network.max_worker_threads",
            )?,
            max_udp_flows: nonzero_usize(self.network.max_udp_flows, "network.max_udp_flows")?,
            http_proxy_port: self.proxy.http_port,
            socks5_proxy_port: self.proxy.socks5_port,
            inject_proxy_env: self.proxy.inject_env,
            no_proxy: self.proxy.no_proxy,
            bwrap_program: self.bwrap.program,
            bwrap_args: self.bwrap.args,
            policy,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSandbox {
    id: String,
    ifname: String,
    setup_socket_host: Option<PathBuf>,
    setup_socket_sandbox: Option<String>,
    setup_helper_host: Option<PathBuf>,
    resolv_conf: String,
    keep_cap_net_raw: bool,
}

impl Default for RawSandbox {
    fn default() -> Self {
        Self {
            id: "foxprox-run".to_string(),
            ifname: "foxprox0".to_string(),
            setup_socket_host: None,
            setup_socket_sandbox: None,
            setup_helper_host: None,
            resolv_conf: "/etc/resolv.conf".to_string(),
            keep_cap_net_raw: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawNetwork {
    sandbox_ip: Ipv4Addr,
    broker_ip: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
    upstream_dns: SocketAddr,
    transparent_tcp_ports: Vec<u16>,
    udp_forward_ports: Vec<u16>,
    audit_queue_capacity: usize,
    max_worker_threads: usize,
    max_udp_flows: usize,
}

impl Default for RawNetwork {
    fn default() -> Self {
        Self {
            sandbox_ip: Ipv4Addr::new(10, 255, 0, 2),
            broker_ip: Ipv4Addr::new(10, 255, 0, 1),
            prefix_len: 24,
            mtu: 1500,
            upstream_dns: SocketAddr::from(([1, 1, 1, 1], 53)),
            transparent_tcp_ports: vec![80, 443],
            udp_forward_ports: vec![443],
            audit_queue_capacity: 8192,
            max_worker_threads: 64,
            max_udp_flows: 4096,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawProxy {
    http_port: Option<u16>,
    socks5_port: Option<u16>,
    inject_env: bool,
    no_proxy: Option<String>,
}

impl Default for RawProxy {
    fn default() -> Self {
        Self {
            http_port: Some(8080),
            socks5_port: Some(1080),
            inject_env: true,
            no_proxy: Some("localhost,127.0.0.1".to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawBwrap {
    program: String,
    args: Option<Vec<String>>,
}

impl Default for RawBwrap {
    fn default() -> Self {
        Self {
            program: "bwrap".to_string(),
            args: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawPolicy {
    default_action: Option<String>,
    deny_direct_dns: Option<bool>,
    deny_multicast_broadcast: Option<bool>,
    deny_sni_dns_mismatch: Option<bool>,
    deny_hidden_sni: Option<bool>,
    broadcast_addresses: Vec<IpAddr>,
    rules: Vec<RawRule>,
}

impl RawPolicy {
    fn try_into_policy(self) -> io::Result<PolicyRuleSet> {
        let mut policy = PolicyRuleSet::default();
        if let Some(action) = self.default_action {
            policy.default_action = parse_decision_action(&action)?;
        }
        if let Some(value) = self.deny_direct_dns {
            policy.deny_direct_dns = value;
        }
        if let Some(value) = self.deny_multicast_broadcast {
            policy.deny_multicast_broadcast = value;
        }
        if let Some(value) = self.deny_sni_dns_mismatch {
            policy.deny_sni_dns_mismatch = value;
        }
        if let Some(value) = self.deny_hidden_sni {
            policy.deny_hidden_sni = value;
        }
        policy.broadcast_addresses.extend(self.broadcast_addresses);
        policy.rules = self
            .rules
            .into_iter()
            .map(RawRule::try_into_rule)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(policy)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    effect: String,
    protocol: Option<String>,
    destination_cidr: Option<String>,
    destination_ports: Option<String>,
    hostname: Option<String>,
    domain_suffix: Option<String>,
    origin_scheme: Option<String>,
    http_methods: Option<Vec<String>>,
    http_path_prefix: Option<String>,
    min_attribution: Option<String>,
}

impl RawRule {
    fn try_into_rule(self) -> io::Result<PolicyRule> {
        let mut rule = PolicyRule::new(self.id, parse_rule_effect(&self.effect)?);
        if let Some(protocol) = self.protocol {
            rule = rule.with_protocol(parse_protocol(&protocol)?);
        }
        if let Some(cidr) = self.destination_cidr {
            rule = rule.with_destination_cidr(parse_cidr(&cidr)?);
        }
        if let Some(ports) = self.destination_ports {
            rule = rule.with_destination_ports(parse_port_range(&ports)?);
        }
        if let Some(hostname) = self.hostname {
            rule = rule.with_hostname(Hostname::parse(hostname).map_err(invalid_value)?);
        }
        if let Some(domain_suffix) = self.domain_suffix {
            rule = rule.with_domain_suffix(Hostname::parse(domain_suffix).map_err(invalid_value)?);
        }
        if let Some(origin_scheme) = self.origin_scheme {
            rule = rule.with_origin_scheme(origin_scheme);
        }
        if let Some(methods) = self.http_methods {
            for method in methods {
                rule = rule.with_http_method(HttpMethod::parse(method).map_err(invalid_value)?);
            }
        }
        if let Some(prefix) = self.http_path_prefix {
            rule = rule.with_http_path_prefix(prefix);
        }
        if let Some(confidence) = self.min_attribution {
            rule = rule.with_min_attribution(parse_attribution_confidence(&confidence)?);
        }
        Ok(rule)
    }
}

fn parse_decision_action(value: &str) -> io::Result<DecisionAction> {
    match normalize(value).as_str() {
        "deny-drop" | "drop" => Ok(DecisionAction::DenyDrop),
        "deny-reset" | "reset" => Ok(DecisionAction::DenyReset),
        "deny-icmp-unreachable" | "icmp-unreachable" => Ok(DecisionAction::DenyIcmpUnreachable),
        "fail-closed" => Ok(DecisionAction::FailClosed),
        other => Err(invalid(format!("unknown policy default_action {other:?}"))),
    }
}

fn parse_rule_effect(value: &str) -> io::Result<RuleEffect> {
    match normalize(value).as_str() {
        "allow" => Ok(RuleEffect::Allow),
        "deny" => Ok(RuleEffect::Deny),
        other => Err(invalid(format!("unknown rule effect {other:?}"))),
    }
}

fn parse_protocol(value: &str) -> io::Result<Protocol> {
    match normalize(value).as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "dns" => Ok(Protocol::Dns),
        "icmp" => Ok(Protocol::Icmp),
        "http" => Ok(Protocol::Http),
        "https-connect" | "connect" => Ok(Protocol::HttpsConnect),
        "tls" | "https" => Ok(Protocol::Tls),
        "socks" | "socks5" => Ok(Protocol::Socks),
        "quic" => Ok(Protocol::Quic),
        "unsupported" => Ok(Protocol::Unsupported),
        other => Err(invalid(format!("unknown protocol {other:?}"))),
    }
}

fn parse_attribution_confidence(value: &str) -> io::Result<AttributionConfidence> {
    match normalize(value).as_str() {
        "low" => Ok(AttributionConfidence::Low),
        "medium" => Ok(AttributionConfidence::Medium),
        "high" => Ok(AttributionConfidence::High),
        other => Err(invalid(format!("unknown attribution confidence {other:?}"))),
    }
}

fn parse_port_range(value: &str) -> io::Result<PortRange> {
    let value = value.trim();
    if let Some((start, end)) = value.split_once('-') {
        let start: u16 = start.trim().parse().map_err(invalid_value)?;
        let end: u16 = end.trim().parse().map_err(invalid_value)?;
        PortRange::new(start, end).ok_or_else(|| invalid("port range start must be <= end"))
    } else {
        let port: u16 = value.parse().map_err(invalid_value)?;
        Ok(PortRange::single(port))
    }
}

fn parse_cidr(value: &str) -> io::Result<Cidr> {
    let (ip, prefix) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| invalid(format!("CIDR must include prefix length: {value:?}")))?;
    let prefix: u8 = prefix.trim().parse().map_err(invalid_value)?;
    match ip.trim().parse::<IpAddr>().map_err(invalid_value)? {
        IpAddr::V4(ip) => Cidr::v4(ip, prefix).ok_or_else(|| invalid("invalid IPv4 prefix")),
        IpAddr::V6(ip) => Cidr::v6(ip, prefix).ok_or_else(|| invalid("invalid IPv6 prefix")),
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

fn nonzero_usize(value: usize, field: &str) -> io::Result<usize> {
    if value == 0 {
        Err(invalid(format!("{field} must be non-zero")))
    } else {
        Ok(value)
    }
}

fn dedupe_ports(ports: Vec<u16>) -> Vec<u16> {
    let mut deduped = Vec::with_capacity(ports.len());
    for port in ports {
        if !deduped.contains(&port) {
            deduped.push(port);
        }
    }
    deduped
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_value(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn parses_minimal_default_deny_config() {
        let config = parse_launcher_config("").unwrap();

        assert_eq!(config.sandbox_id.as_str(), "foxprox-run");
        assert_eq!(config.transparent_tcp_ports, vec![80, 443]);
        assert_eq!(config.udp_forward_ports, vec![443]);
        assert_eq!(config.http_proxy_port, Some(8080));
        assert_eq!(config.socks5_proxy_port, Some(1080));
        assert!(config.policy.rules.is_empty());
        assert_eq!(config.policy.default_action, DecisionAction::DenyDrop);
    }

    #[test]
    fn parses_policy_rules() {
        let config = parse_launcher_config(
            r#"
            [sandbox]
            id = "browser"

            [network]
            transparent_tcp_ports = [80, 443, 443]
            udp_forward_ports = [443]

            [policy]
            default_action = "deny-drop"

            [[policy.rules]]
            id = "allow-example-http"
            effect = "allow"
            protocol = "http"
            domain_suffix = "example.com"
            destination_ports = "80"
            origin_scheme = "http"
            http_methods = ["GET", "HEAD"]
            http_path_prefix = "/"
            min_attribution = "high"

            [[policy.rules]]
            id = "deny-private-tcp"
            effect = "deny"
            protocol = "tcp"
            destination_cidr = "10.0.0.0/8"
            destination_ports = "1-65535"
            "#,
        )
        .unwrap();

        assert_eq!(config.sandbox_id.as_str(), "browser");
        assert_eq!(config.transparent_tcp_ports, vec![80, 443]);
        assert_eq!(config.policy.rules.len(), 2);
        assert_eq!(config.policy.rules[0].id, "allow-example-http");
        assert_eq!(config.policy.rules[1].effect, RuleEffect::Deny);
    }

    #[test]
    fn rejects_invalid_port_ranges() {
        let error = parse_launcher_config(
            r#"
            [[policy.rules]]
            id = "bad"
            effect = "allow"
            destination_ports = "443-80"
            "#,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parses_ipv6_cidr_rule() {
        let config = parse_launcher_config(
            r#"
            [[policy.rules]]
            id = "allow-v6"
            effect = "allow"
            protocol = "tcp"
            destination_cidr = "2001:db8::/32"
            "#,
        )
        .unwrap();

        assert_eq!(config.policy.rules.len(), 1);
        match config.policy.rules[0].destination_cidr {
            Some(Cidr::V6 { network, prefix }) => {
                assert_eq!(network, "2001:db8::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 32);
            }
            other => panic!("expected IPv6 CIDR, got {other:?}"),
        }
    }
}
