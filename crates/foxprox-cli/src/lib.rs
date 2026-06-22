use foxprox_core::{
    AuditKind, AuditRecord, BrokerRuntimeConfig, BwrapSetupPlan, Decision, DenialReason, Frontend,
    NetworkSetupConfig, SetupHelperPlan,
};
use serde_json::json;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_args(args: &[String]) -> CliOutput {
    if args.first().is_some_and(|command| command == "plan-bwrap") {
        return plan_bwrap_args(&args[1..]);
    }
    match args {
        [command, path] if command == "validate-config" => validate_config_path(path),
        [command, sandbox_id] if command == "default-config" => default_config(sandbox_id),
        _ => usage_output(),
    }
}

pub fn run_foxproxsetup_args(args: &[String]) -> CliOutput {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return error_output(
            "setup_missing_separator",
            "expected foxproxsetup <setup flags> -- <target...>".to_string(),
        );
    };
    if args.len() <= separator + 1 {
        return error_output(
            "setup_missing_target",
            "expected non-empty target command after --".to_string(),
        );
    }
    let target = &args[separator + 1..];
    let config = match parse_setup_config(&args[..separator]) {
        Ok(config) => config,
        Err(error) => return error_output("setup_parse_error", error),
    };
    let plan = SetupHelperPlan::new(config, target);
    let output = json!({
        "plan": plan,
        "audit": plan.audit_record(),
    });
    match serde_json::to_string(&output) {
        Ok(json) => CliOutput {
            exit_code: 0,
            stdout: format!("{json}\n"),
            stderr: String::new(),
        },
        Err(error) => error_output("setup_serialize_error", error.to_string()),
    }
}

fn parse_setup_config(args: &[String]) -> Result<NetworkSetupConfig, String> {
    let mut sandbox_id: Option<String> = None;
    let mut tun_name: Option<String> = None;
    let mut sandbox_ip = None;
    let mut gateway_ip = None;
    let mut mtu = None;
    let mut broker_dns_ip = None;
    let mut http_proxy_port = None;
    let mut socks_proxy_port = None;
    let mut setup_control_fd = None;
    let mut index = 0usize;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--sandbox-id" => sandbox_id = Some(value.clone()),
            "--tun-name" => tun_name = Some(value.clone()),
            "--sandbox-ip" => sandbox_ip = Some(value.parse().map_err(|_| "invalid sandbox ip")?),
            "--gateway-ip" => gateway_ip = Some(value.parse().map_err(|_| "invalid gateway ip")?),
            "--mtu" => mtu = Some(value.parse().map_err(|_| "invalid mtu")?),
            "--dns" => broker_dns_ip = Some(value.parse().map_err(|_| "invalid dns ip")?),
            "--http-proxy" => http_proxy_port = Some(parse_proxy_port(value)?),
            "--socks-proxy" => socks_proxy_port = Some(parse_proxy_port(value)?),
            "--setup-control-fd" => {
                setup_control_fd = Some(value.parse().map_err(|_| "invalid setup control fd")?)
            }
            "--drop-cap" if value == "CAP_NET_ADMIN" => {}
            other => return Err(format!("unsupported setup flag {other}")),
        }
        index += 2;
    }
    Ok(NetworkSetupConfig {
        sandbox_id: sandbox_id.ok_or("missing --sandbox-id")?,
        tun_name: tun_name.ok_or("missing --tun-name")?,
        sandbox_ip: sandbox_ip.ok_or("missing --sandbox-ip")?,
        gateway_ip: gateway_ip.ok_or("missing --gateway-ip")?,
        mtu: mtu.ok_or("missing --mtu")?,
        broker_dns_ip: broker_dns_ip.ok_or("missing --dns")?,
        http_proxy_port: http_proxy_port.ok_or("missing --http-proxy")?,
        socks_proxy_port: socks_proxy_port.ok_or("missing --socks-proxy")?,
        setup_control_fd,
    })
}

fn parse_proxy_port(value: &str) -> Result<u16, String> {
    value
        .rsplit_once(':')
        .ok_or_else(|| "proxy endpoint must include port".to_string())?
        .1
        .parse()
        .map_err(|_| "invalid proxy port".to_string())
}

pub fn validate_config_path(path: impl AsRef<Path>) -> CliOutput {
    match fs::read_to_string(path.as_ref()) {
        Ok(text) => validate_config_text(&text),
        Err(error) => error_output("config_io_error", error.to_string()),
    }
}

pub fn validate_config_text(text: &str) -> CliOutput {
    match serde_json::from_str::<BrokerRuntimeConfig>(text) {
        Ok(config) => {
            let audit = config.validation_audit();
            let valid = audit.decision == Some(Decision::Allow);
            audit_output(if valid { 0 } else { 2 }, audit)
        }
        Err(error) => error_output("config_parse_error", error.to_string()),
    }
}

fn plan_bwrap_args(args: &[String]) -> CliOutput {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return error_output(
            "plan_bwrap_missing_separator",
            "expected: plan-bwrap <config> -- <target...>".to_string(),
        );
    };
    if separator != 1 || args.len() <= separator + 1 {
        return error_output(
            "plan_bwrap_missing_target",
            "expected non-empty target command after --".to_string(),
        );
    }
    let config_path = &args[0];
    let target = &args[separator + 1..];
    let text = match fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(error) => return error_output("config_io_error", error.to_string()),
    };
    let config = match serde_json::from_str::<BrokerRuntimeConfig>(&text) {
        Ok(config) => config,
        Err(error) => return error_output("config_parse_error", error.to_string()),
    };
    let validation = config.validation_audit();
    if validation.decision != Some(Decision::Allow) {
        return audit_output(2, validation);
    }
    let plan = BwrapSetupPlan::new(config.setup.clone(), target);
    let output = json!({
        "plan": plan,
        "audit": plan.audit_record(),
    });
    match serde_json::to_string(&output) {
        Ok(json) => CliOutput {
            exit_code: 0,
            stdout: format!("{json}\n"),
            stderr: String::new(),
        },
        Err(error) => error_output("plan_bwrap_serialize_error", error.to_string()),
    }
}

fn default_config(sandbox_id: &str) -> CliOutput {
    match serde_json::to_string_pretty(&BrokerRuntimeConfig::alpha_default(sandbox_id)) {
        Ok(json) => CliOutput {
            exit_code: 0,
            stdout: format!("{json}\n"),
            stderr: String::new(),
        },
        Err(error) => error_output("config_serialize_error", error.to_string()),
    }
}

fn usage_output() -> CliOutput {
    CliOutput {
        exit_code: 64,
        stdout: String::new(),
        stderr: "usage: foxprox validate-config <path> | default-config <sandbox-id> | plan-bwrap <config> -- <target...>\n".to_string(),
    }
}

fn error_output(code: &str, detail: String) -> CliOutput {
    let audit = AuditRecord::new(AuditKind::BrokerError, "unknown")
        .with_frontend(Frontend::Core)
        .with_decision(Decision::FailClosed, Some(DenialReason::PolicyConfig))
        .with_detail("error_codes", code)
        .with_detail("error_detail", detail);
    audit_output(1, audit)
}

fn audit_output(exit_code: i32, audit: AuditRecord) -> CliOutput {
    CliOutput {
        exit_code,
        stdout: format!(
            "{}\n",
            audit.to_json_line().expect("audit record serializes")
        ),
        stderr: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::Value;

    #[test]
    fn validate_config_text_prints_broker_started_audit_for_valid_config() {
        let config = BrokerRuntimeConfig::alpha_default("s1");
        let text = serde_json::to_string(&config).unwrap();
        let output = validate_config_text(&text);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_started");
        assert_eq!(value["sandbox_id"], "s1");
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["details"]["audit_capacity"], "1024");
    }

    #[test]
    fn validate_config_text_prints_fail_closed_audit_for_invalid_config() {
        let mut config = BrokerRuntimeConfig::alpha_default("s1");
        config.audit_capacity = 0;
        config.policy.broker_dns.clear();
        let text = serde_json::to_string(&config).unwrap();
        let output = validate_config_text(&text);
        assert_eq!(output.exit_code, 2);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["decision"], "fail_closed");
        assert!(value["details"]["error_codes"]
            .as_str()
            .unwrap()
            .contains("audit_capacity_zero"));
        assert!(value["details"]["error_codes"]
            .as_str()
            .unwrap()
            .contains("policy_broker_dns_empty"));
    }

    #[test]
    fn malformed_config_json_prints_parse_error_audit() {
        let output = validate_config_text("{not json");
        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["details"]["error_codes"], "config_parse_error");
    }

    #[test]
    fn plan_bwrap_prints_plan_and_setup_audit() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-config-{}-{}.json",
            std::process::id(),
            "plan"
        ));
        let config = BrokerRuntimeConfig::alpha_default("s1");
        std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
        let output = run_args(&[
            "plan-bwrap".to_string(),
            path.to_string_lossy().to_string(),
            "--".to_string(),
            "curl".to_string(),
            "http://example.com".to_string(),
        ]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["plan"]["setup_command"][0], "foxproxsetup");
        assert_eq!(
            value["plan"]["setup_command"]
                .as_array()
                .unwrap()
                .last()
                .unwrap(),
            "http://example.com"
        );
        assert_eq!(value["audit"]["kind"], "setup_plan_created");
        assert_eq!(value["audit"]["details"]["tun_name"], "foxprox0");
    }

    #[test]
    fn plan_bwrap_missing_target_prints_fail_closed_audit() {
        let output = run_args(&[
            "plan-bwrap".to_string(),
            "config.json".to_string(),
            "--".to_string(),
        ]);
        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["details"]["error_codes"], "plan_bwrap_missing_target");
    }

    #[test]
    fn foxproxsetup_plan_parses_bwrap_helper_flags() {
        let output = run_foxproxsetup_args(&[
            "--sandbox-id".to_string(),
            "s1".to_string(),
            "--tun-name".to_string(),
            "foxprox0".to_string(),
            "--sandbox-ip".to_string(),
            "10.0.2.15".to_string(),
            "--gateway-ip".to_string(),
            "10.0.2.2".to_string(),
            "--mtu".to_string(),
            "1500".to_string(),
            "--dns".to_string(),
            "10.0.2.3".to_string(),
            "--http-proxy".to_string(),
            "10.0.2.2:3128".to_string(),
            "--socks-proxy".to_string(),
            "10.0.2.2:1080".to_string(),
            "--setup-control-fd".to_string(),
            "9".to_string(),
            "--drop-cap".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--".to_string(),
            "curl".to_string(),
            "http://example.com".to_string(),
        ]);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["audit"]["kind"], "tun_configured");
        assert_eq!(value["plan"]["steps"][0]["name"], "create_tun");
        assert_eq!(value["plan"]["steps"][6]["name"], "handoff_tun_fd");
        assert_eq!(value["plan"]["steps"][7]["name"], "close_setup_fds");
        assert_eq!(value["plan"]["target_command"][0], "curl");
    }

    #[test]
    fn foxproxsetup_missing_target_prints_fail_closed_audit() {
        let output = run_foxproxsetup_args(&[
            "--sandbox-id".to_string(),
            "s1".to_string(),
            "--".to_string(),
        ]);
        assert_eq!(output.exit_code, 1);
        let value: Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(value["kind"], "broker_error");
        assert_eq!(value["details"]["error_codes"], "setup_missing_target");
    }

    #[test]
    fn default_config_prints_json_config() {
        let output = run_args(&["default-config".to_string(), "s1".to_string()]);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["setup"]["sandbox_id"], "s1");
    }
}
