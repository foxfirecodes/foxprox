use foxprox_core::{AuditKind, AuditRecord, BrokerRuntimeConfig, Decision, DenialReason, Frontend};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_args(args: &[String]) -> CliOutput {
    match args {
        [command, path] if command == "validate-config" => validate_config_path(path),
        [command, sandbox_id] if command == "default-config" => default_config(sandbox_id),
        _ => usage_output(),
    }
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
        stderr: "usage: foxprox validate-config <path> | default-config <sandbox-id>\n".to_string(),
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
    fn default_config_prints_json_config() {
        let output = run_args(&["default-config".to_string(), "s1".to_string()]);
        assert_eq!(output.exit_code, 0);
        let value: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["setup"]["sandbox_id"], "s1");
    }
}
