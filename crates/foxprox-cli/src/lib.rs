//! User-facing runtime harnesses for foxprox.
//!
//! This crate intentionally starts with a narrow, testable command path:
//! process one IPv4 packet using a TOML policy config and emit structured audit
//! JSON. It is a process-boundary proof for the future long-running TUN runtime.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use foxprox_audit::{audit_record_to_json_line, AuditSinkError};
use foxprox_broker::Ipv4PacketBroker;
use foxprox_config::{policy_config_from_toml, ConfigError};
use foxprox_core::{FrontendKind, PolicyEngine, SandboxId};
use foxprox_packet::PacketContext;

/// CLI/runtime errors reported to users.
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Io { context: String, error: io::Error },
    Config(ConfigError),
    Core(String),
    Audit(AuditSinkError),
    Reply(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::Io { context, error } => write!(f, "{context}: {error}"),
            Self::Config(error) => write!(f, "{error}"),
            Self::Core(error) => write!(f, "{error}"),
            Self::Audit(error) => write!(f, "{error}"),
            Self::Reply(error) => write!(f, "packet-reply-error: {error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::Config(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::Usage(_) | Self::Core(_) | Self::Reply(_) => None,
        }
    }
}

impl From<ConfigError> for CliError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<AuditSinkError> for CliError {
    fn from(value: AuditSinkError) -> Self {
        Self::Audit(value)
    }
}

/// Result of one packet-once processing run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketOnceSummary {
    pub audit_json_line: String,
    pub outbound_packet_count: usize,
    pub outbound_byte_count: usize,
}

/// Process one packet using TOML policy configuration.
///
/// The returned JSON line is suitable for stdout. Any synthesized outbound
/// packet bytes are appended to `outbound`, allowing callers to write them to a
/// file or future TUN fd without mixing binary data into audit stdout.
pub fn process_packet_once(
    config_toml: &str,
    sandbox_id: &str,
    packet: &[u8],
    outbound: &mut Vec<u8>,
) -> Result<PacketOnceSummary, CliError> {
    let config = policy_config_from_toml(config_toml)?;
    let sandbox_id =
        SandboxId::new(sandbox_id).map_err(|error| CliError::Core(error.to_string()))?;
    let context = PacketContext::new(sandbox_id, FrontendKind::Tun);
    let broker = Ipv4PacketBroker::new(PolicyEngine::new(config));
    let result = broker.process_packet(&context, packet);

    if let Some(error) = result.reply_error {
        return Err(CliError::Reply(error));
    }

    let outbound_packet_count = result.outbound_packets.len();
    let outbound_byte_count = result.outbound_packets.iter().map(Vec::len).sum::<usize>();
    for packet in result.outbound_packets {
        outbound.extend_from_slice(&packet);
    }

    Ok(PacketOnceSummary {
        audit_json_line: audit_record_to_json_line(&result.evaluation.audit)?,
        outbound_packet_count,
        outbound_byte_count,
    })
}

/// Execute the `packet-once` command using process stdin/stdout semantics.
pub fn run_from_env() -> Result<(), CliError> {
    run_with_args(std::env::args_os().map(PathBuf::from))
}

fn run_with_args<I>(mut args: I) -> Result<(), CliError>
where
    I: Iterator<Item = PathBuf>,
{
    let _program = args.next();
    let Some(command) = args.next() else {
        return Err(usage());
    };
    if command.as_os_str() != "packet-once" {
        return Err(usage());
    }

    let mut config_path = None;
    let mut sandbox_id = None;
    let mut outbound_path = None;

    while let Some(flag) = args.next() {
        match flag.to_string_lossy().as_ref() {
            "--config" => config_path = args.next(),
            "--sandbox" => {
                sandbox_id = args
                    .next()
                    .map(|value| value.to_string_lossy().into_owned())
            }
            "--outbound" => outbound_path = args.next(),
            _ => return Err(usage()),
        }
    }

    let config_path = config_path.ok_or_else(usage)?;
    let sandbox_id = sandbox_id.ok_or_else(usage)?;
    run_packet_once_command(&config_path, &sandbox_id, outbound_path.as_deref())
}

fn run_packet_once_command(
    config_path: &Path,
    sandbox_id: &str,
    outbound_path: Option<&Path>,
) -> Result<(), CliError> {
    let config = fs::read_to_string(config_path).map_err(|error| CliError::Io {
        context: format!("read-config {}", config_path.display()),
        error,
    })?;
    let mut packet = Vec::new();
    io::stdin()
        .read_to_end(&mut packet)
        .map_err(|error| CliError::Io {
            context: "read-stdin-packet".to_owned(),
            error,
        })?;

    let mut outbound = Vec::new();
    let summary = process_packet_once(&config, sandbox_id, &packet, &mut outbound)?;
    io::stdout()
        .write_all(summary.audit_json_line.as_bytes())
        .map_err(|error| CliError::Io {
            context: "write-audit-stdout".to_owned(),
            error,
        })?;

    if let Some(path) = outbound_path {
        fs::write(path, outbound).map_err(|error| CliError::Io {
            context: format!("write-outbound {}", path.display()),
            error,
        })?;
    }

    Ok(())
}

fn usage() -> CliError {
    CliError::Usage(
        "usage: foxprox-cli packet-once --config <policy.toml> --sandbox <id> [--outbound <packet.bin>] < packet.bin"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

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

    fn echo_request_packet() -> Vec<u8> {
        ipv4_packet(
            1,
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            b"\x08\x00\x00\x00\x12\x34\x00\x01payload",
        )
    }

    #[test]
    fn packet_once_loads_config_and_emits_allowed_audit_with_reply_bytes() {
        let config = r#"
            default_policy = "deny"

            [[rules]]
            id = "allow-icmp"
            action = "allow"
            protocol = "icmp"
            "#;
        let mut outbound = Vec::new();

        let summary =
            process_packet_once(config, "cli-test", &echo_request_packet(), &mut outbound)
                .expect("packet-once succeeds");
        let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();

        assert_eq!(audit["sandbox_id"], "cli-test");
        assert_eq!(audit["protocol"], "icmp");
        assert_eq!(audit["decision"], "allowed");
        assert_eq!(audit["rule_id"], "allow-icmp");
        assert_eq!(summary.outbound_packet_count, 1);
        assert_eq!(summary.outbound_byte_count, outbound.len());
        assert!(!outbound.is_empty());
    }

    #[test]
    fn packet_once_default_deny_emits_audit_without_reply_bytes() {
        let mut outbound = Vec::new();

        let summary = process_packet_once("", "cli-test", &echo_request_packet(), &mut outbound)
            .expect("default-deny packet-once succeeds");
        let audit: Value = serde_json::from_str(&summary.audit_json_line).unwrap();

        assert_eq!(audit["decision"], "denied");
        assert_eq!(audit["reason"], "icmp-default-deny");
        assert_eq!(summary.outbound_packet_count, 0);
        assert_eq!(summary.outbound_byte_count, 0);
        assert!(outbound.is_empty());
    }

    #[test]
    fn packet_once_rejects_empty_sandbox_id() {
        let mut outbound = Vec::new();
        let error = process_packet_once("", "  ", &echo_request_packet(), &mut outbound)
            .expect_err("empty sandbox id is invalid");

        assert_eq!(error.to_string(), "sandbox id must not be empty");
    }
}
