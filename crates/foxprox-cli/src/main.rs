use std::env;
use std::path::Path;
use std::process::{Command, ExitCode};

use foxprox_core::audit::{AuditRecord, Decision, EventKind, Frontend, Protocol};
use foxprox_core::scenario::{run_scenario, ScenarioName};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("foxprox-lab: {err}");
            usage();
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [] => {
            usage();
            Ok(())
        }
        [cmd] if cmd == "help" || cmd == "--help" || cmd == "-h" => {
            usage();
            Ok(())
        }
        [cmd] if cmd == "list" => {
            for name in ScenarioName::list() {
                println!("{name}");
            }
            println!("env-smoke");
            println!("tun-smoke");
            Ok(())
        }
        [cmd, scenario] if cmd == "run" => run_named_scenario(scenario),
        [cmd, flag, scenario] if cmd == "run" && flag == "--scenario" => {
            run_named_scenario(scenario)
        }
        _ => Err("unknown command".to_string()),
    }
}

fn run_named_scenario(scenario: &str) -> Result<(), String> {
    let records = if scenario == "env-smoke" {
        env_smoke_records()
    } else if scenario == "tun-smoke" {
        tun_smoke_records()
    } else {
        run_scenario(ScenarioName::parse(scenario)?)
    };
    for record in records {
        println!("{}", record.to_json_line());
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "usage: foxprox-lab list | run [--scenario] <{}|env-smoke|tun-smoke>",
        ScenarioName::list().join("|")
    );
}

fn env_smoke_records() -> Vec<AuditRecord> {
    let tun_exists = Path::new("/dev/net/tun").exists();
    let bwrap_version = Command::new("bwrap").arg("--version").output();
    let bwrap_available = bwrap_version
        .as_ref()
        .is_ok_and(|output| output.status.success());
    let bwrap_text = bwrap_version
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string());

    vec![
        AuditRecord::new(
            EventKind::TunConfigured,
            "env-smoke",
            if tun_exists {
                Decision::Allow
            } else {
                Decision::FailClosed
            },
            if tun_exists {
                "/dev/net/tun exists"
            } else {
                "/dev/net/tun missing"
            },
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Unsupported)
        .with_metadata("path", "/dev/net/tun"),
        AuditRecord::new(
            EventKind::SandboxStarted,
            "env-smoke",
            if bwrap_available {
                Decision::Allow
            } else {
                Decision::FailClosed
            },
            if bwrap_available {
                "bwrap executable responds"
            } else {
                "bwrap executable unavailable"
            },
        )
        .with_frontend(Frontend::Harness)
        .with_metadata("bwrap_version", bwrap_text),
    ]
}

fn tun_smoke_records() -> Vec<AuditRecord> {
    let output = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--dev-bind",
            "/dev/net/tun",
            "/dev/net/tun",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--",
            "/bin/sh",
            "-lc",
            "ip tuntap add dev foxprox0 mode tun && ip addr add 10.0.2.2/24 dev foxprox0 && ip link set foxprox0 up && ip -o addr show dev foxprox0",
        ])
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let mut record = AuditRecord::new(
                EventKind::TunConfigured,
                "tun-smoke",
                if output.status.success() {
                    Decision::Allow
                } else {
                    Decision::FailClosed
                },
                if output.status.success() {
                    "bwrap namespace TUN setup command succeeded"
                } else {
                    "bwrap namespace TUN setup command failed"
                },
            )
            .with_frontend(Frontend::Harness)
            .with_protocol(Protocol::Unsupported)
            .with_metadata("status", output.status.to_string());
            if !stdout.is_empty() {
                record = record.with_metadata("stdout", stdout);
            }
            if !stderr.is_empty() {
                record = record.with_metadata("stderr", stderr);
            }
            vec![record]
        }
        Err(err) => vec![AuditRecord::new(
            EventKind::TunConfigured,
            "tun-smoke",
            Decision::FailClosed,
            format!("failed to execute bwrap TUN smoke: {err}"),
        )
        .with_frontend(Frontend::Harness)
        .with_protocol(Protocol::Unsupported)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_command() {
        assert!(run(vec!["list".to_string()]).is_ok());
    }

    #[test]
    fn rejects_unknown_scenario() {
        assert!(run(vec!["run".to_string(), "missing".to_string()]).is_err());
    }
}
