use std::env;
use std::process::{Command, ExitCode};

use foxprox_core::audit::json_escape;
use foxprox_core::integration::TunSetupConfig;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("foxproxsetup: {err}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupArgs {
    setup: TunSetupConfig,
    target_argv: Vec<String>,
    print_plan: bool,
    configure_only: bool,
    no_default_route: bool,
}

impl SetupArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut setup = TunSetupConfig::alpha_default();
        let mut print_plan = false;
        let mut configure_only = false;
        let mut no_default_route = false;
        let mut target_argv = Vec::new();
        let mut iter = args.into_iter().peekable();
        while let Some(arg) = iter.next() {
            if arg == "--" {
                target_argv.extend(iter);
                break;
            }
            match arg.as_str() {
                "--help" | "-h" => {
                    print_usage();
                    return Err("help requested".to_string());
                }
                "--print-plan" => print_plan = true,
                "--configure-only" => configure_only = true,
                "--no-default-route" => no_default_route = true,
                "--tun-name" => setup.tun_name = next_value(&mut iter, "--tun-name")?,
                "--sandbox-ip" => {
                    let value = next_value(&mut iter, "--sandbox-ip")?;
                    let (ip, prefix) = value
                        .split_once('/')
                        .ok_or_else(|| "--sandbox-ip must be IP/PREFIX".to_string())?;
                    setup.sandbox_ip = ip
                        .parse()
                        .map_err(|err| format!("invalid --sandbox-ip: {err}"))?;
                    setup.prefix_len = prefix
                        .parse()
                        .map_err(|err| format!("invalid --sandbox-ip prefix: {err}"))?;
                }
                "--broker-ip" => {
                    setup.broker_ip = next_value(&mut iter, "--broker-ip")?
                        .parse()
                        .map_err(|err| format!("invalid --broker-ip: {err}"))?;
                }
                "--mtu" => {
                    setup.mtu = next_value(&mut iter, "--mtu")?
                        .parse()
                        .map_err(|err| format!("invalid --mtu: {err}"))?;
                }
                "--dns-listener" => {
                    setup.dns_listener = next_value(&mut iter, "--dns-listener")?
                        .parse()
                        .map_err(|err| format!("invalid --dns-listener: {err}"))?;
                }
                "--http-proxy-listener" => {
                    setup.http_proxy_listener = next_value(&mut iter, "--http-proxy-listener")?
                        .parse()
                        .map_err(|err| format!("invalid --http-proxy-listener: {err}"))?;
                }
                "--socks-proxy-listener" => {
                    setup.socks_proxy_listener = next_value(&mut iter, "--socks-proxy-listener")?
                        .parse()
                        .map_err(|err| format!("invalid --socks-proxy-listener: {err}"))?;
                }
                other => return Err(format!("unknown argument '{other}'")),
            }
        }
        if setup.mtu < 576 {
            return Err("MTU below IPv4 minimum is unsupported".to_string());
        }
        if !configure_only && !print_plan && target_argv.is_empty() {
            return Err(
                "target argv required unless --configure-only or --print-plan is used".to_string(),
            );
        }
        Ok(Self {
            setup,
            target_argv,
            print_plan,
            configure_only,
            no_default_route,
        })
    }
}

fn run(raw_args: Vec<String>) -> Result<(), String> {
    let args = SetupArgs::parse(raw_args)?;
    if args.print_plan {
        println!("{}", plan_json(&args));
        return Ok(());
    }

    configure_tun(&args)?;
    emit_setup_environment(&args.setup);

    if args.configure_only {
        return Ok(());
    }

    exec_target(&args.target_argv)
}

fn configure_tun(args: &SetupArgs) -> Result<(), String> {
    run_ip(&["tuntap", "add", "dev", &args.setup.tun_name, "mode", "tun"])?;
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", args.setup.sandbox_ip, args.setup.prefix_len),
        "dev",
        &args.setup.tun_name,
    ])?;
    run_ip(&[
        "link",
        "set",
        "dev",
        &args.setup.tun_name,
        "mtu",
        &args.setup.mtu.to_string(),
        "up",
    ])?;
    if !args.no_default_route {
        run_ip(&["route", "replace", "default", "dev", &args.setup.tun_name])?;
    }
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let ip_path = env::var("FOXPROX_IP_PATH").unwrap_or_else(|_| "/usr/bin/ip".to_string());
    let command_line = std::iter::once(ip_path.clone())
        .chain(args.iter().map(|arg| arg.to_string()))
        .map(|part| shell_quote(&part))
        .collect::<Vec<_>>()
        .join(" ");
    let output = Command::new("/bin/sh")
        .current_dir("/")
        .args(["-c", &command_line])
        .output()
        .map_err(|err| format!("failed to execute /bin/sh for {ip_path}: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {} failed with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn emit_setup_environment(setup: &TunSetupConfig) {
    for (key, value) in setup.proxy_environment() {
        println!("export {key}={}", shell_quote(&value));
    }
    println!(
        "export FOXPROX_DNS={}",
        shell_quote(&setup.dns_listener.to_string())
    );
}

#[cfg(unix)]
fn exec_target(target_argv: &[String]) -> Result<(), String> {
    let mut command = Command::new(&target_argv[0]);
    command.args(&target_argv[1..]);
    let err = command.exec();
    Err(format!("failed to exec target: {err}"))
}

#[cfg(not(unix))]
fn exec_target(_target_argv: &[String]) -> Result<(), String> {
    Err("foxproxsetup target exec is only supported on Unix".to_string())
}

fn plan_json(args: &SetupArgs) -> String {
    let env = args
        .setup
        .proxy_environment()
        .into_iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", json_escape(&key), json_escape(&value)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"tun_name\":\"{}\",\"sandbox_ip\":\"{}/{}\",\"broker_ip\":\"{}\",\"mtu\":{},\"dns_listener\":\"{}\",\"configure_only\":{},\"no_default_route\":{},\"proxy_environment\":{{{}}},\"target_argv\":[{}]}}",
        json_escape(&args.setup.tun_name),
        args.setup.sandbox_ip,
        args.setup.prefix_len,
        args.setup.broker_ip,
        args.setup.mtu,
        args.setup.dns_listener,
        args.configure_only,
        args.no_default_route,
        env,
        args.target_argv.iter().map(|arg| format!("\"{}\"", json_escape(arg))).collect::<Vec<_>>().join(",")
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "usage: foxproxsetup [setup options] [--configure-only|--print-plan] -- target args..."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_setup_args_with_target() {
        let args = SetupArgs::parse(vec![
            "--tun-name".to_string(),
            "fx0".to_string(),
            "--sandbox-ip".to_string(),
            "10.9.0.2/24".to_string(),
            "--".to_string(),
            "true".to_string(),
        ])
        .unwrap();
        assert_eq!(args.setup.tun_name, "fx0");
        assert_eq!(args.setup.prefix_len, 24);
        assert_eq!(args.target_argv, vec!["true"]);
    }

    #[test]
    fn print_plan_does_not_require_target() {
        let args = SetupArgs::parse(vec!["--print-plan".to_string()]).unwrap();
        assert!(args.print_plan);
        assert!(plan_json(&args).contains("HTTP_PROXY"));
    }

    #[test]
    fn rejects_missing_target_for_real_exec() {
        assert!(SetupArgs::parse(Vec::new()).is_err());
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
