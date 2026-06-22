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
    handoff_env: String,
}

impl SetupArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut setup = TunSetupConfig::alpha_default();
        let mut print_plan = false;
        let mut configure_only = false;
        let mut no_default_route = false;
        let mut handoff_env = "FOXPROX_SETUP_SOCKET".to_string();
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
                "--handoff-env" => handoff_env = next_value(&mut iter, "--handoff-env")?,
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
            handoff_env,
        })
    }
}

fn run(raw_args: Vec<String>) -> Result<(), String> {
    let args = SetupArgs::parse(raw_args)?;
    if args.print_plan {
        println!("{}", plan_json(&args));
        return Ok(());
    }

    let tun = configure_tun(&args)?;
    emit_setup_environment(&args.setup);

    if args.configure_only {
        return Ok(());
    }

    let socket_path = env::var(&args.handoff_env).map_err(|_| {
        format!(
            "target exec requires TUN fd handoff; set {} or use --configure-only",
            args.handoff_env
        )
    })?;
    send_tun_fd(&socket_path, tun.raw_fd())?;
    drop_setup_capabilities()?;
    drop(tun);

    exec_target(&args.target_argv)
}

#[cfg(unix)]
type ConfiguredTun = foxprox_device::linux_tun::ConfiguredTun;

#[cfg(not(unix))]
type ConfiguredTun = foxprox_device::linux_tun::ConfiguredTun;

fn configure_tun(args: &SetupArgs) -> Result<ConfiguredTun, String> {
    let config = foxprox_device::linux_tun::TunConfig {
        tun_name: args.setup.tun_name.clone(),
        sandbox_ip: args.setup.sandbox_ip,
        prefix_len: args.setup.prefix_len,
        mtu: args.setup.mtu,
        install_default_route: !args.no_default_route,
    };
    foxprox_device::linux_tun::configure_tun(&config)
}

#[cfg(unix)]
fn send_tun_fd(socket_path: &str, fd: i32) -> Result<(), String> {
    foxprox_device::fd::send_fd_to_unix_socket(socket_path, fd)
        .map_err(|err| err.replace("fd", "TUN fd"))
}

#[cfg(not(unix))]
fn send_tun_fd(_socket_path: &str, _fd: i32) -> Result<(), String> {
    Err("TUN fd handoff is only supported on Unix".to_string())
}

#[cfg(unix)]
fn drop_setup_capabilities() -> Result<(), String> {
    foxprox_device::caps::drop_net_admin_capability()
}

#[cfg(not(unix))]
fn drop_setup_capabilities() -> Result<(), String> {
    Err("setup capability drop is only supported on Unix".to_string())
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
        "{{\"tun_name\":\"{}\",\"sandbox_ip\":\"{}/{}\",\"broker_ip\":\"{}\",\"mtu\":{},\"dns_listener\":\"{}\",\"configure_only\":{},\"no_default_route\":{},\"handoff_env\":\"{}\",\"proxy_environment\":{{{}}},\"target_argv\":[{}]}}",
        json_escape(&args.setup.tun_name),
        args.setup.sandbox_ip,
        args.setup.prefix_len,
        args.setup.broker_ip,
        args.setup.mtu,
        args.setup.dns_listener,
        args.configure_only,
        args.no_default_route,
        json_escape(&args.handoff_env),
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
            "--handoff-env".to_string(),
            "FX_SOCK".to_string(),
            "--".to_string(),
            "true".to_string(),
        ])
        .unwrap();
        assert_eq!(args.setup.tun_name, "fx0");
        assert_eq!(args.setup.prefix_len, 24);
        assert_eq!(args.handoff_env, "FX_SOCK");
        assert_eq!(args.target_argv, vec!["true"]);
    }

    #[test]
    fn print_plan_does_not_require_target() {
        let args = SetupArgs::parse(vec!["--print-plan".to_string()]).unwrap();
        assert!(args.print_plan);
        assert!(plan_json(&args).contains("HTTP_PROXY"));
        assert!(plan_json(&args).contains("handoff_env"));
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
