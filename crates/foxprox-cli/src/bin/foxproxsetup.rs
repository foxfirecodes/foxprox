use std::env;
use std::ffi::OsString;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

use foxprox_device::{configure_tun_interface, create_tun, IpCommandRunner, TunConfig, TunSetup};
use foxprox_integrations::send_fd;

fn main() {
    if let Err(error) = run(env::args_os().skip(1).collect()) {
        eprintln!("foxproxsetup: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    let config = SetupArgs::parse(args)?;
    let tun = create_tun(
        &TunConfig::new(config.tun_name.clone())
            .map_err(|error| format!("invalid tun name: {error:?}"))?,
    )
    .map_err(|error| format!("create tun: {error:?}"))?;
    let setup = TunSetup::new(
        config.tun_name,
        config.address_cidr,
        config.route_cidr,
        config.mtu,
    )
    .map_err(|error| format!("invalid tun setup: {error:?}"))?;
    configure_tun_interface(&setup, &mut IpCommandRunner)
        .map_err(|error| format!("configure tun: {error:?}"))?;

    // SAFETY: `control_fd` is provided by the trusted launcher as an inherited
    // Unix stream fd. Ownership is transferred here so it is closed before exec.
    let control = unsafe { UnixStream::from_raw_fd(config.control_fd) };
    send_fd(&control, tun.raw_fd()).map_err(|error| format!("send tun fd: {error:?}"))?;
    drop(tun);
    drop(control);

    drop_setup_privileges().map_err(|error| format!("drop setup privileges: {error}"))?;

    let mut command = Command::new(&config.target[0]);
    command.args(&config.target[1..]);
    Err(command.exec().to_string())
}

#[derive(Debug, Eq, PartialEq)]
struct SetupArgs {
    control_fd: RawFd,
    tun_name: String,
    address_cidr: String,
    route_cidr: String,
    mtu: u16,
    target: Vec<OsString>,
}

impl SetupArgs {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut control_fd = None;
        let mut tun_name = Some("fp0".to_string());
        let mut address_cidr = Some("10.0.0.1/24".to_string());
        let mut route_cidr = Some("0.0.0.0/0".to_string());
        let mut mtu = Some(1300_u16);
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].to_string_lossy();
            if arg == "--" {
                let target = args[index + 1..].to_vec();
                if target.is_empty() {
                    return Err("missing target after --".into());
                }
                return Ok(Self {
                    control_fd: control_fd.ok_or("missing --control-fd")?,
                    tun_name: tun_name.take().ok_or("missing --tun-name")?,
                    address_cidr: address_cidr.take().ok_or("missing --address")?,
                    route_cidr: route_cidr.take().ok_or("missing --route")?,
                    mtu: mtu.take().ok_or("missing --mtu")?,
                    target,
                });
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_ref() {
                "--control-fd" => {
                    let parsed: i32 = value
                        .to_string_lossy()
                        .parse()
                        .map_err(|_| "invalid --control-fd".to_string())?;
                    if parsed < 0 {
                        return Err("invalid --control-fd".into());
                    }
                    control_fd = Some(parsed);
                }
                "--tun-name" => tun_name = Some(value.to_string_lossy().into_owned()),
                "--address" => address_cidr = Some(value.to_string_lossy().into_owned()),
                "--route" => route_cidr = Some(value.to_string_lossy().into_owned()),
                "--mtu" => {
                    mtu = Some(
                        value
                            .to_string_lossy()
                            .parse()
                            .map_err(|_| "invalid --mtu".to_string())?,
                    );
                }
                _ => return Err(format!("unknown argument {arg}")),
            }
            index += 2;
        }
        Err("missing -- target separator".into())
    }
}

fn drop_setup_privileges() -> Result<(), String> {
    // SAFETY: prctl PR_SET_NO_NEW_PRIVS affects only the current process and
    // prevents future exec from gaining new privileges.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_control_fd_and_target_separator() {
        let parsed = SetupArgs::parse(vec![
            "--control-fd".into(),
            "7".into(),
            "--tun-name".into(),
            "fp-test".into(),
            "--address".into(),
            "10.0.0.1/24".into(),
            "--route".into(),
            "0.0.0.0/0".into(),
            "--mtu".into(),
            "1400".into(),
            "--".into(),
            "true".into(),
        ])
        .unwrap();

        assert_eq!(parsed.control_fd, 7);
        assert_eq!(parsed.tun_name, "fp-test");
        assert_eq!(parsed.mtu, 1400);
        assert_eq!(parsed.target, vec![OsString::from("true")]);
    }

    #[test]
    fn rejects_missing_control_fd_or_target() {
        assert!(SetupArgs::parse(vec!["--".into(), "true".into()]).is_err());
        assert!(SetupArgs::parse(vec!["--control-fd".into(), "3".into()]).is_err());
        assert!(SetupArgs::parse(vec![
            "--control-fd".into(),
            "-1".into(),
            "--".into(),
            "true".into(),
        ])
        .is_err());
    }
}
