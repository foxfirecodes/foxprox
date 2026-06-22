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

struct ConfiguredTun {
    raw_fd: i32,
}

impl ConfiguredTun {
    fn raw_fd(&self) -> i32 {
        self.raw_fd
    }
}

#[cfg(unix)]
impl Drop for ConfiguredTun {
    fn drop(&mut self) {
        linux_tun::close_fd(self.raw_fd);
    }
}

fn configure_tun(args: &SetupArgs) -> Result<ConfiguredTun, String> {
    linux_tun::configure_tun(&args.setup, !args.no_default_route)
}

#[cfg(unix)]
fn send_tun_fd(socket_path: &str, fd: i32) -> Result<(), String> {
    linux_tun::send_fd(socket_path, fd)
}

#[cfg(not(unix))]
fn send_tun_fd(_socket_path: &str, _fd: i32) -> Result<(), String> {
    Err("TUN fd handoff is only supported on Unix".to_string())
}

#[cfg(unix)]
fn drop_setup_capabilities() -> Result<(), String> {
    linux_tun::drop_net_admin_capability()
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

#[cfg(unix)]
mod linux_tun {
    use std::fs::OpenOptions;
    use std::io;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
    use std::os::raw::{c_char, c_int, c_short, c_ulong, c_void};

    use foxprox_core::integration::TunSetupConfig;

    const IFNAMSIZ: usize = 16;
    const AF_INET: c_int = 2;
    const SOCK_DGRAM: c_int = 2;

    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;
    const IFF_UP: c_short = 0x0001;
    const IFF_RUNNING: c_short = 0x0040;

    const TUNSETIFF: c_ulong = 0x4004_54ca;
    const SIOCGIFFLAGS: c_ulong = 0x8913;
    const SIOCSIFFLAGS: c_ulong = 0x8914;
    const SIOCSIFADDR: c_ulong = 0x8916;
    const SIOCSIFNETMASK: c_ulong = 0x891c;
    const SIOCSIFMTU: c_ulong = 0x8922;
    const SIOCADDRT: c_ulong = 0x890b;

    const RTF_UP: u16 = 0x0001;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockAddr {
        sa_family: u16,
        sa_data: [u8; 14],
    }

    #[repr(C)]
    union IfReqData {
        addr: SockAddr,
        flags: c_short,
        mtu: c_int,
    }

    #[repr(C)]
    struct IfReq {
        name: [c_char; IFNAMSIZ],
        data: IfReqData,
    }

    #[repr(C)]
    struct RtEntry {
        rt_pad1: c_ulong,
        rt_dst: SockAddr,
        rt_gateway: SockAddr,
        rt_genmask: SockAddr,
        rt_flags: u16,
        rt_pad2: c_short,
        rt_pad3: c_ulong,
        rt_pad4: *mut c_void,
        rt_metric: c_short,
        rt_dev: *mut c_char,
        rt_mtu: c_ulong,
        rt_window: c_ulong,
        rt_irtt: u16,
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    pub(super) fn configure_tun(
        setup: &TunSetupConfig,
        install_default_route: bool,
    ) -> Result<super::ConfiguredTun, String> {
        let tun_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|err| format!("failed to open /dev/net/tun: {err}"))?;
        let tun_fd = tun_file.as_raw_fd();
        create_tun(tun_fd, &setup.tun_name)?;
        let ctl_fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if ctl_fd < 0 {
            return Err(format!(
                "failed to open AF_INET control socket: {}",
                io::Error::last_os_error()
            ));
        }
        let control = FdGuard(ctl_fd);
        set_addr(control.0, &setup.tun_name, setup.sandbox_ip)?;
        set_netmask(control.0, &setup.tun_name, setup.prefix_len)?;
        set_mtu(control.0, &setup.tun_name, setup.mtu)?;
        set_up(control.0, &setup.tun_name)?;
        if install_default_route {
            add_default_route(control.0, &setup.tun_name)?;
        }
        Ok(super::ConfiguredTun {
            raw_fd: tun_file.into_raw_fd(),
        })
    }

    pub(super) fn close_fd(fd: RawFd) {
        foxprox_device::fd::close_fd(fd);
    }

    pub(super) fn send_fd(socket_path: &str, fd_to_send: RawFd) -> Result<(), String> {
        foxprox_device::fd::send_fd_to_unix_socket(socket_path, fd_to_send)
            .map_err(|err| err.replace("fd", "TUN fd"))
    }

    pub(super) fn drop_net_admin_capability() -> Result<(), String> {
        foxprox_device::caps::drop_net_admin_capability()
    }

    struct FdGuard(RawFd);

    impl Drop for FdGuard {
        fn drop(&mut self) {
            close_fd(self.0);
        }
    }

    fn create_tun(fd: RawFd, name: &str) -> Result<(), String> {
        let mut ifr = ifreq_flags(name, IFF_TUN | IFF_NO_PI)?;
        ioctl_check(fd, TUNSETIFF, &mut ifr, "TUNSETIFF")
    }

    fn set_addr(fd: RawFd, name: &str, ip: IpAddr) -> Result<(), String> {
        let mut ifr = ifreq_addr(name, ip)?;
        ioctl_check(fd, SIOCSIFADDR, &mut ifr, "SIOCSIFADDR")
    }

    fn set_netmask(fd: RawFd, name: &str, prefix_len: u8) -> Result<(), String> {
        if prefix_len > 32 {
            return Err(
                "only IPv4 prefix lengths up to /32 are supported for alpha TUN setup".to_string(),
            );
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX.checked_shl((32 - prefix_len) as u32).unwrap_or(0)
        };
        let mut ifr = ifreq_addr(name, IpAddr::from(mask.to_be_bytes()))?;
        ioctl_check(fd, SIOCSIFNETMASK, &mut ifr, "SIOCSIFNETMASK")
    }

    fn set_mtu(fd: RawFd, name: &str, mtu: u16) -> Result<(), String> {
        let mut ifr = ifreq_mtu(name, i32::from(mtu))?;
        ioctl_check(fd, SIOCSIFMTU, &mut ifr, "SIOCSIFMTU")
    }

    fn set_up(fd: RawFd, name: &str) -> Result<(), String> {
        let mut ifr = ifreq_flags(name, 0)?;
        ioctl_check(fd, SIOCGIFFLAGS, &mut ifr, "SIOCGIFFLAGS")?;
        let current = unsafe { ifr.data.flags };
        ifr.data.flags = current | IFF_UP | IFF_RUNNING;
        ioctl_check(fd, SIOCSIFFLAGS, &mut ifr, "SIOCSIFFLAGS")
    }

    fn add_default_route(fd: RawFd, name: &str) -> Result<(), String> {
        let mut name = interface_name(name)?;
        let mut route = RtEntry {
            rt_pad1: 0,
            rt_dst: sockaddr_v4([0, 0, 0, 0]),
            rt_gateway: sockaddr_v4([0, 0, 0, 0]),
            rt_genmask: sockaddr_v4([0, 0, 0, 0]),
            rt_flags: RTF_UP,
            rt_pad2: 0,
            rt_pad3: 0,
            rt_pad4: std::ptr::null_mut(),
            rt_metric: 0,
            rt_dev: name.as_mut_ptr(),
            rt_mtu: 0,
            rt_window: 0,
            rt_irtt: 0,
        };
        let rc = unsafe { ioctl(fd, SIOCADDRT, &mut route) };
        if rc == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(17) {
                Ok(())
            } else {
                Err(format!("SIOCADDRT default dev route failed: {err}"))
            }
        }
    }

    fn ioctl_check(
        fd: RawFd,
        request: c_ulong,
        ifr: &mut IfReq,
        label: &str,
    ) -> Result<(), String> {
        let rc = unsafe { ioctl(fd, request, ifr) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("{label} failed: {}", io::Error::last_os_error()))
        }
    }

    fn ifreq_flags(name: &str, flags: c_short) -> Result<IfReq, String> {
        let mut ifr = ifreq_empty(name)?;
        ifr.data.flags = flags;
        Ok(ifr)
    }

    fn ifreq_addr(name: &str, ip: IpAddr) -> Result<IfReq, String> {
        let mut ifr = ifreq_empty(name)?;
        let IpAddr::V4(ip) = ip else {
            return Err("alpha TUN setup currently supports IPv4 addresses only".to_string());
        };
        ifr.data.addr = sockaddr_v4(ip.octets());
        Ok(ifr)
    }

    fn ifreq_mtu(name: &str, mtu: c_int) -> Result<IfReq, String> {
        let mut ifr = ifreq_empty(name)?;
        ifr.data.mtu = mtu;
        Ok(ifr)
    }

    fn ifreq_empty(name: &str) -> Result<IfReq, String> {
        Ok(IfReq {
            name: interface_name(name)?,
            data: IfReqData { flags: 0 },
        })
    }

    fn interface_name(name: &str) -> Result<[c_char; IFNAMSIZ], String> {
        let bytes = name.as_bytes();
        if bytes.is_empty() {
            return Err("TUN interface name must not be empty".to_string());
        }
        if bytes.len() >= IFNAMSIZ {
            return Err(format!("TUN interface name '{name}' is too long"));
        }
        let mut out = [0 as c_char; IFNAMSIZ];
        for (idx, byte) in bytes.iter().enumerate() {
            out[idx] = *byte as c_char;
        }
        Ok(out)
    }

    fn sockaddr_v4(octets: [u8; 4]) -> SockAddr {
        let mut sa_data = [0_u8; 14];
        sa_data[2..6].copy_from_slice(&octets);
        SockAddr {
            sa_family: AF_INET as u16,
            sa_data,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_overlong_interface_names() {
            assert!(interface_name("123456789012345").is_ok());
            assert!(interface_name("1234567890123456").is_err());
        }

        #[test]
        fn sockaddr_v4_places_ipv4_octets_after_port() {
            let addr = sockaddr_v4([10, 0, 2, 2]);
            assert_eq!(addr.sa_family, AF_INET as u16);
            assert_eq!(&addr.sa_data[2..6], &[10, 0, 2, 2]);
        }
    }
}

#[cfg(not(unix))]
mod linux_tun {
    use foxprox_core::integration::TunSetupConfig;

    pub(super) fn configure_tun(
        _setup: &TunSetupConfig,
        _install_default_route: bool,
    ) -> Result<super::ConfiguredTun, String> {
        Err("foxproxsetup direct TUN configuration is only supported on Unix/Linux".to_string())
    }
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
