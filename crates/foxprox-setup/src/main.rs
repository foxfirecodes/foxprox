use caps::{CapSet, Capability};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, IoSlice, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

#[derive(Debug)]
struct SetupArgs {
    setup_socket: String,
    ifname: String,
    sandbox_ip: Ipv4Addr,
    prefix_len: u8,
    broker_ip: Ipv4Addr,
    mtu: u16,
    keep_cap_net_raw: bool,
    target: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("foxproxsetup: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args = parse_args(env::args().skip(1))?;
    validate_ifname(&args.ifname)?;
    let tun = create_tun(&args.ifname)?;
    configure_network(&args)?;

    let mut stream = UnixStream::connect(&args.setup_socket)?;
    send_fd(&stream, tun.as_raw_fd())?;
    writeln!(
        stream,
        "ok ifname={} sandbox_ip={}/{} broker_ip={} mtu={}",
        args.ifname, args.sandbox_ip, args.prefix_len, args.broker_ip, args.mtu
    )?;
    wait_for_broker_ready(&mut stream)?;
    drop(tun);
    drop(stream);

    drop_setup_capabilities(args.keep_cap_net_raw)?;
    exec_target(args.target)
}

fn parse_args<I>(mut args: I) -> io::Result<SetupArgs>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut ifname = "foxprox0".to_string();
    let mut sandbox_ip = Ipv4Addr::new(10, 255, 0, 2);
    let mut prefix_len = 24;
    let mut broker_ip = Ipv4Addr::new(10, 255, 0, 1);
    let mut mtu = 1500;
    let mut keep_cap_net_raw = false;
    let mut target = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--ifname" => ifname = required_value(&mut args, "--ifname")?,
            "--sandbox-ip" => {
                sandbox_ip = parse_value(&required_value(&mut args, "--sandbox-ip")?)?
            }
            "--prefix-len" => {
                prefix_len = parse_value(&required_value(&mut args, "--prefix-len")?)?
            }
            "--broker-ip" => broker_ip = parse_value(&required_value(&mut args, "--broker-ip")?)?,
            "--mtu" => mtu = parse_value(&required_value(&mut args, "--mtu")?)?,
            "--keep-cap-net-raw-for-ping" => keep_cap_net_raw = true,
            "--" => {
                target.extend(args);
                break;
            }
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    if target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing target command\n{}", usage()),
        ));
    }

    Ok(SetupArgs {
        setup_socket: setup_socket.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                    usage()
                ),
            )
        })?,
        ifname,
        sandbox_ip,
        prefix_len,
        broker_ip,
        mtu,
        keep_cap_net_raw,
        target,
    })
}

fn required_value<I>(args: &mut I, flag: &str) -> io::Result<String>
where
    I: Iterator<Item = String>,
{
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn parse_value<T>(value: &str) -> io::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid value {value:?}: {error}"),
        )
    })
}

fn usage() -> &'static str {
    "usage: foxproxsetup --setup-socket PATH [--ifname foxprox0] [--sandbox-ip 10.255.0.2] [--prefix-len 24] [--broker-ip 10.255.0.1] [--mtu 1500] [--keep-cap-net-raw-for-ping] -- target args..."
}

fn validate_ifname(ifname: &str) -> io::Result<()> {
    if ifname.is_empty() || ifname.len() >= IFNAMSIZ || ifname.bytes().any(|byte| byte == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TUN interface name {ifname:?}"),
        ));
    }
    Ok(())
}

fn create_tun(ifname: &str) -> io::Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let fd = file.into_raw_fd();
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut ifreq = IfReq {
        name: [0; IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        padding: [0; 22],
    };
    for (slot, byte) in ifreq.name.iter_mut().zip(ifname.bytes()) {
        *slot = byte as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF, &mut ifreq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

fn configure_network(args: &SetupArgs) -> io::Result<()> {
    run_ip(["link", "set", "lo", "up"])?;
    run_ip([
        "addr",
        "add",
        &format!("{}/{}", args.sandbox_ip, args.prefix_len),
        "dev",
        &args.ifname,
    ])?;
    run_ip([
        "link",
        "set",
        "dev",
        &args.ifname,
        "mtu",
        &args.mtu.to_string(),
    ])?;
    run_ip(["link", "set", "dev", &args.ifname, "up"])?;
    run_ip(["route", "add", "default", "dev", &args.ifname])?;
    Ok(())
}

fn run_ip<const N: usize>(args: [&str; N]) -> io::Result<()> {
    let status = Command::new("/usr/bin/ip")
        .env_clear()
        .args(args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("ip command failed with {status}")))
    }
}

fn send_fd(stream: &UnixStream, fd_to_send: RawFd) -> io::Result<()> {
    let iov = [IoSlice::new(b"tun-fd")];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .map(|_| ())
        .map_err(io::Error::other)
}

fn wait_for_broker_ready(stream: &mut UnixStream) -> io::Result<()> {
    let mut ack = [0_u8; 6];
    stream.read_exact(&mut ack)?;
    if &ack == b"ready\n" {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected broker ack: {:?}", String::from_utf8_lossy(&ack)),
        ))
    }
}

fn drop_setup_capabilities(keep_cap_net_raw: bool) -> io::Result<()> {
    for set in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        for capability in caps::read(None, set).map_err(io::Error::other)? {
            if keep_cap_net_raw && capability == Capability::CAP_NET_RAW {
                continue;
            }
            caps::drop(None, set, capability).map_err(io::Error::other)?;
        }
    }

    if let Ok(bounding) = caps::read(None, CapSet::Bounding) {
        for capability in bounding {
            if keep_cap_net_raw && capability == Capability::CAP_NET_RAW {
                continue;
            }
            let _ = caps::drop(None, CapSet::Bounding, capability);
        }
    }

    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn exec_target(target: Vec<String>) -> io::Result<()> {
    let mut command = Command::new(&target[0]);
    command.args(&target[1..]);
    close_unneeded_fds();
    Err(command.exec())
}

fn close_unneeded_fds() {
    for fd in 3..1024 {
        unsafe {
            libc::close(fd);
        }
    }
}
