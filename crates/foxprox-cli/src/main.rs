use foxprox_core::SandboxId;
use foxprox_device::{
    parse_icmpv4_metadata, parse_ipv4_metadata, synthesize_icmpv4_echo_reply,
    unsupported_event_for_drop,
};
use foxprox_net::{
    run_tcp_proof_with_ready, run_udp_dns_proof_with_ready, TcpProofConfig, UdpDnsProofConfig,
};
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use std::env;
use std::fs::{self, File};
use std::io::{self, IoSliceMut, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

fn main() {
    if let Err(error) = run() {
        eprintln!("foxprox: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("proof-icmp") => proof_icmp(args),
        Some("proof-tcp") => proof_tcp(args),
        Some("proof-udp-dns") => proof_udp_dns(args),
        Some("--help" | "-h") | None => Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command {other:?}\n{}", usage()),
        )),
    }
}

fn usage() -> &'static str {
    "usage: foxprox proof-icmp --setup-socket PATH [--local-ip 10.255.0.1]\n       foxprox proof-tcp --setup-socket PATH [--broker-ip 10.255.0.1] [--prefix-len 24] [--mtu 1500] [--tcp-port 80]\n       foxprox proof-udp-dns --setup-socket PATH [--broker-ip 10.255.0.1] [--prefix-len 24] [--mtu 1500] [--upstream-dns 1.1.1.1:53] [--udp-forward-port PORT]..."
}

fn proof_icmp<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut local_ip = Ipv4Addr::new(10, 255, 0, 1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--local-ip" => local_ip = parse_value(&required_value(&mut args, "--local-ip")?)?,
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = UnixListener::bind(&setup_socket)?;
    fs::set_permissions(&setup_socket, fs::Permissions::from_mode(0o600))?;
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    stream.write_all(b"ready\n")?;
    eprintln!("foxprox: received TUN fd; local ICMP proof address is {local_ip}");

    let mut tun = unsafe { File::from_raw_fd(tun_fd.into_raw_fd()) };
    let mut buffer = vec![0_u8; 4096];
    loop {
        let len = tun.read(&mut buffer)?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN fd reached EOF",
            ));
        }
        let packet = &buffer[..len];
        match parse_ipv4_metadata(packet) {
            Ok(ipv4) => {
                eprintln!(
                    "foxprox: packet len={} src={} dst={} proto={}",
                    ipv4.total_len, ipv4.source, ipv4.destination, ipv4.protocol
                );
                if let Ok(icmp) = parse_icmpv4_metadata(packet, ipv4) {
                    eprintln!("foxprox: icmp type={} code={}", icmp.ty, icmp.code);
                }
            }
            Err(reason) => {
                eprintln!(
                    "foxprox: drop malformed/unsupported packet: {:?}",
                    unsupported_event_for_drop(None, reason.clone())
                );
            }
        }

        match synthesize_icmpv4_echo_reply(packet, local_ip) {
            Ok(reply) => {
                tun.write_all(&reply)?;
                eprintln!("foxprox: wrote ICMP echo reply len={}", reply.len());
            }
            Err(reason) => {
                eprintln!("foxprox: no reply: {reason:?}");
            }
        }
    }
}

fn proof_tcp<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut config = TcpProofConfig::new(SandboxId::new("proof-tcp").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox id: {error}"),
        )
    })?);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--broker-ip" => {
                config.broker_ip = parse_value(&required_value(&mut args, "--broker-ip")?)?
            }
            "--prefix-len" => {
                config.prefix_len = parse_value(&required_value(&mut args, "--prefix-len")?)?
            }
            "--mtu" => config.mtu = parse_value(&required_value(&mut args, "--mtu")?)?,
            "--tcp-port" => {
                config.tcp_port = parse_value(&required_value(&mut args, "--tcp-port")?)?
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

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = UnixListener::bind(&setup_socket)?;
    fs::set_permissions(&setup_socket, fs::Permissions::from_mode(0o600))?;
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    eprintln!(
        "foxprox: received TUN fd; starting TCP proof on port {}",
        config.tcp_port
    );
    run_tcp_proof_with_ready(tun_fd, config, || stream.write_all(b"ready\n"))
}

fn proof_udp_dns<I>(mut args: I) -> io::Result<()>
where
    I: Iterator<Item = String>,
{
    let mut setup_socket = env::var("FOXPROX_SETUP_SOCKET").ok();
    let mut config = UdpDnsProofConfig::new(SandboxId::new("proof-udp-dns").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox id: {error}"),
        )
    })?);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup-socket" => setup_socket = Some(required_value(&mut args, "--setup-socket")?),
            "--broker-ip" => {
                config.broker_ip = parse_value(&required_value(&mut args, "--broker-ip")?)?
            }
            "--prefix-len" => {
                config.prefix_len = parse_value(&required_value(&mut args, "--prefix-len")?)?
            }
            "--mtu" => config.mtu = parse_value(&required_value(&mut args, "--mtu")?)?,
            "--upstream-dns" => {
                config.upstream_dns =
                    parse_socket_addr(&required_value(&mut args, "--upstream-dns")?)?
            }
            "--udp-forward-port" => config.udp_forward_ports.push(parse_value(&required_value(
                &mut args,
                "--udp-forward-port",
            )?)?),
            "--help" | "-h" => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected argument {other:?}\n{}", usage()),
                ));
            }
        }
    }

    let setup_socket = setup_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "missing --setup-socket or FOXPROX_SETUP_SOCKET\n{}",
                usage()
            ),
        )
    })?;

    let listener = UnixListener::bind(&setup_socket)?;
    fs::set_permissions(&setup_socket, fs::Permissions::from_mode(0o600))?;
    eprintln!("foxprox: waiting for foxproxsetup on {setup_socket}");
    let (mut stream, _) = listener.accept()?;
    verify_peer_credentials(&stream)?;
    let tun_fd = recv_fd(stream.as_raw_fd())?;
    eprintln!(
        "foxprox: received TUN fd; starting UDP/DNS proof broker_dns={}:{} upstream={}",
        config.broker_ip, config.dns_port, config.upstream_dns
    );
    run_udp_dns_proof_with_ready(tun_fd, config, || stream.write_all(b"ready\n"))
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

fn parse_socket_addr(value: &str) -> io::Result<SocketAddr> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid socket address {value:?}: {error}"),
        )
    })
}

fn verify_peer_credentials(stream: &UnixStream) -> io::Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let uid = unsafe { libc::geteuid() };
    if credentials.uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "setup peer uid {} did not match broker uid {uid}",
                credentials.uid
            ),
        ));
    }
    Ok(())
}

fn recv_fd(socket_fd: RawFd) -> io::Result<OwnedFd> {
    let mut data = [0_u8; 64];
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        socket_fd,
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )
    .map_err(io::Error::other)?;
    for cmsg in msg.cmsgs().map_err(io::Error::other)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if fds.len() != 1 {
                for fd in fds {
                    unsafe {
                        libc::close(fd);
                    }
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SCM_RIGHTS message did not contain exactly one fd",
                ));
            }
            return Ok(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "setup message did not contain a TUN fd",
    ))
}
