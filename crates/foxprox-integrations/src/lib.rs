//! Integration backend helpers for foxprox.
//!
//! This crate owns launcher/setup command contracts such as the bwrap-compatible
//! `foxproxsetup` wrapper shape. It does not execute commands or import broker
//! core internals.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::path::{Path, PathBuf};

/// Proxy listener addresses that callers can inject into the sandbox process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEnvironment {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub all_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

impl ProxyEnvironment {
    pub fn none() -> Self {
        Self {
            http_proxy: None,
            https_proxy: None,
            all_proxy: None,
            no_proxy: None,
        }
    }

    pub fn loopback_http_socks(
        http_addr: impl Into<String>,
        socks_addr: impl Into<String>,
    ) -> Self {
        let http_addr = http_addr.into();
        let socks_addr = socks_addr.into();
        Self {
            http_proxy: Some(format!("http://{http_addr}")),
            https_proxy: Some(format!("http://{http_addr}")),
            all_proxy: Some(format!("socks5://{socks_addr}")),
            no_proxy: Some("localhost,127.0.0.1,::1".to_owned()),
        }
    }

    fn append_bwrap_env_args(&self, args: &mut Vec<String>) {
        for (name, value) in [
            ("HTTP_PROXY", self.http_proxy.as_ref()),
            ("HTTPS_PROXY", self.https_proxy.as_ref()),
            ("ALL_PROXY", self.all_proxy.as_ref()),
            ("NO_PROXY", self.no_proxy.as_ref()),
        ] {
            if let Some(value) = value {
                args.push("--setenv".to_owned());
                args.push(name.to_owned());
                args.push(value.clone());
            }
        }
    }
}

/// Inputs for a bwrap-compatible foxprox network setup launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwrapSetupConfig {
    pub bwrap_program: PathBuf,
    pub setup_program: PathBuf,
    pub target_argv: Vec<String>,
    pub proxy_environment: ProxyEnvironment,
}

impl BwrapSetupConfig {
    pub fn new(
        bwrap_program: impl Into<PathBuf>,
        setup_program: impl Into<PathBuf>,
        target_argv: Vec<String>,
    ) -> Self {
        Self {
            bwrap_program: bwrap_program.into(),
            setup_program: setup_program.into(),
            target_argv,
            proxy_environment: ProxyEnvironment::none(),
        }
    }

    pub fn with_proxy_environment(mut self, proxy_environment: ProxyEnvironment) -> Self {
        self.proxy_environment = proxy_environment;
        self
    }
}

/// A validated command plan. `program` is executed with `args` by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl CommandPlan {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.display().to_string());
        argv.extend(self.args.clone());
        argv
    }
}

/// Integration planning errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrationPlanError {
    EmptyProgram { field: &'static str },
    EmptyTarget,
}

impl fmt::Display for IntegrationPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProgram { field } => write!(f, "integration-empty-program: {field}"),
            Self::EmptyTarget => f.write_str("integration-empty-target"),
        }
    }
}

impl std::error::Error for IntegrationPlanError {}

/// Build the documented bwrap command shape for alpha network setup.
pub fn plan_bwrap_setup(config: &BwrapSetupConfig) -> Result<CommandPlan, IntegrationPlanError> {
    validate_program("bwrap_program", &config.bwrap_program)?;
    validate_program("setup_program", &config.setup_program)?;
    if config.target_argv.is_empty() || config.target_argv[0].trim().is_empty() {
        return Err(IntegrationPlanError::EmptyTarget);
    }

    let mut args = vec![
        "--unshare-user".to_owned(),
        "--unshare-net".to_owned(),
        "--cap-add".to_owned(),
        "CAP_NET_ADMIN".to_owned(),
        "--dev-bind".to_owned(),
        "/dev/net/tun".to_owned(),
        "/dev/net/tun".to_owned(),
    ];
    config.proxy_environment.append_bwrap_env_args(&mut args);
    args.push(config.setup_program.display().to_string());
    args.push("--".to_owned());
    args.extend(config.target_argv.clone());

    Ok(CommandPlan {
        program: config.bwrap_program.clone(),
        args,
    })
}

fn validate_program(field: &'static str, path: &Path) -> Result<(), IntegrationPlanError> {
    if path.as_os_str().is_empty() {
        return Err(IntegrationPlanError::EmptyProgram { field });
    }
    Ok(())
}

#[cfg(unix)]
pub mod fd_handoff {
    //! Unix fd handoff helpers for `foxproxsetup` → broker control channels.

    use std::fmt;
    use std::io::{IoSlice, IoSliceMut};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;

    use nix::cmsg_space;
    use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};

    const HANDOFF_MARKER: &[u8] = b"foxprox-fd";

    /// File descriptor received by the broker side of the setup handoff.
    #[derive(Debug)]
    pub struct ReceivedFd {
        pub marker: Vec<u8>,
        pub fd: OwnedFd,
    }

    /// Errors from SCM_RIGHTS setup fd handoff.
    #[derive(Debug)]
    pub enum FdHandoffError {
        Send(String),
        Receive(String),
        TruncatedControlMessage,
        MissingFileDescriptor,
        UnexpectedMarker(Vec<u8>),
    }

    impl fmt::Display for FdHandoffError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Send(error) => write!(f, "fd-handoff-send-error: {error}"),
                Self::Receive(error) => write!(f, "fd-handoff-receive-error: {error}"),
                Self::TruncatedControlMessage => {
                    f.write_str("fd-handoff-truncated-control-message")
                }
                Self::MissingFileDescriptor => f.write_str("fd-handoff-missing-file-descriptor"),
                Self::UnexpectedMarker(marker) => {
                    write!(f, "fd-handoff-unexpected-marker: {:?}", marker)
                }
            }
        }
    }

    impl std::error::Error for FdHandoffError {}

    /// Send one fd from setup-helper side to broker side over a Unix stream.
    pub fn send_setup_fd(socket: &UnixStream, fd: RawFd) -> Result<(), FdHandoffError> {
        let iov = [IoSlice::new(HANDOFF_MARKER)];
        let fds = [fd];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg::<()>(socket.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)
            .map_err(|error| FdHandoffError::Send(error.to_string()))?;
        Ok(())
    }

    /// Receive one setup fd on the broker side as an owned descriptor.
    pub fn receive_setup_fd(socket: &UnixStream) -> Result<ReceivedFd, FdHandoffError> {
        let mut marker = [0_u8; HANDOFF_MARKER.len()];
        let (bytes, flags, received_fds) = {
            let mut iov = [IoSliceMut::new(&mut marker)];
            let mut cmsgspace = cmsg_space!([RawFd; 1]);
            let msg = recvmsg::<()>(
                socket.as_raw_fd(),
                &mut iov,
                Some(&mut cmsgspace),
                MsgFlags::empty(),
            )
            .map_err(|error| FdHandoffError::Receive(error.to_string()))?;

            let mut received_fds = Vec::new();
            for cmsg in msg
                .cmsgs()
                .map_err(|error| FdHandoffError::Receive(error.to_string()))?
            {
                if let ControlMessageOwned::ScmRights(fds) = cmsg {
                    received_fds.extend(fds);
                }
            }
            (msg.bytes, msg.flags, received_fds)
        };

        if flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(FdHandoffError::TruncatedControlMessage);
        }

        let received_marker = marker[..bytes].to_vec();
        if received_marker != HANDOFF_MARKER {
            return Err(FdHandoffError::UnexpectedMarker(received_marker));
        }

        let Some(first_fd) = received_fds.first().copied() else {
            return Err(FdHandoffError::MissingFileDescriptor);
        };
        let mut owned_fds: Vec<OwnedFd> = received_fds.into_iter().map(raw_fd_to_owned).collect();
        let first = owned_fds.remove(
            owned_fds
                .iter()
                .position(|fd| fd.as_raw_fd() == first_fd)
                .unwrap_or(0),
        );
        drop(owned_fds);

        Ok(ReceivedFd {
            marker: received_marker,
            fd: first,
        })
    }

    fn raw_fd_to_owned(fd: RawFd) -> OwnedFd {
        // SAFETY: `recvmsg` with SCM_RIGHTS returns fresh file descriptors owned
        // by this process. This function immediately wraps each raw descriptor
        // exactly once in `OwnedFd` so it will be closed on drop.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn setup_fd_handoff_transfers_readable_descriptor_to_broker_side() {
        use std::fs::{remove_file, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let path = std::env::temp_dir().join(format!(
            "foxprox-fd-handoff-{}-{}",
            std::process::id(),
            "proof"
        ));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(b"tun-fd-proof").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let (setup_side, broker_side) = UnixStream::pair().unwrap();

        fd_handoff::send_setup_fd(&setup_side, file.as_raw_fd()).unwrap();
        let received = fd_handoff::receive_setup_fd(&broker_side).unwrap();
        let mut received_file = std::fs::File::from(received.fd);
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();

        assert_eq!(received.marker, b"foxprox-fd".to_vec());
        assert_eq!(contents, "tun-fd-proof");
        remove_file(path).unwrap();
    }

    #[test]
    fn bwrap_plan_uses_foxproxsetup_with_temporary_net_admin_and_tun_access() {
        let config = BwrapSetupConfig::new(
            "bwrap",
            "/usr/libexec/foxproxsetup",
            vec!["curl".to_owned(), "http://example.com".to_owned()],
        )
        .with_proxy_environment(ProxyEnvironment::loopback_http_socks(
            "10.0.2.1:18080",
            "10.0.2.1:18081",
        ));

        let plan = plan_bwrap_setup(&config).expect("bwrap plan is valid");
        let argv = plan.argv();

        assert_eq!(plan.program, PathBuf::from("bwrap"));
        assert!(argv.windows(1).any(|window| window == ["--unshare-user"]));
        assert!(argv.windows(1).any(|window| window == ["--unshare-net"]));
        assert!(argv
            .windows(2)
            .any(|window| window == ["--cap-add", "CAP_NET_ADMIN"]));
        assert!(argv
            .windows(3)
            .any(|window| window == ["--dev-bind", "/dev/net/tun", "/dev/net/tun"]));
        assert!(argv
            .windows(3)
            .any(|window| window == ["--setenv", "HTTP_PROXY", "http://10.0.2.1:18080"]));
        assert!(argv
            .windows(3)
            .any(|window| window == ["--setenv", "ALL_PROXY", "socks5://10.0.2.1:18081"]));
        assert!(argv.windows(4).any(|window| window
            == [
                "/usr/libexec/foxproxsetup",
                "--",
                "curl",
                "http://example.com"
            ]));
    }

    #[test]
    fn bwrap_plan_rejects_missing_target_or_program() {
        let missing_target = BwrapSetupConfig::new("bwrap", "foxproxsetup", Vec::new());
        assert_eq!(
            plan_bwrap_setup(&missing_target).unwrap_err(),
            IntegrationPlanError::EmptyTarget
        );

        let missing_bwrap = BwrapSetupConfig::new("", "foxproxsetup", vec!["true".to_owned()]);
        assert_eq!(
            plan_bwrap_setup(&missing_bwrap).unwrap_err(),
            IntegrationPlanError::EmptyProgram {
                field: "bwrap_program"
            }
        );
    }
}
