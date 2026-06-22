//! Shared host egress backends for foxprox.
//!
//! Frontends and transparent forwarding code should request host networking
//! through this layer rather than opening sockets directly. This crate is kept
//! independent of policy/parser types so it can be reused by proxy and TUN paths.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Host-side TCP connect target.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpTarget {
    host: String,
    port: u16,
}

impl TcpTarget {
    pub fn new_host(host: impl Into<String>, port: u16) -> Result<Self, EgressError> {
        let host = host
            .into()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(EgressError::InvalidTarget(
                "host must not be empty".to_owned(),
            ));
        }
        if port == 0 {
            return Err(EgressError::InvalidTarget(
                "port must not be zero".to_owned(),
            ));
        }
        Ok(Self { host, port })
    }

    pub fn new_ip(ip: IpAddr, port: u16) -> Result<Self, EgressError> {
        Self::new_host(ip.to_string(), port)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Host TCP connection returned by the egress backend.
#[derive(Debug)]
pub struct TcpEgressConnection {
    target: TcpTarget,
    stream: TcpStream,
}

impl TcpEgressConnection {
    pub fn target(&self) -> &TcpTarget {
        &self.target
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

/// TCP egress backend interface.
pub trait TcpEgress {
    fn connect(&self, target: &TcpTarget) -> Result<TcpEgressConnection, EgressError>;
}

/// Blocking host TCP connector used by initial proxy/runtime proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostTcpEgress {
    connect_timeout: Duration,
}

impl HostTcpEgress {
    pub fn new(connect_timeout: Duration) -> Result<Self, EgressError> {
        if connect_timeout.is_zero() {
            return Err(EgressError::InvalidTarget(
                "connect timeout must not be zero".to_owned(),
            ));
        }
        Ok(Self { connect_timeout })
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

impl TcpEgress for HostTcpEgress {
    fn connect(&self, target: &TcpTarget) -> Result<TcpEgressConnection, EgressError> {
        let addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|error| EgressError::Resolve {
                target: target.clone(),
                error: error.to_string(),
            })?;

        let mut last_error = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(stream) => {
                    return Ok(TcpEgressConnection {
                        target: target.clone(),
                        stream,
                    });
                }
                Err(error) => last_error = Some((addr, error)),
            }
        }

        match last_error {
            Some((addr, error)) => Err(EgressError::Connect {
                target: target.clone(),
                addr,
                error: error.to_string(),
            }),
            None => Err(EgressError::NoResolvedAddresses {
                target: target.clone(),
            }),
        }
    }
}

/// Egress errors suitable for audit/retry diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressError {
    InvalidTarget(String),
    Resolve {
        target: TcpTarget,
        error: String,
    },
    NoResolvedAddresses {
        target: TcpTarget,
    },
    Connect {
        target: TcpTarget,
        addr: SocketAddr,
        error: String,
    },
    Io(String),
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(message) => write!(f, "invalid-egress-target: {message}"),
            Self::Resolve { target, error } => {
                write!(
                    f,
                    "egress-resolve-failed: {}:{}: {error}",
                    target.host, target.port
                )
            }
            Self::NoResolvedAddresses { target } => {
                write!(f, "egress-resolve-empty: {}:{}", target.host, target.port)
            }
            Self::Connect {
                target,
                addr,
                error,
            } => write!(
                f,
                "egress-connect-failed: {}:{} via {addr}: {error}",
                target.host, target.port
            ),
            Self::Io(error) => write!(f, "egress-io-error: {error}"),
        }
    }
}

impl std::error::Error for EgressError {}

impl From<io::Error> for EgressError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    #[test]
    fn host_tcp_egress_connects_to_loopback_listener_and_bridges_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"pong").unwrap();
            (peer, request)
        });
        let egress = HostTcpEgress::new(Duration::from_secs(1)).unwrap();
        let target = TcpTarget::new_ip(addr.ip(), addr.port()).unwrap();

        let mut connection = egress.connect(&target).expect("egress connect succeeds");
        connection.stream_mut().write_all(b"ping").unwrap();
        let mut response = [0_u8; 4];
        connection.stream_mut().read_exact(&mut response).unwrap();
        let (_peer, request) = server.join().unwrap();

        assert_eq!(connection.target(), &target);
        assert_eq!(&request, b"ping");
        assert_eq!(&response, b"pong");
    }

    #[test]
    fn tcp_target_rejects_empty_host_and_zero_port() {
        assert_eq!(
            TcpTarget::new_host("  ", 443).unwrap_err().to_string(),
            "invalid-egress-target: host must not be empty"
        );
        assert_eq!(
            TcpTarget::new_host("example.com", 0)
                .unwrap_err()
                .to_string(),
            "invalid-egress-target: port must not be zero"
        );
    }

    #[test]
    fn host_tcp_egress_reports_connect_failure() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let egress = HostTcpEgress::new(Duration::from_millis(100)).unwrap();
        let target = TcpTarget::new_ip(addr.ip(), addr.port()).unwrap();

        let error = egress.connect(&target).expect_err("closed port fails");

        assert!(matches!(error, EgressError::Connect { .. }));
        assert!(error.to_string().contains("egress-connect-failed"));
    }
}
