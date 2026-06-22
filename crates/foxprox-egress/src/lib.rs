//! Shared host egress backends for foxprox.
//!
//! Frontends and transparent forwarding code should request host networking
//! through this layer rather than opening sockets directly. This crate is kept
//! independent of policy/parser types so it can be reused by proxy and TUN paths.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::thread;
use std::time::Duration;

/// Host-side TCP connect target.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpTarget {
    host: String,
    port: u16,
}

/// Host-side UDP datagram target.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UdpTarget {
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

impl UdpTarget {
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

/// Byte counts returned after a TCP bridge finishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBridgeStats {
    pub client_to_target_bytes: u64,
    pub target_to_client_bytes: u64,
}

/// Copy bytes bidirectionally between a frontend client stream and a host egress
/// TCP connection until both directions reach EOF.
pub fn bridge_tcp_streams(
    client: TcpStream,
    target: TcpEgressConnection,
) -> Result<TcpBridgeStats, EgressError> {
    let mut client_reader = client.try_clone().map_err(EgressError::from)?;
    let mut target_writer = target.stream.try_clone().map_err(EgressError::from)?;
    let mut target_reader = target.into_inner();
    let mut client_writer = client;

    let upload = thread::spawn(move || -> Result<u64, EgressError> {
        let bytes = io::copy(&mut client_reader, &mut target_writer).map_err(EgressError::from)?;
        let _ = target_writer.shutdown(Shutdown::Write);
        Ok(bytes)
    });

    let target_to_client_bytes =
        io::copy(&mut target_reader, &mut client_writer).map_err(EgressError::from)?;
    let _ = client_writer.shutdown(Shutdown::Write);
    let client_to_target_bytes = upload
        .join()
        .map_err(|_| EgressError::Io("tcp-bridge-upload-thread-panicked".to_owned()))??;

    Ok(TcpBridgeStats {
        client_to_target_bytes,
        target_to_client_bytes,
    })
}

/// Host UDP session returned by the egress backend.
#[derive(Debug)]
pub struct UdpEgressSession {
    target: UdpTarget,
    socket: UdpSocket,
}

impl UdpEgressSession {
    pub fn target(&self) -> &UdpTarget {
        &self.target
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }
}

/// TCP egress backend interface.
pub trait TcpEgress {
    fn connect(&self, target: &TcpTarget) -> Result<TcpEgressConnection, EgressError>;
}

/// UDP egress backend interface.
pub trait UdpEgress {
    fn connect(&self, target: &UdpTarget) -> Result<UdpEgressSession, EgressError>;
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

/// Blocking host UDP connector used by initial UDP/DNS forwarding proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostUdpEgress {
    read_timeout: Duration,
}

impl HostUdpEgress {
    pub fn new(read_timeout: Duration) -> Result<Self, EgressError> {
        if read_timeout.is_zero() {
            return Err(EgressError::InvalidTarget(
                "read timeout must not be zero".to_owned(),
            ));
        }
        Ok(Self { read_timeout })
    }

    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
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

impl UdpEgress for HostUdpEgress {
    fn connect(&self, target: &UdpTarget) -> Result<UdpEgressSession, EgressError> {
        let mut addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|error| EgressError::UdpResolve {
                target: target.clone(),
                error: error.to_string(),
            })?;
        let addr = addrs
            .next()
            .ok_or_else(|| EgressError::UdpNoResolvedAddresses {
                target: target.clone(),
            })?;
        let bind_addr = match addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(bind_addr).map_err(|error| EgressError::UdpBind {
            target: target.clone(),
            error: error.to_string(),
        })?;
        socket
            .connect(addr)
            .map_err(|error| EgressError::UdpConnect {
                target: target.clone(),
                addr,
                error: error.to_string(),
            })?;
        socket
            .set_read_timeout(Some(self.read_timeout))
            .map_err(EgressError::from)?;
        Ok(UdpEgressSession {
            target: target.clone(),
            socket,
        })
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
    UdpResolve {
        target: UdpTarget,
        error: String,
    },
    UdpNoResolvedAddresses {
        target: UdpTarget,
    },
    UdpBind {
        target: UdpTarget,
        error: String,
    },
    UdpConnect {
        target: UdpTarget,
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
            Self::UdpResolve { target, error } => write!(
                f,
                "udp-egress-resolve-failed: {}:{}: {error}",
                target.host, target.port
            ),
            Self::UdpNoResolvedAddresses { target } => write!(
                f,
                "udp-egress-resolve-empty: {}:{}",
                target.host, target.port
            ),
            Self::UdpBind { target, error } => write!(
                f,
                "udp-egress-bind-failed: {}:{}: {error}",
                target.host, target.port
            ),
            Self::UdpConnect {
                target,
                addr,
                error,
            } => write!(
                f,
                "udp-egress-connect-failed: {}:{} via {addr}: {error}",
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
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
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
    fn tcp_bridge_moves_bytes_between_client_and_egress_and_counts_them() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"pong").unwrap();
            request
        });

        let client_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client = TcpStream::connect(client_addr).unwrap();
        let (broker_client, _) = client_listener.accept().unwrap();
        let egress = HostTcpEgress::new(Duration::from_secs(1)).unwrap();
        let target = TcpTarget::new_ip(upstream_addr.ip(), upstream_addr.port()).unwrap();
        let connection = egress.connect(&target).unwrap();

        let bridge = thread::spawn(move || bridge_tcp_streams(broker_client, connection));
        let mut client = client;
        client.write_all(b"ping").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        let stats = bridge.join().unwrap().unwrap();
        let upstream_request = upstream.join().unwrap();
        assert_eq!(&upstream_request, b"ping");
        assert_eq!(&response, b"pong");
        assert_eq!(stats.client_to_target_bytes, 4);
        assert_eq!(stats.target_to_client_bytes, 4);
    }

    #[test]
    fn host_udp_egress_connects_to_loopback_socket_and_exchanges_datagrams() {
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut request = [0_u8; 4];
            let (length, peer) = server_socket.recv_from(&mut request).unwrap();
            server_socket.send_to(b"pong", peer).unwrap();
            (length, request)
        });
        let egress = HostUdpEgress::new(Duration::from_secs(1)).unwrap();
        let target = UdpTarget::new_ip(server_addr.ip(), server_addr.port()).unwrap();

        let session = egress
            .connect(&target)
            .expect("UDP egress connect succeeds");
        session.socket().send(b"ping").unwrap();
        let mut response = [0_u8; 4];
        let response_len = session.socket().recv(&mut response).unwrap();
        let (request_len, request) = server.join().unwrap();

        assert_eq!(session.target(), &target);
        assert_eq!(request_len, 4);
        assert_eq!(&request, b"ping");
        assert_eq!(response_len, 4);
        assert_eq!(&response, b"pong");
    }

    #[test]
    fn tcp_and_udp_targets_reject_empty_host_and_zero_port() {
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
        assert_eq!(
            UdpTarget::new_host("  ", 53).unwrap_err().to_string(),
            "invalid-egress-target: host must not be empty"
        );
        assert_eq!(
            UdpTarget::new_host("example.com", 0)
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
