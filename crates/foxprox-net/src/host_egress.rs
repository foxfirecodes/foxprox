use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use foxprox_core::{EgressDestination, EgressPermit};

#[derive(Debug)]
pub enum HostEgressError {
    MissingPort,
    Resolve(io::Error),
    NoResolvedAddress,
    Connect(io::Error),
}

impl PartialEq for HostEgressError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::MissingPort, Self::MissingPort)
                | (Self::Resolve(_), Self::Resolve(_))
                | (Self::NoResolvedAddress, Self::NoResolvedAddress)
                | (Self::Connect(_), Self::Connect(_))
        )
    }
}

impl Eq for HostEgressError {}

pub fn connect_tcp_with_permit(permit: &EgressPermit) -> Result<TcpStream, HostEgressError> {
    match &permit.destination {
        EgressDestination::Ip(endpoint) => {
            let port = endpoint.port.ok_or(HostEgressError::MissingPort)?;
            TcpStream::connect(SocketAddr::new(endpoint.ip, port)).map_err(HostEgressError::Connect)
        }
        EgressDestination::Host { hostname, port } => {
            let mut addresses = (hostname.as_str(), *port)
                .to_socket_addrs()
                .map_err(HostEgressError::Resolve)?;
            let address = addresses.next().ok_or(HostEgressError::NoResolvedAddress)?;
            TcpStream::connect(address).map_err(HostEgressError::Connect)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    use foxprox_core::{Decision, EgressPermit, Endpoint, PolicyRequest, Protocol};

    use super::*;

    #[test]
    fn opens_tcp_only_from_allow_derived_ip_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(Endpoint::tcp(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        let permit = EgressPermit::from_policy_decision(
            &request,
            &Decision::Allow {
                rule_id: Some("allow-local".into()),
            },
        )
        .unwrap();

        let mut stream = connect_tcp_with_permit(&permit).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).unwrap();

        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn ip_permits_without_ports_fail_closed_before_connect() {
        let permit = EgressPermit {
            sandbox_id: foxprox_core::SandboxId::new("sandbox"),
            frontend: foxprox_core::Frontend::Tun,
            protocol: Protocol::Tcp,
            destination: EgressDestination::Ip(Endpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                None,
            )),
            rule_id: Some("bad".into()),
        };

        assert!(matches!(
            connect_tcp_with_permit(&permit),
            Err(HostEgressError::MissingPort)
        ));
    }
}
