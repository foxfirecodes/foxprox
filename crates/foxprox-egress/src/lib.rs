//! Synchronous local host egress adapters for harnesses and future broker integration.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use foxprox_core::egress::{EgressBackend, EgressOutcome, EgressRequest};

#[derive(Debug)]
pub struct LocalTcpStreamEgress {
    fixture: SocketAddr,
    calls: usize,
}

impl LocalTcpStreamEgress {
    pub fn new(fixture: SocketAddr) -> Self {
        Self { fixture, calls: 0 }
    }

    pub fn calls(&self) -> usize {
        self.calls
    }
}

impl EgressBackend for LocalTcpStreamEgress {
    fn execute(&mut self, request: &EgressRequest) -> Result<EgressOutcome, String> {
        let EgressRequest::TcpStreamData { bytes, .. } = request else {
            return Err("local TCP stream egress only supports TCP stream data".to_string());
        };
        self.calls += 1;
        let mut stream = TcpStream::connect_timeout(&self.fixture, Duration::from_secs(2))
            .map_err(|err| format!("TCP stream host egress connect failed: {err}"))?;
        stream
            .write_all(bytes)
            .map_err(|err| format!("TCP stream host egress write failed: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|err| format!("TCP stream host egress timeout setup failed: {err}"))?;
        let mut reply = [0_u8; 1024];
        let reply_len = stream
            .read(&mut reply)
            .map_err(|err| format!("TCP stream host egress read failed: {err}"))?;
        Ok(EgressOutcome {
            connected: true,
            bytes_sent: bytes.len() as u64,
            bytes_received: reply_len as u64,
            message: "local TCP stream fixture egress".to_string(),
            response_payload: reply[..reply_len].to_vec(),
        })
    }
}

#[derive(Debug)]
pub struct LocalTcpConnectEgress {
    fixture: SocketAddr,
    calls: usize,
}

impl LocalTcpConnectEgress {
    pub fn new(fixture: SocketAddr) -> Self {
        Self { fixture, calls: 0 }
    }

    pub fn calls(&self) -> usize {
        self.calls
    }
}

impl EgressBackend for LocalTcpConnectEgress {
    fn execute(&mut self, request: &EgressRequest) -> Result<EgressOutcome, String> {
        let EgressRequest::TcpConnect { destination } = request else {
            return Err("local TCP egress only supports TCP connects".to_string());
        };
        self.calls += 1;
        let _stream = TcpStream::connect_timeout(&self.fixture, Duration::from_secs(2))
            .map_err(|err| format!("host TCP egress connect failed: {err}"))?;
        Ok(EgressOutcome {
            connected: true,
            bytes_sent: 0,
            bytes_received: 0,
            message: format!("local TCP fixture egress for {destination}"),
            response_payload: Vec::new(),
        })
    }
}

#[derive(Debug)]
pub struct LocalUdpEgress {
    socket: UdpSocket,
    fixture: SocketAddr,
    calls: usize,
}

impl LocalUdpEgress {
    pub fn new(fixture: SocketAddr) -> Result<Self, String> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .map_err(|err| format!("failed to bind host UDP egress socket: {err}"))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("failed to set host UDP egress timeout: {err}"))?;
        Ok(Self {
            socket,
            fixture,
            calls: 0,
        })
    }

    pub fn calls(&self) -> usize {
        self.calls
    }
}

impl EgressBackend for LocalUdpEgress {
    fn execute(&mut self, request: &EgressRequest) -> Result<EgressOutcome, String> {
        let EgressRequest::UdpDatagram { bytes, .. } = request else {
            return Err("local UDP egress only supports UDP datagrams".to_string());
        };
        self.calls += 1;
        self.socket
            .send_to(bytes, self.fixture)
            .map_err(|err| format!("host UDP egress send failed: {err}"))?;
        let mut reply_payload = [0_u8; 2048];
        let (reply_len, _) = self
            .socket
            .recv_from(&mut reply_payload)
            .map_err(|err| format!("host UDP egress receive failed: {err}"))?;
        Ok(EgressOutcome {
            connected: true,
            bytes_sent: bytes.len() as u64,
            bytes_received: reply_len as u64,
            message: "local UDP fixture egress".to_string(),
            response_payload: reply_payload[..reply_len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn tcp_stream_egress_round_trips_fixture_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 16];
            let n = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let mut egress = LocalTcpStreamEgress::new(addr);
        let outcome = egress
            .execute(&EgressRequest::TcpStreamData {
                destination: addr,
                bytes: b"ping".to_vec(),
            })
            .unwrap();
        thread.join().unwrap();
        assert_eq!(outcome.response_payload, b"pong");
        assert_eq!(egress.calls(), 1);
    }
}
