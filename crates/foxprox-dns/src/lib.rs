//! DNS forwarding helpers for foxprox.
//!
//! The DNS subsystem owns upstream DNS exchange and feeds successful responses
//! into the transparent attribution cache. Policy decisions still happen before
//! this layer; this crate focuses on shared UDP egress and response recording.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::SystemTime;

use foxprox_egress::{EgressError, UdpEgress, UdpTarget};
use foxprox_inspect::{DnsAttributionCache, DnsResponseError};

/// Result of forwarding one DNS query upstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsForwardResult {
    pub response: Vec<u8>,
    pub recorded_answers: usize,
}

/// UDP DNS forwarder backed by shared host UDP egress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDnsForwarder {
    upstream: UdpTarget,
    max_response_len: usize,
}

impl UdpDnsForwarder {
    pub fn new(upstream: UdpTarget) -> Self {
        Self {
            upstream,
            max_response_len: 1232,
        }
    }

    pub fn with_max_response_len(
        mut self,
        max_response_len: usize,
    ) -> Result<Self, DnsForwardError> {
        if max_response_len < 12 {
            return Err(DnsForwardError::InvalidResponseLimit { max_response_len });
        }
        self.max_response_len = max_response_len;
        Ok(self)
    }

    pub fn upstream(&self) -> &UdpTarget {
        &self.upstream
    }

    /// Send one DNS query to the configured upstream, receive one response, and
    /// record A/AAAA answers into the supplied attribution cache.
    pub fn forward_query<E: UdpEgress>(
        &self,
        egress: &E,
        query: &[u8],
        cache: &mut DnsAttributionCache,
        observed_at: SystemTime,
    ) -> Result<DnsForwardResult, DnsForwardError> {
        if query.len() < 12 {
            return Err(DnsForwardError::QueryTooShort {
                actual: query.len(),
            });
        }
        let session = egress
            .connect(&self.upstream)
            .map_err(DnsForwardError::Egress)?;
        session
            .socket()
            .send(query)
            .map_err(DnsForwardError::from)?;
        let mut response = vec![0_u8; self.max_response_len];
        let length = session
            .socket()
            .recv(&mut response)
            .map_err(DnsForwardError::from)?;
        response.truncate(length);
        let recorded_answers = cache
            .record_response(&response, observed_at)
            .map_err(DnsForwardError::ResponseParse)?;
        Ok(DnsForwardResult {
            response,
            recorded_answers,
        })
    }
}

/// DNS forwarding errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsForwardError {
    InvalidResponseLimit { max_response_len: usize },
    QueryTooShort { actual: usize },
    Egress(EgressError),
    Io(String),
    ResponseParse(DnsResponseError),
}

impl fmt::Display for DnsForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResponseLimit { max_response_len } => write!(
                f,
                "dns-forward-invalid-response-limit: max_response_len={max_response_len}"
            ),
            Self::QueryTooShort { actual } => {
                write!(f, "dns-forward-query-too-short: actual={actual}")
            }
            Self::Egress(error) => write!(f, "dns-forward-egress-error: {error}"),
            Self::Io(error) => write!(f, "dns-forward-io-error: {error}"),
            Self::ResponseParse(error) => write!(f, "dns-forward-response-parse-error: {error}"),
        }
    }
}

impl std::error::Error for DnsForwardError {}

impl From<std::io::Error> for DnsForwardError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{Endpoint, FrontendKind, NormalizedEvent, SandboxId, TcpConnectAttempt};
    use foxprox_egress::{HostUdpEgress, UdpTarget};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::thread;
    use std::time::{Duration, SystemTime};

    fn dns_a_query(hostname: &str) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    fn dns_a_response(query: &[u8], address: [u8; 4], ttl_seconds: u32) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x01;
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }

    #[test]
    fn udp_dns_forwarder_records_response_answers_for_later_attribution() {
        let query = dns_a_query("dns.example.com");
        let response = dns_a_response(&query, [93, 184, 216, 34], 60);
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let expected_query = query.clone();
        let server_response = response.clone();
        let server = thread::spawn(move || {
            let mut received = vec![0_u8; 512];
            let (length, peer) = server_socket.recv_from(&mut received).unwrap();
            received.truncate(length);
            assert_eq!(received, expected_query);
            server_socket.send_to(&server_response, peer).unwrap();
        });
        let egress = HostUdpEgress::new(Duration::from_secs(1)).unwrap();
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(server_addr.ip(), server_addr.port()).unwrap());
        let mut cache = DnsAttributionCache::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        let result = forwarder
            .forward_query(&egress, &query, &mut cache, now)
            .expect("DNS forward succeeds");
        server.join().unwrap();

        assert_eq!(result.response, response);
        assert_eq!(result.recorded_answers, 1);
        let flow = NormalizedEvent::TcpConnectAttempt(TcpConnectAttempt {
            sandbox_id: SandboxId::new("dns-forward-test").unwrap(),
            frontend: FrontendKind::Tun,
            source: Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152),
            destination: Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            attribution: None,
        });
        let enriched = cache.enrich_event(flow, now + Duration::from_secs(1));
        assert_eq!(enriched.hostname(), Some("dns.example.com"));
    }

    #[test]
    fn udp_dns_forwarder_rejects_too_short_queries_before_egress() {
        let egress = HostUdpEgress::new(Duration::from_secs(1)).unwrap();
        let forwarder =
            UdpDnsForwarder::new(UdpTarget::new_ip(Ipv4Addr::LOCALHOST.into(), 53).unwrap());
        let mut cache = DnsAttributionCache::new();

        let error = forwarder
            .forward_query(&egress, &[0_u8; 11], &mut cache, SystemTime::UNIX_EPOCH)
            .expect_err("short DNS query is rejected");

        assert_eq!(error, DnsForwardError::QueryTooShort { actual: 11 });
        assert!(cache.is_empty());
    }
}
