//! Explicit proxy frontend parsing and normalization.
//!
//! This crate contains dependency-light protocol parsers that turn explicit
//! HTTP proxy, HTTPS CONNECT, and SOCKS5 CONNECT request bytes into the same
//! normalized policy events used by transparent frontends. It does not open
//! host sockets or perform forwarding.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use foxprox_core::{
    Attribution, AuditBackpressure, AuditBuffer, AuditEvent, AuditEventKind, Decision,
    EgressContext, Frontend, Hostname, HttpMethod, NetworkEvent, Origin, PolicyEngine,
    PolicyRuleSet, SandboxId, SocksDestination, TcpEgressRequest, TransportEndpoint,
};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Explicit proxy parse error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyParseError {
    /// More bytes are needed before a complete request can be parsed.
    Truncated,
    /// The request is malformed and should fail closed.
    Malformed(String),
    /// The request uses an unsupported proxy feature.
    Unsupported(String),
}

/// Configuration for the blocking std HTTP proxy proof listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProxyProofConfig {
    /// Sandbox/session identifier used in normalized events.
    pub sandbox_id: SandboxId,
    /// Address for the explicit proxy proof listener.
    pub listen_addr: SocketAddr,
    /// Policy evaluated before host TCP egress.
    pub policy: PolicyRuleSet,
    /// Maximum proxy request head bytes buffered before failing closed.
    pub request_head_limit: usize,
    /// Request-head read timeout.
    pub request_head_timeout: Duration,
    /// Host TCP connect timeout.
    pub connect_timeout: Duration,
    /// Maximum queued audit events before policy paths fail closed.
    pub audit_queue_capacity: usize,
}

impl HttpProxyProofConfig {
    /// Creates a proof config with deny-by-default policy.
    pub fn new(sandbox_id: SandboxId, listen_addr: SocketAddr) -> Self {
        Self {
            sandbox_id,
            listen_addr,
            policy: PolicyRuleSet::default(),
            request_head_limit: 16 * 1024,
            request_head_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            audit_queue_capacity: 8192,
        }
    }
}

/// Configuration for the blocking std SOCKS5 proxy proof listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5ProxyProofConfig {
    /// Sandbox/session identifier used in normalized events.
    pub sandbox_id: SandboxId,
    /// Address for the SOCKS5 proof listener.
    pub listen_addr: SocketAddr,
    /// Policy evaluated before host TCP egress.
    pub policy: PolicyRuleSet,
    /// Handshake/request read timeout.
    pub request_timeout: Duration,
    /// Host TCP connect timeout.
    pub connect_timeout: Duration,
    /// Maximum queued audit events before policy paths fail closed.
    pub audit_queue_capacity: usize,
}

impl Socks5ProxyProofConfig {
    /// Creates a SOCKS5 proof config with deny-by-default policy.
    pub fn new(sandbox_id: SandboxId, listen_addr: SocketAddr) -> Self {
        Self {
            sandbox_id,
            listen_addr,
            policy: PolicyRuleSet::default(),
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            audit_queue_capacity: 8192,
        }
    }
}

/// Runs the blocking HTTP proxy proof listener forever.
///
/// Each accepted connection is handled on a short-lived thread. This is an
/// alpha proof, not the final async/resource-limited proxy runtime.
pub fn run_http_proxy_proof(config: HttpProxyProofConfig) -> io::Result<()> {
    let audit = shared_audit_buffer(config.audit_queue_capacity)?;
    let listener = TcpListener::bind(config.listen_addr)?;
    eprintln!("foxprox-proxy: listening on {}", listener.local_addr()?);
    for accepted in listener.incoming() {
        let config = config.clone();
        let audit = Arc::clone(&audit);
        match accepted {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_http_proxy_stream_with_audit(stream, &config, &audit)
                    {
                        eprintln!("foxprox-proxy: connection failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("foxprox-proxy: accept failed: {error}"),
        }
    }
    Ok(())
}

/// Runs the blocking SOCKS5 proof listener forever.
pub fn run_socks5_proxy_proof(config: Socks5ProxyProofConfig) -> io::Result<()> {
    let audit = shared_audit_buffer(config.audit_queue_capacity)?;
    let listener = TcpListener::bind(config.listen_addr)?;
    eprintln!(
        "foxprox-proxy: socks5 listening on {}",
        listener.local_addr()?
    );
    for accepted in listener.incoming() {
        let config = config.clone();
        let audit = Arc::clone(&audit);
        match accepted {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) =
                        handle_socks5_proxy_stream_with_audit(stream, &config, &audit)
                    {
                        eprintln!("foxprox-proxy: socks5 connection failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("foxprox-proxy: socks5 accept failed: {error}"),
        }
    }
    Ok(())
}

type SharedAuditBuffer = Arc<Mutex<AuditBuffer>>;

fn shared_audit_buffer(capacity: usize) -> io::Result<SharedAuditBuffer> {
    if capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit queue capacity must be non-zero",
        ));
    }
    Ok(Arc::new(Mutex::new(AuditBuffer::new(capacity))))
}

fn emit_proxy_audit(
    audit: &SharedAuditBuffer,
    event: &NetworkEvent,
    decision: Decision,
) -> io::Result<()> {
    let mut buffer = audit.lock().map_err(|_| {
        io::Error::other("audit queue lock poisoned while recording proxy decision")
    })?;
    let audit_event = proxy_audit_event(event, decision);
    buffer
        .try_push(audit_event.clone())
        .map_err(audit_backpressure_error)?;
    eprintln!("foxprox-proxy: audit event={audit_event:?}");
    Ok(())
}

fn audit_backpressure_error(error: AuditBackpressure) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!("audit queue backpressure: {error:?}"),
    )
}

fn proxy_audit_event(event: &NetworkEvent, decision: Decision) -> AuditEvent {
    let kind = match event {
        NetworkEvent::HttpRequest { .. } => AuditEventKind::HttpRequest,
        NetworkEvent::HttpsConnect { .. } => AuditEventKind::HttpsConnect,
        NetworkEvent::SocksConnect { .. } => AuditEventKind::SocksConnect,
        _ => AuditEventKind::UnsupportedDenied,
    };
    let mut audit = AuditEvent::new(proxy_event_frontend(event), kind).with_decision(decision);
    if let Some(sandbox_id) = event.sandbox_id() {
        audit = audit.with_sandbox_id(sandbox_id.clone());
    }
    audit.protocol = Some(event.protocol());
    match event {
        NetworkEvent::HttpRequest {
            origin,
            method,
            path_and_query,
            ..
        } => {
            audit.hostname = Some(origin.host.clone());
            audit.destination_port = Some(origin.port);
            audit.attribution = Some(Attribution::explicit_proxy(origin.host.clone()));
            audit.origin = Some(origin.clone());
            audit.http_method = Some(method.clone());
            audit.path_and_query = Some(path_and_query.clone());
        }
        NetworkEvent::HttpsConnect { host, port, .. } => {
            audit.hostname = Some(host.clone());
            audit.destination_port = Some(*port);
            audit.attribution = Some(Attribution::explicit_proxy(host.clone()));
        }
        NetworkEvent::SocksConnect { target, .. } => match target {
            SocksDestination::Host { host, port } => {
                audit.hostname = Some(host.clone());
                audit.destination_port = Some(*port);
                audit.attribution = Some(Attribution::explicit_proxy(host.clone()));
            }
            SocksDestination::Ip(endpoint) => {
                audit.destination = Some(*endpoint);
                audit.destination_port = Some(endpoint.port);
                audit.attribution = Some(Attribution::ip_only());
            }
        },
        _ => {}
    }
    audit
}

fn proxy_event_frontend(event: &NetworkEvent) -> Frontend {
    match event {
        NetworkEvent::HttpRequest { frontend, .. }
        | NetworkEvent::HttpsConnect { frontend, .. } => *frontend,
        NetworkEvent::SocksConnect { .. } => Frontend::Socks5,
        _ => Frontend::Setup,
    }
}

#[cfg(test)]
fn handle_socks5_proxy_stream(
    client: TcpStream,
    config: &Socks5ProxyProofConfig,
) -> io::Result<()> {
    let audit = shared_audit_buffer(config.audit_queue_capacity)?;
    handle_socks5_proxy_stream_with_audit(client, config, &audit)
}

fn handle_socks5_proxy_stream_with_audit(
    mut client: TcpStream,
    config: &Socks5ProxyProofConfig,
    audit: &SharedAuditBuffer,
) -> io::Result<()> {
    client.set_read_timeout(Some(config.request_timeout))?;
    let request_bytes = read_socks5_greeting_and_request(&mut client)?;
    client.set_read_timeout(None)?;
    let event = match parse_socks5_connect(config.sandbox_id.clone(), &request_bytes) {
        Ok(event) => event,
        Err(error) => {
            let _ = write_socks5_reply(&mut client, socks_status_for_parse_error(&request_bytes));
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{error:?}"),
            ));
        }
    };
    let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
    eprintln!("foxprox-proxy: socks5 policy decision={decision:?} event={event:?}");
    if let Err(error) = emit_proxy_audit(audit, &event, decision.clone()) {
        let _ = write_socks5_reply(&mut client, 0x01);
        return Err(error);
    }
    if !decision.is_allowed() {
        let _ = write_socks5_reply(&mut client, 0x02);
        return Ok(());
    }
    let destination = match socks_destination_socket_addr(&event, config.connect_timeout) {
        Ok(destination) => destination,
        Err(error) => {
            let _ = write_socks5_reply(&mut client, 0x04);
            return Err(error);
        }
    };
    let upstream = match connect_allowed_tcp(
        &event,
        &decision,
        destination,
        config.connect_timeout,
        Frontend::Socks5,
        config.sandbox_id.clone(),
    ) {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = write_socks5_reply(&mut client, socks_status_for_io_error(&error));
            return Err(error);
        }
    };
    write_socks5_reply(&mut client, 0x00)?;
    tunnel_bidirectional(client, upstream)
}

fn read_socks5_greeting_and_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut greeting_prefix = [0_u8; 2];
    stream.read_exact(&mut greeting_prefix)?;
    if greeting_prefix[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let method_count = greeting_prefix[1] as usize;
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods)?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff])?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 no-auth method not offered",
        ));
    }
    stream.write_all(&[0x05, 0x00])?;

    let mut request_head = [0_u8; 4];
    stream.read_exact(&mut request_head)?;
    let extra_len = match request_head[3] {
        0x01 => 6,
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut out = Vec::with_capacity(2 + method_count + 5 + len[0] as usize + 2);
            out.extend_from_slice(&greeting_prefix);
            out.extend_from_slice(&methods);
            out.extend_from_slice(&request_head);
            out.push(len[0]);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
            return Ok(out);
        }
        0x04 => 18,
        _ => {
            let _ = write_socks5_reply(stream, 0x08);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS5 address type",
            ));
        }
    };
    let mut out = Vec::with_capacity(2 + method_count + 4 + extra_len);
    out.extend_from_slice(&greeting_prefix);
    out.extend_from_slice(&methods);
    out.extend_from_slice(&request_head);
    let mut rest = vec![0_u8; extra_len];
    stream.read_exact(&mut rest)?;
    out.extend_from_slice(&rest);
    Ok(out)
}

fn socks_destination_socket_addr(
    event: &NetworkEvent,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    match event {
        NetworkEvent::SocksConnect {
            target: SocksDestination::Host { host, port },
            ..
        } => resolve_host_port(host, *port, timeout),
        NetworkEvent::SocksConnect {
            target: SocksDestination::Ip(endpoint),
            ..
        } => Ok(SocketAddr::new(endpoint.ip, endpoint.port)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS event",
        )),
    }
}

fn socks_status_for_parse_error(request_bytes: &[u8]) -> u8 {
    if request_bytes.len() >= 2 {
        let request_offset = 2 + request_bytes[1] as usize;
        if request_bytes.len() > request_offset + 3 {
            let command = request_bytes[request_offset + 1];
            let address_type = request_bytes[request_offset + 3];
            if command != 0x01 {
                return 0x07;
            }
            if !matches!(address_type, 0x01 | 0x03 | 0x04) {
                return 0x08;
            }
        }
    }
    0x01
}

fn socks_status_for_io_error(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => 0x05,
        io::ErrorKind::TimedOut => 0x04,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::NotFound => 0x04,
        _ => 0x01,
    }
}

fn write_socks5_reply(stream: &mut TcpStream, status: u8) -> io::Result<()> {
    stream.write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
fn handle_http_proxy_stream(client: TcpStream, config: &HttpProxyProofConfig) -> io::Result<()> {
    let audit = shared_audit_buffer(config.audit_queue_capacity)?;
    handle_http_proxy_stream_with_audit(client, config, &audit)
}

fn handle_http_proxy_stream_with_audit(
    mut client: TcpStream,
    config: &HttpProxyProofConfig,
    audit: &SharedAuditBuffer,
) -> io::Result<()> {
    client.set_read_timeout(Some(config.request_head_timeout))?;
    let buffered = read_proxy_head(&mut client, config.request_head_limit)?;
    client.set_read_timeout(None)?;
    let (head, tail) = split_proxy_head(&buffered)?;
    let event = parse_http_proxy_request_head(config.sandbox_id.clone(), head)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))?;
    let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
    eprintln!("foxprox-proxy: policy decision={decision:?} event={event:?}");
    if let Err(error) = emit_proxy_audit(audit, &event, decision.clone()) {
        let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
        return Err(error);
    }
    if !decision.is_allowed() {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    }
    match event {
        NetworkEvent::HttpRequest { ref origin, .. } => {
            let destination = resolve_host_port(&origin.host, origin.port, config.connect_timeout)?;
            let mut upstream = connect_allowed_tcp(
                &event,
                &decision,
                destination,
                config.connect_timeout,
                Frontend::HttpProxy,
                config.sandbox_id.clone(),
            )?;
            let rewritten = rewrite_http_request_for_origin(head)?;
            upstream.write_all(&rewritten)?;
            upstream.write_all(tail)?;
            tunnel_bidirectional(client, upstream)
        }
        NetworkEvent::HttpsConnect { ref host, port, .. } => {
            let destination = resolve_host_port(host, port, config.connect_timeout)?;
            let mut upstream = connect_allowed_tcp(
                &event,
                &decision,
                destination,
                config.connect_timeout,
                Frontend::HttpProxy,
                config.sandbox_id.clone(),
            )?;
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            upstream.write_all(tail)?;
            tunnel_bidirectional(client, upstream)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected proxy event type",
        )),
    }
}

fn read_proxy_head(stream: &mut TcpStream, limit: usize) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if buffer.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy request head exceeded limit",
            ));
        }
        let read_len = stream.read(&mut chunk)?;
        if read_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before proxy request head",
            ));
        }
        buffer.extend_from_slice(&chunk[..read_len]);
        if buffer.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy request head exceeded limit",
            ));
        }
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buffer);
        }
    }
}

fn split_proxy_head(buffered: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let Some(head_end) = buffered.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request head delimiter missing",
        ));
    };
    let split_at = head_end + 4;
    Ok((&buffered[..split_at], &buffered[split_at..]))
}

fn connect_allowed_tcp(
    event: &NetworkEvent,
    decision: &Decision,
    destination: SocketAddr,
    connect_timeout: Duration,
    frontend: Frontend,
    sandbox_id: SandboxId,
) -> io::Result<TcpStream> {
    let request = TcpEgressRequest {
        context: EgressContext {
            sandbox_id,
            frontend,
            decision: decision.clone(),
            attribution: event_attribution(event),
        },
        source: None,
        destination: TransportEndpoint::from(destination),
        connect_timeout: Some(connect_timeout),
    };
    if !request.context.is_allowed() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "policy denied host egress",
        ));
    }
    TcpStream::connect_timeout(&destination, connect_timeout)
}

fn event_attribution(event: &NetworkEvent) -> Attribution {
    match event {
        NetworkEvent::HttpRequest { origin, .. } => {
            Attribution::explicit_proxy(origin.host.clone())
        }
        NetworkEvent::HttpsConnect { host, .. } => Attribution::explicit_proxy(host.clone()),
        NetworkEvent::SocksConnect { target, .. } => target
            .host()
            .cloned()
            .map(Attribution::explicit_proxy)
            .unwrap_or_else(Attribution::ip_only),
        _ => Attribution::ip_only(),
    }
}

fn resolve_host_port(host: &Hostname, port: u16, timeout: Duration) -> io::Result<SocketAddr> {
    let _ = timeout;
    let mut addrs: Vec<_> = (host.as_str(), port).to_socket_addrs()?.collect();
    addrs.sort_by_key(|addr| !addr.is_ipv4());
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "host did not resolve"))
}

fn rewrite_http_request_for_origin(head: &[u8]) -> io::Result<Vec<u8>> {
    let text = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP head is not UTF-8"))?;
    let line_end = text
        .find("\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let request_line = &text[..line_end];
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let path = absolute_http_path(target)?;
    let mut rewritten = Vec::new();
    rewritten.extend_from_slice(format!("{method} {path} {version}").as_bytes());
    rewritten.extend_from_slice(&text.as_bytes()[line_end..]);
    Ok(rewritten)
}

fn absolute_http_path(target: &str) -> io::Result<&str> {
    let without_scheme = target
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not absolute http target"))?;
    Ok(match without_scheme.find('/') {
        Some(index) => &without_scheme[index..],
        None => "/",
    })
}

fn tunnel_bidirectional(mut client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;
    let client_to_upstream = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let upstream_to_client = io::copy(&mut upstream_read, &mut client);
    let _ = client.shutdown(Shutdown::Both);
    match client_to_upstream.join() {
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
    }
    upstream_to_client.map(|_| ())
}

/// Parses an HTTP proxy request head into a normalized HTTP or CONNECT event.
///
/// Plain HTTP proxy requests must use absolute-form `http://host[:port]/path`.
/// HTTPS tunnels must use `CONNECT host:port HTTP/1.x`.
pub fn parse_http_proxy_request_head(
    sandbox_id: SandboxId,
    input: &[u8],
) -> Result<NetworkEvent, ProxyParseError> {
    let text = std::str::from_utf8(input)
        .map_err(|_| ProxyParseError::Malformed("HTTP proxy head is not UTF-8".to_string()))?;
    let head_end = text.find("\r\n\r\n").ok_or(ProxyParseError::Truncated)?;
    let request_line = text[..head_end]
        .split("\r\n")
        .next()
        .ok_or_else(|| ProxyParseError::Malformed("missing request line".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts
        .next()
        .ok_or_else(|| ProxyParseError::Malformed("missing request target".to_string()))?;
    let version = parts
        .next()
        .ok_or_else(|| ProxyParseError::Malformed("missing HTTP version".to_string()))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return Err(ProxyParseError::Unsupported(
            "only HTTP/1.0 and HTTP/1.1 proxy requests are supported".to_string(),
        ));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, None)?;
        return Ok(NetworkEvent::HttpsConnect {
            sandbox_id,
            frontend: Frontend::HttpProxy,
            host,
            port,
        });
    }

    let method =
        HttpMethod::parse(method).map_err(|error| ProxyParseError::Malformed(error.to_string()))?;
    let (origin, path_and_query) = parse_absolute_http_target(target)?;
    Ok(NetworkEvent::HttpRequest {
        sandbox_id,
        frontend: Frontend::HttpProxy,
        method,
        origin,
        path_and_query,
    })
}

/// Parses a complete SOCKS5 greeting plus CONNECT request into a normalized event.
///
/// This alpha parser supports no-authentication TCP CONNECT only. It returns
/// `Unsupported` for UDP ASSOCIATE, BIND, and unsupported address families.
pub fn parse_socks5_connect(
    sandbox_id: SandboxId,
    input: &[u8],
) -> Result<NetworkEvent, ProxyParseError> {
    if input.len() < 2 {
        return Err(ProxyParseError::Truncated);
    }
    if input[0] != 0x05 {
        return Err(ProxyParseError::Malformed(
            "SOCKS version is not 5".to_string(),
        ));
    }
    let method_count = input[1] as usize;
    let methods_end = 2 + method_count;
    if input.len() < methods_end + 4 {
        return Err(ProxyParseError::Truncated);
    }
    if !input[2..methods_end].contains(&0x00) {
        return Err(ProxyParseError::Unsupported(
            "SOCKS5 no-auth method was not offered".to_string(),
        ));
    }
    let request = &input[methods_end..];
    if request[0] != 0x05 {
        return Err(ProxyParseError::Malformed(
            "SOCKS request version is not 5".to_string(),
        ));
    }
    if request[2] != 0x00 {
        return Err(ProxyParseError::Malformed(
            "SOCKS reserved byte is non-zero".to_string(),
        ));
    }
    if request[1] != 0x01 {
        return Err(ProxyParseError::Unsupported(
            "only SOCKS5 CONNECT is alpha-supported".to_string(),
        ));
    }

    let (target, consumed) = parse_socks_address(request)?;
    if input.len() < methods_end + consumed {
        return Err(ProxyParseError::Truncated);
    }
    Ok(NetworkEvent::SocksConnect { sandbox_id, target })
}

fn parse_absolute_http_target(target: &str) -> Result<(Origin, String), ProxyParseError> {
    let without_scheme = target.strip_prefix("http://").ok_or_else(|| {
        ProxyParseError::Unsupported(
            "only absolute-form http:// proxy targets are supported".into(),
        )
    })?;
    let (authority, path) = match without_scheme.find('/') {
        Some(index) => (&without_scheme[..index], &without_scheme[index..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = parse_host_port(authority, Some(80))?;
    Ok((
        Origin {
            scheme: "http".to_string(),
            host,
            port,
        },
        path.to_string(),
    ))
}

fn parse_host_port(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(Hostname, u16), ProxyParseError> {
    if authority.starts_with('[') {
        return Err(ProxyParseError::Unsupported(
            "IPv6 literal authorities are not supported by hostname-only proxy events".into(),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let port = port
                .parse()
                .map_err(|_| ProxyParseError::Malformed("invalid port".to_string()))?;
            (host, port)
        }
        _ => {
            let Some(default_port) = default_port else {
                return Err(ProxyParseError::Malformed("missing explicit port".into()));
            };
            (authority, default_port)
        }
    };
    if host.parse::<Ipv4Addr>().is_ok() {
        return Err(ProxyParseError::Unsupported(
            "IPv4 literal authorities are not supported by hostname-only proxy events".into(),
        ));
    }
    let host =
        Hostname::parse(host).map_err(|error| ProxyParseError::Malformed(error.to_string()))?;
    Ok((host, port))
}

fn parse_socks_address(request: &[u8]) -> Result<(SocksDestination, usize), ProxyParseError> {
    match request.get(3).copied() {
        Some(0x01) => {
            if request.len() < 10 {
                return Err(ProxyParseError::Truncated);
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                request[4], request[5], request[6], request[7],
            ));
            let port = u16::from_be_bytes([request[8], request[9]]);
            Ok((SocksDestination::Ip(TransportEndpoint::new(ip, port)), 10))
        }
        Some(0x03) => {
            let len = *request.get(4).ok_or(ProxyParseError::Truncated)? as usize;
            if request.len() < 5 + len + 2 {
                return Err(ProxyParseError::Truncated);
            }
            let host = std::str::from_utf8(&request[5..5 + len])
                .map_err(|_| ProxyParseError::Malformed("SOCKS hostname is not UTF-8".into()))?;
            let host = Hostname::parse(host)
                .map_err(|error| ProxyParseError::Malformed(error.to_string()))?;
            let port_offset = 5 + len;
            let port = u16::from_be_bytes([request[port_offset], request[port_offset + 1]]);
            Ok((SocksDestination::Host { host, port }, port_offset + 2))
        }
        Some(0x04) => {
            if request.len() < 22 {
                return Err(ProxyParseError::Truncated);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&request[4..20]);
            let port = u16::from_be_bytes([request[20], request[21]]);
            Ok((
                SocksDestination::Ip(TransportEndpoint::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )),
                22,
            ))
        }
        Some(_) => Err(ProxyParseError::Unsupported(
            "unsupported SOCKS address type".into(),
        )),
        None => Err(ProxyParseError::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{Cidr, PolicyRule, PortRange, Protocol, RuleEffect, SocksDestination};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};

    fn sandbox_id() -> SandboxId {
        SandboxId::new("proxy-test").unwrap()
    }

    fn allow_rule(id: &str, protocol: Protocol, host: &str, port: u16) -> PolicyRule {
        PolicyRule::new(id, RuleEffect::Allow)
            .with_protocol(protocol)
            .with_hostname(Hostname::parse(host).unwrap())
            .with_destination_ports(PortRange::single(port))
    }

    #[test]
    fn parses_http_absolute_form_request() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://Example.com:8080/path?q=1 HTTP/1.1\r\nHost: ignored\r\n\r\n",
        )
        .unwrap();
        match event {
            NetworkEvent::HttpRequest {
                frontend,
                method,
                origin,
                path_and_query,
                ..
            } => {
                assert_eq!(frontend, Frontend::HttpProxy);
                assert_eq!(method.as_str(), "GET");
                assert_eq!(origin.host.as_str(), "example.com");
                assert_eq!(origin.port, 8080);
                assert_eq!(path_and_query, "/path?q=1");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parses_https_connect() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .unwrap();
        match event {
            NetworkEvent::HttpsConnect {
                frontend,
                host,
                port,
                ..
            } => {
                assert_eq!(frontend, Frontend::HttpProxy);
                assert_eq!(host.as_str(), "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_http_proxy_request() {
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"GET /relative HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Unsupported(_))
        ));
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"CONNECT example.com HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_http_proxy_ip_literal_authorities() {
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"GET http://127.0.0.1/ HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Unsupported(_))
        ));
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_unsupported_http_proxy_versions() {
        assert!(matches!(
            parse_http_proxy_request_head(
                sandbox_id(),
                b"GET http://example.com/ HTTP/2.0\r\n\r\n"
            ),
            Err(ProxyParseError::Unsupported(_))
        ));
        assert!(matches!(
            parse_http_proxy_request_head(
                sandbox_id(),
                b"CONNECT example.com:443 HTTP/not-a-version\r\n\r\n"
            ),
            Err(ProxyParseError::Unsupported(_))
        ));
    }

    #[test]
    fn parses_socks5_host_connect() {
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443_u16.to_be_bytes());
        let event = parse_socks5_connect(sandbox_id(), &request).unwrap();
        match event {
            NetworkEvent::SocksConnect {
                target: SocksDestination::Host { host, port },
                ..
            } => {
                assert_eq!(host.as_str(), "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parses_socks5_ipv4_connect() {
        let request = [
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0, 80,
        ];
        let event = parse_socks5_connect(sandbox_id(), &request).unwrap();
        match event {
            NetworkEvent::SocksConnect {
                target: SocksDestination::Ip(endpoint),
                ..
            } => {
                assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
                assert_eq!(endpoint.port, 80);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn rejects_socks_udp_associate() {
        let request = [
            0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53,
        ];
        assert!(matches!(
            parse_socks5_connect(sandbox_id(), &request),
            Err(ProxyParseError::Unsupported(_))
        ));
    }

    #[test]
    fn normalized_proxy_events_have_expected_protocols() {
        let http = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://example.com/ HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let connect = parse_http_proxy_request_head(
            sandbox_id(),
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        assert_eq!(http.protocol(), Protocol::Http);
        assert_eq!(connect.protocol(), Protocol::HttpsConnect);
    }

    #[test]
    fn proxy_audit_event_records_http_metadata() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://example.com/proof?q=1 HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = proxy_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::HttpRequest);
        assert_eq!(audit.protocol, Some(Protocol::Http));
        assert_eq!(audit.hostname.unwrap().as_str(), "example.com");
        assert_eq!(audit.destination_port, Some(80));
        assert_eq!(audit.path_and_query.as_deref(), Some("/proof?q=1"));
        assert_eq!(
            audit.attribution.unwrap().hostname.unwrap().as_str(),
            "example.com"
        );
        assert!(audit.decision.is_some());
    }

    #[test]
    fn proxy_audit_event_records_connect_port_and_attribution() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"CONNECT example.com:8443 HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = proxy_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::HttpsConnect);
        assert_eq!(audit.protocol, Some(Protocol::HttpsConnect));
        assert_eq!(audit.hostname.unwrap().as_str(), "example.com");
        assert_eq!(audit.destination_port, Some(8443));
        assert_eq!(
            audit.attribution.unwrap().hostname.unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn proxy_audit_event_records_socks_host_port_and_attribution() {
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&1080_u16.to_be_bytes());
        let event = parse_socks5_connect(sandbox_id(), &request).unwrap();
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = proxy_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::SocksConnect);
        assert_eq!(audit.protocol, Some(Protocol::Socks));
        assert_eq!(audit.hostname.unwrap().as_str(), "example.com");
        assert_eq!(audit.destination_port, Some(1080));
        assert_eq!(
            audit.attribution.unwrap().hostname.unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn proxy_proofs_reject_zero_audit_capacity_before_binding() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let mut http_config = HttpProxyProofConfig::new(sandbox_id(), occupied_addr);
        http_config.audit_queue_capacity = 0;
        let mut socks_config = Socks5ProxyProofConfig::new(sandbox_id(), occupied_addr);
        socks_config.audit_queue_capacity = 0;

        assert_eq!(
            run_http_proxy_proof(http_config).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            run_socks5_proxy_proof(socks_config).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn proxy_audit_enqueue_reports_backpressure() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://example.com/ HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = shared_audit_buffer(1).unwrap();

        emit_proxy_audit(&audit, &event, decision.clone()).unwrap();
        let error = emit_proxy_audit(&audit, &event, decision).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn proof_http_proxy_fails_closed_when_audit_queue_is_full() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let config = HttpProxyProofConfig::new(sandbox_id(), proxy_addr);
        let audit = shared_audit_buffer(1).unwrap();
        let first = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://example.com/ HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&first);
        emit_proxy_audit(&audit, &first, decision).unwrap();
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            assert!(handle_http_proxy_stream_with_audit(stream, &config, &audit).is_err());
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        proxy_thread.join().unwrap();
    }

    #[test]
    fn proof_http_proxy_forwards_absolute_form_request_body_after_policy_allow() {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_thread = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let len = stream.read(&mut chunk).unwrap();
                if len == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..len]);
                if request.ends_with(b"hello-body") {
                    break;
                }
            }
            let text = std::str::from_utf8(&request).unwrap();
            assert!(text.starts_with("POST /proof HTTP/1.1\r\n"));
            assert!(text.ends_with("hello-body"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let mut config = HttpProxyProofConfig::new(sandbox_id(), proxy_addr);
        config.policy.rules.push(allow_rule(
            "allow-http-localhost",
            Protocol::Http,
            "localhost",
            origin_addr.port(),
        ));
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_http_proxy_stream(stream, &config).unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client
            .write_all(
                format!(
                    "POST http://localhost:{}/proof HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nhello-body",
                    origin_addr.port()
                )
                .as_bytes(),
            )
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.contains("200 OK"));
        assert!(response.ends_with("hello"));
        proxy_thread.join().unwrap();
        origin_thread.join().unwrap();
    }

    #[test]
    fn proof_socks5_connect_tunnels_after_policy_allow() {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_thread = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let mut config = Socks5ProxyProofConfig::new(sandbox_id(), proxy_addr);
        config.policy.rules.push(allow_rule(
            "allow-socks-localhost",
            Protocol::Socks,
            "localhost",
            origin_addr.port(),
        ));
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_socks5_proxy_stream(stream, &config).unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);
        let mut connect = vec![0x05, 0x01, 0x00, 0x03, 9];
        connect.extend_from_slice(b"localhost");
        connect.extend_from_slice(&origin_addr.port().to_be_bytes());
        client.write_all(&connect).unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x00);
        client.write_all(b"ping").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut tunneled = [0_u8; 4];
        client.read_exact(&mut tunneled).unwrap();
        assert_eq!(&tunneled, b"pong");
        proxy_thread.join().unwrap();
        origin_thread.join().unwrap();
    }

    #[test]
    fn proof_socks5_connect_denies_by_default() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let config = Socks5ProxyProofConfig::new(sandbox_id(), proxy_addr);
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_socks5_proxy_stream(stream, &config).unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);
        let mut connect = vec![0x05, 0x01, 0x00, 0x03, 9];
        connect.extend_from_slice(b"localhost");
        connect.extend_from_slice(&443_u16.to_be_bytes());
        client.write_all(&connect).unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x02);
        proxy_thread.join().unwrap();
    }

    #[test]
    fn proof_socks5_udp_associate_returns_unsupported_command() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let config = Socks5ProxyProofConfig::new(sandbox_id(), proxy_addr);
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            assert!(handle_socks5_proxy_stream(stream, &config).is_err());
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);
        client
            .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53])
            .unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x07);
        proxy_thread.join().unwrap();
    }

    #[test]
    fn proof_socks5_allowed_but_unreachable_returns_failure() {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = unused.local_addr().unwrap().port();
        drop(unused);

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let mut config = Socks5ProxyProofConfig::new(sandbox_id(), proxy_addr);
        config.policy.rules.push(
            PolicyRule::new("allow-unused-loopback", RuleEffect::Allow)
                .with_protocol(Protocol::Socks)
                .with_destination_cidr(Cidr::v4(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap())
                .with_destination_ports(PortRange::single(unused_port)),
        );
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            assert!(handle_socks5_proxy_stream(stream, &config).is_err());
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);
        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (unused_port >> 8) as u8,
                unused_port as u8,
            ])
            .unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_ne!(reply[1], 0x00);
        proxy_thread.join().unwrap();
    }

    #[test]
    fn proof_connect_tunnels_after_policy_allow() {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_thread = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let mut config = HttpProxyProofConfig::new(sandbox_id(), proxy_addr);
        config.policy.rules.push(allow_rule(
            "allow-connect-localhost",
            Protocol::HttpsConnect,
            "localhost",
            origin_addr.port(),
        ));
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_http_proxy_stream(stream, &config).unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client
            .write_all(
                format!(
                    "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\nping",
                    origin_addr.port()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = [0_u8; 39];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.shutdown(Shutdown::Write).unwrap();
        let mut tunneled = [0_u8; 4];
        client.read_exact(&mut tunneled).unwrap();
        assert_eq!(&tunneled, b"pong");
        proxy_thread.join().unwrap();
        origin_thread.join().unwrap();
    }
}
