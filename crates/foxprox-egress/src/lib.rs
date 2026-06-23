//! Concrete host-socket egress implementations for foxprox alpha harnesses.
//!
//! This crate stays outside `foxprox-core` so the core policy/audit contracts do
//! not depend on host socket APIs. Runtime code can plug these implementations
//! into the core TCP/UDP forwarding harnesses after policy/audit allow evidence
//! has been recorded.

#![forbid(unsafe_code)]

use foxprox_core::{
    malformed_proxy_request, AuditKind, AuditRecord, AuditSinkError, BrokerRuntimeConfig, Decision,
    DenialReason, DnsBrokerHandler, DnsQueryMetadata, DnsUpstream, DnsUpstreamError,
    ExplicitProxyEgress, ExplicitProxyFrontend, Frontend, HttpProxyRequestMetadata,
    JsonLineAuditSink, NetworkEndpoint, PolicyRequest, Protocol, ProxyEgressError, ProxyParseError,
    RuntimeAuditDrainError, RuntimeAuditDrainReport, RuntimeAuditFanIn, RuntimeAuditFanInError,
    RuntimeAuditIngestReport, RuntimeChildExit, RuntimeCleanupAction, RuntimeCleanupReport,
    RuntimeComponent, RuntimeExitStatus, RuntimeLifecycleError, RuntimeLifecycleHarness,
    RuntimeListenerConfig, RuntimeTaskExpectation, RuntimeTaskHandle, RuntimeTaskJoinReport,
    RuntimeTaskStatus, RuntimeTaskSupervisor, RuntimeTaskSupervisorError, SharedDnsCache,
    SocksConnectMetadata, TcpEgress, TcpEgressError, UdpEgress, UdpEgressError,
};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct BlockingTcpEgress {
    connect_timeout: Duration,
    io_timeout: Duration,
    max_response_bytes: usize,
}

impl BlockingTcpEgress {
    pub fn new(connect_timeout: Duration, io_timeout: Duration, max_response_bytes: usize) -> Self {
        Self {
            connect_timeout,
            io_timeout,
            max_response_bytes,
        }
    }
}

impl Default for BlockingTcpEgress {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(5), 64 * 1024)
    }
}

impl TcpEgress for BlockingTcpEgress {
    fn connect_and_exchange(
        &mut self,
        destination: NetworkEndpoint,
        from_sandbox: &[u8],
    ) -> Result<Vec<u8>, TcpEgressError> {
        let destination = socket_addr(destination).ok_or(TcpEgressError::ConnectFailed)?;
        let mut stream = TcpStream::connect_timeout(&destination, self.connect_timeout)
            .map_err(|_| TcpEgressError::ConnectFailed)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        stream
            .write_all(from_sandbox)
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        let _ = stream.shutdown(std::net::Shutdown::Write);

        let mut response = Vec::new();
        let mut limited = stream.take(self.max_response_bytes as u64);
        limited
            .read_to_end(&mut response)
            .map_err(|_| TcpEgressError::BridgeFailed)?;
        Ok(response)
    }
}

#[derive(Clone, Debug)]
pub struct BlockingExplicitProxyEgress {
    connect_timeout: Duration,
    io_timeout: Duration,
    max_response_bytes: usize,
}

impl BlockingExplicitProxyEgress {
    pub fn new(connect_timeout: Duration, io_timeout: Duration, max_response_bytes: usize) -> Self {
        Self {
            connect_timeout,
            io_timeout,
            max_response_bytes,
        }
    }

    fn connect_ip_literal(&self, ip: IpAddr, port: u16) -> Result<TcpStream, ProxyEgressError> {
        let destination = SocketAddr::new(ip, port);
        let stream = TcpStream::connect_timeout(&destination, self.connect_timeout)
            .map_err(|_| ProxyEgressError::SendFailed)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        Ok(stream)
    }
}

impl Default for BlockingExplicitProxyEgress {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(5), 64 * 1024)
    }
}

impl ExplicitProxyEgress for BlockingExplicitProxyEgress {
    fn forward_http(
        &mut self,
        request: &HttpProxyRequestMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError> {
        let ip = request
            .resolved_destination_ip
            .or_else(|| request.host.parse::<IpAddr>().ok())
            .ok_or(ProxyEgressError::SendFailed)?;
        let mut stream = self.connect_ip_literal(ip, request.port)?;
        stream
            .write_all(bytes)
            .map_err(|_| ProxyEgressError::SendFailed)?;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        let mut limited = stream.take(self.max_response_bytes as u64);
        limited
            .read_to_end(&mut response)
            .map_err(|_| ProxyEgressError::SendFailed)?;
        Ok(())
    }

    fn connect_socks(
        &mut self,
        request: &SocksConnectMetadata,
        _bytes: &[u8],
    ) -> Result<(), ProxyEgressError> {
        let stream = if let Some(ip) = request.destination_ip {
            self.connect_ip_literal(ip, request.destination_port)?
        } else {
            return Err(ProxyEgressError::SendFailed);
        };
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BlockingDnsUpstream {
    upstream: SocketAddr,
    bind_addr: SocketAddr,
    timeout: Duration,
    max_response_bytes: usize,
}

impl BlockingDnsUpstream {
    pub fn new(
        upstream: SocketAddr,
        bind_addr: SocketAddr,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            upstream,
            bind_addr,
            timeout,
            max_response_bytes,
        }
    }

    pub fn from_runtime_config(
        config: &BrokerRuntimeConfig,
        bind_addr: SocketAddr,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self::new(config.dns_upstream, bind_addr, timeout, max_response_bytes)
    }
}

impl DnsUpstream for BlockingDnsUpstream {
    fn exchange(
        &mut self,
        _query: &DnsQueryMetadata,
        packet: &[u8],
    ) -> Result<Vec<u8>, DnsUpstreamError> {
        let socket = UdpSocket::bind(self.bind_addr).map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .send_to(packet, self.upstream)
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        let mut response = vec![0u8; self.max_response_bytes.max(1)];
        let (len, peer) = socket
            .recv_from(&mut response)
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        if peer != self.upstream {
            return Err(DnsUpstreamError::SourceMismatch);
        }
        response.truncate(len);
        Ok(response)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsBrokerStepResult {
    pub client: SocketAddr,
    pub query_len: usize,
    pub response_len: usize,
    pub sent_response: bool,
    pub send_status: String,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
}

pub trait BlockingDnsListenerSocket {
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

impl BlockingDnsListenerSocket for UdpSocket {
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf)
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        UdpSocket::send_to(self, buf, target)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }
}

#[derive(Debug)]
pub struct BlockingDnsBrokerServer<U, S = UdpSocket> {
    socket: S,
    handler: DnsBrokerHandler<U>,
    max_query_bytes: usize,
}

impl<U: DnsUpstream> BlockingDnsBrokerServer<U, UdpSocket> {
    pub fn bind(
        bind_addr: SocketAddr,
        handler: DnsBrokerHandler<U>,
        timeout: Duration,
        max_query_bytes: usize,
    ) -> Result<Self, DnsUpstreamError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| DnsUpstreamError::Unavailable)?;
        Ok(Self {
            socket,
            handler,
            max_query_bytes,
        })
    }
}

impl<U: DnsUpstream, S: BlockingDnsListenerSocket> BlockingDnsBrokerServer<U, S> {
    pub fn local_addr(&self) -> Result<SocketAddr, DnsUpstreamError> {
        self.socket
            .local_addr()
            .map_err(|_| DnsUpstreamError::Unavailable)
    }

    pub fn handle_one(
        &mut self,
        sandbox_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<Option<DnsBrokerStepResult>, DnsUpstreamError> {
        let sandbox_id = sandbox_id.into();
        let mut query = vec![0u8; self.max_query_bytes.max(1)];
        let (query_len, client) = match self.socket.recv_from(&mut query) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err(DnsUpstreamError::Unavailable),
        };
        query.truncate(query_len);
        let result = self
            .handler
            .handle_query(sandbox_id.clone(), &query, now_ms);
        let response_len = result.response.as_ref().map_or(0, Vec::len);
        let mut sent_response = false;
        let mut send_status = "not_sent".to_string();
        if let Some(response) = result.response.as_ref() {
            match self.socket.send_to(response, client) {
                Ok(_) => {
                    if let Some(observation) = result.observation.clone() {
                        self.handler.commit_observation(observation);
                    }
                    sent_response = true;
                    send_status = "sent".to_string();
                }
                Err(_) => {
                    self.record_client_send_failure(
                        &sandbox_id,
                        client,
                        query_len,
                        response_len,
                        now_ms,
                    );
                    return Ok(Some(DnsBrokerStepResult {
                        client,
                        query_len,
                        response_len,
                        sent_response: false,
                        send_status: "send_failed".to_string(),
                        decision: Decision::FailClosed,
                        reason: Some(DenialReason::ResourceLimit),
                    }));
                }
            }
        }
        Ok(Some(DnsBrokerStepResult {
            client,
            query_len,
            response_len,
            sent_response,
            send_status,
            decision: result.decision.decision,
            reason: result.decision.reason,
        }))
    }

    pub fn run_until_cancelled(
        &mut self,
        sandbox_id: impl Into<String>,
        now_ms: u64,
        max_idle_steps: usize,
        should_cancel: impl FnMut() -> bool,
    ) -> RuntimeTaskStatus {
        let sandbox_id = sandbox_id.into();
        run_blocking_listener_loop_until_cancelled(max_idle_steps, should_cancel, || {
            match self.handle_one(sandbox_id.clone(), now_ms) {
                Ok(step) => Ok(step.map(|_| ())),
                Err(error) => {
                    self.record_listener_loop_error(&sandbox_id, now_ms, &error);
                    Err(error)
                }
            }
        })
    }

    pub fn handler(&self) -> &DnsBrokerHandler<U> {
        &self.handler
    }

    fn record_listener_loop_error(
        &mut self,
        sandbox_id: &str,
        now_ms: u64,
        error: &DnsUpstreamError,
    ) {
        let request = PolicyRequest::unsupported(
            sandbox_id.to_string(),
            Frontend::Core,
            DenialReason::RuntimeState,
        );
        let audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            sandbox_id.to_string(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Core)
        .with_protocol(Protocol::Dns)
        .with_decision(Decision::FailClosed, Some(DenialReason::RuntimeState))
        .with_detail("runtime_error", "listener_loop_error")
        .with_detail(
            "listener_component",
            RuntimeComponent::DnsListener.as_detail(),
        )
        .with_detail("listener_task", "dns_accept_loop")
        .with_detail("listener_error", dns_upstream_error_detail(error));
        let _ = self.handler.broker_mut().append_audit_for(&request, audit);
    }

    fn record_client_send_failure(
        &mut self,
        sandbox_id: &str,
        client: SocketAddr,
        query_len: usize,
        response_len: usize,
        now_ms: u64,
    ) {
        let request = PolicyRequest::unsupported(
            sandbox_id.to_string(),
            Frontend::Tun,
            DenialReason::ResourceLimit,
        );
        let audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            sandbox_id.to_string(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Dns)
        .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
        .with_detail("dns_client", client.to_string())
        .with_detail("query_len", query_len.to_string())
        .with_detail("response_len", response_len.to_string())
        .with_detail("send_status", "send_failed")
        .with_detail("error", "dns_client_send_failed");
        let _ = self.handler.broker_mut().append_audit_for(&request, audit);
    }
}

fn run_blocking_listener_loop_until_cancelled<E>(
    max_idle_steps: usize,
    mut should_cancel: impl FnMut() -> bool,
    mut handle_step: impl FnMut() -> Result<Option<()>, E>,
) -> RuntimeTaskStatus {
    let mut idle_steps = 0usize;
    while idle_steps < max_idle_steps {
        if should_cancel() {
            return RuntimeTaskStatus::Cancelled;
        }
        match handle_step() {
            Ok(Some(())) => idle_steps = 0,
            Ok(None) => idle_steps += 1,
            Err(_) => return RuntimeTaskStatus::Failed,
        }
    }
    RuntimeTaskStatus::TimedOut
}

fn dns_upstream_error_detail(error: &DnsUpstreamError) -> &'static str {
    match error {
        DnsUpstreamError::Unavailable => "unavailable",
        DnsUpstreamError::SourceMismatch => "source_mismatch",
        DnsUpstreamError::MalformedResponse => "malformed_response",
    }
}

fn proxy_egress_error_detail(error: &ProxyEgressError) -> &'static str {
    match error {
        ProxyEgressError::SendFailed => "send_failed",
    }
}

#[cfg(test)]
fn run_blocking_audit_fan_in_until_cancelled<E>(
    max_idle_steps: usize,
    should_cancel: impl FnMut() -> bool,
    mut pump_once: impl FnMut() -> Result<bool, E>,
) -> RuntimeTaskStatus {
    run_blocking_listener_loop_until_cancelled(max_idle_steps, should_cancel, || {
        pump_once().map(|made_progress| made_progress.then_some(()))
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpProxyListenerStepResult {
    pub client: SocketAddr,
    pub request_len: usize,
    pub response_len: usize,
    pub sent_response: bool,
    pub send_status: String,
    pub status_code: u16,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub forwarded: bool,
}

pub trait BlockingTcpListenerSocket {
    fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

impl BlockingTcpListenerSocket for TcpListener {
    fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        TcpListener::local_addr(self)
    }
}

#[derive(Debug)]
pub struct BlockingHttpProxyServer<E, L = TcpListener> {
    listener: L,
    frontend: ExplicitProxyFrontend<E>,
    io_timeout: Duration,
    max_request_bytes: usize,
}

impl<E: ExplicitProxyEgress> BlockingHttpProxyServer<E, TcpListener> {
    pub fn bind(
        bind_addr: SocketAddr,
        frontend: ExplicitProxyFrontend<E>,
        io_timeout: Duration,
        max_request_bytes: usize,
    ) -> Result<Self, ProxyEgressError> {
        let listener = TcpListener::bind(bind_addr).map_err(|_| ProxyEgressError::SendFailed)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProxyEgressError::SendFailed)?;
        Ok(Self {
            listener,
            frontend,
            io_timeout,
            max_request_bytes,
        })
    }
}

impl<E: ExplicitProxyEgress, L: BlockingTcpListenerSocket> BlockingHttpProxyServer<E, L> {
    const LISTENER_TASK_NAME: &'static str = "http_proxy_accept_loop";

    pub fn local_addr(&self) -> Result<SocketAddr, ProxyEgressError> {
        self.listener
            .local_addr()
            .map_err(|_| ProxyEgressError::SendFailed)
    }

    pub fn handle_one(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<HttpProxyListenerStepResult>, ProxyEgressError> {
        let (mut stream, client) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err(ProxyEgressError::SendFailed),
        };
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        let read = read_http_proxy_request(&mut stream, self.max_request_bytes)?;
        if !read.status.is_complete() {
            self.record_client_read_failure(client, read.observed_len, read.status, now_ms);
        }
        self.handle_http_proxy_request(client, &read.request, &mut stream, now_ms)
            .map(Some)
    }

    pub fn run_until_cancelled(
        &mut self,
        now_ms: u64,
        max_idle_steps: usize,
        should_cancel: impl FnMut() -> bool,
    ) -> RuntimeTaskStatus {
        run_blocking_listener_loop_until_cancelled(max_idle_steps, should_cancel, || {
            match self.handle_one(now_ms) {
                Ok(step) => Ok(step.map(|_| ())),
                Err(error) => {
                    self.record_listener_loop_error(now_ms, &error);
                    Err(error)
                }
            }
        })
    }

    pub fn frontend(&self) -> &ExplicitProxyFrontend<E> {
        &self.frontend
    }

    fn record_listener_loop_error(&mut self, now_ms: u64, error: &ProxyEgressError) {
        let sandbox_id = self.frontend.sandbox_id().to_string();
        let request = PolicyRequest::unsupported(
            sandbox_id.clone(),
            Frontend::HttpProxy,
            DenialReason::RuntimeState,
        );
        let audit = AuditRecord::new_at(AuditKind::BrokerError, sandbox_id, now_ms as u128)
            .with_frontend(Frontend::HttpProxy)
            .with_protocol(Protocol::Http)
            .with_decision(Decision::FailClosed, Some(DenialReason::RuntimeState))
            .with_detail("runtime_error", "listener_loop_error")
            .with_detail(
                "listener_component",
                RuntimeComponent::HttpProxyListener.as_detail(),
            )
            .with_detail("listener_task", Self::LISTENER_TASK_NAME)
            .with_detail("listener_error", proxy_egress_error_detail(error));
        let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
    }

    fn record_client_read_failure(
        &mut self,
        client: SocketAddr,
        observed_len: usize,
        status: HttpProxyReadStatus,
        now_ms: u64,
    ) {
        let sandbox_id = self.frontend.sandbox_id().to_string();
        let request = PolicyRequest::unsupported(
            sandbox_id.clone(),
            Frontend::HttpProxy,
            DenialReason::ProxyMalformed,
        );
        let audit = AuditRecord::new_at(AuditKind::BrokerError, sandbox_id, now_ms as u128)
            .with_frontend(Frontend::HttpProxy)
            .with_protocol(Protocol::Http)
            .with_source(NetworkEndpoint {
                ip: Some(client.ip()),
                port: Some(client.port()),
            })
            .with_decision(Decision::FailClosed, Some(DenialReason::ProxyMalformed))
            .with_detail("client", client.to_string())
            .with_detail("read_status", status.as_detail())
            .with_detail("observed_request_len", observed_len.to_string())
            .with_detail("error", "http_proxy_client_read_incomplete");
        let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
    }

    fn handle_http_proxy_request<W: Write>(
        &mut self,
        client: SocketAddr,
        request: &[u8],
        writer: &mut W,
        now_ms: u64,
    ) -> Result<HttpProxyListenerStepResult, ProxyEgressError> {
        let request_len = request.len();
        let result = self.frontend.handle_http_proxy_bytes_at(request, now_ms);
        let (decision, reason, forwarded, egress_failed) = match result {
            Ok(result) => (result.decision, result.reason, result.forwarded, false),
            Err(ProxyEgressError::SendFailed) => (
                Decision::FailClosed,
                Some(DenialReason::ResourceLimit),
                false,
                true,
            ),
        };
        let (status_code, response) = http_proxy_response_for(request, decision, egress_failed);
        match writer.write_all(response.as_bytes()) {
            Ok(()) => Ok(HttpProxyListenerStepResult {
                client,
                request_len,
                response_len: response.len(),
                sent_response: true,
                send_status: "sent".to_string(),
                status_code,
                decision,
                reason,
                forwarded,
            }),
            Err(_) => {
                let sandbox_id = self.frontend.sandbox_id().to_string();
                let audit =
                    AuditRecord::new_at(AuditKind::BrokerError, sandbox_id.clone(), now_ms as u128)
                        .with_frontend(Frontend::HttpProxy)
                        .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                        .with_detail("client", client.to_string())
                        .with_detail("request_len", request_len.to_string())
                        .with_detail("response_len", response.len().to_string())
                        .with_detail("send_status", "send_failed")
                        .with_detail("error", "http_proxy_client_send_failed");
                let request = PolicyRequest::unsupported(
                    sandbox_id,
                    Frontend::HttpProxy,
                    DenialReason::ResourceLimit,
                );
                let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
                Ok(HttpProxyListenerStepResult {
                    client,
                    request_len,
                    response_len: response.len(),
                    sent_response: false,
                    send_status: "send_failed".to_string(),
                    status_code,
                    decision: Decision::FailClosed,
                    reason: Some(DenialReason::ResourceLimit),
                    forwarded,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpProxyReadStatus {
    Complete,
    EmptyClosed,
    EmptyError,
    PartialClosed,
    PartialError,
    HeaderLimit,
}

impl HttpProxyReadStatus {
    fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    fn as_detail(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::EmptyClosed => "empty_closed",
            Self::EmptyError => "empty_error",
            Self::PartialClosed => "partial_closed",
            Self::PartialError => "partial_error",
            Self::HeaderLimit => "header_limit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpProxyReadResult {
    request: Vec<u8>,
    observed_len: usize,
    status: HttpProxyReadStatus,
}

fn read_http_proxy_request(
    stream: &mut TcpStream,
    max_request_bytes: usize,
) -> Result<HttpProxyReadResult, ProxyEgressError> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 256];
    let mut status = HttpProxyReadStatus::HeaderLimit;
    while request.len() < max_request_bytes.max(1) {
        let remaining = max_request_bytes.max(1).saturating_sub(request.len());
        let read_len = remaining.min(chunk.len());
        let len = match stream.read(&mut chunk[..read_len]) {
            Ok(len) => len,
            Err(_) => {
                status = if request.is_empty() {
                    HttpProxyReadStatus::EmptyError
                } else {
                    HttpProxyReadStatus::PartialError
                };
                break;
            }
        };
        if len == 0 {
            status = if request.is_empty() {
                HttpProxyReadStatus::EmptyClosed
            } else {
                HttpProxyReadStatus::PartialClosed
            };
            break;
        }
        request.extend_from_slice(&chunk[..len]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(HttpProxyReadResult {
                observed_len: request.len(),
                request,
                status: HttpProxyReadStatus::Complete,
            });
        }
    }
    let observed_len = request.len();
    Ok(HttpProxyReadResult {
        request: Vec::new(),
        observed_len,
        status,
    })
}

fn http_proxy_response_for(
    request: &[u8],
    decision: Decision,
    egress_failed: bool,
) -> (u16, &'static str) {
    if egress_failed {
        return (502, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
    }
    if decision.is_allow() {
        if request.starts_with(b"CONNECT ") {
            (200, "HTTP/1.1 200 Connection Established\r\n\r\n")
        } else {
            (200, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        }
    } else if matches!(decision, Decision::FailClosed) {
        (400, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    } else {
        (403, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5ListenerStepResult {
    pub client: SocketAddr,
    pub greeting_len: usize,
    pub request_len: usize,
    pub response_len: usize,
    pub sent_response: bool,
    pub send_status: String,
    pub reply_code: u8,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub forwarded: bool,
}

struct Socks5MalformedStep<'a> {
    client: SocketAddr,
    greeting_len: usize,
    request_len: usize,
    response: &'a [u8],
    now_ms: u64,
    error: ProxyParseError,
}

#[derive(Debug)]
pub struct BlockingSocks5ProxyServer<E, L = TcpListener> {
    listener: L,
    frontend: ExplicitProxyFrontend<E>,
    io_timeout: Duration,
    max_request_bytes: usize,
}

impl<E: ExplicitProxyEgress> BlockingSocks5ProxyServer<E, TcpListener> {
    pub fn bind(
        bind_addr: SocketAddr,
        frontend: ExplicitProxyFrontend<E>,
        io_timeout: Duration,
        max_request_bytes: usize,
    ) -> Result<Self, ProxyEgressError> {
        let listener = TcpListener::bind(bind_addr).map_err(|_| ProxyEgressError::SendFailed)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProxyEgressError::SendFailed)?;
        Ok(Self {
            listener,
            frontend,
            io_timeout,
            max_request_bytes,
        })
    }
}

impl<E: ExplicitProxyEgress, L: BlockingTcpListenerSocket> BlockingSocks5ProxyServer<E, L> {
    const LISTENER_TASK_NAME: &'static str = "socks5_accept_loop";

    pub fn local_addr(&self) -> Result<SocketAddr, ProxyEgressError> {
        self.listener
            .local_addr()
            .map_err(|_| ProxyEgressError::SendFailed)
    }

    pub fn handle_one(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<Socks5ListenerStepResult>, ProxyEgressError> {
        let (mut stream, client) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err(ProxyEgressError::SendFailed),
        };
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| ProxyEgressError::SendFailed)?;
        let greeting = match read_socks5_greeting(&mut stream, self.max_request_bytes) {
            Ok(greeting) => greeting,
            Err(_) => {
                return Ok(Some(self.handle_socks5_malformed(
                    Socks5MalformedStep {
                        client,
                        greeting_len: 0,
                        request_len: 0,
                        response: &[0x05, 0xff],
                        now_ms,
                        error: ProxyParseError::Truncated,
                    },
                    &mut stream,
                )));
            }
        };
        if !socks5_greeting_supports_no_auth(&greeting) {
            return Ok(Some(self.handle_socks5_malformed(
                Socks5MalformedStep {
                    client,
                    greeting_len: greeting.len(),
                    request_len: 0,
                    response: &[0x05, 0xff],
                    now_ms,
                    error: ProxyParseError::UnsupportedSocksAuthentication,
                },
                &mut stream,
            )));
        }
        if let Some(step) = self.handle_socks5_method_selection_response(
            client,
            greeting.len(),
            &mut stream,
            now_ms,
        ) {
            return Ok(Some(step));
        }
        let request = match read_socks5_connect_request(&mut stream, self.max_request_bytes) {
            Ok(request) => request,
            Err(_) => {
                return Ok(Some(self.handle_socks5_malformed(
                    Socks5MalformedStep {
                        client,
                        greeting_len: greeting.len(),
                        request_len: 0,
                        response: &socks5_connect_response(0x01),
                        now_ms,
                        error: ProxyParseError::Truncated,
                    },
                    &mut stream,
                )));
            }
        };
        self.handle_socks5_connect_request(client, greeting.len(), &request, &mut stream, now_ms)
            .map(Some)
    }

    pub fn run_until_cancelled(
        &mut self,
        now_ms: u64,
        max_idle_steps: usize,
        should_cancel: impl FnMut() -> bool,
    ) -> RuntimeTaskStatus {
        run_blocking_listener_loop_until_cancelled(max_idle_steps, should_cancel, || {
            match self.handle_one(now_ms) {
                Ok(step) => Ok(step.map(|_| ())),
                Err(error) => {
                    self.record_listener_loop_error(now_ms, &error);
                    Err(error)
                }
            }
        })
    }

    pub fn frontend(&self) -> &ExplicitProxyFrontend<E> {
        &self.frontend
    }

    fn record_listener_loop_error(&mut self, now_ms: u64, error: &ProxyEgressError) {
        let sandbox_id = self.frontend.sandbox_id().to_string();
        let request = PolicyRequest::unsupported(
            sandbox_id.clone(),
            Frontend::Socks5Proxy,
            DenialReason::RuntimeState,
        );
        let audit = AuditRecord::new_at(AuditKind::BrokerError, sandbox_id, now_ms as u128)
            .with_frontend(Frontend::Socks5Proxy)
            .with_protocol(Protocol::Socks)
            .with_decision(Decision::FailClosed, Some(DenialReason::RuntimeState))
            .with_detail("runtime_error", "listener_loop_error")
            .with_detail(
                "listener_component",
                RuntimeComponent::Socks5Listener.as_detail(),
            )
            .with_detail("listener_task", Self::LISTENER_TASK_NAME)
            .with_detail("listener_error", proxy_egress_error_detail(error));
        let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
    }

    fn handle_socks5_method_selection_response<W: Write>(
        &mut self,
        client: SocketAddr,
        greeting_len: usize,
        writer: &mut W,
        now_ms: u64,
    ) -> Option<Socks5ListenerStepResult> {
        let response = [0x05, 0x00];
        if writer.write_all(&response).is_ok() {
            return None;
        }
        let sandbox_id = self.frontend.sandbox_id().to_string();
        let audit = AuditRecord::new_at(AuditKind::BrokerError, sandbox_id.clone(), now_ms as u128)
            .with_frontend(Frontend::Socks5Proxy)
            .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
            .with_detail("client", client.to_string())
            .with_detail("greeting_len", greeting_len.to_string())
            .with_detail("request_len", "0")
            .with_detail("response_len", response.len().to_string())
            .with_detail("send_status", "send_failed")
            .with_detail("error", "socks5_method_selection_send_failed");
        let request = PolicyRequest::unsupported(
            sandbox_id,
            Frontend::Socks5Proxy,
            DenialReason::ResourceLimit,
        );
        let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
        Some(Socks5ListenerStepResult {
            client,
            greeting_len,
            request_len: 0,
            response_len: response.len(),
            sent_response: false,
            send_status: "send_failed".to_string(),
            reply_code: 0x00,
            decision: Decision::FailClosed,
            reason: Some(DenialReason::ResourceLimit),
            forwarded: false,
        })
    }

    fn handle_socks5_malformed<W: Write>(
        &mut self,
        step: Socks5MalformedStep<'_>,
        writer: &mut W,
    ) -> Socks5ListenerStepResult {
        let sandbox_id = self.frontend.sandbox_id().to_string();
        let policy_request =
            malformed_proxy_request(sandbox_id.clone(), Frontend::Socks5Proxy, step.error);
        let decision = self.frontend.broker_mut().evaluate(&policy_request);
        let reply_code = step.response.get(1).copied().unwrap_or(0x01);
        match writer.write_all(step.response) {
            Ok(()) => Socks5ListenerStepResult {
                client: step.client,
                greeting_len: step.greeting_len,
                request_len: step.request_len,
                response_len: step.response.len(),
                sent_response: true,
                send_status: "sent".to_string(),
                reply_code,
                decision: decision.decision,
                reason: decision.reason,
                forwarded: false,
            },
            Err(_) => {
                let audit = AuditRecord::new_at(
                    AuditKind::BrokerError,
                    sandbox_id.clone(),
                    step.now_ms as u128,
                )
                .with_frontend(Frontend::Socks5Proxy)
                .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                .with_detail("client", step.client.to_string())
                .with_detail("greeting_len", step.greeting_len.to_string())
                .with_detail("request_len", step.request_len.to_string())
                .with_detail("response_len", step.response.len().to_string())
                .with_detail("send_status", "send_failed")
                .with_detail("error", "socks5_client_send_failed");
                let request = PolicyRequest::unsupported(
                    sandbox_id,
                    Frontend::Socks5Proxy,
                    DenialReason::ResourceLimit,
                );
                let _ = self.frontend.broker_mut().append_audit_for(&request, audit);
                Socks5ListenerStepResult {
                    client: step.client,
                    greeting_len: step.greeting_len,
                    request_len: step.request_len,
                    response_len: step.response.len(),
                    sent_response: false,
                    send_status: "send_failed".to_string(),
                    reply_code,
                    decision: Decision::FailClosed,
                    reason: Some(DenialReason::ResourceLimit),
                    forwarded: false,
                }
            }
        }
    }

    fn handle_socks5_connect_request<W: Write>(
        &mut self,
        client: SocketAddr,
        greeting_len: usize,
        request: &[u8],
        writer: &mut W,
        now_ms: u64,
    ) -> Result<Socks5ListenerStepResult, ProxyEgressError> {
        let result = self
            .frontend
            .handle_socks5_connect_bytes_at(request, now_ms);
        let (decision, reason, forwarded) = match result {
            Ok(result) => (result.decision, result.reason, result.forwarded),
            Err(ProxyEgressError::SendFailed) => (
                Decision::FailClosed,
                Some(DenialReason::ResourceLimit),
                false,
            ),
        };
        let reply_code = socks5_reply_code_for(decision);
        let response = socks5_connect_response(reply_code);
        match writer.write_all(&response) {
            Ok(()) => Ok(Socks5ListenerStepResult {
                client,
                greeting_len,
                request_len: request.len(),
                response_len: response.len(),
                sent_response: true,
                send_status: "sent".to_string(),
                reply_code,
                decision,
                reason,
                forwarded,
            }),
            Err(_) => {
                let sandbox_id = self.frontend.sandbox_id().to_string();
                let audit =
                    AuditRecord::new_at(AuditKind::BrokerError, sandbox_id.clone(), now_ms as u128)
                        .with_frontend(Frontend::Socks5Proxy)
                        .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                        .with_detail("client", client.to_string())
                        .with_detail("greeting_len", greeting_len.to_string())
                        .with_detail("request_len", request.len().to_string())
                        .with_detail("response_len", response.len().to_string())
                        .with_detail("send_status", "send_failed")
                        .with_detail("error", "socks5_client_send_failed");
                let policy_request = PolicyRequest::unsupported(
                    sandbox_id,
                    Frontend::Socks5Proxy,
                    DenialReason::ResourceLimit,
                );
                let _ = self
                    .frontend
                    .broker_mut()
                    .append_audit_for(&policy_request, audit);
                Ok(Socks5ListenerStepResult {
                    client,
                    greeting_len,
                    request_len: request.len(),
                    response_len: response.len(),
                    sent_response: false,
                    send_status: "send_failed".to_string(),
                    reply_code,
                    decision: Decision::FailClosed,
                    reason: Some(DenialReason::ResourceLimit),
                    forwarded,
                })
            }
        }
    }
}

fn read_socks5_greeting(
    stream: &mut TcpStream,
    max_request_bytes: usize,
) -> Result<Vec<u8>, ProxyEgressError> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ProxyEgressError::SendFailed)?;
    let method_count = header[1] as usize;
    if 2 + method_count > max_request_bytes.max(2) {
        return Err(ProxyEgressError::SendFailed);
    }
    let mut greeting = Vec::with_capacity(2 + method_count);
    greeting.extend_from_slice(&header);
    let mut methods = vec![0u8; method_count];
    stream
        .read_exact(&mut methods)
        .map_err(|_| ProxyEgressError::SendFailed)?;
    greeting.extend_from_slice(&methods);
    Ok(greeting)
}

fn socks5_greeting_supports_no_auth(greeting: &[u8]) -> bool {
    greeting.len() >= 2 && greeting[0] == 0x05 && greeting[2..].contains(&0x00)
}

fn read_socks5_connect_request(
    stream: &mut TcpStream,
    max_request_bytes: usize,
) -> Result<Vec<u8>, ProxyEgressError> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| ProxyEgressError::SendFailed)?;
    let mut request = Vec::from(header);
    let remaining = match header[3] {
        0x01 => 6,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|_| ProxyEgressError::SendFailed)?;
            request.push(len[0]);
            len[0] as usize + 2
        }
        0x04 => 18,
        _ => 0,
    };
    if request.len() + remaining > max_request_bytes.max(request.len()) {
        return Err(ProxyEgressError::SendFailed);
    }
    let mut tail = vec![0u8; remaining];
    stream
        .read_exact(&mut tail)
        .map_err(|_| ProxyEgressError::SendFailed)?;
    request.extend_from_slice(&tail);
    Ok(request)
}

fn socks5_reply_code_for(decision: Decision) -> u8 {
    if decision.is_allow() {
        0x00
    } else if matches!(decision, Decision::FailClosed) {
        0x01
    } else {
        0x02
    }
}

fn socks5_connect_response(reply_code: u8) -> [u8; 10] {
    [0x05, reply_code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockingProxyRuntimeError {
    Dns(DnsUpstreamError),
    HttpProxy(ProxyEgressError),
    Socks5Proxy(ProxyEgressError),
    Lifecycle(RuntimeLifecycleError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockingRuntimeAuditFanInDrainReport {
    pub ingest_reports: Vec<RuntimeAuditIngestReport>,
    pub drain_report: RuntimeAuditDrainReport,
}

impl BlockingRuntimeAuditFanInDrainReport {
    pub fn made_progress(&self) -> bool {
        self.ingest_reports
            .iter()
            .any(|report| report.accepted_records > 0)
            || self.drain_report.drained_records > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockingRuntimeAuditFanInDrainError {
    Ingest(RuntimeAuditFanInError),
    Drain(RuntimeAuditDrainError),
}

#[derive(Debug)]
pub struct BlockingDnsHttpRuntime<U, E> {
    sandbox_id: String,
    shared_dns_cache: SharedDnsCache,
    lifecycle: RuntimeLifecycleHarness,
    dns_server: Option<BlockingDnsBrokerServer<U>>,
    http_proxy_server: Option<BlockingHttpProxyServer<E>>,
    aggregate_audit_records: Vec<AuditRecord>,
    last_lifecycle_sequence: u64,
    last_dns_sequence: u64,
    last_http_proxy_sequence: u64,
}

impl<U: DnsUpstream, E: ExplicitProxyEgress> BlockingDnsHttpRuntime<U, E> {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        sandbox_id: impl Into<String>,
        lifecycle_audit_capacity: usize,
        shared_dns_cache: SharedDnsCache,
        dns_bind_addr: SocketAddr,
        dns_handler: DnsBrokerHandler<U>,
        http_proxy_bind_addr: SocketAddr,
        http_proxy_frontend: ExplicitProxyFrontend<E>,
        io_timeout: Duration,
        max_dns_query_bytes: usize,
        max_http_request_bytes: usize,
        now_ms: u64,
    ) -> Result<Self, BlockingProxyRuntimeError> {
        let sandbox_id = sandbox_id.into();
        let dns_handler = dns_handler.with_shared_cache(shared_dns_cache.clone());
        let http_proxy_frontend =
            http_proxy_frontend.with_shared_dns_cache(shared_dns_cache.clone());
        let dns_server = BlockingDnsBrokerServer::bind(
            dns_bind_addr,
            dns_handler,
            io_timeout,
            max_dns_query_bytes,
        )
        .map_err(BlockingProxyRuntimeError::Dns)?;
        let http_proxy_server = BlockingHttpProxyServer::bind(
            http_proxy_bind_addr,
            http_proxy_frontend,
            io_timeout,
            max_http_request_bytes,
        )
        .map_err(BlockingProxyRuntimeError::HttpProxy)?;
        let mut lifecycle =
            RuntimeLifecycleHarness::new(sandbox_id.clone(), lifecycle_audit_capacity);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                    RuntimeComponent::AuditFanIn,
                ],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::HttpProxyListener,
                        "http_proxy_accept_loop",
                    ),
                    RuntimeTaskExpectation::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
                ],
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        let dns_addr = dns_server
            .local_addr()
            .map_err(BlockingProxyRuntimeError::Dns)?;
        let http_addr = http_proxy_server
            .local_addr()
            .map_err(BlockingProxyRuntimeError::HttpProxy)?;
        lifecycle
            .record_listener_config(
                RuntimeListenerConfig::new(RuntimeComponent::DnsListener, dns_addr.to_string())
                    .with_reachable_addr(dns_addr.to_string()),
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        lifecycle
            .record_listener_config(
                RuntimeListenerConfig::new(
                    RuntimeComponent::HttpProxyListener,
                    http_addr.to_string(),
                )
                .with_reachable_addr(http_addr.to_string()),
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        let aggregate_audit_records: Vec<_> = lifecycle.audit().records().cloned().collect();
        let last_lifecycle_sequence = aggregate_audit_records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0);
        Ok(Self {
            sandbox_id,
            shared_dns_cache,
            lifecycle,
            dns_server: Some(dns_server),
            http_proxy_server: Some(http_proxy_server),
            aggregate_audit_records,
            last_lifecycle_sequence,
            last_dns_sequence: 0,
            last_http_proxy_sequence: 0,
        })
    }

    pub fn dns_addr(&self) -> Result<SocketAddr, DnsUpstreamError> {
        self.dns_server
            .as_ref()
            .ok_or(DnsUpstreamError::Unavailable)?
            .local_addr()
    }

    pub fn http_proxy_addr(&self) -> Result<SocketAddr, ProxyEgressError> {
        self.http_proxy_server
            .as_ref()
            .ok_or(ProxyEgressError::SendFailed)?
            .local_addr()
    }

    pub fn handle_dns_once(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<DnsBrokerStepResult>, DnsUpstreamError> {
        let result = self
            .dns_server
            .as_mut()
            .ok_or(DnsUpstreamError::Unavailable)?
            .handle_one(self.sandbox_id.clone(), now_ms);
        self.archive_new_dns_records();
        result
    }

    pub fn handle_http_proxy_once(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<HttpProxyListenerStepResult>, ProxyEgressError> {
        let result = self
            .http_proxy_server
            .as_mut()
            .ok_or(ProxyEgressError::SendFailed)?
            .handle_one(now_ms);
        self.archive_new_http_records();
        result
    }

    pub fn exit(
        &mut self,
        status: RuntimeExitStatus,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        self.exit_with_task_report(status, None, now_ms)
    }

    pub fn exit_with_task_set(
        &mut self,
        status: RuntimeExitStatus,
        mut task_set: BlockingRuntimeTaskSet,
        join_timeout: Duration,
        now_ms: u64,
    ) -> Result<usize, RuntimeLifecycleError> {
        let cancelled_tasks = task_set.request_cancellation();
        let task_report = task_set.join_all_with_timeout(join_timeout);
        self.exit_with_task_report(status, Some(task_report), now_ms)?;
        Ok(cancelled_tasks)
    }

    pub fn exit_with_task_report(
        &mut self,
        status: RuntimeExitStatus,
        task_report: Option<RuntimeTaskJoinReport>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let mut cleanup_actions = Vec::new();
        if self.dns_server.is_some() {
            cleanup_actions.push(RuntimeCleanupAction::DnsListener);
        }
        if self.http_proxy_server.is_some() {
            cleanup_actions.push(RuntimeCleanupAction::HttpProxyListener);
        }
        cleanup_actions.push(RuntimeCleanupAction::AuditFanIn);
        let result = self.lifecycle.exit_with_cleanup_child_and_tasks(
            status,
            RuntimeCleanupReport::all_succeeded(cleanup_actions),
            None,
            task_report,
            now_ms,
        );
        self.archive_new_lifecycle_records();
        self.archive_new_dns_records();
        self.archive_new_http_records();
        self.dns_server = None;
        self.http_proxy_server = None;
        result?;
        Ok(())
    }

    pub fn shared_dns_cache(&self) -> SharedDnsCache {
        self.shared_dns_cache.clone()
    }

    pub fn lifecycle(&self) -> &RuntimeLifecycleHarness {
        &self.lifecycle
    }

    pub fn audit_records(&self) -> Vec<AuditRecord> {
        self.aggregate_audit_records.clone()
    }

    pub fn ingest_live_audit_sources_into_fan_in(
        &self,
        fan_in: &mut RuntimeAuditFanIn,
    ) -> Result<Vec<RuntimeAuditIngestReport>, RuntimeAuditFanInError> {
        let mut reports = Vec::new();
        reports.push(fan_in.ingest("lifecycle", self.lifecycle.audit().records())?);
        if let Some(dns_server) = self.dns_server.as_ref() {
            reports.push(fan_in.ingest("dns", dns_server.handler().broker().audit().records())?);
        }
        if let Some(http_proxy_server) = self.http_proxy_server.as_ref() {
            reports.push(fan_in.ingest(
                "http_proxy",
                http_proxy_server.frontend().broker().audit().records(),
            )?);
        }
        Ok(reports)
    }

    pub fn drain_live_audit_sources_to_sink<W: Write>(
        &self,
        fan_in: &mut RuntimeAuditFanIn,
        sink: &mut JsonLineAuditSink<W>,
    ) -> Result<BlockingRuntimeAuditFanInDrainReport, BlockingRuntimeAuditFanInDrainError> {
        let ingest_reports = self
            .ingest_live_audit_sources_into_fan_in(fan_in)
            .map_err(BlockingRuntimeAuditFanInDrainError::Ingest)?;
        let drain_report = fan_in
            .drain_to_sink(sink)
            .map_err(BlockingRuntimeAuditFanInDrainError::Drain)?;
        Ok(BlockingRuntimeAuditFanInDrainReport {
            ingest_reports,
            drain_report,
        })
    }

    pub fn dns_server(&self) -> &BlockingDnsBrokerServer<U> {
        self.dns_server.as_ref().expect("DNS server is active")
    }

    pub fn http_proxy_server(&self) -> &BlockingHttpProxyServer<E> {
        self.http_proxy_server
            .as_ref()
            .expect("HTTP proxy server is active")
    }

    fn archive_new_lifecycle_records(&mut self) {
        let records: Vec<_> = self
            .lifecycle
            .audit()
            .records()
            .filter(|record| record.sequence > self.last_lifecycle_sequence)
            .cloned()
            .collect();
        self.last_lifecycle_sequence = records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(self.last_lifecycle_sequence);
        self.aggregate_audit_records.extend(records);
    }

    fn archive_new_dns_records(&mut self) {
        if let Some(dns_server) = self.dns_server.as_ref() {
            let records: Vec<_> = dns_server
                .handler()
                .broker()
                .audit()
                .records()
                .filter(|record| record.sequence > self.last_dns_sequence)
                .cloned()
                .collect();
            self.last_dns_sequence = records
                .iter()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(self.last_dns_sequence);
            self.aggregate_audit_records.extend(records);
        }
    }

    fn archive_new_http_records(&mut self) {
        if let Some(http_proxy_server) = self.http_proxy_server.as_ref() {
            let records: Vec<_> = http_proxy_server
                .frontend()
                .broker()
                .audit()
                .records()
                .filter(|record| record.sequence > self.last_http_proxy_sequence)
                .cloned()
                .collect();
            self.last_http_proxy_sequence = records
                .iter()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(self.last_http_proxy_sequence);
            self.aggregate_audit_records.extend(records);
        }
    }
}

#[derive(Debug)]
pub struct BlockingProxyRuntime<U, H, S> {
    sandbox_id: String,
    shared_dns_cache: SharedDnsCache,
    lifecycle: RuntimeLifecycleHarness,
    dns_server: Option<BlockingDnsBrokerServer<U>>,
    http_proxy_server: Option<BlockingHttpProxyServer<H>>,
    socks5_proxy_server: Option<BlockingSocks5ProxyServer<S>>,
    aggregate_audit_records: Vec<AuditRecord>,
    drained_aggregate_audit_records: usize,
    last_lifecycle_sequence: u64,
    last_dns_sequence: u64,
    last_http_proxy_sequence: u64,
    last_socks5_proxy_sequence: u64,
}

impl<U: DnsUpstream, H: ExplicitProxyEgress, S: ExplicitProxyEgress> BlockingProxyRuntime<U, H, S> {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        sandbox_id: impl Into<String>,
        lifecycle_audit_capacity: usize,
        shared_dns_cache: SharedDnsCache,
        dns_bind_addr: SocketAddr,
        dns_handler: DnsBrokerHandler<U>,
        http_proxy_bind_addr: SocketAddr,
        http_proxy_frontend: ExplicitProxyFrontend<H>,
        socks5_proxy_bind_addr: SocketAddr,
        socks5_proxy_frontend: ExplicitProxyFrontend<S>,
        io_timeout: Duration,
        max_dns_query_bytes: usize,
        max_proxy_request_bytes: usize,
        now_ms: u64,
    ) -> Result<Self, BlockingProxyRuntimeError> {
        let sandbox_id = sandbox_id.into();
        let dns_handler = dns_handler.with_shared_cache(shared_dns_cache.clone());
        let http_proxy_frontend =
            http_proxy_frontend.with_shared_dns_cache(shared_dns_cache.clone());
        let socks5_proxy_frontend =
            socks5_proxy_frontend.with_shared_dns_cache(shared_dns_cache.clone());
        let dns_server = BlockingDnsBrokerServer::bind(
            dns_bind_addr,
            dns_handler,
            io_timeout,
            max_dns_query_bytes,
        )
        .map_err(BlockingProxyRuntimeError::Dns)?;
        let http_proxy_server = BlockingHttpProxyServer::bind(
            http_proxy_bind_addr,
            http_proxy_frontend,
            io_timeout,
            max_proxy_request_bytes,
        )
        .map_err(BlockingProxyRuntimeError::HttpProxy)?;
        let socks5_proxy_server = BlockingSocks5ProxyServer::bind(
            socks5_proxy_bind_addr,
            socks5_proxy_frontend,
            io_timeout,
            max_proxy_request_bytes,
        )
        .map_err(BlockingProxyRuntimeError::Socks5Proxy)?;
        let mut lifecycle =
            RuntimeLifecycleHarness::new(sandbox_id.clone(), lifecycle_audit_capacity);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                    RuntimeComponent::Socks5Listener,
                    RuntimeComponent::AuditFanIn,
                ],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::HttpProxyListener,
                        "http_proxy_accept_loop",
                    ),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::Socks5Listener,
                        "socks5_accept_loop",
                    ),
                    RuntimeTaskExpectation::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
                ],
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        let dns_addr = dns_server
            .local_addr()
            .map_err(BlockingProxyRuntimeError::Dns)?;
        let http_addr = http_proxy_server
            .local_addr()
            .map_err(BlockingProxyRuntimeError::HttpProxy)?;
        let socks_addr = socks5_proxy_server
            .local_addr()
            .map_err(BlockingProxyRuntimeError::Socks5Proxy)?;
        lifecycle
            .record_listener_config(
                RuntimeListenerConfig::new(RuntimeComponent::DnsListener, dns_addr.to_string())
                    .with_reachable_addr(dns_addr.to_string()),
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        lifecycle
            .record_listener_config(
                RuntimeListenerConfig::new(
                    RuntimeComponent::HttpProxyListener,
                    http_addr.to_string(),
                )
                .with_reachable_addr(http_addr.to_string()),
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        lifecycle
            .record_listener_config(
                RuntimeListenerConfig::new(
                    RuntimeComponent::Socks5Listener,
                    socks_addr.to_string(),
                )
                .with_reachable_addr(socks_addr.to_string()),
                now_ms,
            )
            .map_err(BlockingProxyRuntimeError::Lifecycle)?;
        let aggregate_audit_records: Vec<_> = lifecycle.audit().records().cloned().collect();
        let last_lifecycle_sequence = aggregate_audit_records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0);
        Ok(Self {
            sandbox_id,
            shared_dns_cache,
            lifecycle,
            dns_server: Some(dns_server),
            http_proxy_server: Some(http_proxy_server),
            socks5_proxy_server: Some(socks5_proxy_server),
            aggregate_audit_records,
            drained_aggregate_audit_records: 0,
            last_lifecycle_sequence,
            last_dns_sequence: 0,
            last_http_proxy_sequence: 0,
            last_socks5_proxy_sequence: 0,
        })
    }

    pub fn dns_addr(&self) -> Result<SocketAddr, DnsUpstreamError> {
        self.dns_server
            .as_ref()
            .ok_or(DnsUpstreamError::Unavailable)?
            .local_addr()
    }

    pub fn http_proxy_addr(&self) -> Result<SocketAddr, ProxyEgressError> {
        self.http_proxy_server
            .as_ref()
            .ok_or(ProxyEgressError::SendFailed)?
            .local_addr()
    }

    pub fn socks5_proxy_addr(&self) -> Result<SocketAddr, ProxyEgressError> {
        self.socks5_proxy_server
            .as_ref()
            .ok_or(ProxyEgressError::SendFailed)?
            .local_addr()
    }

    pub fn handle_dns_once(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<DnsBrokerStepResult>, DnsUpstreamError> {
        let result = self
            .dns_server
            .as_mut()
            .ok_or(DnsUpstreamError::Unavailable)?
            .handle_one(self.sandbox_id.clone(), now_ms);
        self.archive_new_dns_records();
        result
    }

    pub fn handle_http_proxy_once(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<HttpProxyListenerStepResult>, ProxyEgressError> {
        let result = self
            .http_proxy_server
            .as_mut()
            .ok_or(ProxyEgressError::SendFailed)?
            .handle_one(now_ms);
        self.archive_new_http_records();
        result
    }

    pub fn handle_socks5_proxy_once(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<Socks5ListenerStepResult>, ProxyEgressError> {
        let result = self
            .socks5_proxy_server
            .as_mut()
            .ok_or(ProxyEgressError::SendFailed)?
            .handle_one(now_ms);
        self.archive_new_socks5_records();
        result
    }

    pub fn exit(
        &mut self,
        status: RuntimeExitStatus,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        self.exit_with_task_report(status, None, now_ms)
    }

    pub fn exit_with_task_set(
        &mut self,
        status: RuntimeExitStatus,
        mut task_set: BlockingRuntimeTaskSet,
        join_timeout: Duration,
        now_ms: u64,
    ) -> Result<usize, RuntimeLifecycleError> {
        let cancelled_tasks = task_set.request_cancellation();
        let task_report = task_set.join_all_with_timeout(join_timeout);
        self.exit_with_task_report(status, Some(task_report), now_ms)?;
        Ok(cancelled_tasks)
    }

    pub fn exit_with_task_report(
        &mut self,
        status: RuntimeExitStatus,
        task_report: Option<RuntimeTaskJoinReport>,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let mut cleanup_actions = Vec::new();
        if self.dns_server.is_some() {
            cleanup_actions.push(RuntimeCleanupAction::DnsListener);
        }
        if self.http_proxy_server.is_some() {
            cleanup_actions.push(RuntimeCleanupAction::HttpProxyListener);
        }
        if self.socks5_proxy_server.is_some() {
            cleanup_actions.push(RuntimeCleanupAction::Socks5Listener);
        }
        cleanup_actions.push(RuntimeCleanupAction::AuditFanIn);
        let result = self.lifecycle.exit_with_cleanup_child_and_tasks(
            status,
            RuntimeCleanupReport::all_succeeded(cleanup_actions),
            None,
            task_report,
            now_ms,
        );
        self.archive_new_lifecycle_records();
        self.archive_new_dns_records();
        self.archive_new_http_records();
        self.archive_new_socks5_records();
        self.dns_server = None;
        self.http_proxy_server = None;
        self.socks5_proxy_server = None;
        result?;
        Ok(())
    }

    pub fn shared_dns_cache(&self) -> SharedDnsCache {
        self.shared_dns_cache.clone()
    }

    pub fn lifecycle(&self) -> &RuntimeLifecycleHarness {
        &self.lifecycle
    }

    pub fn audit_records(&self) -> Vec<AuditRecord> {
        self.aggregate_audit_records.clone()
    }

    pub fn drain_aggregate_audit_to_sink<W: Write>(
        &mut self,
        sink: &mut JsonLineAuditSink<W>,
    ) -> Result<usize, AuditSinkError> {
        let start = self.drained_aggregate_audit_records;
        let end = self.aggregate_audit_records.len();
        for record in &self.aggregate_audit_records[start..end] {
            sink.append(record)?;
        }
        self.drained_aggregate_audit_records = end;
        Ok(end - start)
    }

    pub fn ingest_live_audit_sources_into_fan_in(
        &self,
        fan_in: &mut RuntimeAuditFanIn,
    ) -> Result<Vec<RuntimeAuditIngestReport>, RuntimeAuditFanInError> {
        let mut reports = Vec::new();
        reports.push(fan_in.ingest("lifecycle", self.lifecycle.audit().records())?);
        if let Some(dns_server) = self.dns_server.as_ref() {
            reports.push(fan_in.ingest("dns", dns_server.handler().broker().audit().records())?);
        }
        if let Some(http_proxy_server) = self.http_proxy_server.as_ref() {
            reports.push(fan_in.ingest(
                "http_proxy",
                http_proxy_server.frontend().broker().audit().records(),
            )?);
        }
        if let Some(socks5_proxy_server) = self.socks5_proxy_server.as_ref() {
            reports.push(fan_in.ingest(
                "socks5_proxy",
                socks5_proxy_server.frontend().broker().audit().records(),
            )?);
        }
        Ok(reports)
    }

    pub fn drain_live_audit_sources_to_sink<W: Write>(
        &self,
        fan_in: &mut RuntimeAuditFanIn,
        sink: &mut JsonLineAuditSink<W>,
    ) -> Result<BlockingRuntimeAuditFanInDrainReport, BlockingRuntimeAuditFanInDrainError> {
        let ingest_reports = self
            .ingest_live_audit_sources_into_fan_in(fan_in)
            .map_err(BlockingRuntimeAuditFanInDrainError::Ingest)?;
        let drain_report = fan_in
            .drain_to_sink(sink)
            .map_err(BlockingRuntimeAuditFanInDrainError::Drain)?;
        Ok(BlockingRuntimeAuditFanInDrainReport {
            ingest_reports,
            drain_report,
        })
    }

    pub fn dns_server(&self) -> &BlockingDnsBrokerServer<U> {
        self.dns_server.as_ref().expect("DNS server is active")
    }

    pub fn http_proxy_server(&self) -> &BlockingHttpProxyServer<H> {
        self.http_proxy_server
            .as_ref()
            .expect("HTTP proxy server is active")
    }

    pub fn socks5_proxy_server(&self) -> &BlockingSocks5ProxyServer<S> {
        self.socks5_proxy_server
            .as_ref()
            .expect("SOCKS5 proxy server is active")
    }

    fn archive_new_lifecycle_records(&mut self) {
        let records: Vec<_> = self
            .lifecycle
            .audit()
            .records()
            .filter(|record| record.sequence > self.last_lifecycle_sequence)
            .cloned()
            .collect();
        self.last_lifecycle_sequence = records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(self.last_lifecycle_sequence);
        self.aggregate_audit_records.extend(records);
    }

    fn archive_new_dns_records(&mut self) {
        if let Some(dns_server) = self.dns_server.as_ref() {
            let records: Vec<_> = dns_server
                .handler()
                .broker()
                .audit()
                .records()
                .filter(|record| record.sequence > self.last_dns_sequence)
                .cloned()
                .collect();
            self.last_dns_sequence = records
                .iter()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(self.last_dns_sequence);
            self.aggregate_audit_records.extend(records);
        }
    }

    fn archive_new_http_records(&mut self) {
        if let Some(http_proxy_server) = self.http_proxy_server.as_ref() {
            let records: Vec<_> = http_proxy_server
                .frontend()
                .broker()
                .audit()
                .records()
                .filter(|record| record.sequence > self.last_http_proxy_sequence)
                .cloned()
                .collect();
            self.last_http_proxy_sequence = records
                .iter()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(self.last_http_proxy_sequence);
            self.aggregate_audit_records.extend(records);
        }
    }

    fn archive_new_socks5_records(&mut self) {
        if let Some(socks5_proxy_server) = self.socks5_proxy_server.as_ref() {
            let records: Vec<_> = socks5_proxy_server
                .frontend()
                .broker()
                .audit()
                .records()
                .filter(|record| record.sequence > self.last_socks5_proxy_sequence)
                .cloned()
                .collect();
            self.last_socks5_proxy_sequence = records
                .iter()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(self.last_socks5_proxy_sequence);
            self.aggregate_audit_records.extend(records);
        }
    }
}

#[derive(Debug, Default)]
pub struct BlockingRuntimeTaskSet {
    supervisor: RuntimeTaskSupervisor,
    tasks: Vec<BlockingRuntimeTask>,
}

#[derive(Debug)]
struct BlockingRuntimeTask {
    handle: RuntimeTaskHandle,
    join: JoinHandle<RuntimeTaskStatus>,
    status_rx: Receiver<RuntimeTaskStatus>,
    cancellation: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Debug)]
pub struct BlockingRuntimeCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl BlockingRuntimeCancellationToken {
    fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockingRuntimeTaskSetError {
    Supervisor(RuntimeTaskSupervisorError),
    SpawnFailed {
        component: RuntimeComponent,
        task_name: String,
    },
}

impl From<RuntimeTaskSupervisorError> for BlockingRuntimeTaskSetError {
    fn from(error: RuntimeTaskSupervisorError) -> Self {
        Self::Supervisor(error)
    }
}

impl BlockingRuntimeTaskSet {
    pub fn new() -> Self {
        Self {
            supervisor: RuntimeTaskSupervisor::new(),
            tasks: Vec::new(),
        }
    }

    pub fn spawn_task<F>(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
        task: F,
    ) -> Result<RuntimeTaskHandle, BlockingRuntimeTaskSetError>
    where
        F: FnOnce() -> RuntimeTaskStatus + Send + 'static,
    {
        self.spawn_task_with_spawner(
            component,
            task_name,
            task,
            None,
            |task_name, task, status_tx| {
                std::thread::Builder::new().name(task_name).spawn(move || {
                    let status = task();
                    let _ = status_tx.send(status);
                    status
                })
            },
        )
    }

    pub fn spawn_cancellable_task<F>(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
        task: F,
    ) -> Result<RuntimeTaskHandle, BlockingRuntimeTaskSetError>
    where
        F: FnOnce(BlockingRuntimeCancellationToken) -> RuntimeTaskStatus + Send + 'static,
    {
        let cancellation = Arc::new(AtomicBool::new(false));
        let token = BlockingRuntimeCancellationToken::new(cancellation.clone());
        self.spawn_task_with_spawner(
            component,
            task_name,
            move || task(token),
            Some(cancellation),
            |task_name, task, status_tx| {
                std::thread::Builder::new().name(task_name).spawn(move || {
                    let status = task();
                    let _ = status_tx.send(status);
                    status
                })
            },
        )
    }

    fn spawn_task_with_spawner<F, S>(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
        task: F,
        cancellation: Option<Arc<AtomicBool>>,
        spawner: S,
    ) -> Result<RuntimeTaskHandle, BlockingRuntimeTaskSetError>
    where
        F: FnOnce() -> RuntimeTaskStatus + Send + 'static,
        S: FnOnce(
            String,
            F,
            mpsc::Sender<RuntimeTaskStatus>,
        ) -> std::io::Result<JoinHandle<RuntimeTaskStatus>>,
    {
        let task_name = task_name.into();
        let handle = self
            .supervisor
            .register_task(component, task_name.clone())?;
        let (status_tx, status_rx) = mpsc::channel();
        match spawner(task_name.clone(), task, status_tx) {
            Ok(join) => {
                self.tasks.push(BlockingRuntimeTask {
                    handle,
                    join,
                    status_rx,
                    cancellation,
                });
                Ok(handle)
            }
            Err(_) => {
                self.supervisor
                    .record_outcome(handle, RuntimeTaskStatus::JoinFailed)
                    .expect("spawn-failed task was just registered");
                Err(BlockingRuntimeTaskSetError::SpawnFailed {
                    component,
                    task_name,
                })
            }
        }
    }

    pub fn expectations(&self) -> Vec<RuntimeTaskExpectation> {
        self.supervisor.expectations()
    }

    pub fn request_cancellation(&mut self) -> usize {
        let mut cancelled = 0usize;
        for cancellation in self
            .tasks
            .iter()
            .filter_map(|task| task.cancellation.as_ref())
        {
            cancellation.store(true, Ordering::SeqCst);
            cancelled += 1;
        }
        cancelled
    }

    pub fn join_all(mut self) -> RuntimeTaskJoinReport {
        for task in self.tasks {
            let status = task.join.join().unwrap_or(RuntimeTaskStatus::JoinFailed);
            self.supervisor
                .record_outcome(task.handle, status)
                .expect("joined task was registered once");
        }
        self.supervisor.join_report()
    }

    pub fn join_all_with_timeout(mut self, timeout: Duration) -> RuntimeTaskJoinReport {
        for task in self.tasks {
            let status = match task.status_rx.recv_timeout(timeout) {
                Ok(status) => match task.join.join() {
                    Ok(join_status) if join_status == status => status,
                    Ok(join_status) => join_status,
                    Err(_) => RuntimeTaskStatus::JoinFailed,
                },
                Err(RecvTimeoutError::Timeout) => RuntimeTaskStatus::TimedOut,
                Err(RecvTimeoutError::Disconnected) => {
                    task.join.join().unwrap_or(RuntimeTaskStatus::JoinFailed)
                }
            };
            self.supervisor
                .record_outcome(task.handle, status)
                .expect("joined task was registered once");
        }
        self.supervisor.join_report()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildSupervisorError {
    SpawnFailed,
    WaitFailed,
}

impl ChildSupervisorError {
    fn as_detail(&self) -> &'static str {
        match self {
            Self::SpawnFailed => "spawn_failed",
            Self::WaitFailed => "wait_failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockingChildSessionOutcome {
    Exited(RuntimeChildExit),
    SupervisionError(ChildSupervisorError),
}

#[derive(Clone, Debug)]
pub struct BlockingChildSession {
    pub lifecycle: RuntimeLifecycleHarness,
    pub outcome: BlockingChildSessionOutcome,
}

#[derive(Debug)]
pub enum BlockingChildSessionError {
    Lifecycle {
        lifecycle: Box<RuntimeLifecycleHarness>,
        error: RuntimeLifecycleError,
    },
}

impl BlockingChildSessionError {
    pub fn lifecycle(&self) -> &RuntimeLifecycleHarness {
        match self {
            Self::Lifecycle { lifecycle, .. } => lifecycle.as_ref(),
        }
    }

    pub fn error(&self) -> RuntimeLifecycleError {
        match self {
            Self::Lifecycle { error, .. } => *error,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockingChildSupervisor;

impl BlockingChildSupervisor {
    pub fn run_session_to_exit<P, I, S>(
        &mut self,
        sandbox_id: impl Into<String>,
        lifecycle_audit_capacity: usize,
        program: P,
        args: I,
        start_ms: u64,
        exit_ms: u64,
    ) -> Result<BlockingChildSession, BlockingChildSessionError>
    where
        P: AsRef<OsStr>,
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut lifecycle = RuntimeLifecycleHarness::new(sandbox_id, lifecycle_audit_capacity);
        if let Err(error) = lifecycle.start(vec![RuntimeComponent::ChildProcess], start_ms) {
            return Err(BlockingChildSessionError::Lifecycle {
                lifecycle: Box::new(lifecycle),
                error,
            });
        }
        let outcome = match self.run_to_exit(program, args) {
            Ok(child_exit) => {
                if let Err(error) = lifecycle.exit_with_cleanup_and_child(
                    RuntimeExitStatus::Clean,
                    RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::ChildProcess]),
                    Some(child_exit.clone()),
                    exit_ms,
                ) {
                    return Err(BlockingChildSessionError::Lifecycle {
                        lifecycle: Box::new(lifecycle),
                        error,
                    });
                }
                BlockingChildSessionOutcome::Exited(child_exit)
            }
            Err(error) => {
                if let Err(lifecycle_error) =
                    lifecycle.record_child_supervision_error(error.as_detail(), exit_ms)
                {
                    return Err(BlockingChildSessionError::Lifecycle {
                        lifecycle: Box::new(lifecycle),
                        error: lifecycle_error,
                    });
                }
                if let Err(lifecycle_error) = lifecycle.exit_with_cleanup(
                    RuntimeExitStatus::Clean,
                    RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::ChildProcess]),
                    exit_ms,
                ) {
                    return Err(BlockingChildSessionError::Lifecycle {
                        lifecycle: Box::new(lifecycle),
                        error: lifecycle_error,
                    });
                }
                BlockingChildSessionOutcome::SupervisionError(error)
            }
        };
        Ok(BlockingChildSession { lifecycle, outcome })
    }

    pub fn run_to_exit<P, I, S>(
        &mut self,
        program: P,
        args: I,
    ) -> Result<RuntimeChildExit, ChildSupervisorError>
    where
        P: AsRef<OsStr>,
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ChildSupervisorError::SpawnFailed)?;
        let process_id = child.id();
        let status = child.wait().map_err(|_| ChildSupervisorError::WaitFailed)?;
        Ok(RuntimeChildExit {
            process_id: Some(process_id),
            exit_code: status.code(),
            signal: child_signal(&status),
        })
    }
}

#[cfg(unix)]
fn child_signal(status: &std::process::ExitStatus) -> Option<i32> {
    status.signal()
}

#[cfg(not(unix))]
fn child_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

#[derive(Clone, Debug)]
pub struct BlockingUdpEgress {
    bind_addr: SocketAddr,
}

impl BlockingUdpEgress {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }
}

impl Default for BlockingUdpEgress {
    fn default() -> Self {
        Self::new("0.0.0.0:0".parse().expect("valid default UDP bind address"))
    }
}

impl UdpEgress for BlockingUdpEgress {
    fn send_datagram(
        &mut self,
        destination: NetworkEndpoint,
        payload: &[u8],
    ) -> Result<(), UdpEgressError> {
        let destination = socket_addr(destination).ok_or(UdpEgressError::SendFailed)?;
        let socket = UdpSocket::bind(self.bind_addr).map_err(|_| UdpEgressError::SendFailed)?;
        socket
            .send_to(payload, destination)
            .map_err(|_| UdpEgressError::SendFailed)?;
        Ok(())
    }
}

fn socket_addr(endpoint: NetworkEndpoint) -> Option<SocketAddr> {
    Some(SocketAddr::new(endpoint.ip?, endpoint.port?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        BrokerCore, Cidr, Decision, DnsBrokerHandler, DnsCache, ExplicitProxyFrontend, FlowKey,
        InMemoryExplicitProxyEgress, PolicyConfig, PolicyEngine, PolicyRule, Protocol,
        RuntimeTaskOutcome, RuntimeTaskStatus, SharedDnsCache, TcpForwarder, UdpForwarder,
        UdpTimeoutConfig,
    };
    use std::collections::VecDeque;
    use std::io::{ErrorKind, Read, Result as IoResult, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    #[derive(Clone, Debug, Default)]
    struct FailingProxyEgress;

    #[derive(Clone, Debug, Default)]
    struct FailingDnsListenerSocket;

    impl BlockingDnsListenerSocket for FailingDnsListenerSocket {
        fn recv_from(&self, _buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
            Err(std::io::Error::other("forced dns listener recv failure"))
        }

        fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> IoResult<usize> {
            panic!("send_to should not be called after forced recv failure")
        }

        fn local_addr(&self) -> IoResult<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct FailingTcpListenerSocket;

    impl BlockingTcpListenerSocket for FailingTcpListenerSocket {
        fn accept(&self) -> IoResult<(TcpStream, SocketAddr)> {
            Err(std::io::Error::other("forced tcp listener accept failure"))
        }

        fn local_addr(&self) -> IoResult<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    impl ExplicitProxyEgress for FailingProxyEgress {
        fn forward_http(
            &mut self,
            _request: &HttpProxyRequestMetadata,
            _bytes: &[u8],
        ) -> Result<(), ProxyEgressError> {
            Err(ProxyEgressError::SendFailed)
        }

        fn connect_socks(
            &mut self,
            _request: &SocksConnectMetadata,
            _bytes: &[u8],
        ) -> Result<(), ProxyEgressError> {
            Err(ProxyEgressError::SendFailed)
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> IoResult<usize> {
            Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "deterministic test write failure",
            ))
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailingAfterRecordsWriter {
        completed_records: usize,
        fail_after_records: usize,
    }

    impl Write for FailingAfterRecordsWriter {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            if self.completed_records >= self.fail_after_records {
                return Err(std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    "deterministic partial sink failure",
                ));
            }
            self.completed_records += buf.iter().filter(|byte| **byte == b'\n').count();
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn blocking_runtime_task_set_feeds_clean_lifecycle_exit() {
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_task(RuntimeComponent::DnsListener, "dns_accept_loop", || {
                RuntimeTaskStatus::Completed
            })
            .unwrap();
        task_set
            .spawn_task(
                RuntimeComponent::HttpProxyListener,
                "http_accept_loop",
                || RuntimeTaskStatus::Cancelled,
            )
            .unwrap();
        let expectations = task_set.expectations();

        let mut lifecycle = RuntimeLifecycleHarness::new("task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                ],
                expectations,
                1_000,
            )
            .unwrap();
        let report = task_set.join_all();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::HttpProxyListener,
                ]),
                None,
                Some(report),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].details["task_join_status"], "complete");
        assert_eq!(records[1].details["failed_runtime_task_count"], "0");
        assert_eq!(records[1].details["missing_runtime_task_count"], "0");
    }

    #[test]
    fn blocking_runtime_task_set_panic_is_join_failed() {
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_task(RuntimeComponent::DnsListener, "dns_accept_loop", || {
                panic!("deterministic task panic")
            })
            .unwrap();
        let expectations = task_set.expectations();

        let mut lifecycle = RuntimeLifecycleHarness::new("task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::DnsListener], expectations, 1_000)
            .unwrap();
        let report = task_set.join_all();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::DnsListener]),
                None,
                Some(report),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "failed");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "dns_listener:dns_accept_loop:join_failed"
        );
        assert_eq!(records[1].details["failed_runtime_task_count"], "1");
    }

    #[test]
    fn blocking_runtime_task_set_rejects_duplicate_task_names() {
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_task(RuntimeComponent::DnsListener, "dns_accept_loop", || {
                RuntimeTaskStatus::Completed
            })
            .unwrap();
        assert_eq!(
            task_set.spawn_task(RuntimeComponent::DnsListener, "dns_accept_loop", || {
                RuntimeTaskStatus::Completed
            }),
            Err(BlockingRuntimeTaskSetError::Supervisor(
                RuntimeTaskSupervisorError::DuplicateTaskName {
                    component: RuntimeComponent::DnsListener,
                    task_name: "dns_accept_loop".to_string(),
                },
            ))
        );
        let report = task_set.join_all();
        assert_eq!(report.outcomes.len(), 1);
    }

    #[test]
    fn blocking_runtime_task_set_spawn_failure_is_join_failed() {
        let mut task_set = BlockingRuntimeTaskSet::new();
        let error = task_set
            .spawn_task_with_spawner(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
                || RuntimeTaskStatus::Completed,
                None,
                |_task_name, _task, _status_tx| {
                    Err(std::io::Error::new(
                        ErrorKind::WouldBlock,
                        "deterministic thread spawn failure",
                    ))
                },
            )
            .unwrap_err();
        assert_eq!(
            error,
            BlockingRuntimeTaskSetError::SpawnFailed {
                component: RuntimeComponent::DnsListener,
                task_name: "dns_accept_loop".to_string(),
            }
        );

        let expectations = task_set.expectations();
        let mut lifecycle = RuntimeLifecycleHarness::new("task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::DnsListener], expectations, 1_000)
            .unwrap();
        let report = task_set.join_all();
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::JoinFailed);
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::DnsListener]),
                None,
                Some(report),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "failed");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "dns_listener:dns_accept_loop:join_failed"
        );
    }

    #[test]
    fn blocking_runtime_task_set_timeout_is_fail_closed() {
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_task(RuntimeComponent::DnsListener, "dns_accept_loop", || {
                std::thread::sleep(Duration::from_millis(50));
                RuntimeTaskStatus::Completed
            })
            .unwrap();
        let expectations = task_set.expectations();

        let mut lifecycle = RuntimeLifecycleHarness::new("task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::DnsListener], expectations, 1_000)
            .unwrap();
        let report = task_set.join_all_with_timeout(Duration::from_millis(1));
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::TimedOut);
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::DnsListener]),
                None,
                Some(report),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "failed");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "dns_listener:dns_accept_loop:timed_out"
        );
        assert_eq!(records[1].details["failed_runtime_task_count"], "1");
    }

    #[test]
    fn blocking_dns_listener_task_cancels_without_packets() {
        let query = dns_query(0x6f6f, "Idle.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut dns_server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            Duration::from_millis(10),
            512,
        )
        .unwrap();
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
                move |token| {
                    while !token.is_cancelled() {
                        let _ = dns_server.handle_one("s1", 1_000);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    RuntimeTaskStatus::Cancelled
                },
            )
            .unwrap();

        assert_eq!(task_set.request_cancellation(), 1);
        let report = task_set.join_all_with_timeout(Duration::from_secs(1));

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(
            report.outcomes[0],
            RuntimeTaskOutcome::new(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
                RuntimeTaskStatus::Cancelled,
            )
        );
    }

    #[test]
    fn blocking_proxy_listener_tasks_cancel_without_clients() {
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut http_server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            Duration::from_millis(10),
            4096,
        )
        .unwrap();
        let mut socks_server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_millis(10),
            4096,
        )
        .unwrap();
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
                move |token| {
                    while !token.is_cancelled() {
                        let _ = http_server.handle_one(1_000);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    RuntimeTaskStatus::Cancelled
                },
            )
            .unwrap();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::Socks5Listener,
                "socks5_accept_loop",
                move |token| {
                    while !token.is_cancelled() {
                        let _ = socks_server.handle_one(1_000);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    RuntimeTaskStatus::Cancelled
                },
            )
            .unwrap();

        assert_eq!(task_set.request_cancellation(), 2);
        let report = task_set.join_all_with_timeout(Duration::from_secs(1));

        assert_eq!(report.outcomes.len(), 2);
        assert_eq!(
            report.outcomes[0],
            RuntimeTaskOutcome::new(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
                RuntimeTaskStatus::Cancelled,
            )
        );
        assert_eq!(
            report.outcomes[1],
            RuntimeTaskOutcome::new(
                RuntimeComponent::Socks5Listener,
                "socks5_accept_loop",
                RuntimeTaskStatus::Cancelled,
            )
        );
    }

    #[test]
    fn blocking_listener_loop_helper_reports_real_errors_as_failed() {
        let mut calls = 0usize;

        let status = run_blocking_listener_loop_until_cancelled(
            8,
            || false,
            || -> Result<Option<()>, ()> {
                calls += 1;
                Err(())
            },
        );

        assert_eq!(status, RuntimeTaskStatus::Failed);
        assert_eq!(calls, 1);
    }

    #[test]
    fn blocking_listener_loop_helper_resets_idle_budget_after_work() {
        let mut steps: VecDeque<Result<Option<()>, ()>> =
            VecDeque::from([Ok(None), Ok(Some(())), Ok(None), Ok(None)]);
        let mut calls = 0usize;

        let status = run_blocking_listener_loop_until_cancelled(
            2,
            || false,
            || {
                calls += 1;
                steps.pop_front().unwrap_or(Ok(None))
            },
        );

        assert_eq!(status, RuntimeTaskStatus::TimedOut);
        assert_eq!(calls, 4);
    }

    #[test]
    fn blocking_listener_loop_helper_reserves_cancelled_for_observed_cancellation() {
        let mut cancel_checks = 0usize;
        let mut calls = 0usize;

        let status = run_blocking_listener_loop_until_cancelled(
            8,
            || {
                cancel_checks += 1;
                cancel_checks == 2
            },
            || -> Result<Option<()>, ()> {
                calls += 1;
                Ok(None)
            },
        );

        assert_eq!(status, RuntimeTaskStatus::Cancelled);
        assert_eq!(calls, 1);
    }

    #[test]
    fn blocking_audit_fan_in_loop_pumps_and_drains_until_cancelled() {
        let mut start_record = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 1_000);
        start_record.sequence = 1;
        let source_records = vec![start_record];
        let mut fan_in = RuntimeAuditFanIn::new("s1", 8);
        let mut sink = JsonLineAuditSink::new(Vec::new());
        let mut first_pump = true;

        let timeout_status = run_blocking_audit_fan_in_until_cancelled(
            1,
            || false,
            || -> Result<bool, ()> {
                if first_pump {
                    first_pump = false;
                    fan_in
                        .ingest("lifecycle", &source_records)
                        .map_err(|_| ())?;
                }
                let drained = fan_in.drain_to_sink(&mut sink).map_err(|_| ())?;
                Ok(drained.drained_records > 0)
            },
        );

        assert_eq!(timeout_status, RuntimeTaskStatus::TimedOut);
        let json_lines = String::from_utf8(sink.into_inner()).unwrap();
        assert!(json_lines.contains("network_session_start"));

        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(RuntimeComponent::AuditFanIn, "audit_fan_in_loop", |token| {
                let mut start_record =
                    AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 2_000);
                start_record.sequence = 1;
                let source_records = vec![start_record];
                let mut fan_in = RuntimeAuditFanIn::new("s1", 8);
                let mut sink = JsonLineAuditSink::new(Vec::new());
                let mut first_pump = true;
                run_blocking_audit_fan_in_until_cancelled(
                    1_000_000,
                    || token.is_cancelled(),
                    || -> Result<bool, ()> {
                        if first_pump {
                            first_pump = false;
                            fan_in
                                .ingest("lifecycle", &source_records)
                                .map_err(|_| ())?;
                        }
                        let drained = fan_in.drain_to_sink(&mut sink).map_err(|_| ())?;
                        if drained.drained_records == 0 {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Ok(drained.drained_records > 0)
                    },
                )
            })
            .unwrap();
        let expectations = task_set.expectations();
        assert_eq!(task_set.request_cancellation(), 1);
        let report = task_set.join_all_with_timeout(Duration::from_secs(1));
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::Cancelled);

        let mut lifecycle = RuntimeLifecycleHarness::new("s1", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::AuditFanIn], expectations, 2_000)
            .unwrap();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::AuditFanIn]),
                None,
                Some(report),
                2_100,
            )
            .unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        let exit = records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::Allow));
        assert_eq!(exit.details["task_join_status"], "complete");
        assert_eq!(exit.details["failed_runtime_task_count"], "0");
        assert_eq!(
            exit.details["runtime_tasks"],
            "audit_fan_in:audit_fan_in_loop:cancelled"
        );
    }

    #[test]
    fn blocking_audit_fan_in_loop_failure_is_lifecycle_fail_closed() {
        let status = run_blocking_audit_fan_in_until_cancelled(
            8,
            || false,
            || -> Result<bool, ()> { Err(()) },
        );
        assert_eq!(status, RuntimeTaskStatus::Failed);

        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                |_token| {
                    run_blocking_audit_fan_in_until_cancelled(
                        8,
                        || false,
                        || -> Result<bool, ()> { Err(()) },
                    )
                },
            )
            .unwrap();
        let expectations = task_set.expectations();
        let report = task_set.join_all_with_timeout(Duration::from_secs(1));
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::Failed);

        let mut lifecycle = RuntimeLifecycleHarness::new("s1", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::AuditFanIn], expectations, 3_000)
            .unwrap();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::AuditFanIn]),
                None,
                Some(report),
                3_100,
            )
            .unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        let exit = records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::FailClosed));
        assert_eq!(exit.reason, Some(DenialReason::RuntimeState));
        assert_eq!(exit.details["task_join_status"], "failed");
        assert_eq!(exit.details["failed_runtime_task_count"], "1");
        assert_eq!(
            exit.details["runtime_tasks"],
            "audit_fan_in:audit_fan_in_loop:failed"
        );
    }

    #[test]
    fn blocking_listener_loop_error_recorders_append_structured_broker_errors() {
        let query = dns_query(0x7171, "Error.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut dns_server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            Duration::from_millis(10),
            512,
        )
        .unwrap();
        dns_server.record_listener_loop_error("s1", 1_000, &DnsUpstreamError::Unavailable);
        let dns_records: Vec<_> = dns_server.handler().broker().audit().records().collect();
        assert_eq!(dns_records.len(), 1);
        assert_eq!(dns_records[0].kind, AuditKind::BrokerError);
        assert_eq!(dns_records[0].frontend, Some(Frontend::Core));
        assert_eq!(dns_records[0].protocol, Some(Protocol::Dns));
        assert_eq!(dns_records[0].decision, Some(Decision::FailClosed));
        assert_eq!(dns_records[0].reason, Some(DenialReason::RuntimeState));
        assert_eq!(
            dns_records[0].details["runtime_error"],
            "listener_loop_error"
        );
        assert_eq!(dns_records[0].details["listener_component"], "dns_listener");
        assert_eq!(dns_records[0].details["listener_task"], "dns_accept_loop");
        assert_eq!(dns_records[0].details["listener_error"], "unavailable");

        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut http_server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            Duration::from_millis(10),
            4096,
        )
        .unwrap();
        http_server.record_listener_loop_error(1_000, &ProxyEgressError::SendFailed);
        let http_records: Vec<_> = http_server.frontend().broker().audit().records().collect();
        assert_eq!(http_records.len(), 1);
        assert_eq!(http_records[0].kind, AuditKind::BrokerError);
        assert_eq!(http_records[0].frontend, Some(Frontend::HttpProxy));
        assert_eq!(http_records[0].protocol, Some(Protocol::Http));
        assert_eq!(http_records[0].decision, Some(Decision::FailClosed));
        assert_eq!(http_records[0].reason, Some(DenialReason::RuntimeState));
        assert_eq!(
            http_records[0].details["runtime_error"],
            "listener_loop_error"
        );
        assert_eq!(
            http_records[0].details["listener_component"],
            "http_proxy_listener"
        );
        assert_eq!(
            http_records[0].details["listener_task"],
            "http_proxy_accept_loop"
        );
        assert_eq!(http_records[0].details["listener_error"], "send_failed");

        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut socks_server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_millis(10),
            4096,
        )
        .unwrap();
        socks_server.record_listener_loop_error(1_000, &ProxyEgressError::SendFailed);
        let socks_records: Vec<_> = socks_server.frontend().broker().audit().records().collect();
        assert_eq!(socks_records.len(), 1);
        assert_eq!(socks_records[0].kind, AuditKind::BrokerError);
        assert_eq!(socks_records[0].frontend, Some(Frontend::Socks5Proxy));
        assert_eq!(socks_records[0].protocol, Some(Protocol::Socks));
        assert_eq!(socks_records[0].decision, Some(Decision::FailClosed));
        assert_eq!(socks_records[0].reason, Some(DenialReason::RuntimeState));
        assert_eq!(
            socks_records[0].details["runtime_error"],
            "listener_loop_error"
        );
        assert_eq!(
            socks_records[0].details["listener_component"],
            "socks5_listener"
        );
        assert_eq!(
            socks_records[0].details["listener_task"],
            "socks5_accept_loop"
        );
        assert_eq!(socks_records[0].details["listener_error"], "send_failed");
    }

    #[test]
    fn blocking_listener_loop_socket_errors_are_audited_and_failed() {
        let query = dns_query(0x7272, "SocketError.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut dns_server = BlockingDnsBrokerServer {
            socket: FailingDnsListenerSocket,
            handler: dns_handler,
            max_query_bytes: 512,
        };

        let dns_status = dns_server.run_until_cancelled("s1", 1_000, 8, || false);
        assert_eq!(dns_status, RuntimeTaskStatus::Failed);
        let dns_records: Vec<_> = dns_server.handler().broker().audit().records().collect();
        assert_eq!(dns_records.len(), 1);
        assert_eq!(dns_records[0].kind, AuditKind::BrokerError);
        assert_eq!(
            dns_records[0].details["runtime_error"],
            "listener_loop_error"
        );
        assert_eq!(dns_records[0].details["listener_component"], "dns_listener");
        assert_eq!(dns_records[0].details["listener_error"], "unavailable");

        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut http_server = BlockingHttpProxyServer {
            listener: FailingTcpListenerSocket,
            frontend: http_frontend,
            io_timeout: Duration::from_millis(10),
            max_request_bytes: 4096,
        };

        let http_status = http_server.run_until_cancelled(1_000, 8, || false);
        assert_eq!(http_status, RuntimeTaskStatus::Failed);
        let http_records: Vec<_> = http_server.frontend().broker().audit().records().collect();
        assert_eq!(http_records.len(), 1);
        assert_eq!(http_records[0].kind, AuditKind::BrokerError);
        assert_eq!(
            http_records[0].details["runtime_error"],
            "listener_loop_error"
        );
        assert_eq!(
            http_records[0].details["listener_component"],
            "http_proxy_listener"
        );
        assert_eq!(http_records[0].details["listener_error"], "send_failed");

        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut socks_server = BlockingSocks5ProxyServer {
            listener: FailingTcpListenerSocket,
            frontend: socks_frontend,
            io_timeout: Duration::from_millis(10),
            max_request_bytes: 4096,
        };

        let socks_status = socks_server.run_until_cancelled(1_000, 8, || false);
        assert_eq!(socks_status, RuntimeTaskStatus::Failed);
        let socks_records: Vec<_> = socks_server.frontend().broker().audit().records().collect();
        assert_eq!(socks_records.len(), 1);
        assert_eq!(socks_records[0].kind, AuditKind::BrokerError);
        assert_eq!(
            socks_records[0].details["runtime_error"],
            "listener_loop_error"
        );
        assert_eq!(
            socks_records[0].details["listener_component"],
            "socks5_listener"
        );
        assert_eq!(socks_records[0].details["listener_error"], "send_failed");
    }

    #[test]
    fn blocking_listener_loop_tasks_feed_lifecycle_exit() {
        let query = dns_query(0x7070, "Loop.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut dns_server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            Duration::from_millis(10),
            512,
        )
        .unwrap();
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut http_server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            Duration::from_millis(10),
            4096,
        )
        .unwrap();
        let mut socks_server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_millis(10),
            4096,
        )
        .unwrap();
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
                move |token| {
                    dns_server.run_until_cancelled("s1", 1_000, 1_000_000, || token.is_cancelled())
                },
            )
            .unwrap();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
                move |token| {
                    http_server.run_until_cancelled(1_000, 1_000_000, || token.is_cancelled())
                },
            )
            .unwrap();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::Socks5Listener,
                "socks5_accept_loop",
                move |token| {
                    socks_server.run_until_cancelled(1_000, 1_000_000, || token.is_cancelled())
                },
            )
            .unwrap();
        task_set
            .spawn_cancellable_task(RuntimeComponent::AuditFanIn, "audit_fan_in_loop", |token| {
                run_blocking_audit_fan_in_until_cancelled(
                    1_000_000,
                    || token.is_cancelled(),
                    || -> Result<bool, ()> {
                        std::thread::sleep(Duration::from_millis(1));
                        Ok(false)
                    },
                )
            })
            .unwrap();
        let expectations = task_set.expectations();
        assert_eq!(task_set.request_cancellation(), 4);

        let report = task_set.join_all_with_timeout(Duration::from_secs(1));
        let mut lifecycle = RuntimeLifecycleHarness::new("task-sandbox", 8);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                    RuntimeComponent::Socks5Listener,
                    RuntimeComponent::AuditFanIn,
                ],
                expectations,
                1_000,
            )
            .unwrap();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![
                    RuntimeCleanupAction::DnsListener,
                    RuntimeCleanupAction::HttpProxyListener,
                    RuntimeCleanupAction::Socks5Listener,
                    RuntimeCleanupAction::AuditFanIn,
                ]),
                None,
                Some(report),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = lifecycle.audit().records().collect();
        let exit = records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::Allow));
        assert_eq!(exit.details["task_join_status"], "complete");
        assert_eq!(exit.details["failed_runtime_task_count"], "0");
        assert_eq!(
            exit.details["runtime_tasks"],
            "dns_listener:dns_accept_loop:cancelled,http_proxy_listener:http_proxy_accept_loop:cancelled,socks5_listener:socks5_accept_loop:cancelled,audit_fan_in:audit_fan_in_loop:cancelled"
        );
    }

    #[test]
    fn blocking_runtime_task_set_cancellation_is_joined_cleanly() {
        let mut task_set = BlockingRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(RuntimeComponent::DnsListener, "dns_accept_loop", |token| {
                while !token.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                RuntimeTaskStatus::Cancelled
            })
            .unwrap();
        let expectations = task_set.expectations();
        assert_eq!(task_set.request_cancellation(), 1);

        let mut lifecycle = RuntimeLifecycleHarness::new("task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::DnsListener], expectations, 1_000)
            .unwrap();
        let report = task_set.join_all_with_timeout(Duration::from_secs(1));
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::Cancelled);
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::DnsListener]),
                None,
                Some(report),
                1_100,
            )
            .unwrap();

        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].details["task_join_status"], "complete");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "dns_listener:dns_accept_loop:cancelled"
        );
        assert_eq!(records[1].details["failed_runtime_task_count"], "0");
    }

    #[test]
    fn blocking_child_supervisor_captures_clean_child_exit_for_lifecycle() {
        let mut runtime = RuntimeLifecycleHarness::new("child-sandbox", 4);
        runtime
            .start(vec![RuntimeComponent::ChildProcess], 1_000)
            .unwrap();
        let mut supervisor = BlockingChildSupervisor;
        let child_exit = supervisor
            .run_to_exit(std::env::current_exe().unwrap(), ["--list"])
            .unwrap();
        assert_eq!(child_exit.exit_code, Some(0));
        assert!(child_exit.process_id.is_some());

        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::ChildProcess]),
                Some(child_exit),
                1_100,
            )
            .unwrap();
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[1].details["child_status"], "clean");
        assert_eq!(records[1].details["child_exit_code"], "0");
    }

    #[test]
    fn blocking_child_supervisor_nonzero_exit_is_fail_closed_in_lifecycle() {
        let mut runtime = RuntimeLifecycleHarness::new("child-sandbox", 4);
        runtime
            .start(vec![RuntimeComponent::ChildProcess], 1_000)
            .unwrap();
        let mut supervisor = BlockingChildSupervisor;
        let child_exit = supervisor
            .run_to_exit(
                std::env::current_exe().unwrap(),
                ["--definitely-not-a-valid-test-harness-flag"],
            )
            .unwrap();
        assert_ne!(child_exit.exit_code, Some(0));
        assert!(child_exit.process_id.is_some());

        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::ChildProcess]),
                Some(child_exit),
                1_100,
            )
            .unwrap();
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["child_status"], "failed");
    }

    #[cfg(unix)]
    #[test]
    fn blocking_child_supervisor_signal_exit_is_fail_closed_in_lifecycle() {
        let mut runtime = RuntimeLifecycleHarness::new("child-sandbox", 4);
        runtime
            .start(vec![RuntimeComponent::ChildProcess], 1_000)
            .unwrap();
        let mut supervisor = BlockingChildSupervisor;
        let child_exit = supervisor
            .run_to_exit("sh", ["-c", "kill -TERM $$"])
            .unwrap();
        assert!(child_exit.process_id.is_some());
        assert_eq!(child_exit.exit_code, None);
        assert_eq!(child_exit.signal, Some(15));

        runtime
            .exit_with_cleanup_and_child(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::ChildProcess]),
                Some(child_exit),
                1_100,
            )
            .unwrap();
        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["child_status"], "signaled");
        assert_eq!(records[1].details["child_signal"], "15");
    }

    #[test]
    fn blocking_child_supervisor_session_spawn_failure_exits_fail_closed() {
        let mut supervisor = BlockingChildSupervisor;
        let session = supervisor
            .run_session_to_exit(
                "child-sandbox",
                8,
                "/definitely/not/a/real/foxprox-child",
                std::iter::empty::<&str>(),
                1_000,
                1_010,
            )
            .unwrap();

        assert_eq!(
            session.outcome,
            BlockingChildSessionOutcome::SupervisionError(ChildSupervisorError::SpawnFailed)
        );
        let records: Vec<_> = session.lifecycle.audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(
            records[1].details["runtime_error"],
            "child_supervision_error"
        );
        assert_eq!(
            records[1].details["child_supervision_error"],
            "spawn_failed"
        );
        assert_eq!(records[2].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[2].decision, Some(Decision::FailClosed));
        assert_eq!(records[2].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[2].details["child_status"], "unknown");
    }

    #[test]
    fn blocking_child_supervisor_session_backpressure_returns_partial_lifecycle() {
        let mut supervisor = BlockingChildSupervisor;
        let error = supervisor
            .run_session_to_exit(
                "child-sandbox",
                2,
                "/definitely/not/a/real/foxprox-child",
                std::iter::empty::<&str>(),
                1_000,
                1_010,
            )
            .unwrap_err();

        assert_eq!(
            error.error(),
            RuntimeLifecycleError::AuditBackpressure {
                attempted_kind: AuditKind::NetworkSessionExit,
            }
        );
        let records: Vec<_> = error.lifecycle().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(
            records[0].details["runtime_error"],
            "child_supervision_error"
        );
        assert_eq!(records[1].kind, AuditKind::AuditBackpressure);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].details["attempted_kind"], "networksessionexit");
    }

    #[test]
    fn blocking_child_supervisor_spawn_failure_is_audited() {
        let mut runtime = RuntimeLifecycleHarness::new("child-sandbox", 4);
        runtime
            .start(vec![RuntimeComponent::ChildProcess], 1_000)
            .unwrap();
        let mut supervisor = BlockingChildSupervisor;
        let error = supervisor
            .run_to_exit(
                "/definitely/not/a/real/foxprox-child",
                std::iter::empty::<&str>(),
            )
            .unwrap_err();
        assert_eq!(error, ChildSupervisorError::SpawnFailed);
        runtime
            .record_child_supervision_error("spawn_failed", 1_010)
            .unwrap();

        let records: Vec<_> = runtime.audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(
            records[1].details["runtime_error"],
            "child_supervision_error"
        );
        assert_eq!(
            records[1].details["child_supervision_error"],
            "spawn_failed"
        );
    }

    #[test]
    fn blocking_tcp_egress_connects_and_exchanges_bytes_through_forwarder() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-loopback")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("127.0.0.0".parse().unwrap(), 8))
                .destination_port(addr.port()),
        );
        let key = FlowKey::tcp("10.0.2.15".parse().unwrap(), 40000, addr.ip(), addr.port());
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            BlockingTcpEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        );

        let result = forwarder
            .connect_and_bridge(key, b"ping", 1_000, 1_010)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.byte_counts.from_sandbox, 4);
        assert_eq!(result.byte_counts.to_sandbox, 4);
        server.join().unwrap();
    }

    #[test]
    fn blocking_udp_egress_sends_datagram_through_forwarder() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let addr = receiver.local_addr().unwrap();

        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::udp("10.0.2.15".parse().unwrap(), 40000, addr.ip(), addr.port());
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = UdpForwarder::new(
            "s1",
            broker,
            BlockingUdpEgress::default(),
            UdpTimeoutConfig::default(),
        );

        let result = forwarder
            .handle_outbound_datagram(key, b"hello", 1_000)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let mut buf = [0u8; 16];
        let (len, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[test]
    fn blocking_explicit_proxy_http_egress_reaches_host_socket_after_policy() {
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_addr = host_listener.local_addr().unwrap();
        let host_server = thread::spawn(move || {
            let (mut stream, _) = host_listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 64];
            loop {
                let len = stream.read(&mut chunk).unwrap();
                if len == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy-host")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "127.0.0.1", host_addr.port()),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "proxy-egress-sandbox",
            broker,
            BlockingExplicitProxyEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        );
        let mut proxy_server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy_server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let request = format!(
            "GET http://127.0.0.1:{}/via-proxy HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            host_addr.port(),
            host_addr.port()
        );
        client.write_all(request.as_bytes()).unwrap();

        let step = proxy_server.handle_one(4_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.send_status, "sent");
        let mut proxy_response = String::new();
        client.read_to_string(&mut proxy_response).unwrap();
        assert!(proxy_response.starts_with("HTTP/1.1 200 OK"));
        let host_request = host_server.join().unwrap();
        assert!(std::str::from_utf8(&host_request)
            .unwrap()
            .contains("/via-proxy"));
        let records: Vec<_> = proxy_server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
    }

    #[test]
    fn blocking_explicit_proxy_socks_domain_uses_frontend_broker_dns_resolution() {
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_addr = host_listener.local_addr().unwrap();
        let host_server = thread::spawn(move || host_listener.accept().unwrap().1);
        let mut cache = DnsCache::default();
        cache.observe(
            "proxy-egress-sandbox",
            "Broker.TEST",
            "A",
            vec![host_addr.ip()],
            4_000,
            1_000,
        );

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks-domain")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("broker.test")
                .destination_port(host_addr.port()),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "proxy-egress-sandbox",
            broker,
            BlockingExplicitProxyEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        )
        .with_dns_cache(cache);
        let mut proxy_server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut response = Vec::new();
        let request = [
            0x05,
            0x01,
            0x00,
            0x03,
            11,
            b'b',
            b'r',
            b'o',
            b'k',
            b'e',
            b'r',
            b'.',
            b't',
            b'e',
            b's',
            b't',
            (host_addr.port() >> 8) as u8,
            host_addr.port() as u8,
        ];

        let step = proxy_server
            .handle_socks5_connect_request(
                "127.0.0.1:43210".parse().unwrap(),
                3,
                &request,
                &mut response,
                4_100,
            )
            .unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.reply_code, 0x00);
        assert_eq!(response, socks5_connect_response(0x00));
        assert_eq!(host_server.join().unwrap().ip(), host_addr.ip());
        let records: Vec<_> = proxy_server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(records[0].details["resolution_source"], "broker_dns");
        assert_eq!(records[0].details["selected_ip"], "127.0.0.1");
        assert_eq!(records[1].kind, AuditKind::SocksConnectDecision);
        assert_eq!(
            records[1].destination.as_ref().unwrap().ip,
            Some(host_addr.ip())
        );
    }

    #[test]
    fn blocking_explicit_proxy_socks_egress_opens_host_socket_after_policy() {
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_addr = host_listener.local_addr().unwrap();
        let host_server = thread::spawn(move || host_listener.accept().unwrap().1);

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks-host")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .destination_cidr(Cidr::new("127.0.0.0".parse().unwrap(), 8))
                .destination_port(host_addr.port()),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "proxy-egress-sandbox",
            broker,
            BlockingExplicitProxyEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        );
        let mut proxy_server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy_server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
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
                (host_addr.port() >> 8) as u8,
                host_addr.port() as u8,
            ])
            .unwrap();

        let step = proxy_server.handle_one(4_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.reply_code, 0x00);
        let accepted_peer = host_server.join().unwrap();
        assert_eq!(
            accepted_peer.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        let records: Vec<_> = proxy_server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::SocksConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
    }

    #[test]
    fn blocking_http_proxy_server_reports_idle_without_failure() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();

        let step = server.handle_one(1_000).unwrap();

        assert_eq!(step, None);
        assert!(server
            .frontend()
            .broker()
            .audit()
            .records()
            .next()
            .is_none());
    }

    #[test]
    fn blocking_http_proxy_server_handles_allowed_request() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        let step = server.handle_one(1_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.status_code, 200);
        assert_eq!(step.send_status, "sent");
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
    }

    #[test]
    fn blocking_http_proxy_server_denies_without_forwarding() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();

        let step = server.handle_one(1_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::DenyDrop);
        assert!(!step.forwarded);
        assert_eq!(step.status_code, 403);
        assert_eq!(step.send_status, "sent");
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, Some(Decision::DenyDrop));
    }

    #[test]
    fn blocking_http_proxy_server_read_timeout_is_audited_request_failure() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_millis(5),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let step = server.handle_one(1_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ProxyMalformed));
        assert!(!step.forwarded);
        assert_eq!(step.status_code, 400);
        assert_eq!(step.send_status, "sent");
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));

        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].frontend, Some(Frontend::HttpProxy));
        assert_eq!(records[0].protocol, Some(Protocol::Http));
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].reason, Some(DenialReason::ProxyMalformed));
        assert_eq!(
            records[0].source.as_ref().unwrap().ip,
            Some(client_addr.ip())
        );
        assert_eq!(
            records[0].source.as_ref().unwrap().port,
            Some(client_addr.port())
        );
        assert_eq!(records[0].details["read_status"], "empty_error");
        assert_eq!(records[0].details["observed_request_len"], "0");
        assert_eq!(
            records[0].details["error"],
            "http_proxy_client_read_incomplete"
        );
        assert_eq!(records[1].kind, AuditKind::UnsupportedDenied);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::ProxyMalformed));
    }

    #[test]
    fn blocking_http_proxy_server_partial_request_timeout_is_not_forwarded() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_millis(5),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n")
            .unwrap();

        let step = server.handle_one(1_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ProxyMalformed));
        assert!(!step.forwarded);
        assert_eq!(step.status_code, 400);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));

        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].frontend, Some(Frontend::HttpProxy));
        assert_eq!(records[0].protocol, Some(Protocol::Http));
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].reason, Some(DenialReason::ProxyMalformed));
        assert_eq!(
            records[0].source.as_ref().unwrap().ip,
            Some(client_addr.ip())
        );
        assert_eq!(
            records[0].source.as_ref().unwrap().port,
            Some(client_addr.port())
        );
        assert_eq!(records[0].details["read_status"], "partial_error");
        assert_eq!(
            records[0].details["observed_request_len"],
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n"
                .len()
                .to_string()
        );
        assert_eq!(
            records[0].details["error"],
            "http_proxy_client_read_incomplete"
        );
        assert_eq!(records[1].kind, AuditKind::UnsupportedDenied);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::ProxyMalformed));
        assert!(server.frontend().egress().forwarded_http().is_empty());
    }

    #[test]
    fn blocking_http_proxy_server_audits_client_send_failure_with_sandbox_id() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "sandbox-http",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut writer = FailingWriter;

        let step = server
            .handle_http_proxy_request(
                "127.0.0.1:43210".parse().unwrap(),
                b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
                &mut writer,
                2_000,
            )
            .unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ResourceLimit));
        assert!(step.forwarded);
        assert!(!step.sent_response);
        assert_eq!(step.send_status, "send_failed");

        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].sandbox_id, "sandbox-http");
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].details["error"], "http_proxy_client_send_failed");
        assert_eq!(records[1].details["send_status"], "send_failed");
    }

    #[test]
    fn blocking_http_proxy_server_maps_egress_failure_to_client_status() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new("sandbox-http", broker, FailingProxyEgress);
        let mut server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut response = Vec::new();

        let step = server
            .handle_http_proxy_request(
                "127.0.0.1:43210".parse().unwrap(),
                b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
                &mut response,
                2_000,
            )
            .unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ResourceLimit));
        assert!(!step.forwarded);
        assert!(step.sent_response);
        assert_eq!(step.status_code, 502);
        assert_eq!(step.send_status, "sent");
        assert!(std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 502 Bad Gateway"));

        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].sandbox_id, "sandbox-http");
        assert_eq!(records[1].details["error"], "proxy_egress_send_failed");
    }

    #[test]
    fn blocking_socks5_method_selection_write_failure_is_audited() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut writer = FailingWriter;

        let step = server
            .handle_socks5_method_selection_response(
                "127.0.0.1:43210".parse().unwrap(),
                3,
                &mut writer,
                3_000,
            )
            .unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ResourceLimit));
        assert!(!step.sent_response);
        assert_eq!(step.send_status, "send_failed");
        assert_eq!(step.reply_code, 0x00);
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].sandbox_id, "socks-sandbox");
        assert_eq!(
            records[0].details["error"],
            "socks5_method_selection_send_failed"
        );
        assert_eq!(records[0].details["send_status"], "send_failed");
    }

    #[test]
    fn blocking_explicit_proxy_http_domain_uses_frontend_broker_dns_resolution() {
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_addr = host_listener.local_addr().unwrap();
        let host_server = thread::spawn(move || {
            let (mut stream, _) = host_listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 64];
            loop {
                let len = stream.read(&mut chunk).unwrap();
                if len == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });
        let mut cache = DnsCache::default();
        cache.observe(
            "proxy-egress-sandbox",
            "Broker.TEST",
            "A",
            vec![host_addr.ip()],
            4_000,
            1_000,
        );
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-domain")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "broker.test", host_addr.port()),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "proxy-egress-sandbox",
            broker,
            BlockingExplicitProxyEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        )
        .with_dns_cache(cache);
        let mut proxy_server = BlockingHttpProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy_server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let request = format!(
            "GET http://broker.test:{}/via-dns HTTP/1.1\r\nHost: broker.test:{}\r\n\r\n",
            host_addr.port(),
            host_addr.port()
        );
        client.write_all(request.as_bytes()).unwrap();

        let step = proxy_server.handle_one(4_100).unwrap().unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.send_status, "sent");
        let host_request = host_server.join().unwrap();
        assert!(std::str::from_utf8(&host_request)
            .unwrap()
            .contains("/via-dns"));
        let records: Vec<_> = proxy_server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(records[0].details["resolution_source"], "broker_dns");
        assert_eq!(records[0].details["selected_ip"], "127.0.0.1");
        assert_eq!(records[0].details["ttl_remaining_ms"], "900");
        assert_eq!(records[1].kind, AuditKind::HttpRequestDecision);
        assert_eq!(
            records[1].destination.as_ref().unwrap().ip,
            Some(host_addr.ip())
        );
    }

    #[test]
    fn blocking_explicit_proxy_socks_egress_rejects_domain_without_host_dns() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks-domain")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .destination_port(443),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            BlockingExplicitProxyEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut response = Vec::new();
        let request = [
            0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x01, 0xbb,
        ];

        let step = server
            .handle_socks5_connect_request(
                "127.0.0.1:43210".parse().unwrap(),
                3,
                &request,
                &mut response,
                3_000,
            )
            .unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ResourceLimit));
        assert!(!step.forwarded);
        assert_eq!(step.reply_code, 0x01);
        assert_eq!(response, socks5_connect_response(0x01));
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::SocksConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].details["error"], "proxy_egress_send_failed");
    }

    #[test]
    fn blocking_socks5_proxy_server_reports_idle_without_failure() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();

        let step = server.handle_one(1_000).unwrap();

        assert_eq!(step, None);
        assert!(server
            .frontend()
            .broker()
            .audit()
            .records()
            .next()
            .is_none());
    }

    #[test]
    fn blocking_socks5_proxy_server_handles_allowed_connect() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .destination_port(443),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .unwrap();

        let step = server.handle_one(3_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::Allow);
        assert!(step.forwarded);
        assert_eq!(step.reply_code, 0x00);
        assert_eq!(step.send_status, "sent");
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(&response[..2], &[0x05, 0x00]);
        assert_eq!(
            &response[2..12],
            &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(server.frontend().egress().connected_socks().len(), 1);
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::SocksConnectDecision);
        assert_eq!(records[0].sandbox_id, "socks-sandbox");
        assert_eq!(records[0].decision, Some(Decision::Allow));
    }

    #[test]
    fn blocking_socks5_proxy_server_denies_without_forwarding() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 42, 0x00, 0x50])
            .unwrap();

        let step = server.handle_one(3_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::DenyDrop);
        assert!(!step.forwarded);
        assert_eq!(step.reply_code, 0x02);
        assert_eq!(step.send_status, "sent");
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(&response[..2], &[0x05, 0x00]);
        assert_eq!(
            &response[2..12],
            &[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert!(server.frontend().egress().connected_socks().is_empty());
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::SocksConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::DenyDrop));
    }

    #[test]
    fn blocking_socks5_proxy_server_rejects_unsupported_greeting() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).unwrap();

        let step = server.handle_one(3_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ProxyMalformed));
        assert!(!step.forwarded);
        assert_eq!(step.reply_code, 0xff);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, [0x05, 0xff]);
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::UnsupportedDenied);
        assert_eq!(records[0].sandbox_id, "socks-sandbox");
        assert_eq!(
            records[0].details["proxy_parse_error"],
            "unsupported_socks_authentication"
        );
    }

    #[test]
    fn blocking_socks5_proxy_server_fails_closed_for_truncated_connect_request() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        client.write_all(&[0x05, 0x01]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let step = server.handle_one(3_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ProxyMalformed));
        assert!(!step.forwarded);
        assert_eq!(step.reply_code, 0x01);
        assert_eq!(step.send_status, "sent");
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(&response[..2], &[0x05, 0x00]);
        assert_eq!(
            &response[2..12],
            &[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::UnsupportedDenied);
        assert_eq!(records[0].details["proxy_parse_error"], "truncated");
    }

    #[test]
    fn blocking_socks5_proxy_server_rejects_nonzero_reserved_byte_without_forwarding() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let frontend = ExplicitProxyFrontend::new(
            "socks-sandbox",
            broker,
            InMemoryExplicitProxyEgress::default(),
        );
        let mut server = BlockingSocks5ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            frontend,
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        client
            .write_all(&[0x05, 0x01, 0x7f, 0x01, 203, 0, 113, 42, 0x00, 0x50])
            .unwrap();

        let step = server.handle_one(3_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ProxyMalformed));
        assert!(!step.forwarded);
        assert_eq!(step.reply_code, 0x01);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(&response[..2], &[0x05, 0x00]);
        assert_eq!(
            &response[2..12],
            &[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert!(server.frontend().egress().connected_socks().is_empty());
        let records: Vec<_> = server.frontend().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::UnsupportedDenied);
        assert_eq!(
            records[0].details["proxy_parse_error"],
            "unsupported_socks_reserved"
        );
    }

    #[test]
    fn blocking_dns_upstream_exchanges_query_through_dns_handler() {
        let resolver = UdpSocket::bind("127.0.0.1:0").unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let query = dns_query(0x4242, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let expected_query = query.clone();
        let expected_response = response.clone();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = resolver.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], expected_query.as_slice());
            resolver.send_to(&expected_response, peer).unwrap();
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut runtime_config = BrokerRuntimeConfig::alpha_default("s1");
        runtime_config.dns_upstream = resolver_addr;
        let upstream = BlockingDnsUpstream::from_runtime_config(
            &runtime_config,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            512,
        );
        let mut handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::Allow);
        assert_eq!(result.response.as_deref(), Some(response.as_slice()));
        assert_eq!(
            result.observed_addresses,
            vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
        );
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        server.join().unwrap();
    }

    #[test]
    fn blocking_dns_upstream_rejects_wrong_source_response() {
        let resolver = UdpSocket::bind("127.0.0.1:0").unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let wrong_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let query = dns_query(0x4545, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let expected_query = query.clone();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, peer) = resolver.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], expected_query.as_slice());
            wrong_sender.send_to(&response, peer).unwrap();
        });

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let upstream = BlockingDnsUpstream::new(
            resolver_addr,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            512,
        );
        let mut handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        assert!(result.observed_addresses.is_empty());
        assert!(handler
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records[1].details["dns_upstream_error"], "source_mismatch");
        server.join().unwrap();
    }

    #[test]
    fn blocking_dns_broker_server_reports_idle_without_failure() {
        let query = dns_query(0x4545, "Idle.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let handler = DnsBrokerHandler::new(
            broker,
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap();

        assert_eq!(step, None);
        assert!(server.handler().broker().audit().records().next().is_none());
    }

    #[test]
    fn blocking_dns_broker_server_handles_one_allowed_query() {
        let resolver = UdpSocket::bind("127.0.0.1:0").unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let query = dns_query(0x4646, "Example.COM", 1);
        let response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let expected_response = response.clone();
        let resolver_thread = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (_, peer) = resolver.recv_from(&mut buf).unwrap();
            resolver.send_to(&expected_response, peer).unwrap();
        });
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let upstream = BlockingDnsUpstream::new(
            resolver_addr,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            512,
        );
        let handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap().unwrap();
        assert_eq!(step.query_len, query.len());
        assert_eq!(step.response_len, response.len());
        assert!(step.sent_response);
        assert_eq!(step.send_status, "sent");
        assert_eq!(step.decision, Decision::Allow);
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], response.as_slice());
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        resolver_thread.join().unwrap();
    }

    #[test]
    fn blocking_dns_broker_server_sends_refused_for_denied_query() {
        let query = dns_query(0x4747, "blocked.test", 1);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 8);
        let upstream = BlockingDnsUpstream::new(
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_millis(10),
            512,
        );
        let handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap().unwrap();
        assert_eq!(step.decision, Decision::DenyDrop);
        assert!(step.sent_response);
        assert_eq!(step.send_status, "sent");
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(buf[3] & 0x0f, 5);
        assert_eq!(step.response_len, len);
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, Some(Decision::DenyDrop));
    }

    #[test]
    fn blocking_dns_broker_server_audits_send_failure_and_rolls_back_cache() {
        let query = dns_query(0x4848, "Example.COM", 1);
        let mut huge_response = dns_a_response(&query, [93, 184, 216, 34], 30);
        huge_response.resize(70_000, 0);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let handler = DnsBrokerHandler::new(
            broker,
            StaticDnsUpstream {
                response: huge_response,
            },
            "10.0.2.3".parse().unwrap(),
        );
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap().unwrap();
        assert!(!step.sent_response);
        assert_eq!(step.send_status, "send_failed");
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ResourceLimit));
        assert!(server
            .handler()
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_none());
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].details["returned_addresses"], "93.184.216.34");
        assert_eq!(records[2].kind, AuditKind::BrokerError);
        assert_eq!(records[2].details["send_status"], "send_failed");
        assert_eq!(records[2].details["error"], "dns_client_send_failed");
    }

    #[test]
    fn blocking_dns_send_failure_does_not_publish_to_shared_proxy_cache() {
        let query = dns_query(0x4a4a, "Broker.TEST", 1);
        let mut huge_response = dns_a_response(&query, [127, 0, 0, 1], 30);
        huge_response.resize(70_000, 0);
        let shared_cache = SharedDnsCache::default();
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-broker-dns")
                .protocol(Protocol::Dns)
                .hostname("broker.test"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 16);
        let handler = DnsBrokerHandler::new(
            broker,
            StaticDnsUpstream {
                response: huge_response,
            },
            "10.0.2.3".parse().unwrap(),
        )
        .with_shared_cache(shared_cache.clone());
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();

        let step = server.handle_one("s1", 1_000).unwrap().unwrap();
        assert_eq!(step.send_status, "send_failed");
        assert!(shared_cache
            .resolve_hostname("broker.test", 1_100)
            .is_none());

        let mut proxy_config = PolicyConfig::default();
        proxy_config.rules.push(
            PolicyRule::allow("allow-http-domain")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "broker.test", 80),
        );
        let proxy_broker = BrokerCore::new(PolicyEngine::new(proxy_config), 8);
        let mut frontend = ExplicitProxyFrontend::new(
            "s1",
            proxy_broker,
            BlockingExplicitProxyEgress::new(Duration::from_secs(1), Duration::from_secs(1), 1024),
        )
        .with_shared_dns_cache(shared_cache);
        let error = frontend
            .handle_http_proxy_bytes_at(
                b"GET http://broker.test/ HTTP/1.1\r\nHost: broker.test\r\n\r\n",
                1_100,
            )
            .unwrap_err();
        assert_eq!(error, ProxyEgressError::SendFailed);
        let records: Vec<_> = frontend.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::HttpRequestDecision);
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert!(!records
            .iter()
            .any(|record| record.kind == AuditKind::ProxyDestinationResolved));
    }

    #[test]
    fn blocking_dns_send_failure_rolls_back_only_latest_duplicate_observation() {
        let query = dns_query(0x4949, "Example.COM", 1);
        let small_response = dns_a_response(&query, [93, 184, 216, 34], 30);
        let mut huge_response = small_response.clone();
        huge_response.resize(70_000, 0);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 12);
        let handler = DnsBrokerHandler::new(
            broker,
            SequenceDnsUpstream {
                responses: VecDeque::from([small_response.clone(), huge_response]),
            },
            "10.0.2.3".parse().unwrap(),
        );
        let mut server = BlockingDnsBrokerServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();
        let delivered = server.handle_one("s1", 1_000).unwrap().unwrap();
        assert_eq!(delivered.send_status, "sent");
        let mut buf = [0u8; 512];
        let _ = client.recv_from(&mut buf).unwrap();

        client
            .send_to(&query, server.local_addr().unwrap())
            .unwrap();
        let failed = server.handle_one("s1", 1_000).unwrap().unwrap();
        assert_eq!(failed.send_status, "send_failed");
        assert!(server
            .handler()
            .cache()
            .attribution_for("93.184.216.34".parse().unwrap(), 2_000)
            .is_some());
        let records: Vec<_> = server.handler().broker().audit().records().collect();
        assert_eq!(
            records.last().unwrap().details["error"],
            "dns_client_send_failed"
        );
    }

    #[test]
    fn blocking_dns_upstream_unavailable_maps_to_handler_fail_closed() {
        let query = dns_query(0x4343, "Example.COM", 1);
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable = closed.local_addr().unwrap();
        drop(closed);
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-example-dns")
                .protocol(Protocol::Dns)
                .hostname("example.com"),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let upstream = BlockingDnsUpstream::new(
            unreachable,
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_millis(10),
            512,
        );
        let mut handler = DnsBrokerHandler::new(broker, upstream, "10.0.2.3".parse().unwrap());

        let result = handler.handle_query("s1", &query, 1_000);
        assert_eq!(result.decision.decision, Decision::FailClosed);
        assert_eq!(result.response.unwrap()[3] & 0x0f, 5);
        let records: Vec<_> = handler.broker().audit().records().collect();
        assert_eq!(records[1].details["dns_upstream_error"], "unavailable");
    }

    #[test]
    fn blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners() {
        let query = dns_query(0x6b6b, "Broker.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let shared_cache = SharedDnsCache::default();

        let mut dns_config = PolicyConfig::default();
        dns_config.rules.push(
            PolicyRule::allow("allow-broker-dns")
                .protocol(Protocol::Dns)
                .hostname("broker.test"),
        );
        let dns_broker = BrokerCore::new(PolicyEngine::new(dns_config), 16);
        let dns_handler = DnsBrokerHandler::new(
            dns_broker,
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );

        let mut proxy_config = PolicyConfig::default();
        proxy_config.rules.push(
            PolicyRule::allow("allow-http-domain")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "broker.test", 80),
        );
        let proxy_broker = BrokerCore::new(PolicyEngine::new(proxy_config), 16);
        let proxy_frontend =
            ExplicitProxyFrontend::new("s1", proxy_broker, InMemoryExplicitProxyEgress::default());

        let mut runtime = BlockingDnsHttpRuntime::bind(
            "s1",
            8,
            shared_cache.clone(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            proxy_frontend,
            Duration::from_secs(1),
            512,
            4096,
            1_000,
        )
        .unwrap();

        let dns_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        dns_client
            .send_to(&query, runtime.dns_addr().unwrap())
            .unwrap();
        let dns_step = runtime.handle_dns_once(1_010).unwrap().unwrap();
        assert_eq!(dns_step.decision, Decision::Allow);
        assert_eq!(dns_step.send_status, "sent");
        let mut dns_reply = [0u8; 512];
        let (dns_reply_len, _) = dns_client.recv_from(&mut dns_reply).unwrap();
        assert!(dns_reply_len > query.len());
        assert!(shared_cache
            .resolve_hostname("broker.test", 1_020)
            .is_some());

        let mut http_client = TcpStream::connect(runtime.http_proxy_addr().unwrap()).unwrap();
        http_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        http_client
            .write_all(b"GET http://broker.test/ HTTP/1.1\r\nHost: broker.test\r\n\r\n")
            .unwrap();
        let http_step = runtime.handle_http_proxy_once(1_020).unwrap().unwrap();
        assert_eq!(http_step.decision, Decision::Allow);
        assert!(http_step.forwarded);
        assert_eq!(http_step.send_status, "sent");
        let mut http_response = String::new();
        http_client.read_to_string(&mut http_response).unwrap();
        assert!(http_response.starts_with("HTTP/1.1 200 OK"));

        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        assert_eq!(lifecycle_records.len(), 3);
        assert_eq!(lifecycle_records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(
            lifecycle_records[0].details["runtime_components"],
            "dns_listener,http_proxy_listener,audit_fan_in"
        );
        assert_eq!(
            lifecycle_records[1].kind,
            AuditKind::ProxyListenerConfigured
        );
        assert_eq!(lifecycle_records[1].protocol, Some(Protocol::Dns));
        assert_eq!(
            lifecycle_records[1].details["listener_component"],
            "dns_listener"
        );
        assert!(lifecycle_records[1].details["bind_addr"].starts_with("127.0.0.1:"));
        assert_eq!(
            lifecycle_records[2].kind,
            AuditKind::ProxyListenerConfigured
        );
        assert_eq!(lifecycle_records[2].protocol, Some(Protocol::Http));
        assert_eq!(
            lifecycle_records[2].details["listener_component"],
            "http_proxy_listener"
        );

        let proxy_records: Vec<_> = runtime
            .http_proxy_server()
            .frontend()
            .broker()
            .audit()
            .records()
            .collect();
        assert_eq!(proxy_records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(proxy_records[0].details["resolution_source"], "broker_dns");
        assert_eq!(proxy_records[0].details["selected_ip"], "127.0.0.1");
        assert_eq!(proxy_records[1].kind, AuditKind::HttpRequestDecision);
        assert_eq!(
            runtime
                .http_proxy_server()
                .frontend()
                .egress()
                .forwarded_http()
                .len(),
            1
        );

        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut sink = JsonLineAuditSink::new(Vec::new());
        let fan_in_report = runtime
            .drain_live_audit_sources_to_sink(&mut fan_in, &mut sink)
            .unwrap();
        assert!(fan_in_report.made_progress());
        assert_eq!(fan_in_report.ingest_reports.len(), 3);
        assert!(fan_in_report.drain_report.drained_records >= 6);
        let duplicate_report = runtime
            .drain_live_audit_sources_to_sink(&mut fan_in, &mut sink)
            .unwrap();
        assert!(!duplicate_report.made_progress());
        assert_eq!(duplicate_report.drain_report.drained_records, 0);
        let fan_in_output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(fan_in_output.contains("network_session_start"));
        assert!(fan_in_output.contains("proxy_destination_resolved"));
        assert!(fan_in_output.contains("http_request_decision"));

        runtime.exit(RuntimeExitStatus::Clean, 1_100).unwrap();
        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        assert_eq!(lifecycle_records.len(), 4);
        assert_eq!(lifecycle_records[3].kind, AuditKind::NetworkSessionExit);
        assert_eq!(lifecycle_records[3].duration_ms, Some(100));
        assert_eq!(lifecycle_records[3].details["cleanup_status"], "complete");
        assert_eq!(
            lifecycle_records[3].details["cleanup_actions"],
            "dns_listener,http_proxy_listener,audit_fan_in"
        );
        assert_eq!(
            runtime.handle_dns_once(1_101).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(1_101).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        let aggregate = runtime.audit_records();
        assert_eq!(
            aggregate.first().unwrap().kind,
            AuditKind::NetworkSessionStart
        );
        assert_eq!(
            aggregate.last().unwrap().kind,
            AuditKind::NetworkSessionExit
        );
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::DnsQueryDecision));
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::ProxyDestinationResolved));
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::HttpRequestDecision));
    }

    #[test]
    fn blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener() {
        let query = dns_query(0x7c7c, "Broker.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let shared_cache = SharedDnsCache::default();

        let mut dns_config = PolicyConfig::default();
        dns_config.rules.push(
            PolicyRule::allow("allow-broker-dns")
                .protocol(Protocol::Dns)
                .hostname("broker.test"),
        );
        let dns_broker = BrokerCore::new(PolicyEngine::new(dns_config), 16);
        let dns_handler = DnsBrokerHandler::new(
            dns_broker,
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );

        let mut http_config = PolicyConfig::default();
        http_config.rules.push(
            PolicyRule::allow("allow-http-domain")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "broker.test", 80),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(http_config), 16),
            InMemoryExplicitProxyEgress::default(),
        );

        let mut socks_config = PolicyConfig::default();
        socks_config.rules.push(
            PolicyRule::allow("allow-socks-domain")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("broker.test")
                .destination_port(443),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(socks_config), 16),
            InMemoryExplicitProxyEgress::default(),
        );

        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            shared_cache.clone(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            2_000,
        )
        .unwrap();

        let dns_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        dns_client
            .send_to(&query, runtime.dns_addr().unwrap())
            .unwrap();
        let dns_step = runtime.handle_dns_once(2_010).unwrap().unwrap();
        assert_eq!(dns_step.decision, Decision::Allow);
        assert_eq!(dns_step.send_status, "sent");
        let mut dns_reply = [0u8; 512];
        let (dns_reply_len, _) = dns_client.recv_from(&mut dns_reply).unwrap();
        assert!(dns_reply_len > query.len());
        assert!(runtime
            .shared_dns_cache()
            .resolve_hostname("broker.test", 2_020)
            .is_some());

        let mut socks_client = TcpStream::connect(runtime.socks5_proxy_addr().unwrap()).unwrap();
        socks_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socks_client
            .write_all(&[
                0x05, 0x01, 0x00, // greeting: no authentication
                0x05, 0x01, 0x00, 0x03, 11, b'b', b'r', b'o', b'k', b'e', b'r', b'.', b't', b'e',
                b's', b't', 0x01, 0xbb, // domain broker.test:443
            ])
            .unwrap();
        let socks_step = runtime.handle_socks5_proxy_once(2_020).unwrap().unwrap();
        assert_eq!(socks_step.decision, Decision::Allow);
        assert!(socks_step.forwarded);
        assert_eq!(socks_step.reply_code, 0x00);
        let mut socks_response = Vec::new();
        socks_client.read_to_end(&mut socks_response).unwrap();
        assert_eq!(
            socks_response,
            [0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );

        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        assert_eq!(lifecycle_records.len(), 4);
        assert_eq!(lifecycle_records[0].kind, AuditKind::NetworkSessionStart);
        assert_eq!(
            lifecycle_records[0].details["runtime_components"],
            "dns_listener,http_proxy_listener,socks5_listener,audit_fan_in"
        );
        assert_eq!(
            lifecycle_records[1].kind,
            AuditKind::ProxyListenerConfigured
        );
        assert_eq!(lifecycle_records[1].protocol, Some(Protocol::Dns));
        assert_eq!(
            lifecycle_records[2].kind,
            AuditKind::ProxyListenerConfigured
        );
        assert_eq!(lifecycle_records[2].protocol, Some(Protocol::Http));
        assert_eq!(
            lifecycle_records[3].kind,
            AuditKind::ProxyListenerConfigured
        );
        assert_eq!(lifecycle_records[3].protocol, Some(Protocol::Socks));
        assert_eq!(
            lifecycle_records[3].details["listener_component"],
            "socks5_listener"
        );

        let socks_records: Vec<_> = runtime
            .socks5_proxy_server()
            .frontend()
            .broker()
            .audit()
            .records()
            .collect();
        assert_eq!(socks_records[0].kind, AuditKind::ProxyDestinationResolved);
        assert_eq!(socks_records[0].details["resolution_source"], "broker_dns");
        assert_eq!(socks_records[0].details["selected_ip"], "127.0.0.1");
        assert_eq!(socks_records[1].kind, AuditKind::SocksConnectDecision);
        assert_eq!(
            socks_records[1].destination.as_ref().unwrap().port,
            Some(443)
        );
        assert_eq!(
            runtime
                .socks5_proxy_server()
                .frontend()
                .egress()
                .connected_socks()
                .len(),
            1
        );

        runtime.exit(RuntimeExitStatus::Clean, 2_100).unwrap();
        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        assert_eq!(lifecycle_records.len(), 5);
        assert_eq!(lifecycle_records[4].kind, AuditKind::NetworkSessionExit);
        assert_eq!(lifecycle_records[4].duration_ms, Some(100));
        assert_eq!(lifecycle_records[4].details["cleanup_status"], "complete");
        assert_eq!(
            lifecycle_records[4].details["cleanup_actions"],
            "dns_listener,http_proxy_listener,socks5_listener,audit_fan_in"
        );
        assert_eq!(
            runtime.handle_dns_once(2_101).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(2_101).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        assert_eq!(
            runtime.handle_socks5_proxy_once(2_101).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        let aggregate = runtime.audit_records();
        assert_eq!(
            aggregate.first().unwrap().kind,
            AuditKind::NetworkSessionStart
        );
        assert_eq!(
            aggregate.last().unwrap().kind,
            AuditKind::NetworkSessionExit
        );
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::DnsQueryDecision));
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::ProxyDestinationResolved));
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::SocksConnectDecision));
    }

    #[test]
    fn blocking_dns_http_runtime_exit_backpressure_still_closes_listeners() {
        let query = dns_query(0x6d6d, "Backpressure.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let proxy_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut runtime = BlockingDnsHttpRuntime::bind(
            "s1",
            3,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            proxy_frontend,
            Duration::from_secs(1),
            512,
            4096,
            3_200,
        )
        .unwrap();

        let error = runtime.exit(RuntimeExitStatus::Clean, 3_300).unwrap_err();

        assert!(matches!(
            error,
            RuntimeLifecycleError::AuditBackpressure {
                attempted_kind: AuditKind::NetworkSessionExit,
            }
        ));
        assert_eq!(
            runtime.handle_dns_once(3_301).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(3_301).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        let aggregate = runtime.audit_records();
        let backpressure = aggregate
            .iter()
            .find(|record| record.kind == AuditKind::AuditBackpressure)
            .expect("aggregate captures lifecycle exit backpressure");
        assert_eq!(backpressure.details["attempted_kind"], "networksessionexit");
    }

    #[test]
    fn blocking_proxy_runtime_exit_backpressure_still_closes_listeners() {
        let query = dns_query(0x7e7e, "Backpressure.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            4,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            3_300,
        )
        .unwrap();

        let error = runtime.exit(RuntimeExitStatus::Clean, 3_400).unwrap_err();

        assert!(matches!(
            error,
            RuntimeLifecycleError::AuditBackpressure {
                attempted_kind: AuditKind::NetworkSessionExit,
            }
        ));
        assert_eq!(
            runtime.handle_dns_once(3_401).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(3_401).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        assert_eq!(
            runtime.handle_socks5_proxy_once(3_401).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        let aggregate = runtime.audit_records();
        let backpressure = aggregate
            .iter()
            .find(|record| record.kind == AuditKind::AuditBackpressure)
            .expect("aggregate captures lifecycle exit backpressure");
        assert_eq!(backpressure.details["attempted_kind"], "networksessionexit");
    }

    #[test]
    fn blocking_proxy_runtime_exit_records_task_join_failure() {
        let query = dns_query(0x7a7a, "Join.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );

        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            3_500,
        )
        .unwrap();

        runtime
            .exit_with_task_report(
                RuntimeExitStatus::Clean,
                Some(RuntimeTaskJoinReport::new(vec![
                    RuntimeTaskOutcome::new(
                        RuntimeComponent::DnsListener,
                        "dns_accept_loop",
                        RuntimeTaskStatus::Completed,
                    ),
                    RuntimeTaskOutcome::new(
                        RuntimeComponent::Socks5Listener,
                        "socks_accept_loop",
                        RuntimeTaskStatus::JoinFailed,
                    ),
                ])),
                3_600,
            )
            .unwrap();

        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        let exit = lifecycle_records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::FailClosed));
        assert_eq!(exit.reason, Some(DenialReason::RuntimeState));
        assert_eq!(exit.details["task_join_status"], "failed");
        assert_eq!(
            exit.details["runtime_tasks"],
            "dns_listener:dns_accept_loop:completed,socks5_listener:socks_accept_loop:join_failed"
        );
        assert_eq!(exit.details["failed_runtime_task_count"], "1");
        assert_eq!(
            runtime.handle_socks5_proxy_once(3_601).unwrap_err(),
            ProxyEgressError::SendFailed
        );
    }

    #[test]
    fn blocking_proxy_runtime_aggregate_captures_http_read_failures() {
        let query = dns_query(0x7e7e, "Partial.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut http_config = PolicyConfig::default();
        http_config.rules.push(
            PolicyRule::allow("allow-partial")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "partial.test", 80),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(http_config), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_millis(5),
            512,
            4096,
            4_100,
        )
        .unwrap();
        let mut client = TcpStream::connect(runtime.http_proxy_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .write_all(b"GET http://partial.test/ HTTP/1.1\r\nHost: partial.test\r\n")
            .unwrap();

        let step = runtime.handle_http_proxy_once(4_110).unwrap().unwrap();
        assert_eq!(step.decision, Decision::FailClosed);
        assert_eq!(step.reason, Some(DenialReason::ProxyMalformed));
        assert!(!step.forwarded);
        assert!(runtime
            .http_proxy_server()
            .frontend()
            .egress()
            .forwarded_http()
            .is_empty());

        let aggregate = runtime.audit_records();
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::NetworkSessionStart));
        let read_error = aggregate
            .iter()
            .find(|record| {
                record.kind == AuditKind::BrokerError
                    && record
                        .details
                        .get("error")
                        .is_some_and(|error| error == "http_proxy_client_read_incomplete")
            })
            .expect("partial HTTP read error is archived");
        assert_eq!(read_error.frontend, Some(Frontend::HttpProxy));
        assert_eq!(read_error.protocol, Some(Protocol::Http));
        assert_eq!(read_error.decision, Some(Decision::FailClosed));
        assert_eq!(read_error.reason, Some(DenialReason::ProxyMalformed));
        assert_eq!(read_error.details["read_status"], "partial_error");
        assert_eq!(
            read_error.details["observed_request_len"],
            b"GET http://partial.test/ HTTP/1.1\r\nHost: partial.test\r\n"
                .len()
                .to_string()
        );
        assert!(aggregate.iter().any(|record| {
            record.kind == AuditKind::UnsupportedDenied
                && record.decision == Some(Decision::FailClosed)
                && record.reason == Some(DenialReason::ProxyMalformed)
        }));

        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let fan_in_reports = runtime
            .ingest_live_audit_sources_into_fan_in(&mut fan_in)
            .unwrap();
        assert!(fan_in_reports
            .iter()
            .any(|report| report.source == "lifecycle" && report.accepted_records >= 4));
        assert!(fan_in_reports
            .iter()
            .any(|report| report.source == "http_proxy" && report.accepted_records == 2));
        let duplicate_reports = runtime
            .ingest_live_audit_sources_into_fan_in(&mut fan_in)
            .unwrap();
        assert!(duplicate_reports
            .iter()
            .all(|report| report.accepted_records == 0));
        let fan_in_record_count: usize = fan_in_reports
            .iter()
            .map(|report| report.accepted_records)
            .sum();
        let mut fan_in_sink = JsonLineAuditSink::new(Vec::new());
        let fan_in_drain = fan_in.drain_to_sink(&mut fan_in_sink).unwrap();
        assert_eq!(fan_in_drain.drained_records, fan_in_record_count);
        let fan_in_json = String::from_utf8(fan_in_sink.into_inner()).unwrap();
        assert!(fan_in_json.contains("network_session_start"));
        assert!(fan_in_json.contains("http_proxy_client_read_incomplete"));
        assert!(fan_in_json.contains("unsupported_denied"));

        let mut loop_fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut loop_sink = JsonLineAuditSink::new(Vec::new());
        let loop_status = run_blocking_audit_fan_in_until_cancelled(
            1,
            || false,
            || -> Result<bool, ()> {
                let report = runtime
                    .drain_live_audit_sources_to_sink(&mut loop_fan_in, &mut loop_sink)
                    .map_err(|_| ())?;
                Ok(report.made_progress())
            },
        );
        assert_eq!(loop_status, RuntimeTaskStatus::TimedOut);
        let loop_json = String::from_utf8(loop_sink.into_inner()).unwrap();
        assert!(loop_json.contains("network_session_start"));
        assert!(loop_json.contains("http_proxy_client_read_incomplete"));
        assert!(loop_json.contains("unsupported_denied"));

        let mut failing_sink = JsonLineAuditSink::new(FailingWriter);
        assert!(runtime
            .drain_aggregate_audit_to_sink(&mut failing_sink)
            .is_err());
        assert_eq!(failing_sink.records_written(), 0);

        let mut partially_failing_sink = JsonLineAuditSink::new(FailingAfterRecordsWriter {
            completed_records: 0,
            fail_after_records: 1,
        });
        assert!(runtime
            .drain_aggregate_audit_to_sink(&mut partially_failing_sink)
            .is_err());
        assert_eq!(partially_failing_sink.records_written(), 1);

        let mut sink = JsonLineAuditSink::new(Vec::new());
        let drained = runtime.drain_aggregate_audit_to_sink(&mut sink).unwrap();
        assert_eq!(drained, aggregate.len());
        assert_eq!(sink.records_written(), aggregate.len() as u64);
        assert_eq!(runtime.drain_aggregate_audit_to_sink(&mut sink).unwrap(), 0);
        let json_lines = String::from_utf8(sink.into_inner()).unwrap();
        assert!(json_lines.contains("network_session_start"));
        assert!(json_lines.contains("http_proxy_client_read_incomplete"));
        assert!(json_lines.contains("unsupported_denied"));
        assert!(json_lines.contains("proxy_malformed"));
    }

    #[test]
    fn blocking_proxy_runtime_exit_fails_closed_for_partial_task_report() {
        let query = dns_query(0x7b7b, "Partial.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );

        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            3_700,
        )
        .unwrap();

        runtime
            .exit_with_task_report(
                RuntimeExitStatus::Clean,
                Some(RuntimeTaskJoinReport::new(vec![RuntimeTaskOutcome::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                    RuntimeTaskStatus::Completed,
                )])),
                3_800,
            )
            .unwrap();

        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        let exit = lifecycle_records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::FailClosed));
        assert_eq!(exit.reason, Some(DenialReason::RuntimeState));
        assert_eq!(exit.details["task_join_status"], "incomplete");
        assert_eq!(
            exit.details["missing_runtime_tasks"],
            "http_proxy_listener:http_proxy_accept_loop,socks5_listener:socks5_accept_loop,audit_fan_in:audit_fan_in_loop"
        );
        assert_eq!(exit.details["missing_runtime_task_count"], "3");
    }

    #[test]
    fn blocking_proxy_runtime_exit_with_task_set_cancels_and_joins_tasks() {
        let query = dns_query(0x7d7d, "Cancel.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            3_900,
        )
        .unwrap();
        let mut task_set = BlockingRuntimeTaskSet::new();
        for (component, task_name) in [
            (RuntimeComponent::DnsListener, "dns_accept_loop"),
            (
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
            ),
            (RuntimeComponent::Socks5Listener, "socks5_accept_loop"),
            (RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
        ] {
            task_set
                .spawn_cancellable_task(component, task_name, |token| {
                    while !token.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    RuntimeTaskStatus::Cancelled
                })
                .unwrap();
        }

        let cancelled = runtime
            .exit_with_task_set(
                RuntimeExitStatus::Clean,
                task_set,
                Duration::from_secs(1),
                4_000,
            )
            .unwrap();

        assert_eq!(cancelled, 4);
        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        let exit = lifecycle_records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::Allow));
        assert_eq!(exit.details["task_join_status"], "complete");
        assert_eq!(exit.details["failed_runtime_task_count"], "0");
        assert_eq!(exit.details["missing_runtime_task_count"], "0");
        assert_eq!(
            exit.details["runtime_tasks"],
            "dns_listener:dns_accept_loop:cancelled,http_proxy_listener:http_proxy_accept_loop:cancelled,socks5_listener:socks5_accept_loop:cancelled,audit_fan_in:audit_fan_in_loop:cancelled"
        );
        assert_eq!(
            runtime.handle_dns_once(4_001).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(4_001).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        assert_eq!(
            runtime.handle_socks5_proxy_once(4_001).unwrap_err(),
            ProxyEgressError::SendFailed
        );
    }

    #[test]
    fn blocking_proxy_runtime_aggregate_preserves_interleaved_component_order() {
        let query = dns_query(0x8d8d, "Later.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let shared_cache = SharedDnsCache::default();

        let mut dns_config = PolicyConfig::default();
        dns_config.rules.push(
            PolicyRule::allow("allow-later-dns")
                .protocol(Protocol::Dns)
                .hostname("later.test"),
        );
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(dns_config), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );

        let mut http_config = PolicyConfig::default();
        http_config.rules.push(
            PolicyRule::allow("allow-http-ip")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "127.0.0.1", 80),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(http_config), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );

        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            shared_cache,
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            3_000,
        )
        .unwrap();

        let mut http_client = TcpStream::connect(runtime.http_proxy_addr().unwrap()).unwrap();
        http_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        http_client
            .write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let http_step = runtime.handle_http_proxy_once(3_010).unwrap().unwrap();
        assert_eq!(http_step.decision, Decision::Allow);
        assert!(http_step.forwarded);
        let mut http_response = String::new();
        http_client.read_to_string(&mut http_response).unwrap();
        assert!(http_response.starts_with("HTTP/1.1 200 OK"));

        let dns_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        dns_client
            .send_to(&query, runtime.dns_addr().unwrap())
            .unwrap();
        let dns_step = runtime.handle_dns_once(3_020).unwrap().unwrap();
        assert_eq!(dns_step.decision, Decision::Allow);
        let mut dns_reply = [0u8; 512];
        let (dns_reply_len, _) = dns_client.recv_from(&mut dns_reply).unwrap();
        assert!(dns_reply_len > query.len());

        runtime.exit(RuntimeExitStatus::Clean, 3_100).unwrap();
        let aggregate = runtime.audit_records();
        let http_index = aggregate
            .iter()
            .position(|record| record.kind == AuditKind::HttpRequestDecision)
            .unwrap();
        let dns_index = aggregate
            .iter()
            .position(|record| record.kind == AuditKind::DnsQueryDecision)
            .unwrap();
        let exit_index = aggregate
            .iter()
            .position(|record| record.kind == AuditKind::NetworkSessionExit)
            .unwrap();
        assert!(http_index < dns_index);
        assert!(dns_index < exit_index);
        assert_eq!(aggregate[http_index].decision, Some(Decision::Allow));
        assert_eq!(
            aggregate[http_index].origin.as_ref().unwrap().host,
            "127.0.0.1"
        );
        assert_eq!(aggregate[dns_index].hostname.as_deref(), Some("later.test"));
        assert_eq!(aggregate[exit_index].details["cleanup_status"], "complete");
    }

    #[test]
    fn blocking_proxy_runtime_aggregate_captures_backpressure_replacement() {
        let query = dns_query(0x9e9e, "Unused.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );

        let http_config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(http_config), 1),
            InMemoryExplicitProxyEgress::default(),
        );
        let socks_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            InMemoryExplicitProxyEgress::default(),
        );

        let mut runtime = BlockingProxyRuntime::bind(
            "s1",
            8,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            http_frontend,
            "127.0.0.1:0".parse().unwrap(),
            socks_frontend,
            Duration::from_secs(1),
            512,
            4096,
            4_000,
        )
        .unwrap();

        for now_ms in [4_010, 4_020] {
            let mut http_client = TcpStream::connect(runtime.http_proxy_addr().unwrap()).unwrap();
            http_client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            http_client
                .write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .unwrap();
            let _ = runtime.handle_http_proxy_once(now_ms).unwrap().unwrap();
            let mut http_response = String::new();
            http_client.read_to_string(&mut http_response).unwrap();
            assert!(http_response.starts_with("HTTP/1.1"));
        }

        let aggregate = runtime.audit_records();
        assert!(aggregate
            .iter()
            .any(|record| record.kind == AuditKind::HttpRequestDecision));
        let backpressure = aggregate
            .iter()
            .find(|record| record.kind == AuditKind::AuditBackpressure)
            .expect("aggregate captures replacement audit_backpressure record");
        assert_eq!(
            backpressure.details["attempted_kind"],
            "httprequestdecision"
        );
    }

    #[test]
    fn missing_endpoint_maps_to_egress_errors() {
        let mut tcp = BlockingTcpEgress::default();
        assert_eq!(
            tcp.connect_and_exchange(NetworkEndpoint::default(), b"x")
                .unwrap_err(),
            TcpEgressError::ConnectFailed
        );
        let mut udp = BlockingUdpEgress::default();
        assert_eq!(
            udp.send_datagram(NetworkEndpoint::default(), b"x")
                .unwrap_err(),
            UdpEgressError::SendFailed
        );
    }

    #[derive(Clone, Debug)]
    struct StaticDnsUpstream {
        response: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct SequenceDnsUpstream {
        responses: VecDeque<Vec<u8>>,
    }

    impl DnsUpstream for SequenceDnsUpstream {
        fn exchange(
            &mut self,
            _query: &DnsQueryMetadata,
            _packet: &[u8],
        ) -> Result<Vec<u8>, DnsUpstreamError> {
            self.responses
                .pop_front()
                .ok_or(DnsUpstreamError::Unavailable)
        }
    }

    impl DnsUpstream for StaticDnsUpstream {
        fn exchange(
            &mut self,
            _query: &DnsQueryMetadata,
            _packet: &[u8],
        ) -> Result<Vec<u8>, DnsUpstreamError> {
            Ok(self.response.clone())
        }
    }

    fn dns_query(transaction_id: u16, hostname: &str, query_type: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&query_type.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn dns_a_response(query: &[u8], address: [u8; 4], ttl_seconds: u32) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }
}
