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
    RuntimeListenerConfig, RuntimeReadinessPlan, RuntimeSchedulerAction, RuntimeTaskExpectation,
    RuntimeTaskHandle, RuntimeTaskJoinReport, RuntimeTaskReadiness, RuntimeTaskStatus,
    RuntimeTaskSupervisor, RuntimeTaskSupervisorError, SharedDnsCache, SocksConnectMetadata,
    TcpEgress, TcpEgressError, UdpEgress, UdpEgressError,
};
use std::ffi::OsStr;
use std::future::Future;
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

    pub fn runtime_readiness(&self) -> RuntimeTaskReadiness {
        RuntimeTaskReadiness::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop")
            .with_ready(self.made_progress())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockingRuntimeAuditFanInDrainError {
    Ingest(RuntimeAuditFanInError),
    Drain(RuntimeAuditDrainError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockingRuntimeAuditFanInShutdownDrainReport {
    pub before_exit: BlockingRuntimeAuditFanInDrainReport,
    pub after_exit: BlockingRuntimeAuditFanInDrainReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockingRuntimeAuditFanInShutdownDrainError {
    PreExitDrain {
        error: BlockingRuntimeAuditFanInDrainError,
        exit: Result<(), RuntimeLifecycleError>,
        post_exit:
            Result<BlockingRuntimeAuditFanInDrainReport, BlockingRuntimeAuditFanInDrainError>,
    },
    Exit {
        before_exit: BlockingRuntimeAuditFanInDrainReport,
        error: RuntimeLifecycleError,
        post_exit:
            Result<BlockingRuntimeAuditFanInDrainReport, BlockingRuntimeAuditFanInDrainError>,
    },
    PostExitDrain {
        before_exit: BlockingRuntimeAuditFanInDrainReport,
        error: BlockingRuntimeAuditFanInDrainError,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncRuntimeAuditFanInShutdownDrainReport {
    pub cancelled_tasks: usize,
    pub task_report: RuntimeTaskJoinReport,
    pub shutdown_drain: BlockingRuntimeAuditFanInShutdownDrainReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsyncRuntimeAuditFanInShutdownDrainError {
    ShutdownDrain {
        cancelled_tasks: usize,
        task_report: RuntimeTaskJoinReport,
        error: BlockingRuntimeAuditFanInShutdownDrainError,
    },
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

    pub fn record_readiness_plan(
        &mut self,
        plan: &RuntimeReadinessPlan,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let result = self.lifecycle.record_readiness_plan(plan, now_ms);
        self.archive_new_lifecycle_records();
        result
    }

    pub fn exit_and_drain_live_audit_sources_to_sink<W: Write>(
        &mut self,
        status: RuntimeExitStatus,
        task_report: Option<RuntimeTaskJoinReport>,
        fan_in: &mut RuntimeAuditFanIn,
        sink: &mut JsonLineAuditSink<W>,
        now_ms: u64,
    ) -> Result<
        BlockingRuntimeAuditFanInShutdownDrainReport,
        BlockingRuntimeAuditFanInShutdownDrainError,
    > {
        let before_exit_result = self.drain_live_audit_sources_to_sink(fan_in, sink);
        let exit_result = self.exit_with_task_report(status, task_report, now_ms);
        let after_exit_result = self.drain_live_audit_sources_to_sink(fan_in, sink);
        match (before_exit_result, exit_result, after_exit_result) {
            (Ok(before_exit), Ok(()), Ok(after_exit)) => {
                Ok(BlockingRuntimeAuditFanInShutdownDrainReport {
                    before_exit,
                    after_exit,
                })
            }
            (Err(error), exit, post_exit) => {
                Err(BlockingRuntimeAuditFanInShutdownDrainError::PreExitDrain {
                    error,
                    exit,
                    post_exit,
                })
            }
            (Ok(before_exit), Err(error), post_exit) => {
                Err(BlockingRuntimeAuditFanInShutdownDrainError::Exit {
                    before_exit,
                    error,
                    post_exit,
                })
            }
            (Ok(before_exit), Ok(()), Err(error)) => {
                Err(BlockingRuntimeAuditFanInShutdownDrainError::PostExitDrain {
                    before_exit,
                    error,
                })
            }
        }
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockingProxyRuntimeReadyTaskReport {
    pub dispatched_tasks: Vec<RuntimeTaskExpectation>,
    pub dns_step: Option<DnsBrokerStepResult>,
    pub http_proxy_step: Option<HttpProxyListenerStepResult>,
    pub socks5_proxy_step: Option<Socks5ListenerStepResult>,
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

    pub fn dispatch_ready_proxy_listener_tasks(
        &mut self,
        ready_tasks: &[RuntimeTaskExpectation],
        now_ms: u64,
    ) -> Result<BlockingProxyRuntimeReadyTaskReport, BlockingProxyRuntimeError> {
        let mut report = BlockingProxyRuntimeReadyTaskReport::default();
        for task in ready_tasks {
            match (task.component, task.task_name.as_str()) {
                (RuntimeComponent::DnsListener, "dns_accept_loop") => {
                    report.dispatched_tasks.push(task.clone());
                    report.dns_step = self
                        .handle_dns_once(now_ms)
                        .map_err(BlockingProxyRuntimeError::Dns)?;
                }
                (RuntimeComponent::HttpProxyListener, "http_proxy_accept_loop") => {
                    report.dispatched_tasks.push(task.clone());
                    report.http_proxy_step = self
                        .handle_http_proxy_once(now_ms)
                        .map_err(BlockingProxyRuntimeError::HttpProxy)?;
                }
                (RuntimeComponent::Socks5Listener, "socks5_accept_loop") => {
                    report.dispatched_tasks.push(task.clone());
                    report.socks5_proxy_step = self
                        .handle_socks5_proxy_once(now_ms)
                        .map_err(BlockingProxyRuntimeError::Socks5Proxy)?;
                }
                _ => {}
            }
        }
        Ok(report)
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

    pub fn record_readiness_plan(
        &mut self,
        plan: &RuntimeReadinessPlan,
        now_ms: u64,
    ) -> Result<(), RuntimeLifecycleError> {
        let result = self.lifecycle.record_readiness_plan(plan, now_ms);
        self.archive_new_lifecycle_records();
        result
    }

    pub fn exit_and_drain_live_audit_sources_to_sink<W: Write>(
        &mut self,
        status: RuntimeExitStatus,
        task_report: Option<RuntimeTaskJoinReport>,
        fan_in: &mut RuntimeAuditFanIn,
        sink: &mut JsonLineAuditSink<W>,
        now_ms: u64,
    ) -> Result<
        BlockingRuntimeAuditFanInShutdownDrainReport,
        BlockingRuntimeAuditFanInShutdownDrainError,
    > {
        let before_exit_result = self.drain_live_audit_sources_to_sink(fan_in, sink);
        let exit_result = self.exit_with_task_report(status, task_report, now_ms);
        let after_exit_result = self.drain_live_audit_sources_to_sink(fan_in, sink);
        match (before_exit_result, exit_result, after_exit_result) {
            (Ok(before_exit), Ok(()), Ok(after_exit)) => {
                Ok(BlockingRuntimeAuditFanInShutdownDrainReport {
                    before_exit,
                    after_exit,
                })
            }
            (Err(error), exit, post_exit) => {
                Err(BlockingRuntimeAuditFanInShutdownDrainError::PreExitDrain {
                    error,
                    exit,
                    post_exit,
                })
            }
            (Ok(before_exit), Err(error), post_exit) => {
                Err(BlockingRuntimeAuditFanInShutdownDrainError::Exit {
                    before_exit,
                    error,
                    post_exit,
                })
            }
            (Ok(before_exit), Ok(()), Err(error)) => {
                Err(BlockingRuntimeAuditFanInShutdownDrainError::PostExitDrain {
                    before_exit,
                    error,
                })
            }
        }
    }

    pub async fn exit_with_async_task_set_and_drain_live_audit_sources_to_sink<W: Write>(
        &mut self,
        status: RuntimeExitStatus,
        mut task_set: AsyncRuntimeTaskSet,
        join_timeout: Duration,
        fan_in: &mut RuntimeAuditFanIn,
        sink: &mut JsonLineAuditSink<W>,
        now_ms: u64,
    ) -> Result<AsyncRuntimeAuditFanInShutdownDrainReport, AsyncRuntimeAuditFanInShutdownDrainError>
    {
        let cancelled_tasks = task_set.request_cancellation();
        let task_report = task_set.join_all_with_timeout(join_timeout).await;
        match self.exit_and_drain_live_audit_sources_to_sink(
            status,
            Some(task_report.clone()),
            fan_in,
            sink,
            now_ms,
        ) {
            Ok(shutdown_drain) => Ok(AsyncRuntimeAuditFanInShutdownDrainReport {
                cancelled_tasks,
                task_report,
                shutdown_drain,
            }),
            Err(error) => Err(AsyncRuntimeAuditFanInShutdownDrainError::ShutdownDrain {
                cancelled_tasks,
                task_report,
                error,
            }),
        }
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

#[derive(Debug, Default)]
pub struct AsyncRuntimeTaskSet {
    supervisor: RuntimeTaskSupervisor,
    tasks: Vec<AsyncRuntimeTask>,
}

#[derive(Debug)]
struct AsyncRuntimeTask {
    handle: RuntimeTaskHandle,
    join: tokio::task::JoinHandle<RuntimeTaskStatus>,
    cancellation: Option<Arc<AsyncRuntimeCancellationState>>,
}

#[derive(Debug)]
struct AsyncRuntimeCancellationState {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl AsyncRuntimeCancellationState {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AsyncRuntimeCancellationToken {
    state: Arc<AsyncRuntimeCancellationState>,
}

impl AsyncRuntimeCancellationToken {
    fn new(state: Arc<AsyncRuntimeCancellationState>) -> Self {
        Self { state }
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.state.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
            if self.is_cancelled() {
                return;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsyncRuntimeTaskSetError {
    Supervisor(RuntimeTaskSupervisorError),
}

impl From<RuntimeTaskSupervisorError> for AsyncRuntimeTaskSetError {
    fn from(error: RuntimeTaskSupervisorError) -> Self {
        Self::Supervisor(error)
    }
}

#[derive(Debug, Default)]
pub struct AsyncLocalRuntimeTaskSet {
    supervisor: RuntimeTaskSupervisor,
    tasks: Vec<AsyncRuntimeTask>,
}

impl AsyncLocalRuntimeTaskSet {
    pub fn new() -> Self {
        Self {
            supervisor: RuntimeTaskSupervisor::new(),
            tasks: Vec::new(),
        }
    }

    pub fn spawn_cancellable_task<F, Fut>(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
        task: F,
    ) -> Result<RuntimeTaskHandle, AsyncRuntimeTaskSetError>
    where
        F: FnOnce(AsyncRuntimeCancellationToken) -> Fut + 'static,
        Fut: Future<Output = RuntimeTaskStatus> + 'static,
    {
        let cancellation = Arc::new(AsyncRuntimeCancellationState::new());
        let token = AsyncRuntimeCancellationToken::new(cancellation.clone());
        let task_name = task_name.into();
        let handle = self.supervisor.register_task(component, task_name)?;
        let join = tokio::task::spawn_local(task(token));
        self.tasks.push(AsyncRuntimeTask {
            handle,
            join,
            cancellation: Some(cancellation),
        });
        Ok(handle)
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
            if !cancellation.cancelled.swap(true, Ordering::SeqCst) {
                cancellation.notify.notify_waiters();
            }
            cancelled += 1;
        }
        cancelled
    }

    pub async fn join_all_with_timeout(mut self, timeout: Duration) -> RuntimeTaskJoinReport {
        for task in self.tasks {
            let mut join = task.join;
            let status = match tokio::time::timeout(timeout, &mut join).await {
                Ok(Ok(status)) => status,
                Ok(Err(_)) => RuntimeTaskStatus::JoinFailed,
                Err(_) => {
                    join.abort();
                    let _ = join.await;
                    RuntimeTaskStatus::TimedOut
                }
            };
            self.supervisor
                .record_outcome(task.handle, status)
                .expect("joined task was registered once");
        }
        self.supervisor.join_report()
    }
}

impl AsyncRuntimeTaskSet {
    pub fn new() -> Self {
        Self {
            supervisor: RuntimeTaskSupervisor::new(),
            tasks: Vec::new(),
        }
    }

    pub fn spawn_task<Fut>(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
        task: Fut,
    ) -> Result<RuntimeTaskHandle, AsyncRuntimeTaskSetError>
    where
        Fut: Future<Output = RuntimeTaskStatus> + Send + 'static,
    {
        let task_name = task_name.into();
        let handle = self.supervisor.register_task(component, task_name)?;
        let join = tokio::spawn(task);
        self.tasks.push(AsyncRuntimeTask {
            handle,
            join,
            cancellation: None,
        });
        Ok(handle)
    }

    pub fn spawn_cancellable_task<F, Fut>(
        &mut self,
        component: RuntimeComponent,
        task_name: impl Into<String>,
        task: F,
    ) -> Result<RuntimeTaskHandle, AsyncRuntimeTaskSetError>
    where
        F: FnOnce(AsyncRuntimeCancellationToken) -> Fut,
        Fut: Future<Output = RuntimeTaskStatus> + Send + 'static,
    {
        let cancellation = Arc::new(AsyncRuntimeCancellationState::new());
        let token = AsyncRuntimeCancellationToken::new(cancellation.clone());
        let task_name = task_name.into();
        let handle = self.supervisor.register_task(component, task_name)?;
        let join = tokio::spawn(task(token));
        self.tasks.push(AsyncRuntimeTask {
            handle,
            join,
            cancellation: Some(cancellation),
        });
        Ok(handle)
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
            if !cancellation.cancelled.swap(true, Ordering::SeqCst) {
                cancellation.notify.notify_waiters();
            }
            cancelled += 1;
        }
        cancelled
    }

    pub async fn join_all_with_timeout(mut self, timeout: Duration) -> RuntimeTaskJoinReport {
        for task in self.tasks {
            let mut join = task.join;
            let status = match tokio::time::timeout(timeout, &mut join).await {
                Ok(Ok(status)) => status,
                Ok(Err(_)) => RuntimeTaskStatus::JoinFailed,
                Err(_) => {
                    join.abort();
                    let _ = join.await;
                    RuntimeTaskStatus::TimedOut
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
pub enum AsyncRuntimeSchedulerWaitStatus {
    NotWaiting,
    TimerElapsed,
    Cancelled,
    IdleYielded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncRuntimeSchedulerStepReport {
    pub plan: RuntimeReadinessPlan,
    pub scheduler_action: RuntimeSchedulerAction,
    pub dispatched_tasks: Vec<RuntimeTaskExpectation>,
    pub wait_status: AsyncRuntimeSchedulerWaitStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsyncRuntimeIoReadinessStatus {
    Ready,
    Cancelled,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncRuntimeIoReadinessReport {
    pub status: AsyncRuntimeIoReadinessStatus,
    pub readiness: RuntimeTaskReadiness,
}

pub async fn wait_for_async_udp_socket_readiness(
    socket: &tokio::net::UdpSocket,
    component: RuntimeComponent,
    task_name: impl Into<String>,
    max_wait: Duration,
    cancellation: &AsyncRuntimeCancellationToken,
) -> AsyncRuntimeIoReadinessReport {
    let task_name = task_name.into();
    let status = tokio::select! {
        result = socket.readable() => {
            if result.is_ok() {
                AsyncRuntimeIoReadinessStatus::Ready
            } else {
                AsyncRuntimeIoReadinessStatus::Failed
            }
        }
        () = tokio::time::sleep(max_wait) => AsyncRuntimeIoReadinessStatus::TimedOut,
        () = cancellation.cancelled() => AsyncRuntimeIoReadinessStatus::Cancelled,
    };
    AsyncRuntimeIoReadinessReport {
        readiness: RuntimeTaskReadiness::new(component, task_name)
            .with_ready(status == AsyncRuntimeIoReadinessStatus::Ready),
        status,
    }
}

#[derive(Debug)]
pub struct AsyncRuntimeTcpAcceptReport {
    pub status: AsyncRuntimeIoReadinessStatus,
    pub readiness: RuntimeTaskReadiness,
    pub accepted_peer: Option<SocketAddr>,
    pub stream: Option<tokio::net::TcpStream>,
}

pub async fn accept_async_tcp_listener_when_ready(
    listener: &tokio::net::TcpListener,
    component: RuntimeComponent,
    task_name: impl Into<String>,
    max_wait: Duration,
    cancellation: &AsyncRuntimeCancellationToken,
) -> AsyncRuntimeTcpAcceptReport {
    let task_name = task_name.into();
    let mut accepted = None;
    let status = tokio::select! {
        result = listener.accept() => {
            match result {
                Ok((stream, peer)) => {
                    accepted = Some((stream, peer));
                    AsyncRuntimeIoReadinessStatus::Ready
                }
                Err(_) => AsyncRuntimeIoReadinessStatus::Failed,
            }
        }
        () = tokio::time::sleep(max_wait) => AsyncRuntimeIoReadinessStatus::TimedOut,
        () = cancellation.cancelled() => AsyncRuntimeIoReadinessStatus::Cancelled,
    };
    let (stream, accepted_peer) = match accepted {
        Some((stream, peer)) => (Some(stream), Some(peer)),
        None => (None, None),
    };
    AsyncRuntimeTcpAcceptReport {
        readiness: RuntimeTaskReadiness::new(component, task_name)
            .with_ready(status == AsyncRuntimeIoReadinessStatus::Ready),
        status,
        accepted_peer,
        stream,
    }
}

#[cfg(unix)]
pub async fn wait_for_async_packet_fd_readiness<F>(
    fd: &tokio::io::unix::AsyncFd<F>,
    max_wait: Duration,
    cancellation: &AsyncRuntimeCancellationToken,
) -> AsyncRuntimeIoReadinessReport
where
    F: std::os::fd::AsRawFd,
{
    let status = tokio::select! {
        result = fd.readable() => {
            if result.is_ok() {
                AsyncRuntimeIoReadinessStatus::Ready
            } else {
                AsyncRuntimeIoReadinessStatus::Failed
            }
        }
        () = tokio::time::sleep(max_wait) => AsyncRuntimeIoReadinessStatus::TimedOut,
        () = cancellation.cancelled() => AsyncRuntimeIoReadinessStatus::Cancelled,
    };
    AsyncRuntimeIoReadinessReport {
        readiness: RuntimeTaskReadiness::new(RuntimeComponent::TunDevice, "tun_packet_loop")
            .with_ready(status == AsyncRuntimeIoReadinessStatus::Ready),
        status,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncRuntimePacketFdReadReport {
    pub status: AsyncRuntimeIoReadinessStatus,
    pub readiness: RuntimeTaskReadiness,
    pub bytes_read: usize,
    pub packet: Option<Vec<u8>>,
}

#[cfg(unix)]
pub async fn read_async_packet_fd_ready_task<F>(
    fd: &tokio::io::unix::AsyncFd<F>,
    ready_tasks: &[RuntimeTaskExpectation],
    max_packet_bytes: usize,
    max_wait: Duration,
    cancellation: &AsyncRuntimeCancellationToken,
) -> std::io::Result<Option<AsyncRuntimePacketFdReadReport>>
where
    F: std::os::fd::AsRawFd,
    for<'a> &'a F: Read,
{
    let should_read = ready_tasks.iter().any(|task| {
        task.component == RuntimeComponent::TunDevice && task.task_name == "tun_packet_loop"
    });
    if !should_read {
        return Ok(None);
    }

    let mut packet = vec![0u8; max_packet_bytes.max(1)];
    let mut bytes_read = 0usize;
    let status = tokio::select! {
        result = fd.readable() => {
            let mut guard = result?;
            match guard.try_io(|inner| {
                let mut reader = inner.get_ref();
                reader.read(&mut packet)
            }) {
                Ok(Ok(len)) => {
                    bytes_read = len;
                    if len == 0 {
                        AsyncRuntimeIoReadinessStatus::TimedOut
                    } else {
                        AsyncRuntimeIoReadinessStatus::Ready
                    }
                }
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => AsyncRuntimeIoReadinessStatus::TimedOut,
            }
        }
        () = tokio::time::sleep(max_wait) => AsyncRuntimeIoReadinessStatus::TimedOut,
        () = cancellation.cancelled() => AsyncRuntimeIoReadinessStatus::Cancelled,
    };
    packet.truncate(bytes_read);
    Ok(Some(AsyncRuntimePacketFdReadReport {
        readiness: RuntimeTaskReadiness::new(RuntimeComponent::TunDevice, "tun_packet_loop")
            .with_ready(status == AsyncRuntimeIoReadinessStatus::Ready),
        status,
        bytes_read,
        packet: (bytes_read > 0).then_some(packet),
    }))
}

pub fn collect_async_runtime_readiness_from_reports(
    io_reports: &[AsyncRuntimeIoReadinessReport],
    tcp_accept_reports: &[AsyncRuntimeTcpAcceptReport],
    packet_read_reports: &[AsyncRuntimePacketFdReadReport],
    additional_readiness: &[RuntimeTaskReadiness],
) -> Vec<RuntimeTaskReadiness> {
    io_reports
        .iter()
        .map(|report| report.readiness.clone())
        .chain(
            tcp_accept_reports
                .iter()
                .map(|report| report.readiness.clone()),
        )
        .chain(
            packet_read_reports
                .iter()
                .map(|report| report.readiness.clone()),
        )
        .chain(additional_readiness.iter().cloned())
        .collect()
}

pub async fn run_async_runtime_scheduler_step<F, Fut>(
    lifecycle: &mut RuntimeLifecycleHarness,
    task_readiness: &[RuntimeTaskReadiness],
    now_ms: u64,
    cancellation: &AsyncRuntimeCancellationToken,
    run_ready_tasks: F,
) -> Result<AsyncRuntimeSchedulerStepReport, RuntimeLifecycleError>
where
    F: FnOnce(Vec<RuntimeTaskExpectation>) -> Fut,
    Fut: Future<Output = ()>,
{
    let plan = RuntimeReadinessPlan::from_tasks(task_readiness);
    lifecycle.record_readiness_plan(&plan, now_ms)?;
    let scheduler_action = plan.scheduler_action();
    let mut dispatched_tasks = Vec::new();
    let wait_status = match scheduler_action {
        RuntimeSchedulerAction::RunReadyTasks => {
            let ready_tasks = plan.ready_tasks.clone();
            tokio::select! {
                () = run_ready_tasks(ready_tasks.clone()) => {
                    dispatched_tasks = ready_tasks;
                    AsyncRuntimeSchedulerWaitStatus::NotWaiting
                }
                () = cancellation.cancelled() => AsyncRuntimeSchedulerWaitStatus::Cancelled,
            }
        }
        RuntimeSchedulerAction::WaitForTimer => {
            let delay = Duration::from_millis(plan.next_ready_delay_ms.unwrap_or_default());
            tokio::select! {
                () = tokio::time::sleep(delay) => AsyncRuntimeSchedulerWaitStatus::TimerElapsed,
                () = cancellation.cancelled() => AsyncRuntimeSchedulerWaitStatus::Cancelled,
            }
        }
        RuntimeSchedulerAction::Idle => {
            tokio::select! {
                () = tokio::task::yield_now() => AsyncRuntimeSchedulerWaitStatus::IdleYielded,
                () = cancellation.cancelled() => AsyncRuntimeSchedulerWaitStatus::Cancelled,
            }
        }
    };
    Ok(AsyncRuntimeSchedulerStepReport {
        plan,
        scheduler_action,
        dispatched_tasks,
        wait_status,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsyncRuntimeSchedulerLoopStatus {
    Cancelled,
    StepLimitReached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncRuntimeSchedulerLoopReport {
    pub status: AsyncRuntimeSchedulerLoopStatus,
    pub steps: Vec<AsyncRuntimeSchedulerStepReport>,
}

pub async fn run_async_runtime_scheduler_loop_until_cancelled<R, Run, Fut>(
    lifecycle: &mut RuntimeLifecycleHarness,
    cancellation: &AsyncRuntimeCancellationToken,
    start_ms: u64,
    step_ms: u64,
    max_steps: usize,
    mut readiness_source: R,
    mut run_ready_tasks: Run,
) -> Result<AsyncRuntimeSchedulerLoopReport, RuntimeLifecycleError>
where
    R: FnMut(usize) -> Vec<RuntimeTaskReadiness>,
    Run: FnMut(Vec<RuntimeTaskExpectation>) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut steps = Vec::new();
    for step_index in 0..max_steps {
        if cancellation.is_cancelled() {
            return Ok(AsyncRuntimeSchedulerLoopReport {
                status: AsyncRuntimeSchedulerLoopStatus::Cancelled,
                steps,
            });
        }
        let now_ms = start_ms.saturating_add((step_index as u64).saturating_mul(step_ms));
        let readiness = readiness_source(step_index);
        let step = run_async_runtime_scheduler_step(
            lifecycle,
            &readiness,
            now_ms,
            cancellation,
            &mut run_ready_tasks,
        )
        .await?;
        let was_cancelled = step.wait_status == AsyncRuntimeSchedulerWaitStatus::Cancelled;
        steps.push(step);
        if was_cancelled {
            return Ok(AsyncRuntimeSchedulerLoopReport {
                status: AsyncRuntimeSchedulerLoopStatus::Cancelled,
                steps,
            });
        }
    }
    Ok(AsyncRuntimeSchedulerLoopReport {
        status: AsyncRuntimeSchedulerLoopStatus::StepLimitReached,
        steps,
    })
}

pub trait AsyncRuntimeReadinessSource {
    fn runtime_readiness(&mut self) -> RuntimeTaskReadiness;
}

impl<F> AsyncRuntimeReadinessSource for F
where
    F: FnMut() -> RuntimeTaskReadiness,
{
    fn runtime_readiness(&mut self) -> RuntimeTaskReadiness {
        self()
    }
}

pub fn collect_async_runtime_readiness(
    sources: &mut [&mut dyn AsyncRuntimeReadinessSource],
) -> Vec<RuntimeTaskReadiness> {
    sources
        .iter_mut()
        .map(|source| source.runtime_readiness())
        .collect()
}

impl<U, S> AsyncRuntimeReadinessSource for &BlockingDnsBrokerServer<U, S> {
    fn runtime_readiness(&mut self) -> RuntimeTaskReadiness {
        RuntimeTaskReadiness::ready(RuntimeComponent::DnsListener, "dns_accept_loop")
    }
}

impl<E, L> AsyncRuntimeReadinessSource for &BlockingHttpProxyServer<E, L> {
    fn runtime_readiness(&mut self) -> RuntimeTaskReadiness {
        RuntimeTaskReadiness::ready(
            RuntimeComponent::HttpProxyListener,
            "http_proxy_accept_loop",
        )
    }
}

impl<E, L> AsyncRuntimeReadinessSource for &BlockingSocks5ProxyServer<E, L> {
    fn runtime_readiness(&mut self) -> RuntimeTaskReadiness {
        RuntimeTaskReadiness::ready(RuntimeComponent::Socks5Listener, "socks5_accept_loop")
    }
}

impl AsyncRuntimeReadinessSource for &RuntimeAuditFanIn {
    fn runtime_readiness(&mut self) -> RuntimeTaskReadiness {
        (*self).runtime_readiness()
    }
}

pub fn run_async_runtime_audit_fan_in_ready_task<W: Write>(
    ready_tasks: &[RuntimeTaskExpectation],
    fan_in: &mut RuntimeAuditFanIn,
    sink: &mut JsonLineAuditSink<W>,
) -> Result<Option<RuntimeAuditDrainReport>, RuntimeAuditDrainError> {
    let should_drain = ready_tasks.iter().any(|task| {
        task.component == RuntimeComponent::AuditFanIn && task.task_name == "audit_fan_in_loop"
    });
    if should_drain {
        fan_in.drain_to_sink(sink).map(Some)
    } else {
        Ok(None)
    }
}

pub async fn run_async_runtime_scheduler_loop_with_sources_until_cancelled<Run, Fut>(
    lifecycle: &mut RuntimeLifecycleHarness,
    cancellation: &AsyncRuntimeCancellationToken,
    start_ms: u64,
    step_ms: u64,
    max_steps: usize,
    readiness_sources: &mut [&mut dyn AsyncRuntimeReadinessSource],
    mut run_ready_tasks: Run,
) -> Result<AsyncRuntimeSchedulerLoopReport, RuntimeLifecycleError>
where
    Run: FnMut(Vec<RuntimeTaskExpectation>) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut steps = Vec::new();
    for step_index in 0..max_steps {
        if cancellation.is_cancelled() {
            return Ok(AsyncRuntimeSchedulerLoopReport {
                status: AsyncRuntimeSchedulerLoopStatus::Cancelled,
                steps,
            });
        }
        let now_ms = start_ms.saturating_add((step_index as u64).saturating_mul(step_ms));
        let readiness = collect_async_runtime_readiness(readiness_sources);
        let step = run_async_runtime_scheduler_step(
            lifecycle,
            &readiness,
            now_ms,
            cancellation,
            &mut run_ready_tasks,
        )
        .await?;
        let was_cancelled = step.wait_status == AsyncRuntimeSchedulerWaitStatus::Cancelled;
        steps.push(step);
        if was_cancelled {
            return Ok(AsyncRuntimeSchedulerLoopReport {
                status: AsyncRuntimeSchedulerLoopStatus::Cancelled,
                steps,
            });
        }
    }
    Ok(AsyncRuntimeSchedulerLoopReport {
        status: AsyncRuntimeSchedulerLoopStatus::StepLimitReached,
        steps,
    })
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

    const EGRESS_TCP_SYN: u8 = 0x02;

    #[derive(Clone, Copy)]
    struct EgressTcpPacketSpec<'a> {
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        payload: &'a [u8],
    }

    fn egress_ipv4_tcp_packet(spec: EgressTcpPacketSpec<'_>) -> Vec<u8> {
        let tcp_len = 20 + spec.payload.len();
        let total_len = 20 + tcp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&spec.source);
        packet[16..20].copy_from_slice(&spec.destination);

        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&spec.source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&spec.destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&spec.sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&spec.acknowledgment.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = spec.flags;
        tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
        tcp[20..].copy_from_slice(spec.payload);

        let tcp_checksum = egress_tcp_checksum(spec.source, spec.destination, tcp);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        let header_checksum = foxprox_core::checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    fn egress_tcp_checksum(source: [u8; 4], destination: [u8; 4], tcp: &[u8]) -> u16 {
        let mut bytes = Vec::with_capacity(12 + tcp.len());
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.push(0);
        bytes.push(6);
        bytes.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        bytes.extend_from_slice(tcp);
        foxprox_core::checksum(&bytes)
    }

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

    #[derive(Clone, Debug)]
    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
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

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_task_set_cancellation_is_joined_cleanly() {
        let mut task_set = AsyncRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                |token| async move {
                    while !token.is_cancelled() {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    RuntimeTaskStatus::Cancelled
                },
            )
            .unwrap();
        let expectations = task_set.expectations();
        assert_eq!(task_set.request_cancellation(), 1);

        let report = task_set.join_all_with_timeout(Duration::from_secs(1)).await;

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(
            report.outcomes[0],
            RuntimeTaskOutcome::new(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                RuntimeTaskStatus::Cancelled,
            )
        );
        let mut lifecycle = RuntimeLifecycleHarness::new("async-task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::AuditFanIn], expectations, 1_000)
            .unwrap();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::AuditFanIn]),
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
            "audit_fan_in:audit_fan_in_loop:cancelled"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_cancellation_token_wakes_awaiting_task() {
        let mut task_set = AsyncRuntimeTaskSet::new();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                |token| async move {
                    tokio::select! {
                        () = token.cancelled() => RuntimeTaskStatus::Cancelled,
                        () = tokio::time::sleep(Duration::from_secs(60)) => RuntimeTaskStatus::TimedOut,
                    }
                },
            )
            .unwrap();

        assert_eq!(task_set.request_cancellation(), 1);
        let report = task_set.join_all_with_timeout(Duration::from_secs(1)).await;

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::Cancelled);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_udp_socket_readiness_uses_os_readable_state_and_audits_plan() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"dns-ready", socket.local_addr().unwrap())
            .unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));

        let report = wait_for_async_udp_socket_readiness(
            &socket,
            RuntimeComponent::DnsListener,
            "dns_accept_loop",
            Duration::from_secs(1),
            &cancellation,
        )
        .await;

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Ready);
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::ready(RuntimeComponent::DnsListener, "dns_accept_loop")
        );
        let mut packet = [0u8; 64];
        let (len, _) = socket.try_recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..len], b"dns-ready");
        let mut lifecycle = RuntimeLifecycleHarness::new("async-io-readiness", 4);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::DnsListener],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                )],
                8_500,
            )
            .unwrap();
        let plan = RuntimeReadinessPlan::from_tasks(&[report.readiness]);
        lifecycle.record_readiness_plan(&plan, 8_510).unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "dns_listener:dns_accept_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_udp_socket_readiness_can_be_cancelled_before_packet() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let report = wait_for_async_udp_socket_readiness(
            &socket,
            RuntimeComponent::DnsListener,
            "dns_accept_loop",
            Duration::from_secs(60),
            &cancellation,
        )
        .await;

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Cancelled);
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::new(RuntimeComponent::DnsListener, "dns_accept_loop")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_tcp_listener_accepts_real_os_connection_and_audits_plan() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(listener_addr).await.unwrap();
            stream.local_addr().unwrap()
        });

        let report = accept_async_tcp_listener_when_ready(
            &listener,
            RuntimeComponent::HttpProxyListener,
            "http_proxy_accept_loop",
            Duration::from_secs(1),
            &cancellation,
        )
        .await;
        let client_addr = client.await.unwrap();

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Ready);
        assert_eq!(report.accepted_peer, Some(client_addr));
        assert!(report.stream.is_some());
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::ready(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop"
            )
        );
        let mut lifecycle = RuntimeLifecycleHarness::new("async-tcp-accept", 4);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::HttpProxyListener],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::HttpProxyListener,
                    "http_proxy_accept_loop",
                )],
                8_600,
            )
            .unwrap();
        let plan = RuntimeReadinessPlan::from_tasks(&[report.readiness]);
        lifecycle.record_readiness_plan(&plan, 8_610).unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "http_proxy_listener:http_proxy_accept_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_tcp_listener_accept_can_be_cancelled_before_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let report = accept_async_tcp_listener_when_ready(
            &listener,
            RuntimeComponent::HttpProxyListener,
            "http_proxy_accept_loop",
            Duration::from_secs(60),
            &cancellation,
        )
        .await;

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Cancelled);
        assert!(report.accepted_peer.is_none());
        assert!(report.stream.is_none());
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::new(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop"
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_tcp_listener_accept_timeout_is_not_ready() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));

        let report = accept_async_tcp_listener_when_ready(
            &listener,
            RuntimeComponent::Socks5Listener,
            "socks5_accept_loop",
            Duration::from_millis(1),
            &cancellation,
        )
        .await;

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::TimedOut);
        assert!(report.accepted_peer.is_none());
        assert!(report.stream.is_none());
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::new(RuntimeComponent::Socks5Listener, "socks5_accept_loop")
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_packet_fd_readiness_uses_asyncfd_and_audits_plan() {
        let (tun_fd, mut sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        tun_fd.set_nonblocking(true).unwrap();
        let async_fd = tokio::io::unix::AsyncFd::new(tun_fd).unwrap();
        sandbox_peer.write_all(b"tun-packet-ready").unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));

        let report =
            wait_for_async_packet_fd_readiness(&async_fd, Duration::from_secs(1), &cancellation)
                .await;

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Ready);
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::ready(RuntimeComponent::TunDevice, "tun_packet_loop")
        );
        let mut packet = [0u8; 64];
        let mut tun_reader = async_fd.get_ref();
        let len = tun_reader.read(&mut packet).unwrap();
        assert_eq!(&packet[..len], b"tun-packet-ready");
        let mut lifecycle = RuntimeLifecycleHarness::new("async-tun-fd-readiness", 4);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::TunDevice],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::TunDevice,
                    "tun_packet_loop",
                )],
                8_700,
            )
            .unwrap();
        let plan = RuntimeReadinessPlan::from_tasks(&[report.readiness]);
        lifecycle.record_readiness_plan(&plan, 8_710).unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "tun_device:tun_packet_loop"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_packet_fd_readiness_can_be_cancelled_before_packet() {
        let (tun_fd, _sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        tun_fd.set_nonblocking(true).unwrap();
        let async_fd = tokio::io::unix::AsyncFd::new(tun_fd).unwrap();
        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let report =
            wait_for_async_packet_fd_readiness(&async_fd, Duration::from_secs(60), &cancellation)
                .await;

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Cancelled);
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::new(RuntimeComponent::TunDevice, "tun_packet_loop")
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_packet_fd_ready_task_reads_and_clears_readiness() {
        let (tun_fd, mut sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        tun_fd.set_nonblocking(true).unwrap();
        let async_fd = tokio::io::unix::AsyncFd::new(tun_fd).unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        sandbox_peer.write_all(b"packet-for-dispatch").unwrap();
        let unrelated = vec![RuntimeTaskExpectation::new(
            RuntimeComponent::AuditFanIn,
            "audit_fan_in_loop",
        )];
        assert!(read_async_packet_fd_ready_task(
            &async_fd,
            &unrelated,
            64,
            Duration::from_secs(1),
            &cancellation,
        )
        .await
        .unwrap()
        .is_none());
        let ready_tasks = vec![RuntimeTaskExpectation::new(
            RuntimeComponent::TunDevice,
            "tun_packet_loop",
        )];

        let report = read_async_packet_fd_ready_task(
            &async_fd,
            &ready_tasks,
            64,
            Duration::from_secs(1),
            &cancellation,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(report.status, AsyncRuntimeIoReadinessStatus::Ready);
        assert_eq!(report.bytes_read, b"packet-for-dispatch".len());
        assert_eq!(report.packet.as_deref(), Some(&b"packet-for-dispatch"[..]));
        assert_eq!(
            report.readiness,
            RuntimeTaskReadiness::ready(RuntimeComponent::TunDevice, "tun_packet_loop")
        );
        let mut lifecycle = RuntimeLifecycleHarness::new("async-packet-fd-dispatch", 4);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::TunDevice],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::TunDevice,
                    "tun_packet_loop",
                )],
                8_800,
            )
            .unwrap();
        let plan = RuntimeReadinessPlan::from_tasks(&[report.readiness]);
        lifecycle.record_readiness_plan(&plan, 8_810).unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "tun_device:tun_packet_loop"
        );
        let drained = read_async_packet_fd_ready_task(
            &async_fd,
            &ready_tasks,
            64,
            Duration::from_millis(1),
            &cancellation,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(drained.status, AsyncRuntimeIoReadinessStatus::TimedOut);
        assert_eq!(drained.bytes_read, 0);
        assert!(drained.packet.is_none());
        assert!(!drained.readiness.ready);
    }

    #[test]
    fn async_runtime_report_collector_preserves_packet_readiness_order() {
        let io_report = AsyncRuntimeIoReadinessReport {
            status: AsyncRuntimeIoReadinessStatus::Ready,
            readiness: RuntimeTaskReadiness::ready(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
            ),
        };
        let tcp_report = AsyncRuntimeTcpAcceptReport {
            status: AsyncRuntimeIoReadinessStatus::Ready,
            readiness: RuntimeTaskReadiness::ready(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
            ),
            accepted_peer: None,
            stream: None,
        };
        let packet_report = AsyncRuntimePacketFdReadReport {
            status: AsyncRuntimeIoReadinessStatus::Ready,
            readiness: RuntimeTaskReadiness::ready(RuntimeComponent::TunDevice, "tun_packet_loop"),
            bytes_read: 6,
            packet: Some(b"packet".to_vec()),
        };
        let additional = [RuntimeTaskReadiness::ready(
            RuntimeComponent::AuditFanIn,
            "audit_fan_in_loop",
        )];

        let readiness = collect_async_runtime_readiness_from_reports(
            &[io_report],
            &[tcp_report],
            &[packet_report],
            &additional,
        );
        let plan = RuntimeReadinessPlan::from_tasks(&readiness);

        assert_eq!(readiness.len(), 4);
        assert_eq!(
            plan.ready_task_details(),
            "dns_listener:dns_accept_loop,http_proxy_listener:http_proxy_accept_loop,tun_device:tun_packet_loop,audit_fan_in:audit_fan_in_loop"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_step_integrates_live_io_reports_and_dispatch() {
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));

        let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_sender
            .send_to(b"dns-ready", udp_socket.local_addr().unwrap())
            .unwrap();
        let udp_report = wait_for_async_udp_socket_readiness(
            &udp_socket,
            RuntimeComponent::DnsListener,
            "dns_accept_loop",
            Duration::from_secs(1),
            &cancellation,
        )
        .await;

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = tcp_listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(listener_addr).await.unwrap();
            stream.local_addr().unwrap()
        });
        let tcp_report = accept_async_tcp_listener_when_ready(
            &tcp_listener,
            RuntimeComponent::HttpProxyListener,
            "http_proxy_accept_loop",
            Duration::from_secs(1),
            &cancellation,
        )
        .await;
        let tcp_client_addr = client.await.unwrap();

        let (packet_fd, mut sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        packet_fd.set_nonblocking(true).unwrap();
        let async_packet_fd = tokio::io::unix::AsyncFd::new(packet_fd).unwrap();
        sandbox_peer.write_all(b"tun-dispatch").unwrap();
        let packet_readiness_report = wait_for_async_packet_fd_readiness(
            &async_packet_fd,
            Duration::from_secs(1),
            &cancellation,
        )
        .await;
        let additional_readiness = vec![RuntimeTaskReadiness::ready(
            RuntimeComponent::AuditFanIn,
            "audit_fan_in_loop",
        )];
        let readiness = collect_async_runtime_readiness_from_reports(
            std::slice::from_ref(&udp_report),
            std::slice::from_ref(&tcp_report),
            &[],
            &additional_readiness,
        )
        .into_iter()
        .chain([packet_readiness_report.readiness.clone()])
        .collect::<Vec<_>>();
        let mut lifecycle = RuntimeLifecycleHarness::new("async-live-io-step", 8);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::HttpProxyListener,
                    RuntimeComponent::TunDevice,
                    RuntimeComponent::AuditFanIn,
                ],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::HttpProxyListener,
                        "http_proxy_accept_loop",
                    ),
                    RuntimeTaskExpectation::new(RuntimeComponent::TunDevice, "tun_packet_loop"),
                    RuntimeTaskExpectation::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
                ],
                8_900,
            )
            .unwrap();
        let tcp_report = std::rc::Rc::new(std::cell::RefCell::new(Some(tcp_report)));
        let udp_consumed = std::rc::Rc::new(std::cell::Cell::new(false));
        let tcp_owned = std::rc::Rc::new(std::cell::Cell::new(false));
        let packet_consumed = std::rc::Rc::new(std::cell::Cell::new(false));
        let fan_in_dispatched = std::rc::Rc::new(std::cell::Cell::new(false));
        let tcp_report_for_dispatch = std::rc::Rc::clone(&tcp_report);
        let udp_consumed_for_dispatch = std::rc::Rc::clone(&udp_consumed);
        let tcp_owned_for_dispatch = std::rc::Rc::clone(&tcp_owned);
        let packet_consumed_for_dispatch = std::rc::Rc::clone(&packet_consumed);
        let fan_in_dispatched_for_dispatch = std::rc::Rc::clone(&fan_in_dispatched);
        let dispatch_cancellation = cancellation.clone();

        let step = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &readiness,
            8_910,
            &cancellation,
            |ready_tasks| async move {
                assert!(ready_tasks.iter().any(|task| {
                    task.component == RuntimeComponent::DnsListener
                        && task.task_name == "dns_accept_loop"
                }));
                assert!(ready_tasks.iter().any(|task| {
                    task.component == RuntimeComponent::HttpProxyListener
                        && task.task_name == "http_proxy_accept_loop"
                }));
                assert!(ready_tasks.iter().any(|task| {
                    task.component == RuntimeComponent::TunDevice
                        && task.task_name == "tun_packet_loop"
                }));
                assert!(ready_tasks.iter().any(|task| {
                    task.component == RuntimeComponent::AuditFanIn
                        && task.task_name == "audit_fan_in_loop"
                }));

                let mut packet = [0u8; 64];
                let (udp_len, _) = udp_socket.try_recv_from(&mut packet).unwrap();
                assert_eq!(&packet[..udp_len], b"dns-ready");
                udp_consumed_for_dispatch.set(true);

                let accepted = tcp_report_for_dispatch.borrow_mut().take().unwrap();
                assert_eq!(accepted.accepted_peer, Some(tcp_client_addr));
                assert!(accepted.stream.is_some());
                tcp_owned_for_dispatch.set(true);

                let packet_report = read_async_packet_fd_ready_task(
                    &async_packet_fd,
                    &ready_tasks,
                    64,
                    Duration::from_secs(1),
                    &dispatch_cancellation,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(packet_report.packet.as_deref(), Some(&b"tun-dispatch"[..]));
                packet_consumed_for_dispatch.set(true);

                fan_in_dispatched_for_dispatch.set(true);
            },
        )
        .await
        .unwrap();

        assert_eq!(step.scheduler_action, RuntimeSchedulerAction::RunReadyTasks);
        assert_eq!(step.dispatched_tasks.len(), 4);
        assert!(udp_consumed.get());
        assert!(tcp_owned.get());
        assert!(packet_consumed.get());
        assert!(fan_in_dispatched.get());
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "dns_listener:dns_accept_loop,http_proxy_listener:http_proxy_accept_loop,audit_fan_in:audit_fan_in_loop,tun_device:tun_packet_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_loop_dispatches_live_smoltcp_timer_wake() {
        let mut stack = foxprox_stack::SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.listen_tcp(8080, 1024, 1024);
        stack.inject_packet(egress_ipv4_tcp_packet(EgressTcpPacketSpec {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 1],
            source_port: 50_000,
            destination_port: 8080,
            sequence: 0x0102_0304,
            acknowledgment: 0,
            flags: EGRESS_TCP_SYN,
            payload: &[],
        }));
        let syn_ack = stack.poll(9_000);
        assert_eq!(syn_ack.packets_emitted, 1);
        let due_ms = 9_000 + syn_ack.next_poll_delay_ms.unwrap() as i64;
        let stack = std::rc::Rc::new(std::cell::RefCell::new(stack));
        let dispatched = std::rc::Rc::new(std::cell::Cell::new(false));
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut lifecycle = RuntimeLifecycleHarness::new("async-smoltcp-loop", 4);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::SmoltcpStack],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )],
                due_ms as u64,
            )
            .unwrap();
        let readiness_stack = std::rc::Rc::clone(&stack);
        let dispatch_stack = std::rc::Rc::clone(&stack);
        let dispatch_observed = std::rc::Rc::clone(&dispatched);

        let report = run_async_runtime_scheduler_loop_until_cancelled(
            &mut lifecycle,
            &cancellation,
            due_ms as u64,
            1,
            1,
            move |_step| vec![readiness_stack.borrow_mut().runtime_timer_readiness(due_ms)],
            move |ready_tasks| {
                let dispatch_stack = std::rc::Rc::clone(&dispatch_stack);
                let dispatch_observed = std::rc::Rc::clone(&dispatch_observed);
                async move {
                    let evidence = dispatch_stack
                        .borrow_mut()
                        .poll_ready_task(&ready_tasks, due_ms)
                        .unwrap();
                    assert_eq!(evidence.packets_emitted, 1);
                    dispatch_observed.set(true);
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.status,
            AsyncRuntimeSchedulerLoopStatus::StepLimitReached
        );
        assert_eq!(report.steps.len(), 1);
        assert_eq!(
            report.steps[0].scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.steps[0].dispatched_tasks,
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::SmoltcpStack,
                "smoltcp_tun_bridge_loop",
            )]
        );
        assert!(dispatched.get());
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "smoltcp_stack:smoltcp_tun_bridge_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_loop_waits_then_dispatches_smoltcp_timer_wake() {
        let mut stack = foxprox_stack::SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
        stack.listen_tcp(8080, 1024, 1024);
        stack.inject_packet(egress_ipv4_tcp_packet(EgressTcpPacketSpec {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 1],
            source_port: 50_000,
            destination_port: 8080,
            sequence: 0x0102_0304,
            acknowledgment: 0,
            flags: EGRESS_TCP_SYN,
            payload: &[],
        }));
        let syn_ack = stack.poll(9_100);
        assert_eq!(syn_ack.packets_emitted, 1);
        let due_ms = 9_100 + syn_ack.next_poll_delay_ms.unwrap() as i64;
        let before_due_ms = due_ms - 1;
        let stack = std::rc::Rc::new(std::cell::RefCell::new(stack));
        let dispatched_packets = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut lifecycle = RuntimeLifecycleHarness::new("async-smoltcp-wait-loop", 8);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::SmoltcpStack],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )],
                before_due_ms as u64,
            )
            .unwrap();
        let readiness_stack = std::rc::Rc::clone(&stack);
        let dispatch_stack = std::rc::Rc::clone(&stack);
        let dispatch_observed = std::rc::Rc::clone(&dispatched_packets);

        let report = run_async_runtime_scheduler_loop_until_cancelled(
            &mut lifecycle,
            &cancellation,
            before_due_ms as u64,
            1,
            2,
            move |step| {
                let now_ms = if step == 0 { before_due_ms } else { due_ms };
                vec![readiness_stack.borrow_mut().runtime_timer_readiness(now_ms)]
            },
            move |ready_tasks| {
                let dispatch_stack = std::rc::Rc::clone(&dispatch_stack);
                let dispatch_observed = std::rc::Rc::clone(&dispatch_observed);
                async move {
                    let evidence = dispatch_stack
                        .borrow_mut()
                        .poll_ready_task(&ready_tasks, due_ms)
                        .unwrap();
                    dispatch_observed.set(evidence.packets_emitted);
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.status,
            AsyncRuntimeSchedulerLoopStatus::StepLimitReached
        );
        assert_eq!(report.steps.len(), 2);
        assert_eq!(
            report.steps[0].scheduler_action,
            RuntimeSchedulerAction::WaitForTimer
        );
        assert_eq!(
            report.steps[0].wait_status,
            AsyncRuntimeSchedulerWaitStatus::TimerElapsed
        );
        assert!(report.steps[0].dispatched_tasks.is_empty());
        assert_eq!(
            report.steps[1].scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.steps[1].dispatched_tasks,
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::SmoltcpStack,
                "smoltcp_tun_bridge_loop",
            )]
        );
        assert_eq!(dispatched_packets.get(), 1);
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "wait_for_timer");
        assert_eq!(records[1].details["readiness_status"], "timer_wait");
        assert_eq!(records[1].details["ready_runtime_tasks"], "");
        assert_eq!(records[1].details["next_ready_delay_ms"], "1");
        assert_eq!(records[2].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[2].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[2].details["ready_runtime_tasks"],
            "smoltcp_stack:smoltcp_tun_bridge_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_local_task_set_owns_non_send_smoltcp_timer_dispatch() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dispatched = Arc::new(AtomicBool::new(false));
                let wait_requested = Arc::new(AtomicBool::new(false));
                let wait_notify = Arc::new(tokio::sync::Notify::new());
                let wait_report = Arc::new(std::sync::Mutex::new(None));
                let mut task_set = AsyncLocalRuntimeTaskSet::new();
                let dispatch_observed = dispatched.clone();
                let wait_observed = wait_requested.clone();
                let wait_notification = wait_notify.clone();
                let wait_report_slot = wait_report.clone();
                task_set
                    .spawn_cancellable_task(
                        RuntimeComponent::SmoltcpStack,
                        "smoltcp_tun_bridge_loop",
                        move |token| async move {
                            let mut stack =
                                foxprox_stack::SmoltcpIpStack::new_ipv4([10, 0, 2, 1], 24, 1500);
                            stack.listen_tcp(8080, 1024, 1024);
                            stack.inject_packet(egress_ipv4_tcp_packet(EgressTcpPacketSpec {
                                source: [10, 0, 2, 15],
                                destination: [10, 0, 2, 1],
                                source_port: 50_000,
                                destination_port: 8080,
                                sequence: 0x0102_0304,
                                acknowledgment: 0,
                                flags: EGRESS_TCP_SYN,
                                payload: &[],
                            }));
                            let syn_ack = stack.poll(9_200);
                            assert_eq!(syn_ack.packets_emitted, 1);
                            let due_ms = 9_200 + syn_ack.next_poll_delay_ms.unwrap() as i64;
                            let stack = std::rc::Rc::new(std::cell::RefCell::new(stack));
                            let readiness_stack = std::rc::Rc::clone(&stack);
                            let dispatch_stack = std::rc::Rc::clone(&stack);
                            let mut lifecycle =
                                RuntimeLifecycleHarness::new("local-smoltcp-task", 8);
                            lifecycle
                                .start_with_task_expectations(
                                    vec![RuntimeComponent::SmoltcpStack],
                                    vec![RuntimeTaskExpectation::new(
                                        RuntimeComponent::SmoltcpStack,
                                        "smoltcp_tun_bridge_loop",
                                    )],
                                    due_ms as u64,
                                )
                                .unwrap();
                            let dispatch_report = run_async_runtime_scheduler_loop_until_cancelled(
                                &mut lifecycle,
                                &token,
                                due_ms as u64,
                                1,
                                1,
                                move |_step| {
                                    vec![readiness_stack
                                        .borrow_mut()
                                        .runtime_timer_readiness(due_ms)]
                                },
                                move |ready_tasks| {
                                    let dispatch_stack = std::rc::Rc::clone(&dispatch_stack);
                                    let dispatch_observed = dispatch_observed.clone();
                                    async move {
                                        let evidence = dispatch_stack
                                            .borrow_mut()
                                            .poll_ready_task(&ready_tasks, due_ms)
                                            .unwrap();
                                        assert_eq!(evidence.packets_emitted, 1);
                                        dispatch_observed.store(true, Ordering::SeqCst);
                                    }
                                },
                            )
                            .await
                            .unwrap();
                            assert_eq!(
                                dispatch_report.status,
                                AsyncRuntimeSchedulerLoopStatus::StepLimitReached
                            );
                            let wait_report = run_async_runtime_scheduler_loop_until_cancelled(
                                &mut lifecycle,
                                &token,
                                due_ms as u64 + 1,
                                1,
                                10,
                                move |_step| {
                                    wait_observed.store(true, Ordering::SeqCst);
                                    wait_notification.notify_waiters();
                                    vec![RuntimeTaskReadiness::new(
                                        RuntimeComponent::SmoltcpStack,
                                        "smoltcp_tun_bridge_loop",
                                    )
                                    .with_next_ready_delay_ms(Some(60_000))]
                                },
                                |_ready_tasks| async {},
                            )
                            .await
                            .unwrap();
                            *wait_report_slot.lock().unwrap() = Some(wait_report.clone());
                            if wait_report.status == AsyncRuntimeSchedulerLoopStatus::Cancelled {
                                RuntimeTaskStatus::Cancelled
                            } else {
                                RuntimeTaskStatus::TimedOut
                            }
                        },
                    )
                    .unwrap();
                assert_eq!(
                    task_set.expectations(),
                    vec![RuntimeTaskExpectation::new(
                        RuntimeComponent::SmoltcpStack,
                        "smoltcp_tun_bridge_loop",
                    )]
                );
                if !wait_requested.load(Ordering::SeqCst) {
                    tokio::time::timeout(Duration::from_secs(1), wait_notify.notified())
                        .await
                        .unwrap();
                }
                assert!(dispatched.load(Ordering::SeqCst));
                assert_eq!(task_set.request_cancellation(), 1);
                let join_report = task_set.join_all_with_timeout(Duration::from_secs(1)).await;
                assert_eq!(join_report.outcomes.len(), 1);
                assert_eq!(
                    join_report.outcomes[0].component,
                    RuntimeComponent::SmoltcpStack
                );
                assert_eq!(join_report.outcomes[0].task_name, "smoltcp_tun_bridge_loop");
                assert_eq!(join_report.outcomes[0].status, RuntimeTaskStatus::Cancelled);
                let wait_report = wait_report.lock().unwrap().clone().unwrap();
                assert_eq!(
                    wait_report.status,
                    AsyncRuntimeSchedulerLoopStatus::Cancelled
                );
                assert_eq!(wait_report.steps.len(), 1);
                assert_eq!(
                    wait_report.steps[0].scheduler_action,
                    RuntimeSchedulerAction::WaitForTimer
                );
                assert_eq!(
                    wait_report.steps[0].wait_status,
                    AsyncRuntimeSchedulerWaitStatus::Cancelled
                );
                assert_eq!(wait_report.steps[0].plan.next_ready_delay_ms, Some(60_000));
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_step_runs_ready_tasks_and_audits_action() {
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::SmoltcpStack,
                ],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::SmoltcpStack,
                        "smoltcp_tun_bridge_loop",
                    ),
                ],
                1_000,
            )
            .unwrap();
        let dispatched = Arc::new(std::sync::Mutex::new(Vec::new()));
        let dispatched_by_runner = dispatched.clone();

        let report = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &[
                RuntimeTaskReadiness::ready(RuntimeComponent::DnsListener, "dns_accept_loop"),
                RuntimeTaskReadiness::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )
                .with_next_ready_delay_ms(Some(50)),
            ],
            1_010,
            &cancellation,
            move |ready_tasks| async move {
                *dispatched_by_runner.lock().unwrap() = ready_tasks;
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.wait_status,
            AsyncRuntimeSchedulerWaitStatus::NotWaiting
        );
        assert_eq!(
            report.dispatched_tasks,
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::DnsListener,
                "dns_accept_loop"
            )]
        );
        assert_eq!(*dispatched.lock().unwrap(), report.dispatched_tasks);
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "dns_listener:dns_accept_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_step_cancellation_preempts_ready_dispatch() {
        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::DnsListener],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                )],
                1_500,
            )
            .unwrap();
        let runner_dropped = Arc::new(AtomicBool::new(false));
        let runner_dropped_by_task = runner_dropped.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let report = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &[RuntimeTaskReadiness::ready(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
            )],
            1_510,
            &cancellation,
            move |_ready_tasks| async move {
                let _drop_flag = DropFlag(runner_dropped_by_task);
                tokio::time::sleep(Duration::from_secs(60)).await;
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.wait_status,
            AsyncRuntimeSchedulerWaitStatus::Cancelled
        );
        assert!(report.dispatched_tasks.is_empty());
        assert!(
            runner_dropped.load(Ordering::SeqCst),
            "ready-task future must be dropped when scheduler cancellation wins"
        );
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_step_waits_for_timer_or_cancellation() {
        let timer_cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut timer_lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        timer_lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::SmoltcpStack],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )],
                2_000,
            )
            .unwrap();

        let timer_report =
            run_async_runtime_scheduler_step(
                &mut timer_lifecycle,
                &[RuntimeTaskReadiness::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )
                .with_next_ready_delay_ms(Some(1))],
                2_010,
                &timer_cancellation,
                |_ready_tasks| async {},
            )
            .await
            .unwrap();

        assert_eq!(
            timer_report.scheduler_action,
            RuntimeSchedulerAction::WaitForTimer
        );
        assert_eq!(
            timer_report.wait_status,
            AsyncRuntimeSchedulerWaitStatus::TimerElapsed
        );
        let timer_records: Vec<_> = timer_lifecycle.audit().records().collect();
        assert_eq!(
            timer_records[1].details["scheduler_action"],
            "wait_for_timer"
        );
        assert_eq!(timer_records[1].details["next_ready_delay_ms"], "1");

        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        let mut cancelled_lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        cancelled_lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::SmoltcpStack],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )],
                3_000,
            )
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let cancelled_report =
            run_async_runtime_scheduler_step(
                &mut cancelled_lifecycle,
                &[RuntimeTaskReadiness::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )
                .with_next_ready_delay_ms(Some(60_000))],
                3_010,
                &cancellation,
                |_ready_tasks| async {},
            )
            .await
            .unwrap();

        assert_eq!(
            cancelled_report.scheduler_action,
            RuntimeSchedulerAction::WaitForTimer
        );
        assert_eq!(
            cancelled_report.wait_status,
            AsyncRuntimeSchedulerWaitStatus::Cancelled
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_step_yields_when_idle_and_audits_action() {
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::TunDevice, RuntimeComponent::AuditFanIn],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::TunDevice, "tun_packet_loop"),
                    RuntimeTaskExpectation::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
                ],
                4_000,
            )
            .unwrap();

        let report = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &[
                RuntimeTaskReadiness::new(RuntimeComponent::TunDevice, "tun_packet_loop"),
                RuntimeTaskReadiness::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
            ],
            4_010,
            &cancellation,
            |_ready_tasks| async { panic!("idle scheduler step must not dispatch ready tasks") },
        )
        .await
        .unwrap();

        assert_eq!(report.scheduler_action, RuntimeSchedulerAction::Idle);
        assert_eq!(
            report.wait_status,
            AsyncRuntimeSchedulerWaitStatus::IdleYielded
        );
        assert!(report.dispatched_tasks.is_empty());
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::RuntimeReadiness);
        assert_eq!(records[1].details["scheduler_action"], "idle");
        assert_eq!(records[1].details["ready_runtime_task_count"], "0");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_loop_dispatches_then_stops_on_cancellation() {
        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::SmoltcpStack,
                ],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::SmoltcpStack,
                        "smoltcp_tun_bridge_loop",
                    ),
                ],
                5_000,
            )
            .unwrap();
        let dispatched = Arc::new(std::sync::Mutex::new(Vec::new()));
        let dispatched_by_runner = dispatched.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let report = run_async_runtime_scheduler_loop_until_cancelled(
            &mut lifecycle,
            &cancellation,
            5_010,
            10,
            4,
            |step_index| match step_index {
                0 => vec![RuntimeTaskReadiness::ready(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                )],
                _ => vec![RuntimeTaskReadiness::new(
                    RuntimeComponent::SmoltcpStack,
                    "smoltcp_tun_bridge_loop",
                )
                .with_next_ready_delay_ms(Some(60_000))],
            },
            move |ready_tasks| {
                let dispatched_by_runner = dispatched_by_runner.clone();
                async move {
                    dispatched_by_runner.lock().unwrap().extend(ready_tasks);
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AsyncRuntimeSchedulerLoopStatus::Cancelled);
        assert_eq!(report.steps.len(), 2);
        assert_eq!(
            report.steps[0].scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.steps[1].scheduler_action,
            RuntimeSchedulerAction::WaitForTimer
        );
        assert_eq!(
            report.steps[1].wait_status,
            AsyncRuntimeSchedulerWaitStatus::Cancelled
        );
        assert_eq!(
            *dispatched.lock().unwrap(),
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::DnsListener,
                "dns_accept_loop"
            )]
        );
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(records[2].details["scheduler_action"], "wait_for_timer");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_loop_reports_step_limit() {
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::AuditFanIn],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::AuditFanIn,
                    "audit_fan_in_loop",
                )],
                6_000,
            )
            .unwrap();

        let report = run_async_runtime_scheduler_loop_until_cancelled(
            &mut lifecycle,
            &cancellation,
            6_010,
            10,
            2,
            |_step_index| {
                vec![RuntimeTaskReadiness::new(
                    RuntimeComponent::AuditFanIn,
                    "audit_fan_in_loop",
                )]
            },
            |_ready_tasks| async {},
        )
        .await
        .unwrap();

        assert_eq!(
            report.status,
            AsyncRuntimeSchedulerLoopStatus::StepLimitReached
        );
        assert_eq!(report.steps.len(), 2);
        assert!(report
            .steps
            .iter()
            .all(|step| step.scheduler_action == RuntimeSchedulerAction::Idle));
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "idle");
        assert_eq!(records[2].details["scheduler_action"], "idle");
    }

    #[test]
    fn async_runtime_readiness_collection_preserves_live_source_order() {
        let mut dns_source =
            || RuntimeTaskReadiness::ready(RuntimeComponent::DnsListener, "dns_accept_loop");
        let mut http_source = || {
            RuntimeTaskReadiness::ready(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
            )
        };
        let mut socks_source =
            || RuntimeTaskReadiness::ready(RuntimeComponent::Socks5Listener, "socks5_accept_loop");
        let mut tun_source =
            || RuntimeTaskReadiness::new(RuntimeComponent::TunDevice, "tun_packet_loop");
        let mut stack_source = || {
            RuntimeTaskReadiness::new(RuntimeComponent::SmoltcpStack, "smoltcp_tun_bridge_loop")
                .with_next_ready_delay_ms(Some(25))
        };
        let mut fan_in_source =
            || RuntimeTaskReadiness::ready(RuntimeComponent::AuditFanIn, "audit_fan_in_loop");
        let mut sources: Vec<&mut dyn AsyncRuntimeReadinessSource> = vec![
            &mut dns_source,
            &mut http_source,
            &mut socks_source,
            &mut tun_source,
            &mut stack_source,
            &mut fan_in_source,
        ];

        let readiness = collect_async_runtime_readiness(&mut sources);

        assert_eq!(readiness.len(), 6);
        assert_eq!(readiness[0].component, RuntimeComponent::DnsListener);
        assert_eq!(readiness[1].component, RuntimeComponent::HttpProxyListener);
        assert_eq!(readiness[2].component, RuntimeComponent::Socks5Listener);
        assert_eq!(readiness[3].component, RuntimeComponent::TunDevice);
        assert_eq!(readiness[4].component, RuntimeComponent::SmoltcpStack);
        assert_eq!(readiness[4].next_ready_delay_ms, Some(25));
        assert_eq!(readiness[5].component, RuntimeComponent::AuditFanIn);
        let plan = RuntimeReadinessPlan::from_tasks(&readiness);
        assert_eq!(
            plan.scheduler_action(),
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(plan.ready_task_details(), "dns_listener:dns_accept_loop,http_proxy_listener:http_proxy_accept_loop,socks5_listener:socks5_accept_loop,audit_fan_in:audit_fan_in_loop");
    }

    #[test]
    fn async_runtime_readiness_sources_cover_live_proxy_runtime_listeners_and_fan_in() {
        let query = dns_query(0x7c7f, "ReadinessSources.TEST", 1);
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
        let runtime = BlockingProxyRuntime::bind(
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
            7_500,
        )
        .unwrap();
        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        runtime
            .ingest_live_audit_sources_into_fan_in(&mut fan_in)
            .unwrap();
        let mut dns_source = runtime.dns_server();
        let mut http_source = runtime.http_proxy_server();
        let mut socks_source = runtime.socks5_proxy_server();
        let mut fan_in_source = &fan_in;
        let mut sources: Vec<&mut dyn AsyncRuntimeReadinessSource> = vec![
            &mut dns_source,
            &mut http_source,
            &mut socks_source,
            &mut fan_in_source,
        ];

        let readiness = collect_async_runtime_readiness(&mut sources);

        assert_eq!(readiness.len(), 4);
        assert_eq!(
            readiness,
            vec![
                RuntimeTaskReadiness::ready(RuntimeComponent::DnsListener, "dns_accept_loop"),
                RuntimeTaskReadiness::ready(
                    RuntimeComponent::HttpProxyListener,
                    "http_proxy_accept_loop",
                ),
                RuntimeTaskReadiness::ready(RuntimeComponent::Socks5Listener, "socks5_accept_loop"),
                RuntimeTaskReadiness::ready(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_dispatch_drains_ready_fan_in() {
        let mut fan_in = RuntimeAuditFanIn::new("s1", 8);
        let mut start = AuditRecord::new_at(AuditKind::NetworkSessionStart, "s1", 8_000);
        start.sequence = 1;
        fan_in.ingest("lifecycle", &[start]).unwrap();
        assert!(fan_in.runtime_readiness().ready);
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::AuditFanIn],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::AuditFanIn,
                    "audit_fan_in_loop",
                )],
                8_000,
            )
            .unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let readiness = fan_in.runtime_readiness();
        let mut sink = JsonLineAuditSink::new(Vec::new());
        let mut observed_drain = None;

        let report = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &[readiness],
            8_010,
            &cancellation,
            |ready_tasks| {
                let fan_in = &mut fan_in;
                let sink = &mut sink;
                let observed_drain = &mut observed_drain;
                async move {
                    *observed_drain =
                        run_async_runtime_audit_fan_in_ready_task(&ready_tasks, fan_in, sink)
                            .unwrap();
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.dispatched_tasks,
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop"
            )]
        );
        assert_eq!(observed_drain.unwrap().drained_records, 1);
        assert_eq!(sink.records_written(), 1);
        assert!(!fan_in.runtime_readiness().ready);
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "audit_fan_in:audit_fan_in_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_dispatch_drives_ready_dns_listener_once() {
        let query = dns_query(0x8123, "Dispatch.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let mut dns_config = PolicyConfig::default();
        dns_config.rules.push(
            PolicyRule::allow("allow-dispatch-dns")
                .protocol(Protocol::Dns)
                .hostname("dispatch.test"),
        );
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(dns_config), 16),
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
            8_100,
        )
        .unwrap();
        let dns_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        dns_client
            .send_to(&query, runtime.dns_addr().unwrap())
            .unwrap();
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![RuntimeComponent::DnsListener],
                vec![RuntimeTaskExpectation::new(
                    RuntimeComponent::DnsListener,
                    "dns_accept_loop",
                )],
                8_100,
            )
            .unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut dispatch_report = None;

        let scheduler_report = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &[RuntimeTaskReadiness::ready(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
            )],
            8_110,
            &cancellation,
            |ready_tasks| {
                let runtime = &mut runtime;
                let dispatch_report = &mut dispatch_report;
                async move {
                    *dispatch_report = Some(
                        runtime
                            .dispatch_ready_proxy_listener_tasks(&ready_tasks, 8_120)
                            .unwrap(),
                    );
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            scheduler_report.scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        let dispatch_report = dispatch_report.unwrap();
        assert_eq!(
            dispatch_report.dispatched_tasks,
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::DnsListener,
                "dns_accept_loop"
            )]
        );
        let dns_step = dispatch_report.dns_step.unwrap();
        assert_eq!(dns_step.decision, Decision::Allow);
        assert!(dns_step.sent_response);
        let mut dns_reply = [0u8; 512];
        let (reply_len, _) = dns_client.recv_from(&mut dns_reply).unwrap();
        assert!(reply_len > 0);
        assert!(runtime
            .audit_records()
            .iter()
            .any(|record| record.kind == AuditKind::DnsQueryDecision));
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "dns_listener:dns_accept_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_dispatch_drives_ready_http_and_socks_listeners_once() {
        let query = dns_query(0x8124, "DispatchProxy.TEST", 1);
        let response = dns_a_response(&query, [127, 0, 0, 1], 30);
        let dns_handler = DnsBrokerHandler::new(
            BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 16),
            StaticDnsUpstream { response },
            "10.0.2.3".parse().unwrap(),
        );
        let mut http_config = PolicyConfig::default();
        http_config.rules.push(
            PolicyRule::allow("allow-dispatch-http")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let http_frontend = ExplicitProxyFrontend::new(
            "s1",
            BrokerCore::new(PolicyEngine::new(http_config), 16),
            InMemoryExplicitProxyEgress::default(),
        );
        let mut socks_config = PolicyConfig::default();
        socks_config.rules.push(
            PolicyRule::allow("allow-dispatch-socks")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
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
            8_200,
        )
        .unwrap();
        let mut http_client = TcpStream::connect(runtime.http_proxy_addr().unwrap()).unwrap();
        http_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        http_client
            .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let mut socks_client = TcpStream::connect(runtime.socks5_proxy_addr().unwrap()).unwrap();
        socks_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socks_client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        socks_client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .unwrap();
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::HttpProxyListener,
                    RuntimeComponent::Socks5Listener,
                ],
                vec![
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::HttpProxyListener,
                        "http_proxy_accept_loop",
                    ),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::Socks5Listener,
                        "socks5_accept_loop",
                    ),
                ],
                8_200,
            )
            .unwrap();
        let cancellation =
            AsyncRuntimeCancellationToken::new(Arc::new(AsyncRuntimeCancellationState::new()));
        let mut dispatch_report = None;

        let scheduler_report = run_async_runtime_scheduler_step(
            &mut lifecycle,
            &[
                RuntimeTaskReadiness::ready(
                    RuntimeComponent::HttpProxyListener,
                    "http_proxy_accept_loop",
                ),
                RuntimeTaskReadiness::ready(RuntimeComponent::Socks5Listener, "socks5_accept_loop"),
            ],
            8_210,
            &cancellation,
            |ready_tasks| {
                let runtime = &mut runtime;
                let dispatch_report = &mut dispatch_report;
                async move {
                    *dispatch_report = Some(
                        runtime
                            .dispatch_ready_proxy_listener_tasks(&ready_tasks, 8_220)
                            .unwrap(),
                    );
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            scheduler_report.scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        let dispatch_report = dispatch_report.unwrap();
        assert_eq!(dispatch_report.dispatched_tasks.len(), 2);
        let http_step = dispatch_report.http_proxy_step.unwrap();
        assert_eq!(http_step.decision, Decision::Allow);
        assert!(http_step.forwarded);
        assert_eq!(http_step.status_code, 200);
        let socks_step = dispatch_report.socks5_proxy_step.unwrap();
        assert_eq!(socks_step.decision, Decision::Allow);
        assert!(socks_step.forwarded);
        assert_eq!(socks_step.reply_code, 0x00);
        let mut http_response = String::new();
        http_client.read_to_string(&mut http_response).unwrap();
        assert!(http_response.starts_with("HTTP/1.1 200 OK"));
        let mut socks_response = Vec::new();
        socks_client.read_to_end(&mut socks_response).unwrap();
        assert_eq!(&socks_response[..2], &[0x05, 0x00]);
        assert_eq!(
            &socks_response[2..12],
            &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert!(runtime
            .audit_records()
            .iter()
            .any(|record| record.kind == AuditKind::HttpRequestDecision));
        assert!(runtime
            .audit_records()
            .iter()
            .any(|record| record.kind == AuditKind::SocksConnectDecision));
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(
            records[1].details["ready_runtime_tasks"],
            "http_proxy_listener:http_proxy_accept_loop,socks5_listener:socks5_accept_loop"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_scheduler_loop_collects_sources_each_step() {
        let cancellation_state = Arc::new(AsyncRuntimeCancellationState::new());
        let cancellation = AsyncRuntimeCancellationToken::new(cancellation_state.clone());
        let mut lifecycle = RuntimeLifecycleHarness::new("async-scheduler", 8);
        lifecycle
            .start_with_task_expectations(
                vec![
                    RuntimeComponent::DnsListener,
                    RuntimeComponent::SmoltcpStack,
                    RuntimeComponent::AuditFanIn,
                ],
                vec![
                    RuntimeTaskExpectation::new(RuntimeComponent::DnsListener, "dns_accept_loop"),
                    RuntimeTaskExpectation::new(
                        RuntimeComponent::SmoltcpStack,
                        "smoltcp_tun_bridge_loop",
                    ),
                    RuntimeTaskExpectation::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop"),
                ],
                7_000,
            )
            .unwrap();
        let dns_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stack_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fan_in_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dns_calls_by_source = dns_calls.clone();
        let stack_calls_by_source = stack_calls.clone();
        let fan_in_calls_by_source = fan_in_calls.clone();
        let mut dns_source = move || {
            if dns_calls_by_source.fetch_add(1, Ordering::SeqCst) == 0 {
                RuntimeTaskReadiness::ready(RuntimeComponent::DnsListener, "dns_accept_loop")
            } else {
                RuntimeTaskReadiness::new(RuntimeComponent::DnsListener, "dns_accept_loop")
            }
        };
        let mut stack_source = move || {
            stack_calls_by_source.fetch_add(1, Ordering::SeqCst);
            RuntimeTaskReadiness::new(RuntimeComponent::SmoltcpStack, "smoltcp_tun_bridge_loop")
                .with_next_ready_delay_ms(Some(60_000))
        };
        let mut fan_in_source = move || {
            fan_in_calls_by_source.fetch_add(1, Ordering::SeqCst);
            RuntimeTaskReadiness::new(RuntimeComponent::AuditFanIn, "audit_fan_in_loop")
        };
        let mut sources: Vec<&mut dyn AsyncRuntimeReadinessSource> =
            vec![&mut dns_source, &mut stack_source, &mut fan_in_source];
        let dispatched = Arc::new(std::sync::Mutex::new(Vec::new()));
        let dispatched_by_runner = dispatched.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_state.cancelled.store(true, Ordering::SeqCst);
            cancellation_state.notify.notify_waiters();
        });

        let report = run_async_runtime_scheduler_loop_with_sources_until_cancelled(
            &mut lifecycle,
            &cancellation,
            7_010,
            10,
            4,
            &mut sources,
            move |ready_tasks| {
                let dispatched_by_runner = dispatched_by_runner.clone();
                async move {
                    dispatched_by_runner.lock().unwrap().extend(ready_tasks);
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AsyncRuntimeSchedulerLoopStatus::Cancelled);
        assert_eq!(report.steps.len(), 2);
        assert_eq!(dns_calls.load(Ordering::SeqCst), 2);
        assert_eq!(stack_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fan_in_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            report.steps[0].scheduler_action,
            RuntimeSchedulerAction::RunReadyTasks
        );
        assert_eq!(
            report.steps[1].scheduler_action,
            RuntimeSchedulerAction::WaitForTimer
        );
        assert_eq!(
            *dispatched.lock().unwrap(),
            vec![RuntimeTaskExpectation::new(
                RuntimeComponent::DnsListener,
                "dns_accept_loop"
            )]
        );
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].details["scheduler_action"], "run_ready_tasks");
        assert_eq!(records[2].details["scheduler_action"], "wait_for_timer");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_task_set_timeout_is_fail_closed() {
        let mut task_set = AsyncRuntimeTaskSet::new();
        task_set
            .spawn_task(
                RuntimeComponent::SmoltcpStack,
                "smoltcp_tun_bridge_loop",
                async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    RuntimeTaskStatus::Completed
                },
            )
            .unwrap();
        let expectations = task_set.expectations();
        let report = task_set
            .join_all_with_timeout(Duration::from_millis(1))
            .await;

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::TimedOut);
        let mut lifecycle = RuntimeLifecycleHarness::new("async-task-sandbox", 4);
        lifecycle
            .start_with_task_expectations(vec![RuntimeComponent::SmoltcpStack], expectations, 2_000)
            .unwrap();
        lifecycle
            .exit_with_cleanup_child_and_tasks(
                RuntimeExitStatus::Clean,
                RuntimeCleanupReport::all_succeeded(vec![RuntimeCleanupAction::SmoltcpStack]),
                None,
                Some(report),
                2_100,
            )
            .unwrap();
        let records: Vec<_> = lifecycle.audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::NetworkSessionExit);
        assert_eq!(records[1].decision, Some(Decision::FailClosed));
        assert_eq!(records[1].reason, Some(DenialReason::RuntimeState));
        assert_eq!(records[1].details["task_join_status"], "failed");
        assert_eq!(
            records[1].details["runtime_tasks"],
            "smoltcp_stack:smoltcp_tun_bridge_loop:timed_out"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_task_set_timeout_awaits_aborted_task_before_report() {
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_by_task = dropped.clone();
        let mut task_set = AsyncRuntimeTaskSet::new();
        task_set
            .spawn_task(
                RuntimeComponent::SmoltcpStack,
                "smoltcp_tun_bridge_loop",
                async move {
                    let _drop_flag = DropFlag(dropped_by_task);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    RuntimeTaskStatus::Completed
                },
            )
            .unwrap();

        let report = task_set
            .join_all_with_timeout(Duration::from_millis(1))
            .await;

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].status, RuntimeTaskStatus::TimedOut);
        assert!(
            dropped.load(Ordering::SeqCst),
            "timed-out async task must be dropped before lifecycle join evidence is returned"
        );
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
        let readiness_plan = RuntimeReadinessPlan::from_tasks(&[fan_in_report.runtime_readiness()]);
        assert_eq!(readiness_plan.status_detail(), "ready");
        assert_eq!(
            readiness_plan.ready_task_details(),
            "audit_fan_in:audit_fan_in_loop"
        );
        runtime
            .record_readiness_plan(&readiness_plan, 1_030)
            .unwrap();
        let shutdown_drain = runtime
            .exit_and_drain_live_audit_sources_to_sink(
                RuntimeExitStatus::Clean,
                None,
                &mut fan_in,
                &mut sink,
                1_100,
            )
            .unwrap();
        assert!(shutdown_drain.before_exit.made_progress());
        assert_eq!(shutdown_drain.before_exit.drain_report.drained_records, 1);
        assert!(shutdown_drain.after_exit.made_progress());
        assert_eq!(shutdown_drain.after_exit.drain_report.drained_records, 1);
        let fan_in_output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(fan_in_output.contains("network_session_start"));
        assert!(fan_in_output.contains("proxy_destination_resolved"));
        assert!(fan_in_output.contains("http_request_decision"));
        assert!(fan_in_output.contains("runtime_readiness"));
        assert!(fan_in_output.contains("network_session_exit"));
        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        assert_eq!(lifecycle_records.len(), 5);
        assert_eq!(lifecycle_records[3].kind, AuditKind::RuntimeReadiness);
        assert_eq!(lifecycle_records[3].details["readiness_status"], "ready");
        assert_eq!(
            lifecycle_records[3].details["scheduler_action"],
            "run_ready_tasks"
        );
        assert_eq!(
            lifecycle_records[3].details["ready_runtime_tasks"],
            "audit_fan_in:audit_fan_in_loop"
        );
        assert_eq!(lifecycle_records[4].kind, AuditKind::NetworkSessionExit);
        assert_eq!(lifecycle_records[4].duration_ms, Some(100));
        assert_eq!(lifecycle_records[4].details["cleanup_status"], "complete");
        assert_eq!(
            lifecycle_records[4].details["cleanup_actions"],
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
    fn blocking_dns_http_runtime_shutdown_drain_failure_still_exits_and_closes() {
        let query = dns_query(0x6c6c, "Shutdown.TEST", 1);
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
            8,
            SharedDnsCache::default(),
            "127.0.0.1:0".parse().unwrap(),
            dns_handler,
            "127.0.0.1:0".parse().unwrap(),
            proxy_frontend,
            Duration::from_secs(1),
            512,
            4096,
            1_200,
        )
        .unwrap();
        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut failing_sink = JsonLineAuditSink::new(FailingWriter);

        let error = runtime
            .exit_and_drain_live_audit_sources_to_sink(
                RuntimeExitStatus::Clean,
                None,
                &mut fan_in,
                &mut failing_sink,
                1_300,
            )
            .unwrap_err();

        match error {
            BlockingRuntimeAuditFanInShutdownDrainError::PreExitDrain {
                error,
                exit,
                post_exit,
            } => {
                assert!(matches!(
                    error,
                    BlockingRuntimeAuditFanInDrainError::Drain(
                        RuntimeAuditDrainError::SinkWriteFailed { .. }
                    )
                ));
                assert!(exit.is_ok());
                assert!(matches!(
                    post_exit,
                    Err(BlockingRuntimeAuditFanInDrainError::Drain(
                        RuntimeAuditDrainError::SinkWriteFailed { .. }
                    ))
                ));
            }
            other => panic!("unexpected shutdown drain error: {other:?}"),
        }
        assert_eq!(failing_sink.records_written(), 0);
        let lifecycle_records: Vec<_> = runtime.lifecycle().audit().records().collect();
        let exit = lifecycle_records.last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(
            exit.details["cleanup_actions"],
            "dns_listener,http_proxy_listener,audit_fan_in"
        );
        assert_eq!(
            runtime.handle_dns_once(1_301).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(1_301).unwrap_err(),
            ProxyEgressError::SendFailed
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_owned_scheduler_task_shutdown_cancels_joins_and_drains() {
        let query = dns_query(0x7d7e, "OwnedSchedulerShutdown.TEST", 1);
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
            1_550,
        )
        .unwrap();
        let wait_plan_requested = Arc::new(AtomicBool::new(false));
        let wait_plan_notify = Arc::new(tokio::sync::Notify::new());
        let scheduler_cancelled = Arc::new(AtomicBool::new(false));
        let scheduler_report = Arc::new(std::sync::Mutex::new(None));
        let mut task_set = AsyncRuntimeTaskSet::new();
        for (component, task_name) in [
            (RuntimeComponent::DnsListener, "dns_accept_loop"),
            (
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
            ),
            (RuntimeComponent::Socks5Listener, "socks5_accept_loop"),
        ] {
            task_set
                .spawn_cancellable_task(component, task_name, |token| async move {
                    token.cancelled().await;
                    RuntimeTaskStatus::Cancelled
                })
                .unwrap();
        }
        let wait_requested = wait_plan_requested.clone();
        let wait_notify = wait_plan_notify.clone();
        let cancelled = scheduler_cancelled.clone();
        let report_slot = scheduler_report.clone();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                move |token| async move {
                    let mut lifecycle = RuntimeLifecycleHarness::new("owned-scheduler-task", 8);
                    lifecycle
                        .start_with_task_expectations(
                            vec![RuntimeComponent::AuditFanIn],
                            vec![RuntimeTaskExpectation::new(
                                RuntimeComponent::AuditFanIn,
                                "audit_fan_in_loop",
                            )],
                            1_560,
                        )
                        .unwrap();
                    let report = run_async_runtime_scheduler_loop_until_cancelled(
                        &mut lifecycle,
                        &token,
                        1_560,
                        1,
                        10,
                        move |_step| {
                            wait_requested.store(true, Ordering::SeqCst);
                            wait_notify.notify_waiters();
                            vec![RuntimeTaskReadiness::new(
                                RuntimeComponent::AuditFanIn,
                                "audit_fan_in_loop",
                            )
                            .with_next_ready_delay_ms(Some(60_000))]
                        },
                        |_ready_tasks| async {},
                    )
                    .await
                    .unwrap();
                    *report_slot.lock().unwrap() = Some(report.clone());
                    if report.status == AsyncRuntimeSchedulerLoopStatus::Cancelled {
                        cancelled.store(true, Ordering::SeqCst);
                        RuntimeTaskStatus::Cancelled
                    } else {
                        RuntimeTaskStatus::TimedOut
                    }
                },
            )
            .unwrap();
        if !wait_plan_requested.load(Ordering::SeqCst) {
            tokio::time::timeout(Duration::from_secs(1), wait_plan_notify.notified())
                .await
                .unwrap();
        }
        assert!(wait_plan_requested.load(Ordering::SeqCst));
        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut sink = JsonLineAuditSink::new(Vec::new());

        let shutdown = runtime
            .exit_with_async_task_set_and_drain_live_audit_sources_to_sink(
                RuntimeExitStatus::Clean,
                task_set,
                Duration::from_secs(1),
                &mut fan_in,
                &mut sink,
                1_650,
            )
            .await
            .unwrap();

        assert!(scheduler_cancelled.load(Ordering::SeqCst));
        let scheduler_report = scheduler_report.lock().unwrap().clone().unwrap();
        assert_eq!(
            scheduler_report.status,
            AsyncRuntimeSchedulerLoopStatus::Cancelled
        );
        assert_eq!(scheduler_report.steps.len(), 1);
        assert_eq!(
            scheduler_report.steps[0].scheduler_action,
            RuntimeSchedulerAction::WaitForTimer
        );
        assert_eq!(
            scheduler_report.steps[0].wait_status,
            AsyncRuntimeSchedulerWaitStatus::Cancelled
        );
        assert_eq!(
            scheduler_report.steps[0].plan.next_ready_delay_ms,
            Some(60_000)
        );
        assert!(scheduler_report.steps[0].dispatched_tasks.is_empty());
        assert_eq!(shutdown.cancelled_tasks, 4);
        assert_eq!(shutdown.task_report.outcomes.len(), 4);
        assert!(shutdown
            .task_report
            .outcomes
            .iter()
            .all(|outcome| outcome.status == RuntimeTaskStatus::Cancelled));
        assert!(shutdown.shutdown_drain.before_exit.made_progress());
        assert!(shutdown.shutdown_drain.after_exit.made_progress());
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.contains("network_session_exit"));
        assert!(output.contains("audit_fan_in:audit_fan_in_loop:cancelled"));
        let exit = runtime.lifecycle().audit().records().last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.details["task_join_status"], "complete");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn async_owned_live_io_scheduler_task_dispatches_then_shutdown_drains() {
        let query = dns_query(0x7d8e, "OwnedLiveSchedulerShutdown.TEST", 1);
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
            1_750,
        )
        .unwrap();
        let live_dispatch_done = Arc::new(AtomicBool::new(false));
        let shutdown_wait_requested = Arc::new(AtomicBool::new(false));
        let shutdown_wait_notify = Arc::new(tokio::sync::Notify::new());
        let shutdown_report = Arc::new(std::sync::Mutex::new(None));
        let mut task_set = AsyncRuntimeTaskSet::new();
        for (component, task_name) in [
            (RuntimeComponent::DnsListener, "dns_accept_loop"),
            (
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
            ),
            (RuntimeComponent::Socks5Listener, "socks5_accept_loop"),
        ] {
            task_set
                .spawn_cancellable_task(component, task_name, |token| async move {
                    token.cancelled().await;
                    RuntimeTaskStatus::Cancelled
                })
                .unwrap();
        }
        let dispatch_done = live_dispatch_done.clone();
        let wait_requested = shutdown_wait_requested.clone();
        let wait_notify = shutdown_wait_notify.clone();
        let report_slot = shutdown_report.clone();
        task_set
            .spawn_cancellable_task(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                move |token| async move {
                    let mut lifecycle = RuntimeLifecycleHarness::new("owned-live-scheduler", 16);
                    lifecycle
                        .start_with_task_expectations(
                            vec![
                                RuntimeComponent::DnsListener,
                                RuntimeComponent::HttpProxyListener,
                                RuntimeComponent::TunDevice,
                                RuntimeComponent::AuditFanIn,
                            ],
                            vec![
                                RuntimeTaskExpectation::new(
                                    RuntimeComponent::DnsListener,
                                    "dns_accept_loop",
                                ),
                                RuntimeTaskExpectation::new(
                                    RuntimeComponent::HttpProxyListener,
                                    "http_proxy_accept_loop",
                                ),
                                RuntimeTaskExpectation::new(
                                    RuntimeComponent::TunDevice,
                                    "tun_packet_loop",
                                ),
                                RuntimeTaskExpectation::new(
                                    RuntimeComponent::AuditFanIn,
                                    "audit_fan_in_loop",
                                ),
                            ],
                            1_760,
                        )
                        .unwrap();

                    let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
                    udp_sender
                        .send_to(b"owned-dns-ready", udp_socket.local_addr().unwrap())
                        .unwrap();
                    let udp_report = wait_for_async_udp_socket_readiness(
                        &udp_socket,
                        RuntimeComponent::DnsListener,
                        "dns_accept_loop",
                        Duration::from_secs(1),
                        &token,
                    )
                    .await;

                    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let listener_addr = tcp_listener.local_addr().unwrap();
                    let client = tokio::spawn(async move {
                        let stream = tokio::net::TcpStream::connect(listener_addr).await.unwrap();
                        stream.local_addr().unwrap()
                    });
                    let tcp_report = accept_async_tcp_listener_when_ready(
                        &tcp_listener,
                        RuntimeComponent::HttpProxyListener,
                        "http_proxy_accept_loop",
                        Duration::from_secs(1),
                        &token,
                    )
                    .await;
                    let tcp_client_addr = client.await.unwrap();

                    let (packet_fd, mut sandbox_peer) =
                        std::os::unix::net::UnixStream::pair().unwrap();
                    packet_fd.set_nonblocking(true).unwrap();
                    let async_packet_fd = tokio::io::unix::AsyncFd::new(packet_fd).unwrap();
                    sandbox_peer.write_all(b"owned-tun-ready").unwrap();
                    let packet_report = wait_for_async_packet_fd_readiness(
                        &async_packet_fd,
                        Duration::from_secs(1),
                        &token,
                    )
                    .await;

                    let audit_ready = RuntimeTaskReadiness::ready(
                        RuntimeComponent::AuditFanIn,
                        "audit_fan_in_loop",
                    );
                    let io_reports = [udp_report, packet_report];
                    let readiness = collect_async_runtime_readiness_from_reports(
                        &io_reports,
                        std::slice::from_ref(&tcp_report),
                        &[],
                        &[audit_ready],
                    );
                    let mut tcp_stream = Some(tcp_report.stream.unwrap());
                    let tcp_peer = tcp_report.accepted_peer;
                    let dispatch_token = token.clone();
                    let dispatch_step = run_async_runtime_scheduler_step(
                        &mut lifecycle,
                        &readiness,
                        1_770,
                        &token,
                        |ready_tasks| async move {
                            let mut packet = [0u8; 64];
                            let (udp_len, _) = udp_socket.try_recv_from(&mut packet).unwrap();
                            assert_eq!(&packet[..udp_len], b"owned-dns-ready");
                            assert_eq!(tcp_peer, Some(tcp_client_addr));
                            assert!(tcp_stream.take().is_some());
                            let packet_read = read_async_packet_fd_ready_task(
                                &async_packet_fd,
                                &ready_tasks,
                                64,
                                Duration::from_secs(1),
                                &dispatch_token,
                            )
                            .await
                            .unwrap()
                            .unwrap();
                            assert_eq!(
                                packet_read.packet.as_deref(),
                                Some(&b"owned-tun-ready"[..])
                            );
                            assert!(ready_tasks.iter().any(|task| {
                                task.component == RuntimeComponent::AuditFanIn
                                    && task.task_name == "audit_fan_in_loop"
                            }));
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        dispatch_step.scheduler_action,
                        RuntimeSchedulerAction::RunReadyTasks
                    );
                    assert_eq!(dispatch_step.dispatched_tasks.len(), 4);
                    dispatch_done.store(true, Ordering::SeqCst);

                    let shutdown_report = run_async_runtime_scheduler_loop_until_cancelled(
                        &mut lifecycle,
                        &token,
                        1_780,
                        1,
                        10,
                        move |_step| {
                            wait_requested.store(true, Ordering::SeqCst);
                            wait_notify.notify_waiters();
                            vec![RuntimeTaskReadiness::new(
                                RuntimeComponent::AuditFanIn,
                                "audit_fan_in_loop",
                            )
                            .with_next_ready_delay_ms(Some(60_000))]
                        },
                        |_ready_tasks| async {},
                    )
                    .await
                    .unwrap();
                    *report_slot.lock().unwrap() = Some(shutdown_report.clone());
                    if shutdown_report.status == AsyncRuntimeSchedulerLoopStatus::Cancelled {
                        RuntimeTaskStatus::Cancelled
                    } else {
                        RuntimeTaskStatus::TimedOut
                    }
                },
            )
            .unwrap();
        if !shutdown_wait_requested.load(Ordering::SeqCst) {
            tokio::time::timeout(Duration::from_secs(1), shutdown_wait_notify.notified())
                .await
                .unwrap();
        }
        assert!(live_dispatch_done.load(Ordering::SeqCst));
        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut sink = JsonLineAuditSink::new(Vec::new());

        let shutdown = runtime
            .exit_with_async_task_set_and_drain_live_audit_sources_to_sink(
                RuntimeExitStatus::Clean,
                task_set,
                Duration::from_secs(1),
                &mut fan_in,
                &mut sink,
                1_850,
            )
            .await
            .unwrap();

        let shutdown_report = shutdown_report.lock().unwrap().clone().unwrap();
        assert_eq!(
            shutdown_report.status,
            AsyncRuntimeSchedulerLoopStatus::Cancelled
        );
        assert_eq!(shutdown_report.steps.len(), 1);
        assert_eq!(
            shutdown_report.steps[0].wait_status,
            AsyncRuntimeSchedulerWaitStatus::Cancelled
        );
        assert_eq!(shutdown.cancelled_tasks, 4);
        assert!(shutdown
            .task_report
            .outcomes
            .iter()
            .all(|outcome| outcome.status == RuntimeTaskStatus::Cancelled));
        assert!(shutdown.shutdown_drain.before_exit.made_progress());
        assert!(shutdown.shutdown_drain.after_exit.made_progress());
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.contains("network_session_exit"));
        assert!(output.contains("audit_fan_in:audit_fan_in_loop:cancelled"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_proxy_runtime_async_task_shutdown_drains_final_audit() {
        let query = dns_query(0x7c7e, "AsyncShutdownFull.TEST", 1);
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
            1_350,
        )
        .unwrap();
        let mut task_set = AsyncRuntimeTaskSet::new();
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
                .spawn_cancellable_task(component, task_name, |token| async move {
                    token.cancelled().await;
                    RuntimeTaskStatus::Cancelled
                })
                .unwrap();
        }
        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut sink = JsonLineAuditSink::new(Vec::new());

        let shutdown = runtime
            .exit_with_async_task_set_and_drain_live_audit_sources_to_sink(
                RuntimeExitStatus::Clean,
                task_set,
                Duration::from_secs(1),
                &mut fan_in,
                &mut sink,
                1_450,
            )
            .await
            .unwrap();

        assert_eq!(shutdown.cancelled_tasks, 4);
        assert_eq!(shutdown.task_report.outcomes.len(), 4);
        assert!(shutdown
            .task_report
            .outcomes
            .iter()
            .all(|outcome| outcome.status == RuntimeTaskStatus::Cancelled));
        assert!(shutdown.shutdown_drain.before_exit.made_progress());
        assert!(shutdown.shutdown_drain.after_exit.made_progress());
        assert_eq!(
            shutdown
                .shutdown_drain
                .after_exit
                .drain_report
                .drained_records,
            1
        );
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.contains("network_session_start"));
        assert!(output.contains("network_session_exit"));
        assert!(output.contains("dns_listener:dns_accept_loop:cancelled"));
        assert!(output.contains("http_proxy_listener:http_proxy_accept_loop:cancelled"));
        assert!(output.contains("socks5_listener:socks5_accept_loop:cancelled"));
        assert!(output.contains("audit_fan_in:audit_fan_in_loop:cancelled"));
        let exit = runtime.lifecycle().audit().records().last().unwrap();
        assert_eq!(exit.kind, AuditKind::NetworkSessionExit);
        assert_eq!(exit.decision, Some(Decision::Allow));
        assert_eq!(exit.details["task_join_status"], "complete");
        assert_eq!(
            runtime.handle_dns_once(1_451).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(1_451).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        assert_eq!(
            runtime.handle_socks5_proxy_once(1_451).unwrap_err(),
            ProxyEgressError::SendFailed
        );
    }

    #[test]
    fn blocking_proxy_runtime_shutdown_drain_emits_exit_and_closes_all_listeners() {
        let query = dns_query(0x7c7d, "ShutdownFull.TEST", 1);
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
            1_400,
        )
        .unwrap();
        let task_report = RuntimeTaskJoinReport::new(vec![
            RuntimeTaskOutcome::new(
                RuntimeComponent::DnsListener,
                "dns_accept_loop",
                RuntimeTaskStatus::Cancelled,
            ),
            RuntimeTaskOutcome::new(
                RuntimeComponent::HttpProxyListener,
                "http_proxy_accept_loop",
                RuntimeTaskStatus::Cancelled,
            ),
            RuntimeTaskOutcome::new(
                RuntimeComponent::Socks5Listener,
                "socks5_accept_loop",
                RuntimeTaskStatus::Cancelled,
            ),
            RuntimeTaskOutcome::new(
                RuntimeComponent::AuditFanIn,
                "audit_fan_in_loop",
                RuntimeTaskStatus::Cancelled,
            ),
        ]);
        let mut fan_in = RuntimeAuditFanIn::new("s1", 16);
        let mut sink = JsonLineAuditSink::new(Vec::new());

        let shutdown_drain = runtime
            .exit_and_drain_live_audit_sources_to_sink(
                RuntimeExitStatus::Clean,
                Some(task_report),
                &mut fan_in,
                &mut sink,
                1_500,
            )
            .unwrap();

        assert!(shutdown_drain.before_exit.made_progress());
        assert!(shutdown_drain.after_exit.made_progress());
        assert_eq!(shutdown_drain.after_exit.drain_report.drained_records, 1);
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.contains("network_session_start"));
        assert!(output.contains("socks5_listener"));
        assert!(output.contains("network_session_exit"));
        assert_eq!(
            runtime.handle_dns_once(1_501).unwrap_err(),
            DnsUpstreamError::Unavailable
        );
        assert_eq!(
            runtime.handle_http_proxy_once(1_501).unwrap_err(),
            ProxyEgressError::SendFailed
        );
        assert_eq!(
            runtime.handle_socks5_proxy_once(1_501).unwrap_err(),
            ProxyEgressError::SendFailed
        );
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
