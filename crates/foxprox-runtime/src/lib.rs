//! Runtime boundary traits for wiring verified core decisions to egress.
//!
//! This crate intentionally contains no Linux, bwrap, TUN, or smoltcp code yet.
//! Those integrations should implement these traits so policy/audit decisions
//! remain mandatory before host egress is attempted.

#![forbid(unsafe_code)]

use foxprox_core::{
    classify_udp, parse_dns_query, parse_http_proxy_request_line, parse_http_request,
    parse_ip_packet, parse_socks5_connect, parse_tls_client_hello_sni,
    synthesize_icmpv4_echo_reply, synthesize_udpv4_response, validate_policy_config,
    AttributionConfidence, AttributionSource, AuditSink, ConfigError, Decision, DecisionAction,
    DecisionReason, DnsCache, DnsParseError, Endpoint, FlowKey, FlowTable, FrontendKind,
    HostnameAttribution, HttpProxyRequestLine, HttpRequestMetadata, InspectError, NormalizedEvent,
    PacketError, ParsedIpPacket, PolicyEngine, Protocol, ProxyParseError, QuicStatus, SandboxId,
    SniStatus, SocksDestination, StaticDnsRecord, StaticDnsResolver, Tcpv4Segment, UdpFlow,
    Udpv4Packet, UnsupportedIpv4Protocol, VerificationKernel,
};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpConnectRequest {
    pub frontend: FrontendKind,
    pub destination: Endpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagramRequest {
    pub frontend: FrontendKind,
    pub destination: Endpoint,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressError {
    ConnectFailed,
    SendFailed,
    UnsupportedProtocol,
}

pub trait HostEgress {
    fn open_tcp(&mut self, request: TcpConnectRequest) -> Result<(), EgressError>;
    fn send_udp(&mut self, request: UdpDatagramRequest) -> Result<(), EgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StdHostEgress {
    tcp_connect_timeout: Duration,
}

impl StdHostEgress {
    pub fn new(tcp_connect_timeout: Duration) -> Self {
        Self {
            tcp_connect_timeout,
        }
    }
}

impl Default for StdHostEgress {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

impl HostEgress for StdHostEgress {
    fn open_tcp(&mut self, request: TcpConnectRequest) -> Result<(), EgressError> {
        TcpStream::connect_timeout(
            &endpoint_to_socket_addr(&request.destination),
            self.tcp_connect_timeout,
        )
        .map(|_| ())
        .map_err(|_| EgressError::ConnectFailed)
    }

    fn send_udp(&mut self, request: UdpDatagramRequest) -> Result<(), EgressError> {
        let socket = UdpSocket::bind(unspecified_socket_addr_for(request.destination.ip))
            .map_err(|_| EgressError::SendFailed)?;
        let bytes_sent = socket
            .send_to(
                &request.bytes,
                endpoint_to_socket_addr(&request.destination),
            )
            .map_err(|_| EgressError::SendFailed)?;
        if bytes_sent == request.bytes.len() {
            Ok(())
        } else {
            Err(EgressError::SendFailed)
        }
    }
}

fn endpoint_to_socket_addr(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::new(endpoint.ip, endpoint.port)
}

fn unspecified_socket_addr_for(destination: IpAddr) -> SocketAddr {
    match destination {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpStackConnectAttempt {
    pub source: Endpoint,
    pub destination: Endpoint,
}

pub trait TcpStackAdapter {
    fn next_connect_attempt(&mut self) -> Option<TcpStackConnectAttempt>;
    fn reset_connect(&mut self, attempt: &TcpStackConnectAttempt);
    fn mark_connect_opened(&mut self, attempt: &TcpStackConnectAttempt);
}

pub struct TcpStackRuntime<A, E, S> {
    stack: A,
    egress: E,
    kernel: VerificationKernel<S>,
    sandbox_id: SandboxId,
}

impl<A, E, S> TcpStackRuntime<A, E, S> {
    pub fn new(stack: A, egress: E, kernel: VerificationKernel<S>, sandbox_id: SandboxId) -> Self {
        Self {
            stack,
            egress,
            kernel,
            sandbox_id,
        }
    }

    pub fn stack(&self) -> &A {
        &self.stack
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (A, E, VerificationKernel<S>) {
        (self.stack, self.egress, self.kernel)
    }
}

impl<A: TcpStackAdapter, E: HostEgress, S: AuditSink> TcpStackRuntime<A, E, S> {
    pub fn handle_next_connect(&mut self, timestamp_millis: u128) -> Option<TcpStackOutcome> {
        let attempt = self.stack.next_connect_attempt()?;
        let event = NormalizedEvent::TcpConnectAttempt {
            sandbox_id: self.sandbox_id.clone(),
            frontend: FrontendKind::Tun,
            source: Some(attempt.source.clone()),
            destination: attempt.destination.clone(),
            hostname: None,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
        };
        let decision = self.kernel.decide_and_audit(&event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            self.stack.reset_connect(&attempt);
            return Some(TcpStackOutcome::DeniedReset { decision, attempt });
        }
        match self.egress.open_tcp(TcpConnectRequest {
            frontend: FrontendKind::Tun,
            destination: attempt.destination.clone(),
        }) {
            Ok(()) => {
                self.stack.mark_connect_opened(&attempt);
                Some(TcpStackOutcome::HostConnectOpened { decision, attempt })
            }
            Err(error) => {
                self.stack.reset_connect(&attempt);
                Some(TcpStackOutcome::HostConnectFailed {
                    decision,
                    attempt,
                    error,
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpStackOutcome {
    DeniedReset {
        decision: Decision,
        attempt: TcpStackConnectAttempt,
    },
    HostConnectOpened {
        decision: Decision,
        attempt: TcpStackConnectAttempt,
    },
    HostConnectFailed {
        decision: Decision,
        attempt: TcpStackConnectAttempt,
        error: EgressError,
    },
}

pub struct HttpProxyRuntime<E, S> {
    egress: E,
    kernel: VerificationKernel<S>,
    sandbox_id: SandboxId,
}

impl<E, S> HttpProxyRuntime<E, S> {
    pub fn new(egress: E, kernel: VerificationKernel<S>, sandbox_id: SandboxId) -> Self {
        Self {
            egress,
            kernel,
            sandbox_id,
        }
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn kernel(&self) -> &VerificationKernel<S> {
        &self.kernel
    }

    pub fn into_parts(self) -> (E, VerificationKernel<S>) {
        (self.egress, self.kernel)
    }
}

impl<E: HostEgress, S: AuditSink> HttpProxyRuntime<E, S> {
    pub fn handle_request_line(
        &mut self,
        line: &str,
        resolved_ip: IpAddr,
        timestamp_millis: u128,
    ) -> Result<HttpProxyOutcome, ProxyParseError> {
        let parsed = parse_http_proxy_request_line(line)?;
        let (event, destination) =
            http_proxy_line_to_event_and_destination(self.sandbox_id.clone(), parsed, resolved_ip);
        let decision = self.kernel.decide_and_audit(&event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            return Ok(HttpProxyOutcome::Denied { decision, event });
        }
        match self.egress.open_tcp(TcpConnectRequest {
            frontend: FrontendKind::HttpProxy,
            destination,
        }) {
            Ok(()) => Ok(HttpProxyOutcome::HostConnectOpened { decision, event }),
            Err(error) => Ok(HttpProxyOutcome::HostConnectFailed {
                decision,
                event,
                error,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpProxyOutcome {
    Denied {
        decision: Decision,
        event: NormalizedEvent,
    },
    HostConnectOpened {
        decision: Decision,
        event: NormalizedEvent,
    },
    HostConnectFailed {
        decision: Decision,
        event: NormalizedEvent,
        error: EgressError,
    },
}

fn http_proxy_line_to_event_and_destination(
    sandbox_id: SandboxId,
    parsed: HttpProxyRequestLine,
    resolved_ip: IpAddr,
) -> (NormalizedEvent, Endpoint) {
    match parsed {
        HttpProxyRequestLine::PlainHttp {
            method,
            origin,
            path_query,
        } => {
            let destination = Endpoint::new(resolved_ip, origin.port);
            (
                NormalizedEvent::HttpRequest {
                    sandbox_id,
                    frontend: FrontendKind::HttpProxy,
                    source: None,
                    destination: Some(destination.clone()),
                    metadata: HttpRequestMetadata {
                        method,
                        host: origin.host,
                        port: origin.port,
                        path_query,
                        scheme: origin.scheme,
                    },
                },
                destination,
            )
        }
        HttpProxyRequestLine::Connect { origin } => {
            let destination = Endpoint::new(resolved_ip, origin.port);
            (
                NormalizedEvent::HttpsConnect {
                    sandbox_id,
                    frontend: FrontendKind::HttpProxy,
                    hostname: HostnameAttribution::explicit_proxy(origin.host),
                    port: origin.port,
                },
                destination,
            )
        }
    }
}

pub struct SocksRuntime<E, S> {
    egress: E,
    kernel: VerificationKernel<S>,
    sandbox_id: SandboxId,
}

impl<E, S> SocksRuntime<E, S> {
    pub fn new(egress: E, kernel: VerificationKernel<S>, sandbox_id: SandboxId) -> Self {
        Self {
            egress,
            kernel,
            sandbox_id,
        }
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn kernel(&self) -> &VerificationKernel<S> {
        &self.kernel
    }
}

impl<E: HostEgress, S: AuditSink> SocksRuntime<E, S> {
    pub fn handle_connect_request(
        &mut self,
        bytes: &[u8],
        resolved_ip: Option<IpAddr>,
        timestamp_millis: u128,
    ) -> Result<SocksOutcome, SocksRuntimeError> {
        let request = parse_socks5_connect(bytes).map_err(SocksRuntimeError::Parse)?;
        let (event, destination) = socks_connect_to_event_and_destination(
            self.sandbox_id.clone(),
            request.destination,
            resolved_ip,
        )?;
        let decision = self.kernel.decide_and_audit(&event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            return Ok(SocksOutcome::Denied { decision, event });
        }
        match self.egress.open_tcp(TcpConnectRequest {
            frontend: FrontendKind::Socks5,
            destination,
        }) {
            Ok(()) => Ok(SocksOutcome::HostConnectOpened { decision, event }),
            Err(error) => Ok(SocksOutcome::HostConnectFailed {
                decision,
                event,
                error,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksRuntimeError {
    Parse(ProxyParseError),
    MissingResolvedIp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksOutcome {
    Denied {
        decision: Decision,
        event: NormalizedEvent,
    },
    HostConnectOpened {
        decision: Decision,
        event: NormalizedEvent,
    },
    HostConnectFailed {
        decision: Decision,
        event: NormalizedEvent,
        error: EgressError,
    },
}

fn socks_connect_to_event_and_destination(
    sandbox_id: SandboxId,
    destination: SocksDestination,
    resolved_ip: Option<IpAddr>,
) -> Result<(NormalizedEvent, Endpoint), SocksRuntimeError> {
    match destination {
        SocksDestination::Ip(endpoint) => Ok((
            NormalizedEvent::SocksConnect {
                sandbox_id,
                hostname: None,
                destination: Some(endpoint.clone()),
                port: endpoint.port,
            },
            endpoint,
        )),
        SocksDestination::Host { host, port } => {
            let endpoint = Endpoint::new(
                resolved_ip.ok_or(SocksRuntimeError::MissingResolvedIp)?,
                port,
            );
            Ok((
                NormalizedEvent::SocksConnect {
                    sandbox_id,
                    hostname: Some(HostnameAttribution::explicit_proxy(host)),
                    destination: Some(endpoint.clone()),
                    port,
                },
                endpoint,
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpResponseRouteError {
    NonUdpFlow,
    UnsupportedAddressFamily,
}

pub fn synthesize_tun_udp_response(
    flow: &FlowKey,
    payload: &[u8],
) -> Result<Vec<u8>, UdpResponseRouteError> {
    if flow.protocol != Protocol::Udp {
        return Err(UdpResponseRouteError::NonUdpFlow);
    }
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (flow.source.ip, flow.destination.ip)
    else {
        return Err(UdpResponseRouteError::UnsupportedAddressFamily);
    };
    let packet = Udpv4Packet {
        source,
        destination,
        source_port: flow.source.port,
        destination_port: flow.destination.port,
        payload: &[],
    };
    Ok(synthesize_udpv4_response(&packet, payload))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOutcome {
    Denied {
        decision: Decision,
    },
    EgressOpened {
        decision: Decision,
    },
    EgressFailed {
        decision: Decision,
        error: EgressError,
    },
    NotAnEgressEvent {
        decision: Decision,
    },
}

pub struct BrokerRuntime<E, S> {
    egress: E,
    kernel: VerificationKernel<S>,
}

impl<E, S> BrokerRuntime<E, S> {
    pub fn new(egress: E, kernel: VerificationKernel<S>) -> Self {
        Self { egress, kernel }
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (E, VerificationKernel<S>) {
        (self.egress, self.kernel)
    }
}

impl<E: HostEgress, S: AuditSink> BrokerRuntime<E, S> {
    pub fn handle_event(
        &mut self,
        event: &NormalizedEvent,
        timestamp_millis: u128,
    ) -> RuntimeOutcome {
        let decision = self.kernel.decide_and_audit(event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            return RuntimeOutcome::Denied { decision };
        }
        match event_to_egress(event) {
            Some(EgressRequest::Tcp(request)) => match self.egress.open_tcp(request) {
                Ok(()) => RuntimeOutcome::EgressOpened { decision },
                Err(error) => RuntimeOutcome::EgressFailed { decision, error },
            },
            None => RuntimeOutcome::NotAnEgressEvent { decision },
        }
    }

    pub fn handle_udp_datagram_event(
        &mut self,
        event: &NormalizedEvent,
        bytes: Vec<u8>,
        timestamp_millis: u128,
    ) -> RuntimeOutcome {
        let decision = self.kernel.decide_and_audit(event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            return RuntimeOutcome::Denied { decision };
        }
        let NormalizedEvent::UdpFlowAttempt {
            frontend,
            destination,
            ..
        } = event
        else {
            return RuntimeOutcome::NotAnEgressEvent { decision };
        };
        match self.egress.send_udp(UdpDatagramRequest {
            frontend: *frontend,
            destination: destination.clone(),
            bytes,
        }) {
            Ok(()) => RuntimeOutcome::EgressOpened { decision },
            Err(error) => RuntimeOutcome::EgressFailed { decision, error },
        }
    }
}

enum EgressRequest {
    Tcp(TcpConnectRequest),
}

fn event_to_egress(event: &NormalizedEvent) -> Option<EgressRequest> {
    match event {
        NormalizedEvent::TcpConnectAttempt {
            frontend,
            destination,
            ..
        } => Some(EgressRequest::Tcp(TcpConnectRequest {
            frontend: *frontend,
            destination: destination.clone(),
        })),
        NormalizedEvent::UdpFlowAttempt { .. } => None,
        NormalizedEvent::HttpsConnect { frontend, port, .. } => {
            Some(EgressRequest::Tcp(TcpConnectRequest {
                frontend: *frontend,
                destination: Endpoint::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    *port,
                ),
            }))
        }
        NormalizedEvent::SocksConnect {
            destination: Some(destination),
            ..
        } => Some(EgressRequest::Tcp(TcpConnectRequest {
            frontend: FrontendKind::Socks5,
            destination: destination.clone(),
        })),
        NormalizedEvent::DnsQuery { .. }
        | NormalizedEvent::DnsPacketAttempt { .. }
        | NormalizedEvent::HttpRequest { .. }
        | NormalizedEvent::IcmpMessage { .. }
        | NormalizedEvent::MalformedNetworkEvent { .. }
        | NormalizedEvent::UnsupportedNetworkEvent { .. }
        | NormalizedEvent::SocksConnect { .. } => None,
    }
}

pub fn event_protocol(event: &NormalizedEvent) -> Protocol {
    event.to_policy_input().protocol
}

pub struct TunIcmpProofSession<T> {
    device: T,
    buffer: Vec<u8>,
}

impl<T> TunIcmpProofSession<T> {
    pub fn new(device: T, mtu: usize) -> Self {
        Self {
            device,
            buffer: vec![0; mtu],
        }
    }

    pub fn into_inner(self) -> T {
        self.device
    }
}

impl<T: Read + Write> TunIcmpProofSession<T> {
    pub fn run_once(&mut self) -> io::Result<TunPacketOutcome> {
        let bytes_read = self.device.read(&mut self.buffer)?;
        let packet = &self.buffer[..bytes_read];
        match tun_packet_reply(packet) {
            Ok(Some(reply)) => {
                self.device.write_all(&reply)?;
                Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
            }
            Ok(None) => unsupported_or_malformed_outcome(packet),
            Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
        }
    }
}

pub struct TunUdpEgressSession<T, E, S> {
    device: T,
    egress: E,
    kernel: VerificationKernel<S>,
    flow_table: FlowTable,
    sandbox_id: SandboxId,
    broker_dns: Vec<IpAddr>,
    buffer: Vec<u8>,
}

impl<T, E, S> TunUdpEgressSession<T, E, S> {
    pub fn new(
        device: T,
        egress: E,
        kernel: VerificationKernel<S>,
        sandbox_id: SandboxId,
        broker_dns: Vec<IpAddr>,
        mtu: usize,
    ) -> Self {
        Self {
            device,
            egress,
            kernel,
            flow_table: FlowTable::new(),
            sandbox_id,
            broker_dns,
            buffer: vec![0; mtu],
        }
    }

    pub fn flow_table(&self) -> &FlowTable {
        &self.flow_table
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (T, E, VerificationKernel<S>, FlowTable) {
        (self.device, self.egress, self.kernel, self.flow_table)
    }
}

impl<T: Read + Write, E: HostEgress, S: AuditSink> TunUdpEgressSession<T, E, S> {
    pub fn run_once(&mut self, timestamp_millis: u128) -> io::Result<TunUdpSessionOutcome> {
        let bytes_read = self.device.read(&mut self.buffer)?;
        let packet = &self.buffer[..bytes_read];
        let udp = match parse_ip_packet(packet) {
            Ok(ParsedIpPacket::Udpv4Packet(udp)) => udp,
            Ok(ParsedIpPacket::Tcpv4Segment(_)) => {
                return Ok(TunUdpSessionOutcome::NotUdp);
            }
            Ok(ParsedIpPacket::Icmpv4EchoRequest(_)) => {
                return Ok(TunUdpSessionOutcome::NotUdp);
            }
            Ok(ParsedIpPacket::UnsupportedIpv4Protocol(unsupported)) => {
                return Ok(TunUdpSessionOutcome::DroppedUnsupportedIpv4 {
                    source: IpAddr::V4(unsupported.source),
                    destination: IpAddr::V4(unsupported.destination),
                    protocol: unsupported.protocol,
                });
            }
            Err(error) => return Ok(TunUdpSessionOutcome::DroppedMalformed { error }),
        };
        let flow = record_udpv4_flow(
            &mut self.flow_table,
            &udp,
            &self.broker_dns,
            timestamp_millis,
        );
        let flow_key = flow.key.clone();
        let event =
            udpv4_packet_to_event_with_broker_dns(self.sandbox_id.clone(), &udp, &self.broker_dns);
        let decision = self.kernel.decide_and_audit(&event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            return Ok(TunUdpSessionOutcome::PolicyDenied { decision });
        }
        match self.egress.send_udp(UdpDatagramRequest {
            frontend: FrontendKind::Tun,
            destination: flow_key.destination.clone(),
            bytes: udp.payload.to_vec(),
        }) {
            Ok(()) => Ok(TunUdpSessionOutcome::EgressSent {
                decision,
                flow: flow_key,
            }),
            Err(error) => Ok(TunUdpSessionOutcome::EgressFailed {
                decision,
                flow: flow_key,
                error,
            }),
        }
    }

    pub fn write_host_udp_reply(
        &mut self,
        flow: &FlowKey,
        payload: &[u8],
    ) -> io::Result<Result<usize, UdpResponseRouteError>> {
        match synthesize_tun_udp_response(flow, payload) {
            Ok(packet) => {
                self.device.write_all(&packet)?;
                Ok(Ok(packet.len()))
            }
            Err(error) => Ok(Err(error)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunUdpSessionOutcome {
    EgressSent {
        decision: Decision,
        flow: FlowKey,
    },
    EgressFailed {
        decision: Decision,
        flow: FlowKey,
        error: EgressError,
    },
    PolicyDenied {
        decision: Decision,
    },
    DroppedMalformed {
        error: PacketError,
    },
    DroppedUnsupportedIpv4 {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
    },
    NotUdp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunPacketOutcome {
    EchoReplyWritten {
        bytes: usize,
    },
    DroppedMalformed {
        error: PacketError,
    },
    DroppedMalformedDns,
    DroppedUnsupportedIpv4 {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
    },
    UdpObserved {
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
        payload_len: usize,
    },
    TcpConnectObserved {
        decision: Decision,
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
    },
    DnsResponseWritten {
        bytes: usize,
        cached: bool,
    },
    PolicyDenied {
        decision: Decision,
    },
}

pub fn handle_one_tun_packet<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    match tun_packet_reply(packet) {
        Ok(Some(reply)) => {
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(None) => unsupported_or_malformed_outcome(packet),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRuntimeConfig {
    pub sandbox_id: SandboxId,
    pub policy: foxprox_core::PolicyConfig,
    pub static_dns_ttl_secs: u32,
    pub static_dns_records: Vec<StaticDnsRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeConfigError {
    InvalidPolicy(ConfigError),
    ZeroDnsTtl,
}

pub struct BrokerRuntimeComponents {
    pub sandbox_id: SandboxId,
    pub policy_engine: PolicyEngine,
    pub resolver: StaticDnsResolver,
    pub cache: DnsCache,
    pub broker_dns: Vec<IpAddr>,
}

pub fn build_runtime_components(
    config: BrokerRuntimeConfig,
) -> Result<BrokerRuntimeComponents, RuntimeConfigError> {
    validate_policy_config(&config.policy).map_err(RuntimeConfigError::InvalidPolicy)?;
    if config.static_dns_ttl_secs == 0 {
        return Err(RuntimeConfigError::ZeroDnsTtl);
    }
    let broker_dns = config.policy.broker_dns.clone();
    let mut resolver = StaticDnsResolver::new(config.static_dns_ttl_secs);
    for record in config.static_dns_records {
        resolver.insert(record.hostname, record.addresses);
    }
    Ok(BrokerRuntimeComponents {
        sandbox_id: config.sandbox_id,
        policy_engine: PolicyEngine::new(config.policy),
        resolver,
        cache: DnsCache::new(),
        broker_dns,
    })
}

pub struct BrokerDnsRuntime<'a, S> {
    pub sandbox_id: SandboxId,
    pub resolver: &'a StaticDnsResolver,
    pub cache: &'a mut DnsCache,
    pub broker_dns: &'a [IpAddr],
    pub kernel: &'a mut VerificationKernel<S>,
}

pub struct TunBrokerSession<T, S> {
    device: T,
    sandbox_id: SandboxId,
    resolver: StaticDnsResolver,
    cache: DnsCache,
    broker_dns: Vec<IpAddr>,
    kernel: VerificationKernel<S>,
    buffer: Vec<u8>,
}

impl<T, S> TunBrokerSession<T, S> {
    pub fn new(device: T, components: BrokerRuntimeComponents, audit_sink: S, mtu: usize) -> Self {
        Self {
            device,
            sandbox_id: components.sandbox_id,
            resolver: components.resolver,
            cache: components.cache,
            broker_dns: components.broker_dns,
            kernel: VerificationKernel::new(components.policy_engine, audit_sink),
            buffer: vec![0; mtu],
        }
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    pub fn kernel(&self) -> &VerificationKernel<S> {
        &self.kernel
    }

    pub fn into_parts(self) -> (T, DnsCache, VerificationKernel<S>) {
        (self.device, self.cache, self.kernel)
    }
}

impl<T: Read + Write, S: AuditSink> TunBrokerSession<T, S> {
    pub fn run_once(&mut self, timestamp_millis: u128) -> io::Result<TunPacketOutcome> {
        let bytes_read = self.device.read(&mut self.buffer)?;
        let packet = &self.buffer[..bytes_read];
        let mut runtime = BrokerDnsRuntime {
            sandbox_id: self.sandbox_id.clone(),
            resolver: &self.resolver,
            cache: &mut self.cache,
            broker_dns: &self.broker_dns,
            kernel: &mut self.kernel,
        };
        handle_tun_packet_with_policy(packet, &mut self.device, &mut runtime, timestamp_millis)
    }
}

pub fn handle_one_tun_packet_with_policy<R: Read, W: Write, S: AuditSink>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    runtime: &mut BrokerDnsRuntime<'_, S>,
    timestamp_millis: u128,
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    handle_tun_packet_with_policy(&buffer[..bytes_read], writer, runtime, timestamp_millis)
}

fn handle_tun_packet_with_policy<W: Write, S: AuditSink>(
    packet: &[u8],
    writer: &mut W,
    runtime: &mut BrokerDnsRuntime<'_, S>,
    timestamp_millis: u128,
) -> io::Result<TunPacketOutcome> {
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Icmpv4EchoRequest(request)) => {
            let event = NormalizedEvent::IcmpMessage {
                sandbox_id: runtime.sandbox_id.clone(),
                frontend: FrontendKind::Tun,
                source: Endpoint::new(IpAddr::V4(request.source), 0),
                destination: Endpoint::new(IpAddr::V4(request.destination), 0),
            };
            let decision = runtime.kernel.decide_and_audit(&event, timestamp_millis);
            if decision.action != DecisionAction::Allow {
                return Ok(TunPacketOutcome::PolicyDenied { decision });
            }
            let reply = synthesize_icmpv4_echo_reply(&request);
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(ParsedIpPacket::Tcpv4Segment(tcp)) => {
            let mut event = tcpv4_segment_to_event(runtime.sandbox_id.clone(), &tcp);
            enrich_event_with_dns_cache(&mut event, runtime.cache, timestamp_millis);
            let decision = runtime.kernel.decide_and_audit(&event, timestamp_millis);
            Ok(TunPacketOutcome::TcpConnectObserved {
                decision,
                source: IpAddr::V4(tcp.source),
                destination: IpAddr::V4(tcp.destination),
                source_port: tcp.source_port,
                destination_port: tcp.destination_port,
            })
        }
        Ok(ParsedIpPacket::Udpv4Packet(udp)) => {
            let mut event = udpv4_packet_to_event_with_broker_dns(
                runtime.sandbox_id.clone(),
                &udp,
                runtime.broker_dns,
            );
            enrich_event_with_dns_cache(&mut event, runtime.cache, timestamp_millis);
            let decision = runtime.kernel.decide_and_audit(&event, timestamp_millis);
            if decision.action != DecisionAction::Allow {
                return Ok(TunPacketOutcome::PolicyDenied { decision });
            }
            if matches!(event, NormalizedEvent::DnsQuery { .. }) {
                return match handle_broker_dns_udp_packet(
                    &udp,
                    runtime.resolver,
                    runtime.cache,
                    timestamp_millis,
                ) {
                    Ok(response) => {
                        writer.write_all(&response.packet)?;
                        Ok(TunPacketOutcome::DnsResponseWritten {
                            bytes: response.packet.len(),
                            cached: response.cached,
                        })
                    }
                    Err(_) => Ok(TunPacketOutcome::DroppedMalformedDns),
                };
            }
            Ok(TunPacketOutcome::UdpObserved {
                source: IpAddr::V4(udp.source),
                destination: IpAddr::V4(udp.destination),
                source_port: udp.source_port,
                destination_port: udp.destination_port,
                payload_len: udp.payload.len(),
            })
        }
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(unsupported)) => {
            let event = NormalizedEvent::UnsupportedNetworkEvent {
                sandbox_id: runtime.sandbox_id.clone(),
                frontend: FrontendKind::Tun,
                protocol: Protocol::Unsupported(unsupported.protocol),
            };
            let decision = runtime.kernel.decide_and_audit(&event, timestamp_millis);
            Ok(TunPacketOutcome::PolicyDenied { decision })
        }
        Err(_) => {
            let event = NormalizedEvent::MalformedNetworkEvent {
                sandbox_id: runtime.sandbox_id.clone(),
                frontend: FrontendKind::Tun,
                protocol: Protocol::Unsupported(0),
            };
            let decision = runtime.kernel.decide_and_audit(&event, timestamp_millis);
            Ok(TunPacketOutcome::PolicyDenied { decision })
        }
    }
}

pub fn handle_one_tun_packet_with_icmp_policy<R: Read, W: Write, S: AuditSink>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    sandbox_id: SandboxId,
    kernel: &mut VerificationKernel<S>,
    timestamp_millis: u128,
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Icmpv4EchoRequest(request)) => {
            let event = NormalizedEvent::IcmpMessage {
                sandbox_id,
                frontend: FrontendKind::Tun,
                source: Endpoint::new(IpAddr::V4(request.source), 0),
                destination: Endpoint::new(IpAddr::V4(request.destination), 0),
            };
            let decision = kernel.decide_and_audit(&event, timestamp_millis);
            if decision.action != DecisionAction::Allow {
                return Ok(TunPacketOutcome::PolicyDenied { decision });
            }
            let reply = synthesize_icmpv4_echo_reply(&request);
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(ParsedIpPacket::Tcpv4Segment(tcp)) => Ok(TunPacketOutcome::TcpConnectObserved {
            decision: Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::UnsupportedProtocol,
            ),
            source: IpAddr::V4(tcp.source),
            destination: IpAddr::V4(tcp.destination),
            source_port: tcp.source_port,
            destination_port: tcp.destination_port,
        }),
        Ok(ParsedIpPacket::Udpv4Packet(udp)) => Ok(TunPacketOutcome::UdpObserved {
            source: IpAddr::V4(udp.source),
            destination: IpAddr::V4(udp.destination),
            source_port: udp.source_port,
            destination_port: udp.destination_port,
            payload_len: udp.payload.len(),
        }),
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(_)) => unsupported_or_malformed_outcome(packet),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

pub fn handle_one_tun_packet_with_dns_policy<R: Read, W: Write, S: AuditSink>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    dns: &mut BrokerDnsRuntime<'_, S>,
    timestamp_millis: u128,
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Tcpv4Segment(tcp)) => Ok(TunPacketOutcome::TcpConnectObserved {
            decision: Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::UnsupportedProtocol,
            ),
            source: IpAddr::V4(tcp.source),
            destination: IpAddr::V4(tcp.destination),
            source_port: tcp.source_port,
            destination_port: tcp.destination_port,
        }),
        Ok(ParsedIpPacket::Udpv4Packet(udp)) if udp.destination_port == 53 => {
            let event =
                udpv4_packet_to_event_with_broker_dns(dns.sandbox_id.clone(), &udp, dns.broker_dns);
            let decision = dns.kernel.decide_and_audit(&event, timestamp_millis);
            if decision.action != DecisionAction::Allow {
                return Ok(TunPacketOutcome::PolicyDenied { decision });
            }
            if matches!(event, NormalizedEvent::DnsQuery { .. }) {
                return match handle_broker_dns_udp_packet(
                    &udp,
                    dns.resolver,
                    dns.cache,
                    timestamp_millis,
                ) {
                    Ok(response) => {
                        writer.write_all(&response.packet)?;
                        Ok(TunPacketOutcome::DnsResponseWritten {
                            bytes: response.packet.len(),
                            cached: response.cached,
                        })
                    }
                    Err(_) => Ok(TunPacketOutcome::DroppedMalformedDns),
                };
            }
            Ok(TunPacketOutcome::UdpObserved {
                source: IpAddr::V4(udp.source),
                destination: IpAddr::V4(udp.destination),
                source_port: udp.source_port,
                destination_port: udp.destination_port,
                payload_len: udp.payload.len(),
            })
        }
        Ok(ParsedIpPacket::Udpv4Packet(udp)) => Ok(TunPacketOutcome::UdpObserved {
            source: IpAddr::V4(udp.source),
            destination: IpAddr::V4(udp.destination),
            source_port: udp.source_port,
            destination_port: udp.destination_port,
            payload_len: udp.payload.len(),
        }),
        Ok(ParsedIpPacket::Icmpv4EchoRequest(request)) => {
            let reply = synthesize_icmpv4_echo_reply(&request);
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(_)) => unsupported_or_malformed_outcome(packet),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

pub fn handle_one_tun_packet_with_dns<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    resolver: &StaticDnsResolver,
    cache: &mut DnsCache,
    broker_dns: &[IpAddr],
    now_millis: u128,
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Tcpv4Segment(tcp)) => Ok(TunPacketOutcome::TcpConnectObserved {
            decision: Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::UnsupportedProtocol,
            ),
            source: IpAddr::V4(tcp.source),
            destination: IpAddr::V4(tcp.destination),
            source_port: tcp.source_port,
            destination_port: tcp.destination_port,
        }),
        Ok(ParsedIpPacket::Udpv4Packet(udp)) => {
            let destination = IpAddr::V4(udp.destination);
            if udp.destination_port == 53 && broker_dns.contains(&destination) {
                return match handle_broker_dns_udp_packet(&udp, resolver, cache, now_millis) {
                    Ok(response) => {
                        writer.write_all(&response.packet)?;
                        Ok(TunPacketOutcome::DnsResponseWritten {
                            bytes: response.packet.len(),
                            cached: response.cached,
                        })
                    }
                    Err(_) => Ok(TunPacketOutcome::DroppedMalformedDns),
                };
            }
            unsupported_or_malformed_outcome(packet)
        }
        Ok(ParsedIpPacket::Icmpv4EchoRequest(request)) => {
            let reply = synthesize_icmpv4_echo_reply(&request);
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(_)) => unsupported_or_malformed_outcome(packet),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

fn unsupported_or_malformed_outcome(packet: &[u8]) -> io::Result<TunPacketOutcome> {
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Tcpv4Segment(tcp)) => Ok(TunPacketOutcome::TcpConnectObserved {
            decision: Decision::denied(
                DecisionAction::FailClosed,
                DecisionReason::UnsupportedProtocol,
            ),
            source: IpAddr::V4(tcp.source),
            destination: IpAddr::V4(tcp.destination),
            source_port: tcp.source_port,
            destination_port: tcp.destination_port,
        }),
        Ok(ParsedIpPacket::Udpv4Packet(Udpv4Packet {
            source,
            destination,
            source_port,
            destination_port,
            payload,
        })) => Ok(TunPacketOutcome::UdpObserved {
            source: IpAddr::V4(source),
            destination: IpAddr::V4(destination),
            source_port,
            destination_port,
            payload_len: payload.len(),
        }),
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(UnsupportedIpv4Protocol {
            source,
            destination,
            protocol,
            ..
        })) => Ok(TunPacketOutcome::DroppedUnsupportedIpv4 {
            source: IpAddr::V4(source),
            destination: IpAddr::V4(destination),
            protocol,
        }),
        Ok(ParsedIpPacket::Icmpv4EchoRequest(_)) => unreachable!("echo requests produce replies"),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerDnsUdpResponse {
    pub packet: Vec<u8>,
    pub cached: bool,
}

pub fn handle_broker_dns_udp_packet(
    packet: &Udpv4Packet<'_>,
    resolver: &StaticDnsResolver,
    cache: &mut DnsCache,
    now_millis: u128,
) -> Result<BrokerDnsUdpResponse, DnsParseError> {
    let dns_response = resolver.resolve_query_packet(packet.payload, now_millis)?;
    let cached = if let Some(observation) = dns_response.observation {
        cache.record(observation);
        true
    } else {
        false
    };
    Ok(BrokerDnsUdpResponse {
        packet: synthesize_udpv4_response(packet, &dns_response.packet),
        cached,
    })
}

pub fn record_udpv4_flow(
    table: &mut FlowTable,
    packet: &Udpv4Packet<'_>,
    broker_dns: &[IpAddr],
    now_millis: u128,
) -> UdpFlow {
    let source = Endpoint::new(IpAddr::V4(packet.source), packet.source_port);
    let destination = Endpoint::new(IpAddr::V4(packet.destination), packet.destination_port);
    let class = classify_udp(&destination, broker_dns);
    let key = FlowKey::new(Protocol::Udp, source, destination);
    table
        .upsert_udp(key, class, now_millis, (8 + packet.payload.len()) as u64)
        .clone()
}

pub fn tcpv4_segment_to_event(
    sandbox_id: SandboxId,
    segment: &Tcpv4Segment<'_>,
) -> NormalizedEvent {
    if !segment.is_connect_attempt() {
        return NormalizedEvent::UnsupportedNetworkEvent {
            sandbox_id,
            frontend: FrontendKind::Tun,
            protocol: Protocol::Tcp,
        };
    }
    NormalizedEvent::TcpConnectAttempt {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source: Some(Endpoint::new(
            IpAddr::V4(segment.source),
            segment.source_port,
        )),
        destination: Endpoint::new(IpAddr::V4(segment.destination), segment.destination_port),
        hostname: None,
        sni_status: SniStatus::Missing,
        sni_dns_mismatch: false,
    }
}

pub fn tcpv4_tls_client_hello_to_event(
    sandbox_id: SandboxId,
    segment: &Tcpv4Segment<'_>,
) -> Result<NormalizedEvent, InspectError> {
    tcpv4_tls_client_hello_to_event_with_dns_attribution(sandbox_id, segment, None)
}

pub fn tcpv4_tls_client_hello_to_event_with_dns_attribution(
    sandbox_id: SandboxId,
    segment: &Tcpv4Segment<'_>,
    dns_attribution: Option<HostnameAttribution>,
) -> Result<NormalizedEvent, InspectError> {
    let hello = parse_tls_client_hello_sni(segment.payload)?;
    let sni_dns_mismatch = dns_attribution
        .as_ref()
        .is_some_and(|dns| dns.hostname != hello.sni);
    Ok(NormalizedEvent::TcpConnectAttempt {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source: Some(Endpoint::new(
            IpAddr::V4(segment.source),
            segment.source_port,
        )),
        destination: Endpoint::new(IpAddr::V4(segment.destination), segment.destination_port),
        hostname: Some(HostnameAttribution::new(
            hello.sni,
            AttributionSource::TlsSni,
            AttributionConfidence::High,
        )),
        sni_status: SniStatus::Present,
        sni_dns_mismatch,
    })
}

pub fn tcpv4_tls_client_hello_without_visible_sni_to_event(
    sandbox_id: SandboxId,
    segment: &Tcpv4Segment<'_>,
    sni_status: SniStatus,
) -> NormalizedEvent {
    debug_assert_ne!(sni_status, SniStatus::Present);
    NormalizedEvent::TcpConnectAttempt {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source: Some(Endpoint::new(
            IpAddr::V4(segment.source),
            segment.source_port,
        )),
        destination: Endpoint::new(IpAddr::V4(segment.destination), segment.destination_port),
        hostname: None,
        sni_status,
        sni_dns_mismatch: false,
    }
}

pub fn tcpv4_http_request_to_event(
    sandbox_id: SandboxId,
    segment: &Tcpv4Segment<'_>,
) -> Result<NormalizedEvent, InspectError> {
    let metadata = parse_http_request(segment.payload)?;
    Ok(NormalizedEvent::HttpRequest {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source: Some(Endpoint::new(
            IpAddr::V4(segment.source),
            segment.source_port,
        )),
        destination: Some(Endpoint::new(
            IpAddr::V4(segment.destination),
            segment.destination_port,
        )),
        metadata,
    })
}

pub fn udpv4_packet_to_event(sandbox_id: SandboxId, packet: &Udpv4Packet<'_>) -> NormalizedEvent {
    udpv4_packet_to_event_with_broker_dns(sandbox_id, packet, &[])
}

pub fn udpv4_packet_to_event_with_broker_dns(
    sandbox_id: SandboxId,
    packet: &Udpv4Packet<'_>,
    broker_dns: &[IpAddr],
) -> NormalizedEvent {
    udpv4_packet_to_event_with_attribution(sandbox_id, packet, broker_dns, None)
}

pub fn udpv4_packet_to_event_with_attribution(
    sandbox_id: SandboxId,
    packet: &Udpv4Packet<'_>,
    broker_dns: &[IpAddr],
    hostname: Option<HostnameAttribution>,
) -> NormalizedEvent {
    let source = Endpoint::new(IpAddr::V4(packet.source), packet.source_port);
    let destination = Endpoint::new(IpAddr::V4(packet.destination), packet.destination_port);
    if destination.is_dns_port() {
        if broker_dns.contains(&destination.ip) {
            return match parse_dns_query(packet.payload) {
                Ok(question) => NormalizedEvent::DnsQuery {
                    sandbox_id,
                    frontend: FrontendKind::Tun,
                    source,
                    destination,
                    query: HostnameAttribution::broker_dns(question.hostname),
                },
                Err(_) => NormalizedEvent::MalformedNetworkEvent {
                    sandbox_id,
                    frontend: FrontendKind::Tun,
                    protocol: Protocol::Dns,
                },
            };
        }
        return NormalizedEvent::DnsPacketAttempt {
            sandbox_id,
            frontend: FrontendKind::Tun,
            source,
            destination,
        };
    }
    NormalizedEvent::UdpFlowAttempt {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source,
        destination: destination.clone(),
        hostname,
        quic_status: if destination.is_quic_port() {
            QuicStatus::Candidate
        } else {
            QuicStatus::NotQuic
        },
    }
}

fn enrich_event_with_dns_cache(event: &mut NormalizedEvent, cache: &DnsCache, now_millis: u128) {
    match event {
        NormalizedEvent::TcpConnectAttempt {
            destination,
            hostname,
            ..
        }
        | NormalizedEvent::UdpFlowAttempt {
            destination,
            hostname,
            ..
        } if hostname.is_none() => {
            *hostname = cache.lookup_ip(destination.ip, now_millis);
        }
        _ => {}
    }
}

fn tun_packet_reply(packet: &[u8]) -> Result<Option<Vec<u8>>, PacketError> {
    match parse_ip_packet(packet)? {
        ParsedIpPacket::Icmpv4EchoRequest(request) => {
            Ok(Some(synthesize_icmpv4_echo_reply(&request)))
        }
        ParsedIpPacket::Tcpv4Segment(_)
        | ParsedIpPacket::Udpv4Packet(_)
        | ParsedIpPacket::UnsupportedIpv4Protocol(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        DecisionAction, DecisionReason, DnsObservation, Hostname, PolicyConfig, PolicyEngine,
        PolicyRule, RuleSet, SniStatus, UdpClass, UdpTimeouts, VecAuditSink,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Default)]
    struct FakeEgress {
        tcp_attempts: usize,
        udp_attempts: usize,
        last_tcp_destination: Option<Endpoint>,
        last_udp_payload: Vec<u8>,
    }

    impl HostEgress for FakeEgress {
        fn open_tcp(&mut self, request: TcpConnectRequest) -> Result<(), EgressError> {
            self.tcp_attempts += 1;
            self.last_tcp_destination = Some(request.destination);
            Ok(())
        }

        fn send_udp(&mut self, request: UdpDatagramRequest) -> Result<(), EgressError> {
            self.udp_attempts += 1;
            self.last_udp_payload = request.bytes;
            Ok(())
        }
    }

    struct FakeTunIo {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    #[derive(Default)]
    struct FakeTcpStack {
        next: Option<TcpStackConnectAttempt>,
        resets: usize,
        opened: usize,
    }

    impl TcpStackAdapter for FakeTcpStack {
        fn next_connect_attempt(&mut self) -> Option<TcpStackConnectAttempt> {
            self.next.take()
        }

        fn reset_connect(&mut self, _attempt: &TcpStackConnectAttempt) {
            self.resets += 1;
        }

        fn mark_connect_opened(&mut self, _attempt: &TcpStackConnectAttempt) {
            self.opened += 1;
        }
    }

    impl Read for FakeTunIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for FakeTunIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn udp_event() -> NormalizedEvent {
        NormalizedEvent::UdpFlowAttempt {
            sandbox_id: SandboxId::new("runtime").unwrap(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 53000),
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            hostname: None,
            quic_status: QuicStatus::Candidate,
        }
    }

    fn tcp_event() -> NormalizedEvent {
        NormalizedEvent::TcpConnectAttempt {
            sandbox_id: SandboxId::new("runtime").unwrap(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            hostname: None,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
        }
    }

    fn tcp_stack_attempt() -> TcpStackConnectAttempt {
        TcpStackConnectAttempt {
            source: Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 53000),
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        }
    }

    #[test]
    fn tcp_stack_runtime_resets_denied_connect_before_host_egress() {
        let stack = FakeTcpStack {
            next: Some(tcp_stack_attempt()),
            ..FakeTcpStack::default()
        };
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            stack,
            FakeEgress::default(),
            kernel,
            SandboxId::new("tcp-stack-deny").unwrap(),
        );

        let outcome = runtime.handle_next_connect(100).unwrap();

        assert!(matches!(outcome, TcpStackOutcome::DeniedReset { .. }));
        assert_eq!(runtime.stack().resets, 1);
        assert_eq!(runtime.stack().opened, 0);
        assert_eq!(runtime.egress().tcp_attempts, 0);
    }

    #[test]
    fn tcp_stack_runtime_opens_host_connect_after_policy_allows() {
        let stack = FakeTcpStack {
            next: Some(tcp_stack_attempt()),
            ..FakeTcpStack::default()
        };
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-tcp-stack");
        rule.protocol = Some(Protocol::Tcp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = TcpStackRuntime::new(
            stack,
            FakeEgress::default(),
            kernel,
            SandboxId::new("tcp-stack-allow").unwrap(),
        );

        let outcome = runtime.handle_next_connect(100).unwrap();

        assert!(matches!(outcome, TcpStackOutcome::HostConnectOpened { .. }));
        assert_eq!(runtime.stack().resets, 0);
        assert_eq!(runtime.stack().opened, 1);
        assert_eq!(runtime.egress().tcp_attempts, 1);
    }

    #[test]
    fn runtime_config_builds_policy_engine_and_static_dns_resolver() {
        let mut rule = PolicyRule::allow("allow-broker-dns");
        rule.protocol = Some(Protocol::Dns);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let config = BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("configured-sandbox").unwrap(),
            policy: PolicyConfig {
                broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
                rules,
                ..PolicyConfig::default()
            },
            static_dns_ttl_secs: 30,
            static_dns_records: vec![StaticDnsRecord {
                hostname: Hostname::normalize("example.com").unwrap(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            }],
        };

        let components = build_runtime_components(config).unwrap();

        assert_eq!(components.sandbox_id.as_str(), "configured-sandbox");
        assert_eq!(
            components.broker_dns,
            vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))]
        );
        let response = components
            .resolver
            .resolve_query_packet(&dns_query_payload(), 100)
            .unwrap();
        let observation = response.observation.unwrap();
        assert_eq!(observation.hostname.as_str(), "example.com");
        assert_eq!(
            observation.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        let event = NormalizedEvent::DnsPacketAttempt {
            sandbox_id: components.sandbox_id,
            frontend: FrontendKind::Tun,
            source: Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 53000),
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)), 53),
        };
        let decision = components.policy_engine.evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::Allow);
    }

    #[test]
    fn runtime_config_rejects_invalid_policy_and_zero_dns_ttl() {
        let duplicate_rules = {
            let mut rules = RuleSet::default();
            rules.push(PolicyRule::allow("duplicate"));
            rules.push(PolicyRule::deny_drop("duplicate"));
            rules
        };
        let invalid_policy = BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("invalid-policy").unwrap(),
            policy: PolicyConfig {
                rules: duplicate_rules,
                ..PolicyConfig::default()
            },
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
        };
        assert!(matches!(
            build_runtime_components(invalid_policy),
            Err(RuntimeConfigError::InvalidPolicy(_))
        ));

        let zero_ttl = BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("zero-ttl").unwrap(),
            policy: PolicyConfig::default(),
            static_dns_ttl_secs: 0,
            static_dns_records: Vec::new(),
        };
        assert!(matches!(
            build_runtime_components(zero_ttl),
            Err(RuntimeConfigError::ZeroDnsTtl)
        ));
    }

    #[test]
    fn tun_broker_session_answers_broker_dns_and_updates_cache() {
        let mut dns_rule = PolicyRule::allow("allow-broker-dns");
        dns_rule.protocol = Some(Protocol::Dns);
        let mut rules = RuleSet::default();
        rules.push(dns_rule);
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("tun-session-dns").unwrap(),
            policy: PolicyConfig {
                broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
                rules,
                ..PolicyConfig::default()
            },
            static_dns_ttl_secs: 30,
            static_dns_records: vec![StaticDnsRecord {
                hostname: Hostname::normalize("example.com").unwrap(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            }],
        })
        .unwrap();
        let fake = FakeTunIo {
            input: std::io::Cursor::new(build_dns_udp_ipv4_packet()),
            output: Vec::new(),
        };
        let mut session = TunBrokerSession::new(fake, components, VecAuditSink::bounded(8), 1500);

        let outcome = session.run_once(100).unwrap();
        let (fake, cache, kernel) = session.into_parts();

        assert!(matches!(
            outcome,
            TunPacketOutcome::DnsResponseWritten { cached: true, .. }
        ));
        assert!(!fake.output.is_empty());
        assert!(cache
            .lookup_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 100)
            .is_some());
        assert_eq!(kernel.audit_sink().events().len(), 1);
    }

    #[test]
    fn tun_broker_session_applies_icmp_policy_with_owned_kernel() {
        let components = build_runtime_components(BrokerRuntimeConfig {
            sandbox_id: SandboxId::new("tun-session-icmp").unwrap(),
            policy: PolicyConfig {
                allow_ping: true,
                ..PolicyConfig::default()
            },
            static_dns_ttl_secs: 30,
            static_dns_records: Vec::new(),
        })
        .unwrap();
        let fake = FakeTunIo {
            input: std::io::Cursor::new(build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7])),
            output: Vec::new(),
        };
        let mut session = TunBrokerSession::new(fake, components, VecAuditSink::bounded(8), 1500);

        let outcome = session.run_once(100).unwrap();
        let (fake, _, kernel) = session.into_parts();

        assert!(matches!(outcome, TunPacketOutcome::EchoReplyWritten { .. }));
        assert!(!fake.output.is_empty());
        assert_eq!(kernel.audit_sink().events().len(), 1);
    }

    #[test]
    fn tun_tcp_policy_uses_live_dns_cache_attribution() {
        let mut rule = PolicyRule::allow("allow-cached-tcp-domain");
        rule.protocol = Some(Protocol::Tcp);
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::Medium);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut cache = DnsCache::new();
        cache.record(DnsObservation::new(
            Hostname::normalize("www.example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
            1_000,
        ));
        let resolver = StaticDnsResolver::new(30);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("cached-tcp").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[],
            kernel: &mut kernel,
        };
        let request = build_tcp_ipv4_packet(53000, 80, 0x02, &[]);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet_with_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut runtime,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::TcpConnectObserved { decision, .. }
                if decision.action == DecisionAction::Allow
                    && decision.rule_id.as_deref() == Some("allow-cached-tcp-domain")
        ));
    }

    #[test]
    fn tun_udp_policy_uses_live_dns_cache_attribution() {
        let mut rule = PolicyRule::allow("allow-cached-quic-domain");
        rule.protocol = Some(Protocol::Udp);
        rule.destination_port = Some(foxprox_core::PortMatcher::Exact(443));
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::Medium);
        rule.quic_status = Some(QuicStatus::Candidate);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let mut cache = DnsCache::new();
        cache.record(DnsObservation::new(
            Hostname::normalize("www.example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
            1_000,
        ));
        let resolver = StaticDnsResolver::new(30);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("cached-udp").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[],
            kernel: &mut kernel,
        };
        let request = build_udp_ipv4_packet(53000, 443, b"quic?");
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet_with_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut runtime,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::UdpObserved {
                destination_port: 443,
                ..
            }
        ));
        assert_eq!(
            runtime.kernel.audit_sink().events()[0].rule_id.as_deref(),
            Some("allow-cached-quic-domain")
        );
    }

    #[test]
    fn http_proxy_runtime_denies_plain_http_before_host_egress_by_default() {
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = HttpProxyRuntime::new(
            FakeEgress::default(),
            kernel,
            SandboxId::new("http-proxy-deny").unwrap(),
        );

        let outcome = runtime
            .handle_request_line(
                "GET http://www.example.com/blocked HTTP/1.1",
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                100,
            )
            .unwrap();

        assert!(matches!(outcome, HttpProxyOutcome::Denied { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 0);
        assert_eq!(runtime.kernel().audit_sink().events().len(), 1);
    }

    #[test]
    fn http_proxy_runtime_opens_plain_http_after_origin_path_policy_allows() {
        let mut rule = PolicyRule::allow("allow-http-origin-path");
        rule.protocol = Some(Protocol::Http);
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::High);
        rule.http_method = Some("GET".to_string());
        rule.http_path_prefix = Some("/allowed".to_string());
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = HttpProxyRuntime::new(
            FakeEgress::default(),
            kernel,
            SandboxId::new("http-proxy-allow").unwrap(),
        );

        let outcome = runtime
            .handle_request_line(
                "GET http://www.example.com/allowed?q=1 HTTP/1.1",
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                100,
            )
            .unwrap();

        assert!(matches!(
            outcome,
            HttpProxyOutcome::HostConnectOpened { .. }
        ));
        assert_eq!(runtime.egress().tcp_attempts, 1);
        assert_eq!(
            runtime.egress().last_tcp_destination,
            Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                80
            ))
        );
    }

    #[test]
    fn http_proxy_runtime_opens_connect_after_origin_policy_allows() {
        let mut rule = PolicyRule::allow("allow-connect-origin");
        rule.protocol = Some(Protocol::HttpsConnect);
        rule.destination_port = Some(foxprox_core::PortMatcher::Exact(443));
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::High);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = HttpProxyRuntime::new(
            FakeEgress::default(),
            kernel,
            SandboxId::new("connect-proxy-allow").unwrap(),
        );

        let outcome = runtime
            .handle_request_line(
                "CONNECT api.example.com:443 HTTP/1.1",
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                100,
            )
            .unwrap();

        assert!(matches!(
            outcome,
            HttpProxyOutcome::HostConnectOpened { .. }
        ));
        assert_eq!(runtime.egress().tcp_attempts, 1);
        assert_eq!(
            runtime.egress().last_tcp_destination,
            Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443
            ))
        );
    }

    #[test]
    fn socks_runtime_denies_ip_connect_before_host_egress_by_default() {
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = SocksRuntime::new(
            FakeEgress::default(),
            kernel,
            SandboxId::new("socks-deny").unwrap(),
        );
        let request = [5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xbb];

        let outcome = runtime.handle_connect_request(&request, None, 100).unwrap();

        assert!(matches!(outcome, SocksOutcome::Denied { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 0);
        assert_eq!(runtime.kernel().audit_sink().events().len(), 1);
    }

    #[test]
    fn socks_runtime_opens_host_connect_after_domain_policy_allows() {
        let mut rule = PolicyRule::allow("allow-socks-origin");
        rule.protocol = Some(Protocol::Socks);
        rule.destination_port = Some(foxprox_core::PortMatcher::Exact(443));
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::High);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = SocksRuntime::new(
            FakeEgress::default(),
            kernel,
            SandboxId::new("socks-allow").unwrap(),
        );
        let mut request = vec![5, 1, 0, 3, 15];
        request.extend_from_slice(b"api.example.com");
        request.extend_from_slice(&443u16.to_be_bytes());

        let outcome = runtime
            .handle_connect_request(
                &request,
                Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                100,
            )
            .unwrap();

        assert!(matches!(outcome, SocksOutcome::HostConnectOpened { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 1);
        assert_eq!(
            runtime.egress().last_tcp_destination,
            Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443
            ))
        );
    }

    #[test]
    fn socks_runtime_rejects_domain_connect_without_resolved_ip_before_audit() {
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = SocksRuntime::new(
            FakeEgress::default(),
            kernel,
            SandboxId::new("socks-missing-resolution").unwrap(),
        );
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());

        let error = runtime
            .handle_connect_request(&request, None, 100)
            .unwrap_err();

        assert_eq!(error, SocksRuntimeError::MissingResolvedIp);
        assert_eq!(runtime.egress().tcp_attempts, 0);
        assert!(runtime.kernel().audit_sink().events().is_empty());
    }

    #[test]
    fn tun_icmp_proof_session_runs_one_packet_against_device_io() {
        let request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let fake = FakeTunIo {
            input: std::io::Cursor::new(request),
            output: Vec::new(),
        };
        let mut session = TunIcmpProofSession::new(fake, 1500);

        let outcome = session.run_once().unwrap();
        let fake = session.into_inner();

        assert_eq!(outcome, TunPacketOutcome::EchoReplyWritten { bytes: 28 });
        assert_eq!(fake.output[20], 0);
        assert_eq!(checksum(&fake.output[..20]), 0);
        assert_eq!(checksum(&fake.output[20..]), 0);
    }

    #[test]
    fn tun_echo_packet_writes_synthetic_reply() {
        let request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7, b'o', b'k']);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert_eq!(outcome, TunPacketOutcome::EchoReplyWritten { bytes: 30 });
        assert_eq!(writer[9], 1);
        assert_eq!(&writer[12..16], &[10, 66, 0, 1]);
        assert_eq!(&writer[16..20], &[10, 66, 0, 2]);
        assert_eq!(writer[20], 0);
        assert_eq!(&writer[24..28], &[0x12, 0x34, 0, 7]);
        assert_eq!(&writer[28..], b"ok");
        assert_eq!(checksum(&writer[..20]), 0);
        assert_eq!(checksum(&writer[20..]), 0);
    }

    #[test]
    fn unified_tun_policy_handler_audits_unsupported_packets() {
        let request = build_ipv4_packet(99, b"unsupported");
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(4),
        );
        let mut runtime = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("unsupported-audit").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            kernel: &mut kernel,
        };

        let outcome = handle_one_tun_packet_with_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut runtime,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::PolicyDenied { decision }
                if decision.action == DecisionAction::FailClosed
        ));
        assert!(writer.is_empty());
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "unsupported-audit"
        );
    }

    #[test]
    fn unified_tun_policy_handler_audits_malformed_packets() {
        let mut request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        request[10] = 0xff;
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(4),
        );
        let mut runtime = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("malformed-audit").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            kernel: &mut kernel,
        };

        let outcome = handle_one_tun_packet_with_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut runtime,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::PolicyDenied { decision }
                if decision.reason == DecisionReason::MalformedInput
        ));
        assert!(writer.is_empty());
        assert_eq!(kernel.audit_sink().events().len(), 1);
    }

    #[test]
    fn icmp_policy_gate_denies_ping_before_writeback_by_default() {
        let request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(4),
        );

        let outcome = handle_one_tun_packet_with_icmp_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            SandboxId::new("icmp-deny").unwrap(),
            &mut kernel,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::PolicyDenied { decision }
                if decision.action == DecisionAction::DenyDrop
        ));
        assert!(writer.is_empty());
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "icmp-deny"
        );
    }

    #[test]
    fn icmp_policy_gate_allows_ping_when_configured() {
        let request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                allow_ping: true,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(4),
        );

        let outcome = handle_one_tun_packet_with_icmp_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            SandboxId::new("icmp-allow").unwrap(),
            &mut kernel,
            100,
        )
        .unwrap();

        assert_eq!(outcome, TunPacketOutcome::EchoReplyWritten { bytes: 28 });
        assert_eq!(writer[20], 0);
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "icmp-allow"
        );
    }

    #[test]
    fn dns_tun_policy_gate_denies_before_writeback_by_default() {
        let request = build_dns_udp_ipv4_packet();
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(4),
        );
        let mut dns = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("dns-deny").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            kernel: &mut kernel,
        };

        let outcome = handle_one_tun_packet_with_dns_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut dns,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::PolicyDenied { decision }
                if decision.action == DecisionAction::DenyDrop
        ));
        assert!(writer.is_empty());
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "dns-deny"
        );
    }

    #[test]
    fn dns_tun_policy_gate_allows_then_writes_response() {
        let request = build_dns_udp_ipv4_packet();
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let mut resolver = StaticDnsResolver::new(30);
        resolver.insert(
            Hostname::normalize("example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );
        let mut cache = DnsCache::new();
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-broker-dns");
        rule.protocol = Some(Protocol::Dns);
        rules.push(rule);
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(4),
        );
        let mut dns = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("dns-allow").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            kernel: &mut kernel,
        };

        let outcome = handle_one_tun_packet_with_dns_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut dns,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::DnsResponseWritten { cached: true, .. }
        ));
        assert!(!writer.is_empty());
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "dns-allow"
        );
    }

    #[test]
    fn tun_packet_with_broker_dns_query_writes_dns_response() {
        let dns_payload = dns_query_payload();
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&53000u16.to_be_bytes());
        udp_payload.extend_from_slice(&53u16.to_be_bytes());
        udp_payload.extend_from_slice(&((8 + dns_payload.len()) as u16).to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(&dns_payload);
        let request = build_ipv4_packet(17, &udp_payload);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let mut resolver = StaticDnsResolver::new(30);
        resolver.insert(
            Hostname::normalize("example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );
        let mut cache = DnsCache::new();

        let outcome = handle_one_tun_packet_with_dns(
            &mut reader,
            &mut writer,
            &mut buffer,
            &resolver,
            &mut cache,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
        )
        .unwrap();

        assert_eq!(
            outcome,
            TunPacketOutcome::DnsResponseWritten {
                bytes: writer.len(),
                cached: true,
            }
        );
        let ParsedIpPacket::Udpv4Packet(response_udp) = parse_ip_packet(&writer).unwrap() else {
            panic!("expected UDP response");
        };
        assert_eq!(response_udp.source_port, 53);
        assert_eq!(response_udp.destination_port, 53000);
        assert!(cache
            .lookup_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 101)
            .is_some());
    }

    #[test]
    fn tun_packet_with_malformed_broker_dns_query_drops_without_writeback() {
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&53000u16.to_be_bytes());
        udp_payload.extend_from_slice(&53u16.to_be_bytes());
        udp_payload.extend_from_slice(&11u16.to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(&[0, 1, 2]);
        let request = build_ipv4_packet(17, &udp_payload);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();

        let outcome = handle_one_tun_packet_with_dns(
            &mut reader,
            &mut writer,
            &mut buffer,
            &resolver,
            &mut cache,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
        )
        .unwrap();

        assert_eq!(outcome, TunPacketOutcome::DroppedMalformedDns);
        assert!(writer.is_empty());
        assert!(cache.observations().is_empty());
    }

    #[test]
    fn broker_dns_udp_handler_writes_response_and_caches_observation() {
        let dns_payload = dns_query_payload();
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &dns_payload,
        };
        let mut resolver = StaticDnsResolver::new(30);
        resolver.insert(
            Hostname::normalize("example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );
        let mut cache = DnsCache::new();

        let response = handle_broker_dns_udp_packet(&packet, &resolver, &mut cache, 100).unwrap();

        assert!(response.cached);
        let ParsedIpPacket::Udpv4Packet(response_udp) = parse_ip_packet(&response.packet).unwrap()
        else {
            panic!("expected UDP response packet");
        };
        assert_eq!(response_udp.source, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(response_udp.destination, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(response_udp.source_port, 53);
        assert_eq!(response_udp.destination_port, 53000);
        assert!(cache
            .lookup_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 101)
            .is_some());
    }

    #[test]
    fn broker_dns_udp_handler_rejects_malformed_query_without_cache() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &[0, 1, 2],
        };
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();

        assert!(handle_broker_dns_udp_packet(&packet, &resolver, &mut cache, 100).is_err());
        assert!(cache.observations().is_empty());
    }

    #[test]
    fn udp_flow_recording_classifies_and_counts_datagrams() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: b"dns?",
        };
        let mut table = FlowTable::new();

        let flow = record_udpv4_flow(
            &mut table,
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
        );
        assert_eq!(flow.class, UdpClass::BrokerDns);
        assert_eq!(flow.bytes_from_sandbox, 12);

        let flow = record_udpv4_flow(
            &mut table,
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            110,
        );
        assert_eq!(flow.bytes_from_sandbox, 24);
        assert_eq!(flow.last_seen_millis, 110);
    }

    #[test]
    fn udp_flow_recording_applies_quic_timeout_class() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(93, 184, 216, 34),
            source_port: 53000,
            destination_port: 443,
            payload: b"quic?",
        };
        let mut table = FlowTable::new();
        let flow = record_udpv4_flow(&mut table, &packet, &[], 0);
        assert_eq!(flow.class, UdpClass::QuicCandidate);

        assert!(table
            .expire_udp(121_000, &UdpTimeouts::default())
            .is_empty());
        assert_eq!(table.expire_udp(181_000, &UdpTimeouts::default()).len(), 1);
    }

    #[test]
    fn flow_keyed_udp_response_synthesis_routes_payload_back_to_sandbox() {
        let flow = FlowKey::new(
            Protocol::Udp,
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 53000),
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        );

        let packet = synthesize_tun_udp_response(&flow, b"host-reply").unwrap();

        let ParsedIpPacket::Udpv4Packet(response) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected UDP response packet");
        };
        assert_eq!(response.source, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(response.destination, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(response.source_port, 443);
        assert_eq!(response.destination_port, 53000);
        assert_eq!(response.payload, b"host-reply");
    }

    #[test]
    fn udp_response_synthesis_rejects_non_udp_or_non_ipv4_routes() {
        let non_udp = FlowKey::new(
            Protocol::Tcp,
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 53000),
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        );
        assert_eq!(
            synthesize_tun_udp_response(&non_udp, b"nope"),
            Err(UdpResponseRouteError::NonUdpFlow)
        );

        let ipv6 = FlowKey::new(
            Protocol::Udp,
            Endpoint::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 53000),
            Endpoint::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443),
        );
        assert_eq!(
            synthesize_tun_udp_response(&ipv6, b"nope"),
            Err(UdpResponseRouteError::UnsupportedAddressFamily)
        );
    }

    #[test]
    fn broker_dns_udp_packet_parses_query_for_audit_policy_event() {
        let dns_payload = dns_query_payload();
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &dns_payload,
        };
        let event = udpv4_packet_to_event_with_broker_dns(
            SandboxId::new("udp-policy").unwrap(),
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
        );

        let NormalizedEvent::DnsQuery { query, .. } = event else {
            panic!("expected parsed DNS query event");
        };
        assert_eq!(query.hostname.as_str(), "example.com");
    }

    #[test]
    fn malformed_broker_dns_udp_packet_fails_closed_as_malformed() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &[0, 1, 2],
        };
        let event = udpv4_packet_to_event_with_broker_dns(
            SandboxId::new("udp-policy").unwrap(),
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
        );

        let decision =
            PolicyEngine::new(PolicyConfig::default()).evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, DecisionReason::MalformedInput);
    }

    #[test]
    fn tcp_syn_packet_event_is_normalized_connect_attempt() {
        let packet = build_tcp_ipv4_packet(53000, 80, 0x02, &[]);
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };
        let event = tcpv4_segment_to_event(SandboxId::new("tcp-policy").unwrap(), &tcp);

        let NormalizedEvent::TcpConnectAttempt {
            source,
            destination,
            ..
        } = event
        else {
            panic!("expected TCP connect event");
        };
        assert_eq!(source.unwrap().port, 53000);
        assert_eq!(destination.port, 80);
    }

    #[test]
    fn non_syn_tcp_packet_is_unsupported_for_now() {
        let packet = build_tcp_ipv4_packet(53000, 80, 0x10, b"payload");
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };
        let event = tcpv4_segment_to_event(SandboxId::new("tcp-policy").unwrap(), &tcp);

        let decision =
            PolicyEngine::new(PolicyConfig::default()).evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, DecisionReason::UnsupportedProtocol);
    }

    #[test]
    fn tcp_payload_http_request_becomes_normalized_http_event() {
        let request = b"GET /allowed?q=1 HTTP/1.1\r\nHost: Example.com\r\n\r\n";
        let packet = build_tcp_ipv4_packet(53000, 80, 0x18, request);
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };

        let event = tcpv4_http_request_to_event(SandboxId::new("http-tun").unwrap(), &tcp).unwrap();

        let NormalizedEvent::HttpRequest {
            source,
            destination,
            metadata,
            ..
        } = event
        else {
            panic!("expected HTTP request event");
        };
        assert_eq!(source.unwrap().port, 53000);
        assert_eq!(destination.unwrap().port, 80);
        assert_eq!(metadata.host.as_str(), "example.com");
        assert_eq!(metadata.method, "GET");
        assert_eq!(metadata.path_query, "/allowed?q=1");
    }

    #[test]
    fn incomplete_tcp_http_payload_needs_more_data_instead_of_guessing() {
        let packet = build_tcp_ipv4_packet(53000, 80, 0x18, b"GET / HTTP/1.1\r\n");
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };

        assert_eq!(
            tcpv4_http_request_to_event(SandboxId::new("http-tun").unwrap(), &tcp),
            Err(InspectError::NeedMoreData)
        );
    }

    #[test]
    fn tcp_tls_client_hello_sni_becomes_hostname_attributed_connect_event() {
        let hello = build_tls_client_hello("Example.com");
        let packet = build_tcp_ipv4_packet(53000, 443, 0x18, &hello);
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };

        let event =
            tcpv4_tls_client_hello_to_event(SandboxId::new("tls-tun").unwrap(), &tcp).unwrap();

        let NormalizedEvent::TcpConnectAttempt {
            hostname,
            sni_status,
            destination,
            ..
        } = event
        else {
            panic!("expected TCP connect event");
        };
        let hostname = hostname.unwrap();
        assert_eq!(hostname.hostname.as_str(), "example.com");
        assert_eq!(hostname.source, AttributionSource::TlsSni);
        assert_eq!(hostname.confidence, AttributionConfidence::High);
        assert_eq!(sni_status, SniStatus::Present);
        assert_eq!(destination.port, 443);
    }

    #[test]
    fn tcp_tls_without_sni_is_reported_instead_of_guessed() {
        let hello = build_tls_client_hello_without_extensions();
        let packet = build_tcp_ipv4_packet(53000, 443, 0x18, &hello);
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };

        assert_eq!(
            tcpv4_tls_client_hello_to_event(SandboxId::new("tls-tun").unwrap(), &tcp),
            Err(InspectError::MissingSni)
        );
    }

    #[test]
    fn tcp_tls_sni_dns_mismatch_from_metadata_conversion_fails_closed() {
        let hello = build_tls_client_hello("api.evil.example");
        let packet = build_tcp_ipv4_packet(53000, 443, 0x18, &hello);
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };
        let event = tcpv4_tls_client_hello_to_event_with_dns_attribution(
            SandboxId::new("tls-mismatch").unwrap(),
            &tcp,
            Some(HostnameAttribution::broker_dns(
                Hostname::normalize("api.example.com").unwrap(),
            )),
        )
        .unwrap();

        let NormalizedEvent::TcpConnectAttempt {
            sni_dns_mismatch,
            hostname,
            ..
        } = &event
        else {
            panic!("expected TCP connect event");
        };
        assert!(*sni_dns_mismatch);
        assert_eq!(
            hostname.as_ref().unwrap().hostname.as_str(),
            "api.evil.example"
        );

        let mut rules = RuleSet::default();
        rules.push(PolicyRule::allow("allow-all-after-mismatch"));
        let decision = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        })
        .evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, DecisionReason::SniDnsMismatch);
    }

    #[test]
    fn tcp_tls_missing_or_hidden_sni_metadata_is_not_allowed_by_broad_rules() {
        let hello = build_tls_client_hello_without_extensions();
        let packet = build_tcp_ipv4_packet(53000, 443, 0x18, &hello);
        let ParsedIpPacket::Tcpv4Segment(tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected TCP segment");
        };
        assert_eq!(
            tcpv4_tls_client_hello_to_event(SandboxId::new("tls-missing").unwrap(), &tcp),
            Err(InspectError::MissingSni)
        );

        let missing_event = tcpv4_tls_client_hello_without_visible_sni_to_event(
            SandboxId::new("tls-missing").unwrap(),
            &tcp,
            SniStatus::Missing,
        );
        let missing_decision =
            PolicyEngine::new(PolicyConfig::default()).evaluate(&missing_event.to_policy_input());
        assert_eq!(missing_decision.action, DecisionAction::FailClosed);
        assert_eq!(
            missing_decision.reason,
            DecisionReason::HostnameAttributionRequired
        );

        let mut rules = RuleSet::default();
        rules.push(PolicyRule::allow("broad-allow-is-not-enough"));
        let hidden_event = tcpv4_tls_client_hello_without_visible_sni_to_event(
            SandboxId::new("tls-hidden").unwrap(),
            &tcp,
            SniStatus::HiddenOrEncrypted,
        );
        let hidden_decision = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        })
        .evaluate(&hidden_event.to_policy_input());
        assert_eq!(hidden_decision.action, DecisionAction::FailClosed);
        assert_eq!(hidden_decision.reason, DecisionReason::HiddenSniOrEch);
    }

    #[test]
    fn unified_tun_policy_handler_audits_tcp_connect_attempts() {
        let request = build_tcp_ipv4_packet(53000, 80, 0x02, &[]);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();
        let mut kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(4),
        );
        let mut runtime = BrokerDnsRuntime {
            sandbox_id: SandboxId::new("tcp-audit").unwrap(),
            resolver: &resolver,
            cache: &mut cache,
            broker_dns: &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            kernel: &mut kernel,
        };

        let outcome = handle_one_tun_packet_with_policy(
            &mut reader,
            &mut writer,
            &mut buffer,
            &mut runtime,
            100,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::TcpConnectObserved { decision, destination_port: 80, .. }
                if decision.action == DecisionAction::DenyDrop
        ));
        assert!(writer.is_empty());
        assert_eq!(kernel.audit_sink().events().len(), 1);
        assert_eq!(
            kernel.audit_sink().events()[0].sandbox_id.as_str(),
            "tcp-audit"
        );
    }

    #[test]
    fn udp_dns_packet_event_triggers_direct_dns_policy_denial() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(8, 8, 8, 8),
            source_port: 53000,
            destination_port: 53,
            payload: b"dns?",
        };
        let event = udpv4_packet_to_event(SandboxId::new("udp-policy").unwrap(), &packet);
        assert!(matches!(event, NormalizedEvent::DnsPacketAttempt { .. }));

        let decision = PolicyEngine::new(PolicyConfig {
            broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            ..PolicyConfig::default()
        })
        .evaluate(&event.to_policy_input());

        assert_eq!(decision.action, DecisionAction::RequireBrokerDns);
        assert_eq!(decision.reason, DecisionReason::DirectDnsBypass);
    }

    #[test]
    fn udp_443_packet_event_is_quic_candidate() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(93, 184, 216, 34),
            source_port: 53000,
            destination_port: 443,
            payload: b"quic?",
        };
        let event = udpv4_packet_to_event(SandboxId::new("udp-policy").unwrap(), &packet);
        let NormalizedEvent::UdpFlowAttempt { quic_status, .. } = event else {
            panic!("expected UDP flow event");
        };
        assert_eq!(quic_status, QuicStatus::Candidate);
    }

    #[test]
    fn quic_candidate_is_denied_when_quic_is_disabled() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(93, 184, 216, 34),
            source_port: 53000,
            destination_port: 443,
            payload: b"quic?",
        };
        let event = udpv4_packet_to_event(SandboxId::new("quic-policy").unwrap(), &packet);
        let decision = PolicyEngine::new(PolicyConfig {
            quic_enabled: false,
            ..PolicyConfig::default()
        })
        .evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::DenyDrop);
        assert_eq!(decision.reason, DecisionReason::QuicDisabled);
    }

    #[test]
    fn dns_attributed_quic_candidate_can_share_domain_policy() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(93, 184, 216, 34),
            source_port: 53000,
            destination_port: 443,
            payload: b"quic?",
        };
        let event = udpv4_packet_to_event_with_attribution(
            SandboxId::new("quic-policy").unwrap(),
            &packet,
            &[],
            Some(HostnameAttribution::broker_dns(
                Hostname::normalize("www.example.com").unwrap(),
            )),
        );
        let mut rule = PolicyRule::allow("allow-dns-attributed-quic");
        rule.protocol = Some(Protocol::Udp);
        rule.destination_port = Some(foxprox_core::PortMatcher::Exact(443));
        rule.domain_suffix = Some(Hostname::normalize("example.com").unwrap());
        rule.minimum_confidence = Some(AttributionConfidence::Medium);
        rule.quic_status = Some(QuicStatus::Candidate);
        let mut rules = RuleSet::default();
        rules.push(rule);
        let decision = PolicyEngine::new(PolicyConfig {
            rules,
            ..PolicyConfig::default()
        })
        .evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("allow-dns-attributed-quic")
        );
    }

    #[test]
    fn tun_udp_packet_is_observed_without_writeback_until_forwarder_exists() {
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&53000u16.to_be_bytes());
        udp_payload.extend_from_slice(&53u16.to_be_bytes());
        udp_payload.extend_from_slice(&12u16.to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(b"dns?");
        let request = build_ipv4_packet(17, &udp_payload);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert_eq!(
            outcome,
            TunPacketOutcome::UdpObserved {
                source: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
                source_port: 53000,
                destination_port: 53,
                payload_len: 4,
            }
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn tun_unsupported_protocol_is_dropped_without_writeback() {
        let request = build_ipv4_packet(99, b"unsupported");
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert_eq!(
            outcome,
            TunPacketOutcome::DroppedUnsupportedIpv4 {
                source: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
                protocol: 99,
            }
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn tun_malformed_packet_is_dropped_without_writeback() {
        let mut request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        request[10] = 0xff;
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::DroppedMalformed {
                error: PacketError::InvalidChecksum
            }
        ));
        assert!(writer.is_empty());
    }

    #[test]
    fn denied_events_do_not_reach_host_egress() {
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_event(&tcp_event(), 1);
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 0);
    }

    fn build_dns_udp_ipv4_packet() -> Vec<u8> {
        let dns_payload = dns_query_payload();
        build_udp_ipv4_packet(53000, 53, &dns_payload)
    }

    fn build_udp_ipv4_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&source_port.to_be_bytes());
        udp_payload.extend_from_slice(&destination_port.to_be_bytes());
        udp_payload.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(payload);
        build_ipv4_packet(17, &udp_payload)
    }

    fn build_tcp_ipv4_packet(
        source_port: u16,
        destination_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp_payload = vec![0u8; 20 + payload.len()];
        tcp_payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp_payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp_payload[4..8].copy_from_slice(&0x01020304u32.to_be_bytes());
        tcp_payload[12] = 0x50;
        tcp_payload[13] = flags;
        tcp_payload[14..16].copy_from_slice(&4096u16.to_be_bytes());
        tcp_payload[20..].copy_from_slice(payload);
        let tcp_checksum = ipv4_pseudo_checksum(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            6,
            &tcp_payload,
        );
        tcp_payload[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
        build_ipv4_packet(6, &tcp_payload)
    }

    fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
        let host = hostname.as_bytes();
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        wrap_tls_client_hello_body(&body)
    }

    fn build_tls_client_hello_without_extensions() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        wrap_tls_client_hello_body(&body)
    }

    fn wrap_tls_client_hello_body(body: &[u8]) -> Vec<u8> {
        let mut handshake = vec![
            1,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn dns_query_payload() -> Vec<u8> {
        let mut packet = vec![0x12, 0x34];
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn build_ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 66, 0, 1]);
        packet[20..].copy_from_slice(payload);
        if protocol == 1 {
            let icmp_checksum = checksum(&packet[20..]);
            packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        }
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn checksum(bytes: &[u8]) -> u16 {
        finish_checksum(add_checksum_bytes(0, bytes))
    }

    fn ipv4_pseudo_checksum(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> u16 {
        let mut sum = 0u32;
        sum = add_checksum_bytes(sum, &source.octets());
        sum = add_checksum_bytes(sum, &destination.octets());
        sum = add_checksum_bytes(sum, &[0, protocol]);
        sum = add_checksum_bytes(sum, &(payload.len() as u16).to_be_bytes());
        sum = add_checksum_bytes(sum, payload);
        finish_checksum(sum)
    }

    fn add_checksum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        if let Some(&remaining) = chunks.remainder().first() {
            sum += (remaining as u32) << 8;
        }
        sum
    }

    fn finish_checksum(mut sum: u32) -> u16 {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn denied_udp_datagram_does_not_reach_host_egress() {
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_udp_datagram_event(&udp_event(), b"payload".to_vec(), 1);

        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
        assert_eq!(runtime.egress().udp_attempts, 0);
    }

    #[test]
    fn tun_udp_egress_session_denies_before_host_send() {
        let request = build_udp_ipv4_packet(53000, 1234, b"blocked");
        let fake = FakeTunIo {
            input: std::io::Cursor::new(request),
            output: Vec::new(),
        };
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut session = TunUdpEgressSession::new(
            fake,
            FakeEgress::default(),
            kernel,
            SandboxId::new("udp-session-deny").unwrap(),
            Vec::new(),
            1500,
        );

        let outcome = session.run_once(100).unwrap();

        assert!(matches!(outcome, TunUdpSessionOutcome::PolicyDenied { .. }));
        assert_eq!(session.egress().udp_attempts, 0);
        assert_eq!(session.flow_table().udp_flows().len(), 1);
    }

    #[test]
    fn tun_udp_egress_session_records_flow_and_sends_allowed_payload() {
        let request = build_udp_ipv4_packet(53000, 1234, b"allowed");
        let fake = FakeTunIo {
            input: std::io::Cursor::new(request),
            output: Vec::new(),
        };
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-udp-session");
        rule.protocol = Some(Protocol::Udp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut session = TunUdpEgressSession::new(
            fake,
            FakeEgress::default(),
            kernel,
            SandboxId::new("udp-session-allow").unwrap(),
            Vec::new(),
            1500,
        );

        let outcome = session.run_once(100).unwrap();

        let TunUdpSessionOutcome::EgressSent { flow, .. } = outcome else {
            panic!("expected UDP egress");
        };
        assert_eq!(session.egress().udp_attempts, 1);
        assert_eq!(session.egress().last_udp_payload, b"allowed");
        assert!(session.flow_table().udp_flows().contains_key(&flow));
    }

    #[test]
    fn tun_udp_egress_session_writes_host_reply_to_tun_like_device() {
        let request = build_udp_ipv4_packet(53000, 1234, b"allowed");
        let fake = FakeTunIo {
            input: std::io::Cursor::new(request),
            output: Vec::new(),
        };
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-udp-session");
        rule.protocol = Some(Protocol::Udp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut session = TunUdpEgressSession::new(
            fake,
            FakeEgress::default(),
            kernel,
            SandboxId::new("udp-session-reply").unwrap(),
            Vec::new(),
            1500,
        );
        let TunUdpSessionOutcome::EgressSent { flow, .. } = session.run_once(100).unwrap() else {
            panic!("expected UDP egress");
        };

        let bytes = session
            .write_host_udp_reply(&flow, b"host-answer")
            .unwrap()
            .unwrap();
        let (fake, _, _, _) = session.into_parts();

        assert_eq!(bytes, fake.output.len());
        let ParsedIpPacket::Udpv4Packet(response) = parse_ip_packet(&fake.output).unwrap() else {
            panic!("expected UDP response packet");
        };
        assert_eq!(response.source, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(response.destination, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(response.source_port, 1234);
        assert_eq!(response.destination_port, 53000);
        assert_eq!(response.payload, b"host-answer");
    }

    #[test]
    fn allowed_udp_datagram_reaches_host_egress_with_payload() {
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-udp");
        rule.protocol = Some(Protocol::Udp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_udp_datagram_event(&udp_event(), b"payload".to_vec(), 1);

        assert!(matches!(outcome, RuntimeOutcome::EgressOpened { .. }));
        assert_eq!(runtime.egress().udp_attempts, 1);
        assert_eq!(runtime.egress().last_udp_payload, b"payload");
    }

    #[test]
    fn std_host_egress_sends_allowed_udp_datagram_to_loopback() {
        let server = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let destination = Endpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server.local_addr().unwrap().port(),
        );
        let event = NormalizedEvent::UdpFlowAttempt {
            sandbox_id: SandboxId::new("std-udp").unwrap(),
            frontend: FrontendKind::Tun,
            source: Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 53000),
            destination,
            hostname: None,
            quic_status: QuicStatus::NotQuic,
        };
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-loopback-udp");
        rule.protocol = Some(Protocol::Udp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(StdHostEgress::default(), kernel);

        let outcome = runtime.handle_udp_datagram_event(&event, b"hello-loopback".to_vec(), 1);

        assert!(matches!(outcome, RuntimeOutcome::EgressOpened { .. }));
        let mut received = [0u8; 64];
        let (bytes, _) = server.recv_from(&mut received).unwrap();
        assert_eq!(&received[..bytes], b"hello-loopback");
    }

    #[test]
    fn generic_handle_event_does_not_send_empty_udp_payloads() {
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-udp");
        rule.protocol = Some(Protocol::Udp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_event(&udp_event(), 1);

        assert!(matches!(outcome, RuntimeOutcome::NotAnEgressEvent { .. }));
        assert_eq!(runtime.egress().udp_attempts, 0);
    }

    #[test]
    fn allowed_tcp_event_reaches_host_egress_once() {
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-tcp");
        rule.protocol = Some(Protocol::Tcp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_event(&tcp_event(), 1);
        assert!(matches!(outcome, RuntimeOutcome::EgressOpened { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 1);
    }
}
