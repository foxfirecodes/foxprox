//! smoltcp-backed UDP/DNS forwarding proof.
//!
//! This module implements the first live Milestone 4 gate: a broker-reachable
//! DNS service at the TUN broker IP, direct external DNS fail-closed logging,
//! and configured generic UDP forwarding proof ports.

use foxprox_core::{
    classify_udp_candidate, parse_dns_query, parse_dns_response, Attribution, AuditBackpressure,
    AuditBuffer, AuditEvent, AuditEventKind, Decision, DecisionAction, DenialReason, DnsCache,
    DnsCacheEntry, DnsEgressRequest, DnsResponseObservation, EgressContext, FlowKey,
    FlowTimeoutClass, Frontend, NetworkEvent, PolicyEngine, PolicyRuleSet, Protocol, SandboxId,
    TransportEndpoint, UdpEgressRequest, UdpFlowRecord, UdpFlowTable, UnsupportedReason,
};
use foxprox_egress::{egress_error_to_io, StdHostEgress};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Medium, PacketMeta, TunTapInterface};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Configuration for the UDP/DNS forwarding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDnsProofConfig {
    /// Sandbox/session identifier used in normalized events.
    pub sandbox_id: SandboxId,
    /// Broker/gateway IPv4 address configured on the smoltcp interface.
    pub broker_ip: Ipv4Addr,
    /// Network prefix length for the broker interface address.
    pub prefix_len: u8,
    /// TUN MTU.
    pub mtu: usize,
    /// Broker DNS port reachable from the sandbox.
    pub dns_port: u16,
    /// Upstream DNS resolver used by the proof.
    pub upstream_dns: SocketAddr,
    /// Maximum queued UDP packets in each smoltcp UDP direction.
    pub udp_packet_capacity: usize,
    /// Maximum queued UDP payload bytes in each smoltcp UDP direction.
    pub udp_payload_capacity: usize,
    /// Timeout for one upstream DNS query.
    pub upstream_timeout: Duration,
    /// Destination UDP ports to forward without filtering for this proof.
    pub udp_forward_ports: Vec<u16>,
    /// Timeout for one generic UDP response read.
    pub udp_forward_timeout: Duration,
    /// Policy used before host UDP forwarding in the proof runtime.
    pub policy: PolicyRuleSet,
    /// Maximum queued audit events before UDP proof paths fail closed.
    pub audit_queue_capacity: usize,
    /// Maximum simultaneous DNS/UDP host worker threads.
    pub max_worker_threads: usize,
    /// Maximum simultaneous tracked UDP pseudo-flows.
    pub max_udp_flows: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct UdpForwardSocket {
    pub(crate) port: u16,
    pub(crate) handle: smoltcp::iface::SocketHandle,
}

pub(crate) struct UdpForwardDatagram {
    pub(crate) socket: UdpForwardSocket,
    pub(crate) payload: Vec<u8>,
    pub(crate) metadata: udp::UdpMetadata,
}

#[derive(Clone)]
pub(crate) struct WorkerLimiter {
    max_workers: usize,
    active: Arc<AtomicUsize>,
}

impl WorkerLimiter {
    pub(crate) fn new(max_workers: usize) -> io::Result<Self> {
        if max_workers == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max worker threads must be non-zero",
            ));
        }
        Ok(Self {
            max_workers,
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn try_acquire(&self) -> Option<WorkerPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max_workers {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(WorkerPermit {
                        active: Arc::clone(&self.active),
                    })
                }
                Err(next) => current = next,
            }
        }
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

struct WorkerPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) enum UdpWorkerResult {
    Dns {
        metadata: udp::UdpMetadata,
        source: TransportEndpoint,
        response: io::Result<Vec<u8>>,
        response_observation: Option<DnsResponseObservation>,
        cache_entries: Vec<DnsCacheEntry>,
    },
    Forward {
        handle: smoltcp::iface::SocketHandle,
        metadata: udp::UdpMetadata,
        source: TransportEndpoint,
        destination: TransportEndpoint,
        key: FlowKey,
        response: io::Result<Option<Vec<u8>>>,
    },
}

impl UdpDnsProofConfig {
    /// Creates a proof config using the repository's default TUN addresses.
    pub fn new(sandbox_id: SandboxId) -> Self {
        Self {
            sandbox_id,
            broker_ip: Ipv4Addr::new(10, 255, 0, 1),
            prefix_len: 24,
            mtu: 1500,
            dns_port: 53,
            upstream_dns: SocketAddr::from(([1, 1, 1, 1], 53)),
            udp_packet_capacity: 16,
            udp_payload_capacity: 16 * 1500,
            upstream_timeout: Duration::from_secs(5),
            udp_forward_ports: Vec::new(),
            udp_forward_timeout: Duration::from_secs(3),
            policy: PolicyRuleSet::default(),
            audit_queue_capacity: 8192,
            max_worker_threads: 1024,
            max_udp_flows: 4096,
        }
    }
}

/// Runs the UDP/DNS proof until the TUN fd errors or the process is interrupted.
pub fn run_udp_dns_proof(tun_fd: OwnedFd, config: UdpDnsProofConfig) -> io::Result<()> {
    run_udp_dns_proof_with_ready(tun_fd, config, || Ok(()))
}

/// Runs the UDP/DNS proof and calls `ready` after UDP sockets are installed.
pub fn run_udp_dns_proof_with_ready<F>(
    tun_fd: OwnedFd,
    config: UdpDnsProofConfig,
    ready: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    let mut audit = audit_buffer(config.audit_queue_capacity)?;
    let worker_limiter = WorkerLimiter::new(config.max_worker_threads)?;
    validate_max_udp_flows(config.max_udp_flows)?;
    set_nonblocking(tun_fd.as_raw_fd())?;
    let raw_fd = tun_fd.into_raw_fd();
    let mut device = TunTapInterface::from_fd(raw_fd, Medium::Ip, config.mtu).map_err(|error| {
        io::Error::other(format!("failed to create smoltcp TUN device: {error}"))
    })?;

    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = 0x0f0f_7564_u64;
    let mut iface = Interface::new(iface_config, &mut device, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(smoltcp_ipv4(config.broker_ip)),
            config.prefix_len,
        ));
    });
    iface.set_any_ip(true);
    iface
        .routes_mut()
        .add_default_ipv4_route(smoltcp_ipv4(config.broker_ip))
        .map_err(|error| io::Error::other(format!("failed to add smoltcp route: {error}")))?;

    let mut dns_socket = udp_socket(&config)?;
    dns_socket
        .bind(config.dns_port)
        .map_err(|error| io::Error::other(format!("udp dns bind failed: {error}")))?;
    let mut sockets = SocketSet::new(vec![]);
    let dns_handle = sockets.add(dns_socket);
    let mut forward_sockets = Vec::new();
    for port in &config.udp_forward_ports {
        if *port == config.dns_port {
            continue;
        }
        let mut socket = udp_socket(&config)?;
        socket
            .bind(*port)
            .map_err(|error| io::Error::other(format!("udp forward bind failed: {error}")))?;
        forward_sockets.push(UdpForwardSocket {
            port: *port,
            handle: sockets.add(socket),
        });
    }
    emit_udp_lifecycle_audit(&mut audit, &config, AuditEventKind::SessionStarted)?;
    emit_udp_lifecycle_audit(&mut audit, &config, AuditEventKind::BrokerStarted)?;
    emit_udp_lifecycle_audit(&mut audit, &config, AuditEventKind::TunConfigured)?;
    eprintln!(
        "foxprox-net: DNS proof listening on {}:{} upstream={} udp_forward_ports={:?}",
        config.broker_ip, config.dns_port, config.upstream_dns, config.udp_forward_ports
    );
    ready()?;

    let (worker_tx, worker_rx) = mpsc::channel();
    let mut cache = DnsCache::default();
    let mut udp_flows = UdpFlowTable::default();
    loop {
        iface.poll(Instant::now(), &mut device, &mut sockets);
        handle_worker_results(
            &config,
            &mut cache,
            &mut udp_flows,
            &mut audit,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );

        let mut received = Vec::new();
        {
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((payload, metadata)) => received.push((payload.to_vec(), metadata)),
                    Err(error) => {
                        eprintln!("foxprox-net: udp recv failed: {error}");
                        break;
                    }
                }
            }
        }
        for (payload, metadata) in received {
            if let Err(error) = handle_dns_datagram(
                &config,
                &mut audit,
                &worker_limiter,
                worker_tx.clone(),
                payload,
                metadata,
            ) {
                eprintln!("foxprox-net: dns datagram handling failed: {error}");
            }
        }

        let mut forward_received = Vec::new();
        for forward_socket in &forward_sockets {
            let socket = sockets.get_mut::<udp::Socket>(forward_socket.handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((payload, metadata)) => {
                        forward_received.push((*forward_socket, payload.to_vec(), metadata));
                    }
                    Err(error) => {
                        eprintln!("foxprox-net: udp forward recv failed: {error}");
                        break;
                    }
                }
            }
        }
        for (forward_socket, payload, metadata) in forward_received {
            if let Err(error) = handle_udp_forward_datagram(
                &config,
                &cache,
                &mut udp_flows,
                &mut audit,
                &worker_limiter,
                worker_tx.clone(),
                UdpForwardDatagram {
                    socket: forward_socket,
                    payload,
                    metadata,
                },
            ) {
                eprintln!("foxprox-net: udp datagram handling failed: {error}");
            }
        }
        handle_worker_results(
            &config,
            &mut cache,
            &mut udp_flows,
            &mut audit,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );
        let now = SystemTime::now();
        let expired_cache_entries = cache.expire(now);
        if expired_cache_entries > 0 {
            eprintln!("foxprox-net: expired {expired_cache_entries} DNS cache entries");
        }
        if let Err(error) =
            expire_udp_flows_with_audit(&mut audit, &config.sandbox_id, &mut udp_flows, now)
        {
            eprintln!("foxprox-net: udp expiry audit failed: {error}");
        }

        std::thread::sleep(Duration::from_millis(2));
    }
}

pub(crate) fn udp_socket(config: &UdpDnsProofConfig) -> io::Result<udp::Socket<'static>> {
    if config.udp_packet_capacity == 0 || config.udp_payload_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "udp capacities must be non-zero",
        ));
    }
    let rx_meta = vec![udp::PacketMetadata::EMPTY; config.udp_packet_capacity];
    let tx_meta = vec![udp::PacketMetadata::EMPTY; config.udp_packet_capacity];
    let rx_buffer = udp::PacketBuffer::new(rx_meta, vec![0; config.udp_payload_capacity]);
    let tx_buffer = udp::PacketBuffer::new(tx_meta, vec![0; config.udp_payload_capacity]);
    Ok(udp::Socket::new(rx_buffer, tx_buffer))
}

pub(crate) fn handle_worker_results(
    config: &UdpDnsProofConfig,
    cache: &mut DnsCache,
    flows: &mut UdpFlowTable,
    audit: &mut AuditBuffer,
    sockets: &mut SocketSet<'_>,
    dns_handle: smoltcp::iface::SocketHandle,
    worker_rx: &Receiver<UdpWorkerResult>,
) {
    while let Ok(result) = worker_rx.try_recv() {
        match result {
            UdpWorkerResult::Dns {
                metadata,
                source,
                response,
                response_observation,
                cache_entries,
            } => {
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        eprintln!("foxprox-net: upstream DNS failed: {error}");
                        continue;
                    }
                };
                if let Some(observation) = response_observation.as_ref() {
                    if let Err(error) = emit_dns_response_audit(audit, config, observation) {
                        eprintln!("foxprox-net: dns response audit failed: {error}");
                        continue;
                    }
                }
                if let Err(error) = send_udp_response(
                    sockets,
                    dns_handle,
                    metadata.endpoint,
                    IpAddress::Ipv4(smoltcp_ipv4(config.broker_ip)),
                    &response,
                ) {
                    eprintln!("foxprox-net: dns response send failed: {error}");
                    continue;
                }
                for entry in cache_entries {
                    eprintln!(
                        "foxprox-net: dns cache host={} answers={:?}",
                        entry.hostname.as_str(),
                        entry.addresses
                    );
                    cache.insert(entry);
                }
                eprintln!(
                    "foxprox-net: dns response sandbox={}:{} len={} cache_entries={}",
                    source.ip,
                    source.port,
                    response.len(),
                    cache.len()
                );
            }
            UdpWorkerResult::Forward {
                handle,
                metadata,
                source,
                destination,
                key,
                response,
            } => {
                let response = match response {
                    Ok(Some(response)) => response,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!("foxprox-net: host UDP forward failed: {error}");
                        continue;
                    }
                };
                flows.record_host_datagram(&key, response.len(), SystemTime::now());
                let local_address = match std_ip_to_smoltcp(destination.ip) {
                    Ok(address) => address,
                    Err(error) => {
                        eprintln!("foxprox-net: udp response address failed: {error}");
                        continue;
                    }
                };
                if let Err(error) =
                    send_udp_response(sockets, handle, metadata.endpoint, local_address, &response)
                {
                    eprintln!("foxprox-net: udp response send failed: {error}");
                    continue;
                }
                eprintln!(
                    "foxprox-net: udp response sandbox={}:{} destination={}:{} len={}",
                    source.ip,
                    source.port,
                    destination.ip,
                    destination.port,
                    response.len()
                );
            }
        }
    }
}

pub(crate) fn handle_dns_datagram(
    config: &UdpDnsProofConfig,
    audit: &mut AuditBuffer,
    worker_limiter: &WorkerLimiter,
    worker_tx: Sender<UdpWorkerResult>,
    payload: Vec<u8>,
    metadata: udp::UdpMetadata,
) -> io::Result<()> {
    let destination_ip = metadata
        .local_address
        .map(ip_to_std)
        .transpose()?
        .ok_or_else(|| io::Error::other("udp metadata missing local destination"))?;
    let source = endpoint_to_transport(metadata.endpoint)?;
    let destination = TransportEndpoint::new(destination_ip, config.dns_port);

    if destination_ip != IpAddr::V4(config.broker_ip) {
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: config.sandbox_id.clone(),
            frontend: Frontend::Tun,
            source,
            destination,
            attribution: Attribution::ip_only(),
            classification: foxprox_core::Protocol::Dns,
        };
        let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
        emit_udp_audit(audit, &event, decision)?;
        eprintln!("foxprox-net: deny direct DNS bypass {event:?}");
        return Ok(());
    }

    let question = match parse_dns_query(&payload) {
        Ok(question) => question,
        Err(error) => {
            eprintln!(
                "foxprox-net: drop malformed DNS query sandbox={}:{} error={:?}",
                source.ip, source.port, error
            );
            emit_udp_unsupported_audit(
                audit,
                &config.sandbox_id,
                format!(
                    "malformed broker DNS query source={}:{} destination={}:{} error={error:?}",
                    source.ip, source.port, destination.ip, destination.port
                ),
            )?;
            return Ok(());
        }
    };
    let event = NetworkEvent::DnsQuery {
        sandbox_id: config.sandbox_id.clone(),
        hostname: question.hostname.clone(),
        query_type: question.query_type.as_str().to_string(),
        frontend: Frontend::Tun,
    };
    eprintln!(
        "foxprox-net: dns query sandbox={}:{} host={} type={} event={:?}",
        source.ip,
        source.port,
        question.hostname.as_str(),
        question.query_type.as_str(),
        event
    );
    emit_udp_audit(audit, &event, Decision::allow("broker-dns"))?;

    let Some(permit) = worker_limiter.try_acquire() else {
        eprintln!("foxprox-net: drop DNS query: worker limit reached");
        return Ok(());
    };
    let upstream = config.upstream_dns;
    let timeout = config.upstream_timeout;
    let sandbox_id = config.sandbox_id.clone();
    let request = DnsEgressRequest {
        context: EgressContext {
            sandbox_id: sandbox_id.clone(),
            frontend: Frontend::Tun,
            decision: Decision::allow("broker-dns"),
            attribution: Attribution::ip_only(),
        },
        hostname: question.hostname.clone(),
        query_type: question.query_type.as_str().to_string(),
        upstream: TransportEndpoint::from(upstream),
    };
    std::thread::spawn(move || {
        let _permit = permit;
        let response = forward_dns_query(request, &payload, timeout);
        let response_observation = response
            .as_ref()
            .ok()
            .and_then(|response| parse_dns_response(response, Some(&question)).ok());
        let cache_entries = response_observation
            .as_ref()
            .map(|observation| {
                DnsCacheEntry::from_response(sandbox_id, observation, SystemTime::now(), true)
            })
            .unwrap_or_default();
        let _ = worker_tx.send(UdpWorkerResult::Dns {
            metadata,
            source,
            response,
            response_observation,
            cache_entries,
        });
    });
    Ok(())
}

pub(crate) fn handle_udp_forward_datagram(
    config: &UdpDnsProofConfig,
    cache: &DnsCache,
    flows: &mut UdpFlowTable,
    audit: &mut AuditBuffer,
    worker_limiter: &WorkerLimiter,
    worker_tx: Sender<UdpWorkerResult>,
    datagram: UdpForwardDatagram,
) -> io::Result<()> {
    let destination_ip = datagram
        .metadata
        .local_address
        .map(ip_to_std)
        .transpose()?
        .ok_or_else(|| io::Error::other("udp metadata missing local destination"))?;
    let source = endpoint_to_transport(datagram.metadata.endpoint)?;
    let destination = TransportEndpoint::new(destination_ip, datagram.socket.port);
    let key = FlowKey::udp(source.ip, source.port, destination.ip, destination.port);
    let (classification, timeout_class) = udp_classification_for_port(destination.port);
    let now = SystemTime::now();
    let attribution = udp_attribution_for_destination(config, cache, destination.ip, now);
    let event = NetworkEvent::UdpFlowAttempt {
        sandbox_id: config.sandbox_id.clone(),
        frontend: Frontend::Tun,
        source,
        destination,
        attribution: attribution.clone(),
        classification,
    };
    let decision = PolicyEngine::new(config.policy.clone()).evaluate(&event);
    if classification == Protocol::Quic {
        eprintln!(
            "foxprox-net: quic candidate flow sandbox={}:{} destination={}:{} attribution={:?} decision={:?}",
            source.ip, source.port, destination.ip, destination.port, attribution, decision
        );
    }
    eprintln!(
        "foxprox-net: udp policy sandbox={}:{} destination={}:{} classification={:?} len={} decision={:?} event={:?}",
        source.ip,
        source.port,
        destination.ip,
        destination.port,
        classification,
        datagram.payload.len(),
        decision,
        event
    );
    emit_udp_audit(audit, &event, decision.clone())?;
    if !decision.is_allowed() {
        return Ok(());
    }
    if flows.get(&key).is_none() && flows.len() >= config.max_udp_flows {
        let decision = Decision {
            action: DecisionAction::FailClosed,
            rule_id: None,
            reason: Some(DenialReason::ResourceLimit("max_udp_flows")),
        };
        emit_udp_audit(audit, &event, decision)?;
        eprintln!(
            "foxprox-net: drop UDP forward: max udp flows reached capacity={}",
            config.max_udp_flows
        );
        return Ok(());
    }
    let Some(permit) = worker_limiter.try_acquire() else {
        eprintln!("foxprox-net: drop UDP forward: worker limit reached");
        return Ok(());
    };
    flows.record_sandbox_datagram(
        key,
        timeout_class,
        attribution.clone(),
        datagram.payload.len(),
        now,
    );

    let timeout = config.udp_forward_timeout;
    let request = UdpEgressRequest {
        context: EgressContext {
            sandbox_id: config.sandbox_id.clone(),
            frontend: Frontend::Tun,
            decision,
            attribution,
        },
        source,
        destination,
        timeout_class,
    };
    std::thread::spawn(move || {
        let _permit = permit;
        let response = forward_udp_datagram(request, &datagram.payload, timeout);
        let _ = worker_tx.send(UdpWorkerResult::Forward {
            handle: datagram.socket.handle,
            metadata: datagram.metadata,
            source,
            destination,
            key,
            response,
        });
    });
    Ok(())
}

fn audit_buffer(capacity: usize) -> io::Result<AuditBuffer> {
    if capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit queue capacity must be non-zero",
        ));
    }
    Ok(AuditBuffer::new(capacity))
}

pub(crate) fn validate_max_udp_flows(max_udp_flows: usize) -> io::Result<()> {
    if max_udp_flows == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max UDP flows must be non-zero",
        ));
    }
    Ok(())
}

fn emit_udp_raw_audit(audit: &mut AuditBuffer, audit_event: AuditEvent) -> io::Result<()> {
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(audit_event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: udp audit event={audit_event:?}");
    Ok(())
}

fn emit_udp_lifecycle_audit(
    audit: &mut AuditBuffer,
    config: &UdpDnsProofConfig,
    kind: AuditEventKind,
) -> io::Result<()> {
    let mut event = AuditEvent::new(Frontend::Tun, kind).with_sandbox_id(config.sandbox_id.clone());
    event.protocol = Some(Protocol::Dns);
    event.destination = Some(TransportEndpoint::new(
        IpAddr::V4(config.broker_ip),
        config.dns_port,
    ));
    event.detail = Some(format!(
        "broker_dns={}:{} upstream={} udp_forward_ports={:?}",
        config.broker_ip, config.dns_port, config.upstream_dns, config.udp_forward_ports
    ));
    emit_udp_raw_audit(audit, event)
}

fn emit_udp_audit(
    audit: &mut AuditBuffer,
    event: &NetworkEvent,
    decision: Decision,
) -> io::Result<()> {
    let audit_event = udp_audit_event(event, decision);
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(audit_event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: udp audit event={audit_event:?}");
    Ok(())
}

fn audit_backpressure_error(error: AuditBackpressure) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!("audit queue backpressure: {error:?}"),
    )
}

fn emit_dns_response_audit(
    audit: &mut AuditBuffer,
    config: &UdpDnsProofConfig,
    observation: &DnsResponseObservation,
) -> io::Result<()> {
    let mut event = AuditEvent::new(Frontend::Tun, AuditEventKind::DnsQuery)
        .with_sandbox_id(config.sandbox_id.clone());
    event.protocol = Some(Protocol::Dns);
    event.hostname = observation.hostname.clone();
    event.dns_query_type = observation
        .query_type
        .as_ref()
        .map(|query_type| query_type.as_str().to_string());
    event.dns_rcode = Some(observation.rcode);
    event.dns_answers = observation
        .answers
        .iter()
        .map(|answer| answer.address)
        .collect();
    event.decision = Some(Decision::allow("broker-dns-response"));
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: udp audit event={event:?}");
    Ok(())
}

#[cfg(not(test))]
fn drain_audit_to_stderr(audit: &mut AuditBuffer) -> io::Result<()> {
    let mut stderr = io::stderr();
    foxprox_core::drain_audit_buffer_to_json_lines(audit, &mut stderr)
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("audit sink write failed: {error}")))
}

#[cfg(test)]
fn drain_audit_to_stderr(_audit: &mut AuditBuffer) -> io::Result<()> {
    Ok(())
}

pub(crate) fn expire_udp_flows_with_audit(
    audit: &mut AuditBuffer,
    sandbox_id: &SandboxId,
    flows: &mut UdpFlowTable,
    now: SystemTime,
) -> io::Result<()> {
    for expired in flows.expired(now) {
        emit_udp_flow_expired_audit(audit, sandbox_id, &expired)?;
        let _ = flows.remove(&expired.key);
        eprintln!(
            "foxprox-net: udp flow expired destination={}:{} sandbox_to_host={} host_to_sandbox={}",
            expired.key.destination_ip,
            expired.key.destination_port,
            expired.bytes_from_sandbox,
            expired.bytes_to_sandbox
        );
    }
    Ok(())
}

pub(crate) fn emit_udp_flow_expired_audit(
    audit: &mut AuditBuffer,
    sandbox_id: &SandboxId,
    flow: &UdpFlowRecord,
) -> io::Result<()> {
    let mut event = AuditEvent::new(Frontend::Tun, AuditEventKind::UdpFlowExpired)
        .with_sandbox_id(sandbox_id.clone())
        .with_endpoints(
            Some(TransportEndpoint::new(
                flow.key.source_ip,
                flow.key.source_port,
            )),
            Some(TransportEndpoint::new(
                flow.key.destination_ip,
                flow.key.destination_port,
            )),
        );
    event.protocol = Some(Protocol::Udp);
    event.destination_port = Some(flow.key.destination_port);
    event.attribution = Some(flow.attribution.clone());
    event.hostname = flow.attribution.hostname.clone();
    event.bytes_from_sandbox = flow.bytes_from_sandbox;
    event.bytes_to_sandbox = flow.bytes_to_sandbox;
    event.flow_duration = flow.last_activity.duration_since(flow.created_at).ok();
    drain_audit_to_stderr(audit)?;
    audit
        .try_push(event.clone())
        .map_err(audit_backpressure_error)?;
    drain_audit_to_stderr(audit)?;
    eprintln!("foxprox-net: udp audit event={event:?}");
    Ok(())
}

fn emit_udp_unsupported_audit(
    audit: &mut AuditBuffer,
    sandbox_id: &SandboxId,
    detail: impl Into<String>,
) -> io::Result<()> {
    let event = NetworkEvent::Unsupported {
        sandbox_id: Some(sandbox_id.clone()),
        frontend: Frontend::Tun,
        reason: UnsupportedReason::Malformed(detail.into()),
    };
    let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
    emit_udp_audit(audit, &event, decision)
}

fn udp_audit_event(event: &NetworkEvent, decision: Decision) -> AuditEvent {
    let kind = match event {
        NetworkEvent::DnsQuery { .. } => AuditEventKind::DnsQuery,
        NetworkEvent::UdpFlowAttempt { classification, .. }
            if *classification == Protocol::Quic && decision.is_allowed() =>
        {
            AuditEventKind::QuicCandidateFlowCreated
        }
        NetworkEvent::UdpFlowAttempt { .. } if decision.is_allowed() => {
            AuditEventKind::UdpFlowCreated
        }
        NetworkEvent::UdpFlowAttempt { .. } => AuditEventKind::UdpPacketDenied,
        _ => AuditEventKind::UnsupportedDenied,
    };
    let mut audit = AuditEvent::new(Frontend::Tun, kind).with_decision(decision);
    if let Some(sandbox_id) = event.sandbox_id() {
        audit = audit.with_sandbox_id(sandbox_id.clone());
    }
    audit.protocol = Some(event.protocol());
    match event {
        NetworkEvent::DnsQuery {
            hostname,
            query_type,
            ..
        } => {
            audit.hostname = Some(hostname.clone());
            audit.dns_query_type = Some(query_type.clone());
        }
        NetworkEvent::UdpFlowAttempt {
            source,
            destination,
            attribution,
            ..
        } => {
            audit = audit.with_endpoints(Some(*source), Some(*destination));
            audit.attribution = Some(attribution.clone());
            audit.hostname = attribution.hostname.clone();
        }
        NetworkEvent::Unsupported { reason, .. } => {
            audit.detail = Some(format!("{reason:?}"));
        }
        _ => {}
    }
    audit
}

fn udp_classification_for_port(port: u16) -> (Protocol, FlowTimeoutClass) {
    let classification = classify_udp_candidate(port);
    let timeout_class = if classification == Protocol::Quic {
        FlowTimeoutClass::Quic
    } else {
        FlowTimeoutClass::GenericUdp
    };
    (classification, timeout_class)
}

fn udp_attribution_for_destination(
    config: &UdpDnsProofConfig,
    cache: &DnsCache,
    destination_ip: IpAddr,
    now: SystemTime,
) -> Attribution {
    cache
        .lookup_address(&config.sandbox_id, destination_ip, now)
        .map(DnsCacheEntry::attribution)
        .unwrap_or_else(Attribution::ip_only)
}

fn send_udp_response(
    sockets: &mut SocketSet<'_>,
    handle: smoltcp::iface::SocketHandle,
    endpoint: smoltcp::wire::IpEndpoint,
    local_address: IpAddress,
    response: &[u8],
) -> io::Result<()> {
    let response_meta = udp::UdpMetadata {
        endpoint,
        local_address: Some(local_address),
        meta: PacketMeta::default(),
    };
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket
        .send_slice(response, response_meta)
        .map_err(|error| io::Error::other(format!("smoltcp udp send failed: {error}")))
}

fn forward_udp_datagram(
    request: UdpEgressRequest,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    StdHostEgress::new()
        .forward_udp_once(request, payload, timeout)
        .map_err(egress_error_to_io)
}

fn forward_dns_query(
    request: DnsEgressRequest,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    StdHostEgress::new()
        .query_dns_raw(request, payload, timeout)
        .map_err(egress_error_to_io)
}

fn endpoint_to_transport(endpoint: smoltcp::wire::IpEndpoint) -> io::Result<TransportEndpoint> {
    Ok(TransportEndpoint::new(
        ip_to_std(endpoint.addr)?,
        endpoint.port,
    ))
}

fn ip_to_std(ip: IpAddress) -> io::Result<IpAddr> {
    match ip {
        IpAddress::Ipv4(ip) => Ok(IpAddr::V4(Ipv4Addr::from(ip.octets()))),
    }
}

fn std_ip_to_smoltcp(ip: IpAddr) -> io::Result<IpAddress> {
    match ip {
        IpAddr::V4(ip) => Ok(IpAddress::Ipv4(smoltcp_ipv4(ip))),
        IpAddr::V6(_) => Err(io::Error::other("IPv6 is unsupported in UDP proof")),
    }
}

fn smoltcp_ipv4(ip: Ipv4Addr) -> Ipv4Address {
    let [a, b, c, d] = ip.octets();
    Ipv4Address::new(a, b, c, d)
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        AttributionConfidence, AttributionSource, DecisionAction, DnsAddressRecord, DnsObservation,
        DnsQueryType, Hostname, PolicyRule, PortRange, RuleEffect,
    };

    #[test]
    fn default_udp_dns_config_is_bounded() {
        let config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        assert_eq!(config.dns_port, 53);
        assert_eq!(config.broker_ip, Ipv4Addr::new(10, 255, 0, 1));
        assert!(config.udp_packet_capacity >= 4);
        assert!(config.udp_payload_capacity >= 1500);
        assert!(config.upstream_timeout <= Duration::from_secs(5));
        assert!(config.udp_forward_timeout <= Duration::from_secs(3));
        assert!(config.audit_queue_capacity > 0);
        assert!(config.max_worker_threads > 0);
        assert!(config.max_udp_flows > 0);
    }

    #[test]
    fn udp_classification_marks_port_443_as_quic() {
        assert_eq!(
            udp_classification_for_port(443),
            (Protocol::Quic, FlowTimeoutClass::Quic)
        );
        assert_eq!(
            udp_classification_for_port(12345),
            (Protocol::Udp, FlowTimeoutClass::GenericUdp)
        );
    }

    #[test]
    fn default_udp_policy_denies_host_forwarding_events() {
        let config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: config.sandbox_id.clone(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_444),
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            attribution: Attribution::ip_only(),
            classification: Protocol::Quic,
        };
        assert!(!PolicyEngine::new(config.policy)
            .evaluate(&event)
            .is_allowed());
    }

    #[test]
    fn worker_limiter_enforces_capacity_and_releases_on_drop() {
        let limiter = WorkerLimiter::new(1).unwrap();
        let permit = limiter.try_acquire().unwrap();
        assert_eq!(limiter.active_count(), 1);
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert_eq!(limiter.active_count(), 0);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn worker_limiter_rejects_zero_capacity() {
        let error = match WorkerLimiter::new(0) {
            Ok(_) => panic!("zero-capacity worker limiter unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn udp_flow_limit_rejects_zero_capacity() {
        assert_eq!(
            validate_max_udp_flows(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    fn udp_metadata(source_ip: Ipv4Addr, source_port: u16, local_ip: Ipv4Addr) -> udp::UdpMetadata {
        udp::UdpMetadata {
            endpoint: smoltcp::wire::IpEndpoint {
                addr: IpAddress::Ipv4(smoltcp_ipv4(source_ip)),
                port: source_port,
            },
            local_address: Some(IpAddress::Ipv4(smoltcp_ipv4(local_ip))),
            meta: PacketMeta::default(),
        }
    }

    #[test]
    fn udp_audit_event_records_unsupported_metadata() {
        let event = NetworkEvent::Unsupported {
            sandbox_id: Some(SandboxId::new("test").unwrap()),
            frontend: Frontend::Tun,
            reason: UnsupportedReason::Malformed("bad dns".to_string()),
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let audit = udp_audit_event(&event, decision);

        assert_eq!(audit.kind, AuditEventKind::UnsupportedDenied);
        assert_eq!(audit.protocol, Some(Protocol::Unsupported));
        assert_eq!(audit.frontend, Frontend::Tun);
        assert_eq!(
            audit.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::FailClosed)
        );
        assert!(audit
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("bad dns")));
    }

    #[test]
    fn malformed_broker_dns_query_emits_unsupported_audit() {
        let config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        let mut audit = audit_buffer(8).unwrap();
        let limiter = WorkerLimiter::new(1).unwrap();
        let (worker_tx, _worker_rx) = mpsc::channel();
        let metadata = udp_metadata(Ipv4Addr::new(10, 255, 0, 2), 44_444, config.broker_ip);

        handle_dns_datagram(
            &config,
            &mut audit,
            &limiter,
            worker_tx,
            vec![0xde, 0xad, 0xbe, 0xef],
            metadata,
        )
        .unwrap();

        let event = audit.pop_front().unwrap();
        assert_eq!(event.kind, AuditEventKind::UnsupportedDenied);
        assert_eq!(event.protocol, Some(Protocol::Unsupported));
        assert_eq!(event.frontend, Frontend::Tun);
        assert_eq!(
            event.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::FailClosed)
        );
        assert!(event
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("malformed broker DNS query")));
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn malformed_broker_dns_query_backpressure_fails_closed() {
        let config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        let mut audit = audit_buffer(1).unwrap();
        let limiter = WorkerLimiter::new(1).unwrap();
        let (worker_tx, _worker_rx) = mpsc::channel();
        let filled = NetworkEvent::DnsQuery {
            sandbox_id: config.sandbox_id.clone(),
            hostname: Hostname::parse("example.com").unwrap(),
            query_type: "A".to_string(),
            frontend: Frontend::Tun,
        };
        emit_udp_audit(&mut audit, &filled, Decision::allow("broker-dns")).unwrap();
        let metadata = udp_metadata(Ipv4Addr::new(10, 255, 0, 2), 44_444, config.broker_ip);

        let error = handle_dns_datagram(
            &config,
            &mut audit,
            &limiter,
            worker_tx,
            vec![0xde, 0xad, 0xbe, 0xef],
            metadata,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn udp_audit_event_records_flow_metadata() {
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_444),
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            attribution: Attribution::ip_only(),
            classification: Protocol::Quic,
        };
        let audit = udp_audit_event(&event, Decision::allow("allow-quic"));

        assert_eq!(audit.kind, AuditEventKind::QuicCandidateFlowCreated);
        assert_eq!(audit.protocol, Some(Protocol::Quic));
        assert_eq!(audit.source.unwrap().port, 44_444);
        assert_eq!(audit.destination.unwrap().port, 443);
        assert_eq!(audit.destination_port, Some(443));
        assert!(audit.decision.unwrap().is_allowed());
    }

    #[test]
    fn udp_flow_limit_denies_new_flow_before_record_or_worker_spawn() {
        let mut config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        config.max_udp_flows = 1;
        config.udp_forward_ports.push(443);
        config.policy.rules.push(
            PolicyRule::new("allow-udp-443", RuleEffect::Allow)
                .with_protocol(Protocol::Quic)
                .with_destination_ports(PortRange::single(443)),
        );
        let existing_key = FlowKey::udp(
            IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
            40000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        );
        let mut flows = UdpFlowTable::default();
        flows.record_sandbox_datagram(
            existing_key,
            FlowTimeoutClass::Quic,
            Attribution::ip_only(),
            1,
            SystemTime::now(),
        );
        let mut audit = audit_buffer(8).unwrap();
        let limiter = WorkerLimiter::new(1).unwrap();
        let (worker_tx, worker_rx) = mpsc::channel();
        let mut socket = udp_socket(&config).unwrap();
        socket.bind(443).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);

        handle_udp_forward_datagram(
            &config,
            &DnsCache::default(),
            &mut flows,
            &mut audit,
            &limiter,
            worker_tx,
            UdpForwardDatagram {
                socket: UdpForwardSocket { port: 443, handle },
                payload: vec![1, 2, 3],
                metadata: udp_metadata(Ipv4Addr::new(10, 255, 0, 2), 40001, config.broker_ip),
            },
        )
        .unwrap();

        assert_eq!(flows.len(), 1);
        assert!(flows
            .get(&FlowKey::udp(
                IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
                40001,
                IpAddr::V4(config.broker_ip),
                443,
            ))
            .is_none());
        assert_eq!(limiter.active_count(), 0);
        assert!(worker_rx.try_recv().is_err());
        let _policy_allow = audit.pop_front().unwrap();
        let limit_audit = audit.pop_front().unwrap();
        assert_eq!(limit_audit.kind, AuditEventKind::UdpPacketDenied);
        assert_eq!(
            limit_audit.decision.unwrap().reason,
            Some(DenialReason::ResourceLimit("max_udp_flows"))
        );
    }

    #[test]
    fn dns_response_audit_records_rcode_and_answers() {
        let config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        let observation = DnsResponseObservation {
            transaction_id: 7,
            hostname: Some(Hostname::parse("example.com").unwrap()),
            query_type: Some(DnsQueryType::A),
            rcode: 0,
            truncated: false,
            answers: vec![DnsAddressRecord {
                hostname: Hostname::parse("example.com").unwrap(),
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                ttl: Duration::from_secs(60),
            }],
        };
        let mut audit = audit_buffer(8).unwrap();

        emit_dns_response_audit(&mut audit, &config, &observation).unwrap();
        let event = audit.pop_front().unwrap();

        assert_eq!(event.kind, AuditEventKind::DnsQuery);
        assert_eq!(event.protocol, Some(Protocol::Dns));
        assert_eq!(event.hostname.unwrap().as_str(), "example.com");
        assert_eq!(event.dns_query_type.as_deref(), Some("A"));
        assert_eq!(event.dns_rcode, Some(0));
        assert_eq!(
            event.dns_answers,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert!(event.decision.unwrap().is_allowed());
    }

    #[test]
    fn dns_response_audit_backpressure_keeps_cache_empty_and_sends_no_response() {
        let mut config = UdpDnsProofConfig::new(SandboxId::new("test").unwrap());
        config.udp_packet_capacity = 1;
        let observation = DnsResponseObservation {
            transaction_id: 7,
            hostname: Some(Hostname::parse("example.com").unwrap()),
            query_type: Some(DnsQueryType::A),
            rcode: 0,
            truncated: false,
            answers: vec![DnsAddressRecord {
                hostname: Hostname::parse("example.com").unwrap(),
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                ttl: Duration::from_secs(60),
            }],
        };
        let cache_entries = DnsCacheEntry::from_response(
            config.sandbox_id.clone(),
            &observation,
            SystemTime::now(),
            true,
        );
        assert!(!cache_entries.is_empty());
        let mut cache = DnsCache::default();
        let mut flows = UdpFlowTable::default();
        let mut audit = audit_buffer(1).unwrap();
        audit
            .try_push(AuditEvent::new(Frontend::Tun, AuditEventKind::DnsQuery))
            .unwrap();
        let mut socket = udp_socket(&config).unwrap();
        socket.bind(config.dns_port).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let dns_handle = sockets.add(socket);
        let (worker_tx, worker_rx) = std::sync::mpsc::channel();
        worker_tx
            .send(UdpWorkerResult::Dns {
                metadata: udp_metadata(Ipv4Addr::new(10, 255, 0, 2), 44444, config.broker_ip),
                source: TransportEndpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
                    port: 44444,
                },
                response: Ok(vec![0_u8; 12]),
                response_observation: Some(observation),
                cache_entries,
            })
            .unwrap();

        handle_worker_results(
            &config,
            &mut cache,
            &mut flows,
            &mut audit,
            &mut sockets,
            dns_handle,
            &worker_rx,
        );

        assert_eq!(cache.len(), 0);
        let socket = sockets.get_mut::<udp::Socket>(dns_handle);
        assert!(socket.can_send());
    }

    #[test]
    fn dns_audit_event_records_query_metadata() {
        let event = NetworkEvent::DnsQuery {
            sandbox_id: SandboxId::new("test").unwrap(),
            hostname: Hostname::parse("example.com").unwrap(),
            query_type: "A".to_string(),
            frontend: Frontend::Tun,
        };
        let audit = udp_audit_event(&event, Decision::allow("broker-dns"));

        assert_eq!(audit.kind, AuditEventKind::DnsQuery);
        assert_eq!(audit.protocol, Some(Protocol::Dns));
        assert_eq!(audit.hostname.unwrap().as_str(), "example.com");
        assert_eq!(audit.dns_query_type.as_deref(), Some("A"));
        assert!(audit.decision.unwrap().is_allowed());
    }

    #[test]
    fn udp_flow_expired_audit_records_bytes_duration_and_endpoints() {
        let sandbox_id = SandboxId::new("test").unwrap();
        let now = SystemTime::now();
        let key = FlowKey::udp(
            IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
            44_444,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        );
        let mut flow = UdpFlowRecord::new(key, FlowTimeoutClass::Quic, Attribution::ip_only(), now);
        flow.record_sandbox_bytes(123, now);
        flow.record_host_bytes(456, now + Duration::from_millis(5));
        let mut audit = audit_buffer(8).unwrap();

        emit_udp_flow_expired_audit(&mut audit, &sandbox_id, &flow).unwrap();
        let event = audit.pop_front().unwrap();

        assert_eq!(event.kind, AuditEventKind::UdpFlowExpired);
        assert_eq!(event.protocol, Some(Protocol::Udp));
        assert_eq!(event.source.unwrap().port, 44_444);
        assert_eq!(event.destination.unwrap().port, 443);
        assert_eq!(event.destination_port, Some(443));
        assert_eq!(event.bytes_from_sandbox, 123);
        assert_eq!(event.bytes_to_sandbox, 456);
        assert!(event.flow_duration.is_some());
    }

    #[test]
    fn udp_flow_expiry_backpressure_keeps_record_for_retry() {
        let sandbox_id = SandboxId::new("test").unwrap();
        let now = SystemTime::now();
        let key = FlowKey::udp(
            IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)),
            44_444,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        );
        let mut flows = UdpFlowTable::default();
        flows.record_sandbox_datagram(
            key,
            FlowTimeoutClass::Quic,
            Attribution::ip_only(),
            123,
            now,
        );
        let mut audit = audit_buffer(1).unwrap();
        let filler = NetworkEvent::DnsQuery {
            sandbox_id: sandbox_id.clone(),
            hostname: Hostname::parse("example.com").unwrap(),
            query_type: "A".to_string(),
            frontend: Frontend::Tun,
        };
        emit_udp_audit(&mut audit, &filler, Decision::allow("broker-dns")).unwrap();

        let error = expire_udp_flows_with_audit(
            &mut audit,
            &sandbox_id,
            &mut flows,
            now + FlowTimeoutClass::Quic.default_duration(),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(flows.get(&key).is_some());
    }

    #[test]
    fn udp_audit_enqueue_reports_backpressure() {
        let event = NetworkEvent::UdpFlowAttempt {
            sandbox_id: SandboxId::new("test").unwrap(),
            frontend: Frontend::Tun,
            source: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)), 44_444),
            destination: TransportEndpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 53),
            attribution: Attribution::ip_only(),
            classification: Protocol::Dns,
        };
        let decision = PolicyEngine::new(PolicyRuleSet::default()).evaluate(&event);
        let mut audit = audit_buffer(1).unwrap();

        emit_udp_audit(&mut audit, &event, decision.clone()).unwrap();
        let error = emit_udp_audit(&mut audit, &event, decision).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn udp_audit_rejects_zero_capacity() {
        assert_eq!(
            audit_buffer(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn udp_attribution_uses_dns_cache_for_destination_ip() {
        let sandbox_id = SandboxId::new("test").unwrap();
        let config = UdpDnsProofConfig::new(sandbox_id.clone());
        let now = SystemTime::now();
        let observation = DnsObservation {
            sandbox_id,
            hostname: Hostname::parse("video.example.com").unwrap(),
            query_type: DnsQueryType::A,
            observed_at: now,
            broker_controlled: true,
        };
        let entry = DnsCacheEntry::new(
            observation,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            Duration::from_secs(60),
        )
        .unwrap();
        let mut cache = DnsCache::default();
        cache.insert(entry);

        let attribution = udp_attribution_for_destination(
            &config,
            &cache,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            now,
        );
        assert_eq!(
            attribution.hostname.as_ref().unwrap().as_str(),
            "video.example.com"
        );
        assert_eq!(attribution.source, AttributionSource::DnsCache);
        assert_eq!(attribution.confidence, AttributionConfidence::Medium);
    }
}
