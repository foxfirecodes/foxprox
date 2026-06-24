//! Device IO adapters for foxprox alpha runtime integration.
//!
//! `foxprox-core` owns policy/audit/packet contracts. This crate provides a
//! small TUN-like packet device adapter over replaceable `Read`/`Write` objects
//! so Linux-specific TUN opening can be added without changing core logic.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditKind, AuditRecord, Decision, DenialReason, DeviceIoError, Frontend, NetworkSetupConfig,
    PacketDevice,
};
use std::io::{Read, Write};

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
const TUN_FD_HANDOFF_VERSION: &str = "foxprox-tun-fd-v1";

#[derive(Debug)]
pub struct TunIoPacketDevice<RW> {
    io: RW,
    mtu: usize,
}

impl<RW> TunIoPacketDevice<RW> {
    pub fn new(io: RW, mtu: usize) -> Self {
        Self { io, mtu }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn into_inner(self) -> RW {
        self.io
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunFdHandoffStatus {
    Sent,
    Received,
    Opened,
    Failed,
}

#[cfg(unix)]
impl TunFdHandoffStatus {
    fn as_detail(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
            Self::Opened => "opened",
            Self::Failed => "failed",
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunFdHandoffErrorKind {
    SendFailed,
    ReceiveFailed,
    MissingFd,
    UnexpectedPayload,
    MultipleFds,
    OpenFailed,
}

#[cfg(unix)]
impl TunFdHandoffErrorKind {
    fn as_detail(self) -> &'static str {
        match self {
            Self::SendFailed => "send_failed",
            Self::ReceiveFailed => "receive_failed",
            Self::MissingFd => "missing_fd",
            Self::UnexpectedPayload => "unexpected_payload",
            Self::MultipleFds => "multiple_fds",
            Self::OpenFailed => "open_failed",
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunFdHandoffSource {
    ScmRights,
    DeviceOpen,
}

#[cfg(unix)]
impl TunFdHandoffSource {
    fn as_detail(self) -> &'static str {
        match self {
            Self::ScmRights => "scm_rights",
            Self::DeviceOpen => "device_open",
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunFdHandoffReport {
    pub tun_name: String,
    pub status: TunFdHandoffStatus,
    pub source: TunFdHandoffSource,
    pub payload: String,
    pub fd_count: usize,
    pub device_path: Option<PathBuf>,
    pub error: Option<TunFdHandoffErrorKind>,
}

#[cfg(unix)]
impl TunFdHandoffReport {
    pub fn sent(tun_name: impl Into<String>, fd_count: usize) -> Self {
        let tun_name = tun_name.into();
        Self {
            payload: handoff_payload(&tun_name),
            tun_name,
            status: TunFdHandoffStatus::Sent,
            source: TunFdHandoffSource::ScmRights,
            fd_count,
            device_path: None,
            error: None,
        }
    }

    pub fn received(tun_name: impl Into<String>, fd_count: usize) -> Self {
        let tun_name = tun_name.into();
        Self {
            payload: handoff_payload(&tun_name),
            tun_name,
            status: TunFdHandoffStatus::Received,
            source: TunFdHandoffSource::ScmRights,
            fd_count,
            device_path: None,
            error: None,
        }
    }

    pub fn failed(
        tun_name: impl Into<String>,
        payload: impl Into<String>,
        fd_count: usize,
        error: TunFdHandoffErrorKind,
    ) -> Self {
        Self {
            tun_name: tun_name.into(),
            status: TunFdHandoffStatus::Failed,
            source: TunFdHandoffSource::ScmRights,
            payload: payload.into(),
            fd_count,
            device_path: None,
            error: Some(error),
        }
    }

    pub fn for_opened_device(path: impl Into<PathBuf>, tun_name: impl Into<String>) -> Self {
        let tun_name = tun_name.into();
        Self {
            payload: String::new(),
            tun_name,
            status: TunFdHandoffStatus::Opened,
            source: TunFdHandoffSource::DeviceOpen,
            fd_count: 1,
            device_path: Some(path.into()),
            error: None,
        }
    }

    pub fn failed_open(path: impl Into<PathBuf>, tun_name: impl Into<String>) -> Self {
        let tun_name = tun_name.into();
        Self {
            payload: String::new(),
            tun_name,
            status: TunFdHandoffStatus::Failed,
            source: TunFdHandoffSource::DeviceOpen,
            fd_count: 0,
            device_path: Some(path.into()),
            error: Some(TunFdHandoffErrorKind::OpenFailed),
        }
    }

    pub fn audit_record(&self, sandbox_id: impl Into<String>) -> AuditRecord {
        let mut record = if self.status == TunFdHandoffStatus::Failed {
            AuditRecord::new(AuditKind::BrokerError, sandbox_id.into())
                .with_frontend(Frontend::Setup)
                .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        } else if self.source == TunFdHandoffSource::DeviceOpen {
            AuditRecord::new(AuditKind::TunFdOpened, sandbox_id.into())
                .with_frontend(Frontend::Setup)
                .with_decision(Decision::Allow, None)
        } else {
            AuditRecord::new(AuditKind::TunConfigured, sandbox_id.into())
                .with_frontend(Frontend::Setup)
                .with_decision(Decision::Allow, None)
        }
        .with_detail("tun_name", self.tun_name.clone())
        .with_detail("fd_source", self.source.as_detail())
        .with_detail("handoff_status", self.status.as_detail())
        .with_detail("fd_count", self.fd_count.to_string());
        if !self.payload.is_empty() {
            record = record.with_detail("handoff_payload", self.payload.clone());
        }
        if let Some(path) = &self.device_path {
            record = record.with_detail("device_path", path.display().to_string());
        }
        if let Some(error) = self.error {
            record = record.with_detail("handoff_error", error.as_detail());
        }
        record
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub struct ReceivedTunFd {
    pub fd: OwnedFd,
    pub report: TunFdHandoffReport,
}

#[cfg(unix)]
impl ReceivedTunFd {
    pub fn into_file_device(self, mtu: usize) -> (TunIoPacketDevice<File>, TunFdHandoffReport) {
        (
            TunIoPacketDevice::new(File::from(self.fd), mtu),
            self.report,
        )
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunSetupHandoffStatus {
    Complete,
    Failed,
}

#[cfg(unix)]
impl TunSetupHandoffStatus {
    fn as_detail(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct TunSetupHandoffReport {
    pub status: TunSetupHandoffStatus,
    pub completed_steps: Vec<&'static str>,
    pub failed_step: Option<&'static str>,
    pub open_report: Option<TunFdHandoffReport>,
    pub configure_record: Option<AuditRecord>,
    pub handoff_report: Option<TunFdHandoffReport>,
    pub audit_records: Vec<AuditRecord>,
}

#[cfg(unix)]
impl TunSetupHandoffReport {
    fn new() -> Self {
        Self {
            status: TunSetupHandoffStatus::Complete,
            completed_steps: Vec::new(),
            failed_step: None,
            open_report: None,
            configure_record: None,
            handoff_report: None,
            audit_records: Vec::new(),
        }
    }

    fn fail(mut self, failed_step: &'static str, audit: AuditRecord) -> Self {
        self.status = TunSetupHandoffStatus::Failed;
        self.failed_step = Some(failed_step);
        self.audit_records.push(audit);
        self
    }

    pub fn summary_audit(&self, sandbox_id: impl Into<String>) -> AuditRecord {
        let mut record = if self.status == TunSetupHandoffStatus::Failed {
            AuditRecord::new(AuditKind::BrokerError, sandbox_id.into())
                .with_frontend(Frontend::Setup)
                .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        } else {
            AuditRecord::new(AuditKind::TunConfigured, sandbox_id.into())
                .with_frontend(Frontend::Setup)
                .with_decision(Decision::Allow, None)
        }
        .with_detail("setup_status", self.status.as_detail())
        .with_detail("completed_steps", self.completed_steps.join(","));
        if let Some(step) = self.failed_step {
            record = record.with_detail("failed_step", step);
        }
        record
    }
}

#[cfg(unix)]
pub trait TunSetupDeviceOps {
    type TunFd: AsFd;

    fn open_tun(
        &mut self,
        config: &NetworkSetupConfig,
    ) -> Result<(Self::TunFd, TunFdHandoffReport), TunFdHandoffReport>;

    fn configure_tun(
        &mut self,
        config: &NetworkSetupConfig,
        fd: &Self::TunFd,
    ) -> Result<AuditRecord, Box<AuditRecord>>;

    fn send_tun_fd(
        &mut self,
        control: &UnixStream,
        config: &NetworkSetupConfig,
        fd: &Self::TunFd,
    ) -> Result<TunFdHandoffReport, TunFdHandoffReport>;
}

#[cfg(unix)]
pub fn execute_tun_setup_handoff<O: TunSetupDeviceOps>(
    ops: &mut O,
    control: &UnixStream,
    config: &NetworkSetupConfig,
) -> TunSetupHandoffReport {
    let mut report = TunSetupHandoffReport::new();
    let (tun_fd, open_report) = match ops.open_tun(config) {
        Ok(result) => result,
        Err(open_report) => {
            let audit = open_report.audit_record(config.sandbox_id.clone());
            report.open_report = Some(open_report);
            return report.fail("open_tun", audit);
        }
    };
    report
        .audit_records
        .push(open_report.audit_record(config.sandbox_id.clone()));
    report.open_report = Some(open_report);
    report.completed_steps.push("open_tun");

    let configure_record = match ops.configure_tun(config, &tun_fd) {
        Ok(record) => record,
        Err(record) => return report.fail("configure_tun", *record),
    };
    report.audit_records.push(configure_record.clone());
    report.configure_record = Some(configure_record);
    report.completed_steps.push("configure_tun");

    let handoff_report = match ops.send_tun_fd(control, config, &tun_fd) {
        Ok(report) => report,
        Err(handoff_report) => {
            let audit = handoff_report.audit_record(config.sandbox_id.clone());
            report.handoff_report = Some(handoff_report);
            return report.fail("handoff_tun_fd", audit);
        }
    };
    report
        .audit_records
        .push(handoff_report.audit_record(config.sandbox_id.clone()));
    report.handoff_report = Some(handoff_report);
    report.completed_steps.push("handoff_tun_fd");
    report
}

#[cfg(unix)]
pub fn open_dev_net_tun_handoff(
    tun_name: impl Into<String>,
) -> Result<(File, TunFdHandoffReport), TunFdHandoffReport> {
    open_tun_device_path("/dev/net/tun", tun_name)
}

#[cfg(unix)]
pub fn open_tun_device_path(
    path: impl AsRef<Path>,
    tun_name: impl Into<String>,
) -> Result<(File, TunFdHandoffReport), TunFdHandoffReport> {
    let path = path.as_ref().to_path_buf();
    let tun_name = tun_name.into();
    match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => Ok((file, TunFdHandoffReport::for_opened_device(path, tun_name))),
        Err(_) => Err(TunFdHandoffReport::failed_open(path, tun_name)),
    }
}

#[cfg(unix)]
pub fn send_tun_fd(
    control: &UnixStream,
    tun_name: impl AsRef<str>,
    fd: &impl std::os::fd::AsFd,
) -> Result<TunFdHandoffReport, TunFdHandoffReport> {
    use unix_ancillary::UnixStreamExt;

    let tun_name = tun_name.as_ref();
    let payload = handoff_payload(tun_name);
    match control.send_fds(payload.as_bytes(), &[fd]) {
        Ok(_) => Ok(TunFdHandoffReport::sent(tun_name, 1)),
        Err(_) => Err(TunFdHandoffReport::failed(
            tun_name,
            payload,
            0,
            TunFdHandoffErrorKind::SendFailed,
        )),
    }
}

#[cfg(unix)]
pub fn recv_tun_fd(
    control: &UnixStream,
    expected_tun_name: impl AsRef<str>,
) -> Result<ReceivedTunFd, TunFdHandoffReport> {
    use unix_ancillary::UnixStreamExt;

    let expected_tun_name = expected_tun_name.as_ref();
    let received = match control.recv_fds::<2>() {
        Ok(received) => received,
        Err(_) => {
            return Err(TunFdHandoffReport::failed(
                expected_tun_name,
                "",
                0,
                TunFdHandoffErrorKind::ReceiveFailed,
            ));
        }
    };
    let payload = String::from_utf8_lossy(&received.data).to_string();
    if payload != handoff_payload(expected_tun_name) {
        return Err(TunFdHandoffReport::failed(
            expected_tun_name,
            payload,
            received.fds.len(),
            TunFdHandoffErrorKind::UnexpectedPayload,
        ));
    }
    if received.fds.is_empty() {
        return Err(TunFdHandoffReport::failed(
            expected_tun_name,
            payload,
            0,
            TunFdHandoffErrorKind::MissingFd,
        ));
    }
    if received.fds.len() != 1 {
        return Err(TunFdHandoffReport::failed(
            expected_tun_name,
            payload,
            received.fds.len(),
            TunFdHandoffErrorKind::MultipleFds,
        ));
    }
    let mut fds = received.fds;
    Ok(ReceivedTunFd {
        fd: fds.pop().unwrap(),
        report: TunFdHandoffReport::received(expected_tun_name, 1),
    })
}

#[cfg(unix)]
fn handoff_payload(tun_name: &str) -> String {
    format!("{TUN_FD_HANDOFF_VERSION}:{tun_name}")
}

impl<RW: Read + Write> PacketDevice for TunIoPacketDevice<RW> {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
        let mut packet = vec![0u8; self.mtu.max(1)];
        match self.io.read(&mut packet) {
            Ok(0) => Ok(None),
            Ok(len) => {
                packet.truncate(len);
                Ok(Some(packet))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(DeviceIoError::ReadFailed),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceIoError> {
        if packet.len() > self.mtu {
            return Err(DeviceIoError::WriteFailed);
        }
        self.io
            .write_all(packet)
            .map_err(|_| DeviceIoError::WriteFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        checksum, BrokerCore, Decision, PolicyConfig, PolicyEngine, TunPacketHarness,
    };
    use pretty_assertions::assert_eq;
    use std::collections::VecDeque;
    use std::io;

    #[derive(Debug, Default)]
    struct ScriptedTunIo {
        reads: VecDeque<io::Result<Vec<u8>>>,
        writes: Vec<Vec<u8>>,
        fail_writes: bool,
    }

    impl ScriptedTunIo {
        fn with_packets(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                reads: packets.into_iter().map(Ok).collect(),
                writes: Vec::new(),
                fail_writes: false,
            }
        }
    }

    impl Read for ScriptedTunIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                Some(Ok(packet)) => {
                    let len = packet.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                }
                Some(Err(error)) => Err(error),
                None => Ok(0),
            }
        }
    }

    impl Write for ScriptedTunIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_writes {
                return Err(io::Error::other("write failed"));
            }
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tun_io_device_feeds_packet_harness_observation() {
        let packet = ipv4_packet(17, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let io = ScriptedTunIo::with_packets([packet]);
        let device = TunIoPacketDevice::new(io, 1500);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(1_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[0].details["packet_len"], "28");
    }

    #[test]
    fn tun_io_device_writes_icmp_reply_after_audit() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, &icmp);
        let io = ScriptedTunIo::with_packets([packet]);
        let device = TunIoPacketDevice::new(io, 1500);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(2_000).unwrap().unwrap();
        assert!(result.wrote_packet);
        let (_, device) = harness.into_parts();
        let io = device.into_inner();
        assert_eq!(io.writes.len(), 1);
        assert_eq!(io.writes[0][20], 0);
    }

    #[test]
    fn tun_io_device_maps_would_block_to_idle_read() {
        let mut io = ScriptedTunIo::default();
        io.reads.push_back(Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "no packet ready",
        )));
        let mut device = TunIoPacketDevice::new(io, 1500);

        assert_eq!(device.read_packet().unwrap(), None);
    }

    #[test]
    fn tun_io_device_maps_read_write_failures() {
        let mut read_fail = ScriptedTunIo::default();
        read_fail
            .reads
            .push_back(Err(io::Error::other("read failed")));
        let mut device = TunIoPacketDevice::new(read_fail, 1500);
        assert_eq!(device.read_packet().unwrap_err(), DeviceIoError::ReadFailed);

        let write_fail = ScriptedTunIo {
            fail_writes: true,
            ..ScriptedTunIo::default()
        };
        let mut device = TunIoPacketDevice::new(write_fail, 1500);
        assert_eq!(
            device.write_packet(b"abc").unwrap_err(),
            DeviceIoError::WriteFailed
        );
        assert_eq!(
            device.write_packet(&vec![0; 1501]).unwrap_err(),
            DeviceIoError::WriteFailed
        );
    }

    #[cfg(unix)]
    #[test]
    fn tun_fd_handoff_receives_packet_device_and_audits_success() {
        let (control_tx, control_rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let (tun_fd, mut sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();

        let send_report = send_tun_fd(&control_tx, "foxprox0", &tun_fd).unwrap();
        assert_eq!(send_report.status, TunFdHandoffStatus::Sent);
        assert_eq!(send_report.fd_count, 1);
        assert_eq!(
            send_report.audit_record("s1").kind,
            AuditKind::TunConfigured
        );

        let received = recv_tun_fd(&control_rx, "foxprox0").unwrap();
        assert_eq!(received.report.status, TunFdHandoffStatus::Received);
        assert_eq!(received.report.fd_count, 1);
        let audit = received.report.audit_record("s1");
        assert_eq!(audit.kind, AuditKind::TunConfigured);
        assert_eq!(audit.details["fd_source"], "scm_rights");
        assert_eq!(audit.details["handoff_status"], "received");
        assert_eq!(audit.details["tun_name"], "foxprox0");

        let received_tun = std::os::unix::net::UnixStream::from(received.fd);
        let mut device = TunIoPacketDevice::new(received_tun, 1500);
        sandbox_peer.write_all(b"handoff-packet").unwrap();
        assert_eq!(
            device.read_packet().unwrap(),
            Some(b"handoff-packet".to_vec())
        );
        device.write_packet(b"handoff-reply").unwrap();
        let mut reply = [0u8; 13];
        sandbox_peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"handoff-reply");
    }

    #[cfg(unix)]
    #[test]
    fn tun_fd_handoff_fails_closed_for_wrong_payload() {
        use unix_ancillary::UnixStreamExt;

        let (control_tx, control_rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let (tun_fd, _sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        control_tx.send_fds(b"wrong-payload", &[&tun_fd]).unwrap();

        let report = recv_tun_fd(&control_rx, "foxprox0").unwrap_err();
        assert_eq!(report.status, TunFdHandoffStatus::Failed);
        assert_eq!(report.error, Some(TunFdHandoffErrorKind::UnexpectedPayload));
        assert_eq!(report.fd_count, 1);
        let audit = report.audit_record("s1");
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.decision, Some(Decision::FailClosed));
        assert_eq!(audit.details["fd_source"], "scm_rights");
        assert_eq!(audit.details["handoff_error"], "unexpected_payload");
    }

    #[cfg(unix)]
    #[derive(Debug)]
    struct ScriptedTunSetupOps {
        tun_fd: Option<std::os::unix::net::UnixStream>,
        fail_configure: bool,
        fail_handoff: bool,
    }

    #[cfg(unix)]
    impl TunSetupDeviceOps for ScriptedTunSetupOps {
        type TunFd = std::os::unix::net::UnixStream;

        fn open_tun(
            &mut self,
            config: &NetworkSetupConfig,
        ) -> Result<(Self::TunFd, TunFdHandoffReport), TunFdHandoffReport> {
            let fd = self.tun_fd.take().unwrap();
            Ok((
                fd,
                TunFdHandoffReport::for_opened_device("/dev/net/tun", &config.tun_name),
            ))
        }

        fn configure_tun(
            &mut self,
            config: &NetworkSetupConfig,
            _fd: &Self::TunFd,
        ) -> Result<AuditRecord, Box<AuditRecord>> {
            let record = if self.fail_configure {
                AuditRecord::new(AuditKind::BrokerError, config.sandbox_id.clone())
                    .with_frontend(Frontend::Setup)
                    .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                    .with_detail("setup_step", "configure_tun")
                    .with_detail("tun_name", config.tun_name.clone())
                    .with_detail("configure_error", "scripted")
            } else {
                AuditRecord::new(AuditKind::TunConfigured, config.sandbox_id.clone())
                    .with_frontend(Frontend::Setup)
                    .with_decision(Decision::Allow, None)
                    .with_detail("setup_step", "configure_tun")
                    .with_detail("tun_name", config.tun_name.clone())
                    .with_detail("mtu", config.mtu.to_string())
            };
            if self.fail_configure {
                Err(Box::new(record))
            } else {
                Ok(record)
            }
        }

        fn send_tun_fd(
            &mut self,
            control: &std::os::unix::net::UnixStream,
            config: &NetworkSetupConfig,
            fd: &Self::TunFd,
        ) -> Result<TunFdHandoffReport, TunFdHandoffReport> {
            if self.fail_handoff {
                return Err(TunFdHandoffReport::failed(
                    &config.tun_name,
                    "",
                    0,
                    TunFdHandoffErrorKind::SendFailed,
                ));
            }
            send_tun_fd(control, &config.tun_name, fd)
        }
    }

    #[cfg(unix)]
    #[test]
    fn tun_setup_handoff_executor_orders_open_configure_and_handoff_evidence() {
        let config = NetworkSetupConfig::alpha_default("s1");
        let (control_tx, control_rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let (tun_fd, mut sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut ops = ScriptedTunSetupOps {
            tun_fd: Some(tun_fd),
            fail_configure: false,
            fail_handoff: false,
        };

        let report = execute_tun_setup_handoff(&mut ops, &control_tx, &config);
        assert_eq!(report.status, TunSetupHandoffStatus::Complete);
        assert_eq!(
            report.completed_steps,
            vec!["open_tun", "configure_tun", "handoff_tun_fd"]
        );
        assert_eq!(report.failed_step, None);
        assert_eq!(report.audit_records[0].kind, AuditKind::TunFdOpened);
        assert_eq!(report.audit_records[1].kind, AuditKind::TunConfigured);
        assert_eq!(
            report.audit_records[1].details["setup_step"],
            "configure_tun"
        );
        assert_eq!(report.audit_records[2].kind, AuditKind::TunConfigured);
        assert_eq!(report.audit_records[2].details["fd_source"], "scm_rights");
        let summary = report.summary_audit("s1");
        assert_eq!(summary.kind, AuditKind::TunConfigured);
        assert_eq!(summary.details["setup_status"], "complete");

        let received = recv_tun_fd(&control_rx, "foxprox0").unwrap();
        let received_tun = std::os::unix::net::UnixStream::from(received.fd);
        let mut device = TunIoPacketDevice::new(received_tun, config.mtu as usize);
        sandbox_peer.write_all(b"setup-handoff-packet").unwrap();
        assert_eq!(
            device.read_packet().unwrap(),
            Some(b"setup-handoff-packet".to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn tun_setup_handoff_executor_fails_closed_before_handoff_on_configure_error() {
        let config = NetworkSetupConfig::alpha_default("s1");
        let (control_tx, _control_rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let (tun_fd, _sandbox_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut ops = ScriptedTunSetupOps {
            tun_fd: Some(tun_fd),
            fail_configure: true,
            fail_handoff: false,
        };

        let report = execute_tun_setup_handoff(&mut ops, &control_tx, &config);
        assert_eq!(report.status, TunSetupHandoffStatus::Failed);
        assert_eq!(report.completed_steps, vec!["open_tun"]);
        assert_eq!(report.failed_step, Some("configure_tun"));
        assert!(report.handoff_report.is_none());
        assert_eq!(report.audit_records[0].kind, AuditKind::TunFdOpened);
        assert_eq!(report.audit_records[1].kind, AuditKind::BrokerError);
        assert_eq!(report.audit_records[1].decision, Some(Decision::FailClosed));
        assert_eq!(
            report.audit_records[1].details["setup_step"],
            "configure_tun"
        );
        let summary = report.summary_audit("s1");
        assert_eq!(summary.kind, AuditKind::BrokerError);
        assert_eq!(summary.details["setup_status"], "failed");
        assert_eq!(summary.details["failed_step"], "configure_tun");
    }

    #[cfg(unix)]
    #[test]
    fn tun_device_open_reports_success_or_fail_closed_evidence() {
        let path = std::env::temp_dir().join(format!(
            "foxprox-dev-net-tun-{}-open-test",
            std::process::id()
        ));
        std::fs::write(&path, b"").unwrap();
        let (_file, report) = open_tun_device_path(&path, "foxprox0").unwrap();
        assert_eq!(report.status, TunFdHandoffStatus::Opened);
        assert_eq!(report.fd_count, 1);
        assert_eq!(report.device_path.as_deref(), Some(path.as_path()));
        let audit = report.audit_record("s1");
        assert_eq!(audit.kind, AuditKind::TunFdOpened);
        assert_eq!(audit.details["fd_source"], "device_open");
        assert_eq!(audit.details["handoff_status"], "opened");
        assert_eq!(audit.details["device_path"], path.display().to_string());
        assert!(!audit.details.contains_key("handoff_payload"));
        let _ = std::fs::remove_file(&path);

        let missing = std::env::temp_dir().join(format!(
            "foxprox-dev-net-tun-{}-missing",
            std::process::id()
        ));
        let report = open_tun_device_path(&missing, "foxprox0").unwrap_err();
        assert_eq!(report.status, TunFdHandoffStatus::Failed);
        assert_eq!(report.error, Some(TunFdHandoffErrorKind::OpenFailed));
        let audit = report.audit_record("s1");
        assert_eq!(audit.kind, AuditKind::BrokerError);
        assert_eq!(audit.details["fd_source"], "device_open");
        assert_eq!(audit.details["handoff_error"], "open_failed");
        assert_eq!(audit.details["device_path"], missing.display().to_string());
    }

    fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 2, 15]);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        packet[20..].copy_from_slice(payload);
        let csum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&csum.to_be_bytes());
        packet
    }
}
