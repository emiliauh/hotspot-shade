//! Bounded, flow-affine packet relay. The caller owns the tunnel device.
//!
//! The relay is portable. It compiles on macOS, Linux, and Windows. The
//! Windows source device proxy path uses the readiness waits in
//! [`crate::relay_poll`].
use crate::relay_poll::{self, Interest, PollSet, WakePair, WakeReceiver, WakeSender};
use crate::{diagnostics, failures, normalization, packet, pairing, phone, tcp};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const QUEUE: usize = 4096;
// Keep a bounded number of slots for TCP close and reset packets.
const TCP_CONTROL_RESERVE: usize = 64;
const MAX_PENDING_RESETS: usize = 64;
const RESET_RETRY: Duration = Duration::from_millis(100);
const MAX_RESET_ATTEMPTS: u8 = 3;
const MAX_CLOSED_TCP: usize = 128;
const CLOSED_TCP_LIFETIME: Duration = Duration::from_secs(30);
// Bound the memory reserved by flow buffers when traffic is heavy.
const MAX_FLOWS_PER_WORKER: usize = 128;
const MAX_UDP_BUFFER: usize = 512 * 1024;
// Bound the target device to source device queue of one UDP flow. A large queue adds delay
// for real-time traffic when the hotspot link is slow. The relay drops new
// datagrams when the queue is full. UDP senders treat the drop as loss.
const MAX_UDP_OUTGOING: usize = 128 * 1024;
// Drop a queued datagram that waits longer than this for the phone stream.
// Real-time senders discard such a datagram anyway. The age limit does not
// apply to DNS flows, and it starts after the phone handshake ends.
const MAX_UDP_OUTGOING_AGE: Duration = Duration::from_millis(250);

/// Track the age of each length-prefixed frame in a UDP-over-TCP output buffer.
/// The buffer holds frames in order. The first frame can be partly written.
/// A partly written frame must stay in the buffer. Whole frames can leave it.
struct UdpFrameQueue {
    // Full frame length (prefix included) and enqueue time, oldest first.
    frames: VecDeque<(usize, Instant)>,
    // Bytes of the first frame that the stream already accepted.
    front_sent: usize,
}
impl UdpFrameQueue {
    fn new() -> Self {
        UdpFrameQueue {
            frames: VecDeque::new(),
            front_sent: 0,
        }
    }
    fn push(&mut self, frame_len: usize, at: Instant) {
        self.frames.push_back((frame_len, at));
    }
    /// Record that the stream accepted `n` bytes from the front of the buffer.
    fn advance(&mut self, mut n: usize) {
        while n > 0 {
            let Some(&(len, _)) = self.frames.front() else {
                self.front_sent = 0;
                return;
            };
            let remaining = len - self.front_sent;
            if n >= remaining {
                n -= remaining;
                self.frames.pop_front();
                self.front_sent = 0;
            } else {
                self.front_sent += n;
                return;
            }
        }
    }
    /// Restart the clock for every queued frame. Call this when the setup ends.
    fn restamp(&mut self, now: Instant) {
        for frame in self.frames.iter_mut() {
            frame.1 = now;
        }
    }
    /// Remove whole frames older than `max_age` from `buffer`. Return the count.
    /// Frames are oldest first, so the scan stops at the first fresh frame.
    fn expire(&mut self, buffer: &mut Vec<u8>, now: Instant, max_age: Duration) -> u64 {
        let mut dropped = 0;
        let mut offset = 0;
        let mut index = 0;
        while index < self.frames.len() {
            let (len, at) = self.frames[index];
            let partial = index == 0 && self.front_sent > 0;
            if partial {
                // The partly written frame must finish. Skip its remaining bytes.
                offset += len - self.front_sent;
                index += 1;
                continue;
            }
            if now.saturating_duration_since(at) < max_age {
                break;
            }
            buffer.drain(offset..offset + len);
            self.frames.remove(index);
            dropped += 1;
        }
        dropped
    }
}
const MAX_DATAGRAM: usize = 1472;
const UDP_IDLE: Duration = Duration::from_secs(120);
// A UDP flow can yield its flow slot to a new TCP flow after this long without
// traffic in either direction. This limit is shorter than the UDP idle timeout.
// The relay evicts only at the flow cap and only a flow with no pending work.
const UDP_EVICT_IDLE: Duration = Duration::from_secs(30);
const DNS_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ICMP_ACTIVE: usize = 8;
const ICMP_TIMEOUT: Duration = Duration::from_secs(8);
const ICMP_SESSION_IDLE: Duration = Duration::from_secs(5);
const ICMP_SESSION_MAX_AGE: Duration = Duration::from_secs(300);
const ICMP_PENDING_LIMIT: usize = 4;

/// Fixed text for the first outer socket keepalive failure in a process.
pub(crate) const KEEPALIVE_FAILED_MESSAGE: &str =
    "[relay] tcp keepalive could not be enabled on an outer socket; flows continue without dead-peer detection";

static KEEPALIVE_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);

/// Turn on TCP keepalive for an outer socket without failing the flow.
///
/// A rejected keepalive leaves the flow usable, but a silent dead peer is then
/// found only by an application timeout. The first failure in the process is
/// written once to standard error with fixed text. The text holds no address
/// and no error detail. Later failures are not repeated.
pub(crate) fn enable_outer_keepalive(stream: &TcpStream) {
    let result =
        normalization::set_tcp_keepalive(stream, normalization::TcpKeepalive::SOURCE_DEVICE);
    if first_keepalive_failure(&result, &KEEPALIVE_FAILURE_REPORTED) {
        eprintln!("{KEEPALIVE_FAILED_MESSAGE}");
    }
}

/// Return true only for the first failed result seen through `reported`.
fn first_keepalive_failure(result: &io::Result<()>, reported: &AtomicBool) -> bool {
    result.is_err() && !reported.swap(true, Ordering::Relaxed)
}

// Phone proxy streams carry small control and echo frames as well as data.
fn phone_tcp_start(
    address: SocketAddr,
    iface: Option<u32>,
    audit: &normalization::Audit,
) -> io::Result<TcpStream> {
    let stream = normalization::tcp_start(address, iface, audit)?;
    enable_outer_keepalive(&stream);
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn direct_tcp_start(
    address: SocketAddr,
    iface: Option<u32>,
    audit: &normalization::Audit,
) -> io::Result<TcpStream> {
    let stream = normalization::tcp_start(address, iface, audit)?;
    enable_outer_keepalive(&stream);
    Ok(stream)
}

#[derive(Clone)]
pub struct RelayConfig {
    pub iface: Option<u32>,
    pub phone: Option<Arc<phone::PhoneProxy>>,
    pub dns_upstream: Option<SocketAddr>,
    pub workers: usize,
    /// Permit IPv6 inner packets only when the service installs IPv6 routes.
    pub ipv6_forward: bool,
    /// Enable the experimental authenticated phone echo protocol explicitly.
    pub icmp_phone: bool,
    /// Reuse a phone echo session only for the same inner ICMP flow.
    pub icmp_persistent: bool,
    /// Diagnostic mode only. Production callers must set a hotspot interface.
    pub allow_unpinned: bool,
    /// Bounded in-memory record of failed source device setups.
    pub failures: Option<Arc<failures::FailureRecorder>>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            iface: None,
            phone: None,
            dns_upstream: None,
            workers: 2,
            allow_unpinned: false,
            ipv6_forward: false,
            icmp_phone: false,
            icmp_persistent: false,
            failures: None,
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct RelayStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tcp_flows: u64,
    pub tcp_flows_closed: u64,
    /// Live target relay TCP flow table entries. This counts current flows of
    /// this relay only: it holds a flow while its setup is still running,
    /// excludes UDP and ICMP, and holds no count from another device.
    pub tcp_flows_active: u64,
    pub udp_flows_closed: u64,
    pub udp_datagrams_in: u64,
    pub udp_datagrams_out: u64,
    pub udp_errors: u64,
    pub udp_dropped: u64,
    pub udp_reply_too_big: u64,
    pub ttl_bad: u64,
    pub ipv6_dropped: u64,
    pub fragments_dropped: u64,
    pub icmp_dropped: u64,
    pub icmp_requests: u64,
    pub icmp_replies: u64,
    pub icmp_errors: u64,
    pub icmp_setup_errors: u64,
    pub icmp_timeouts: u64,
    pub icmp_phone_no_cellular: u64,
    pub icmp_phone_busy: u64,
    pub icmp_phone_timeout: u64,
    pub icmp_phone_failed: u64,
    pub icmp_phone_path_no_update: u64,
    pub icmp_phone_path_unsatisfied: u64,
    pub icmp_phone_path_not_cellular: u64,
    pub icmp_phone_path_no_interface: u64,
    pub icmp_phone_path_ambiguous: u64,
    pub icmp_malformed: u64,
    pub icmp_payload_mismatch: u64,
    pub icmp_io_errors: u64,
    pub icmp_output_errors: u64,
    pub send_dropped: u64,
    pub flow_errors: u64,
    pub queue_dropped: u64,
    pub tcp_setup_errors: u64,
    pub tcp_io_errors: u64,
    pub tcp_setup_refused: u64,
    pub tcp_setup_timed_out: u64,
    pub tcp_setup_timeout_phone_connect: u64,
    pub tcp_setup_timeout_phone_auth: u64,
    /// Retained for the diagnostics shape. A local phone deadline is not proof
    /// that the destination timed out, and no SOCKS reply code means timeout.
    /// This counter therefore stays zero. Direct timeouts use the direct
    /// counter below.
    pub tcp_setup_timeout_phone_destination: u64,
    pub tcp_setup_timeout_direct_connect: u64,
    pub tcp_setup_permission_denied: u64,
    pub tcp_setup_other: u64,
    pub tcp_setup_phone_unreachable: u64,
    /// TCP flows reset because the worker flow table was full.
    pub tcp_capacity_refused: u64,
    /// UDP flows closed to make room for a new TCP flow.
    pub udp_flows_evicted: u64,
    pub dns_flows: u64,
    pub dns_setup_ok: u64,
    pub dns_setup_failed: u64,
    pub tcp_ack_rtt_samples: u64,
    pub tcp_ack_rtt_sum_us: u64,
    pub tcp_ack_rtt_max_us: u64,
    pub tcp_window_limited_us: u64,
    pub tcp_upload_buffer_peak_bytes: u64,
    pub tcp_download_buffer_peak_bytes: u64,
    /// Destination-privacy counters. Every value is zero while only the `off`
    /// mode is supported.
    pub destination_privacy: DestinationPrivacyStats,
    pub input_queues: Vec<QueueStats>,
    pub output_queue: QueueStats,
}

/// Destination-privacy counters.
///
/// The keys are the stable contract shared with
/// `diagnostics::zero_destination_privacy_counters()`. A counter is an event
/// count only: it never holds a name, an address, a certificate, or an ECH
/// config. No code path increments one today, because no mode other than `off`
/// exists. The wiring for a mode increments these counters and nothing else.
#[derive(Default, Clone, Copy, Debug)]
pub struct DestinationPrivacyStats {
    pub flows: u64,
    pub shaped_flows: u64,
    pub shaped_errors: u64,
    pub ech_attempts: u64,
    pub ech_ok: u64,
    pub ech_grease: u64,
    pub ech_rejected: u64,
    pub ech_fallback: u64,
    pub doh_lookups: u64,
    pub doh_ok: u64,
    pub doh_failed: u64,
    pub cover_flows: u64,
    pub cover_errors: u64,
}

/// Queue occupancy and longest observed dequeue delay, in microseconds.
#[derive(Default, Clone, Debug)]
pub struct QueueStats {
    pub packets_current: u64,
    pub packets_peak: u64,
    pub max_age_us: u64,
}

#[derive(Default)]
struct QueueMetrics(Mutex<QueueStats>);
impl QueueMetrics {
    fn snapshot(&self) -> QueueStats {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
struct QueuedPacket {
    data: Vec<u8>,
    since: Instant,
    metrics: Option<Arc<QueueMetrics>>,
}
impl QueuedPacket {
    fn consume(mut self) -> Vec<u8> {
        if let Some(metrics) = self.metrics.take() {
            let mut stats = metrics.0.lock().unwrap_or_else(|e| e.into_inner());
            stats.packets_current -= 1;
            let age = self.since.elapsed().as_micros().min(u64::MAX as u128) as u64;
            stats.max_age_us = stats.max_age_us.max(age);
        }
        std::mem::take(&mut self.data)
    }
}
impl Drop for QueuedPacket {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics.take() {
            let mut stats = metrics.0.lock().unwrap_or_else(|e| e.into_inner());
            stats.packets_current -= 1;
        }
    }
}

fn enqueue(
    sender: &mpsc::SyncSender<QueuedPacket>,
    data: Vec<u8>,
    metrics: &Arc<QueueMetrics>,
) -> Result<(), mpsc::TrySendError<()>> {
    let mut stats = metrics.0.lock().unwrap_or_else(|e| e.into_inner());
    stats.packets_current += 1;
    let packet = QueuedPacket {
        data,
        since: Instant::now(),
        metrics: Some(metrics.clone()),
    };
    match sender.try_send(packet) {
        Ok(()) => {
            stats.packets_peak = stats.packets_peak.max(stats.packets_current);
            Ok(())
        }
        Err(mpsc::TrySendError::Full(mut packet)) => {
            packet.metrics = None;
            stats.packets_current -= 1;
            Err(mpsc::TrySendError::Full(()))
        }
        Err(mpsc::TrySendError::Disconnected(mut packet)) => {
            packet.metrics = None;
            stats.packets_current -= 1;
            Err(mpsc::TrySendError::Disconnected(()))
        }
    }
}

#[derive(Default)]
struct Counters {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    tcp_flows: AtomicU64,
    tcp_flows_closed: AtomicU64,
    udp_flows_closed: AtomicU64,
    udp_datagrams_in: AtomicU64,
    udp_datagrams_out: AtomicU64,
    udp_errors: AtomicU64,
    udp_dropped: AtomicU64,
    udp_reply_too_big: AtomicU64,
    ipv6_dropped: AtomicU64,
    fragments_dropped: AtomicU64,
    icmp_dropped: AtomicU64,
    icmp_requests: AtomicU64,
    icmp_replies: AtomicU64,
    icmp_errors: AtomicU64,
    icmp_setup_errors: AtomicU64,
    icmp_timeouts: AtomicU64,
    icmp_phone_no_cellular: AtomicU64,
    icmp_phone_busy: AtomicU64,
    icmp_phone_timeout: AtomicU64,
    icmp_phone_failed: AtomicU64,
    icmp_phone_path_no_update: AtomicU64,
    icmp_phone_path_unsatisfied: AtomicU64,
    icmp_phone_path_not_cellular: AtomicU64,
    icmp_phone_path_no_interface: AtomicU64,
    icmp_phone_path_ambiguous: AtomicU64,
    icmp_malformed: AtomicU64,
    icmp_payload_mismatch: AtomicU64,
    icmp_io_errors: AtomicU64,
    icmp_output_errors: AtomicU64,
    icmp_active: AtomicUsize,
    send_dropped: AtomicU64,
    flow_errors: AtomicU64,
    queue_dropped: AtomicU64,
    tcp_setup_errors: AtomicU64,
    tcp_io_errors: AtomicU64,
    tcp_setup_refused: AtomicU64,
    tcp_setup_timed_out: AtomicU64,
    tcp_setup_timeout_phone_connect: AtomicU64,
    tcp_setup_timeout_phone_auth: AtomicU64,
    tcp_setup_timeout_phone_destination: AtomicU64,
    tcp_setup_timeout_direct_connect: AtomicU64,
    tcp_setup_permission_denied: AtomicU64,
    tcp_setup_other: AtomicU64,
    tcp_setup_phone_unreachable: AtomicU64,
    tcp_capacity_refused: AtomicU64,
    udp_flows_evicted: AtomicU64,
    dns_flows: AtomicU64,
    dns_setup_ok: AtomicU64,
    dns_setup_failed: AtomicU64,
    tcp_ack_rtt_samples: AtomicU64,
    tcp_ack_rtt_sum_us: AtomicU64,
    tcp_ack_rtt_max_us: AtomicU64,
    tcp_window_limited_us: AtomicU64,
    tcp_upload_buffer_peak_bytes: AtomicU64,
    tcp_download_buffer_peak_bytes: AtomicU64,
    tcp_retransmits: AtomicU64,
    tcp_resets_lost: AtomicU64,
    tcp_flows_active: AtomicUsize,
    tcp_flows_peak: AtomicUsize,
    setup_connect_us: diagnostics::Reservoir,
    setup_greeting_us: diagnostics::Reservoir,
    setup_auth_us: diagnostics::Reservoir,
    setup_request_us: diagnostics::Reservoir,
    dns_lookups: AtomicU64,
    dns_ok: AtomicU64,
    dns_failed: AtomicU64,
    dns_ms: diagnostics::Reservoir,
    udp_flows: AtomicU64,
    udp_age_drops: AtomicU64,
    privacy_flows: AtomicU64,
    privacy_shaped_flows: AtomicU64,
    privacy_shaped_errors: AtomicU64,
    privacy_ech_attempts: AtomicU64,
    privacy_ech_ok: AtomicU64,
    privacy_ech_grease: AtomicU64,
    privacy_ech_rejected: AtomicU64,
    privacy_ech_fallback: AtomicU64,
    privacy_doh_lookups: AtomicU64,
    privacy_doh_ok: AtomicU64,
    privacy_doh_failed: AtomicU64,
    privacy_cover_flows: AtomicU64,
    privacy_cover_errors: AtomicU64,
    timeline: diagnostics::EventTimeline,
}
fn inc(v: &AtomicU64) {
    v.fetch_add(1, Ordering::Relaxed);
}
fn add(v: &AtomicU64, n: usize) {
    v.fetch_add(n as u64, Ordering::Relaxed);
}
fn value(v: &AtomicU64) -> u64 {
    v.load(Ordering::Relaxed)
}
fn value_usize(v: &AtomicUsize) -> u64 {
    v.load(Ordering::Relaxed) as u64
}
fn collect_tcp_metrics(c: &Counters, engine: &mut tcp::TcpFlow, now: Instant) {
    let m = engine.take_metrics(now);
    c.tcp_ack_rtt_samples
        .fetch_add(m.ack_samples, Ordering::Relaxed);
    c.tcp_ack_rtt_sum_us
        .fetch_add(m.ack_sum_us, Ordering::Relaxed);
    c.tcp_ack_rtt_max_us
        .fetch_max(m.ack_max_us, Ordering::Relaxed);
    c.tcp_window_limited_us
        .fetch_add(m.window_limited_us, Ordering::Relaxed);
    c.tcp_upload_buffer_peak_bytes
        .fetch_max(m.upload_peak as u64, Ordering::Relaxed);
    c.tcp_download_buffer_peak_bytes
        .fetch_max(m.download_peak as u64, Ordering::Relaxed);
    c.tcp_retransmits
        .fetch_add(m.retransmits, Ordering::Relaxed);
    if m.retransmits > 0 {
        c.timeline.record_count(
            now,
            diagnostics::TimelineEvent::TcpRetransmit,
            m.retransmits,
        );
    }
    if m.window_limited_us > 0 {
        c.timeline.record_count(
            now,
            diagnostics::TimelineEvent::WindowLimitedUs(m.window_limited_us),
            1,
        );
    }
}
fn record_setup_timings(c: &Counters, timings: [u64; 4]) {
    c.setup_connect_us.record(timings[0]);
    c.setup_greeting_us.record(timings[1]);
    c.setup_auth_us.record(timings[2]);
    c.setup_request_us.record(timings[3]);
}
enum IcmpFailure {
    Setup,
    Timeout,
    NoCellular,
    Busy,
    PhoneTimeout,
    PhoneFailed,
    PathNoUpdate,
    PathUnsatisfied,
    PathNotCellular,
    PathNoInterface,
    PathAmbiguous,
    Malformed,
    PayloadMismatch,
    Io,
    Output,
}
fn count_icmp_failure(c: &Counters, failure: IcmpFailure) {
    inc(&c.icmp_errors);
    inc(match failure {
        IcmpFailure::Setup => &c.icmp_setup_errors,
        IcmpFailure::Timeout => &c.icmp_timeouts,
        IcmpFailure::NoCellular => &c.icmp_phone_no_cellular,
        IcmpFailure::Busy => &c.icmp_phone_busy,
        IcmpFailure::PhoneTimeout => &c.icmp_phone_timeout,
        IcmpFailure::PhoneFailed => &c.icmp_phone_failed,
        IcmpFailure::PathNoUpdate => &c.icmp_phone_path_no_update,
        IcmpFailure::PathUnsatisfied => &c.icmp_phone_path_unsatisfied,
        IcmpFailure::PathNotCellular => &c.icmp_phone_path_not_cellular,
        IcmpFailure::PathNoInterface => &c.icmp_phone_path_no_interface,
        IcmpFailure::PathAmbiguous => &c.icmp_phone_path_ambiguous,
        IcmpFailure::Malformed => &c.icmp_malformed,
        IcmpFailure::PayloadMismatch => &c.icmp_payload_mismatch,
        IcmpFailure::Io => &c.icmp_io_errors,
        IcmpFailure::Output => &c.icmp_output_errors,
    });
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpSetupPhase {
    PhoneConnect,
    PhoneAuth,
    PhoneDestination,
    DirectConnect,
}
impl TcpSetupPhase {
    fn failure_phase(self) -> failures::Phase {
        match self {
            TcpSetupPhase::PhoneConnect => failures::Phase::Connect,
            TcpSetupPhase::PhoneAuth => failures::Phase::Auth,
            TcpSetupPhase::PhoneDestination => failures::Phase::Request,
            TcpSetupPhase::DirectConnect => failures::Phase::Connect,
        }
    }
}
fn count_tcp_setup_error(c: &Counters, error: &io::Error, phase: TcpSetupPhase, code: Option<u8>) {
    inc(&c.flow_errors);
    inc(&c.tcp_setup_errors);
    // A SOCKS reply code is the only proof that the destination answered. A
    // local socket error on the source device path is not.
    if let Some(code) = code {
        match code {
            2 => inc(&c.tcp_setup_permission_denied),
            3 | 4 => inc(&c.tcp_setup_phone_unreachable),
            5 => inc(&c.tcp_setup_refused),
            // Code 6 is an expired TTL. It is not a timeout and it does not
            // prove that the destination timed out, so no timeout counter moves.
            _ => inc(&c.tcp_setup_other),
        }
        return;
    }
    match error.kind() {
        // A direct connect refusal comes from the destination path. A refused
        // source device socket does not prove that the destination refused.
        io::ErrorKind::ConnectionRefused if phase == TcpSetupPhase::DirectConnect => {
            inc(&c.tcp_setup_refused)
        }
        io::ErrorKind::TimedOut => {
            inc(&c.tcp_setup_timed_out);
            match phase {
                TcpSetupPhase::PhoneConnect => inc(&c.tcp_setup_timeout_phone_connect),
                TcpSetupPhase::PhoneAuth => inc(&c.tcp_setup_timeout_phone_auth),
                // The target device stopped waiting for the source device
                // reply. Without a source reply, this is not proof that the
                // destination timed out, so the destination counter stays.
                TcpSetupPhase::PhoneDestination => {}
                TcpSetupPhase::DirectConnect => inc(&c.tcp_setup_timeout_direct_connect),
            }
        }
        io::ErrorKind::PermissionDenied => inc(&c.tcp_setup_permission_denied),
        _ => inc(&c.tcp_setup_other),
    }
}

/// Map one setup error to the failure record reason.
///
/// A source device reply code is an answer about the destination. A local
/// socket error without a reply code is not. Only a typed source device
/// authentication rejection is a denial.
///
/// A local timeout on the source device path is `Other`: the target device
/// stopped waiting, but the destination did not answer. A direct connect
/// timeout stays `TimedOut`, because that path reaches the destination. Reply
/// code 6 is an expired TTL, not a timeout, and it becomes `Other`.
fn failure_reason(error: &io::Error, code: Option<u8>, source_device: bool) -> failures::Reason {
    if let Some(code) = code {
        return failures::Reason::from_code(code);
    }
    if source_device {
        if phone::auth_rejection(error).is_some() {
            failures::Reason::Denied
        } else {
            failures::Reason::from_setup_error(error.kind(), None)
        }
    } else {
        failures::Reason::from_direct_setup_error(error.kind())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Key {
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

fn flow_key(raw: &[u8]) -> Option<Key> {
    let ip = packet::parse_ip(raw)?;
    if ip.fragmented {
        return None;
    }
    let (src, dst) = (ip.src, ip.dst);
    let (sport, dport) = match ip.protocol {
        packet::PROTO_TCP => {
            let p = packet::parse_tcp(ip.payload)?;
            (p.sport, p.dport)
        }
        packet::PROTO_UDP => {
            let p = packet::parse_udp(ip.payload)?;
            (p.sport, p.dport)
        }
        packet::PROTO_ICMP | packet::PROTO_ICMPV6 => {
            let p = packet::parse_echo_request(&ip)?;
            // All sequences for the same ICMP identifier use one worker.
            (p.identifier, 0)
        }
        _ => return None,
    };
    Some(Key {
        proto: ip.protocol,
        src,
        dst,
        sport,
        dport,
    })
}
fn shard(key: &Key, workers: usize) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % workers
}

// The output notification is level-triggered. Keep the byte present while
// the queue is nonempty. The lock prevents a lost wake when a producer and
// the device reader operate at the same time.
struct Output {
    queue: Mutex<VecDeque<QueuedPacket>>,
    metrics: Arc<QueueMetrics>,
    notify_read: WakeReceiver,
    notify_write: WakeSender,
}
impl Output {
    fn new() -> io::Result<Self> {
        let (notify_write, notify_read) = WakePair::new()?.split();
        Ok(Self {
            queue: Mutex::new(VecDeque::new()),
            metrics: Arc::new(QueueMetrics::default()),
            notify_read,
            notify_write,
        })
    }
    fn push(&self, packet: Vec<u8>) -> bool {
        self.push_with_limit(packet, QUEUE)
    }
    fn push_tcp_control(&self, packet: Vec<u8>) -> bool {
        self.push_with_limit(packet, QUEUE + TCP_CONTROL_RESERVE)
    }
    fn push_with_limit(&self, packet: Vec<u8>, limit: usize) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() >= limit {
            return false;
        }
        let empty = queue.is_empty();
        {
            let mut stats = self.metrics.0.lock().unwrap_or_else(|e| e.into_inner());
            stats.packets_current += 1;
            stats.packets_peak = stats.packets_peak.max(stats.packets_current);
        }
        queue.push_back(QueuedPacket {
            data: packet,
            since: Instant::now(),
            metrics: Some(self.metrics.clone()),
        });
        if empty {
            self.notify_write.signal();
        }
        true
    }
    fn pop(&self) -> Option<Vec<u8>> {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let result = queue.pop_front();
        if queue.is_empty() {
            self.notify_read.drain();
        }
        result.map(QueuedPacket::consume)
    }
    fn signal_failure(&self) {
        let _queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        self.notify_write.signal();
    }
    fn handle(&self) -> relay_poll::RawHandle {
        self.notify_read.handle()
    }
}

struct WorkerExit {
    running: Arc<AtomicBool>,
    output: Arc<Output>,
}
impl Drop for WorkerExit {
    fn drop(&mut self) {
        if self.running.swap(false, Ordering::AcqRel) {
            self.output.signal_failure();
        }
    }
}

/// A worker pool. Feed and drain raw IP packets from the tunnel owner.
pub struct Relay {
    input: Vec<mpsc::SyncSender<QueuedPacket>>,
    input_metrics: Vec<Arc<QueueMetrics>>,
    wake: Vec<WakeSender>,
    output: Arc<Output>,
    counters: Arc<Counters>,
    audit: Arc<normalization::Audit>,
    running: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    ipv6_forward: bool,
    icmp_phone: bool,
}

impl Relay {
    pub fn start(config: RelayConfig) -> io::Result<Self> {
        if config.workers == 0 || config.workers > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker count must be 1 to 8",
            ));
        }
        if config.iface.is_none() && !config.allow_unpinned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hotspot interface is required",
            ));
        }
        if config.phone.is_some() && config.iface.is_none() && !config.allow_unpinned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source device proxy mode requires interface pinning",
            ));
        }
        if config.icmp_phone && config.phone.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source device ICMP requires source device proxy mode",
            ));
        }
        if config.icmp_persistent && !config.icmp_phone {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "persistent source device ICMP requires experimental source device ICMP",
            ));
        }
        if let Some(phone) = &config.phone {
            if phone.iface != config.iface || config.dns_upstream.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "the source device interface must match the hotspot, and source device proxy mode does not accept a DNS upstream"));
            }
        }
        if let Some(upstream) = config.dns_upstream {
            crate::dns::validate_upstream(upstream)?;
        }
        let counters = Arc::new(Counters::default());
        let audit = Arc::new(normalization::Audit::default());
        let running = Arc::new(AtomicBool::new(true));
        let output = Arc::new(Output::new()?);
        let mut input = Vec::new();
        let mut input_metrics = Vec::new();
        let mut wake: Vec<WakeSender> = Vec::new();
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        for index in 0..config.workers {
            let (tx, rx) = mpsc::sync_channel(QUEUE);
            let (wake_tx, wake_rx) = match WakePair::new() {
                Ok(pair) => pair.split(),
                Err(e) => {
                    running.store(false, Ordering::Release);
                    drop(input);
                    drop(wake);
                    for h in handles {
                        let _: thread::Result<()> = h.join();
                    }
                    return Err(e);
                }
            };
            let (cfg, out, count, aud, run) = (
                config.clone(),
                output.clone(),
                counters.clone(),
                audit.clone(),
                running.clone(),
            );
            let handle = match thread::Builder::new()
                .name(format!("hotspot-relay-{}", index))
                .spawn(move || {
                    let _exit = WorkerExit {
                        running: run.clone(),
                        output: out.clone(),
                    };
                    Worker::new(cfg, out, count, aud, run).run(rx, wake_rx)
                }) {
                Ok(h) => h,
                Err(e) => {
                    running.store(false, Ordering::Release);
                    drop(input);
                    drop(wake);
                    for h in handles {
                        let _: thread::Result<()> = h.join();
                    }
                    return Err(e);
                }
            };
            input.push(tx);
            input_metrics.push(Arc::new(QueueMetrics::default()));
            wake.push(wake_tx);
            handles.push(handle);
        }
        Ok(Self {
            input,
            input_metrics,
            wake,
            output,
            counters,
            audit,
            running,
            handles,
            ipv6_forward: config.ipv6_forward,
            icmp_phone: config.icmp_phone,
        })
    }

    /// Queue one packet without blocking the device reader.
    pub fn dispatch(&self, raw: Vec<u8>) -> io::Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "relay stopped"));
        }
        inc(&self.counters.packets_in);
        let ip = match packet::parse_ip(&raw) {
            Some(p) => p,
            None => return Ok(()),
        };
        if ip.version == 6 && !self.ipv6_forward {
            inc(&self.counters.ipv6_dropped);
            self.reject_blocked_ipv6(&ip, &raw);
            return Ok(());
        }
        if ip.version == 6 && ip.protocol == 44 {
            inc(&self.counters.fragments_dropped);
            return Ok(());
        }
        if ip.fragmented {
            inc(&self.counters.fragments_dropped);
            return Ok(());
        }
        let is_icmp = matches!(ip.protocol, packet::PROTO_ICMP | packet::PROTO_ICMPV6);
        if is_icmp && !self.icmp_phone {
            inc(&self.counters.icmp_dropped);
            return Ok(());
        }
        let key = match flow_key(&raw) {
            Some(k) => k,
            None => {
                if is_icmp {
                    inc(&self.counters.icmp_dropped);
                }
                return Ok(());
            }
        };
        let index = shard(&key, self.input.len());
        match enqueue(&self.input[index], raw, &self.input_metrics[index]) {
            Ok(()) => {
                // A pending signal already stands for the queued packet.
                self.wake[index].signal();
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => {
                inc(&self.counters.queue_dropped);
                self.counters
                    .timeline
                    .record(Instant::now(), diagnostics::TimelineEvent::RelayDrop);
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "relay queue full",
                ))
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.running.store(false, Ordering::Release);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "relay worker stopped",
                ))
            }
        }
    }

    /// Answer a blocked IPv6 destination with a local error. The engine does
    /// not route the packet anywhere. A TCP flow gets a reset. A UDP flow gets
    /// an ICMPv6 destination unreachable message. This lets a browser fall back
    /// at once instead of waiting for a connect timeout.
    fn reject_blocked_ipv6(&self, ip: &packet::IpPacket<'_>, raw: &[u8]) {
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (ip.src, ip.dst) else {
            return;
        };
        if dst.segments()[0] & 0xe000 != 0x2000
            || ip.fragmented
            || src.is_unspecified()
            || src.is_multicast()
            || src.is_loopback()
        {
            return;
        }
        if ip.protocol == packet::PROTO_TCP {
            if let Some(seg) = packet::parse_tcp(ip.payload) {
                if seg.flags & packet::RST != 0 {
                    return;
                }
                let syn = if seg.flags & packet::SYN != 0 { 1 } else { 0 };
                let ack = seg.seq.wrapping_add(syn + seg.data.len() as u32);
                let seq = if seg.flags & packet::ACK != 0 {
                    seg.ack
                } else {
                    0
                };
                let reply = packet::build_tcp_v6(&packet::TcpBuildV6 {
                    src: dst,
                    dst: src,
                    sport: seg.dport,
                    dport: seg.sport,
                    seq,
                    ack,
                    flags: packet::RST | packet::ACK,
                    window: 0,
                    payload: &[],
                    options: &[],
                    hop_limit: 64,
                });
                if let Ok(reply) = reply {
                    self.send_blocked(reply);
                }
                return;
            }
        }
        if ip.protocol == packet::PROTO_ICMPV6 {
            return;
        }
        if let Ok(reply) = packet::build_icmpv6_unreachable(dst, src, 1, raw) {
            self.send_blocked(reply);
        }
    }
    fn send_blocked(&self, raw: Vec<u8>) {
        let n = raw.len();
        if self.output.push(raw) {
            inc(&self.counters.packets_out);
            add(&self.counters.bytes_out, n);
        } else {
            inc(&self.counters.send_dropped);
            self.counters
                .timeline
                .record(Instant::now(), diagnostics::TimelineEvent::RelayDrop);
        }
    }
    pub fn try_receive(&self) -> Option<Vec<u8>> {
        self.output.pop()
    }
    /// Poll this handle for readability. It stays readable while output exists.
    pub fn output_fd(&self) -> relay_poll::RawHandle {
        self.output.handle()
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Vec<u8>, mpsc::RecvTimeoutError> {
        if let Some(packet) = self.try_receive() {
            return Ok(packet);
        }
        let mut set = PollSet::with_capacity(1);
        if set
            .push_handle(self.output_fd(), Interest::READABLE)
            .is_err()
        {
            return Err(mpsc::RecvTimeoutError::Timeout);
        }
        match set.wait(timeout) {
            Ok(count) if count > 0 => {}
            _ => return Err(mpsc::RecvTimeoutError::Timeout),
        }
        self.try_receive().ok_or(mpsc::RecvTimeoutError::Timeout)
    }
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire) && self.handles.iter().all(|h| !h.is_finished())
    }
    pub fn stats(&self) -> RelayStats {
        let c = &self.counters;
        RelayStats {
            packets_in: value(&c.packets_in),
            packets_out: value(&c.packets_out),
            bytes_in: value(&c.bytes_in),
            bytes_out: value(&c.bytes_out),
            tcp_flows: value(&c.tcp_flows),
            tcp_flows_closed: value(&c.tcp_flows_closed),
            tcp_flows_active: value_usize(&c.tcp_flows_active),
            udp_flows_closed: value(&c.udp_flows_closed),
            udp_datagrams_in: value(&c.udp_datagrams_in),
            udp_datagrams_out: value(&c.udp_datagrams_out),
            udp_errors: value(&c.udp_errors),
            udp_dropped: value(&c.udp_dropped),
            udp_reply_too_big: value(&c.udp_reply_too_big),
            ttl_bad: self.audit.snapshot().1,
            ipv6_dropped: value(&c.ipv6_dropped),
            fragments_dropped: value(&c.fragments_dropped),
            icmp_dropped: value(&c.icmp_dropped),
            icmp_requests: value(&c.icmp_requests),
            icmp_replies: value(&c.icmp_replies),
            icmp_errors: value(&c.icmp_errors),
            icmp_setup_errors: value(&c.icmp_setup_errors),
            icmp_timeouts: value(&c.icmp_timeouts),
            icmp_phone_no_cellular: value(&c.icmp_phone_no_cellular),
            icmp_phone_busy: value(&c.icmp_phone_busy),
            icmp_phone_timeout: value(&c.icmp_phone_timeout),
            icmp_phone_failed: value(&c.icmp_phone_failed),
            icmp_phone_path_no_update: value(&c.icmp_phone_path_no_update),
            icmp_phone_path_unsatisfied: value(&c.icmp_phone_path_unsatisfied),
            icmp_phone_path_not_cellular: value(&c.icmp_phone_path_not_cellular),
            icmp_phone_path_no_interface: value(&c.icmp_phone_path_no_interface),
            icmp_phone_path_ambiguous: value(&c.icmp_phone_path_ambiguous),
            icmp_malformed: value(&c.icmp_malformed),
            icmp_payload_mismatch: value(&c.icmp_payload_mismatch),
            icmp_io_errors: value(&c.icmp_io_errors),
            icmp_output_errors: value(&c.icmp_output_errors),
            send_dropped: value(&c.send_dropped),
            flow_errors: value(&c.flow_errors),
            queue_dropped: value(&c.queue_dropped),
            tcp_setup_errors: value(&c.tcp_setup_errors),
            tcp_io_errors: value(&c.tcp_io_errors),
            tcp_setup_refused: value(&c.tcp_setup_refused),
            tcp_setup_timed_out: value(&c.tcp_setup_timed_out),
            tcp_setup_timeout_phone_connect: value(&c.tcp_setup_timeout_phone_connect),
            tcp_setup_timeout_phone_auth: value(&c.tcp_setup_timeout_phone_auth),
            tcp_setup_timeout_phone_destination: value(&c.tcp_setup_timeout_phone_destination),
            tcp_setup_timeout_direct_connect: value(&c.tcp_setup_timeout_direct_connect),
            tcp_setup_permission_denied: value(&c.tcp_setup_permission_denied),
            tcp_setup_other: value(&c.tcp_setup_other),
            tcp_setup_phone_unreachable: value(&c.tcp_setup_phone_unreachable),
            tcp_capacity_refused: value(&c.tcp_capacity_refused),
            udp_flows_evicted: value(&c.udp_flows_evicted),
            dns_flows: value(&c.dns_flows),
            dns_setup_ok: value(&c.dns_setup_ok),
            dns_setup_failed: value(&c.dns_setup_failed),
            tcp_ack_rtt_samples: value(&c.tcp_ack_rtt_samples),
            tcp_ack_rtt_sum_us: value(&c.tcp_ack_rtt_sum_us),
            tcp_ack_rtt_max_us: value(&c.tcp_ack_rtt_max_us),
            tcp_window_limited_us: value(&c.tcp_window_limited_us),
            tcp_upload_buffer_peak_bytes: value(&c.tcp_upload_buffer_peak_bytes),
            tcp_download_buffer_peak_bytes: value(&c.tcp_download_buffer_peak_bytes),
            destination_privacy: DestinationPrivacyStats {
                flows: value(&c.privacy_flows),
                shaped_flows: value(&c.privacy_shaped_flows),
                shaped_errors: value(&c.privacy_shaped_errors),
                ech_attempts: value(&c.privacy_ech_attempts),
                ech_ok: value(&c.privacy_ech_ok),
                ech_grease: value(&c.privacy_ech_grease),
                ech_rejected: value(&c.privacy_ech_rejected),
                ech_fallback: value(&c.privacy_ech_fallback),
                doh_lookups: value(&c.privacy_doh_lookups),
                doh_ok: value(&c.privacy_doh_ok),
                doh_failed: value(&c.privacy_doh_failed),
                cover_flows: value(&c.privacy_cover_flows),
                cover_errors: value(&c.privacy_cover_errors),
            },
            input_queues: self.input_metrics.iter().map(|m| m.snapshot()).collect(),
            output_queue: self.output.metrics.snapshot(),
        }
    }
    /// The diagnostics metrics for the running relay. It holds counters and
    /// bounded timing reservoirs only. It never holds an address.
    pub fn diagnostics(&self) -> serde_json::Value {
        let c = &self.counters;
        let input = self
            .input_metrics
            .iter()
            .map(|m| {
                let s = m.snapshot();
                json!({"peak": s.packets_peak, "max_age_us": s.max_age_us})
            })
            .collect::<Vec<_>>();
        let output = self.output.metrics.snapshot();
        // The mode is a service setting, so the shared section provides the
        // mode name and the relay supplies only its counters. Every counter is
        // zero until a mode other than `off` exists.
        let privacy = self.stats().destination_privacy;
        let mut destination_privacy = diagnostics::destination_privacy();
        destination_privacy["counters"] = json!({
            "flows": privacy.flows,
            "shaped_flows": privacy.shaped_flows,
            "shaped_errors": privacy.shaped_errors,
            "ech_attempts": privacy.ech_attempts,
            "ech_ok": privacy.ech_ok,
            "ech_grease": privacy.ech_grease,
            "ech_rejected": privacy.ech_rejected,
            "ech_fallback": privacy.ech_fallback,
            "doh_lookups": privacy.doh_lookups,
            "doh_ok": privacy.doh_ok,
            "doh_failed": privacy.doh_failed,
            "cover_flows": privacy.cover_flows,
            "cover_errors": privacy.cover_errors,
        });
        let established = c
            .timeline
            .snapshot(Instant::now())
            .into_iter()
            .map(|b| {
                json!({
                    "age_s": b.age_s,
                    "observed": b.observed,
                    "tcp_retransmits": b.tcp_retransmits,
                    "window_limited_ms": b.window_limited_ms,
                    "tcp_teardowns": b.tcp_teardowns,
                    "udp_teardowns": b.udp_teardowns,
                    "udp_drops": b.udp_drops,
                    "relay_drops": b.relay_drops,
                    "outer_errors": b.outer_errors,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "setup": {
                "connect_ms": c.setup_connect_us.metric_ms(),
                "greeting_ms": c.setup_greeting_us.metric_ms(),
                "auth_ms": c.setup_auth_us.metric_ms(),
                "request_ms": c.setup_request_us.metric_ms(),
            },
            "dns": {
                "lookups": value(&c.dns_lookups),
                "ok": value(&c.dns_ok),
                "failed": value(&c.dns_failed),
                "ms": c.dns_ms.metric_ms(),
            },
            "queues": {
                "input": input,
                "output": {"peak": output.packets_peak, "max_age_us": output.max_age_us},
            },
            "udp": {
                "flows": value(&c.udp_flows),
                "age_drops": value(&c.udp_age_drops),
                "evicted": value(&c.udp_flows_evicted),
            },
            "tcp": {
                "flows_active": value_usize(&c.tcp_flows_active),
                "flows_peak": value_usize(&c.tcp_flows_peak),
                "retransmits": value(&c.tcp_retransmits),
                "resets_lost": value(&c.tcp_resets_lost),
                "zero_window_ms": value(&c.tcp_window_limited_us) / 1000,
                "capacity_refused": value(&c.tcp_capacity_refused),
            },
            "destination_privacy": destination_privacy,
            "established": {
                "bucket_s": diagnostics::ESTABLISHED_BUCKET_SECONDS,
                "window_s": diagnostics::ESTABLISHED_WINDOW,
                "buckets": established,
            },
        })
    }
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Release);
        self.input.clear();
        for wake in &self.wake {
            wake.shutdown();
        }
        self.wake.clear();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                inc(&self.counters.flow_errors);
            }
        }
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupStage {
    Connect,
    SendHello,
    ReadHello,
    SendAuth,
    ReadAuth,
    SendRequest,
    ReadHeader,
    ReadDomainLength,
    ReadTail,
    Done,
}

// All operations are nonblocking. The worker can therefore stop while a
// phone is unreachable or while it delays any part of authentication.
struct Setup {
    stage: SetupStage,
    deadline: Instant,
    phone: bool,
    auth: Zeroizing<Vec<u8>>,
    request: Vec<u8>,
    read: Vec<u8>,
    sent: usize,
    need: usize,
    /// The SOCKS reply code from the source device, when it replied.
    reply: Option<u8>,
    /// Record the four phone TCP setup phases for diagnostics.
    record_timings: bool,
    timings_us: [u64; 4],
    phase_at: Instant,
}
impl Setup {
    /// Store one completed phase: connect, greeting, auth, or request.
    fn complete_phase(&mut self, index: usize, at: Instant) {
        if self.record_timings {
            self.timings_us[index] = at
                .saturating_duration_since(self.phase_at)
                .as_micros()
                .min(u64::MAX as u128) as u64;
        }
        self.phase_at = at;
    }
    /// The four phase values after a completed phone TCP setup.
    fn take_timings(&mut self) -> Option<[u64; 4]> {
        if self.record_timings && self.stage == SetupStage::Done {
            self.record_timings = false;
            Some(self.timings_us)
        } else {
            None
        }
    }
    fn timeout_phase(&self) -> TcpSetupPhase {
        if !self.phone {
            return TcpSetupPhase::DirectConnect;
        }
        match self.stage {
            SetupStage::Connect => TcpSetupPhase::PhoneConnect,
            SetupStage::SendHello
            | SetupStage::ReadHello
            | SetupStage::SendAuth
            | SetupStage::ReadAuth => TcpSetupPhase::PhoneAuth,
            SetupStage::SendRequest
            | SetupStage::ReadHeader
            | SetupStage::ReadDomainLength
            | SetupStage::ReadTail
            | SetupStage::Done => TcpSetupPhase::PhoneDestination,
        }
    }
    fn direct() -> Self {
        Self {
            stage: SetupStage::Connect,
            deadline: Instant::now() + CONNECT_TIMEOUT,
            phone: false,
            auth: Zeroizing::new(Vec::new()),
            request: Vec::new(),
            read: Vec::new(),
            sent: 0,
            need: 0,
            reply: None,
            record_timings: false,
            timings_us: [0; 4],
            phase_at: Instant::now(),
        }
    }
    fn phone(
        phone: &phone::PhoneProxy,
        target: IpAddr,
        port: u16,
        command: u8,
    ) -> io::Result<Self> {
        let user = phone.username.as_bytes();
        let pass = phone.token.as_bytes();
        if user.is_empty()
            || user.len() > 255
            || pass.is_empty()
            || pass.len() > 255
            || (port == 0 && command != 0x81 && command != 0x82)
            || phone.timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid phone credentials, target, or timeout",
            ));
        }
        let mut auth = Zeroizing::new(Vec::with_capacity(3 + user.len() + pass.len()));
        auth.extend_from_slice(&[1, user.len() as u8]);
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        let mut request = vec![5, command, 0];
        match crate::dns::canonical_ip(target) {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        Ok(Self {
            stage: SetupStage::Connect,
            deadline: Instant::now() + phone.timeout,
            phone: true,
            auth,
            request,
            read: Vec::new(),
            sent: 0,
            need: 0,
            reply: None,
            record_timings: command == 1,
            timings_us: [0; 4],
            phase_at: Instant::now(),
        })
    }
    /// The setup stage for the failure record.
    fn failure_phase(&self) -> failures::Phase {
        match self.stage {
            SetupStage::Connect => failures::Phase::Connect,
            SetupStage::SendHello | SetupStage::ReadHello => failures::Phase::Greeting,
            SetupStage::SendAuth | SetupStage::ReadAuth => failures::Phase::Auth,
            SetupStage::SendRequest
            | SetupStage::ReadHeader
            | SetupStage::ReadDomainLength
            | SetupStage::ReadTail
            | SetupStage::Done => failures::Phase::Request,
        }
    }
    fn events(&self) -> Interest {
        match self.stage {
            SetupStage::Connect
            | SetupStage::SendHello
            | SetupStage::SendAuth
            | SetupStage::SendRequest => Interest::WRITABLE,
            _ => Interest::READABLE,
        }
    }
    fn advance(&mut self, stream: &mut TcpStream) -> io::Result<bool> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "outer connection timed out",
            ));
        }
        for _ in 0..20 {
            match self.stage {
                SetupStage::Connect => {
                    let mut set = PollSet::with_capacity(1);
                    set.push_handle(relay_poll::handle(stream), Interest::WRITABLE)?;
                    let rc = match set.wait(Duration::ZERO) {
                        Ok(count) => count,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(false),
                        Err(e) => return Err(e),
                    };
                    if rc == 0 {
                        return Ok(false);
                    }
                    if let Some(e) = stream.take_error()? {
                        return Err(e);
                    }
                    if set.ready(0).is_failure() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "outer connection failed",
                        ));
                    }
                    if !self.phone {
                        self.stage = SetupStage::Done;
                    } else {
                        self.stage = SetupStage::SendHello;
                    }
                    self.complete_phase(0, Instant::now());
                }
                SetupStage::SendHello | SetupStage::SendAuth | SetupStage::SendRequest => {
                    let data: &[u8] = match self.stage {
                        SetupStage::SendHello => &[5, 1, 2],
                        SetupStage::SendAuth => &self.auth,
                        _ => &self.request,
                    };
                    match stream.write(&data[self.sent..]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "phone closed during setup",
                            ))
                        }
                        Ok(n) => {
                            self.sent += n;
                            if self.sent < data.len() {
                                continue;
                            }
                        }
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::Interrupted =>
                        {
                            return Ok(false)
                        }
                        Err(e) => return Err(e),
                    }
                    if self.stage == SetupStage::SendAuth {
                        self.auth.zeroize();
                    }
                    self.sent = 0;
                    self.read.clear();
                    self.stage = match self.stage {
                        SetupStage::SendHello => SetupStage::ReadHello,
                        SetupStage::SendAuth => SetupStage::ReadAuth,
                        _ => SetupStage::ReadHeader,
                    };
                    self.need = if self.stage == SetupStage::ReadHeader {
                        4
                    } else {
                        2
                    };
                }
                SetupStage::ReadHello
                | SetupStage::ReadAuth
                | SetupStage::ReadHeader
                | SetupStage::ReadDomainLength
                | SetupStage::ReadTail => {
                    let mut buf = [0u8; 256];
                    let take = (self.need - self.read.len()).min(buf.len());
                    let n = match stream.read(&mut buf[..take]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "phone closed during setup",
                            ))
                        }
                        Ok(n) => n,
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::Interrupted =>
                        {
                            return Ok(false)
                        }
                        Err(e) => return Err(e),
                    };
                    self.read.extend_from_slice(&buf[..n]);
                    if self.read.len() < self.need {
                        continue;
                    }
                    match self.stage {
                        SetupStage::ReadHello => {
                            if self.read != [5, 2] {
                                return Err(phone::rejected_method_error(
                                    io::ErrorKind::PermissionDenied,
                                ));
                            }
                            self.stage = SetupStage::SendAuth;
                            self.complete_phase(1, Instant::now());
                        }
                        SetupStage::ReadAuth => {
                            if self.read != [1, 0] {
                                return Err(phone::rejected_credentials_error());
                            }
                            self.stage = SetupStage::SendRequest;
                            self.complete_phase(2, Instant::now());
                        }
                        SetupStage::ReadHeader => {
                            if self.read[0] != 5 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid phone reply",
                                ));
                            }
                            if self.read[1] != 0 {
                                self.reply = Some(self.read[1]);
                                return Err(phone::reply_error(self.read[1]));
                            }
                            if self.read[2] != 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid phone reply",
                                ));
                            }
                            match self.read[3] {
                                1 => {
                                    self.stage = SetupStage::ReadTail;
                                    self.need = 6;
                                }
                                4 => {
                                    self.stage = SetupStage::ReadTail;
                                    self.need = 18;
                                }
                                3 => {
                                    self.stage = SetupStage::ReadDomainLength;
                                    self.need = 1;
                                }
                                _ => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "invalid phone reply",
                                    ))
                                }
                            }
                        }
                        SetupStage::ReadDomainLength => {
                            if self.read[0] == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "empty phone reply domain",
                                ));
                            }
                            self.need = self.read[0] as usize + 2;
                            self.stage = SetupStage::ReadTail;
                        }
                        SetupStage::ReadTail => {
                            self.stage = SetupStage::Done;
                            self.complete_phase(3, Instant::now());
                        }
                        _ => unreachable!(),
                    }
                    self.read.clear();
                }
                SetupStage::Done => return Ok(true),
            }
        }
        Ok(self.stage == SetupStage::Done)
    }
}

struct TcpEntry {
    engine: tcp::TcpFlow,
    stream: TcpStream,
    setup: Option<Setup>,
    /// True after the flow reached the established state. The timeline counts
    /// only established teardowns. Setup failures keep their own counters.
    was_established: bool,
    /// Keeps the live flow gauge equal to the number of `TcpEntry` values.
    /// The guard is declared last, so it lowers the gauge after the entry and
    /// its outer socket are gone. The leading underscore marks the field as
    /// held only for its `Drop` effect; no code reads it.
    _gauge: TcpFlowGauge,
}
/// One live target relay TCP flow, counted from creation until drop. A normal
/// teardown, a failed setup that already reached the flow table, a worker stop,
/// and an unwind all drop the entry, so the gauge cannot leak a stale count or
/// subtract the same flow twice.
struct TcpFlowGauge {
    counters: Arc<Counters>,
}
impl TcpFlowGauge {
    fn new(counters: &Arc<Counters>) -> Self {
        let active = counters.tcp_flows_active.fetch_add(1, Ordering::AcqRel) + 1;
        counters.tcp_flows_peak.fetch_max(active, Ordering::AcqRel);
        Self {
            counters: Arc::clone(counters),
        }
    }
}
impl Drop for TcpFlowGauge {
    fn drop(&mut self) {
        self.counters
            .tcp_flows_active
            .fetch_sub(1, Ordering::AcqRel);
    }
}
/// Close the outer socket. An abortive teardown resets it, so a destination
/// that reads until end of stream cannot take a truncated upload for a
/// complete one. A graceful close, or one whose upload direction already ended
/// with a FIN, keeps the normal close.
fn close_outer(entry: &TcpEntry) {
    if entry.engine.outer_abortive_close() {
        reset_outer_socket(&entry.stream);
    }
}
/// Set `SO_LINGER` to zero so that close sends a reset. The call is best
/// effort: a failure leaves the normal FIN close in place.
#[cfg(unix)]
fn reset_outer_socket(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: the descriptor belongs to `stream`, and the option value is a
    // `libc::linger` with the size that the call reports.
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        );
    }
}
/// Set `SO_LINGER` to zero so that close sends a reset. Windows treats a zero
/// linger as an abortive close, the same as the POSIX behavior.
#[cfg(windows)]
fn reset_outer_socket(stream: &TcpStream) {
    use std::os::windows::io::{AsRawSocket, RawSocket};
    const SOL_SOCKET: i32 = 0xffff;
    const SO_LINGER: i32 = 0x0080;
    /// The Winsock `linger` structure. Both fields are 16 bits.
    #[repr(C)]
    struct Linger {
        onoff: u16,
        linger: u16,
    }
    #[link(name = "ws2_32")]
    extern "system" {
        #[allow(clashing_extern_declarations)]
        fn setsockopt(
            socket: RawSocket,
            level: i32,
            option: i32,
            value: *const u8,
            length: i32,
        ) -> i32;
    }
    let linger = Linger {
        onoff: 1,
        linger: 0,
    };
    // SAFETY: the socket belongs to `stream`, and the option value points to
    // a `Linger` with the size that the call reports.
    unsafe {
        setsockopt(
            stream.as_raw_socket(),
            SOL_SOCKET,
            SO_LINGER,
            (&linger as *const Linger).cast(),
            std::mem::size_of_val(&linger) as i32,
        );
    }
}
#[cfg(not(any(unix, windows)))]
fn reset_outer_socket(_stream: &TcpStream) {}
// The flow table stores this enum for every UDP flow. Boxing the setup state
// would add an allocation and a pointer chase for every setup packet.
#[allow(clippy::large_enum_variant)]
enum UdpSocketKind {
    Direct(normalization::NormalizedUdpSocket),
    Phone {
        stream: TcpStream,
        incoming: Vec<u8>,
        outgoing: Vec<u8>,
        frames: UdpFrameQueue,
        dns: bool,
        setup: Option<Setup>,
    },
}
struct UdpEntry {
    socket: UdpSocketKind,
    last: Instant,
    dns_query_id: Option<[u8; 2]>,
    dns_started: Option<Instant>,
}
struct IcmpPermit(Arc<Counters>);
impl Drop for IcmpPermit {
    fn drop(&mut self) {
        self.0.icmp_active.fetch_sub(1, Ordering::AcqRel);
    }
}
fn reserve_icmp(counters: &Arc<Counters>) -> Option<IcmpPermit> {
    let mut active = counters.icmp_active.load(Ordering::Acquire);
    loop {
        if active >= MAX_ICMP_ACTIVE {
            return None;
        }
        match counters.icmp_active.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(IcmpPermit(counters.clone())),
            Err(n) => active = n,
        }
    }
}
fn valid_icmp_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            b[0] != 0 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254)
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}
struct IcmpEntry {
    stream: TcpStream,
    setup: Option<Setup>,
    src: IpAddr,
    dst: IpAddr,
    identifier: u16,
    sequence: u16,
    outgoing: Vec<u8>,
    sent: usize,
    incoming: Vec<u8>,
    payload: Vec<u8>,
    deadline: Instant,
    _permit: IcmpPermit,
}
struct EchoProbe {
    sequence: u16,
    payload: Vec<u8>,
    nonce: [u8; 16],
    deadline: Instant,
}
struct IcmpSession {
    stream: TcpStream,
    setup: Option<Setup>,
    queued: VecDeque<EchoProbe>,
    active: Option<EchoProbe>,
    outgoing: Vec<u8>,
    sent: usize,
    incoming: Vec<u8>,
    created: Instant,
    last: Instant,
    _permit: IcmpPermit,
}
struct Worker {
    config: RelayConfig,
    output: Arc<Output>,
    counters: Arc<Counters>,
    audit: Arc<normalization::Audit>,
    running: Arc<AtomicBool>,
    tcp: HashMap<Key, TcpEntry>,
    udp: HashMap<Key, UdpEntry>,
    icmp: Vec<IcmpEntry>,
    sessions: HashMap<Key, IcmpSession>,
    pending_resets: HashMap<Key, PendingReset>,
    closed_tcp: HashMap<Key, ClosedTcp>,
}
#[derive(Clone, Copy)]
struct ClosedTcp {
    seq: u32,
    ack: u32,
    closed_at: Instant,
}
struct PendingReset {
    packet: Vec<u8>,
    created: Instant,
    next_attempt: Instant,
    attempts: u8,
}
impl Worker {
    fn new(
        config: RelayConfig,
        output: Arc<Output>,
        counters: Arc<Counters>,
        audit: Arc<normalization::Audit>,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            output,
            counters,
            audit,
            running,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            icmp: Vec::new(),
            sessions: HashMap::new(),
            pending_resets: HashMap::new(),
            closed_tcp: HashMap::new(),
        }
    }
    fn record_failure(
        &self,
        proto: failures::Proto,
        ip: IpAddr,
        port: u16,
        error: &io::Error,
        code: Option<u8>,
        phase: Option<failures::Phase>,
    ) {
        if self.config.phone.is_none() {
            return;
        }
        let Some(recorder) = self.config.failures.as_ref() else {
            return;
        };
        recorder.record(failures::FailureEvent {
            proto,
            ip,
            port,
            reason: failure_reason(error, code, self.config.phone.is_some()),
            code,
            phase,
        });
    }
    fn record_dns_failure(
        &self,
        error: &io::Error,
        code: Option<u8>,
        phase: Option<failures::Phase>,
    ) {
        if self.config.phone.is_none() {
            return;
        }
        let Some(recorder) = self.config.failures.as_ref() else {
            return;
        };
        recorder.record(failures::FailureEvent::dns(
            failure_reason(error, code, self.config.phone.is_some()),
            code,
            phase,
        ));
    }
    /// Count one UDP drop and put it in the current second.
    fn count_udp_drop(&self, now: Instant) {
        inc(&self.counters.udp_dropped);
        self.counters
            .timeline
            .record(now, diagnostics::TimelineEvent::UdpDrop);
    }
    /// Count one local queue drop and put it in the current second.
    fn count_relay_drop(&self) {
        self.counters
            .timeline
            .record(Instant::now(), diagnostics::TimelineEvent::RelayDrop);
    }
    /// Count one established TCP teardown.
    fn note_tcp_teardown(&self, entry: &TcpEntry, now: Instant) {
        if entry.was_established {
            // The teardown proves that a flow was present in this bucket.
            self.counters
                .timeline
                .record(now, diagnostics::TimelineEvent::Observed);
            self.counters
                .timeline
                .record(now, diagnostics::TimelineEvent::TcpTeardown);
        }
    }
    /// Count one UDP flow close.
    fn note_udp_teardown(&self, now: Instant) {
        self.counters
            .timeline
            .record(now, diagnostics::TimelineEvent::UdpTeardown);
    }
    /// Count one outer TCP socket error.
    fn count_outer_error(&self, now: Instant) {
        self.counters
            .timeline
            .record(now, diagnostics::TimelineEvent::OuterError);
    }
    /// True when the worker flow table has no free slot.
    fn flows_at_capacity(&self) -> bool {
        self.tcp.len() + self.udp.len() + self.icmp.len() + self.sessions.len()
            >= MAX_FLOWS_PER_WORKER
    }
    /// True when the UDP flow can give its slot to a new TCP flow. The flow
    /// must be idle and must hold no pending work.
    fn evictable(entry: &UdpEntry, now: Instant) -> bool {
        if now.saturating_duration_since(entry.last) < UDP_EVICT_IDLE {
            return false;
        }
        if entry.dns_query_id.is_some() {
            return false;
        }
        match &entry.socket {
            UdpSocketKind::Direct(_) => true,
            UdpSocketKind::Phone {
                incoming,
                outgoing,
                frames,
                setup,
                ..
            } => {
                setup.is_none()
                    && incoming.is_empty()
                    && outgoing.is_empty()
                    && frames.frames.is_empty()
            }
        }
    }
    /// Close the least recently used idle UDP flow. Return true when one left.
    fn evict_idle_udp(&mut self, now: Instant) -> bool {
        let victim = self
            .udp
            .iter()
            .filter(|(_, entry)| Worker::evictable(entry, now))
            .min_by_key(|(_, entry)| entry.last)
            .map(|(key, _)| *key);
        let Some(victim) = victim else {
            return false;
        };
        self.udp.remove(&victim);
        inc(&self.counters.udp_flows_evicted);
        self.note_udp_teardown(now);
        inc(&self.counters.udp_flows_closed);
        true
    }
    /// Reset an inner TCP SYN that the relay cannot serve. The client fails
    /// fast instead of retransmitting a SYN that cannot be admitted.
    fn refuse_tcp(&mut self, key: Key, seg: &packet::TcpSegment<'_>) {
        let syn = u32::from(seg.flags & packet::SYN != 0);
        let ack = seg
            .seq
            .wrapping_add(syn.wrapping_add(seg.data.len() as u32));
        let raw = match (key.dst, key.src) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => packet::build_tcp(&packet::TcpBuild {
                src,
                dst,
                sport: key.dport,
                dport: key.sport,
                seq: 0,
                ack,
                flags: packet::RST | packet::ACK,
                window: 0,
                payload: &[],
                options: &[],
                ttl: 64,
                ident: 0,
            }),
            (IpAddr::V6(src), IpAddr::V6(dst)) => packet::build_tcp_v6(&packet::TcpBuildV6 {
                src,
                dst,
                sport: key.dport,
                dport: key.sport,
                seq: 0,
                ack,
                flags: packet::RST | packet::ACK,
                window: 0,
                payload: &[],
                options: &[],
                hop_limit: 64,
            }),
            _ => Err("address family mismatch"),
        };
        match raw {
            Ok(raw) => {
                self.output_reset(key, raw, Instant::now());
            }
            Err(_) => {
                inc(&self.counters.send_dropped);
                self.count_relay_drop();
            }
        }
    }
    fn run(mut self, input: mpsc::Receiver<QueuedPacket>, wake: WakeReceiver) {
        while self.running.load(Ordering::Acquire) {
            let mut processed = 0;
            for _ in 0..256 {
                match input.try_recv() {
                    Ok(data) => {
                        self.handle(&data.consume());
                        processed += 1;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return,
                }
            }
            self.pump();
            if processed == 256 {
                continue;
            }
            let mut fds = PollSet::new();
            let mut wait_ok = fds.push_handle(wake.handle(), Interest::READABLE).is_ok();
            for entry in self.tcp.values_mut() {
                let mut events = entry.setup.as_ref().map_or(Interest::NONE, Setup::events);
                if entry.setup.is_none() {
                    if !entry.engine.read_paused && !entry.engine.outer_eof {
                        events |= Interest::READABLE;
                    }
                    if !entry.engine.pending_bytes().is_empty() {
                        events |= Interest::WRITABLE;
                    }
                }
                if !events.is_empty() {
                    wait_ok = wait_ok
                        && fds
                            .push_handle(relay_poll::handle(&entry.stream), events)
                            .is_ok();
                }
            }
            for entry in self.udp.values() {
                let (handle, events) = match &entry.socket {
                    UdpSocketKind::Direct(s) => (s.raw_handle(), Interest::READABLE),
                    UdpSocketKind::Phone {
                        stream,
                        outgoing,
                        setup,
                        ..
                    } => (
                        relay_poll::handle(stream),
                        setup.as_ref().map_or_else(
                            || {
                                Interest::READABLE
                                    | if outgoing.is_empty() {
                                        Interest::NONE
                                    } else {
                                        Interest::WRITABLE
                                    }
                            },
                            Setup::events,
                        ),
                    ),
                };
                wait_ok = wait_ok && fds.push_handle(handle, events).is_ok();
            }
            for entry in &self.icmp {
                let events = entry.setup.as_ref().map_or_else(
                    || {
                        if entry.sent < entry.outgoing.len() {
                            Interest::WRITABLE
                        } else {
                            Interest::READABLE
                        }
                    },
                    Setup::events,
                );
                wait_ok = wait_ok
                    && fds
                        .push_handle(relay_poll::handle(&entry.stream), events)
                        .is_ok();
            }
            for entry in self.sessions.values() {
                let events = entry.setup.as_ref().map_or_else(
                    || {
                        Interest::READABLE
                            | if (entry.active.is_some() && entry.sent < entry.outgoing.len())
                                || (entry.active.is_none() && !entry.queued.is_empty())
                            {
                                Interest::WRITABLE
                            } else {
                                Interest::NONE
                            }
                    },
                    Setup::events,
                );
                wait_ok = wait_ok
                    && fds
                        .push_handle(relay_poll::handle(&entry.stream), events)
                        .is_ok();
            }
            if !wait_ok {
                // A live socket value is valid on every platform. An entry
                // that the set rejects is a serious fault. Stop the worker so
                // the stop is visible in the counters.
                inc(&self.counters.flow_errors);
                break;
            }
            // Wake periodically for retransmission and flow expiration.
            let timeout = if self.tcp.is_empty()
                && self.udp.is_empty()
                && self.icmp.is_empty()
                && self.sessions.is_empty()
                && self.pending_resets.is_empty()
            {
                Duration::from_millis(1000)
            } else {
                Duration::from_millis(50)
            };
            match fds.wait(timeout) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    inc(&self.counters.flow_errors);
                    break;
                }
            }
            if !fds.ready(0).is_empty() {
                wake.drain();
            }
        }
    }
    fn output(&self, raw: Vec<u8>) -> bool {
        self.output_with_class(raw, false)
    }
    fn output_tcp_control(&self, raw: Vec<u8>) -> bool {
        self.output_with_class(raw, true)
    }
    // Reset packets are small. Keep a bounded copy if the output queue is
    // full so the flow can signal its close after the queue drains.
    fn output_reset(&mut self, key: Key, packet: Vec<u8>, now: Instant) -> bool {
        if self.output_tcp_control(packet.clone()) {
            self.pending_resets.remove(&key);
            return true;
        }
        if !self.pending_resets.contains_key(&key)
            && self.pending_resets.len() >= MAX_PENDING_RESETS
        {
            if let Some(oldest) = self
                .pending_resets
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| *k)
            {
                self.pending_resets.remove(&oldest);
                inc(&self.counters.tcp_resets_lost);
            }
        }
        self.pending_resets.insert(
            key,
            PendingReset {
                packet,
                created: now,
                next_attempt: now + RESET_RETRY,
                attempts: 1,
            },
        );
        false
    }
    fn retry_resets(&mut self, now: Instant) {
        for (key, mut pending) in std::mem::take(&mut self.pending_resets) {
            if now < pending.next_attempt {
                self.pending_resets.insert(key, pending);
            } else if !self.output_tcp_control(pending.packet.clone()) {
                pending.attempts += 1;
                if pending.attempts < MAX_RESET_ATTEMPTS {
                    pending.next_attempt = now + RESET_RETRY;
                    self.pending_resets.insert(key, pending);
                } else {
                    inc(&self.counters.tcp_resets_lost);
                }
            }
        }
    }
    fn remember_tcp_close(&mut self, key: Key, engine: &tcp::TcpFlow, now: Instant) {
        let Some((seq, ack)) = engine.graceful_close_ack() else {
            return;
        };
        self.closed_tcp.retain(|_, entry| {
            now.saturating_duration_since(entry.closed_at) < CLOSED_TCP_LIFETIME
        });
        if !self.closed_tcp.contains_key(&key) && self.closed_tcp.len() >= MAX_CLOSED_TCP {
            if let Some(oldest) = self
                .closed_tcp
                .iter()
                .min_by_key(|(_, entry)| entry.closed_at)
                .map(|(key, _)| *key)
            {
                self.closed_tcp.remove(&oldest);
            }
        }
        self.closed_tcp.insert(
            key,
            ClosedTcp {
                seq,
                ack,
                closed_at: now,
            },
        );
    }
    fn acknowledge_closed_fin(&mut self, key: Key, seg: &packet::TcpSegment<'_>, now: Instant) {
        let Some(closed) = self.closed_tcp.get(&key).copied() else {
            return;
        };
        if now.saturating_duration_since(closed.closed_at) >= CLOSED_TCP_LIFETIME {
            self.closed_tcp.remove(&key);
            return;
        }
        // A retransmitted FIN can repeat the original PSH, ECE, CWR, or URG
        // flags. Only SYN and RST make it a different segment. The ACK flag
        // and the final sequence number identify the duplicate FIN.
        if seg.flags & (packet::FIN | packet::ACK) != (packet::FIN | packet::ACK)
            || seg.flags & (packet::SYN | packet::RST) != 0
            || seg.seq.wrapping_add(seg.data.len() as u32).wrapping_add(1) != closed.ack
        {
            return;
        }
        let raw = match (key.dst, key.src) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => packet::build_tcp(&packet::TcpBuild {
                src,
                dst,
                sport: key.dport,
                dport: key.sport,
                seq: closed.seq,
                ack: closed.ack,
                flags: packet::ACK,
                window: 0,
                payload: &[],
                options: &[],
                ttl: 64,
                ident: 0,
            }),
            (IpAddr::V6(src), IpAddr::V6(dst)) => packet::build_tcp_v6(&packet::TcpBuildV6 {
                src,
                dst,
                sport: key.dport,
                dport: key.sport,
                seq: closed.seq,
                ack: closed.ack,
                flags: packet::ACK,
                window: 0,
                payload: &[],
                options: &[],
                hop_limit: 64,
            }),
            _ => Err("address family mismatch"),
        };
        match raw {
            Ok(packet) => {
                self.output_tcp_control(packet);
            }
            Err(_) => {
                inc(&self.counters.send_dropped);
                self.count_relay_drop();
            }
        }
    }
    fn output_with_class(&self, raw: Vec<u8>, control: bool) -> bool {
        let n = raw.len();
        let queued = if control {
            self.output.push_tcp_control(raw)
        } else {
            self.output.push(raw)
        };
        if queued {
            inc(&self.counters.packets_out);
            add(&self.counters.bytes_out, n);
            true
        } else {
            inc(&self.counters.send_dropped);
            self.counters
                .timeline
                .record(Instant::now(), diagnostics::TimelineEvent::RelayDrop);
            false
        }
    }
    fn handle(&mut self, raw: &[u8]) {
        let key = match flow_key(raw) {
            Some(k) => k,
            None => return,
        };
        let p = match packet::parse_ip(raw) {
            Some(p) => p,
            None => return,
        };
        if matches!(key.proto, packet::PROTO_ICMP | packet::PROTO_ICMPV6) {
            self.handle_icmp(&p);
            return;
        }
        if key.proto == packet::PROTO_TCP {
            let seg = match packet::parse_tcp(p.payload) {
                Some(s) => s,
                None => return,
            };
            // A bare SYN on an occupied 4-tuple gets a challenge ACK from the
            // endpoint, not a replacement. The tunnel can carry forwarded as
            // well as local traffic, so a forged SYN must not close a live
            // flow without a sequence number. A local client in SYN-SENT
            // answers the challenge with a reset at the next expected byte,
            // and its SYN retransmit then creates a new flow.
            if !self.tcp.contains_key(&key) {
                if seg.flags & packet::SYN == 0
                    || seg.flags & (packet::ACK | packet::RST | packet::FIN) != 0
                {
                    self.acknowledge_closed_fin(key, &seg, Instant::now());
                    return;
                }
                self.closed_tcp.remove(&key);
                // A retained reset belongs to the previous use of this tuple.
                self.pending_resets.remove(&key);
                let now = Instant::now();
                if self.flows_at_capacity() && !self.evict_idle_udp(now) {
                    // No slot is free and no UDP flow is idle. Reset the inner
                    // SYN so the client fails fast and retries later. The cap
                    // also bounds pending source device connects.
                    inc(&self.counters.flow_errors);
                    inc(&self.counters.tcp_capacity_refused);
                    self.refuse_tcp(key, &seg);
                    return;
                }
                let result = match &self.config.phone {
                    Some(phone) => Setup::phone(phone, key.dst, key.dport, 1).and_then(|setup| {
                        phone_tcp_start(phone.address, self.config.iface, &self.audit)
                            .map(|stream| (stream, setup))
                    }),
                    None => direct_tcp_start(
                        SocketAddr::new(crate::dns::canonical_ip(key.dst), key.dport),
                        self.config.iface,
                        &self.audit,
                    )
                    .map(|stream| (stream, Setup::direct())),
                };
                let isn = match random_isn() {
                    Ok(isn) => isn,
                    Err(_) => {
                        inc(&self.counters.flow_errors);
                        return;
                    }
                };
                let mut engine =
                    tcp::TcpFlow::new(seg.seq, isn, seg.options, seg.window, Instant::now());
                // Hold the inner SYN-ACK in source device proxy mode until the
                // source device answers the connect request. The browser must
                // not see a connected socket that cannot carry data.
                if self.config.phone.is_some() {
                    engine.hold_start();
                }
                match result {
                    Ok((stream, setup)) => {
                        if self.config.phone.is_none() {
                            engine.start();
                        }
                        inc(&self.counters.tcp_flows);
                        self.emit(key, &mut engine, Some(&stream));
                        self.tcp.insert(
                            key,
                            TcpEntry {
                                engine,
                                stream,
                                setup: Some(setup),
                                was_established: false,
                                _gauge: TcpFlowGauge::new(&self.counters),
                            },
                        );
                    }
                    Err(e) => {
                        engine.outer_failed();
                        self.emit(key, &mut engine, None);
                        let phase = if self.config.phone.is_some() {
                            TcpSetupPhase::PhoneConnect
                        } else {
                            TcpSetupPhase::DirectConnect
                        };
                        count_tcp_setup_error(&self.counters, &e, phase, None);
                        self.record_failure(
                            failures::Proto::Tcp,
                            key.dst,
                            key.dport,
                            &e,
                            None,
                            Some(failures::Phase::Connect),
                        );
                    }
                }
            } else if let Some(mut entry) = self.tcp.remove(&key) {
                let now = Instant::now();
                entry.engine.on_inner(&seg, now);
                if entry.engine.state == tcp::State::Established {
                    entry.was_established = true;
                }
                self.emit(key, &mut entry.engine, Some(&entry.stream));
                collect_tcp_metrics(&self.counters, &mut entry.engine, now);
                if entry.engine.state != tcp::State::Closed {
                    self.tcp.insert(key, entry);
                } else {
                    close_outer(&entry);
                    self.remember_tcp_close(key, &entry.engine, now);
                    self.note_tcp_teardown(&entry, now);
                    inc(&self.counters.tcp_flows_closed);
                    // `entry` drops at the end of this block and its gauge
                    // lowers the live flow count exactly once.
                }
            }
        } else if key.proto == packet::PROTO_UDP {
            let now = Instant::now();
            let seg = match packet::parse_udp(p.payload) {
                Some(s) => s,
                None => return,
            };
            let max_payload = if key.dst.is_ipv6() {
                MAX_DATAGRAM - 20
            } else {
                MAX_DATAGRAM
            };
            if seg.data.len() > max_payload {
                self.count_udp_drop(now);
                return;
            }
            if self.config.phone.is_some()
                && key.dport == 53
                && (seg.data.len() < 12 || seg.data[2] & 0x80 != 0)
            {
                self.count_udp_drop(now);
                return;
            }
            if !self.udp.contains_key(&key) {
                if self.tcp.len() + self.udp.len() + self.icmp.len() + self.sessions.len()
                    >= MAX_FLOWS_PER_WORKER
                {
                    self.count_udp_drop(now);
                    return;
                }
                match self.new_udp(key) {
                    Ok(entry) => {
                        self.udp.insert(key, entry);
                    }
                    Err(_) => {
                        inc(&self.counters.udp_errors);
                        return;
                    }
                }
            }
            let entry = self.udp.get_mut(&key).unwrap();
            let result = match &mut entry.socket {
                UdpSocketKind::Direct(sock) => sock.send(seg.data).map(|_| ()),
                UdpSocketKind::Phone {
                    outgoing,
                    frames,
                    dns,
                    ..
                } => {
                    if (*dns && entry.dns_query_id.is_some())
                        || outgoing.len() + seg.data.len() + 2 > MAX_UDP_OUTGOING
                    {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, "UDP queue full"))
                    } else {
                        if *dns {
                            entry.dns_query_id = Some([seg.data[0], seg.data[1]]);
                        }
                        outgoing.extend_from_slice(&(seg.data.len() as u16).to_be_bytes());
                        outgoing.extend_from_slice(seg.data);
                        frames.push(seg.data.len() + 2, Instant::now());
                        Ok(())
                    }
                }
            };
            match result {
                Ok(()) => {
                    entry.last = Instant::now();
                    inc(&self.counters.udp_datagrams_out);
                }
                Err(_) => self.count_udp_drop(now),
            }
        }
    }
    fn handle_icmp(&mut self, ip: &packet::IpPacket<'_>) {
        let echo = match packet::parse_echo_request(ip) {
            Some(e) => e,
            None => {
                inc(&self.counters.icmp_dropped);
                return;
            }
        };
        if self.config.icmp_persistent {
            self.handle_persistent_icmp(ip, echo.identifier, echo.sequence, echo.data);
            return;
        }
        if !self.config.icmp_phone
            || !valid_icmp_target(ip.dst)
            || self.tcp.len() + self.udp.len() + self.icmp.len() + self.sessions.len()
                >= MAX_FLOWS_PER_WORKER
        {
            inc(&self.counters.icmp_dropped);
            return;
        }
        let Some(permit) = reserve_icmp(&self.counters) else {
            inc(&self.counters.icmp_dropped);
            return;
        };
        let Some(phone) = self.config.phone.as_ref() else {
            inc(&self.counters.icmp_dropped);
            return;
        };
        let setup = match Setup::phone(phone, ip.dst, 0, 0x81) {
            Ok(s) => s,
            Err(_) => {
                count_icmp_failure(&self.counters, IcmpFailure::Setup);
                return;
            }
        };
        let stream = match phone_tcp_start(phone.address, self.config.iface, &self.audit) {
            Ok(s) => s,
            Err(_) => {
                count_icmp_failure(&self.counters, IcmpFailure::Setup);
                return;
            }
        };
        let mut outgoing = Vec::with_capacity(2 + echo.data.len());
        outgoing.extend_from_slice(&(echo.data.len() as u16).to_be_bytes());
        outgoing.extend_from_slice(echo.data);
        self.icmp.push(IcmpEntry {
            stream,
            setup: Some(setup),
            src: ip.src,
            dst: ip.dst,
            identifier: echo.identifier,
            sequence: echo.sequence,
            outgoing,
            sent: 0,
            incoming: Vec::new(),
            payload: echo.data.to_vec(),
            deadline: Instant::now() + ICMP_TIMEOUT,
            _permit: permit,
        });
        inc(&self.counters.icmp_requests);
    }
    fn handle_persistent_icmp(
        &mut self,
        ip: &packet::IpPacket<'_>,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) {
        if !self.config.icmp_phone || !valid_icmp_target(ip.dst) || payload.len() > 1184 {
            inc(&self.counters.icmp_dropped);
            return;
        }
        let key = Key {
            proto: ip.protocol,
            src: ip.src,
            dst: ip.dst,
            sport: identifier,
            dport: 0,
        };
        let now = Instant::now();
        if !self.sessions.contains_key(&key) {
            if self.tcp.len() + self.udp.len() + self.icmp.len() + self.sessions.len()
                >= MAX_FLOWS_PER_WORKER
            {
                inc(&self.counters.icmp_dropped);
                return;
            }
            let mut permit = reserve_icmp(&self.counters);
            if permit.is_none() {
                // Release an idle local session before rejecting a new flow.
                if let Some(oldest) = self
                    .sessions
                    .iter()
                    .filter(|(_, s)| s.active.is_none() && s.queued.is_empty())
                    .min_by_key(|(_, s)| s.last)
                    .map(|(k, _)| *k)
                {
                    self.sessions.remove(&oldest);
                    permit = reserve_icmp(&self.counters);
                }
            }
            let Some(permit) = permit else {
                inc(&self.counters.icmp_dropped);
                return;
            };
            let Some(phone) = self.config.phone.as_ref() else {
                inc(&self.counters.icmp_dropped);
                return;
            };
            let setup = match Setup::phone(phone, ip.dst, 0, 0x82) {
                Ok(s) => s,
                Err(_) => {
                    count_icmp_failure(&self.counters, IcmpFailure::Setup);
                    return;
                }
            };
            let stream = match phone_tcp_start(phone.address, self.config.iface, &self.audit) {
                Ok(s) => s,
                Err(_) => {
                    count_icmp_failure(&self.counters, IcmpFailure::Setup);
                    return;
                }
            };
            self.sessions.insert(
                key,
                IcmpSession {
                    stream,
                    setup: Some(setup),
                    queued: VecDeque::new(),
                    active: None,
                    outgoing: Vec::new(),
                    sent: 0,
                    incoming: Vec::new(),
                    created: now,
                    last: now,
                    _permit: permit,
                },
            );
        }
        let session = self.sessions.get_mut(&key).unwrap();
        if session.queued.len() + usize::from(session.active.is_some()) >= ICMP_PENDING_LIMIT {
            inc(&self.counters.icmp_dropped);
            return;
        }
        let mut nonce = [0u8; 16];
        if random_bytes(&mut nonce).is_err() {
            count_icmp_failure(&self.counters, IcmpFailure::Io);
            return;
        }
        session.queued.push_back(EchoProbe {
            sequence,
            payload: payload.to_vec(),
            nonce,
            deadline: now + ICMP_TIMEOUT,
        });
        session.last = now;
        inc(&self.counters.icmp_requests);
    }
    fn new_udp(&self, key: Key) -> io::Result<UdpEntry> {
        let now = Instant::now();
        let socket = if let Some(phone) = &self.config.phone {
            let dns = key.dport == 53;
            if dns {
                inc(&self.counters.dns_flows);
                inc(&self.counters.dns_lookups);
            }
            let (target, port, command) = if dns {
                (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53, 1)
            } else {
                (key.dst, key.dport, 0x80)
            };
            let setup = match Setup::phone(phone, target, port, command) {
                Ok(setup) => setup,
                Err(error) => {
                    if dns {
                        inc(&self.counters.dns_setup_failed);
                        inc(&self.counters.dns_failed);
                        self.counters
                            .dns_ms
                            .record(now.elapsed().as_micros().min(u64::MAX as u128) as u64);
                        self.record_dns_failure(&error, None, Some(failures::Phase::Connect));
                    } else {
                        self.record_failure(
                            failures::Proto::Udp,
                            key.dst,
                            key.dport,
                            &error,
                            None,
                            Some(failures::Phase::Connect),
                        );
                    }
                    return Err(error);
                }
            };
            let stream = match phone_tcp_start(phone.address, self.config.iface, &self.audit) {
                Ok(stream) => stream,
                Err(error) => {
                    if dns {
                        inc(&self.counters.dns_setup_failed);
                        inc(&self.counters.dns_failed);
                        self.counters
                            .dns_ms
                            .record(now.elapsed().as_micros().min(u64::MAX as u128) as u64);
                        self.record_dns_failure(&error, None, Some(failures::Phase::Connect));
                    } else {
                        self.record_failure(
                            failures::Proto::Udp,
                            key.dst,
                            key.dport,
                            &error,
                            None,
                            Some(failures::Phase::Connect),
                        );
                    }
                    return Err(error);
                }
            };
            UdpSocketKind::Phone {
                stream,
                incoming: Vec::new(),
                outgoing: Vec::new(),
                frames: UdpFrameQueue::new(),
                dns,
                setup: Some(setup),
            }
        } else {
            let dest = if key.dport == 53 {
                self.config
                    .dns_upstream
                    .unwrap_or(SocketAddr::new(key.dst, key.dport))
            } else {
                SocketAddr::new(crate::dns::canonical_ip(key.dst), key.dport)
            };
            let dest = SocketAddr::new(crate::dns::canonical_ip(dest.ip()), dest.port());
            let sock = normalization::udp_socket(dest.ip(), self.config.iface, &self.audit)?;
            sock.connect(dest)?;
            sock.set_nonblocking(true)?;
            UdpSocketKind::Direct(sock)
        };
        inc(&self.counters.udp_flows);
        Ok(UdpEntry {
            socket,
            last: now,
            dns_query_id: None,
            dns_started: (key.dport == 53 && self.config.phone.is_some()).then_some(now),
        })
    }
    /// Record one completed DNS lookup, answer or failure.
    fn record_dns_result(&self, started: Option<Instant>, ok: bool) {
        if let Some(started) = started {
            self.counters
                .dns_ms
                .record(started.elapsed().as_micros().min(u64::MAX as u128) as u64);
        }
        if ok {
            inc(&self.counters.dns_ok);
        } else {
            inc(&self.counters.dns_failed);
        }
    }
    fn emit(&mut self, key: Key, engine: &mut tcp::TcpFlow, stream: Option<&TcpStream>) {
        for action in engine.actions() {
            match action {
                tcp::Action::Send {
                    accounting,
                    flags,
                    seq,
                    ack,
                    window,
                    options,
                    data,
                } => {
                    let raw = match (key.dst, key.src) {
                        (IpAddr::V4(src), IpAddr::V4(dst)) => {
                            packet::build_tcp(&packet::TcpBuild {
                                src,
                                dst,
                                sport: key.dport,
                                dport: key.sport,
                                seq,
                                ack,
                                flags,
                                window,
                                payload: &data,
                                options: &options,
                                ttl: 64,
                                ident: 0,
                            })
                        }
                        (IpAddr::V6(src), IpAddr::V6(dst)) => {
                            packet::build_tcp_v6(&packet::TcpBuildV6 {
                                src,
                                dst,
                                sport: key.dport,
                                dport: key.sport,
                                seq,
                                ack,
                                flags,
                                window,
                                payload: &data,
                                options: &options,
                                hop_limit: 64,
                            })
                        }
                        _ => Err("address family mismatch"),
                    };
                    let queued = if let Ok(raw) = raw {
                        if flags & packet::RST != 0 {
                            self.output_reset(key, raw, Instant::now())
                        } else if flags & packet::FIN != 0 {
                            self.output_tcp_control(raw)
                        } else {
                            self.output(raw)
                        }
                    } else {
                        inc(&self.counters.send_dropped);
                        self.count_relay_drop();
                        false
                    };
                    if !queued {
                        engine.output_rejected(accounting, Instant::now());
                    }
                }
                tcp::Action::ShutdownWrite => {
                    if let Some(s) = stream {
                        let _ = s.shutdown(Shutdown::Write);
                    }
                }
                tcp::Action::Close => {}
            }
        }
    }
    fn pump_icmp_sessions(&mut self, now: Instant) {
        for (key, mut s) in std::mem::take(&mut self.sessions) {
            let mut failure = None;
            while s.queued.front().is_some_and(|p| now >= p.deadline) {
                s.queued.pop_front();
                count_icmp_failure(&self.counters, IcmpFailure::Timeout);
            }
            if s.active.as_ref().is_some_and(|p| now >= p.deadline) {
                failure = Some(IcmpFailure::Timeout);
            }
            if now.duration_since(s.created) >= ICMP_SESSION_MAX_AGE {
                failure = Some(IcmpFailure::Timeout);
            }
            if failure.is_none() {
                if let Some(setup) = s.setup.as_mut() {
                    match setup.advance(&mut s.stream) {
                        Ok(true) => s.setup = None,
                        Ok(false) => {}
                        Err(e) => {
                            failure = Some(if e.kind() == io::ErrorKind::TimedOut {
                                IcmpFailure::Timeout
                            } else {
                                IcmpFailure::Setup
                            })
                        }
                    }
                }
            }
            if failure.is_none() && s.setup.is_none() {
                // Detect unexpected data or EOF before sending the next request.
                if s.active.is_none() {
                    let mut extra = [0u8; 1];
                    match s.stream.read(&mut extra) {
                        Ok(0) | Ok(_) => failure = Some(IcmpFailure::Malformed),
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => failure = Some(IcmpFailure::Io),
                    }
                }
                if failure.is_none() && s.active.is_none() {
                    if let Some(probe) = s.queued.pop_front() {
                        s.outgoing.clear();
                        s.outgoing.extend_from_slice(
                            &((probe.payload.len() + probe.nonce.len()) as u16).to_be_bytes(),
                        );
                        s.outgoing.extend_from_slice(&probe.nonce);
                        s.outgoing.extend_from_slice(&probe.payload);
                        s.sent = 0;
                        s.active = Some(probe);
                    }
                }
                if failure.is_none() && s.active.is_some() && s.sent < s.outgoing.len() {
                    match s.stream.write(&s.outgoing[s.sent..]) {
                        Ok(0) => failure = Some(IcmpFailure::Io),
                        Ok(n) => s.sent += n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => failure = Some(IcmpFailure::Io),
                    }
                }
                if failure.is_none() && s.active.is_some() && s.sent == s.outgoing.len() {
                    let mut data = [0u8; 1204];
                    match s.stream.read(&mut data) {
                        Ok(0) => failure = Some(IcmpFailure::Malformed),
                        Ok(n) => {
                            s.incoming.extend_from_slice(&data[..n]);
                            if s.incoming.len() > 1203 {
                                failure = Some(IcmpFailure::Malformed);
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => failure = Some(IcmpFailure::Io),
                    }
                }
                if failure.is_none() && s.incoming.len() >= 3 {
                    let status = s.incoming[0];
                    let len = u16::from_be_bytes([s.incoming[1], s.incoming[2]]) as usize;
                    let probe = s.active.as_ref().unwrap();
                    if len > 1200
                        || (status != 0 && len != 0)
                        || status > 9
                        || s.incoming.len() > len + 3
                    {
                        failure = Some(IcmpFailure::Malformed);
                    } else if status == 0 && len != probe.payload.len() + probe.nonce.len() {
                        failure = Some(IcmpFailure::PayloadMismatch);
                    } else if s.incoming.len() == len + 3 {
                        failure = match status {
                            1 => Some(IcmpFailure::NoCellular),
                            2 => Some(IcmpFailure::Busy),
                            3 => Some(IcmpFailure::PhoneTimeout),
                            4 => Some(IcmpFailure::PhoneFailed),
                            5 => Some(IcmpFailure::PathNoUpdate),
                            6 => Some(IcmpFailure::PathUnsatisfied),
                            7 => Some(IcmpFailure::PathNotCellular),
                            8 => Some(IcmpFailure::PathNoInterface),
                            9 => Some(IcmpFailure::PathAmbiguous),
                            _ if s.incoming[3..19] != probe.nonce
                                || s.incoming[19..] != probe.payload =>
                            {
                                Some(IcmpFailure::PayloadMismatch)
                            }
                            _ => match packet::build_echo_reply(
                                key.dst,
                                key.src,
                                key.sport,
                                probe.sequence,
                                &probe.payload,
                            ) {
                                Ok(reply) => {
                                    if self.output(reply) {
                                        inc(&self.counters.icmp_replies);
                                        None
                                    } else {
                                        Some(IcmpFailure::Output)
                                    }
                                }
                                _ => Some(IcmpFailure::Output),
                            },
                        };
                        if failure.is_none() {
                            s.active = None;
                            s.incoming.clear();
                            s.last = now;
                        }
                    }
                }
            }
            if let Some(reason) = failure {
                if s.active.take().is_some() {
                    count_icmp_failure(&self.counters, reason);
                } else if !s.queued.is_empty() {
                    count_icmp_failure(&self.counters, reason);
                    s.queued.pop_front();
                }
                for _ in s.queued {
                    count_icmp_failure(&self.counters, IcmpFailure::Io);
                }
            } else if s.active.is_some()
                || !s.queued.is_empty()
                || now.duration_since(s.last) < ICMP_SESSION_IDLE
            {
                self.sessions.insert(key, s);
            }
        }
    }
    fn pump(&mut self) {
        let now = Instant::now();
        // A close record answers a retransmitted FIN for a bounded time. Drop
        // the expired records even when no new flow closes, so the table does
        // not hold tuple state for an idle worker.
        self.closed_tcp.retain(|_, entry| {
            now.saturating_duration_since(entry.closed_at) < CLOSED_TCP_LIFETIME
        });
        self.retry_resets(now);
        self.pump_icmp_sessions(now);
        for mut entry in std::mem::take(&mut self.icmp) {
            let mut failure = if now >= entry.deadline {
                Some(IcmpFailure::Timeout)
            } else {
                None
            };
            if failure.is_none() {
                if let Some(setup) = entry.setup.as_mut() {
                    match setup.advance(&mut entry.stream) {
                        Ok(true) => entry.setup = None,
                        Ok(false) => {}
                        Err(e) => {
                            failure = Some(if e.kind() == io::ErrorKind::TimedOut {
                                IcmpFailure::Timeout
                            } else {
                                IcmpFailure::Setup
                            })
                        }
                    }
                }
            }
            if failure.is_none() && entry.setup.is_none() && entry.sent < entry.outgoing.len() {
                match entry.stream.write(&entry.outgoing[entry.sent..]) {
                    Ok(0) => failure = Some(IcmpFailure::Io),
                    Ok(n) => entry.sent += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => failure = Some(IcmpFailure::Io),
                }
            }
            if failure.is_none() && entry.setup.is_none() && entry.sent == entry.outgoing.len() {
                let mut data = [0u8; 1204];
                match entry.stream.read(&mut data) {
                    Ok(0) => failure = Some(IcmpFailure::Malformed),
                    Ok(n) => {
                        entry.incoming.extend_from_slice(&data[..n]);
                        if entry.incoming.len() > 1203 {
                            failure = Some(IcmpFailure::Malformed);
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => failure = Some(IcmpFailure::Io),
                }
            }
            let mut complete = false;
            if failure.is_none() && entry.incoming.len() >= 3 {
                let status = entry.incoming[0];
                let len = u16::from_be_bytes([entry.incoming[1], entry.incoming[2]]) as usize;
                if len > 1200
                    || (status != 0 && len != 0)
                    || status > 9
                    || entry.incoming.len() > len + 3
                {
                    failure = Some(IcmpFailure::Malformed);
                } else if status == 0 && len != entry.payload.len() {
                    failure = Some(IcmpFailure::PayloadMismatch);
                } else if entry.incoming.len() == len + 3 {
                    complete = true;
                    failure = match status {
                        1 => Some(IcmpFailure::NoCellular),
                        2 => Some(IcmpFailure::Busy),
                        3 => Some(IcmpFailure::PhoneTimeout),
                        4 => Some(IcmpFailure::PhoneFailed),
                        5 => Some(IcmpFailure::PathNoUpdate),
                        6 => Some(IcmpFailure::PathUnsatisfied),
                        7 => Some(IcmpFailure::PathNotCellular),
                        8 => Some(IcmpFailure::PathNoInterface),
                        9 => Some(IcmpFailure::PathAmbiguous),
                        _ if entry.incoming[3..] != entry.payload => {
                            Some(IcmpFailure::PayloadMismatch)
                        }
                        _ => match packet::build_echo_reply(
                            entry.dst,
                            entry.src,
                            entry.identifier,
                            entry.sequence,
                            &entry.payload,
                        ) {
                            Ok(reply) => {
                                if self.output(reply) {
                                    inc(&self.counters.icmp_replies);
                                    None
                                } else {
                                    Some(IcmpFailure::Output)
                                }
                            }
                            Err(_) => Some(IcmpFailure::Output),
                        },
                    };
                }
            }
            if let Some(failure) = failure {
                count_icmp_failure(&self.counters, failure);
            } else if !complete {
                self.icmp.push(entry);
            }
        }
        let mut observed = false;
        for (key, mut entry) in std::mem::take(&mut self.tcp) {
            if let Some(setup) = entry.setup.as_mut() {
                match setup.advance(&mut entry.stream) {
                    Ok(true) => {
                        let timings = entry.setup.as_mut().and_then(Setup::take_timings);
                        entry.setup = None;
                        if let Some(timings) = timings {
                            record_setup_timings(&self.counters, timings);
                        }
                        entry.engine.release_start();
                        entry.engine.outer_connected();
                        entry.was_established = entry.engine.state == tcp::State::Established;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        entry.engine.outer_failed();
                        let phase = setup.timeout_phase();
                        let failure_phase = setup.failure_phase();
                        let code = setup.reply;
                        count_tcp_setup_error(&self.counters, &e, phase, code);
                        self.record_failure(
                            failures::Proto::Tcp,
                            key.dst,
                            key.dport,
                            &e,
                            code,
                            Some(failure_phase),
                        );
                    }
                }
            }
            if entry.setup.is_none() && entry.engine.state != tcp::State::Closed {
                let pending = entry.engine.pending_bytes();
                if !pending.is_empty() {
                    match entry.stream.write(pending) {
                        Ok(0) => {
                            entry.engine.outer_failed();
                            inc(&self.counters.flow_errors);
                            inc(&self.counters.tcp_io_errors);
                            self.count_outer_error(now);
                        }
                        Ok(n) => {
                            entry.engine.outer_written(n);
                            add(&self.counters.bytes_in, n);
                        }
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            entry.engine.outer_failed();
                            inc(&self.counters.flow_errors);
                            inc(&self.counters.tcp_io_errors);
                            self.count_outer_error(now);
                        }
                    }
                }
                if !entry.engine.read_paused
                    && !entry.engine.outer_eof
                    && entry.engine.state != tcp::State::Closed
                {
                    let mut buf = [0u8; 65536];
                    match entry.stream.read(&mut buf) {
                        Ok(0) => entry.engine.outer_end(now),
                        Ok(n) => entry.engine.outer_data(&buf[..n], now),
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            entry.engine.outer_failed();
                            inc(&self.counters.flow_errors);
                            inc(&self.counters.tcp_io_errors);
                            self.count_outer_error(now);
                        }
                    }
                }
            }
            let connecting_phase = if entry.engine.state == tcp::State::Connecting {
                entry.setup.as_ref().map(Setup::timeout_phase)
            } else {
                None
            };
            entry.engine.tick(now);
            if entry.engine.state == tcp::State::Established {
                entry.was_established = true;
            }
            observed |= entry.was_established;
            if entry.engine.state == tcp::State::Closed {
                if let Some(phase) = connecting_phase {
                    let error = io::Error::new(io::ErrorKind::TimedOut, "TCP setup timed out");
                    count_tcp_setup_error(&self.counters, &error, phase, None);
                    self.record_failure(
                        failures::Proto::Tcp,
                        key.dst,
                        key.dport,
                        &error,
                        None,
                        Some(phase.failure_phase()),
                    );
                }
            }
            self.emit(key, &mut entry.engine, Some(&entry.stream));
            collect_tcp_metrics(&self.counters, &mut entry.engine, now);
            if entry.engine.state != tcp::State::Closed {
                self.tcp.insert(key, entry);
            } else {
                close_outer(&entry);
                self.remember_tcp_close(key, &entry.engine, now);
                self.note_tcp_teardown(&entry, now);
                inc(&self.counters.tcp_flows_closed);
                // `entry` drops at the end of this block and its gauge lowers
                // the live flow count exactly once.
            }
        }
        // Record one observation for the whole worker. The old per-packet
        // write added an atomic compare-exchange to the data path.
        if observed {
            self.counters
                .timeline
                .record(now, diagnostics::TimelineEvent::Observed);
        }
        for (key, mut entry) in std::mem::take(&mut self.udp) {
            let mut replies: Vec<Vec<u8>> = Vec::new();
            let mut closed = false;
            let mut setup_failed = false;
            let mut answered = false;
            let dns_started = entry.dns_started;
            let observing = match &entry.socket {
                UdpSocketKind::Direct(_) => true,
                UdpSocketKind::Phone { setup, .. } => setup.is_none(),
            };
            if observing {
                self.counters
                    .timeline
                    .record(now, diagnostics::TimelineEvent::Observed);
            }
            match &mut entry.socket {
                UdpSocketKind::Direct(sock) => {
                    let mut buf = [0u8; 65535];
                    for _ in 0..32 {
                        match sock.recv(&mut buf) {
                            Ok(n) => replies.push(buf[..n].to_vec()),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => {
                                inc(&self.counters.udp_errors);
                                closed = true;
                                break;
                            }
                        }
                    }
                }
                UdpSocketKind::Phone {
                    stream,
                    incoming,
                    outgoing,
                    frames,
                    dns,
                    setup,
                } => {
                    if let Some(state) = setup.as_mut() {
                        match state.advance(stream) {
                            Ok(true) => {
                                *setup = None;
                                if *dns {
                                    inc(&self.counters.dns_setup_ok);
                                }
                                // Datagrams queued during setup start fresh.
                                frames.restamp(Instant::now());
                            }
                            Ok(false) => {}
                            Err(error) => {
                                closed = true;
                                setup_failed = true;
                                let code = state.reply;
                                let phase = state.failure_phase();
                                if *dns {
                                    inc(&self.counters.dns_setup_failed);
                                    self.record_dns_result(dns_started, false);
                                    self.record_dns_failure(&error, code, Some(phase));
                                } else {
                                    self.record_failure(
                                        failures::Proto::Udp,
                                        key.dst,
                                        key.dport,
                                        &error,
                                        code,
                                        Some(phase),
                                    );
                                }
                                inc(&self.counters.udp_errors);
                            }
                        }
                    }
                    if setup.is_some() || closed {
                        if closed {
                            self.note_udp_teardown(now);
                            inc(&self.counters.udp_flows_closed);
                        } else {
                            self.udp.insert(key, entry);
                        }
                        continue;
                    }
                    if !*dns && !outgoing.is_empty() {
                        let expired_at = Instant::now();
                        let expired = frames.expire(outgoing, expired_at, MAX_UDP_OUTGOING_AGE);
                        for _ in 0..expired {
                            inc(&self.counters.udp_age_drops);
                            self.count_udp_drop(expired_at);
                        }
                    }
                    if !outgoing.is_empty() {
                        match stream.write(outgoing) {
                            Ok(0) => closed = true,
                            Ok(n) => {
                                outgoing.drain(..n);
                                frames.advance(n);
                            }
                            Err(e)
                                if e.kind() == io::ErrorKind::WouldBlock
                                    || e.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => closed = true,
                        }
                    }
                    let mut buf = [0u8; 16384];
                    for _ in 0..8 {
                        match stream.read(&mut buf) {
                            Ok(0) => {
                                closed = true;
                                break;
                            }
                            Ok(n) => {
                                incoming.extend_from_slice(&buf[..n]);
                                if incoming.len() > MAX_UDP_BUFFER {
                                    closed = true;
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => {
                                closed = true;
                                break;
                            }
                        }
                    }
                    while incoming.len() >= 2 {
                        let n = u16::from_be_bytes([incoming[0], incoming[1]]) as usize;
                        if n > MAX_DATAGRAM {
                            inc(&self.counters.udp_reply_too_big);
                            closed = true;
                            break;
                        }
                        if incoming.len() < n + 2 {
                            break;
                        }
                        if *dns
                            && (n < 12
                                || Some([incoming[2], incoming[3]]) != entry.dns_query_id
                                || incoming[4] & 0x80 == 0)
                        {
                            inc(&self.counters.udp_errors);
                            closed = true;
                            break;
                        }
                        if *dns {
                            if let Some(recorder) = self.config.failures.as_ref() {
                                recorder.remember_dns_response(&incoming[2..n + 2]);
                            }
                        }
                        answered = true;
                        if *dns {
                            self.record_dns_result(dns_started, true);
                        }
                        replies.push(incoming[2..n + 2].to_vec());
                        incoming.drain(..n + 2);
                        if *dns {
                            closed = true;
                            break;
                        }
                    }
                }
            }
            if closed
                && !setup_failed
                && !answered
                && matches!(&entry.socket, UdpSocketKind::Phone { .. })
            {
                let error = io::Error::other("source device UDP flow closed");
                if matches!(&entry.socket, UdpSocketKind::Phone { dns: true, .. }) {
                    self.record_dns_result(dns_started, false);
                    self.record_dns_failure(&error, None, Some(failures::Phase::Request));
                } else {
                    self.record_failure(
                        failures::Proto::Udp,
                        key.dst,
                        key.dport,
                        &error,
                        None,
                        Some(failures::Phase::Request),
                    );
                }
            }
            for data in replies {
                let max_payload = if key.dst.is_ipv6() {
                    MAX_DATAGRAM - 20
                } else {
                    MAX_DATAGRAM
                };
                if data.len() > max_payload {
                    inc(&self.counters.udp_reply_too_big);
                    continue;
                }
                let raw = match (key.dst, key.src) {
                    (IpAddr::V4(src), IpAddr::V4(dst)) => {
                        packet::build_udp(src, dst, key.dport, key.sport, &data, 64, 0)
                    }
                    (IpAddr::V6(src), IpAddr::V6(dst)) => {
                        packet::build_udp_v6(src, dst, key.dport, key.sport, &data, 64)
                    }
                    _ => Err("address family mismatch"),
                };
                if let Ok(raw) = raw {
                    self.output(raw);
                    inc(&self.counters.udp_datagrams_in);
                    entry.last = now;
                }
            }
            let timeout = match &entry.socket {
                UdpSocketKind::Phone { dns: true, .. } => DNS_TIMEOUT,
                _ => UDP_IDLE,
            };
            let dns_timeout = !closed
                && matches!(&entry.socket, UdpSocketKind::Phone { dns: true, .. })
                && now.duration_since(entry.last) > timeout;
            if dns_timeout {
                let error = io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out");
                self.record_dns_result(dns_started, false);
                self.record_dns_failure(&error, None, Some(failures::Phase::Request));
            }
            if closed || dns_timeout || now.duration_since(entry.last) > timeout {
                self.note_udp_teardown(now);
                inc(&self.counters.udp_flows_closed);
            } else {
                self.udp.insert(key, entry);
            }
        }
    }
}

/// Fill `buffer` from the operating system random source.
///
/// The relay uses the pairing random source. Do not add a second generator.
fn random_bytes(buffer: &mut [u8]) -> io::Result<()> {
    pairing::random_bytes(buffer).map_err(|_| io::Error::other("random source failed"))
}

fn random_isn() -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    random_bytes(&mut bytes)?;
    Ok(u32::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn phone_setup_clears_authentication_after_send() {
        let (mut client, mut peer) = tcp_pair();
        let phone = phone::PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(5),
        };
        let mut setup = Setup::phone(&phone, Ipv4Addr::LOCALHOST.into(), 443, 1).unwrap();
        setup.stage = SetupStage::SendAuth;
        assert!(!setup.advance(&mut client).unwrap());
        let mut frame = [0u8; 6];
        peer.read_exact(&mut frame).unwrap();
        assert_eq!(frame, [1, 1, b'u', 2, b'p', b'w']);
        assert!(setup.auth.is_empty());
        assert!(matches!(setup.stage, SetupStage::ReadAuth));
    }

    /// The local access-denied values that map to `PermissionDenied`.
    #[cfg(unix)]
    const LOCAL_DENIED_CODES: [i32; 2] = [libc::EACCES, libc::EPERM];
    /// The local access-denied value that maps to `PermissionDenied`.
    #[cfg(windows)]
    const LOCAL_DENIED_CODES: [i32; 1] = [5];

    #[cfg(unix)]
    fn keepalive_enabled(stream: &TcpStream) -> bool {
        use std::os::fd::AsRawFd;
        let mut enabled: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&enabled) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&mut enabled as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(len as usize, std::mem::size_of_val(&enabled));
        enabled != 0
    }

    /// Set SO_LINGER to zero so that close sends a reset.
    #[cfg(unix)]
    fn reset_on_close(stream: &TcpStream) {
        use std::os::fd::AsRawFd;
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    std::mem::size_of_val(&linger) as libc::socklen_t,
                )
            },
            0
        );
    }

    /// Read `SO_KEEPALIVE` on one stream.
    #[cfg(windows)]
    fn keepalive_enabled(stream: &TcpStream) -> bool {
        use std::os::windows::io::AsRawSocket;
        const SOL_SOCKET: i32 = 0xffff;
        const SO_KEEPALIVE: i32 = 0x0008;
        #[link(name = "ws2_32")]
        extern "system" {
            #[allow(clashing_extern_declarations)]
            fn getsockopt(
                socket: std::os::windows::io::RawSocket,
                level: i32,
                option: i32,
                value: *mut u8,
                length: *mut i32,
            ) -> i32;
        }
        // Winsock returns one byte for this BOOL option on current Windows
        // and four bytes on some providers. Decode each length on its own.
        let mut enabled = [0u8; 4];
        let mut length = enabled.len() as i32;
        let result = unsafe {
            getsockopt(
                stream.as_raw_socket(),
                SOL_SOCKET,
                SO_KEEPALIVE,
                enabled.as_mut_ptr(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        match length {
            1 => enabled[0] != 0,
            4 => i32::from_ne_bytes(enabled) != 0,
            other => panic!("unexpected SO_KEEPALIVE length {other}"),
        }
    }

    /// Set SO_LINGER to zero so that close sends a reset.
    #[cfg(windows)]
    fn reset_on_close(stream: &TcpStream) {
        use std::os::windows::io::{AsRawSocket, RawSocket};
        const SOL_SOCKET: i32 = 0xffff;
        const SO_LINGER: i32 = 0x0080;
        /// The Winsock `linger` structure. Both fields are 16 bits.
        #[repr(C)]
        struct Linger {
            onoff: u16,
            linger: u16,
        }
        #[link(name = "ws2_32")]
        extern "system" {
            #[allow(clashing_extern_declarations)]
            fn setsockopt(
                socket: RawSocket,
                level: i32,
                option: i32,
                value: *const u8,
                length: i32,
            ) -> i32;
        }
        let linger = Linger {
            onoff: 1,
            linger: 0,
        };
        assert_eq!(
            unsafe {
                setsockopt(
                    stream.as_raw_socket(),
                    SOL_SOCKET,
                    SO_LINGER,
                    (&linger as *const Linger).cast(),
                    std::mem::size_of_val(&linger) as i32,
                )
            },
            0
        );
    }

    #[test]
    fn keepalive_failure_is_reported_once_with_fixed_text() {
        let reported = AtomicBool::new(false);
        assert!(!first_keepalive_failure(&Ok(()), &reported));
        let failed = || Err(io::Error::other("detail for 192.0.2.1"));
        assert!(first_keepalive_failure(&failed(), &reported));
        assert!(!first_keepalive_failure(&failed(), &reported));
        assert!(!first_keepalive_failure(&Ok(()), &reported));
        assert!(!KEEPALIVE_FAILED_MESSAGE.contains('{'));
        assert!(KEEPALIVE_FAILED_MESSAGE.is_ascii());
    }

    #[test]
    fn phone_tcp_socket_disables_nagle_and_preserves_audit() {
        use std::net::TcpListener;
        // This test does not pin a loopback adapter by name on Windows.
        #[cfg(unix)]
        let iface = Some(
            normalization::interface_index(if cfg!(target_os = "macos") {
                "lo0"
            } else {
                "lo"
            })
            .unwrap(),
        );
        #[cfg(windows)]
        let iface = None;
        let audit = normalization::Audit::default();
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).unwrap();
            let mut stream =
                phone_tcp_start(listener.local_addr().unwrap(), iface, &audit).unwrap();
            let (mut peer, _) = listener.accept().unwrap();
            assert!(stream.nodelay().unwrap());
            assert!(keepalive_enabled(&stream));
            stream.set_nonblocking(false).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            stream.write_all(b"small frame").unwrap();
            let mut received = [0; 11];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"small frame");
        }
        assert_eq!(audit.snapshot(), (2, 0));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let direct = direct_tcp_start(listener.local_addr().unwrap(), iface, &audit).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        assert!(!direct.nodelay().unwrap());
        assert!(keepalive_enabled(&direct));
        assert_eq!(audit.snapshot(), (3, 0));
    }
    #[test]
    fn tcp_setup_timeout_phases_keep_the_aggregate_without_a_destination_claim() {
        let c = Counters::default();
        let error = io::Error::new(io::ErrorKind::TimedOut, "private detail");
        for phase in [
            TcpSetupPhase::PhoneConnect,
            TcpSetupPhase::PhoneAuth,
            TcpSetupPhase::PhoneDestination,
            TcpSetupPhase::DirectConnect,
        ] {
            count_tcp_setup_error(&c, &error, phase, None);
        }
        assert_eq!(value(&c.flow_errors), 4);
        assert_eq!(value(&c.tcp_setup_errors), 4);
        assert_eq!(value(&c.tcp_setup_timed_out), 4);
        assert_eq!(value(&c.tcp_setup_timeout_phone_connect), 1);
        assert_eq!(value(&c.tcp_setup_timeout_phone_auth), 1);
        // A local phone deadline without a source reply is not proof that the
        // destination timed out. It keeps the aggregate and the other zero.
        assert_eq!(value(&c.tcp_setup_timeout_phone_destination), 0);
        assert_eq!(value(&c.tcp_setup_timeout_direct_connect), 1);
        assert_eq!(value(&c.tcp_setup_other), 0);
        count_tcp_setup_error(
            &c,
            &io::Error::new(io::ErrorKind::ConnectionRefused, "private detail"),
            TcpSetupPhase::PhoneAuth,
            None,
        );
        assert_eq!(value(&c.tcp_setup_timeout_phone_auth), 1);
        assert_eq!(value(&c.tcp_setup_refused), 0);
        assert_eq!(value(&c.tcp_setup_other), 1);
        let phone = phone::PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(1),
        };
        let mut setup = Setup::phone(&phone, Ipv4Addr::LOCALHOST.into(), 443, 1).unwrap();
        for (stage, expected) in [
            (SetupStage::Connect, TcpSetupPhase::PhoneConnect),
            (SetupStage::SendHello, TcpSetupPhase::PhoneAuth),
            (SetupStage::ReadHello, TcpSetupPhase::PhoneAuth),
            (SetupStage::SendAuth, TcpSetupPhase::PhoneAuth),
            (SetupStage::ReadAuth, TcpSetupPhase::PhoneAuth),
            (SetupStage::SendRequest, TcpSetupPhase::PhoneDestination),
            (SetupStage::ReadHeader, TcpSetupPhase::PhoneDestination),
            (
                SetupStage::ReadDomainLength,
                TcpSetupPhase::PhoneDestination,
            ),
            (SetupStage::ReadTail, TcpSetupPhase::PhoneDestination),
        ] {
            setup.stage = stage;
            assert_eq!(setup.timeout_phase(), expected);
        }
        assert_eq!(
            Setup::direct().timeout_phase(),
            TcpSetupPhase::DirectConnect
        );
    }
    #[test]
    fn local_phone_and_direct_errors_keep_distinct_setup_semantics() {
        let counters = Counters::default();
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "private detail");
        count_tcp_setup_error(&counters, &timeout, TcpSetupPhase::PhoneDestination, None);
        assert_eq!(value(&counters.tcp_setup_timed_out), 1);
        assert_eq!(value(&counters.tcp_setup_timeout_phone_destination), 0);
        count_tcp_setup_error(&counters, &timeout, TcpSetupPhase::DirectConnect, None);
        assert_eq!(value(&counters.tcp_setup_timed_out), 2);
        assert_eq!(value(&counters.tcp_setup_timeout_direct_connect), 1);
        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "private detail");
        count_tcp_setup_error(&counters, &refused, TcpSetupPhase::PhoneConnect, None);
        assert_eq!(value(&counters.tcp_setup_refused), 0);
        assert_eq!(value(&counters.tcp_setup_other), 1);
        count_tcp_setup_error(&counters, &refused, TcpSetupPhase::DirectConnect, None);
        assert_eq!(value(&counters.tcp_setup_refused), 1);
    }
    #[test]
    fn phone_handshake_timeouts_use_local_counters_and_a_reply_wait_is_not_destination_timeout() {
        use std::net::TcpListener;
        for wait_for in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mock = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).unwrap();
                if wait_for >= 1 {
                    stream.write_all(&[5, 2]).unwrap();
                    let mut auth = [0; 6];
                    stream.read_exact(&mut auth).unwrap();
                    if wait_for >= 2 {
                        stream.write_all(&[1, 0]).unwrap();
                        let mut request = [0; 10];
                        stream.read_exact(&mut request).unwrap();
                    }
                }
                let mut byte = [0; 1];
                assert_eq!(stream.read(&mut byte).unwrap(), 0);
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_millis(150),
            });
            let recorder = Arc::new(failures::FailureRecorder::new());
            recorder.start();
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone),
                failures: Some(recorder.clone()),
                ..RelayConfig::default()
            })
            .unwrap();
            let src = Ipv4Addr::new(198, 18, 0, 2);
            let dst = Ipv4Addr::LOCALHOST;
            relay
                .dispatch(
                    packet::build_tcp(&packet::TcpBuild {
                        src,
                        dst,
                        sport: 5555,
                        dport: 443,
                        seq: 1,
                        ack: 0,
                        flags: packet::SYN,
                        window: 65535,
                        payload: &[],
                        options: &[],
                        ttl: 64,
                        ident: 0,
                    })
                    .unwrap(),
                )
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while relay.stats().tcp_setup_timed_out == 0 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            let stats = relay.stats();
            assert_eq!((stats.tcp_setup_errors, stats.tcp_setup_timed_out), (1, 1));
            assert_eq!(stats.tcp_setup_timeout_phone_auth, u64::from(wait_for < 2));
            // The mock stops at the greeting, auth, or request reply. No reply
            // arrived, so the destination timeout counter must stay zero.
            assert_eq!(stats.tcp_setup_timeout_phone_destination, 0);
            assert_eq!(
                stats.tcp_setup_timeout_phone_connect + stats.tcp_setup_timeout_direct_connect,
                0
            );
            assert_eq!(stats.tcp_setup_other, 0);
            let value = wait_for_total(&recorder, 1);
            let group = group(&value, "tcp");
            assert_eq!(group["reason"], "other");
            assert_eq!(
                group["phase"],
                ["greeting", "auth", "request"][wait_for as usize]
            );
            assert_eq!(group["code"], Value::Null);
            relay.stop();
            mock.join().unwrap();
        }
    }
    #[test]
    fn dns_lookups_through_the_phone_are_counted_separately() {
        use std::net::TcpListener;
        for setup_ok in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mock = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).unwrap();
                assert_eq!(hello, [5, 1, 2]);
                stream.write_all(&[5, 2]).unwrap();
                let mut auth = [0; 6];
                stream.read_exact(&mut auth).unwrap();
                assert_eq!(auth, [1, 1, b'u', 2, b'p', b'w']);
                stream.write_all(&[1, 0]).unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).unwrap();
                // UDP associate to 1.1.1.1:53.
                assert_eq!(request, [5, 1, 0, 1, 1, 1, 1, 1, 0, 53]);
                let reply = if setup_ok { 0 } else { 5 };
                stream
                    .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                let mut byte = [0; 1];
                let _ = stream.read(&mut byte);
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(2),
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone),
                ..RelayConfig::default()
            })
            .unwrap();
            // A minimal DNS query: 12 bytes, standard query bit clear.
            let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
            relay
                .dispatch(
                    packet::build_udp(
                        Ipv4Addr::new(198, 18, 0, 2),
                        Ipv4Addr::new(8, 8, 8, 8),
                        53000,
                        53,
                        &query,
                        64,
                        0,
                    )
                    .unwrap(),
                )
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            while relay.stats().dns_flows == 0
                || (setup_ok && relay.stats().dns_setup_ok == 0)
                || (!setup_ok && relay.stats().dns_setup_failed == 0)
            {
                assert!(Instant::now() < deadline, "DNS counters did not move");
                thread::sleep(Duration::from_millis(5));
            }
            let stats = relay.stats();
            assert_eq!(stats.dns_flows, 1);
            assert_eq!(stats.dns_setup_ok, u64::from(setup_ok));
            assert_eq!(stats.dns_setup_failed, u64::from(!setup_ok));
            assert_eq!(stats.ttl_bad, 0);
            relay.stop();
            mock.join().unwrap();
        }
    }
    #[test]
    fn phone_reply_codes_keep_their_meaning() {
        use std::net::TcpListener;
        // Code 1 is a general failure, such as a deadline. Code 2 is a policy
        // denial. Codes 3 and 4 are unreachable. Code 5 is refused. Code 6 is
        // an expired TTL, not a timeout. Codes 7 and 8 are unsupported. A
        // deadline or an expired TTL must not look like a destination refusal,
        // a destination timeout, or a destination that is unreachable.
        for (code, refused, unreachable, timed_out, permission, other) in [
            (1u8, 0, 0, 0, 0, 1),
            (2, 0, 0, 0, 1, 0),
            (3, 0, 1, 0, 0, 0),
            (4, 0, 1, 0, 0, 0),
            (5, 1, 0, 0, 0, 0),
            (6, 0, 0, 0, 0, 1),
            (7, 0, 0, 0, 0, 1),
            (8, 0, 0, 0, 0, 1),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mock = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).unwrap();
                stream.write_all(&[5, 2]).unwrap();
                let mut auth = [0; 6];
                stream.read_exact(&mut auth).unwrap();
                stream.write_all(&[1, 0]).unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).unwrap();
                stream
                    .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                let mut byte = [0; 1];
                let _ = stream.read(&mut byte);
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(2),
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone),
                ..RelayConfig::default()
            })
            .unwrap();
            relay
                .dispatch(
                    packet::build_tcp(&packet::TcpBuild {
                        src: Ipv4Addr::new(198, 18, 0, 2),
                        dst: Ipv4Addr::LOCALHOST,
                        sport: 5556,
                        dport: 443,
                        seq: 1,
                        ack: 0,
                        flags: packet::SYN,
                        window: 65535,
                        payload: &[],
                        options: &[],
                        ttl: 64,
                        ident: 0,
                    })
                    .unwrap(),
                )
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while relay.stats().tcp_setup_errors == 0 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            let stats = relay.stats();
            assert_eq!(stats.tcp_setup_errors, 1, "code {code}");
            assert_eq!(stats.tcp_setup_refused, refused, "code {code}");
            assert_eq!(
                stats.tcp_setup_phone_unreachable, unreachable,
                "code {code}"
            );
            assert_eq!(stats.tcp_setup_timed_out, timed_out, "code {code}");
            // No source reply code means a destination timeout.
            assert_eq!(stats.tcp_setup_timeout_phone_destination, 0, "code {code}");
            assert_eq!(stats.tcp_setup_permission_denied, permission, "code {code}");
            assert_eq!(stats.tcp_setup_other, other, "code {code}");
            relay.stop();
            mock.join().unwrap();
        }
        // A local socket error does not prove that the destination refused
        // the flow or is unreachable. Only a source device reply code does.
        let c = Counters::default();
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
        ] {
            count_tcp_setup_error(
                &c,
                &io::Error::new(kind, "private detail"),
                TcpSetupPhase::PhoneDestination,
                None,
            );
        }
        assert_eq!(value(&c.tcp_setup_other), 4);
        assert_eq!(value(&c.tcp_setup_refused), 0);
        assert_eq!(value(&c.tcp_setup_phone_unreachable), 0);
        count_tcp_setup_error(
            &c,
            &phone::reply_error(4),
            TcpSetupPhase::PhoneDestination,
            Some(4),
        );
        count_tcp_setup_error(
            &c,
            &phone::reply_error(5),
            TcpSetupPhase::PhoneDestination,
            Some(5),
        );
        assert_eq!(value(&c.tcp_setup_phone_unreachable), 1);
        assert_eq!(value(&c.tcp_setup_refused), 1);
        // A direct connect refusal is a destination answer.
        count_tcp_setup_error(
            &c,
            &io::Error::new(io::ErrorKind::ConnectionRefused, "private detail"),
            TcpSetupPhase::DirectConnect,
            None,
        );
        assert_eq!(value(&c.tcp_setup_refused), 2);
        assert_eq!(value(&c.tcp_setup_errors), 7);
    }
    #[test]
    fn source_ttl_expiry_is_not_a_timeout() {
        let counters = Counters::default();
        let error = phone::reply_error(6);
        count_tcp_setup_error(&counters, &error, TcpSetupPhase::PhoneDestination, Some(6));
        assert_eq!(value(&counters.tcp_setup_errors), 1);
        assert_eq!(value(&counters.tcp_setup_other), 1);
        assert_eq!(value(&counters.tcp_setup_timed_out), 0);
        assert_eq!(value(&counters.tcp_setup_timeout_phone_destination), 0);
        assert_eq!(
            failure_reason(&error, Some(6), true),
            failures::Reason::Other
        );
    }
    #[test]
    fn destination_privacy_diagnostics_are_zero_and_name_no_host() {
        // No interface, no source device, and no flow: this test only reads
        // the counter shape. It creates no route and opens no destination
        // socket.
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            ..RelayConfig::default()
        })
        .unwrap();
        let stats = relay.stats().destination_privacy;
        let counters = [
            stats.flows,
            stats.shaped_flows,
            stats.shaped_errors,
            stats.ech_attempts,
            stats.ech_ok,
            stats.ech_grease,
            stats.ech_rejected,
            stats.ech_fallback,
            stats.doh_lookups,
            stats.doh_ok,
            stats.doh_failed,
            stats.cover_flows,
            stats.cover_errors,
        ];
        assert_eq!(counters, [0u64; 13]);
        // The relay reports the shared section with its own counters, so the
        // mode name and the counter keys cannot drift from `empty()`.
        let diag = relay.diagnostics();
        let section = &diag["destination_privacy"];
        assert_eq!(section, &diagnostics::destination_privacy());
        assert_eq!(section["mode"], "off");
        let counters = section["counters"].as_object().unwrap();
        assert_eq!(counters.len(), 13);
        assert!(counters.values().all(|count| count.as_u64() == Some(0)));
        let text = section.to_string();
        assert!(!text.contains("token"));
        assert!(!text.contains("127.0.0.1"));
        relay.stop();
    }
    #[test]
    fn inner_connect_deadline_keeps_the_timeout_without_claiming_a_destination_timeout() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let audit = Arc::new(normalization::Audit::default());
        let stream = normalization::tcp_start(address, None, &audit).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let counters = Arc::new(Counters::default());
        let output = Arc::new(Output::new().unwrap());
        let mut worker = Worker::new(
            RelayConfig::default(),
            output,
            counters.clone(),
            audit,
            Arc::new(AtomicBool::new(true)),
        );
        let phone = phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(30),
        };
        let mut setup = Setup::phone(&phone, Ipv4Addr::LOCALHOST.into(), 443, 1).unwrap();
        setup.stage = SetupStage::ReadHeader;
        setup.need = 4;
        let engine = tcp::TcpFlow::new(1, 2, &[], 65535, Instant::now() - Duration::from_secs(9));
        let key = Key {
            proto: packet::PROTO_TCP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::LOCALHOST.into(),
            sport: 1,
            dport: 443,
        };
        worker.tcp.insert(
            key,
            TcpEntry {
                engine,
                stream,
                setup: Some(setup),
                was_established: false,
                _gauge: TcpFlowGauge::new(&counters),
            },
        );
        worker.pump();
        worker.pump();
        assert_eq!(value(&counters.flow_errors), 1);
        assert_eq!(value(&counters.tcp_setup_timed_out), 1);
        // No source reply arrived before the local deadline. The target device
        // must not report a destination timeout.
        assert_eq!(value(&counters.tcp_setup_timeout_phone_destination), 0);
        assert_eq!(value(&counters.tcp_setup_timeout_phone_auth), 0);
        assert_eq!(value(&counters.tcp_setup_other), 0);
    }
    #[test]
    fn phone_mode_holds_the_syn_ack_until_the_socks_reply() {
        use std::net::TcpListener;
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let request = read_phone_request(&mut stream);
            assert_eq!(request[1], 1);
            ready_tx.send(()).unwrap();
            // The source device delays its SOCKS reply by 3 seconds.
            thread::sleep(Duration::from_secs(3));
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut data = [0u8; 5];
            stream.read_exact(&mut data).unwrap();
            stream.write_all(&data).unwrap();
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone_at(address, Duration::from_secs(10))),
            ..RelayConfig::default()
        })
        .unwrap();
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::LOCALHOST;
        let syn = |seq| {
            packet::build_tcp(&packet::TcpBuild {
                src,
                dst,
                sport: 5556,
                dport: 443,
                seq,
                ack: 0,
                flags: packet::SYN,
                window: 65535,
                payload: &[],
                options: &[2, 4, 1, 44],
                ttl: 64,
                ident: 0,
            })
            .unwrap()
        };
        // Before any flow, the timeline says "no observation", not "no drops".
        let empty = relay.diagnostics();
        assert!(empty["established"]["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|bucket| bucket["observed"] == false));
        relay.dispatch(syn(100)).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // The source device has not answered the connect request. No SYN-ACK
        // and no reset may reach the inner client.
        assert!(relay.recv_timeout(Duration::from_millis(400)).is_err());
        // A duplicate SYN is a retransmit. It must not start another outer
        // connection and it must not answer early.
        relay.dispatch(syn(100)).unwrap();
        assert!(relay.recv_timeout(Duration::from_millis(300)).is_err());
        assert_eq!(relay.stats().tcp_flows, 1);
        let raw = relay.recv_timeout(Duration::from_secs(4)).unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(seg.flags, packet::SYN | packet::ACK);
        assert_eq!(seg.ack, 101);
        let server_seq = seg.seq;
        // The connection now carries data exactly as before.
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src,
                    dst,
                    sport: 5556,
                    dport: 443,
                    seq: 101,
                    ack: server_seq.wrapping_add(1),
                    flags: packet::ACK,
                    window: 65535,
                    payload: b"hello",
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut echoed = false;
        while Instant::now() < deadline {
            let Ok(raw) = relay.recv_timeout(Duration::from_millis(300)) else {
                continue;
            };
            let ip = packet::parse_ip(&raw).unwrap();
            let seg = packet::parse_tcp(ip.payload).unwrap();
            if seg.data == b"hello" {
                assert_eq!((seg.sport, seg.dport), (443, 5556));
                echoed = true;
                break;
            }
        }
        assert!(echoed);
        // A client reset at the next expected sequence tears the flow down.
        // The timeline counts it without reporting an outer error.
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src,
                    dst,
                    sport: 5556,
                    dport: 443,
                    seq: 106,
                    ack: server_seq.wrapping_add(1),
                    flags: packet::RST | packet::ACK,
                    window: 0,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while relay.stats().tcp_flows_closed == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let d = relay.diagnostics();
        let buckets = d["established"]["buckets"].as_array().unwrap();
        assert!(buckets.iter().any(|bucket| bucket["observed"] == true));
        assert_eq!(
            buckets
                .iter()
                .map(|bucket| bucket["tcp_teardowns"].as_u64().unwrap())
                .sum::<u64>(),
            1
        );
        assert_eq!(
            buckets
                .iter()
                .map(|bucket| bucket["outer_errors"].as_u64().unwrap())
                .sum::<u64>(),
            0
        );
        assert_eq!(
            buckets
                .iter()
                .map(|bucket| bucket["relay_drops"].as_u64().unwrap())
                .sum::<u64>(),
            0
        );
        assert_eq!(d["setup"]["connect_ms"]["count"], 1);
        assert_eq!(d["setup"]["greeting_ms"]["count"], 1);
        assert_eq!(d["setup"]["auth_ms"]["count"], 1);
        assert_eq!(d["setup"]["request_ms"]["count"], 1);
        assert_eq!(d["tcp"]["flows_peak"], 1);
        assert_eq!(d["queues"]["input"].as_array().unwrap().len(), 1);
        assert!(d["queues"]["input"][0]["peak"].as_u64().is_some());
        assert!(d["queues"]["output"]["max_age_us"].as_u64().is_some());
        assert_eq!(relay.stats().ttl_bad, 0);
        relay.stop();
        mock.join().unwrap();
    }

    #[test]
    fn direct_socket_setup_failure_resets_without_a_syn_ack() {
        let mut relay = Relay::start(RelayConfig {
            iface: Some(0),
            workers: 1,
            ..RelayConfig::default()
        })
        .unwrap();
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src: Ipv4Addr::new(198, 18, 0, 2),
                    dst: Ipv4Addr::LOCALHOST,
                    sport: 5556,
                    dport: 443,
                    seq: 1,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        let raw = relay.recv_timeout(Duration::from_secs(2)).unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(seg.flags, packet::RST | packet::ACK);
        assert!(relay.recv_timeout(Duration::from_millis(100)).is_err());
        // A setup that never opened an outer socket holds no live flow, so the
        // gauge stays at zero and the peak stays at zero too.
        let stats = relay.stats();
        assert_eq!(stats.tcp_flows, 0);
        assert_eq!(stats.tcp_flows_active, 0);
        let diagnostics = relay.diagnostics();
        assert_eq!(diagnostics["tcp"]["flows_active"], 0);
        assert_eq!(diagnostics["tcp"]["flows_peak"], 0);
        relay.stop();
    }

    /// Dispatch one inner TCP segment from the fixed inner client.
    fn inner_tcp(relay: &Relay, sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) {
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src: Ipv4Addr::new(198, 18, 0, 2),
                    dst: Ipv4Addr::LOCALHOST,
                    sport,
                    dport,
                    seq,
                    ack,
                    flags,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
    }

    /// Wait for the relay stats to satisfy `ready`, and fail at a deadline.
    fn wait_for_stats(relay: &Relay, ready: impl Fn(&RelayStats) -> bool) -> RelayStats {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let stats = relay.stats();
            if ready(&stats) {
                return stats;
            }
            assert!(
                Instant::now() < deadline,
                "relay stats did not reach the expected state: active {}, closed {}",
                stats.tcp_flows_active,
                stats.tcp_flows_closed
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn target_tcp_flow_gauge_tracks_live_flows_and_decrements_on_close() {
        use std::net::TcpListener;
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                held.push(stream);
            }
            // Hold the outer sockets open until the test has closed the flows.
            let _ = stop_rx.recv_timeout(Duration::from_secs(20));
            drop(held);
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            ..RelayConfig::default()
        })
        .unwrap();
        assert_eq!(relay.stats().tcp_flows_active, 0);
        let mut flows = Vec::new();
        for sport in [6101u16, 6102, 6103] {
            inner_tcp(&relay, sport, port, 100, 0, packet::SYN);
            let raw = relay.recv_timeout(Duration::from_secs(3)).unwrap();
            let ip = packet::parse_ip(&raw).unwrap();
            let seg = packet::parse_tcp(ip.payload).unwrap();
            assert_eq!(seg.flags, packet::SYN | packet::ACK);
            assert_eq!(seg.dport, sport);
            assert_eq!(seg.ack, 101);
            inner_tcp(
                &relay,
                sport,
                port,
                101,
                seg.seq.wrapping_add(1),
                packet::ACK,
            );
            flows.push((sport, seg.seq));
        }
        let stats = wait_for_stats(&relay, |s| s.tcp_flows_active == 3);
        assert_eq!(stats.tcp_flows_active, 3);
        assert_eq!(stats.tcp_flows, 3);
        assert_eq!(stats.tcp_flows_closed, 0);
        let diagnostics = relay.diagnostics();
        assert_eq!(diagnostics["tcp"]["flows_active"], 3);
        assert_eq!(diagnostics["tcp"]["flows_peak"], 3);
        // One client reset lowers the live count by one. The peak keeps the
        // high-water mark and does not follow the live count down.
        let (sport, server_seq) = flows[0];
        inner_tcp(
            &relay,
            sport,
            port,
            101,
            server_seq.wrapping_add(1),
            packet::RST | packet::ACK,
        );
        let stats = wait_for_stats(&relay, |s| s.tcp_flows_active == 2);
        assert_eq!(stats.tcp_flows_active, 2);
        assert_eq!(stats.tcp_flows_closed, 1);
        let diagnostics = relay.diagnostics();
        assert_eq!(diagnostics["tcp"]["flows_active"], 2);
        assert_eq!(diagnostics["tcp"]["flows_peak"], 3);
        // The remaining flows bring the gauge back to zero.
        for &(sport, server_seq) in &flows[1..] {
            inner_tcp(
                &relay,
                sport,
                port,
                101,
                server_seq.wrapping_add(1),
                packet::RST | packet::ACK,
            );
        }
        let stats = wait_for_stats(&relay, |s| s.tcp_flows_active == 0);
        assert_eq!(stats.tcp_flows_active, 0);
        assert_eq!(stats.tcp_flows_closed, 3);
        assert_eq!(relay.diagnostics()["tcp"]["flows_active"], 0);
        // A stop drops every remaining entry. The gauge must not keep a stale
        // live count after the workers are gone.
        relay.stop();
        assert_eq!(relay.stats().tcp_flows_active, 0);
        let _ = stop_tx.send(());
        server.join().unwrap();
    }

    #[test]
    fn phone_connect_errors_reset_the_inner_client_without_a_syn_ack() {
        use std::sync::mpsc;
        for code in [3u8, 4, 5] {
            let (failed_tx, failed_rx) = mpsc::channel();
            let (address, mock) = mock_phone(1, move |stream, _| {
                stream
                    .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                failed_tx.send(()).unwrap();
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte);
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone_at(address, Duration::from_secs(2))),
                ..RelayConfig::default()
            })
            .unwrap();
            relay
                .dispatch(
                    packet::build_tcp(&packet::TcpBuild {
                        src: Ipv4Addr::new(198, 18, 0, 2),
                        dst: Ipv4Addr::LOCALHOST,
                        sport: 5556,
                        dport: 443,
                        seq: 1,
                        ack: 0,
                        flags: packet::SYN,
                        window: 65535,
                        payload: &[],
                        options: &[],
                        ttl: 64,
                        ident: 0,
                    })
                    .unwrap(),
                )
                .unwrap();
            failed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let failed_at = Instant::now();
            let raw = relay.recv_timeout(Duration::from_secs(2)).unwrap();
            let elapsed = failed_at.elapsed();
            let ip = packet::parse_ip(&raw).unwrap();
            let seg = packet::parse_tcp(ip.payload).unwrap();
            assert_eq!(
                seg.flags,
                packet::RST | packet::ACK,
                "reply code {code} must reset without a SYN-ACK"
            );
            assert_eq!(seg.data, b"");
            assert!(
                elapsed < Duration::from_millis(50),
                "reset took {elapsed:?} for reply code {code}"
            );
            // The worker counts the setup error before it queues the reset.
            // It removes the flow from its table after the output signal, so
            // this thread can observe the reset first. Wait for the close.
            let deadline = Instant::now() + Duration::from_secs(2);
            while relay.stats().tcp_flows_closed == 0 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            let stats = wait_for_stats(&relay, |s| s.tcp_flows_active == 0);
            assert_eq!(stats.tcp_setup_errors, 1, "reply code {code}");
            assert_eq!(stats.tcp_flows_closed, 1, "reply code {code}");
            // The entry existed while the source device connect was pending.
            // The failed setup drops it, so no live flow remains. The live
            // count can trail the close counter by one short step, because the
            // entry drops after the close is counted.
            assert_eq!(stats.tcp_flows_active, 0, "reply code {code}");
            assert_eq!(stats.tcp_setup_timed_out, 0, "reply code {code}");
            match code {
                5 => assert_eq!(stats.tcp_setup_refused, 1, "reply code {code}"),
                3 | 4 => {
                    assert_eq!(stats.tcp_setup_phone_unreachable, 1, "reply code {code}")
                }
                _ => unreachable!(),
            }
            assert_eq!(stats.ttl_bad, 0);
            relay.stop();
            mock.join().unwrap();
        }
    }

    #[test]
    fn phone_connect_timeout_resets_the_inner_client_once() {
        use std::sync::mpsc;
        let (ready_tx, ready_rx) = mpsc::channel();
        let (address, mock) = mock_phone(1, move |stream, _| {
            ready_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(600));
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone_at(address, Duration::from_millis(150))),
            ..RelayConfig::default()
        })
        .unwrap();
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src: Ipv4Addr::new(198, 18, 0, 2),
                    dst: Ipv4Addr::LOCALHOST,
                    sport: 5557,
                    dport: 443,
                    seq: 7,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let raw = relay.recv_timeout(Duration::from_secs(2)).unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(seg.flags, packet::RST | packet::ACK);
        assert!(relay.recv_timeout(Duration::from_millis(200)).is_err());
        let stats = relay.stats();
        assert_eq!(stats.tcp_setup_errors, 1);
        assert_eq!(stats.tcp_setup_timed_out, 1);
        assert_eq!(stats.tcp_flows_closed, 1);
        assert_eq!(stats.ttl_bad, 0);
        relay.stop();
        mock.join().unwrap();
    }

    #[test]
    fn stop_during_a_pending_phone_connect_releases_the_flow() {
        use std::net::TcpListener;
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _request = read_phone_request(&mut stream);
            ready_tx.send(()).unwrap();
            let mut byte = [0u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone_at(address, Duration::from_secs(20))),
            ..RelayConfig::default()
        })
        .unwrap();
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src: Ipv4Addr::new(198, 18, 0, 2),
                    dst: Ipv4Addr::LOCALHOST,
                    sport: 5558,
                    dport: 443,
                    seq: 9,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(relay.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(relay.stats().tcp_flows_active, 1);
        let start = Instant::now();
        relay.stop();
        assert!(start.elapsed() < Duration::from_millis(500));
        // The pending flow lived in the worker table. Stopping the worker drops
        // the entry, and the gauge guard lowers the live count with it.
        assert_eq!(relay.stats().tcp_flows_active, 0);
        mock.join().unwrap();
    }

    fn echo_request(src: IpAddr, dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 8];
        msg[4..6].copy_from_slice(&id.to_be_bytes());
        msg[6..8].copy_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(payload);
        match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                msg[0] = 8;
                let checksum = packet::checksum(&msg);
                msg[2..4].copy_from_slice(&checksum.to_be_bytes());
                packet::build_ipv4(src, dst, packet::PROTO_ICMP, &msg, 64, 0).unwrap()
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                msg[0] = 128;
                let mut pseudo = Vec::new();
                pseudo.extend_from_slice(&src.octets());
                pseudo.extend_from_slice(&dst.octets());
                pseudo.extend_from_slice(&(msg.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, packet::PROTO_ICMPV6]);
                pseudo.extend_from_slice(&msg);
                let checksum = packet::checksum(&pseudo);
                msg[2..4].copy_from_slice(&checksum.to_be_bytes());
                packet::build_ipv6(src, dst, packet::PROTO_ICMPV6, &msg, 64).unwrap()
            }
            _ => panic!("mixed address families"),
        }
    }
    #[test]
    fn icmp_is_off_by_default() {
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            ipv6_forward: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = "198.18.0.2".parse().unwrap();
        let dst = "203.0.113.5".parse().unwrap();
        relay
            .dispatch(echo_request(src, dst, 44, 77, b"probe"))
            .unwrap();
        assert_eq!(relay.stats().icmp_dropped, 1);
        assert_eq!(relay.stats().icmp_requests, 0);
        assert!(relay.recv_timeout(Duration::from_millis(30)).is_err());
        relay.stop();
        assert!(Relay::start(RelayConfig {
            allow_unpinned: true,
            icmp_phone: true,
            ..RelayConfig::default()
        })
        .is_err());
    }
    #[test]
    fn phone_icmp_ipv4_ipv6_echo_keeps_identity_and_checksums() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                tasks.push(thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut hello = [0; 3];
                    s.read_exact(&mut hello).unwrap();
                    assert_eq!(hello, [5, 1, 2]);
                    s.write_all(&[5, 2]).unwrap();
                    let mut auth = [0; 6];
                    s.read_exact(&mut auth).unwrap();
                    assert_eq!(&auth, b"\x01\x01u\x02pw");
                    s.write_all(&[1, 0]).unwrap();
                    let mut head = [0; 4];
                    s.read_exact(&mut head).unwrap();
                    assert_eq!(&head[..3], &[5, 0x81, 0]);
                    let size = match head[3] {
                        1 => 4,
                        4 => 16,
                        _ => panic!("numeric target required"),
                    };
                    let mut addr = vec![0; size + 2];
                    s.read_exact(&mut addr).unwrap();
                    assert_eq!(&addr[size..], &[0, 0]);
                    if size == 4 {
                        assert_eq!(&addr[..4], &[203, 0, 113, 5]);
                    } else {
                        assert_eq!(
                            &addr[..16],
                            &"2001:db8::5"
                                .parse::<std::net::Ipv6Addr>()
                                .unwrap()
                                .octets()
                        );
                    }
                    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                    let mut len = [0; 2];
                    s.read_exact(&mut len).unwrap();
                    let mut payload = vec![0; u16::from_be_bytes(len) as usize];
                    s.read_exact(&mut payload).unwrap();
                    s.write_all(&[0]).unwrap();
                    s.write_all(&len).unwrap();
                    s.write_all(&payload).unwrap();
                }));
            }
            for task in tasks {
                task.join().unwrap();
            }
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 2,
            phone: Some(phone),
            ipv6_forward: true,
            icmp_phone: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let requests = [
            (
                "198.18.0.2".parse().unwrap(),
                "203.0.113.5".parse().unwrap(),
                0x1234,
                7,
                b"ipv4-probe".as_slice(),
            ),
            (
                "fd00::2".parse().unwrap(),
                "2001:db8::5".parse().unwrap(),
                0xabcd,
                8,
                b"ipv6-probe".as_slice(),
            ),
        ];
        for &(src, dst, id, seq, data) in &requests {
            relay
                .dispatch(echo_request(src, dst, id, seq, data))
                .unwrap();
        }
        let mut seen = [false; 2];
        for _ in 0..2 {
            let reply = relay.recv_timeout(Duration::from_secs(3)).unwrap();
            let ip = packet::parse_ip(&reply).unwrap();
            let index = requests
                .iter()
                .position(|(src, dst, _, _, _)| *src == ip.dst && *dst == ip.src)
                .unwrap();
            let (src, dst, id, seq, data) = requests[index];
            assert_eq!(
                reply,
                packet::build_echo_reply(dst, src, id, seq, data).unwrap()
            );
            seen[index] = true;
        }
        assert!(seen.iter().all(|v| *v));
        // A reply can reach the consumer before the worker publishes its count.
        let deadline = Instant::now() + Duration::from_secs(2);
        let stats = loop {
            let stats = relay.stats();
            if stats.icmp_replies >= 2 || Instant::now() >= deadline {
                break stats;
            }
            thread::yield_now();
        };
        assert_eq!(
            (
                stats.icmp_requests,
                stats.icmp_replies,
                stats.icmp_errors,
                stats.ttl_bad
            ),
            (2, 2, 0, 0)
        );
        relay.stop();
        mock.join().unwrap();
    }
    #[test]
    fn phone_icmp_replies_when_on_and_drops_when_off() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 2]);
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            s.write_all(&[1, 0]).unwrap();
            let mut head = [0; 4];
            s.read_exact(&mut head).unwrap();
            assert_eq!(&head[..3], &[5, 0x81, 0]);
            assert_eq!(head[3], 1);
            let mut addr = [0; 6];
            s.read_exact(&mut addr).unwrap();
            assert_eq!(&addr[..4], &[203, 0, 113, 5]);
            assert_eq!(&addr[4..], &[0, 0]);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut len = [0; 2];
            s.read_exact(&mut len).unwrap();
            let mut payload = vec![0; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut payload).unwrap();
            s.write_all(&[0]).unwrap();
            s.write_all(&len).unwrap();
            s.write_all(&payload).unwrap();
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let src: IpAddr = "198.18.0.2".parse().unwrap();
        let dst: IpAddr = "203.0.113.5".parse().unwrap();
        // Off: the relay drops the echo and never opens the control connection.
        let mut off = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(Arc::clone(&phone)),
            ipv6_forward: true,
            icmp_phone: false,
            ..RelayConfig::default()
        })
        .unwrap();
        off.dispatch(echo_request(src, dst, 0x1234, 7, b"probe"))
            .unwrap();
        assert_eq!(off.stats().icmp_dropped, 1);
        assert_eq!(off.stats().icmp_requests, 0);
        assert!(off.recv_timeout(Duration::from_millis(30)).is_err());
        off.stop();
        // On: the same inner echo gets a reply through the mock source device.
        let mut on = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone),
            ipv6_forward: true,
            icmp_phone: true,
            ..RelayConfig::default()
        })
        .unwrap();
        on.dispatch(echo_request(src, dst, 0x1234, 7, b"probe"))
            .unwrap();
        let reply = on.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            reply,
            packet::build_echo_reply(dst, src, 0x1234, 7, b"probe").unwrap()
        );
        // A reply can reach the consumer before the worker publishes its count.
        let deadline = Instant::now() + Duration::from_secs(2);
        let stats = loop {
            let stats = on.stats();
            if stats.icmp_replies >= 1 || Instant::now() >= deadline {
                break stats;
            }
            thread::yield_now();
        };
        assert_eq!(
            (
                stats.icmp_requests,
                stats.icmp_replies,
                stats.icmp_dropped,
                stats.ttl_bad
            ),
            (1, 1, 0, 0)
        );
        on.stop();
        mock.join().unwrap();
    }
    #[test]
    fn persistent_phone_echo_reuses_only_matching_flow() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                tasks.push(thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut hello = [0; 3];
                    s.read_exact(&mut hello).unwrap();
                    assert_eq!(hello, [5, 1, 2]);
                    s.write_all(&[5, 2]).unwrap();
                    let mut auth = [0; 6];
                    s.read_exact(&mut auth).unwrap();
                    assert_eq!(&auth, b"\x01\x01u\x02pw");
                    s.write_all(&[1, 0]).unwrap();
                    let mut head = [0; 4];
                    s.read_exact(&mut head).unwrap();
                    assert_eq!(&head[..3], &[5, 0x82, 0]);
                    let n = if head[3] == 1 {
                        4
                    } else {
                        assert_eq!(head[3], 4);
                        16
                    };
                    let mut addr = vec![0; n + 2];
                    s.read_exact(&mut addr).unwrap();
                    assert_eq!(&addr[n..], &[0, 0]);
                    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                    for _ in 0..3 {
                        let mut len = [0; 2];
                        s.read_exact(&mut len).unwrap();
                        let mut data = vec![0; u16::from_be_bytes(len) as usize];
                        s.read_exact(&mut data).unwrap();
                        for b in [vec![0], len.to_vec(), data].concat() {
                            s.write_all(&[b]).unwrap();
                        }
                    }
                }));
            }
            for t in tasks {
                t.join().unwrap();
            }
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 2,
            phone: Some(phone),
            ipv6_forward: true,
            icmp_phone: true,
            icmp_persistent: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let pairs: [(IpAddr, IpAddr); 2] = [
            (
                "198.18.0.2".parse().unwrap(),
                "203.0.113.5".parse().unwrap(),
            ),
            ("fd00::2".parse().unwrap(), "2001:db8::5".parse().unwrap()),
        ];
        let probes: [(u16, &[u8]); 3] = [(1, b""), (1, b"duplicate-sequence"), (2, b"last")];
        let mut expected = Vec::new();
        for (src, dst) in pairs {
            for (seq, data) in probes {
                relay
                    .dispatch(echo_request(src, dst, 42, seq, data))
                    .unwrap();
                expected.push(packet::build_echo_reply(dst, src, 42, seq, data).unwrap());
            }
        }
        for _ in 0..6 {
            let actual = relay.recv_timeout(Duration::from_secs(5)).unwrap();
            let index = expected.iter().position(|p| *p == actual).unwrap();
            expected.remove(index);
        }
        assert!(expected.is_empty());
        assert_eq!(relay.audit.snapshot(), (2, 0));
        // The output queue can deliver the last reply before the worker
        // increments its counter. Wait for that publication to complete.
        let deadline = Instant::now() + Duration::from_secs(2);
        let stats = loop {
            let stats = relay.stats();
            if stats.icmp_replies == 6 || Instant::now() >= deadline {
                break stats;
            }
            thread::yield_now();
        };
        assert_eq!(
            (stats.icmp_requests, stats.icmp_replies, stats.icmp_errors),
            (6, 6, 0)
        );
        relay.stop();
        mock.join().unwrap();
    }
    #[test]
    fn persistent_echo_bounds_queue_and_old_phone_rejection() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, wait) = mpsc::channel();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            wait.recv_timeout(Duration::from_secs(3)).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            s.write_all(&[1, 0]).unwrap();
            let mut request = [0; 10];
            s.read_exact(&mut request).unwrap();
            assert_eq!(request[1], 0x82);
            s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone),
            icmp_phone: true,
            icmp_persistent: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = "198.18.0.2".parse().unwrap();
        let dst = "203.0.113.5".parse().unwrap();
        for seq in 0..6 {
            relay
                .dispatch(echo_request(src, dst, 42, seq, b"test"))
                .unwrap();
        }
        let until = Instant::now() + Duration::from_secs(2);
        while relay.stats().icmp_dropped < 2 && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            (relay.stats().icmp_requests, relay.stats().icmp_dropped),
            (4, 2)
        );
        release.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while relay.stats().icmp_errors < 4 && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(relay.stats().icmp_errors, 4);
        assert_eq!(relay.stats().icmp_replies, 0);
        assert!(relay.recv_timeout(Duration::from_millis(30)).is_err());
        relay.stop();
        mock.join().unwrap();
    }
    #[test]
    fn persistent_echo_timeout_closes_session_without_replay() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(12))).unwrap();
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            s.write_all(&[1, 0]).unwrap();
            let mut request = [0; 10];
            s.read_exact(&mut request).unwrap();
            assert_eq!(request[1], 0x82);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut frame = [0; 22];
            s.read_exact(&mut frame).unwrap();
            assert_eq!(&frame[..2], b"\x00\x14");
            assert_eq!(&frame[18..], b"test");
            let mut extra = [0; 10];
            assert_eq!(s.read(&mut extra).unwrap(), 0);
            let _ = s.write_all(&[&[0], &frame[..]].concat());
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone),
            icmp_phone: true,
            icmp_persistent: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = "198.18.0.2".parse().unwrap();
        let dst = "203.0.113.5".parse().unwrap();
        relay
            .dispatch(echo_request(src, dst, 42, 1, b"test"))
            .unwrap();
        relay
            .dispatch(echo_request(src, dst, 42, 2, b"test"))
            .unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while relay.stats().icmp_errors < 2 && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(relay.stats().icmp_errors, 2);
        assert_eq!(relay.stats().icmp_replies, 0);
        assert!(relay.recv_timeout(Duration::from_millis(30)).is_err());
        relay.stop();
        mock.join().unwrap();
    }
    #[test]
    fn persistent_echo_rejects_late_duplicate_with_identical_inner_payload() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            s.write_all(&[1, 0]).unwrap();
            let mut request = [0; 10];
            s.read_exact(&mut request).unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut first = [0; 22];
            s.read_exact(&mut first).unwrap();
            s.write_all(&[&[0], &first[..]].concat()).unwrap();
            let mut second = [0; 22];
            s.read_exact(&mut second).unwrap();
            assert_ne!(&first[2..18], &second[2..18]);
            assert_eq!(&first[18..], &second[18..]);
            s.write_all(&[&[0], &first[..]].concat()).unwrap();
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone),
            icmp_phone: true,
            icmp_persistent: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = "198.18.0.2".parse().unwrap();
        let dst = "203.0.113.5".parse().unwrap();
        relay
            .dispatch(echo_request(src, dst, 42, 1, b"test"))
            .unwrap();
        relay
            .dispatch(echo_request(src, dst, 42, 2, b"test"))
            .unwrap();
        assert_eq!(
            relay.recv_timeout(Duration::from_secs(3)).unwrap(),
            packet::build_echo_reply(dst, src, 42, 1, b"test").unwrap()
        );
        let until = Instant::now() + Duration::from_secs(3);
        while relay.stats().icmp_payload_mismatch == 0 && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(relay.stats().icmp_payload_mismatch, 1);
        assert_eq!(relay.stats().icmp_replies, 1);
        assert!(relay.recv_timeout(Duration::from_millis(30)).is_err());
        relay.stop();
        mock.join().unwrap();
    }
    #[test]
    fn icmp_capacity_and_target_filters_are_bounded() {
        let counters = Arc::new(Counters::default());
        let mut permits = Vec::new();
        for _ in 0..MAX_ICMP_ACTIVE {
            permits.push(reserve_icmp(&counters).unwrap());
        }
        assert!(reserve_icmp(&counters).is_none());
        drop(permits.pop());
        assert!(reserve_icmp(&counters).is_some());
        for addr in [
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!valid_icmp_target(addr.parse().unwrap()), "{addr}");
        }
        assert!(valid_icmp_target("203.0.113.5".parse().unwrap()));
        assert!(valid_icmp_target("2001:db8::5".parse().unwrap()));
    }
    #[test]
    fn phone_icmp_failure_never_synthesizes_a_reply() {
        use std::net::TcpListener;
        let cases: Vec<(Vec<u8>, usize)> = vec![
            (vec![1, 0, 0], 0),
            (vec![2, 0, 0], 1),
            (vec![3, 0, 0], 2),
            (vec![4, 0, 0], 3),
            (vec![5, 0, 0], 4),
            (vec![6, 0, 0], 5),
            (vec![7, 0, 0], 6),
            (vec![8, 0, 0], 7),
            (vec![9, 0, 0], 8),
            (vec![10, 0, 0], 9),
            (vec![1, 0, 1, 0], 9),
            (vec![8, 0, 1, 0], 9),
            (vec![], 9),
            (b"\x00\x00\x05wrong".to_vec(), 10),
            (b"\x00\x00\x01x".to_vec(), 10),
        ];
        for (frame, category) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mock = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut hello = [0; 3];
                s.read_exact(&mut hello).unwrap();
                s.write_all(&[5, 2]).unwrap();
                let mut auth = [0; 6];
                s.read_exact(&mut auth).unwrap();
                s.write_all(&[1, 0]).unwrap();
                let mut request = [0; 10];
                s.read_exact(&mut request).unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let mut request_payload = [0; 7];
                s.read_exact(&mut request_payload).unwrap();
                if !frame.is_empty() {
                    s.write_all(&frame).unwrap();
                }
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(3),
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone),
                icmp_phone: true,
                ..RelayConfig::default()
            })
            .unwrap();
            relay
                .dispatch(echo_request(
                    "198.18.0.2".parse().unwrap(),
                    "203.0.113.5".parse().unwrap(),
                    1,
                    2,
                    b"hello",
                ))
                .unwrap();
            assert!(relay.recv_timeout(Duration::from_millis(200)).is_err());
            // The worker records the failure after the reply deadline. Wait for it
            // so a slow runner does not read the counters too early.
            let deadline = Instant::now() + Duration::from_secs(5);
            while relay.stats().icmp_errors < 1 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            let stats = relay.stats();
            assert_eq!(
                (
                    stats.icmp_requests,
                    stats.icmp_replies,
                    stats.icmp_errors,
                    stats.ttl_bad
                ),
                (1, 0, 1, 0)
            );
            let counts = [
                stats.icmp_phone_no_cellular,
                stats.icmp_phone_busy,
                stats.icmp_phone_timeout,
                stats.icmp_phone_failed,
                stats.icmp_phone_path_no_update,
                stats.icmp_phone_path_unsatisfied,
                stats.icmp_phone_path_not_cellular,
                stats.icmp_phone_path_no_interface,
                stats.icmp_phone_path_ambiguous,
                stats.icmp_malformed,
                stats.icmp_payload_mismatch,
            ];
            assert_eq!(counts[category], 1);
            assert_eq!(counts.iter().sum::<u64>(), 1);
            assert_eq!(
                stats.icmp_setup_errors
                    + stats.icmp_timeouts
                    + stats.icmp_io_errors
                    + stats.icmp_output_errors,
                0
            );
            relay.stop();
            mock.join().unwrap();
        }
    }
    #[test]
    fn phone_icmp_limits_concurrency_and_stop_cancels_requests() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            let mut tasks = Vec::new();
            for _ in 0..MAX_ICMP_ACTIVE {
                let (mut s, _) = listener.accept().unwrap();
                let tx = tx.clone();
                tasks.push(thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut hello = [0; 3];
                    s.read_exact(&mut hello).unwrap();
                    tx.send(()).unwrap();
                    let mut byte = [0; 1];
                    assert_eq!(s.read(&mut byte).unwrap(), 0);
                }));
            }
            for task in tasks {
                task.join().unwrap();
            }
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone),
            icmp_phone: true,
            ..RelayConfig::default()
        })
        .unwrap();
        for sequence in 0..=MAX_ICMP_ACTIVE {
            relay
                .dispatch(echo_request(
                    "198.18.0.2".parse().unwrap(),
                    "203.0.113.5".parse().unwrap(),
                    1,
                    sequence as u16,
                    b"hello",
                ))
                .unwrap();
        }
        for _ in 0..MAX_ICMP_ACTIVE {
            rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while relay.stats().icmp_dropped == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(relay.stats().icmp_requests, MAX_ICMP_ACTIVE as u64);
        assert_eq!(relay.stats().icmp_dropped, 1);
        let start = Instant::now();
        relay.stop();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(relay.counters.icmp_active.load(Ordering::Acquire), 0);
        mock.join().unwrap();
    }
    #[test]
    fn phone_icmp_counts_setup_failure_and_local_timeout() {
        use std::net::TcpListener;
        for stall in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mock = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).unwrap();
                if stall {
                    let mut b = [0; 1];
                    assert_eq!(stream.read(&mut b).unwrap(), 0);
                } else {
                    stream.write_all(&[5, 255]).unwrap();
                }
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: if stall {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(2)
                },
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone),
                icmp_phone: true,
                ..RelayConfig::default()
            })
            .unwrap();
            relay
                .dispatch(echo_request(
                    "198.18.0.2".parse().unwrap(),
                    "203.0.113.5".parse().unwrap(),
                    1,
                    2,
                    b"hello",
                ))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while relay.stats().icmp_errors == 0 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            let stats = relay.stats();
            assert_eq!(
                (
                    stats.icmp_errors,
                    stats.icmp_setup_errors,
                    stats.icmp_timeouts
                ),
                (1, u64::from(!stall), u64::from(stall))
            );
            assert_eq!(stats.icmp_replies, 0);
            relay.stop();
            mock.join().unwrap();
        }
    }
    #[test]
    fn malformed_icmp_and_disallowed_targets_do_not_open_sockets() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let phone = Arc::new(phone::PhoneProxy {
            address: listener.local_addr().unwrap(),
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone),
            icmp_phone: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = "198.18.0.2".parse().unwrap();
        let dst = "203.0.113.5".parse().unwrap();
        let mut bad = echo_request(src, dst, 1, 2, b"hello");
        *bad.last_mut().unwrap() ^= 1;
        relay.dispatch(bad).unwrap();
        relay
            .dispatch(echo_request(src, dst, 1, 2, &vec![1; 1201]))
            .unwrap();
        relay
            .dispatch(echo_request(
                src,
                "127.0.0.1".parse().unwrap(),
                1,
                2,
                b"hello",
            ))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while relay.stats().icmp_dropped < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(relay.stats().icmp_dropped, 3);
        assert_eq!(relay.stats().icmp_requests, 0);
        assert!(matches!(listener.accept(),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        assert_eq!(relay.audit.snapshot(), (0, 0));
        relay.stop();
    }
    #[test]
    fn tcp_failure_counters_distinguish_setup_and_io() {
        use std::net::TcpListener;
        for reject in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut hello = [0u8; 3];
                s.read_exact(&mut hello).unwrap();
                if reject {
                    s.write_all(&[5, 255]).unwrap();
                    return;
                }
                s.write_all(&[5, 2]).unwrap();
                let mut auth = [0u8; 6];
                s.read_exact(&mut auth).unwrap();
                s.write_all(&[1, 0]).unwrap();
                let mut req = [0u8; 10];
                s.read_exact(&mut req).unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let mut byte = [0u8; 1];
                s.read_exact(&mut byte).unwrap();
                reset_on_close(&s);
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(3),
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone),
                ..RelayConfig::default()
            })
            .unwrap();
            let src = Ipv4Addr::new(198, 18, 0, 2);
            let dst = Ipv4Addr::LOCALHOST;
            let make = |seq, ack, flags, data: &[u8]| {
                packet::build_tcp(&packet::TcpBuild {
                    src,
                    dst,
                    sport: 5555,
                    dport: 443,
                    seq,
                    ack,
                    flags,
                    window: 65535,
                    payload: data,
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap()
            };
            relay.dispatch(make(1, 0, packet::SYN, &[])).unwrap();
            if reject {
                // The source device rejects the greeting. The inner client
                // gets a reset and never sees a SYN-ACK.
                let raw = relay.recv_timeout(Duration::from_secs(3)).unwrap();
                let ip = packet::parse_ip(&raw).unwrap();
                let segment = packet::parse_tcp(ip.payload).unwrap();
                assert_eq!(segment.flags, packet::RST | packet::ACK);
            } else {
                let syn = relay.recv_timeout(Duration::from_secs(3)).unwrap();
                let ip = packet::parse_ip(&syn).unwrap();
                let segment = packet::parse_tcp(ip.payload).unwrap();
                assert_eq!(
                    segment.flags & (packet::SYN | packet::ACK),
                    packet::SYN | packet::ACK
                );
                relay
                    .dispatch(make(2, segment.seq.wrapping_add(1), packet::ACK, b"x"))
                    .unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline && relay.stats().flow_errors == 0 {
                thread::sleep(Duration::from_millis(5));
            }
            let s = relay.stats();
            assert_eq!(s.flow_errors, 1);
            assert_eq!(s.tcp_setup_errors, u64::from(reject));
            assert_eq!(s.tcp_io_errors, u64::from(!reject));
            assert_eq!(s.tcp_setup_permission_denied, u64::from(reject));
            assert_eq!(
                s.tcp_setup_refused + s.tcp_setup_timed_out + s.tcp_setup_other,
                0
            );
            relay.stop();
            server.join().unwrap();
        }
    }
    #[test]
    fn setup_error_kinds_are_counted_without_details() {
        let counters = Counters::default();
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
        ] {
            count_tcp_setup_error(
                &counters,
                &io::Error::new(kind, "private detail"),
                TcpSetupPhase::PhoneAuth,
                None,
            );
        }
        assert_eq!(value(&counters.flow_errors), 4);
        assert_eq!(value(&counters.tcp_setup_errors), 4);
        // A local refusal during source device authentication is not proof
        // that the destination refused the flow.
        assert_eq!(value(&counters.tcp_setup_refused), 0);
        assert_eq!(value(&counters.tcp_setup_timed_out), 1);
        assert_eq!(value(&counters.tcp_setup_permission_denied), 1);
        assert_eq!(value(&counters.tcp_setup_other), 2);
    }
    #[test]
    fn failure_reason_distinguishes_local_errors_from_source_replies() {
        for code in LOCAL_DENIED_CODES {
            let local = io::Error::from_raw_os_error(code);
            assert_eq!(local.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(failure_reason(&local, None, true), failures::Reason::Other);
        }
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::TimedOut,
        ] {
            let local = io::Error::new(kind, "private detail");
            assert_eq!(
                failure_reason(&local, None, true),
                failures::Reason::Other,
                "{kind:?}"
            );
        }
        for rejected in [
            phone::rejected_credentials_error(),
            phone::rejected_method_error(io::ErrorKind::PermissionDenied),
        ] {
            assert_eq!(rejected.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                failure_reason(&rejected, None, true),
                failures::Reason::Denied
            );
        }
        let method = phone::rejected_method_error(io::ErrorKind::InvalidData);
        assert_eq!(
            failure_reason(&method, None, true),
            failures::Reason::Denied
        );
        // A source device reply code is a source device decision.
        let local = io::Error::from_raw_os_error(LOCAL_DENIED_CODES[0]);
        assert_eq!(
            failure_reason(&local, Some(5), true),
            failures::Reason::Refused
        );
        // A direct connect timeout reaches the destination.
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "private detail");
        assert_eq!(
            failure_reason(&timeout, None, false),
            failures::Reason::TimedOut
        );
        assert_eq!(
            failure_reason(&timeout, None, true),
            failures::Reason::Other
        );
        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "private detail");
        assert_eq!(
            failure_reason(&refused, None, false),
            failures::Reason::Refused
        );
        assert_eq!(
            failure_reason(&refused, None, true),
            failures::Reason::Other
        );
    }
    #[test]
    fn auth_rejection_keeps_the_permission_denied_counter() {
        let counters = Counters::default();
        for rejected in [
            phone::rejected_credentials_error(),
            phone::rejected_method_error(io::ErrorKind::PermissionDenied),
        ] {
            count_tcp_setup_error(&counters, &rejected, TcpSetupPhase::PhoneAuth, None);
        }
        assert_eq!(value(&counters.flow_errors), 2);
        assert_eq!(value(&counters.tcp_setup_errors), 2);
        assert_eq!(value(&counters.tcp_setup_permission_denied), 2);
        assert_eq!(value(&counters.tcp_setup_other), 0);
    }
    #[test]
    fn tcp_retransmits_reach_the_diagnostics_counter() {
        let counters = Counters::default();
        let now = Instant::now();
        let mut engine = tcp::TcpFlow::new(1, 2, &[], 65535, now);
        engine.outer_connected();
        engine.outer_data(b"abc", now);
        engine.actions();
        engine.tick(now + Duration::from_millis(400));
        collect_tcp_metrics(&counters, &mut engine, now + Duration::from_millis(400));
        assert_eq!(value(&counters.tcp_retransmits), 1);
        assert_eq!(value_usize(&counters.tcp_flows_peak), 0);
    }
    #[test]
    fn established_teardown_marks_the_same_bucket_observed() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        stream.set_nonblocking(true).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let counters = Arc::new(Counters::default());
        let output = Arc::new(Output::new().unwrap());
        let audit = Arc::new(normalization::Audit::default());
        let mut worker = Worker::new(
            RelayConfig::default(),
            output,
            Arc::clone(&counters),
            audit,
            Arc::new(AtomicBool::new(true)),
        );
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::LOCALHOST;
        let key = Key {
            proto: packet::PROTO_TCP,
            src: src.into(),
            dst: dst.into(),
            sport: 5555,
            dport: 443,
        };
        let mut engine = tcp::TcpFlow::new(1, 2, &[], 65535, Instant::now());
        engine.outer_connected();
        worker.tcp.insert(
            key,
            TcpEntry {
                engine,
                stream,
                setup: None,
                was_established: true,
                _gauge: TcpFlowGauge::new(&counters),
            },
        );
        let rst = packet::build_tcp(&packet::TcpBuild {
            src,
            dst,
            sport: key.sport,
            dport: key.dport,
            seq: 2,
            ack: 3,
            flags: packet::RST | packet::ACK,
            window: 0,
            payload: &[],
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap();
        worker.handle(&rst);
        let buckets = counters.timeline.snapshot(Instant::now());
        let teardown = buckets
            .iter()
            .find(|bucket| bucket.tcp_teardowns == 1)
            .expect("one teardown bucket");
        assert!(
            teardown.observed,
            "a teardown bucket must show that a flow was present"
        );
        assert_eq!(value(&counters.tcp_flows_closed), 1);
        assert_eq!(value_usize(&counters.tcp_flows_active), 0);
    }
    #[test]
    fn pump_records_one_observation_for_an_established_flow() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        stream.set_nonblocking(true).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let counters = Arc::new(Counters::default());
        let output = Arc::new(Output::new().unwrap());
        let audit = Arc::new(normalization::Audit::default());
        let mut worker = Worker::new(
            RelayConfig::default(),
            output,
            Arc::clone(&counters),
            audit,
            Arc::new(AtomicBool::new(true)),
        );
        let key = Key {
            proto: packet::PROTO_TCP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::LOCALHOST.into(),
            sport: 5555,
            dport: 443,
        };
        let mut engine = tcp::TcpFlow::new(1, 2, &[], 65535, Instant::now());
        engine.outer_connected();
        worker.tcp.insert(
            key,
            TcpEntry {
                engine,
                stream,
                setup: None,
                was_established: true,
                _gauge: TcpFlowGauge::new(&counters),
            },
        );
        worker.pump();
        let buckets = counters.timeline.snapshot(Instant::now());
        assert!(
            buckets.iter().any(|bucket| bucket.observed),
            "an established flow must be observed"
        );
        // Sampling metrics does not record an observation. The worker pump
        // records it once, not once for each inner packet.
        let other = Counters::default();
        let mut engine = tcp::TcpFlow::new(1, 2, &[], 65535, Instant::now());
        engine.outer_connected();
        collect_tcp_metrics(&other, &mut engine, Instant::now());
        assert!(other
            .timeline
            .snapshot(Instant::now())
            .iter()
            .all(|bucket| !bucket.observed));
    }
    #[test]
    fn udp_age_drops_reach_the_diagnostics_counter() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let audit = Arc::new(normalization::Audit::default());
        let counters = Arc::new(Counters::default());
        let output = Arc::new(Output::new().unwrap());
        let mut worker = Worker::new(
            RelayConfig::default(),
            output,
            Arc::clone(&counters),
            audit,
            Arc::new(AtomicBool::new(true)),
        );
        let key = Key {
            proto: packet::PROTO_UDP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::new(1, 1, 1, 1).into(),
            sport: 1234,
            dport: 4321,
        };
        let mut frames = UdpFrameQueue::new();
        frames.push(5, Instant::now() - Duration::from_millis(300));
        worker.udp.insert(
            key,
            UdpEntry {
                socket: UdpSocketKind::Phone {
                    stream,
                    incoming: Vec::new(),
                    outgoing: vec![0, 3, b'a', b'b', b'c'],
                    frames,
                    dns: false,
                    setup: None,
                },
                last: Instant::now(),
                dns_query_id: None,
                dns_started: None,
            },
        );
        worker.pump();
        assert_eq!(value(&counters.udp_age_drops), 1);
        assert_eq!(value(&counters.udp_dropped), 1);
        assert!(
            counters
                .timeline
                .snapshot(Instant::now())
                .iter()
                .all(|bucket| bucket.udp_teardowns == 0),
            "dropping a datagram is not a flow teardown"
        );
    }
    #[test]
    fn udp_setup_failure_counts_as_a_teardown() {
        let (client, _peer) = tcp_pair();
        let audit = Arc::new(normalization::Audit::default());
        let counters = Arc::new(Counters::default());
        let output = Arc::new(Output::new().unwrap());
        let mut worker = Worker::new(
            RelayConfig::default(),
            output,
            Arc::clone(&counters),
            audit,
            Arc::new(AtomicBool::new(true)),
        );
        let phone = phone::PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_millis(1),
        };
        let mut setup =
            Setup::phone(&phone, Ipv4Addr::new(203, 0, 113, 5).into(), 4321, 1).unwrap();
        setup.stage = SetupStage::ReadHeader;
        setup.need = 4;
        // Make the local setup deadline expire without waiting.
        setup.deadline = Instant::now() - Duration::from_millis(1);
        let key = Key {
            proto: packet::PROTO_UDP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::new(203, 0, 113, 5).into(),
            sport: 1234,
            dport: 4321,
        };
        worker.udp.insert(
            key,
            UdpEntry {
                socket: UdpSocketKind::Phone {
                    stream: client,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    frames: UdpFrameQueue::new(),
                    dns: false,
                    setup: Some(setup),
                },
                last: Instant::now(),
                dns_query_id: None,
                dns_started: None,
            },
        );
        worker.pump();
        assert!(worker.udp.is_empty());
        assert_eq!(value(&counters.udp_flows_closed), 1);
        assert_eq!(value(&counters.udp_dropped), 0);
        let buckets = counters.timeline.snapshot(Instant::now());
        assert_eq!(
            buckets
                .iter()
                .map(|bucket| bucket.udp_teardowns)
                .sum::<u64>(),
            1,
            "a failed UDP setup still closes a flow, so it is a teardown"
        );
        assert!(
            buckets.iter().all(|bucket| !bucket.observed),
            "a setup failure never reached an established flow"
        );
    }
    #[test]
    fn diagnostics_convert_units_and_keep_the_shape() {
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            ..RelayConfig::default()
        })
        .unwrap();
        relay
            .counters
            .tcp_window_limited_us
            .store(2_500, Ordering::Relaxed);
        relay.counters.tcp_retransmits.store(3, Ordering::Relaxed);
        relay.counters.udp_flows.store(5, Ordering::Relaxed);
        relay.counters.udp_age_drops.store(4, Ordering::Relaxed);
        relay.counters.dns_lookups.store(6, Ordering::Relaxed);
        relay.counters.dns_ok.store(4, Ordering::Relaxed);
        relay.counters.dns_failed.store(2, Ordering::Relaxed);
        relay.counters.setup_connect_us.record(12_000);
        relay.counters.setup_connect_us.record(20_000);
        let d = relay.diagnostics();
        assert_eq!(d["tcp"]["zero_window_ms"], 2);
        assert_eq!(d["tcp"]["retransmits"], 3);
        assert_eq!(d["udp"]["flows"], 5);
        assert_eq!(d["udp"]["age_drops"], 4);
        assert_eq!(d["dns"]["lookups"], 6);
        assert_eq!(d["dns"]["ok"], 4);
        assert_eq!(d["dns"]["failed"], 2);
        assert_eq!(d["setup"]["connect_ms"]["count"], 2);
        assert_eq!(d["setup"]["connect_ms"]["p50"], 12);
        assert_eq!(d["setup"]["connect_ms"]["p95"], 20);
        assert_eq!(d["setup"]["connect_ms"]["max"], 20);
        assert_eq!(d["queues"]["input"].as_array().unwrap().len(), 1);
        assert!(d["queues"]["output"].is_object());
        assert!(!d.to_string().contains("127.0.0.1"));
        relay.stop();
    }
    #[test]
    fn queue_metrics_track_full_dequeue_and_disconnect() {
        let metrics = Arc::new(QueueMetrics::default());
        let (tx, rx) = mpsc::sync_channel(1);
        enqueue(&tx, vec![1], &metrics).unwrap();
        assert!(enqueue(&tx, vec![2], &metrics).is_err());
        let snapshot = metrics.snapshot();
        assert_eq!((snapshot.packets_current, snapshot.packets_peak), (1, 1));
        thread::sleep(Duration::from_millis(2));
        assert_eq!(rx.try_recv().unwrap().consume(), vec![1]);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.packets_current, 0);
        assert!(snapshot.max_age_us >= 1000);
        enqueue(&tx, vec![3], &metrics).unwrap();
        drop(rx);
        assert_eq!(metrics.snapshot().packets_current, 0);
    }
    #[test]
    fn output_queue_metrics_follow_queue_contents() {
        let output = Output::new().unwrap();
        assert!(output.push(vec![1]));
        assert!(output.push(vec![2]));
        let snapshot = output.metrics.snapshot();
        assert_eq!((snapshot.packets_current, snapshot.packets_peak), (2, 2));
        thread::sleep(Duration::from_millis(2));
        assert_eq!(output.pop(), Some(vec![1]));
        assert_eq!(output.metrics.snapshot().packets_current, 1);
        assert_eq!(output.pop(), Some(vec![2]));
        let snapshot = output.metrics.snapshot();
        assert_eq!(snapshot.packets_current, 0);
        assert!(snapshot.max_age_us >= 1000);
    }
    #[test]
    fn output_reserves_a_bounded_fifo_tail_for_tcp_control() {
        let output = Output::new().unwrap();
        for _ in 0..QUEUE {
            assert!(output.push(vec![1]));
        }
        assert!(!output.push(vec![2]));
        for _ in 0..TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![3]));
        }
        assert!(!output.push_tcp_control(vec![4]));
        assert_eq!(
            output.metrics.snapshot().packets_peak,
            (QUEUE + TCP_CONTROL_RESERVE) as u64
        );
        for _ in 0..QUEUE {
            assert_eq!(output.pop(), Some(vec![1]));
        }
        for _ in 0..TCP_CONTROL_RESERVE {
            assert_eq!(output.pop(), Some(vec![3]));
        }
        assert_eq!(output.pop(), None);
        assert_eq!(output.metrics.snapshot().packets_current, 0);
    }
    #[test]
    fn full_output_does_not_turn_idle_probes_into_a_peer_timeout() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE {
            assert!(output.push(vec![1]));
        }
        let now = Instant::now();
        let mut engine = tcp::TcpFlow::new(100, 200, &[], 65535, now - Duration::from_secs(601));
        engine.outer_connected();
        let key = Key {
            proto: packet::PROTO_TCP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::new(203, 0, 113, 9).into(),
            sport: 5555,
            dport: 443,
        };
        for cycle in 0..5 {
            engine.tick(now + Duration::from_secs(cycle * 61));
            worker.emit(key, &mut engine, None);
            assert_eq!(engine.state, tcp::State::Established);
        }
        assert_eq!(value(&counters.send_dropped), 5);
        assert_eq!(value(&counters.packets_out), 0);
        assert_eq!(output.pop(), Some(vec![1]));
        engine.tick(now + Duration::from_secs(5 * 61));
        worker.emit(key, &mut engine, None);
        assert_eq!(value(&counters.packets_out), 1);
        for _ in 1..QUEUE {
            assert_eq!(output.pop(), Some(vec![1]));
        }
        let raw = output.pop().expect("the retried probe must be queued");
        let ip = packet::parse_ip(&raw).unwrap();
        let segment = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(segment.flags, packet::ACK);
        assert_eq!(segment.seq, engine.next_seq().wrapping_sub(1));
        assert!(segment.data.is_empty());
    }
    #[test]
    fn flow_assignment_is_stable_and_distinguishes_ports() {
        let k = Key {
            proto: 6,
            src: Ipv4Addr::LOCALHOST.into(),
            dst: Ipv4Addr::new(1, 1, 1, 1).into(),
            sport: 123,
            dport: 443,
        };
        assert_eq!(shard(&k, 4), shard(&k, 4));
        assert!((100..200).any(|port| shard(&Key { sport: port, ..k }, 4) != shard(&k, 4)));
    }
    #[test]
    fn rejects_implicit_unpinned_and_bounds_workers() {
        assert!(Relay::start(RelayConfig::default()).is_err());
        assert!(Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 9,
            ..RelayConfig::default()
        })
        .is_err());
    }
    #[test]
    fn relay_rejects_invalid_dns_upstreams_before_start() {
        for upstream in [
            "127.0.0.1:53",
            "[::1]:53",
            "0.0.0.0:53",
            "224.0.0.1:53",
            "[::ffff:192.0.2.53]:53",
        ] {
            assert!(
                Relay::start(RelayConfig {
                    allow_unpinned: true,
                    dns_upstream: Some(upstream.parse().unwrap()),
                    ..RelayConfig::default()
                })
                .is_err(),
                "{upstream}"
            );
        }
        let scoped = std::net::SocketAddrV6::new("2001:db8::53".parse().unwrap(), 53, 1, 2);
        assert!(Relay::start(RelayConfig {
            allow_unpinned: true,
            dns_upstream: Some(scoped.into()),
            ..RelayConfig::default()
        })
        .is_err());
    }
    #[test]
    fn mock_tun_udp_roundtrip_and_ttl_audit() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let mut b = [0u8; 32];
            let (n, src) = server.recv_from(&mut b).unwrap();
            server.send_to(&b[..n], src).unwrap();
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 2,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::LOCALHOST;
        relay
            .dispatch(packet::build_udp(src, dst, 5555, port, b"hello", 64, 0).unwrap())
            .unwrap();
        let response = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let p = packet::parse_ip(&response).unwrap();
        let udp = packet::parse_udp(p.payload).unwrap();
        assert_eq!(udp.data, b"hello");
        assert_eq!((udp.sport, udp.dport), (port, 5555));
        assert_eq!(relay.stats().ttl_bad, 0);
        relay.stop();
        echo.join().unwrap();
    }
    #[test]
    fn mock_tun_tcp_echo_preserves_tuple() {
        use std::net::TcpListener;
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut data = [0u8; 5];
            s.read_exact(&mut data).unwrap();
            s.write_all(&data).unwrap();
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 2,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::LOCALHOST;
        let make = |seq, ack, flags, payload: &[u8]| {
            packet::build_tcp(&packet::TcpBuild {
                src,
                dst,
                sport: 5556,
                dport: port,
                seq,
                ack,
                flags,
                window: 65535,
                payload,
                options: &[],
                ttl: 64,
                ident: 0,
            })
            .unwrap()
        };
        relay.dispatch(make(100, 0, packet::SYN, &[])).unwrap();
        let syn = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let p = packet::parse_ip(&syn).unwrap();
        let seg = packet::parse_tcp(p.payload).unwrap();
        assert_eq!(seg.flags, packet::SYN | packet::ACK);
        let server_seq = seg.seq;
        relay
            .dispatch(make(101, server_seq.wrapping_add(1), packet::ACK, b"hello"))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut got = false;
        while Instant::now() < deadline {
            let raw = relay.recv_timeout(Duration::from_millis(500)).unwrap();
            let p = packet::parse_ip(&raw).unwrap();
            let seg = packet::parse_tcp(p.payload).unwrap();
            if seg.data == b"hello" {
                assert_eq!((seg.sport, seg.dport), (port, 5556));
                got = true;
                break;
            }
        }
        assert!(got);
        assert_eq!(relay.stats().ttl_bad, 0);
        relay.stop();
        echo.join().unwrap();
    }
    #[test]
    fn phone_udp_uses_authenticated_stream_and_frames() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut b = [0u8; 3];
            s.read_exact(&mut b).unwrap();
            assert_eq!(b, [5, 1, 2]);
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0u8; 6];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            s.write_all(&[1, 0]).unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req[1], 0x80);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut frame = [0u8; 7];
            s.read_exact(&mut frame).unwrap();
            assert_eq!(&frame, b"\x00\x05hello");
            s.write_all(&frame).unwrap();
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            phone: Some(phone),
            workers: 2,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        relay
            .dispatch(packet::build_udp(src, dst, 5557, 123, b"hello", 64, 0).unwrap())
            .unwrap();
        let raw = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        let udp = packet::parse_udp(ip.payload).unwrap();
        assert_eq!(udp.data, b"hello");
        assert_eq!((udp.sport, udp.dport), (123, 5557));
        assert_eq!(relay.stats().ttl_bad, 0);
        relay.stop();
        server.join().unwrap();
    }
    #[test]
    fn phone_udp_queue_is_bounded_when_the_phone_stream_stalls() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut b = [0u8; 3];
            s.read_exact(&mut b).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0u8; 6];
            s.read_exact(&mut auth).unwrap();
            s.write_all(&[1, 0]).unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req[1], 0x80);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            ready_tx.send(()).unwrap();
            // Stop reading. The stream stalls until the test ends.
            let _ = release_rx.recv_timeout(Duration::from_secs(20));
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            phone: Some(phone),
            workers: 1,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::new(203, 0, 113, 7);
        let payload = [0x5au8; 1400];
        relay
            .dispatch(packet::build_udp(src, dst, 5560, 9999, &payload, 64, 0).unwrap())
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while relay.stats().udp_dropped == 0 && Instant::now() < until {
            for _ in 0..64 {
                let _ = relay
                    .dispatch(packet::build_udp(src, dst, 5560, 9999, &payload, 64, 0).unwrap());
            }
            thread::sleep(Duration::from_millis(2));
        }
        let stats = relay.stats();
        assert!(
            stats.udp_dropped > 0,
            "a stalled phone stream must cause counted drops"
        );
        assert_eq!(stats.ttl_bad, 0);
        relay.stop();
        let _ = release_tx.send(());
        server.join().unwrap();
    }
    fn frame_buffer(sizes: &[usize]) -> (Vec<u8>, UdpFrameQueue, Instant) {
        let t0 = Instant::now();
        let mut buffer = Vec::new();
        let mut queue = UdpFrameQueue::new();
        for (i, size) in sizes.iter().enumerate() {
            buffer.extend_from_slice(&(*size as u16).to_be_bytes());
            buffer.extend(std::iter::repeat_n(i as u8 + 1, *size));
            queue.push(size + 2, t0 + Duration::from_millis(100 * i as u64));
        }
        (buffer, queue, t0)
    }
    fn parse_frames(buffer: &[u8]) -> Vec<(usize, u8)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < buffer.len() {
            let n = u16::from_be_bytes([buffer[at], buffer[at + 1]]) as usize;
            out.push((n, buffer[at + 2]));
            at += 2 + n;
        }
        assert_eq!(at, buffer.len(), "buffer must hold whole frames");
        out
    }
    #[test]
    fn frame_queue_expires_only_old_whole_frames() {
        let (mut buffer, mut queue, t0) = frame_buffer(&[10, 20, 30]);
        // Frames are 0, 100, and 200 ms old at t0 + 200 ms offsets. At t0 + 450 ms
        // the ages are 450, 350, 250 ms. The limit is 300 ms.
        let now = t0 + Duration::from_millis(450);
        let dropped = queue.expire(&mut buffer, now, Duration::from_millis(300));
        assert_eq!(dropped, 2);
        assert_eq!(parse_frames(&buffer), vec![(30, 3)]);
        assert_eq!(
            queue.expire(&mut buffer, now, Duration::from_millis(300)),
            0
        );
    }
    #[test]
    fn frame_queue_keeps_a_partly_written_frame() {
        let (mut buffer, mut queue, t0) = frame_buffer(&[10, 20, 30]);
        // The stream accepted 5 bytes of the first frame.
        buffer.drain(..5);
        queue.advance(5);
        let now = t0 + Duration::from_millis(1000);
        let dropped = queue.expire(&mut buffer, now, Duration::from_millis(300));
        // The first frame is partly written, so it stays. The other two leave.
        assert_eq!(dropped, 2);
        assert_eq!(buffer.len(), 12 - 5);
        // The stream accepts the rest. The queue is empty and consistent.
        queue.advance(7);
        buffer.clear();
        assert_eq!(
            queue.expire(&mut buffer, now, Duration::from_millis(300)),
            0
        );
        assert!(queue.frames.is_empty());
        assert_eq!(queue.front_sent, 0);
    }
    #[test]
    fn frame_queue_advance_tracks_frame_boundaries() {
        let (mut buffer, mut queue, t0) = frame_buffer(&[10, 20, 30]);
        // Write the first frame fully and 3 bytes of the second.
        buffer.drain(..15);
        queue.advance(15);
        assert_eq!(queue.frames.len(), 2);
        assert_eq!(queue.front_sent, 3);
        let now = t0 + Duration::from_millis(1000);
        let dropped = queue.expire(&mut buffer, now, Duration::from_millis(300));
        assert_eq!(dropped, 1);
        assert_eq!(buffer.len(), 22 - 3);
    }
    #[test]
    fn frame_queue_restamp_gives_queued_frames_a_fresh_age() {
        let (mut buffer, mut queue, t0) = frame_buffer(&[10, 20]);
        let now = t0 + Duration::from_millis(5000);
        queue.restamp(now);
        assert_eq!(
            queue.expire(
                &mut buffer,
                now + Duration::from_millis(100),
                Duration::from_millis(300)
            ),
            0
        );
        assert_eq!(parse_frames(&buffer).len(), 2);
    }
    #[test]
    fn mock_tun_ipv6_udp_roundtrip() {
        use std::net::Ipv6Addr;
        let server = UdpSocket::bind("[::1]:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let mut b = [0u8; 32];
            let (n, src) = server.recv_from(&mut b).unwrap();
            server.send_to(&b[..n], src).unwrap();
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            ipv6_forward: true,
            workers: 2,
            ..RelayConfig::default()
        })
        .unwrap();
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst = Ipv6Addr::LOCALHOST;
        relay
            .dispatch(packet::build_udp_v6(src, dst, 5555, port, b"hello6", 64).unwrap())
            .unwrap();
        let raw = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let p = packet::parse_ip(&raw).unwrap();
        assert_eq!(p.src, IpAddr::V6(dst));
        assert_eq!(p.dst, IpAddr::V6(src));
        let udp = packet::parse_udp(p.payload).unwrap();
        assert_eq!(udp.data, b"hello6");
        assert_eq!((udp.sport, udp.dport), (port, 5555));
        assert_eq!(relay.stats().ttl_bad, 0);
        relay.stop();
        echo.join().unwrap();
    }
    #[test]
    fn mock_tun_ipv6_tcp_echo() {
        use std::net::{Ipv6Addr, TcpListener};
        let server = TcpListener::bind("[::1]:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut data = [0u8; 6];
            s.read_exact(&mut data).unwrap();
            s.write_all(&data).unwrap();
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            ipv6_forward: true,
            workers: 2,
            ..RelayConfig::default()
        })
        .unwrap();
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst = Ipv6Addr::LOCALHOST;
        let make = |seq, ack, flags, payload: &[u8]| {
            packet::build_tcp_v6(&packet::TcpBuildV6 {
                src,
                dst,
                sport: 5556,
                dport: port,
                seq,
                ack,
                flags,
                window: 65535,
                payload,
                options: &[],
                hop_limit: 64,
            })
            .unwrap()
        };
        relay.dispatch(make(100, 0, packet::SYN, &[])).unwrap();
        let syn = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let p = packet::parse_ip(&syn).unwrap();
        let seg = packet::parse_tcp(p.payload).unwrap();
        assert_eq!(seg.flags, packet::SYN | packet::ACK);
        let server_seq = seg.seq;
        relay
            .dispatch(make(
                101,
                server_seq.wrapping_add(1),
                packet::ACK,
                b"hello6",
            ))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut got = false;
        while Instant::now() < deadline {
            let raw = relay.recv_timeout(Duration::from_millis(500)).unwrap();
            let p = packet::parse_ip(&raw).unwrap();
            assert_eq!(p.src, IpAddr::V6(dst));
            assert_eq!(p.dst, IpAddr::V6(src));
            let seg = packet::parse_tcp(p.payload).unwrap();
            if seg.data == b"hello6" {
                got = true;
                break;
            }
        }
        assert!(got);
        assert_eq!(relay.stats().ttl_bad, 0);
        relay.stop();
        echo.join().unwrap();
    }
    #[test]
    fn ipv6_is_dropped_by_default_and_fragments_are_not_forwarded() {
        use std::net::Ipv6Addr;
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let raw = packet::build_udp_v6(src, dst, 10, 11, b"x", 64).unwrap();
        relay.dispatch(raw).unwrap();
        assert_eq!(relay.stats().ipv6_dropped, 1);
        relay.stop();
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            ipv6_forward: true,
            ..RelayConfig::default()
        })
        .unwrap();
        let mut raw = packet::build_udp_v6(src, dst, 10, 11, b"x", 64).unwrap();
        raw[6] = 44;
        raw.splice(40..40, [17, 0, 0, 0, 0, 0, 0, 1]);
        let len = (raw.len() - 40) as u16;
        raw[4..6].copy_from_slice(&len.to_be_bytes());
        relay.dispatch(raw).unwrap();
        assert_eq!(relay.stats().fragments_dropped, 1);
        assert_eq!(relay.audit.snapshot().0, 0);
        relay.stop();
    }
    #[test]
    fn phone_proxy_ipv6_udp_and_tcp_are_authenticated() {
        use std::net::{Ipv6Addr, TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for command in [0x80, 1] {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut hello = [0u8; 3];
                s.read_exact(&mut hello).unwrap();
                assert_eq!(hello, [5, 1, 2]);
                s.write_all(&[5, 2]).unwrap();
                let mut auth = [0u8; 6];
                s.read_exact(&mut auth).unwrap();
                assert_eq!(&auth, b"\x01\x01u\x02pw");
                s.write_all(&[1, 0]).unwrap();
                let mut req = [0u8; 22];
                s.read_exact(&mut req).unwrap();
                assert_eq!((req[1], req[3]), (command, 4));
                assert_eq!(
                    &req[4..20],
                    &"2001:db8::5".parse::<Ipv6Addr>().unwrap().octets()
                );
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                if command == 0x80 {
                    let mut buf = [0; 7];
                    s.read_exact(&mut buf).unwrap();
                    assert_eq!(&buf, b"\x00\x05hello");
                    s.write_all(&buf).unwrap();
                } else {
                    let mut buf = [0; 5];
                    s.read_exact(&mut buf).unwrap();
                    assert_eq!(&buf, b"hello");
                    s.write_all(&buf).unwrap();
                }
            }
        });
        let phone = Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(3),
        });
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            ipv6_forward: true,
            phone: Some(phone),
            workers: 2,
            ..RelayConfig::default()
        })
        .unwrap();
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::5".parse().unwrap();
        relay
            .dispatch(packet::build_udp_v6(src, dst, 5555, 123, b"hello", 64).unwrap())
            .unwrap();
        let raw = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let p = packet::parse_ip(&raw).unwrap();
        assert_eq!(packet::parse_udp(p.payload).unwrap().data, b"hello");
        let make = |seq, ack, flags, payload: &[u8]| {
            packet::build_tcp_v6(&packet::TcpBuildV6 {
                src,
                dst,
                sport: 5556,
                dport: 443,
                seq,
                ack,
                flags,
                window: 65535,
                payload,
                options: &[],
                hop_limit: 64,
            })
            .unwrap()
        };
        relay.dispatch(make(100, 0, packet::SYN, &[])).unwrap();
        let syn = relay.recv_timeout(Duration::from_secs(3)).unwrap();
        let p = packet::parse_ip(&syn).unwrap();
        let seg = packet::parse_tcp(p.payload).unwrap();
        let server_seq = seg.seq;
        assert_eq!(seg.flags, packet::SYN | packet::ACK);
        relay
            .dispatch(make(101, server_seq.wrapping_add(1), packet::ACK, b"hello"))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut got = false;
        while Instant::now() < deadline {
            let raw = relay.recv_timeout(Duration::from_millis(500)).unwrap();
            let p = packet::parse_ip(&raw).unwrap();
            if let Some(seg) = packet::parse_tcp(p.payload) {
                if seg.data == b"hello" {
                    got = true;
                    break;
                }
            }
        }
        assert!(got);
        assert_eq!(relay.audit.snapshot(), (2, 0));
        relay.stop();
        server.join().unwrap();
    }
    #[test]
    fn phone_ipv6_dns_checks_reply_transaction_and_stays_on_phone_path() {
        use std::net::{Ipv6Addr, TcpListener};
        for good in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut hello = [0u8; 3];
                s.read_exact(&mut hello).unwrap();
                s.write_all(&[5, 2]).unwrap();
                let mut auth = [0u8; 6];
                s.read_exact(&mut auth).unwrap();
                s.write_all(&[1, 0]).unwrap();
                let mut req = [0u8; 10];
                s.read_exact(&mut req).unwrap();
                assert_eq!(req, [5, 1, 0, 1, 1, 1, 1, 1, 0, 53]);
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let mut frame = [0u8; 14];
                s.read_exact(&mut frame).unwrap();
                assert_eq!(&frame[..2], &[0, 12]);
                frame[4] |= 0x80;
                if !good {
                    frame[2] ^= 1;
                }
                s.write_all(&frame).unwrap();
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(3),
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                ipv6_forward: true,
                phone: Some(phone),
                workers: 2,
                ..RelayConfig::default()
            })
            .unwrap();
            let src: Ipv6Addr = "fd00::2".parse().unwrap();
            let dst: Ipv6Addr = "2001:db8::53".parse().unwrap();
            let query = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            relay
                .dispatch(packet::build_udp_v6(src, dst, 5555, 53, &query, 64).unwrap())
                .unwrap();
            if good {
                let raw = relay.recv_timeout(Duration::from_secs(2)).unwrap();
                let p = packet::parse_ip(&raw).unwrap();
                let udp = packet::parse_udp(p.payload).unwrap();
                assert_eq!(&udp.data[..2], &query[..2]);
                assert_ne!(udp.data[2] & 0x80, 0);
            } else {
                assert!(relay.recv_timeout(Duration::from_millis(300)).is_err());
                assert!(relay.stats().udp_errors > 0);
            }
            let d = relay.diagnostics();
            assert_eq!(d["dns"]["lookups"], 1);
            assert_eq!(d["dns"]["ok"], u64::from(good));
            assert_eq!(d["dns"]["failed"], u64::from(!good));
            assert_eq!(d["dns"]["ms"]["count"], 1);
            assert!(d["dns"]["ms"]["max"].as_u64().is_some());
            assert_eq!(relay.audit.snapshot(), (1, 0));
            relay.stop();
            server.join().unwrap();
        }
    }
    /// Return true when the output notification is readable before the deadline.
    fn output_ready_within(output: &Output, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let mut set = PollSet::with_capacity(1);
            set.push_handle(output.handle(), Interest::READABLE)
                .unwrap();
            if set.wait(Duration::ZERO).unwrap() > 0 {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Return true when the output notification is readable now.
    fn output_ready_now(output: &Output) -> bool {
        let mut set = PollSet::with_capacity(1);
        set.push_handle(output.handle(), Interest::READABLE)
            .unwrap();
        set.wait(Duration::ZERO).unwrap() > 0
    }

    #[test]
    fn output_notification_remains_readable_until_all_packets_are_taken() {
        let output = Output::new().unwrap();
        assert!(!output_ready_now(&output));
        assert!(output.push(vec![1]));
        assert!(output.push(vec![2]));
        assert!(output_ready_within(&output, Duration::from_millis(100)));
        assert_eq!(output.pop(), Some(vec![1]));
        assert!(output_ready_now(&output));
        assert_eq!(output.pop(), Some(vec![2]));
        assert!(!output_ready_now(&output));
        assert!(output.push(vec![3]));
        assert!(output_ready_within(&output, Duration::from_millis(100)));
        assert_eq!(output.pop(), Some(vec![3]));
        assert!(!output_ready_now(&output));
    }
    #[test]
    fn output_wakeup_is_not_lost_with_concurrent_producers() {
        let output = Arc::new(Output::new().unwrap());
        let producers: Vec<_> = (0..4)
            .map(|id| {
                let output = output.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        while !output.push(vec![id]) {
                            thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        let mut seen = 0;
        while seen < 4000 {
            while output.pop().is_some() {
                seen += 1;
            }
            if seen == 4000 {
                break;
            }
            let mut set = PollSet::with_capacity(1);
            set.push_handle(output.handle(), Interest::READABLE)
                .unwrap();
            assert_eq!(
                set.wait(Duration::from_secs(3)).unwrap(),
                1,
                "output wake was lost"
            );
        }
        for producer in producers {
            producer.join().unwrap();
        }
    }
    #[test]
    fn stop_cancels_stalled_phone_handshakes_for_tcp_and_udp() {
        use std::net::TcpListener;
        for udp in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (ready_tx, ready_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).unwrap();
                assert_eq!(hello, [5, 1, 2]);
                ready_tx.send(()).unwrap();
                let mut b = [0; 1];
                assert_eq!(stream.read(&mut b).unwrap(), 0);
            });
            let phone = Arc::new(phone::PhoneProxy {
                address,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(20),
            });
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                phone: Some(phone),
                workers: 1,
                ..RelayConfig::default()
            })
            .unwrap();
            let src = Ipv4Addr::new(198, 18, 0, 2);
            let dst = Ipv4Addr::new(1, 1, 1, 1);
            let raw = if udp {
                packet::build_udp(src, dst, 5555, 123, b"hello", 64, 0).unwrap()
            } else {
                packet::build_tcp(&packet::TcpBuild {
                    src,
                    dst,
                    sport: 5555,
                    dport: 443,
                    seq: 100,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap()
            };
            relay.dispatch(raw).unwrap();
            ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let start = Instant::now();
            relay.stop();
            assert!(start.elapsed() < Duration::from_millis(500));
            server.join().unwrap();
        }
    }

    fn read_phone_request(stream: &mut TcpStream) -> [u8; 10] {
        let mut hello = [0; 3];
        stream.read_exact(&mut hello).unwrap();
        assert_eq!(hello, [5, 1, 2]);
        stream.write_all(&[5, 2]).unwrap();
        let mut auth = [0; 6];
        stream.read_exact(&mut auth).unwrap();
        assert_eq!(&auth, b"\x01\x01u\x02pw");
        stream.write_all(&[1, 0]).unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).unwrap();
        request
    }
    fn mock_phone<F>(count: usize, mut handle: F) -> (SocketAddr, JoinHandle<()>)
    where
        F: FnMut(&mut TcpStream, [u8; 10]) + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let request = read_phone_request(&mut stream);
                handle(&mut stream, request);
            }
        });
        (address, worker)
    }
    fn phone_at(address: SocketAddr, timeout: Duration) -> Arc<phone::PhoneProxy> {
        Arc::new(phone::PhoneProxy {
            address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout,
        })
    }
    fn wait_for_total(recorder: &failures::FailureRecorder, wanted: u64) -> Value {
        // Wait for the group too. The total counts an event before the ring
        // stores it. Poll slowly so the reader does not contend with the relay.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let snapshot = recorder.snapshot();
            let seen = snapshot["total"].as_u64().unwrap_or(0);
            let stored = snapshot["groups"].as_array().is_some_and(|g| !g.is_empty());
            if seen >= wanted && stored {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "failure record stalled: {snapshot}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn group<'a>(value: &'a Value, proto: &str) -> &'a Value {
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["proto"] == proto)
            .unwrap_or_else(|| panic!("no {proto} group in {value}"))
    }
    #[test]
    fn failures_record_tcp_udp_and_dns_reply_codes() {
        for code in [3u8, 4, 5] {
            let (address, mock) = mock_phone(3, move |stream, _| {
                stream
                    .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
                    .unwrap();
            });
            let recorder = Arc::new(failures::FailureRecorder::new());
            recorder.start();
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone_at(address, Duration::from_secs(2))),
                failures: Some(recorder.clone()),
                ..RelayConfig::default()
            })
            .unwrap();
            let src = Ipv4Addr::new(198, 18, 0, 2);
            let dst = Ipv4Addr::new(203, 0, 113, 5);
            relay
                .dispatch(
                    packet::build_tcp(&packet::TcpBuild {
                        src,
                        dst,
                        sport: 5555,
                        dport: 443,
                        seq: 1,
                        ack: 0,
                        flags: packet::SYN,
                        window: 65535,
                        payload: &[],
                        options: &[],
                        ttl: 64,
                        ident: 0,
                    })
                    .unwrap(),
                )
                .unwrap();
            relay
                .dispatch(packet::build_udp(src, dst, 5556, 443, b"x", 64, 0).unwrap())
                .unwrap();
            let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            relay
                .dispatch(packet::build_udp(src, dst, 5557, 53, &query, 64, 0).unwrap())
                .unwrap();
            let value = wait_for_total(&recorder, 3);
            assert_eq!(value["total"], 3);
            let expected = match code {
                3 | 4 => "unreachable",
                _ => "refused",
            };
            for proto in ["tcp", "udp", "dns"] {
                let group = group(&value, proto);
                assert_eq!(group["count"], 1, "{proto}");
                assert_eq!(group["family"], "ipv4", "{proto}");
                assert_eq!(group["reason"], expected, "{proto}");
                assert_eq!(group["phase"], "request", "{proto}");
                assert_eq!(group["code"], code, "{proto}");
            }
            assert_eq!(group(&value, "tcp")["example_ip"], "203.0.113.5");
            assert_eq!(group(&value, "dns")["example_ip"], "1.1.1.1");
            assert_eq!(value["recent"].as_array().unwrap().len(), 3);
            for recent in value["recent"].as_array().unwrap() {
                assert_eq!(recent["phase"], "request");
            }
            relay.stop();
            mock.join().unwrap();
        }
    }
    #[test]
    fn failures_record_source_device_token_rejection_as_denied() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            stream.write_all(&[1, 1]).unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        let recorder = Arc::new(failures::FailureRecorder::new());
        recorder.start();
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone_at(address, Duration::from_secs(2))),
            failures: Some(recorder.clone()),
            ..RelayConfig::default()
        })
        .unwrap();
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src: Ipv4Addr::new(198, 18, 0, 2),
                    dst: Ipv4Addr::new(203, 0, 113, 5),
                    sport: 5555,
                    dport: 443,
                    seq: 1,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        let value = wait_for_total(&recorder, 1);
        let group = group(&value, "tcp");
        assert_eq!(group["reason"], "denied");
        assert_eq!(group["phase"], "auth");
        assert_eq!(group["code"], Value::Null);
        assert_eq!(value["recent"][0]["reason"], "denied");
        assert_eq!(value["recent"][0]["phase"], "auth");
        let stats = relay.stats();
        assert_eq!(stats.tcp_setup_errors, 1);
        assert_eq!(stats.tcp_setup_permission_denied, 1);
        assert_eq!(stats.tcp_setup_refused + stats.tcp_setup_other, 0);
        relay.stop();
        mock.join().unwrap();
    }
    #[test]
    fn local_source_device_connect_errors_do_not_blame_the_destination() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let recorder = Arc::new(failures::FailureRecorder::new());
        recorder.start();
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone_at(address, Duration::from_millis(500))),
            failures: Some(recorder.clone()),
            ..RelayConfig::default()
        })
        .unwrap();
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src: Ipv4Addr::new(198, 18, 0, 2),
                    dst: Ipv4Addr::new(203, 0, 113, 5),
                    sport: 5555,
                    dport: 443,
                    seq: 1,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        let value = wait_for_total(&recorder, 1);
        let group = group(&value, "tcp");
        assert_eq!(group["reason"], "other");
        assert_eq!(group["phase"], "connect");
        assert_eq!(group["code"], Value::Null);
        let stats = relay.stats();
        assert_eq!(stats.tcp_setup_errors, 1);
        assert_eq!(stats.tcp_setup_other, 1);
        assert_eq!(stats.tcp_setup_refused, 0);
        assert_eq!(stats.tcp_setup_phone_unreachable, 0);
        relay.stop();
    }
    #[test]
    fn failures_record_setup_timeouts_for_tcp_udp_and_dns() {
        for proto in ["tcp", "udp", "dns"] {
            let (address, mock) = mock_phone(1, |stream, _| {
                thread::sleep(Duration::from_millis(600));
                let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
            });
            let recorder = Arc::new(failures::FailureRecorder::new());
            recorder.start();
            let mut relay = Relay::start(RelayConfig {
                allow_unpinned: true,
                workers: 1,
                phone: Some(phone_at(address, Duration::from_millis(100))),
                failures: Some(recorder.clone()),
                ..RelayConfig::default()
            })
            .unwrap();
            let src = Ipv4Addr::new(198, 18, 0, 2);
            let dst = Ipv4Addr::new(203, 0, 113, 5);
            let raw = match proto {
                "tcp" => packet::build_tcp(&packet::TcpBuild {
                    src,
                    dst,
                    sport: 5555,
                    dport: 443,
                    seq: 1,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
                "udp" => packet::build_udp(src, dst, 5555, 443, b"x", 64, 0).unwrap(),
                _ => {
                    let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                    packet::build_udp(src, dst, 5555, 53, &query, 64, 0).unwrap()
                }
            };
            relay.dispatch(raw).unwrap();
            let value = wait_for_total(&recorder, 1);
            let group = group(&value, proto);
            // The target device stopped waiting for the source device reply.
            // No reply arrived, so the destination did not prove a timeout.
            assert_eq!(group["reason"], "other", "{proto}");
            assert_eq!(group["phase"], "request", "{proto}");
            assert_eq!(group["code"], Value::Null, "{proto}");
            assert_eq!(value["recent"][0]["reason"], "other", "{proto}");
            assert_eq!(value["recent"][0]["phase"], "request", "{proto}");
            let stats = relay.stats();
            assert_eq!(stats.tcp_setup_timed_out, u64::from(proto == "tcp"));
            assert_eq!(stats.tcp_setup_timeout_phone_destination, 0);
            assert_eq!(stats.tcp_setup_timeout_direct_connect, 0);
            relay.stop();
            mock.join().unwrap();
        }
    }
    #[test]
    fn dns_answers_attach_a_name_to_a_later_tcp_failure() {
        let (address, mock) = mock_phone(2, |stream, request| {
            if request[1] == 1 && request[9] == 53 {
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let mut frame = [0; 2];
                stream.read_exact(&mut frame).unwrap();
                let length = u16::from_be_bytes(frame) as usize;
                let mut query = vec![0; length];
                stream.read_exact(&mut query).unwrap();
                let answer = vec![
                    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm',
                    b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0,
                    0, 0, 60, 0, 4, 203, 0, 113, 5,
                ];
                let mut frame = (answer.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&answer);
                stream.write_all(&frame).unwrap();
            } else {
                stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            }
            let mut extra = [0; 1];
            let _ = stream.read(&mut extra);
        });
        let recorder = Arc::new(failures::FailureRecorder::new());
        recorder.start();
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            phone: Some(phone_at(address, Duration::from_secs(2))),
            failures: Some(recorder.clone()),
            ..RelayConfig::default()
        })
        .unwrap();
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        relay
            .dispatch(packet::build_udp(src, dst_dns(), 5555, 53, &query, 64, 0).unwrap())
            .unwrap();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while recorder.name_hint(ip).is_none() {
            assert!(Instant::now() < deadline, "name hint stalled");
            thread::sleep(Duration::from_millis(5));
        }
        relay
            .dispatch(
                packet::build_tcp(&packet::TcpBuild {
                    src,
                    dst: Ipv4Addr::new(203, 0, 113, 5),
                    sport: 5556,
                    dport: 443,
                    seq: 1,
                    ack: 0,
                    flags: packet::SYN,
                    window: 65535,
                    payload: &[],
                    options: &[],
                    ttl: 64,
                    ident: 0,
                })
                .unwrap(),
            )
            .unwrap();
        let value = wait_for_total(&recorder, 1);
        let group = group(&value, "tcp");
        assert_eq!(group["reason"], "unreachable");
        assert_eq!(group["name"], "example.com");
        assert_eq!(group["example_ip"], "203.0.113.5");
        assert_eq!(value["recent"][0]["name"], "example.com");
        relay.stop();
        mock.join().unwrap();
    }
    fn dst_dns() -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, 53)
    }
    #[test]
    fn blocked_ipv6_tcp_gets_a_reset_and_udp_gets_an_icmp_error() {
        let mut relay = Relay::start(RelayConfig {
            allow_unpinned: true,
            workers: 1,
            ipv6_forward: false,
            ..RelayConfig::default()
        })
        .unwrap();
        let src = "2001:db8::2".parse().unwrap();
        let dst = "2001:db8::3".parse().unwrap();
        let syn = packet::build_tcp_v6(&packet::TcpBuildV6 {
            src,
            dst,
            sport: 5555,
            dport: 443,
            seq: 100,
            ack: 0,
            flags: packet::SYN,
            window: 65535,
            payload: &[],
            options: &[],
            hop_limit: 64,
        })
        .unwrap();
        relay.dispatch(syn).unwrap();
        let reply = relay.recv_timeout(Duration::from_secs(1)).unwrap();
        let ip = packet::parse_ip(&reply).unwrap();
        assert_eq!(ip.version, 6);
        assert_eq!(ip.protocol, packet::PROTO_TCP);
        assert_eq!(ip.src, IpAddr::V6(dst));
        assert_eq!(ip.dst, IpAddr::V6(src));
        let segment = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(segment.sport, 443);
        assert_eq!(segment.dport, 5555);
        assert_eq!(
            segment.flags & (packet::RST | packet::ACK),
            packet::RST | packet::ACK
        );
        assert_eq!(segment.ack, 101);
        assert_eq!(segment.seq, 0);
        let udp = packet::build_udp_v6(src, dst, 5555, 443, b"q", 64).unwrap();
        relay.dispatch(udp.clone()).unwrap();
        let reply = relay.recv_timeout(Duration::from_secs(1)).unwrap();
        let ip = packet::parse_ip(&reply).unwrap();
        assert_eq!(ip.protocol, packet::PROTO_ICMPV6);
        assert_eq!(ip.src, IpAddr::V6(dst));
        assert_eq!(ip.dst, IpAddr::V6(src));
        assert_eq!(&ip.payload[..2], &[1, 1]);
        assert_eq!(&ip.payload[4..], &udp[..]);
        let link_local =
            packet::build_udp_v6(src, "fe80::1".parse().unwrap(), 5555, 443, b"q", 64).unwrap();
        relay.dispatch(link_local).unwrap();
        assert!(matches!(
            relay.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(relay.audit.snapshot(), (0, 0));
        relay.stop();
    }

    fn udp_direct_entry(last: Instant) -> UdpEntry {
        let socket = normalization::udp_socket(
            "127.0.0.1".parse().unwrap(),
            None,
            &normalization::Audit::default(),
        )
        .unwrap();
        socket.set_nonblocking(true).unwrap();
        UdpEntry {
            socket: UdpSocketKind::Direct(socket),
            last,
            dns_query_id: None,
            dns_started: None,
        }
    }
    fn test_worker(counters: &Arc<Counters>) -> (Worker, Arc<Output>) {
        let output = Arc::new(Output::new().unwrap());
        let worker = Worker::new(
            RelayConfig::default(),
            output.clone(),
            counters.clone(),
            Arc::new(normalization::Audit::default()),
            Arc::new(AtomicBool::new(true)),
        );
        (worker, output)
    }
    fn tcp_pair() -> (TcpStream, TcpStream) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        (client, server)
    }
    fn udp_key(port: u16, dst: Ipv4Addr) -> Key {
        Key {
            proto: packet::PROTO_UDP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: dst.into(),
            sport: port,
            dport: 443,
        }
    }
    fn syn_to(dst: Ipv4Addr, port: u16, seq: u32) -> Vec<u8> {
        syn_with_flags(dst, port, seq, packet::SYN)
    }
    fn syn_with_flags(dst: Ipv4Addr, port: u16, seq: u32, flags: u8) -> Vec<u8> {
        packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst,
            sport: 5555,
            dport: port,
            seq,
            ack: 0,
            flags,
            window: 65535,
            payload: &[],
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap()
    }

    #[test]
    fn syn_with_fin_cannot_create_or_replace_a_flow() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let dst = Ipv4Addr::LOCALHOST;
        worker.handle(&syn_with_flags(dst, port, 500, packet::SYN | packet::FIN));
        assert!(worker.tcp.is_empty());
        assert!(output.pop().is_none());

        worker.handle(&syn_to(dst, port, 500));
        assert!(output.pop().is_some());
        assert_eq!(worker.tcp.len(), 1);
        worker.handle(&syn_with_flags(dst, port, 9000, packet::SYN | packet::FIN));
        assert_eq!(worker.tcp.len(), 1);
        assert_eq!(value(&counters.tcp_flows_closed), 0);
        assert!(output.pop().is_none());
    }

    fn gracefully_closed_flow(now: Instant) -> tcp::TcpFlow {
        let mut engine = tcp::TcpFlow::new(100, 200, &[], 65535, now);
        engine.outer_connected();
        engine.outer_end(now);
        engine.actions();
        engine.on_inner(
            &packet::TcpSegment {
                sport: 5555,
                dport: 443,
                seq: 101,
                ack: 202,
                flags: packet::FIN | packet::ACK,
                window: 65535,
                options: &[],
                data: &[],
            },
            now,
        );
        assert_eq!(engine.graceful_close_ack(), Some((202, 102)));
        engine
    }

    fn fin_to(dst: Ipv4Addr, seq: u32) -> Vec<u8> {
        packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst,
            sport: 5555,
            dport: 443,
            seq,
            ack: 202,
            flags: packet::FIN | packet::ACK,
            window: 65535,
            payload: &[],
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap()
    }

    #[test]
    fn a_retransmitted_fin_is_acknowledged_after_graceful_close() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        let fin = fin_to(Ipv4Addr::new(203, 0, 113, 9), 101);
        let key = flow_key(&fin).unwrap();
        worker.remember_tcp_close(key, &gracefully_closed_flow(now), now);
        worker.handle(&fin_to(Ipv4Addr::new(203, 0, 113, 9), 99));
        assert!(output.pop().is_none());
        worker.handle(&fin);
        let raw = output.pop().expect("the duplicate FIN needs an ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let ack = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((ack.flags, ack.seq, ack.ack), (packet::ACK, 202, 102));
        assert_eq!(worker.audit.snapshot(), (0, 0));
    }

    #[test]
    fn normal_close_installs_a_record_for_a_later_fin() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let (stream, _peer) = tcp_pair();
        let now = Instant::now();
        let mut engine = tcp::TcpFlow::new(100, 200, &[], 65535, now);
        engine.outer_connected();
        engine.outer_end(now);
        engine.actions();
        let fin = fin_to(Ipv4Addr::new(203, 0, 113, 9), 101);
        let key = flow_key(&fin).unwrap();
        worker.tcp.insert(
            key,
            TcpEntry {
                engine,
                stream,
                setup: None,
                was_established: true,
                _gauge: TcpFlowGauge::new(&counters),
            },
        );
        worker.handle(&fin);
        assert!(!worker.tcp.contains_key(&key));
        assert!(worker.closed_tcp.contains_key(&key));
        assert!(output.pop().is_some());
        worker.handle(&fin);
        let raw = output.pop().expect("the duplicate FIN needs a second ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let ack = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((ack.flags, ack.seq, ack.ack), (packet::ACK, 202, 102));
    }

    #[test]
    fn ipv6_fin_retry_recovers_after_a_full_output_queue() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        let src = "2001:db8::2".parse().unwrap();
        let dst = "2001:db8::3".parse().unwrap();
        let fin = packet::build_tcp_v6(&packet::TcpBuildV6 {
            src,
            dst,
            sport: 5555,
            dport: 443,
            seq: 101,
            ack: 202,
            flags: packet::FIN | packet::ACK,
            window: 65535,
            payload: &[],
            options: &[],
            hop_limit: 64,
        })
        .unwrap();
        let key = flow_key(&fin).unwrap();
        worker.remember_tcp_close(key, &gracefully_closed_flow(now), now);
        for _ in 0..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![1]));
        }
        worker.handle(&fin);
        assert!(worker.closed_tcp.contains_key(&key));
        assert_eq!(value(&counters.send_dropped), 1);
        assert_eq!(output.pop(), Some(vec![1]));
        worker.handle(&fin);
        for _ in 1..QUEUE + TCP_CONTROL_RESERVE {
            assert_eq!(output.pop(), Some(vec![1]));
        }
        let raw = output.pop().unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        assert_eq!((ip.src, ip.dst), (IpAddr::V6(dst), IpAddr::V6(src)));
        let ack = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((ack.flags, ack.seq, ack.ack), (packet::ACK, 202, 102));
    }

    #[test]
    fn close_records_expire_and_do_not_survive_a_new_syn() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        let syn = syn_to(Ipv4Addr::LOCALHOST, port, 500);
        let key = flow_key(&syn).unwrap();
        let engine = gracefully_closed_flow(now);
        worker.remember_tcp_close(key, &engine, now - CLOSED_TCP_LIFETIME);
        let seg = packet::TcpSegment {
            sport: 5555,
            dport: port,
            seq: 101,
            ack: 202,
            flags: packet::FIN | packet::ACK,
            window: 65535,
            options: &[],
            data: &[],
        };
        worker.acknowledge_closed_fin(key, &seg, now);
        assert!(!worker.closed_tcp.contains_key(&key));
        assert!(output.pop().is_none());
        worker.remember_tcp_close(key, &engine, now);
        worker.handle(&syn);
        assert!(worker.tcp.contains_key(&key));
        assert!(!worker.closed_tcp.contains_key(&key));
    }

    #[test]
    fn close_records_are_bounded_and_only_cover_graceful_flows() {
        let counters = Arc::new(Counters::default());
        let (mut worker, _) = test_worker(&counters);
        let now = Instant::now();
        let engine = gracefully_closed_flow(now);
        for port in 0..=MAX_CLOSED_TCP {
            let mut key = udp_key(port as u16, Ipv4Addr::new(203, 0, 113, 9));
            key.proto = packet::PROTO_TCP;
            worker.remember_tcp_close(key, &engine, now + Duration::from_millis(port as u64));
        }
        assert_eq!(worker.closed_tcp.len(), MAX_CLOSED_TCP);
        let mut aborted = tcp::TcpFlow::new(1, 2, &[], 65535, now);
        aborted.outer_failed();
        let key = udp_key(5000, Ipv4Addr::new(203, 0, 113, 9));
        worker.remember_tcp_close(key, &aborted, now);
        assert_eq!(worker.closed_tcp.len(), MAX_CLOSED_TCP);
    }

    #[test]
    fn reused_tuple_recovers_through_a_challenge_ack_and_reset() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let dst = Ipv4Addr::LOCALHOST;
        worker.handle(&syn_to(dst, port, 500));
        let raw = output.pop().expect("the new flow gets a SYN-ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(
            seg.flags & (packet::SYN | packet::ACK),
            packet::SYN | packet::ACK
        );
        assert_eq!(seg.ack, 501);
        let old_cseq = 501;
        assert_eq!(worker.tcp.len(), 1);
        // The local client reused the 4-tuple for a new connection. A bare SYN
        // with a different ISN is not proof of a new incarnation: the tunnel
        // can carry forwarded traffic, so it must not close a live flow
        // without a sequence number. RFC 5961, Section 4, answers with a
        // challenge ACK instead.
        worker.handle(&syn_to(dst, port, 9000));
        let raw = output.pop().expect("the bare SYN gets a challenge ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let challenge = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(challenge.flags, packet::ACK);
        assert_eq!(challenge.ack, old_cseq);
        assert_eq!(worker.tcp.len(), 1, "the live flow is still open");
        assert_eq!(value(&counters.tcp_flows_closed), 0);
        assert_eq!(counters.tcp_flows_active.load(Ordering::Relaxed), 1);
        // A client in SYN-SENT answers the challenge ACK with a reset at the
        // next expected byte. That retires the stale flow.
        let rst = packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst,
            sport: 5555,
            dport: port,
            seq: old_cseq,
            ack: challenge.seq.wrapping_add(1),
            flags: packet::RST | packet::ACK,
            window: 0,
            payload: &[],
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap();
        worker.handle(&rst);
        assert!(worker.tcp.is_empty());
        assert_eq!(value(&counters.tcp_flows_closed), 1);
        assert_eq!(counters.tcp_flows_active.load(Ordering::Relaxed), 0);
        // The SYN retransmit that follows now opens a new flow.
        worker.handle(&syn_to(dst, port, 9000));
        let raw = output.pop().expect("the retried SYN gets a new SYN-ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(
            seg.flags & (packet::SYN | packet::ACK),
            packet::SYN | packet::ACK
        );
        assert_eq!(seg.ack, 9001);
        assert_eq!(worker.tcp.len(), 1);
        assert_eq!(counters.tcp_flows_active.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_wrong_handshake_ack_resets_and_the_client_can_retry() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let dst = Ipv4Addr::LOCALHOST;
        worker.handle(&syn_to(dst, port, 500));
        let raw = output.pop().expect("the flow gets a SYN-ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let syn_ack = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(syn_ack.ack, 501);
        assert_eq!(worker.tcp.len(), 1);
        // The first ACK acknowledges the server's initial sequence number, not
        // the SYN-ACK. RFC 9293 rejects it in SYN-RECEIVED and resets the
        // half-open flow.
        let bad = packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst,
            sport: 5555,
            dport: port,
            seq: 501,
            ack: syn_ack.seq,
            flags: packet::ACK,
            window: 65535,
            payload: b"early",
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap();
        worker.handle(&bad);
        let raw = output.pop().expect("the half-open flow gets a reset");
        let ip = packet::parse_ip(&raw).unwrap();
        let rst = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(rst.flags & packet::RST, packet::RST);
        assert!(!worker.tcp.contains_key(&flow_key(&bad).unwrap()));
        assert_eq!(value(&counters.tcp_flows_closed), 1);
        // The retried SYN opens a new flow instead of staying blackholed.
        worker.handle(&syn_to(dst, port, 500));
        let raw = output.pop().expect("the retry gets a SYN-ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(
            seg.flags & (packet::SYN | packet::ACK),
            packet::SYN | packet::ACK
        );
        assert_eq!(seg.ack, 501);
        assert_eq!(worker.tcp.len(), 1);
    }

    #[test]
    fn dropped_syn_ack_is_resent_on_the_syn_retransmit() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE {
            assert!(output.push(vec![1]));
        }
        let syn = syn_to(Ipv4Addr::LOCALHOST, port, 500);
        worker.handle(&syn);
        assert_eq!(worker.tcp.len(), 1, "the flow is admitted");
        assert_eq!(value(&counters.send_dropped), 1);
        for _ in 0..QUEUE {
            assert_eq!(output.pop(), Some(vec![1]));
        }
        // The same SYN is a handshake retransmission. The endpoint answers it
        // again, so a dropped SYN-ACK does not blackhole the connection.
        worker.handle(&syn);
        let raw = output.pop().expect("the retransmitted SYN needs a SYN-ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(
            seg.flags & (packet::SYN | packet::ACK),
            packet::SYN | packet::ACK
        );
        assert_eq!(seg.ack, 501);
        assert_eq!(worker.tcp.len(), 1);
        assert_eq!(value(&counters.tcp_flows_closed), 0);
    }

    #[test]
    fn closed_flow_answers_a_retransmitted_fin_with_psh_and_data() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        let mut engine = tcp::TcpFlow::new(100, 200, &[], 65535, now);
        engine.outer_connected();
        engine.outer_end(now);
        engine.actions();
        engine.on_inner(
            &packet::TcpSegment {
                sport: 5555,
                dport: 443,
                seq: 101,
                ack: 202,
                flags: packet::ACK | packet::FIN,
                window: 65535,
                options: &[],
                data: b"tail",
            },
            now,
        );
        // The relay writes the pending upload bytes to the outer socket and
        // then shuts the write side down. The flow closes after both FINs.
        engine.outer_written(4);
        assert_eq!(engine.graceful_close_ack(), Some((202, 106)));
        let key = flow_key(&syn_to(Ipv4Addr::new(203, 0, 113, 9), 443, 0)).unwrap();
        worker.remember_tcp_close(key, &engine, now);
        // A real retransmission repeats the PSH flag and the trailing data.
        let fin = packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst: Ipv4Addr::new(203, 0, 113, 9),
            sport: 5555,
            dport: 443,
            seq: 101,
            ack: 202,
            flags: packet::FIN | packet::ACK | packet::PSH,
            window: 65535,
            payload: b"tail",
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap();
        worker.handle(&fin);
        let raw = output.pop().expect("the duplicate FIN needs an ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let ack = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((ack.flags, ack.seq, ack.ack), (packet::ACK, 202, 106));
        assert_eq!(worker.audit.snapshot(), (0, 0));
    }

    #[test]
    fn psh_fin_retry_recovers_after_a_full_output_queue() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        let key = flow_key(&fin_to(Ipv4Addr::new(203, 0, 113, 9), 101)).unwrap();
        worker.remember_tcp_close(key, &gracefully_closed_flow(now), now);
        for _ in 0..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![1]));
        }
        let raw = packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst: Ipv4Addr::new(203, 0, 113, 9),
            sport: 5555,
            dport: 443,
            seq: 101,
            ack: 202,
            flags: packet::FIN | packet::ACK | packet::PSH,
            window: 65535,
            payload: &[],
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap();
        worker.handle(&raw);
        assert_eq!(value(&counters.send_dropped), 1);
        assert!(output.pop().is_some());
        for _ in 1..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.pop().is_some());
        }
        // The close record is still present, so the next retransmitted FIN
        // gets an ACK after the queue drains.
        worker.handle(&raw);
        let raw = output.pop().expect("the retried FIN needs an ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let ack = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((ack.flags, ack.seq, ack.ack), (packet::ACK, 202, 102));
    }

    #[test]
    fn closed_flow_ignores_a_fin_that_is_not_the_last_segment() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        let key = flow_key(&fin_to(Ipv4Addr::new(203, 0, 113, 9), 101)).unwrap();
        worker.remember_tcp_close(key, &gracefully_closed_flow(now), now);
        for flags in [
            packet::FIN | packet::ACK | packet::SYN,
            packet::FIN | packet::ACK | packet::RST,
        ] {
            let raw = packet::build_tcp(&packet::TcpBuild {
                src: Ipv4Addr::new(198, 18, 0, 2),
                dst: Ipv4Addr::new(203, 0, 113, 9),
                sport: 5555,
                dport: 443,
                seq: 101,
                ack: 202,
                flags,
                window: 65535,
                payload: &[],
                options: &[],
                ttl: 64,
                ident: 0,
            })
            .unwrap();
            worker.handle(&raw);
            assert!(output.pop().is_none(), "flags {flags}");
        }
        // A FIN before the final sequence number is not the duplicate of the
        // closed segment.
        worker.handle(&fin_to(Ipv4Addr::new(203, 0, 113, 9), 99));
        assert!(output.pop().is_none());
        assert!(worker.closed_tcp.contains_key(&key));
    }

    #[test]
    fn close_records_expire_during_a_pump() {
        let counters = Arc::new(Counters::default());
        let (mut worker, _) = test_worker(&counters);
        let now = Instant::now();
        let engine = gracefully_closed_flow(now);
        let mut key = udp_key(1, Ipv4Addr::new(203, 0, 113, 9));
        key.proto = packet::PROTO_TCP;
        worker.remember_tcp_close(
            key,
            &engine,
            now - CLOSED_TCP_LIFETIME - Duration::from_secs(1),
        );
        assert!(worker.closed_tcp.contains_key(&key));
        worker.pump();
        assert!(worker.closed_tcp.is_empty());
    }

    /// The relay key used by the outer socket teardown tests below.
    fn teardown_key() -> Key {
        Key {
            proto: packet::PROTO_TCP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::LOCALHOST.into(),
            sport: 5555,
            dport: 443,
        }
    }

    #[test]
    fn abortive_close_resets_the_outer_stream_with_an_unfinished_upload() {
        let counters = Arc::new(Counters::default());
        let (mut worker, _output) = test_worker(&counters);
        let (client, mut server) = tcp_pair();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let now = Instant::now();
        let mut engine = tcp::TcpFlow::new(100, 200, &[], 65535, now);
        engine.outer_connected();
        engine.actions();
        // The endpoint accepted upload bytes but the relay has not written
        // them to the outer socket yet.
        engine.on_inner(
            &packet::TcpSegment {
                sport: 5555,
                dport: 443,
                seq: 101,
                ack: 201,
                flags: packet::ACK,
                window: 65535,
                options: &[],
                data: b"partial",
            },
            now,
        );
        engine.actions();
        assert_eq!(engine.pending_bytes(), b"partial");
        worker.tcp.insert(
            teardown_key(),
            TcpEntry {
                engine,
                stream: client,
                setup: None,
                was_established: true,
                _gauge: TcpFlowGauge::new(&counters),
            },
        );
        // The inner client resets. The upload is truncated, so the
        // destination must see a reset and not a clean end of stream. The
        // reset carries the next expected byte after the accepted data.
        let rst = packet::build_tcp(&packet::TcpBuild {
            src: Ipv4Addr::new(198, 18, 0, 2),
            dst: Ipv4Addr::LOCALHOST,
            sport: 5555,
            dport: 443,
            seq: 108,
            ack: 201,
            flags: packet::RST | packet::ACK,
            window: 0,
            payload: &[],
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .unwrap();
        worker.handle(&rst);
        assert!(worker.tcp.is_empty());
        assert_eq!(value(&counters.tcp_flows_closed), 1);
        let mut buf = [0u8; 16];
        let error = server
            .read(&mut buf)
            .expect_err("the destination must read a reset, not a clean EOF");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn graceful_close_ends_the_outer_stream_with_a_fin() {
        let counters = Arc::new(Counters::default());
        let (mut worker, _output) = test_worker(&counters);
        let (client, mut server) = tcp_pair();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let now = Instant::now();
        worker.tcp.insert(
            teardown_key(),
            TcpEntry {
                engine: gracefully_closed_flow(now),
                stream: client,
                setup: None,
                was_established: true,
                _gauge: TcpFlowGauge::new(&counters),
            },
        );
        worker.pump();
        assert!(worker.tcp.is_empty());
        let mut buf = [0u8; 16];
        assert_eq!(
            server.read(&mut buf).unwrap(),
            0,
            "a graceful close keeps the normal FIN"
        );
    }

    #[test]
    fn tcp_syn_at_capacity_gets_a_reset_when_no_udp_flow_is_idle() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        for port in 0..MAX_FLOWS_PER_WORKER as u16 {
            let key = udp_key(10_000 + port, Ipv4Addr::new(203, 0, 113, 7));
            worker.udp.insert(key, udp_direct_entry(now));
        }
        let dst = Ipv4Addr::new(203, 0, 113, 9);
        worker.handle(&syn_to(dst, 443, 500));
        assert_eq!(worker.udp.len(), MAX_FLOWS_PER_WORKER);
        assert!(worker.tcp.is_empty());
        assert_eq!(value(&counters.tcp_capacity_refused), 1);
        assert_eq!(value(&counters.flow_errors), 1);
        assert_eq!(value(&counters.udp_flows_evicted), 0);
        // A refused SYN opens no outer socket.
        assert_eq!(worker.audit.snapshot(), (0, 0));
        let raw = output.pop().expect("a refused SYN must get a reset");
        let ip = packet::parse_ip(&raw).unwrap();
        assert_eq!(
            (ip.src, ip.dst),
            (IpAddr::V4(dst), IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)))
        );
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(
            (seg.sport, seg.dport, seg.flags),
            (443, 5555, packet::RST | packet::ACK)
        );
        assert_eq!((seg.seq, seg.ack), (0, 501));
        assert!(seg.data.is_empty());
        assert_eq!(output.pop(), None);
    }

    #[test]
    fn refused_tcp_syn_uses_control_reserve_when_data_queue_is_full() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE {
            assert!(output.push(vec![1]));
        }
        let dst = Ipv4Addr::new(203, 0, 113, 9);
        let syn = syn_to(dst, 443, 500);
        let ip = packet::parse_ip(&syn).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        worker.refuse_tcp(flow_key(&syn).unwrap(), &seg);
        assert_eq!(value(&counters.send_dropped), 0);
        for _ in 0..QUEUE {
            assert_eq!(output.pop(), Some(vec![1]));
        }
        let reset = output.pop().expect("the reset uses the control reserve");
        let ip = packet::parse_ip(&reset).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(seg.flags, packet::RST | packet::ACK);
        assert_eq!(seg.ack, 501);
        assert_eq!(output.pop(), None);
        assert_eq!(worker.audit.snapshot(), (0, 0));
    }

    #[test]
    fn reset_waits_for_queue_space_and_is_retried_once_due() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![1]));
        }
        let syn = syn_to(Ipv4Addr::new(203, 0, 113, 9), 443, 500);
        let ip = packet::parse_ip(&syn).unwrap();
        let segment = packet::parse_tcp(ip.payload).unwrap();
        let key = flow_key(&syn).unwrap();
        worker.refuse_tcp(key, &segment);
        assert_eq!(worker.pending_resets.len(), 1);
        assert_eq!(value(&counters.send_dropped), 1);
        let due = worker.pending_resets[&key].next_attempt;
        assert_eq!(output.pop(), Some(vec![1]));
        worker.retry_resets(due - Duration::from_millis(1));
        assert_eq!(worker.pending_resets.len(), 1);
        worker.retry_resets(due);
        assert!(worker.pending_resets.is_empty());
        assert_eq!(value(&counters.packets_out), 1);
        assert_eq!(value(&counters.tcp_resets_lost), 0);
        for _ in 1..QUEUE + TCP_CONTROL_RESERVE {
            assert_eq!(output.pop(), Some(vec![1]));
        }
        let raw = output.pop().unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        let segment = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(segment.flags, packet::RST | packet::ACK);
        assert_eq!(segment.ack, 501);
    }

    #[test]
    fn reset_retries_are_bounded_when_the_output_stays_full() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![1]));
        }
        let key = udp_key(1234, Ipv4Addr::new(203, 0, 113, 9));
        let now = Instant::now();
        assert!(!worker.output_reset(key, vec![2], now));
        worker.retry_resets(now + RESET_RETRY);
        assert_eq!(worker.pending_resets.len(), 1);
        worker.retry_resets(now + RESET_RETRY * 2);
        assert!(worker.pending_resets.is_empty());
        assert_eq!(value(&counters.send_dropped), 3);
        assert_eq!(value(&counters.tcp_resets_lost), 1);
    }

    #[test]
    fn retained_resets_have_a_fixed_capacity() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![1]));
        }
        let now = Instant::now();
        for port in 0..=MAX_PENDING_RESETS {
            let key = udp_key(port as u16, Ipv4Addr::new(203, 0, 113, 9));
            assert!(!worker.output_reset(key, vec![2], now + Duration::from_millis(port as u64)));
        }
        assert_eq!(worker.pending_resets.len(), MAX_PENDING_RESETS);
        assert!(!worker
            .pending_resets
            .contains_key(&udp_key(0, Ipv4Addr::new(203, 0, 113, 9))));
        assert_eq!(value(&counters.tcp_resets_lost), 1);
    }

    #[test]
    fn new_tcp_flow_discards_a_reset_from_a_previous_use_of_the_tuple() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        for _ in 0..QUEUE + TCP_CONTROL_RESERVE {
            assert!(output.push_tcp_control(vec![1]));
        }
        let syn = syn_to(Ipv4Addr::LOCALHOST, port, 500);
        let key = flow_key(&syn).unwrap();
        assert!(!worker.output_reset(key, vec![2], Instant::now()));
        worker.handle(&syn);
        assert!(worker.tcp.contains_key(&key));
        assert!(!worker.pending_resets.contains_key(&key));
        assert_eq!(value(&counters.tcp_resets_lost), 0);
    }

    #[test]
    fn refused_ipv6_syn_gets_a_reset_with_the_same_rules() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        for port in 0..MAX_FLOWS_PER_WORKER as u16 {
            let key = udp_key(40_000 + port, Ipv4Addr::new(203, 0, 113, 7));
            worker.udp.insert(key, udp_direct_entry(now));
        }
        let src: IpAddr = "fd00::2".parse().unwrap();
        let dst: IpAddr = "2001:db8::9".parse().unwrap();
        let (IpAddr::V6(src6), IpAddr::V6(dst6)) = (src, dst) else {
            unreachable!()
        };
        let syn = packet::build_tcp_v6(&packet::TcpBuildV6 {
            src: src6,
            dst: dst6,
            sport: 5555,
            dport: 443,
            seq: 900,
            ack: 0,
            flags: packet::SYN,
            window: 65535,
            payload: &[],
            options: &[],
            hop_limit: 64,
        })
        .unwrap();
        worker.handle(&syn);
        assert!(worker.tcp.is_empty());
        assert_eq!(value(&counters.tcp_capacity_refused), 1);
        let raw = output.pop().expect("a refused IPv6 SYN must get a reset");
        let ip = packet::parse_ip(&raw).unwrap();
        assert_eq!((ip.src, ip.dst), (dst, src));
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((seg.sport, seg.dport), (443, 5555));
        assert_eq!(seg.flags, packet::RST | packet::ACK);
        assert_eq!((seg.seq, seg.ack), (0, 901));
    }

    #[test]
    fn tcp_syn_at_capacity_evicts_one_idle_udp_flow_and_connects() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut data = [0u8; 5];
            s.read_exact(&mut data).unwrap();
            s.write_all(&data).unwrap();
        });
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let now = Instant::now();
        // Fill the table with live UDP flows.
        for port in 0..(MAX_FLOWS_PER_WORKER - 2) as u16 {
            let key = udp_key(20_000 + port, Ipv4Addr::new(203, 0, 113, 7));
            worker.udp.insert(key, udp_direct_entry(now));
        }
        // This flow is old but still holds queued data. It must keep its slot.
        let (client, _peer) = tcp_pair();
        let mut frames = UdpFrameQueue::new();
        frames.push(5, now - Duration::from_secs(120));
        let busy_key = udp_key(30_001, Ipv4Addr::new(203, 0, 113, 8));
        worker.udp.insert(
            busy_key,
            UdpEntry {
                socket: UdpSocketKind::Phone {
                    stream: client,
                    incoming: Vec::new(),
                    outgoing: vec![0, 3, b'a', b'b', b'c'],
                    frames,
                    dns: false,
                    setup: None,
                },
                last: now - Duration::from_secs(60),
                dns_query_id: None,
                dns_started: None,
            },
        );
        // This flow is idle with no pending work. It yields the free slot.
        let idle_key = udp_key(30_002, Ipv4Addr::new(203, 0, 113, 10));
        worker.udp.insert(
            idle_key,
            udp_direct_entry(now - UDP_EVICT_IDLE - Duration::from_secs(1)),
        );
        assert_eq!(worker.udp.len(), MAX_FLOWS_PER_WORKER);
        worker.handle(&syn_to(Ipv4Addr::LOCALHOST, port, 700));
        assert!(worker.tcp.contains_key(&Key {
            proto: packet::PROTO_TCP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::LOCALHOST.into(),
            sport: 5555,
            dport: port,
        }));
        assert_eq!(worker.udp.len(), MAX_FLOWS_PER_WORKER - 1);
        assert!(!worker.udp.contains_key(&idle_key));
        assert!(worker.udp.contains_key(&busy_key));
        assert_eq!(value(&counters.udp_flows_evicted), 1);
        assert_eq!(value(&counters.udp_flows_closed), 1);
        assert_eq!(
            counters
                .timeline
                .snapshot(Instant::now())
                .iter()
                .map(|bucket| bucket.udp_teardowns)
                .sum::<u64>(),
            1,
            "an evicted UDP flow is a teardown"
        );
        assert_eq!(value(&counters.tcp_capacity_refused), 0);
        assert_eq!(value(&counters.flow_errors), 0);
        assert_eq!(worker.audit.snapshot(), (1, 0));
        let raw = output.pop().expect("the admitted SYN gets a SYN-ACK");
        let ip = packet::parse_ip(&raw).unwrap();
        let seg = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!(seg.flags, packet::SYN | packet::ACK);
        assert_eq!(seg.ack, 701);
        let server_seq = seg.seq;
        // The client completes the handshake and the flow carries data.
        worker.handle(
            &packet::build_tcp(&packet::TcpBuild {
                src: Ipv4Addr::new(198, 18, 0, 2),
                dst: Ipv4Addr::LOCALHOST,
                sport: 5555,
                dport: port,
                seq: 701,
                ack: server_seq.wrapping_add(1),
                flags: packet::ACK,
                window: 65535,
                payload: b"hello",
                options: &[],
                ttl: 64,
                ident: 0,
            })
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut echoed = false;
        while Instant::now() < deadline && !echoed {
            worker.pump();
            while let Some(raw) = output.pop() {
                let ip = packet::parse_ip(&raw).unwrap();
                if let Some(seg) = packet::parse_tcp(ip.payload) {
                    if seg.data == b"hello" {
                        echoed = true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(echoed, "the admitted flow must carry data");
        assert_eq!(value(&counters.udp_flows_evicted), 1);
        drop(worker);
        server.join().unwrap();
    }

    #[test]
    fn only_idle_udp_flows_without_pending_work_are_evictable() {
        let now = Instant::now();
        let idle = now - UDP_EVICT_IDLE - Duration::from_millis(1);
        assert!(!Worker::evictable(&udp_direct_entry(now), now));
        assert!(Worker::evictable(&udp_direct_entry(idle), now));
        let mut pending_dns = udp_direct_entry(idle);
        pending_dns.dns_query_id = Some([0x12, 0x34]);
        assert!(!Worker::evictable(&pending_dns, now));
        let (client, _peer) = tcp_pair();
        let phone = |outgoing: Vec<u8>, frames: UdpFrameQueue, setup: Option<Setup>| UdpEntry {
            socket: UdpSocketKind::Phone {
                stream: client.try_clone().unwrap(),
                incoming: Vec::new(),
                outgoing,
                frames,
                dns: false,
                setup,
            },
            last: idle,
            dns_query_id: None,
            dns_started: None,
        };
        assert!(Worker::evictable(
            &phone(Vec::new(), UdpFrameQueue::new(), None),
            now
        ));
        let mut frames = UdpFrameQueue::new();
        frames.push(5, idle);
        assert!(!Worker::evictable(
            &phone(vec![0, 3, b'a', b'b', b'c'], frames, None),
            now
        ));
        assert!(!Worker::evictable(
            &phone(Vec::new(), UdpFrameQueue::new(), Some(Setup::direct())),
            now
        ));
        let mut partial = phone(Vec::new(), UdpFrameQueue::new(), None);
        if let UdpSocketKind::Phone { incoming, .. } = &mut partial.socket {
            incoming.push(1);
        }
        assert!(!Worker::evictable(&partial, now));
    }

    #[test]
    fn evicts_the_oldest_eligible_udp_flow() {
        let counters = Arc::new(Counters::default());
        let (mut worker, _) = test_worker(&counters);
        let now = Instant::now();
        let older = udp_key(31001, Ipv4Addr::new(203, 0, 113, 9));
        let newer = udp_key(31002, Ipv4Addr::new(203, 0, 113, 9));
        worker
            .udp
            .insert(older, udp_direct_entry(now - Duration::from_secs(60)));
        worker
            .udp
            .insert(newer, udp_direct_entry(now - Duration::from_secs(40)));
        assert!(worker.evict_idle_udp(now));
        assert!(!worker.udp.contains_key(&older));
        assert!(worker.udp.contains_key(&newer));
    }

    #[test]
    fn refused_syn_acknowledges_payload_across_sequence_wrap() {
        let counters = Arc::new(Counters::default());
        let (mut worker, output) = test_worker(&counters);
        let key = Key {
            proto: packet::PROTO_TCP,
            src: Ipv4Addr::new(198, 18, 0, 2).into(),
            dst: Ipv4Addr::new(203, 0, 113, 9).into(),
            sport: 5555,
            dport: 443,
        };
        let seg = packet::TcpSegment {
            sport: 5555,
            dport: 443,
            seq: u32::MAX,
            ack: 0,
            flags: packet::SYN,
            window: 65535,
            options: &[],
            data: b"abc",
        };
        worker.refuse_tcp(key, &seg);
        let raw = output.pop().unwrap();
        let ip = packet::parse_ip(&raw).unwrap();
        let reply = packet::parse_tcp(ip.payload).unwrap();
        assert_eq!((reply.flags, reply.ack), (packet::RST | packet::ACK, 3));
        assert_eq!(worker.audit.snapshot(), (0, 0));
    }
}
