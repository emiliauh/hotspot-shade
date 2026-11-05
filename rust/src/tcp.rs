//! The inner TCP endpoint. The caller owns the outer socket and the clock.
use crate::packet::{self, TcpSegment};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const MSS_INNER: usize = 1400;
pub const DEFAULT_PEER_MSS: usize = 536;
pub const RCV_WINDOW: u16 = 65535;
pub const MAX_PENDING_CLIENT: usize = 256 * 1024;
pub const MAX_INFLIGHT: usize = 256 * 1024;
pub const OUTBUF_HIGH_WATER: usize = 512 * 1024;
pub const OUTBUF_LOW_WATER: usize = 256 * 1024;
pub const OUTBUF_HARD_LIMIT: usize = 2 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// A silent established flow is not a dead flow. After this long without
/// traffic in either direction, probe the inner peer.
const IDLE_PROBE_AFTER: Duration = Duration::from_secs(600);
/// The wait for an answer to one idle probe.
const IDLE_PROBE_INTERVAL: Duration = Duration::from_secs(60);
/// The count of unanswered idle probes before the flow resets.
const MAX_IDLE_PROBES: u8 = 3;
const RTO_MIN: Duration = Duration::from_millis(300);
const RTO_MAX: Duration = Duration::from_secs(2);
const MAX_RETX: u8 = 12;
// Retry a locally rejected timer packet without treating it as peer loss.
const OUTPUT_RETRY: Duration = Duration::from_millis(250);
/// The wait before the first zero-window probe. RFC 9293, Section 3.8.6.1,
/// uses the retransmission timeout for the first probe.
const PERSIST_MIN: Duration = RTO_MIN;
/// The largest wait between zero-window probes. The wait doubles after each
/// probe up to this value. The bound keeps the probe rate low when a reader
/// stays paused for a long time.
const PERSIST_MAX: Duration = Duration::from_secs(60);
/// The count of unanswered zero-window probes before the flow resets. The
/// peer clears the count with any inner segment. RFC 9293, Section 3.8.6.1,
/// requires the flow to stay open while the peer answers probes.
const MAX_PERSIST_PROBES: u8 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Connecting,
    Established,
    Closed,
}

/// Timer state to restore when the relay cannot queue a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendAccounting {
    None,
    IdleProbe {
        previous_at: Option<Instant>,
    },
    PersistProbe {
        previous_at: Option<Instant>,
        previous_interval: Duration,
    },
    Retransmit {
        previous_at: Instant,
        previous_rto: Duration,
    },
    FinRetransmit {
        previous_at: Instant,
        previous_rto: Duration,
    },
}

/// An action is consumed by the relay that owns the outer socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send {
        accounting: SendAccounting,
        flags: u8,
        seq: u32,
        ack: u32,
        window: u16,
        options: Vec<u8>,
        data: Vec<u8>,
    },
    ShutdownWrite,
    Close,
}

/// Parse a SYN option list. Ignore malformed trailing options.
pub fn parse_tcp_options(options: &[u8]) -> (Option<u16>, Option<u8>) {
    let (mut mss, mut scale, mut i) = (None, None, 0);
    while i < options.len() {
        let kind = options[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        if len < 2 || i + len > options.len() {
            break;
        }
        if kind == 2 && len == 4 {
            mss = Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
        }
        if kind == 3 && len == 3 {
            scale = Some(options[i + 2]);
        }
        i += len;
    }
    (mss, scale)
}

/// True when `a` comes before `b` in the 32-bit sequence space. The distance
/// between the two values must be less than 2^31, which holds for a TCP
/// window.
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// True when `a` comes before `b` or equals it in the 32-bit sequence space.
fn seq_at_or_before(a: u32, b: u32) -> bool {
    a == b || seq_before(a, b)
}

pub struct TcpFlow {
    pub state: State,
    client_isn: u32,
    inner_handshake_complete: bool,
    graceful_close: bool,
    /// A source device flow holds the inner SYN-ACK until the outer connect
    /// completes. The inner client must not see a connected socket before then.
    start_held: bool,
    pub cseq: u32,
    pub send_mss: usize,
    pub peer_window: usize,
    /// The sequence number of the segment that last updated `peer_window`
    /// (SND.WL1).
    window_seq: u32,
    /// The acknowledgment number of the segment that last updated
    /// `peer_window` (SND.WL2).
    window_ack: u32,
    pub read_paused: bool,
    pub client_fin: bool,
    pub outer_eof: bool,
    pub outer_write_shutdown: bool,
    pub isn: u32,
    pub sent_data: u64,
    pub acked_data: u64,
    outbuf: VecDeque<u8>,
    unacked: VecDeque<u8>,
    pending: VecDeque<u8>,
    fin_sent_seq: Option<u32>,
    fin_sent_at: Option<Instant>,
    fin_acked: bool,
    created: Instant,
    last_activity: Instant,
    /// The unanswered idle probes. Any inner segment clears the count.
    idle_probes: u8,
    /// The time of the last idle probe. `None` means no probe is outstanding.
    idle_probe_at: Option<Instant>,
    /// The start of the current zero-window block, or the time of the last
    /// zero-window probe.
    persist_at: Option<Instant>,
    /// The wait before the next zero-window probe.
    persist_interval: Duration,
    /// The zero-window probes with no answer. Any inner segment clears it.
    persist_probes: u8,
    last_ack_progress: Instant,
    rto: Duration,
    retx: u8,
    output_retry_at: Option<Instant>,
    advertised_window: u16,
    actions: Vec<Action>,
    metric_ack_start: Option<Instant>,
    metric_ack_samples: u64,
    metric_ack_sum_us: u64,
    metric_ack_max_us: u64,
    metric_retransmits: u64,
    metric_last: Instant,
    metric_limited: bool,
    metric_upload_peak: usize,
    metric_download_peak: usize,
}

#[derive(Default)]
pub struct TcpMetrics {
    pub ack_samples: u64,
    pub ack_sum_us: u64,
    pub ack_max_us: u64,
    pub retransmits: u64,
    pub window_limited_us: u64,
    pub upload_peak: usize,
    pub download_peak: usize,
}

impl TcpFlow {
    /// `isn` must come from the caller's random number source.
    pub fn new(client_isn: u32, isn: u32, options: &[u8], window: u16, now: Instant) -> Self {
        let (mss, _) = parse_tcp_options(options);
        Self {
            state: State::Connecting,
            client_isn,
            inner_handshake_complete: false,
            graceful_close: false,
            start_held: false,
            cseq: client_isn.wrapping_add(1),
            send_mss: mss
                .filter(|v| *v != 0)
                .map_or(DEFAULT_PEER_MSS, |v| (v as usize).min(MSS_INNER)),
            peer_window: window as usize,
            // The window came from the SYN. Its sequence number is the client
            // ISN, and its ACK acknowledges our SYN at isn + 1.
            window_seq: client_isn,
            window_ack: isn.wrapping_add(1),
            read_paused: false,
            client_fin: false,
            outer_eof: false,
            outer_write_shutdown: false,
            isn,
            sent_data: 0,
            acked_data: 0,
            outbuf: VecDeque::new(),
            unacked: VecDeque::new(),
            pending: VecDeque::new(),
            fin_sent_seq: None,
            fin_sent_at: None,
            fin_acked: false,
            created: now,
            last_activity: now,
            idle_probes: 0,
            idle_probe_at: None,
            persist_at: None,
            persist_interval: PERSIST_MIN,
            persist_probes: 0,
            last_ack_progress: now,
            rto: RTO_MIN,
            retx: 0,
            output_retry_at: None,
            advertised_window: RCV_WINDOW,
            actions: Vec::new(),
            metric_ack_start: None,
            metric_ack_samples: 0,
            metric_ack_sum_us: 0,
            metric_ack_max_us: 0,
            metric_retransmits: 0,
            metric_last: now,
            metric_limited: false,
            metric_upload_peak: 0,
            metric_download_peak: 0,
        }
    }
    pub fn start(&mut self) {
        self.start_held = false;
        self.send(
            packet::SYN | packet::ACK,
            self.isn,
            self.cseq,
            RCV_WINDOW,
            packet::mss_option(MSS_INNER as u16).to_vec(),
            Vec::new(),
        );
    }
    /// Hold the inner SYN-ACK until the caller releases it.
    pub fn hold_start(&mut self) {
        if self.state == State::Connecting {
            self.start_held = true;
        }
    }
    /// Send the held SYN-ACK. Do nothing when no start is held.
    pub fn release_start(&mut self) {
        if self.start_held {
            self.start();
        }
    }
    pub fn start_held(&self) -> bool {
        self.start_held
    }
    pub fn next_seq(&self) -> u32 {
        self.isn
            .wrapping_add(1)
            .wrapping_add(self.sent_data as u32)
            .wrapping_add(u32::from(self.fin_sent_seq.is_some()))
    }
    /// Return the final ACK numbers only for a fully drained graceful close.
    pub(crate) fn graceful_close_ack(&self) -> Option<(u32, u32)> {
        (self.state == State::Closed && self.graceful_close).then(|| (self.next_seq(), self.cseq))
    }
    pub fn inflight(&self) -> usize {
        (self.sent_data - self.acked_data) as usize
    }
    pub fn actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }
    /// Sample aggregate measurements without changing TCP behavior.
    pub fn take_metrics(&mut self, now: Instant) -> TcpMetrics {
        let elapsed = now
            .saturating_duration_since(self.metric_last)
            .as_micros()
            .min(u64::MAX as u128) as u64;
        self.metric_last = now;
        let limited = if self.metric_limited { elapsed } else { 0 };
        self.metric_limited = self.state != State::Closed
            && !self.outbuf.is_empty()
            && self.inflight() >= self.peer_window.min(MAX_INFLIGHT);
        TcpMetrics {
            ack_samples: std::mem::take(&mut self.metric_ack_samples),
            ack_sum_us: std::mem::take(&mut self.metric_ack_sum_us),
            ack_max_us: std::mem::take(&mut self.metric_ack_max_us),
            retransmits: std::mem::take(&mut self.metric_retransmits),
            window_limited_us: limited,
            upload_peak: std::mem::take(&mut self.metric_upload_peak),
            download_peak: std::mem::take(&mut self.metric_download_peak),
        }
    }
    /// Read pending app bytes, write some to the outer socket, and call `outer_written`.
    pub fn pending_bytes(&mut self) -> &[u8] {
        self.pending.make_contiguous()
    }
    pub fn outer_written(&mut self, count: usize) {
        let count = count.min(self.pending.len());
        self.pending.drain(..count);
        let window = self.receive_window();
        // Reopen credit after a partial write. Do not wait for an empty buffer.
        if window.saturating_sub(self.advertised_window) as usize >= MSS_INNER {
            self.ctrl(packet::ACK, window);
        }
        if self.pending.is_empty()
            && self.client_fin
            && !self.outer_write_shutdown
            && self.state == State::Established
        {
            self.outer_write_shutdown = true;
            self.actions.push(Action::ShutdownWrite);
        }
        // The last queued upload byte can drain after both FINs. Close here so
        // that the flow does not wait for another inner segment.
        self.maybe_close();
    }
    pub fn outer_connected(&mut self) {
        if self.state != State::Connecting {
            return;
        }
        self.state = State::Established;
        self.outer_written(0);
    }
    pub fn outer_failed(&mut self) {
        self.abort();
    }
    pub fn outer_data(&mut self, data: &[u8], now: Instant) {
        if self.state == State::Closed || self.outer_eof {
            return;
        }
        if self.outbuf.len().saturating_add(data.len()) > OUTBUF_HARD_LIMIT {
            self.abort();
            return;
        }
        self.outbuf.extend(data);
        self.metric_download_peak = self.metric_download_peak.max(self.outbuf.len());
        if self.outbuf.len() >= OUTBUF_HIGH_WATER {
            self.read_paused = true;
        }
        self.emit(now);
        self.note_activity(now);
    }
    pub fn outer_end(&mut self, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        self.outer_eof = true;
        self.maybe_fin(now);
        self.note_activity(now);
    }
    pub fn on_inner(&mut self, seg: &TcpSegment<'_>, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        if seg.flags & packet::RST != 0 {
            if seg.seq == self.cseq {
                self.close();
            } else if seg.seq.wrapping_sub(self.cseq) < u32::from(self.receive_window()) {
                // An in-window reset at the wrong sequence needs a challenge.
                self.ctrl(packet::ACK, self.receive_window());
            }
            return;
        }
        if seg.flags & packet::SYN != 0 {
            if seg.seq != self.client_isn || self.inner_handshake_complete {
                // Do not acknowledge a new SYN using the old sequence space.
                // The client can reset the stale flow and retry the SYN.
                self.ctrl(packet::ACK, self.receive_window());
                return;
            }
            self.persist_probes = 0;
            self.note_activity(now);
            // A duplicate SYN is a retransmit. Do not answer it and do not
            // start another outer connection while the first one is pending.
            if self.start_held {
                return;
            }
            self.send(
                packet::SYN | packet::ACK,
                self.isn,
                seg.seq.wrapping_add(1),
                self.receive_window(),
                packet::mss_option(MSS_INNER as u16).to_vec(),
                Vec::new(),
            );
            return;
        }
        if self.start_held {
            // The inner client cannot send data before the SYN-ACK. Ignore it.
            return;
        }
        if seg.flags & packet::ACK == 0 {
            return;
        }
        if !self.on_ack(seg.ack, seg.window, seg.seq, now) {
            // The ACK is beyond SND.NXT. Drop the whole segment.
            return;
        }
        if self.state == State::Closed {
            return;
        }
        self.inner_handshake_complete = true;
        self.persist_probes = 0;
        self.note_activity(now);
        if !seg.data.is_empty() {
            let offset = self.cseq.wrapping_sub(seg.seq) as usize;
            if !self.client_fin && offset < seg.data.len() {
                // A retransmit can contain an accepted prefix and new bytes.
                let fresh = &seg.data[offset..];
                let count = fresh.len().min(MAX_PENDING_CLIENT - self.pending.len());
                self.pending.extend(&fresh[..count]);
                self.metric_upload_peak = self.metric_upload_peak.max(self.pending.len());
                self.cseq = self.cseq.wrapping_add(count as u32);
            }
            self.ctrl(packet::ACK, self.receive_window());
        } else if seg.flags & packet::ACK != 0
            && seg.flags & (packet::SYN | packet::FIN | packet::RST) == 0
            && seg.seq == self.cseq.wrapping_sub(1)
        {
            // A TCP keepalive probe carries the sequence number before the next
            // expected byte and no data. The peer needs an ACK, or it resets an
            // idle connection. Remote desktop and terminal sessions depend on
            // this. A normal ACK uses the next expected byte and gets no answer.
            self.ctrl(packet::ACK, self.receive_window());
        }
        if seg.flags & packet::FIN != 0 {
            if self.client_fin {
                self.ctrl(packet::ACK, self.receive_window());
            } else if seg.seq.wrapping_add(seg.data.len() as u32) == self.cseq {
                self.cseq = self.cseq.wrapping_add(1);
                self.client_fin = true;
                self.ctrl(packet::ACK, self.receive_window());
                self.outer_written(0);
                self.maybe_fin(now);
                self.maybe_close();
            }
        }
    }
    pub fn tick(&mut self, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        if self.state == State::Connecting
            && now.saturating_duration_since(self.created) > CONNECT_TIMEOUT
        {
            self.abort();
            return;
        }
        // Send a FIN that became ready after the last outer write drained.
        // A flow can also become window-blocked without a new inner segment,
        // for example when outer data arrives before the outer connect
        // completes. Arm the probe timer on the first tick.
        self.maybe_fin(now);
        self.sync_persist(now);
        if self.output_retry_at.is_some_and(|at| now < at) {
            return;
        }
        self.output_retry_at = None;
        let zero_window_blocked = self.zero_window_blocked();
        if zero_window_blocked {
            // RFC 9293, Section 3.8.6.1. A zero window is backpressure, not
            // proof that the peer is gone. Probe the window. Do not
            // retransmit data into it. Do not count the probes as data
            // retransmissions.
            if self.persist_due(now) {
                self.send_persist_probe(now);
            }
        } else if self.inflight() > 0
            && now.saturating_duration_since(self.last_ack_progress) > self.rto
        {
            self.metric_ack_start = None;
            if self.retx >= MAX_RETX {
                self.abort();
                return;
            }
            // Retransmit only the bytes in the current window. A peer can
            // shrink its window after it accepted the data.
            let count = self.send_mss.min(self.peer_window);
            let data: Vec<u8> = self.unacked.iter().take(count).copied().collect();
            if !data.is_empty() {
                let seq = self
                    .isn
                    .wrapping_add(1)
                    .wrapping_add(self.acked_data as u32);
                self.send(
                    packet::ACK | packet::PSH,
                    seq,
                    self.cseq,
                    self.receive_window(),
                    Vec::new(),
                    data,
                );
                self.account_last_send(SendAccounting::Retransmit {
                    previous_at: self.last_ack_progress,
                    previous_rto: self.rto,
                });
            }
            self.retx += 1;
            self.metric_retransmits += 1;
            self.last_ack_progress = now;
            self.rto = (self.rto * 2).min(RTO_MAX);
        } else if let (Some(seq), Some(at)) = (self.fin_sent_seq, self.fin_sent_at) {
            if !self.fin_acked && now.saturating_duration_since(at) > self.rto {
                if self.retx >= MAX_RETX {
                    // The peer stopped answering the FIN. Reset the inner flow
                    // instead of removing it with no signal.
                    self.abort();
                    return;
                }
                // A FIN occupies one sequence number. Send it only when the
                // window has room for it. The persist probe covers a zero
                // window.
                if self.inflight() < self.peer_window {
                    self.send(
                        packet::ACK | packet::FIN,
                        seq,
                        self.cseq,
                        self.receive_window(),
                        Vec::new(),
                        Vec::new(),
                    );
                    self.account_last_send(SendAccounting::FinRetransmit {
                        previous_at: at,
                        previous_rto: self.rto,
                    });
                    self.fin_sent_at = Some(now);
                    self.retx += 1;
                    self.metric_retransmits += 1;
                    self.rto = (self.rto * 2).min(RTO_MAX);
                }
            }
        }
        // The probe check is separate. A flow that already sent and acked its
        // FIN also needs idle probes when the peer goes silent.
        if !zero_window_blocked && self.idle_probe_due(now) {
            self.probe_idle_peer(now);
        }
    }
    /// A silent established flow is not a dead flow. Probe it after a long
    /// silence. A live peer answers the probe with an ACK.
    fn idle_probe_due(&self, now: Instant) -> bool {
        if self.state != State::Established || self.start_held {
            return false;
        }
        if self.inflight() > 0 || (self.fin_sent_seq.is_some() && !self.fin_acked) {
            return false;
        }
        // A zero peer window with queued work uses the persist probes below.
        // A zero window with no work still needs a bounded liveness check.
        // A responsive paused reader answers each probe and stays open.
        if self.peer_window == 0 && self.persist_pending() {
            return false;
        }
        if now.saturating_duration_since(self.last_activity) < IDLE_PROBE_AFTER {
            return false;
        }
        self.idle_probe_at
            .is_none_or(|at| now.saturating_duration_since(at) >= IDLE_PROBE_INTERVAL)
    }
    /// Send one keepalive probe to the inner peer. Keepalive is not application
    /// traffic. Any inner segment answers it and clears the count. After
    /// `MAX_IDLE_PROBES` unanswered probes, reset the flow. The reset frees the
    /// flow slot of a peer that is gone.
    fn probe_idle_peer(&mut self, now: Instant) {
        if self.idle_probes >= MAX_IDLE_PROBES {
            self.abort();
            return;
        }
        let seq = self.next_seq().wrapping_sub(1);
        self.send(
            packet::ACK,
            seq,
            self.cseq,
            self.receive_window(),
            Vec::new(),
            Vec::new(),
        );
        self.account_last_send(SendAccounting::IdleProbe {
            previous_at: self.idle_probe_at,
        });
        self.idle_probes += 1;
        self.idle_probe_at = Some(now);
    }
    /// Work that a zero peer window holds back: unacknowledged data, queued
    /// outer bytes, or a FIN that needs one sequence number.
    fn persist_pending(&self) -> bool {
        self.inflight() > 0
            || !self.outbuf.is_empty()
            || (self.outer_eof && self.fin_sent_seq.is_none())
            || (self.fin_sent_seq.is_some() && !self.fin_acked)
    }
    /// A zero peer window with work to send. The flow probes the window.
    fn zero_window_blocked(&self) -> bool {
        self.state == State::Established
            && !self.start_held
            && self.peer_window == 0
            && self.persist_pending()
    }
    fn persist_due(&self, now: Instant) -> bool {
        self.persist_at
            .is_some_and(|at| now.saturating_duration_since(at) >= self.persist_interval)
    }
    /// Start, continue, or clear the zero-window probe timer.
    fn sync_persist(&mut self, now: Instant) {
        if self.zero_window_blocked() {
            if self.persist_at.is_none() {
                // RFC 9293, Section 3.8.6.1: the first probe waits one
                // retransmission timeout. Later probes back off.
                self.persist_at = Some(now);
                self.persist_interval = PERSIST_MIN;
                // The wait is not a round-trip measurement.
                self.metric_ack_start = None;
            }
        } else {
            self.persist_at = None;
            self.persist_interval = PERSIST_MIN;
            self.persist_probes = 0;
        }
    }
    /// Send a zero-window probe. The probe is a zero-length segment at
    /// SND.UNA - 1. It uses no sequence space, so it does not change byte
    /// accounting. RFC 9293, Section 3.8.6.1, requires a zero-window receiver
    /// to answer any segment with its current window. The peer must answer.
    fn send_persist_probe(&mut self, now: Instant) {
        if self.persist_probes >= MAX_PERSIST_PROBES {
            // The peer answered no probe. The reset tells the inner peer that
            // the flow is gone. It is not a silent removal.
            self.abort();
            return;
        }
        // SND.UNA is isn + 1 + acked_data. The probe carries SND.UNA - 1.
        let seq = self.isn.wrapping_add(self.acked_data as u32);
        self.send(
            packet::ACK,
            seq,
            self.cseq,
            self.receive_window(),
            Vec::new(),
            Vec::new(),
        );
        self.account_last_send(SendAccounting::PersistProbe {
            previous_at: self.persist_at,
            previous_interval: self.persist_interval,
        });
        self.persist_probes += 1;
        self.persist_at = Some(now);
        self.persist_interval = (self.persist_interval * 2).min(PERSIST_MAX);
    }
    /// Record real traffic. A keepalive probe that this endpoint sends does not
    /// count as traffic.
    fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
        self.idle_probes = 0;
        self.idle_probe_at = None;
    }
    fn send(
        &mut self,
        flags: u8,
        seq: u32,
        ack: u32,
        window: u16,
        options: Vec<u8>,
        data: Vec<u8>,
    ) {
        self.advertised_window = window;
        self.actions.push(Action::Send {
            accounting: SendAccounting::None,
            flags,
            seq,
            ack,
            window,
            options,
            data,
        });
    }
    fn account_last_send(&mut self, value: SendAccounting) {
        if let Some(Action::Send { accounting, .. }) = self.actions.last_mut() {
            *accounting = value;
        }
    }
    /// Restore timer state when the relay rejects a generated packet.
    /// The sequence space and buffered bytes remain unchanged.
    pub fn output_rejected(&mut self, accounting: SendAccounting, now: Instant) {
        match accounting {
            SendAccounting::None => return,
            SendAccounting::IdleProbe { previous_at } => {
                self.idle_probes = self.idle_probes.saturating_sub(1);
                self.idle_probe_at = previous_at;
            }
            SendAccounting::PersistProbe {
                previous_at,
                previous_interval,
            } => {
                self.persist_probes = self.persist_probes.saturating_sub(1);
                self.persist_at = previous_at;
                self.persist_interval = previous_interval;
            }
            SendAccounting::Retransmit {
                previous_at,
                previous_rto,
            } => {
                self.retx = self.retx.saturating_sub(1);
                self.metric_retransmits = self.metric_retransmits.saturating_sub(1);
                self.last_ack_progress = previous_at;
                self.rto = previous_rto;
            }
            SendAccounting::FinRetransmit {
                previous_at,
                previous_rto,
            } => {
                self.retx = self.retx.saturating_sub(1);
                self.metric_retransmits = self.metric_retransmits.saturating_sub(1);
                self.fin_sent_at = Some(previous_at);
                self.rto = previous_rto;
            }
        }
        self.output_retry_at = now.checked_add(OUTPUT_RETRY);
    }
    fn receive_window(&self) -> u16 {
        (MAX_PENDING_CLIENT - self.pending.len()).min(RCV_WINDOW as usize) as u16
    }
    fn ctrl(&mut self, flags: u8, window: u16) {
        self.send(
            flags,
            self.next_seq(),
            self.cseq,
            window,
            Vec::new(),
            Vec::new(),
        );
    }
    fn close(&mut self) {
        if self.state != State::Closed {
            self.state = State::Closed;
            self.persist_at = None;
            self.persist_probes = 0;
            self.actions.push(Action::Close);
        }
    }
    fn abort(&mut self) {
        if self.state != State::Closed {
            self.ctrl(packet::RST | packet::ACK, 0);
            self.close();
        }
    }
    /// Apply one ACK and window update. Return false when the ACK is beyond
    /// SND.NXT. The caller must drop the rest of that segment.
    fn on_ack(&mut self, ack: u32, window: u16, seq: u32, now: Instant) -> bool {
        let una = self
            .isn
            .wrapping_add(1)
            .wrapping_add(self.acked_data as u32);
        let nxt = self.next_seq();
        if seq_before(nxt, ack) {
            // The peer acknowledges data that was never sent. RFC 9293,
            // Section 3.10.7.4: send an ACK, drop the segment, and return.
            // Do not advance SND.UNA and do not acknowledge the FIN.
            self.ctrl(packet::ACK, self.receive_window());
            return false;
        }
        let inflight_before = self.inflight();
        if seq_before(una, ack) {
            // The ACK is acceptable: SND.UNA < SEG.ACK <= SND.NXT.
            let n = (ack.wrapping_sub(una) as usize).min(inflight_before);
            if n > 0 {
                if let Some(start) = self.metric_ack_start.take() {
                    let us = now
                        .saturating_duration_since(start)
                        .as_micros()
                        .min(u64::MAX as u128) as u64;
                    self.metric_ack_samples += 1;
                    self.metric_ack_sum_us = self.metric_ack_sum_us.saturating_add(us);
                    self.metric_ack_max_us = self.metric_ack_max_us.max(us);
                }
                self.acked_data += n as u64;
                self.unacked.drain(..n);
                self.last_ack_progress = now;
                self.rto = RTO_MIN;
                self.retx = 0;
            }
            if let Some(fin) = self.fin_sent_seq {
                if ack == fin.wrapping_add(1) {
                    self.fin_acked = true;
                }
            }
        }
        // A window update needs SND.UNA <= SEG.ACK <= SND.NXT. RFC 9293,
        // Section 3.10.7.4, also requires the segment to be newer than the
        // last update: SND.WL1 < SEG.SEQ, or the same SEG.SEQ with
        // SND.WL2 <= SEG.ACK. Serial arithmetic handles wrap for both values.
        if seq_at_or_before(una, ack) {
            let newer = seq_before(self.window_seq, seq)
                || (self.window_seq == seq && seq_at_or_before(self.window_ack, ack));
            if newer {
                self.window_seq = seq;
                self.window_ack = ack;
                let was_zero = self.peer_window == 0;
                self.peer_window = window as usize;
                if was_zero && self.peer_window > 0 {
                    // The peer reopened its zero window. Do not retransmit old
                    // data at once, and give the FIN timer a fresh start. A
                    // later loss still uses the normal retransmission timer.
                    self.last_ack_progress = now;
                    self.rto = RTO_MIN;
                    self.retx = 0;
                    if self.fin_sent_seq.is_some() && !self.fin_acked {
                        self.fin_sent_at = Some(now);
                    }
                }
            }
        }
        self.emit(now);
        self.maybe_close();
        true
    }
    /// Close when both directions are shut down and every byte is delivered.
    fn maybe_close(&mut self) {
        if self.state == State::Established
            && self.fin_acked
            && self.client_fin
            && self.outer_write_shutdown
            && self.outbuf.is_empty()
            && self.pending.is_empty()
        {
            self.graceful_close = true;
            self.close();
        }
    }
    /// Move up to `count` leading bytes of `buffer` into `out` with one copy.
    fn take_front(buffer: &mut VecDeque<u8>, count: usize, out: &mut Vec<u8>) {
        assert!(count <= buffer.len());
        let (head, tail) = buffer.as_slices();
        let first = head.len().min(count);
        out.extend_from_slice(&head[..first]);
        if first < count {
            out.extend_from_slice(&tail[..count - first]);
        }
        buffer.drain(..count);
    }
    fn emit(&mut self, now: Instant) {
        let limit = self.peer_window.min(MAX_INFLIGHT);
        let mut started_empty = self.inflight() == 0;
        while !self.outbuf.is_empty() && self.inflight() < limit {
            let n = self
                .send_mss
                .min(self.outbuf.len())
                .min(limit - self.inflight());
            if n == 0 {
                break;
            }
            let mut data = Vec::with_capacity(n);
            Self::take_front(&mut self.outbuf, n, &mut data);
            // Keep one copy for the retransmit buffer and give the action the
            // other one. The relay consumes the action after this call.
            self.unacked.extend(data.iter().copied());
            self.send(
                packet::ACK | packet::PSH,
                self.next_seq(),
                self.cseq,
                self.receive_window(),
                Vec::new(),
                data,
            );
            self.sent_data += n as u64;
            if started_empty {
                self.last_ack_progress = now;
                self.metric_ack_start = Some(now);
                started_empty = false;
            }
        }
        self.maybe_fin(now);
        if self.read_paused
            && self.outbuf.len() <= OUTBUF_LOW_WATER
            && self.inflight() < MAX_INFLIGHT
        {
            self.read_paused = false;
        }
        self.sync_persist(now);
    }
    fn maybe_fin(&mut self, now: Instant) {
        if self.state == State::Established
            && !self.start_held
            && self.outer_eof
            && self.fin_sent_seq.is_none()
            && self.outbuf.is_empty()
            // The FIN closes the download direction. Pending upload bytes are
            // the other direction and must not hold it back.
            // A FIN occupies one sequence number. Do not send it into a zero
            // or full window. The next window update sends it.
            && self.inflight() < self.peer_window
        {
            let seq = self.next_seq();
            self.send(
                packet::ACK | packet::FIN,
                seq,
                self.cseq,
                self.receive_window(),
                Vec::new(),
                Vec::new(),
            );
            self.fin_sent_seq = Some(seq);
            self.fin_sent_at = Some(now);
            self.note_activity(now);
        }
        self.sync_persist(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn upload(seq: u32, data: &[u8]) -> TcpSegment<'_> {
        TcpSegment {
            sport: 1,
            dport: 2,
            seq,
            ack: 201,
            flags: packet::ACK,
            window: 65535,
            options: &[],
            data,
        }
    }

    fn seg(seq: u32, ack: u32, flags: u8, window: u16, data: &[u8]) -> TcpSegment<'_> {
        TcpSegment {
            sport: 1,
            dport: 2,
            seq,
            ack,
            flags,
            window,
            options: &[],
            data,
        }
    }

    fn fill_upload_buffer(f: &mut TcpFlow, now: Instant) {
        let data = [7; MSS_INNER];
        while f.pending.len() < MAX_PENDING_CLIENT {
            let n = data.len().min(MAX_PENDING_CLIENT - f.pending.len());
            f.on_inner(&upload(f.cseq, &data[..n]), now);
            f.actions();
        }
    }

    #[test]
    fn take_front_copies_a_wrapped_ring_in_order() {
        let mut ring: VecDeque<u8> = VecDeque::with_capacity(8);
        ring.extend(0..8u8);
        ring.drain(..5);
        ring.extend(8..12u8);
        // The live bytes now sit at both ends of the ring.
        let (head, tail) = ring.as_slices();
        assert!(!head.is_empty() && !tail.is_empty());
        let mut out = Vec::new();
        TcpFlow::take_front(&mut ring, 3, &mut out);
        assert_eq!(out, [5, 6, 7]);
        assert_eq!(ring, VecDeque::from(vec![8, 9, 10, 11]));
        // A count that spans both slices keeps the byte order.
        out.clear();
        TcpFlow::take_front(&mut ring, 4, &mut out);
        assert_eq!(out, [8, 9, 10, 11]);
        assert!(ring.is_empty());
        // A second ring holds a count that ends before the wrap.
        let mut ring: VecDeque<u8> = VecDeque::with_capacity(8);
        ring.extend(0..8u8);
        ring.drain(..5);
        ring.extend(8..12u8);
        out.clear();
        TcpFlow::take_front(&mut ring, 2, &mut out);
        assert_eq!(out, [5, 6]);
        out.clear();
        TcpFlow::take_front(&mut ring, 5, &mut out);
        assert_eq!(out, [7, 8, 9, 10, 11]);
        assert!(ring.is_empty());
    }

    #[test]
    fn download_stream_keeps_byte_order_across_chunk_boundaries() {
        let now = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, now);
        f.outer_connected();
        f.actions();
        let total = 512 * 1024 + 7;
        let chunk = 8 * 1024;
        let expected: Vec<u8> = (0..total)
            .map(|i| ((i * 37 + i / 97) % 251) as u8)
            .collect();
        let mut fed = 0;
        let mut got: Vec<u8> = Vec::with_capacity(total);
        let mut acked = 0u32;
        while got.len() < total {
            assert!(fed < total, "download lost bytes");
            let n = chunk.min(total - fed);
            f.outer_data(&expected[fed..fed + n], now);
            fed += n;
            loop {
                let mut emitted = false;
                for action in f.actions() {
                    if let Action::Send { data, .. } = action {
                        if !data.is_empty() {
                            got.extend_from_slice(&data);
                            acked = acked.wrapping_add(data.len() as u32);
                            emitted = true;
                        }
                    }
                }
                if !emitted {
                    break;
                }
                // The inner client acknowledges every segment it accepted.
                f.on_inner(
                    &TcpSegment {
                        sport: 1,
                        dport: 2,
                        seq: 101,
                        ack: 201u32.wrapping_add(acked),
                        flags: packet::ACK,
                        window: 65535,
                        options: &[],
                        data: &[],
                    },
                    now,
                );
            }
        }
        assert_eq!(got, expected);
        assert_eq!(f.inflight(), 0);
    }

    #[test]
    fn retransmit_carries_the_bytes_of_the_taken_action() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[], 65535, t);
        f.outer_connected();
        f.outer_data(b"abcdefghij", t);
        let sent = f.actions();
        let first = match &sent[0] {
            Action::Send { data, seq, .. } => (data.clone(), *seq),
            other => panic!("unexpected action: {other:?}"),
        };
        f.tick(t + Duration::from_millis(400));
        let retx = f.actions();
        match &retx[0] {
            Action::Send { data, seq, .. } => {
                assert_eq!(*data, first.0);
                assert_eq!(*seq, first.1);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn retransmit_after_partial_ack_starts_at_unacknowledged_byte() {
        let t = Instant::now();
        let mut flow = TcpFlow::new(10, 100, &[2, 4, 5, 120], 65535, t);
        flow.outer_connected();
        let data: Vec<u8> = (0..6000).map(|i| ((i * 37 + i / 97) % 251) as u8).collect();
        flow.outer_data(&data, t);
        flow.actions();
        flow.on_inner(
            &TcpSegment {
                sport: 1,
                dport: 2,
                seq: 11,
                ack: 101 + 1800,
                flags: packet::ACK,
                window: 65535,
                options: &[],
                data: &[],
            },
            t,
        );
        flow.actions();
        flow.tick(t + Duration::from_millis(400));
        match &flow.actions()[0] {
            Action::Send {
                data: retransmit,
                seq,
                ..
            } => {
                assert_eq!(*seq, 101 + 1800);
                assert_eq!(retransmit, &data[1800..1800 + 1400]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn receive_credit_covers_only_free_buffer_space() {
        let now = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, now);
        f.outer_connected();
        let data = [3; MSS_INNER];
        while f.pending.len() < MAX_PENDING_CLIENT {
            let n = data.len().min(MAX_PENDING_CLIENT - f.pending.len());
            f.on_inner(&upload(f.cseq, &data[..n]), now);
            for action in f.actions() {
                if let Action::Send { window, .. } = action {
                    assert!(f.pending.len() + window as usize <= MAX_PENDING_CLIENT);
                }
            }
        }
        // A reply and its retransmit must not reopen the full upload buffer.
        f.outer_data(b"response", now);
        f.tick(now + Duration::from_secs(1));
        assert!(f
            .actions()
            .iter()
            .all(|a| matches!(a, Action::Send { window: 0, .. })));
    }

    #[test]
    fn partial_outer_write_reopens_a_full_upload_buffer() {
        let now = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, now);
        f.outer_connected();
        fill_upload_buffer(&mut f, now);
        f.outer_written(16 * 1024);
        assert_eq!(f.pending.len(), MAX_PENDING_CLIENT - 16 * 1024);
        assert_eq!(
            f.actions(),
            vec![Action::Send {
                accounting: SendAccounting::None,
                flags: packet::ACK,
                seq: 201,
                ack: f.cseq,
                window: 16 * 1024,
                options: Vec::new(),
                data: Vec::new(),
            }]
        );
    }

    #[test]
    fn oversized_segment_keeps_available_prefix_and_defers_fin() {
        let now = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, now);
        f.outer_connected();
        fill_upload_buffer(&mut f, now);
        f.outer_written(3);
        f.actions();
        let seq = f.cseq;
        let mut segment = upload(seq, b"abcdef");
        segment.flags |= packet::FIN;
        f.on_inner(&segment, now);
        assert_eq!(f.cseq, seq.wrapping_add(3));
        assert!(!f.client_fin);
        assert_eq!(f.pending.len(), MAX_PENDING_CLIENT);
        assert_eq!(&f.pending_bytes()[MAX_PENDING_CLIENT - 3..], b"abc");
        assert!(matches!(
            f.actions().last(),
            Some(Action::Send { window: 0, .. })
        ));
        // The sender can retry the same segment after credit reopens.
        f.outer_written(16 * 1024);
        f.actions();
        f.on_inner(&segment, now);
        assert_eq!(f.cseq, seq.wrapping_add(7));
        assert!(f.client_fin);
        let n = f.pending.len();
        assert_eq!(&f.pending_bytes()[n - 6..], b"abcdef");
    }

    #[test]
    fn thirty_mib_single_upload_survives_repeated_partial_outer_writes() {
        let now = Instant::now();
        // Start near sequence wrap. Keep one inner flow for the full request.
        let mut f = TcpFlow::new(u32::MAX - 1024, 200, &[], 65535, now);
        f.outer_connected();
        let total = 30 * 1024 * 1024;
        let payload: Vec<u8> = (0..total)
            .map(|n| ((n * 31 + n / 251) % 256) as u8)
            .collect();
        let mut sent = 0;
        let mut written = 0;
        let mut window = RCV_WINDOW as usize;
        let mut stalls = 0;
        while written < total {
            if sent < total && window > 0 {
                let n = MSS_INNER.min(window).min(total - sent);
                f.on_inner(&upload(f.cseq, &payload[sent..sent + n]), now);
                sent += n;
            } else {
                // Model an outer socket that accepts only part of its queued data.
                let n = f.pending.len().min(16 * 1024);
                assert!(n > 0, "upload has no pending bytes and no receive credit");
                assert_eq!(&f.pending_bytes()[..n], &payload[written..written + n]);
                f.outer_written(n);
                written += n;
                stalls += 1;
            }
            for action in f.actions() {
                if let Action::Send {
                    ack, window: next, ..
                } = action
                {
                    assert_eq!(ack, f.cseq);
                    assert!(f.pending.len() + next as usize <= MAX_PENDING_CLIENT);
                    window = next as usize;
                }
            }
            assert_eq!(f.state, State::Established);
            assert!(f.pending.len() <= MAX_PENDING_CLIENT);
        }
        assert_eq!(sent, total);
        assert!(stalls > 1000);
        let mut fin = upload(f.cseq, &[]);
        fin.flags |= packet::FIN;
        f.on_inner(&fin, now);
        assert!(f.client_fin);
        assert!(f.actions().contains(&Action::ShutdownWrite));
    }

    #[test]
    fn metrics_measure_ack_window_and_buffer_without_retransmit_sample() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[], 100, t);
        f.outer_connected();
        f.outer_data(&[7; 200], t);
        let first = f.take_metrics(t);
        assert_eq!(first.download_peak, 200);
        assert_eq!(first.ack_samples, 0);
        let ack = TcpSegment {
            sport: 1,
            dport: 2,
            seq: 11,
            ack: 201,
            flags: packet::ACK,
            window: 100,
            options: &[],
            data: b"upload",
        };
        let later = t + Duration::from_millis(12);
        f.on_inner(&ack, later);
        let measured = f.take_metrics(later);
        assert_eq!(
            (
                measured.ack_samples,
                measured.ack_sum_us,
                measured.ack_max_us
            ),
            (1, 12000, 12000)
        );
        assert_eq!(measured.window_limited_us, 12000);
        assert_eq!(measured.upload_peak, 6);
        f.tick(later + Duration::from_millis(400));
        let ack2 = TcpSegment {
            ack: 301,
            data: &[],
            ..ack
        };
        f.on_inner(&ack2, later + Duration::from_millis(410));
        assert_eq!(
            f.take_metrics(later + Duration::from_millis(410))
                .ack_samples,
            0
        );
    }
    #[test]
    fn window_mss_and_ack_wrap() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 0xfffffff0, &[2, 4, 1, 44, 3, 3, 7], 600, t);
        assert_eq!(f.send_mss, 300);
        f.start();
        assert_eq!(f.actions().len(), 1);
        f.outer_connected();
        f.outer_data(&vec![7; 900], t);
        let a = f.actions();
        assert_eq!(a.len(), 2);
        assert_eq!(f.inflight(), 600);
        let s = TcpSegment {
            sport: 1,
            dport: 2,
            seq: 11,
            ack: 0xfffffff1u32.wrapping_add(600),
            flags: packet::ACK,
            window: 600,
            options: &[],
            data: &[],
        };
        f.on_inner(&s, t);
        assert_eq!(f.acked_data, 600);
        assert_eq!(f.actions().len(), 1);
    }
    #[test]
    fn duplicate_data_is_not_forwarded_twice_and_fin_shuts_down() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.start();
        f.actions();
        f.outer_connected();
        let s = TcpSegment {
            sport: 1,
            dport: 2,
            seq: 101,
            ack: 201,
            flags: packet::ACK | packet::FIN,
            window: 1024,
            options: &[],
            data: b"abc",
        };
        f.on_inner(&s, t);
        assert_eq!(f.pending_bytes(), b"abc");
        f.on_inner(&s, t);
        assert_eq!(f.pending_bytes(), b"abc");
        f.actions();
        f.outer_written(3);
        assert_eq!(f.actions(), vec![Action::ShutdownWrite]);
    }
    #[test]
    fn connect_timeout_aborts() {
        let t = Instant::now();
        let mut f = TcpFlow::new(1, 2, &[], 10, t);
        f.tick(t + Duration::from_secs(9));
        assert_eq!(f.state, State::Closed);
        assert!(f.actions().contains(&Action::Close));
    }
    #[test]
    fn held_start_ignores_duplicate_syn_and_releases_one_syn_ack() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[2, 4, 1, 44], 65535, t);
        f.hold_start();
        assert!(f.start_held());
        let syn = TcpSegment {
            sport: 1,
            dport: 2,
            seq: 100,
            ack: 0,
            flags: packet::SYN,
            window: 65535,
            options: &[2, 4, 1, 20],
            data: &[],
        };
        f.on_inner(&syn, t);
        f.on_inner(&syn, t + Duration::from_millis(300));
        assert!(f.actions().is_empty());
        assert_eq!(f.send_mss, 300);
        f.release_start();
        let actions = f.actions();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Send {
                flags, seq, ack, ..
            } => {
                assert_eq!(*flags, packet::SYN | packet::ACK);
                assert_eq!((*seq, *ack), (200, 101));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert!(!f.start_held());
        f.release_start();
        assert!(f.actions().is_empty());
    }
    #[test]
    fn held_start_ignores_data_until_release() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.hold_start();
        f.on_inner(&upload(101, b"early"), t);
        assert!(f.pending_bytes().is_empty());
        assert!(f.actions().is_empty());
        f.release_start();
        f.on_inner(&upload(101, b"early"), t);
        assert_eq!(f.pending_bytes(), b"early");
    }
    #[test]
    fn invalid_ack_does_not_clear_the_liveness_budget() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.idle_probes = 2;
        f.idle_probe_at = Some(t);
        f.persist_probes = 11;
        let later = t + Duration::from_secs(1);
        let invalid = TcpSegment {
            ack: f.next_seq().wrapping_add(1),
            ..upload(f.cseq, b"bad")
        };
        f.on_inner(&invalid, later);
        assert_eq!(f.idle_probes, 2);
        assert_eq!(f.idle_probe_at, Some(t));
        assert_eq!(f.persist_probes, 11);
        assert_eq!(f.last_activity, t);
        assert!(f.pending_bytes().is_empty());
    }
    #[test]
    fn reset_needs_the_next_expected_sequence() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.on_inner(
            &TcpSegment {
                flags: packet::RST,
                seq: 0xdeadbeef,
                ..upload(101, &[])
            },
            t,
        );
        assert_eq!(f.state, State::Established);
        assert!(f.actions().is_empty());
        f.on_inner(
            &TcpSegment {
                flags: packet::RST,
                seq: 102,
                ..upload(101, &[])
            },
            t,
        );
        assert_eq!(f.state, State::Established);
        assert!(matches!(&f.actions()[..], [Action::Send { flags, .. }] if *flags == packet::ACK));
        f.on_inner(
            &TcpSegment {
                flags: packet::RST,
                seq: 101,
                ..upload(101, &[])
            },
            t,
        );
        assert_eq!(f.state, State::Closed);
    }
    #[test]
    fn new_syn_on_a_live_tuple_gets_a_challenge_not_an_old_syn_ack() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[2, 4, 1, 44], 65535, t);
        f.outer_connected();
        f.on_inner(&upload(101, &[]), t);
        f.actions();
        let syn = TcpSegment {
            flags: packet::SYN,
            seq: 5000,
            options: &[2, 4, 0, 1],
            ..upload(101, &[])
        };
        f.on_inner(&syn, t);
        assert_eq!(f.state, State::Established);
        assert_eq!(f.send_mss, 300);
        assert!(
            matches!(&f.actions()[..], [Action::Send { flags, ack: 101, .. }] if *flags == packet::ACK)
        );
        // A reset from the new client can retire the old flow. Its next SYN
        // is then handled as a new flow by the relay.
        f.on_inner(
            &TcpSegment {
                flags: packet::RST,
                seq: 101,
                ..upload(101, &[])
            },
            t,
        );
        assert_eq!(f.state, State::Closed);
    }
    #[test]
    fn data_and_fin_without_ack_are_not_accepted() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.on_inner(
            &TcpSegment {
                flags: packet::FIN,
                ..upload(101, b"data")
            },
            t,
        );
        assert_eq!(f.cseq, 101);
        assert!(!f.client_fin);
        assert!(f.pending_bytes().is_empty());
        assert!(f.actions().is_empty());
    }
    #[test]
    fn retransmit_metric_counts_each_data_and_fin_retry() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[], 65535, t);
        f.outer_connected();
        f.outer_data(b"abc", t);
        f.actions();
        f.tick(t + Duration::from_millis(400));
        let first = f.take_metrics(t + Duration::from_millis(400));
        assert_eq!(first.retransmits, 1);
        f.outer_end(t + Duration::from_millis(401));
        f.actions();
        f.tick(t + Duration::from_secs(2));
        let second = f.take_metrics(t + Duration::from_secs(2));
        assert!(second.retransmits >= 1);
    }
    #[test]
    fn keepalive_probe_is_acknowledged_without_advancing_sequence() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        // A normal ACK at the next expected byte needs no answer.
        f.on_inner(&upload(101, &[]), t);
        assert!(f.actions().is_empty());
        // A keepalive probe carries the byte before the next expected byte.
        let probe = TcpSegment {
            seq: 100,
            ..upload(100, &[])
        };
        f.on_inner(&probe, t + Duration::from_secs(60));
        let actions = f.actions();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Send {
                flags,
                ack,
                data,
                window,
                ..
            } => {
                assert_eq!(*flags, packet::ACK);
                assert_eq!(*ack, f.cseq);
                assert!(data.is_empty());
                assert_eq!(*window, f.receive_window());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.cseq, 101);
        assert_eq!(f.state, State::Established);
    }
    #[test]
    fn keepalive_probe_at_sequence_wrap_preserves_data_order() {
        let t = Instant::now();
        let mut flow = TcpFlow::new(u32::MAX, 200, &[], 65535, t);
        flow.outer_connected();
        flow.actions();
        flow.on_inner(&upload(u32::MAX, &[]), t);
        let actions = flow.actions();
        assert!(matches!(actions.as_slice(),
            [Action::Send { flags, ack: 0, data, .. }] if *flags == packet::ACK && data.is_empty()));
        flow.on_inner(&upload(0, b"next"), t);
        assert_eq!(flow.pending_bytes(), b"next");
        assert_eq!(flow.cseq, 4);
    }
    #[test]
    fn silent_established_flow_probes_the_inner_peer_instead_of_resetting() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.actions();
        f.tick(t + IDLE_PROBE_AFTER + Duration::from_secs(1));
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert_eq!(actions.len(), 1, "{actions:?}");
        match &actions[0] {
            Action::Send {
                flags,
                seq,
                ack,
                window,
                data,
                ..
            } => {
                assert_eq!(*flags, packet::ACK);
                // A keepalive probe carries the sequence number before the
                // next expected byte.
                assert_eq!(*seq, f.next_seq().wrapping_sub(1));
                assert_eq!(*ack, f.cseq);
                assert_eq!(*window, f.receive_window());
                assert!(data.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert!(!actions.contains(&Action::Close));
    }
    #[test]
    fn answered_idle_probes_keep_a_silent_flow_open() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.actions();
        let mut at = t + IDLE_PROBE_AFTER + Duration::from_secs(1);
        // Run more probe cycles than the reset limit. Every answer keeps the
        // flow open, so a healthy silent flow has no application idle expiry.
        for cycle in 0..(u32::from(MAX_IDLE_PROBES) + 3) {
            f.tick(at);
            assert_eq!(f.state, State::Established, "cycle {cycle}");
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, data, .. }]
                    if *flags == packet::ACK && data.is_empty()),
                "cycle {cycle}: {actions:?}"
            );
            f.on_inner(&upload(101, &[]), at);
            assert_eq!(f.state, State::Established);
            at += IDLE_PROBE_AFTER;
        }
    }
    #[test]
    fn unanswered_idle_probes_reset_the_flow_within_a_bound() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.actions();
        let first = t + IDLE_PROBE_AFTER + Duration::from_secs(1);
        let mut probes = 0;
        for i in 0..u32::from(MAX_IDLE_PROBES) {
            f.tick(first + IDLE_PROBE_INTERVAL * i);
            assert_eq!(f.state, State::Established, "probe {i}");
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, data, .. }]
                    if *flags == packet::ACK && data.is_empty()),
                "probe {i}: {actions:?}"
            );
            probes += 1;
        }
        assert_eq!(probes, MAX_IDLE_PROBES);
        f.tick(first + IDLE_PROBE_INTERVAL * u32::from(MAX_IDLE_PROBES));
        assert_eq!(f.state, State::Closed);
        let actions = f.actions();
        assert!(
            actions.iter().any(
                |action| matches!(action, Action::Send { flags, .. } if flags & packet::RST != 0)
            ),
            "the inner flow must see a reset: {actions:?}"
        );
        assert!(actions.contains(&Action::Close));
    }
    #[test]
    fn rejected_idle_probes_do_not_consume_the_peer_budget() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        let mut now = t + IDLE_PROBE_AFTER;
        for _ in 0..MAX_IDLE_PROBES + 2 {
            f.tick(now);
            let actions = f.actions();
            let [Action::Send { accounting, .. }] = actions.as_slice() else {
                panic!("expected one idle probe: {actions:?}");
            };
            assert!(matches!(accounting, SendAccounting::IdleProbe { .. }));
            f.output_rejected(*accounting, now);
            assert_eq!(f.idle_probes, 0);
            assert_eq!(f.state, State::Established);
            f.tick(now + OUTPUT_RETRY / 2);
            assert!(f.actions().is_empty());
            now += OUTPUT_RETRY;
        }
        for _ in 0..MAX_IDLE_PROBES {
            f.tick(now);
            assert!(matches!(
                &f.actions()[..],
                [Action::Send {
                    accounting: SendAccounting::IdleProbe { .. },
                    ..
                }]
            ));
            now += IDLE_PROBE_INTERVAL;
        }
        f.tick(now);
        assert_eq!(f.state, State::Closed);
    }

    #[test]
    fn rejected_persist_probes_restore_the_exact_backoff() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.outer_data(b"queued", t);
        f.actions();
        let mut now = t + PERSIST_MIN;
        for _ in 0..MAX_PERSIST_PROBES + 2 {
            f.tick(now);
            let actions = f.actions();
            let [Action::Send { accounting, .. }] = actions.as_slice() else {
                panic!("expected one persist probe: {actions:?}");
            };
            assert!(matches!(accounting, SendAccounting::PersistProbe { .. }));
            f.output_rejected(*accounting, now);
            assert_eq!(f.persist_probes, 0);
            assert_eq!(f.persist_interval, PERSIST_MIN);
            assert_eq!(f.state, State::Established);
            now += OUTPUT_RETRY;
        }
        f.tick(now);
        assert_eq!(f.persist_probes, 1);
        assert_eq!(f.outbuf.len(), 6);
    }

    #[test]
    fn rejected_retransmissions_keep_bytes_and_retry_budget() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.outer_data(b"data", t);
        f.actions();
        let mut now = t + RTO_MIN + Duration::from_millis(1);
        for _ in 0..MAX_RETX + 2 {
            f.tick(now);
            let actions = f.actions();
            let [Action::Send {
                accounting, data, ..
            }] = actions.as_slice()
            else {
                panic!("expected one retransmission: {actions:?}");
            };
            assert_eq!(data, b"data");
            assert!(matches!(accounting, SendAccounting::Retransmit { .. }));
            f.output_rejected(*accounting, now);
            assert_eq!(f.retx, 0);
            assert_eq!(f.rto, RTO_MIN);
            assert_eq!(f.inflight(), 4);
            assert_eq!(f.take_metrics(now).retransmits, 0);
            now += OUTPUT_RETRY;
        }
        f.tick(now);
        assert_eq!(f.retx, 1);
        assert_eq!(f.take_metrics(now).retransmits, 1);
    }

    #[test]
    fn rejected_fin_retransmissions_do_not_consume_the_peer_budget() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.outer_end(t);
        f.actions();
        let fin = f.fin_sent_seq.unwrap();
        let mut now = t + RTO_MIN + Duration::from_millis(1);
        for _ in 0..MAX_RETX + 2 {
            f.tick(now);
            let actions = f.actions();
            let [Action::Send {
                accounting,
                seq,
                flags,
                ..
            }] = actions.as_slice()
            else {
                panic!("expected one FIN retransmission: {actions:?}");
            };
            assert_eq!(*seq, fin);
            assert_ne!(*flags & packet::FIN, 0);
            assert!(matches!(accounting, SendAccounting::FinRetransmit { .. }));
            f.output_rejected(*accounting, now);
            assert_eq!(f.retx, 0);
            assert_eq!(f.rto, RTO_MIN);
            assert_eq!(f.fin_sent_seq, Some(fin));
            assert_eq!(f.state, State::Established);
            assert_eq!(f.take_metrics(now).retransmits, 0);
            now += OUTPUT_RETRY;
        }
        f.tick(now);
        assert_eq!(f.retx, 1);
        assert_eq!(f.take_metrics(now).retransmits, 1);
    }
    #[test]
    fn outer_activity_clears_a_pending_idle_probe_cycle() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.actions();
        let first = t + IDLE_PROBE_AFTER + Duration::from_secs(1);
        f.tick(first);
        assert_eq!(f.actions().len(), 1);
        // A late response arrives and the inner peer acknowledges it.
        let next = f.next_seq();
        f.outer_data(b"late", first + Duration::from_secs(1));
        for action in f.actions() {
            if let Action::Send { data, .. } = action {
                f.on_inner(
                    &TcpSegment {
                        ack: next.wrapping_add(data.len() as u32),
                        ..upload(101, &[])
                    },
                    first + Duration::from_secs(2),
                );
            }
        }
        assert_eq!(f.inflight(), 0);
        // The next silence starts a new probe cycle. It is not the fourth
        // unanswered probe, so the flow stays open.
        f.tick(first + IDLE_PROBE_AFTER + Duration::from_secs(2));
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert!(
            matches!(&actions[..], [Action::Send { flags, data, .. }]
                if *flags == packet::ACK && data.is_empty()),
            "{actions:?}"
        );
    }
    #[test]
    fn sending_fin_clears_an_old_idle_probe_cycle() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.idle_probes = 2;
        f.idle_probe_at = Some(t);
        f.outer_eof = true;
        f.maybe_fin(t + Duration::from_secs(1));
        assert_eq!(f.idle_probes, 0);
        assert!(f.idle_probe_at.is_none());
    }

    #[test]
    fn zero_window_persist_probes_without_consuming_queued_bytes() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.actions();
        f.outer_data(b"abcdef", t);
        assert!(f.actions().is_empty(), "a zero window carries no data");
        assert_eq!(f.outbuf.len(), 6);
        assert_eq!(f.sent_data, 0);
        assert!(f.unacked.is_empty());

        f.tick(t + PERSIST_MIN - Duration::from_millis(1));
        assert!(f.actions().is_empty(), "the first probe waits one RTO");
        f.tick(t + PERSIST_MIN);
        let actions = f.actions();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Send {
                flags,
                seq,
                ack,
                window,
                data,
                ..
            } => {
                assert_eq!(*flags, packet::ACK);
                assert_eq!(*seq, 200, "the probe carries SND.UNA - 1");
                assert_eq!(*ack, 101);
                assert_eq!(*window, f.receive_window());
                assert!(data.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.outbuf.len(), 6);
        assert_eq!(f.sent_data, 0);
        assert_eq!(f.acked_data, 0);
        assert!(f.unacked.is_empty());
        assert_eq!(f.persist_probes, 1);
    }
    #[test]
    fn zero_window_timer_arms_when_data_arrives_before_the_connect_completes() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_data(b"early", t);
        f.outer_connected();
        assert!(f.actions().is_empty());
        // The first tick arms the timer. The next one sends the probe.
        f.tick(t + PERSIST_MIN);
        assert!(f.actions().is_empty());
        f.tick(t + PERSIST_MIN * 2);
        assert!(
            matches!(&f.actions()[..], [Action::Send { flags, data, .. }]
                if *flags == packet::ACK && data.is_empty()),
            "a blocked flow must probe after it becomes established"
        );
        assert_eq!(f.outbuf.len(), 5);
    }
    #[test]
    fn unanswered_zero_window_probes_back_off_then_reset_with_a_signal() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.outer_data(b"queued", t);
        f.actions();
        let mut at = t;
        for probe in 1..=MAX_PERSIST_PROBES {
            at += f.persist_interval;
            f.tick(at);
            let actions = f.actions();
            assert_eq!(actions.len(), 1, "probe {probe}: {actions:?}");
            assert!(
                matches!(&actions[0], Action::Send { flags, data, seq, .. }
                    if *flags == packet::ACK && data.is_empty() && *seq == 200),
                "probe {probe}: {actions:?}"
            );
            assert_eq!(f.persist_probes, probe);
            assert_eq!(f.state, State::Established);
            assert_eq!(f.outbuf.len(), 6);
            assert_eq!(f.sent_data, 0);
        }
        assert_eq!(f.persist_interval, PERSIST_MAX);
        at += f.persist_interval;
        f.tick(at);
        assert_eq!(f.state, State::Closed);
        let actions = f.actions();
        assert!(
            actions.iter().any(
                |action| matches!(action, Action::Send { flags, .. } if flags & packet::RST != 0)
            ),
            "the inner peer must see a reset: {actions:?}"
        );
        assert!(actions.contains(&Action::Close));
        f.tick(at + PERSIST_MAX * 4);
        assert!(f.actions().is_empty(), "a closed flow sends no probes");
    }
    #[test]
    fn answered_zero_window_probes_keep_a_paused_peer_open() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.outer_data(b"queued", t);
        f.actions();
        let mut at = t;
        for cycle in 0..u32::from(MAX_PERSIST_PROBES) * 3 {
            at += f.persist_interval;
            f.tick(at);
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, data, .. }]
                    if *flags == packet::ACK && data.is_empty()),
                "cycle {cycle}: {actions:?}"
            );
            // The peer must answer a zero-window probe with its current
            // window. An answer keeps the flow open with no progress.
            f.on_inner(&seg(101, 201, packet::ACK, 0, &[]), at);
            assert!(f.actions().is_empty(), "cycle {cycle}");
            assert_eq!(f.state, State::Established, "cycle {cycle}");
            assert_eq!(f.outbuf.len(), 6);
            assert_eq!(f.sent_data, 0);
            assert_eq!(f.retx, 0, "probes are not data retransmissions");
        }
        assert_eq!(f.persist_interval, PERSIST_MAX);
    }
    #[test]
    fn answered_zero_window_acks_do_not_exhaust_the_data_retry_limit() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[2, 4, 3, 232], 1000, t);
        f.outer_connected();
        f.actions();
        f.outer_data(&[7u8; 2000], t);
        f.actions();
        assert_eq!(f.sent_data, 1000);
        assert_eq!(f.inflight(), 1000);

        // The peer accepts 300 bytes and advertises a zero window.
        let zero_ack = seg(11, 401, packet::ACK, 0, &[]);
        f.on_inner(&zero_ack, t);
        assert_eq!(f.acked_data, 300);
        assert_eq!(f.inflight(), 700);
        assert_eq!(f.outbuf.len(), 1000);

        let mut at = t;
        for cycle in 0..u32::from(MAX_RETX) * 3 {
            at += f.persist_interval;
            f.tick(at);
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, data, .. }]
                    if *flags == packet::ACK && data.is_empty()),
                "cycle {cycle}: {actions:?}"
            );
            assert_eq!(f.inflight(), 700, "no data enters the zero window");
            // The peer answers the probe with the same zero window.
            f.on_inner(&zero_ack, at);
            assert!(f.actions().is_empty(), "cycle {cycle}");
            assert_eq!(f.state, State::Established, "cycle {cycle}");
            assert_eq!(f.retx, 0, "answered probes are not data retries");
        }
        assert_eq!(f.sent_data, 1000);
        assert_eq!(f.outbuf.len(), 1000);
    }
    #[test]
    fn zero_window_ack_keeps_accepted_bytes_and_waits_for_the_window() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[2, 4, 3, 232], 1000, t);
        f.outer_connected();
        f.actions();
        let data: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        f.outer_data(&data, t);
        let first = f.actions();
        assert_eq!(first.len(), 1);
        assert_eq!(f.sent_data, 1000);
        assert_eq!(f.inflight(), 1000);

        // The peer accepts 400 bytes and then advertises a zero window.
        f.on_inner(&seg(11, 501, packet::ACK, 0, &[]), t);
        assert_eq!(f.acked_data, 400);
        assert_eq!(f.inflight(), 600);
        assert_eq!(f.peer_window, 0);
        assert_eq!(f.retx, 0);
        assert_eq!(f.outbuf.len(), 2000);

        // The retransmission timer must not resend 600 bytes into the closed
        // window. It sends one probe instead.
        f.tick(t + RTO_MIN);
        let probe = f.actions();
        assert_eq!(probe.len(), 1);
        match &probe[0] {
            Action::Send {
                flags,
                seq,
                data: probe_data,
                ..
            } => {
                assert_eq!(*flags, packet::ACK);
                assert_eq!(*seq, 500, "the probe carries SND.UNA - 1");
                assert!(probe_data.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        // The peer answers with the same zero window. The flow stays open and
        // the probe is not a data retransmission.
        f.on_inner(&seg(11, 501, packet::ACK, 0, &[]), t + RTO_MIN);
        assert!(f.actions().is_empty());
        assert_eq!(f.retx, 0);
        assert_eq!(f.state, State::Established);

        // A lost window update arrives with 1600 bytes of credit. Only the
        // free part of the window carries new bytes, in order.
        f.on_inner(
            &seg(11, 501, packet::ACK, 1600, &[]),
            t + RTO_MIN + Duration::from_millis(500),
        );
        let sent = f.actions();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            Action::Send {
                seq,
                data: chunk,
                flags,
                ..
            } => {
                assert_eq!(*flags, packet::ACK | packet::PSH);
                assert_eq!(*seq, 1101);
                assert_eq!(chunk.as_slice(), &data[1000..2000]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.sent_data, 2000);
        assert_eq!(f.inflight(), 1600);
        assert_eq!(f.outbuf.len(), 1000);

        // Acknowledge every outstanding byte and close the window again.
        f.on_inner(
            &seg(11, 2101, packet::ACK, 0, &[]),
            t + Duration::from_secs(1),
        );
        assert_eq!(f.acked_data, 2000);
        assert_eq!(f.inflight(), 0);
        assert_eq!(f.outbuf.len(), 1000);
        f.tick(t + Duration::from_secs(1) + PERSIST_MIN);
        let probe = f.actions();
        assert!(
            matches!(&probe[..], [Action::Send { flags, data, seq, .. }]
                if *flags == packet::ACK && data.is_empty() && *seq == 2100),
            "{probe:?}"
        );

        // The final window update sends the last 1000 bytes.
        f.on_inner(
            &seg(11, 2101, packet::ACK, 1000, &[]),
            t + Duration::from_secs(2),
        );
        let sent = f.actions();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            Action::Send {
                seq, data: chunk, ..
            } => {
                assert_eq!(*seq, 2101);
                assert_eq!(chunk.as_slice(), &data[2000..3000]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        f.on_inner(
            &seg(11, 3101, packet::ACK, 65535, &[]),
            t + Duration::from_secs(2),
        );
        f.actions();
        assert_eq!(f.acked_data, 3000);
        assert_eq!(f.sent_data, 3000);
        assert!(f.outbuf.is_empty());
        assert!(f.unacked.is_empty());
    }
    #[test]
    fn partial_window_update_sends_only_the_offered_bytes() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[2, 4, 3, 232], 0, t);
        f.outer_connected();
        f.actions();
        let data: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        f.outer_data(&data, t);
        f.actions();
        f.on_inner(&seg(101, 201, packet::ACK, 200, &[]), t);
        let sent = f.actions();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            Action::Send {
                seq, data: chunk, ..
            } => {
                assert_eq!(*seq, 201);
                assert_eq!(chunk.as_slice(), &data[..200]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.sent_data, 200);
        assert_eq!(f.outbuf.len(), 2800);
        // The peer acknowledges the 200 bytes and offers 1000 more.
        f.on_inner(&seg(101, 401, packet::ACK, 1000, &[]), t);
        let sent = f.actions();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            Action::Send {
                seq, data: chunk, ..
            } => {
                assert_eq!(*seq, 401);
                assert_eq!(chunk.as_slice(), &data[200..1200]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.sent_data, 1200);
        assert_eq!(f.outbuf.len(), 1800);
    }
    #[test]
    fn fin_waits_for_window_credit_and_follows_data() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[2, 4, 3, 232], 0, t);
        f.outer_connected();
        f.actions();
        f.outer_data(b"hello", t);
        f.outer_end(t);
        assert!(
            f.actions().is_empty(),
            "no data or FIN enters a zero window"
        );
        assert!(f.fin_sent_seq.is_none());
        assert!(f.fin_sent_at.is_none());
        assert_eq!(f.outbuf.len(), 5);

        let mut at = t;
        at += f.persist_interval;
        f.tick(at);
        assert!(matches!(
            &f.actions()[..],
            [Action::Send { flags, data, .. }] if *flags == packet::ACK && data.is_empty()
        ));

        // The window opens with 3 bytes. The FIN must wait for the rest of the
        // data and for one more sequence number.
        f.on_inner(&seg(101, 201, packet::ACK, 3, &[]), at);
        let sent = f.actions();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            Action::Send {
                flags, seq, data, ..
            } => {
                assert_eq!(*flags, packet::ACK | packet::PSH);
                assert_eq!(*seq, 201);
                assert_eq!(data.as_slice(), b"hel");
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.sent_data, 3);
        assert_eq!(f.outbuf.len(), 2);
        assert!(f.fin_sent_seq.is_none(), "the FIN needs a free byte");

        // The peer acknowledges the first 3 bytes and offers 3 more.
        f.on_inner(&seg(101, 204, packet::ACK, 3, &[]), at);
        let sent = f.actions();
        assert_eq!(sent.len(), 2);
        match &sent[0] {
            Action::Send {
                seq, data, flags, ..
            } => {
                assert_eq!(*seq, 204);
                assert_eq!(data.as_slice(), b"lo");
                assert_eq!(*flags, packet::ACK | packet::PSH);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        match &sent[1] {
            Action::Send {
                flags, seq, data, ..
            } => {
                assert_eq!(*flags, packet::ACK | packet::FIN);
                assert_eq!(*seq, 206);
                assert!(data.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.sent_data, 5);
        assert!(f.outbuf.is_empty());

        // The peer acknowledges the FIN, then half-closes. The flow closes
        // when both directions are shut down.
        f.on_inner(&seg(101, 207, packet::ACK, 3, &[]), at);
        assert!(f.fin_acked);
        assert!(!f.client_fin);
        assert_eq!(f.state, State::Established);
        f.on_inner(
            &seg(101, 207, packet::ACK | packet::FIN, 3, &[]),
            at + Duration::from_millis(1),
        );
        let end = f.actions();
        assert!(end.contains(&Action::ShutdownWrite));
        assert!(end.contains(&Action::Close));
        assert_eq!(f.state, State::Closed);
    }
    #[test]
    fn pending_upload_bytes_do_not_hold_back_the_download_fin() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.on_inner(&upload(101, b"abc"), t);
        assert_eq!(f.pending_bytes(), b"abc");
        f.actions();
        f.outer_end(t);
        let actions = f.actions();
        match &actions[..] {
            [Action::Send {
                flags, seq, data, ..
            }] => {
                assert_eq!(*flags, packet::ACK | packet::FIN);
                assert_eq!(*seq, 201);
                assert!(data.is_empty());
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(f.fin_sent_seq, Some(201));
        assert_eq!(
            f.pending_bytes(),
            b"abc",
            "the FIN must not drop upload bytes"
        );
        f.outer_written(3);
        assert!(f.pending_bytes().is_empty());
        assert!(
            !f.outer_write_shutdown,
            "the client has not closed its side"
        );
        assert_eq!(f.state, State::Established);
    }
    #[test]
    fn last_upload_write_closes_after_both_fins() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        let client_fin = TcpSegment {
            flags: packet::ACK | packet::FIN,
            ..upload(101, b"abc")
        };
        f.on_inner(&client_fin, t);
        assert!(f.client_fin);
        assert_eq!(f.pending_bytes(), b"abc");
        f.actions();
        f.outer_end(t);
        let fin = f.actions();
        assert!(
            fin.iter().any(|action| matches!(action,
                Action::Send { flags, .. } if flags & packet::FIN != 0)),
            "the download FIN must not wait for the upload: {fin:?}"
        );
        let fin_seq = f.fin_sent_seq.expect("the FIN has a sequence number");
        f.on_inner(
            &seg(105, fin_seq.wrapping_add(1), packet::ACK, 65535, &[]),
            t + Duration::from_millis(1),
        );
        assert!(f.fin_acked);
        assert!(!f.outer_write_shutdown);
        assert_eq!(f.state, State::Established);
        assert!(f.actions().is_empty());
        // The last upload byte drains after both FINs. The flow must close
        // without another inner segment.
        f.outer_written(3);
        assert_eq!(
            f.actions(),
            vec![Action::ShutdownWrite, Action::Close],
            "the shutdown must come before the close"
        );
        assert_eq!(f.state, State::Closed);
    }
    #[test]
    fn fin_retransmit_waits_for_window_recovery() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 1000, t);
        f.outer_connected();
        f.actions();
        f.outer_end(t);
        let fin = f.actions();
        match &fin[..] {
            [Action::Send {
                flags, seq, data, ..
            }] => {
                assert_eq!(*flags, packet::ACK | packet::FIN);
                assert_eq!(*seq, 201);
                assert!(data.is_empty());
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(f.fin_sent_seq, Some(201));

        // The peer acknowledges no data and closes its window. The FIN must
        // not enter it.
        f.on_inner(&seg(101, 201, packet::ACK, 0, &[]), t);
        assert!(!f.fin_acked);
        assert_eq!(f.peer_window, 0);

        let mut at = t;
        for _ in 0..u32::from(MAX_PERSIST_PROBES) / 2 {
            at += f.persist_interval;
            f.tick(at);
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, data, .. }]
                    if flags & packet::FIN == 0 && data.is_empty()),
                "the FIN must not enter a zero window: {actions:?}"
            );
        }
        assert_eq!(f.state, State::Established);

        // The peer reopens the window. The FIN retransmit waits one RTO and
        // does not advance the sequence number.
        f.on_inner(&seg(101, 201, packet::ACK, 1000, &[]), at);
        assert!(f.actions().is_empty());
        f.tick(at + RTO_MIN - Duration::from_millis(1));
        assert!(f.actions().is_empty());
        f.tick(at + RTO_MIN + Duration::from_millis(1));
        let retry = f.actions();
        match &retry[..] {
            [Action::Send {
                flags, seq, data, ..
            }] => {
                assert_eq!(*flags, packet::ACK | packet::FIN);
                assert_eq!(*seq, 201);
                assert!(data.is_empty());
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        f.on_inner(
            &seg(101, 202, packet::ACK, 1000, &[]),
            at + RTO_MIN + Duration::from_millis(1),
        );
        assert!(f.fin_acked);
        assert_eq!(f.state, State::Established);
    }
    #[test]
    fn zero_window_probe_and_window_recovery_cross_sequence_wrap() {
        let t = Instant::now();
        let isn = u32::MAX - 10;
        let mut f = TcpFlow::new(10, isn, &[2, 4, 3, 232], 30, t);
        f.outer_connected();
        f.actions();
        let data: Vec<u8> = (0..80).map(|i| (i + 1) as u8).collect();
        f.outer_data(&data, t);
        let first = f.actions();
        match &first[..] {
            [Action::Send {
                seq, data: sent, ..
            }] => {
                assert_eq!(*seq, isn.wrapping_add(1));
                assert_eq!(sent.as_slice(), &data[..30]);
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(f.sent_data, 30);
        assert_eq!(f.outbuf.len(), 50);

        // The peer accepts 15 bytes and closes the window.
        let ack15 = isn.wrapping_add(1).wrapping_add(15);
        f.on_inner(&seg(11, ack15, packet::ACK, 0, &[]), t);
        assert_eq!(f.acked_data, 15);
        assert_eq!(f.inflight(), 15);
        assert_eq!(f.peer_window, 0);

        // The probe uses SND.UNA - 1, which wraps here.
        let mut at = t;
        at += f.persist_interval;
        f.tick(at);
        let probe = f.actions();
        match &probe[..] {
            [Action::Send {
                flags,
                seq,
                data: probe_data,
                ..
            }] => {
                assert_eq!(*flags, packet::ACK);
                assert_eq!(*seq, isn.wrapping_add(15));
                assert!(probe_data.is_empty());
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(f.outbuf.len(), 50);
        assert_eq!(f.sent_data, 30);
        assert_eq!(f.acked_data, 15);

        // The window update offers 30 bytes. The 15 unacknowledged bytes use
        // half of it, so 15 new bytes cross the wrap.
        f.on_inner(&seg(11, ack15, packet::ACK, 30, &[]), at);
        let sent = f.actions();
        match &sent[..] {
            [Action::Send {
                seq, data: chunk, ..
            }] => {
                assert_eq!(*seq, isn.wrapping_add(1).wrapping_add(30));
                assert_eq!(chunk.as_slice(), &data[30..45]);
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(f.sent_data, 45);
        assert_eq!(f.outbuf.len(), 35);
        assert_eq!(f.inflight(), 30);

        // Acknowledge every byte and close the window again.
        let ack45 = isn.wrapping_add(1).wrapping_add(45);
        let at2 = at + Duration::from_millis(1);
        f.on_inner(&seg(11, ack45, packet::ACK, 0, &[]), at2);
        assert_eq!(f.acked_data, 45);
        assert_eq!(f.inflight(), 0);
        assert_eq!(f.outbuf.len(), 35);
        let at3 = at2 + PERSIST_MIN;
        f.tick(at3);
        let probe = f.actions();
        match &probe[..] {
            [Action::Send {
                flags,
                seq,
                data: probe_data,
                ..
            }] => {
                assert_eq!(*flags, packet::ACK);
                assert_eq!(*seq, isn.wrapping_add(45));
                assert!(probe_data.is_empty());
            }
            other => panic!("unexpected actions: {other:?}"),
        }

        // The window offers 30 more bytes. 30 new bytes cross the wrap.
        f.on_inner(
            &seg(11, ack45, packet::ACK, 30, &[]),
            at3 + Duration::from_millis(1),
        );
        let sent = f.actions();
        match &sent[..] {
            [Action::Send {
                seq, data: chunk, ..
            }] => {
                assert_eq!(*seq, isn.wrapping_add(1).wrapping_add(45));
                assert_eq!(chunk.as_slice(), &data[45..75]);
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(f.sent_data, 75);
        assert_eq!(f.outbuf.len(), 5);
        assert_eq!(f.inflight(), 30);

        // Acknowledge all 75 bytes, close the window, and defer the FIN.
        let ack75 = isn.wrapping_add(1).wrapping_add(75);
        let at4 = at3 + Duration::from_millis(2);
        f.on_inner(&seg(11, ack75, packet::ACK, 0, &[]), at4);
        assert_eq!(f.acked_data, 75);
        assert_eq!(f.inflight(), 0);
        assert_eq!(f.outbuf.len(), 5);
        f.outer_end(at4);
        assert!(f.actions().is_empty());
        assert!(f.fin_sent_seq.is_none());

        // The last window update sends 5 bytes and then the FIN. Both cross
        // the wrap and keep order.
        f.on_inner(
            &seg(11, ack75, packet::ACK, 30, &[]),
            at4 + Duration::from_millis(1),
        );
        let sent = f.actions();
        assert_eq!(sent.len(), 2);
        match &sent[0] {
            Action::Send {
                seq, data: chunk, ..
            } => {
                assert_eq!(*seq, isn.wrapping_add(1).wrapping_add(75));
                assert_eq!(chunk.as_slice(), &data[75..80]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        let fin_seq = isn.wrapping_add(1).wrapping_add(80);
        match &sent[1] {
            Action::Send {
                flags, seq, data, ..
            } => {
                assert_eq!(*flags, packet::ACK | packet::FIN);
                assert_eq!(*seq, fin_seq);
                assert!(data.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(f.sent_data, 80);
        assert_eq!(f.fin_sent_seq, Some(fin_seq));

        f.on_inner(
            &seg(11, fin_seq.wrapping_add(1), packet::ACK, 30, &[]),
            at4 + Duration::from_millis(2),
        );
        assert_eq!(f.acked_data, 80);
        assert!(f.fin_acked);
        assert_eq!(f.state, State::Established);
        assert!(f.unacked.is_empty());
        assert!(f.outbuf.is_empty());
    }
    #[test]
    fn over_ack_is_dropped_before_it_can_advance_or_close() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.outer_data(b"abcdef", t);
        f.actions();
        f.outer_end(t);
        f.actions();
        let over = f.next_seq().wrapping_add(1);
        // The over-ACK also carries data and a FIN. The whole segment must be
        // dropped, not only the acknowledgment field.
        f.on_inner(&seg(101, over, packet::ACK | packet::FIN, 0, b"evil"), t);
        assert_eq!(f.acked_data, 0);
        assert_eq!(f.inflight(), 6);
        assert!(!f.fin_acked);
        assert!(!f.client_fin);
        assert!(f.pending_bytes().is_empty());
        assert_eq!(f.peer_window, 65535, "the over-ACK window is not current");
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert!(
            matches!(&actions[..], [Action::Send { flags, ack, data, .. }]
                if *flags == packet::ACK && *ack == f.cseq && data.is_empty()),
            "the peer must receive a challenge ACK: {actions:?}"
        );
        assert!(!actions.contains(&Action::Close));
    }
    #[test]
    fn over_ack_cannot_close_a_flow_that_waits_for_its_fin() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        // The client half-closes first and the upload direction is empty.
        f.on_inner(&seg(101, 201, packet::ACK | packet::FIN, 65535, &[]), t);
        assert!(f.client_fin);
        assert!(f.outer_write_shutdown);
        f.actions();
        f.outer_end(t);
        assert!(f.fin_sent_seq.is_some());
        f.actions();
        let over = f.next_seq().wrapping_add(1);
        f.on_inner(&seg(102, over, packet::ACK, 65535, &[]), t);
        assert!(!f.fin_acked);
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Send { flags, .. }
                    if *flags == packet::ACK)),
            "the peer must receive a challenge ACK: {actions:?}"
        );
        assert!(!actions.contains(&Action::Close));
    }
    #[test]
    fn over_ack_is_rejected_across_the_sequence_wrap() {
        let t = Instant::now();
        let isn = u32::MAX - 3;
        let mut f = TcpFlow::new(100, isn, &[], 65535, t);
        f.outer_connected();
        f.outer_data(b"abcdef", t);
        f.actions();
        let nxt = f.next_seq();
        assert_eq!(nxt, isn.wrapping_add(7));
        // An ACK at SND.NXT is valid even though it wrapped to a small value.
        f.on_inner(&seg(101, nxt, packet::ACK, 65535, &[]), t);
        assert_eq!(f.acked_data, 6);
        assert_eq!(f.inflight(), 0);
        // More data crosses the wrap again. One byte beyond SND.NXT is an
        // over-ACK and must not reach the new data or the window.
        f.outer_data(b"ghij", t + Duration::from_millis(1));
        f.actions();
        let nxt = f.next_seq();
        f.on_inner(
            &seg(101, nxt.wrapping_add(1), packet::ACK, 0, &[]),
            t + Duration::from_millis(2),
        );
        assert_eq!(f.acked_data, 6);
        assert_eq!(f.inflight(), 4);
        assert_eq!(f.peer_window, 65535);
        assert_eq!(f.state, State::Established);
        assert!(matches!(&f.actions()[..],
            [Action::Send { flags, data, .. }]
                if *flags == packet::ACK && data.is_empty()));
    }
    #[test]
    fn window_update_rejects_the_same_ack_from_an_older_segment() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 100, t);
        f.outer_connected();
        assert_eq!((f.window_seq, f.window_ack), (100, 201));
        assert!(f.on_ack(201, 500, 101, t));
        assert_eq!(f.peer_window, 500);
        assert_eq!((f.window_seq, f.window_ack), (101, 201));
        // The same ACK from an older segment must not replace the window.
        assert!(f.on_ack(201, 0, 100, t));
        assert_eq!(f.peer_window, 500);
        assert_eq!((f.window_seq, f.window_ack), (101, 201));
        // The same ACK and sequence number can refresh the window report.
        assert!(f.on_ack(201, 700, 101, t));
        assert_eq!(f.peer_window, 700);
        assert_eq!((f.window_seq, f.window_ack), (101, 201));
    }
    #[test]
    fn window_update_compares_segment_sequence_numbers_across_wrap() {
        let t = Instant::now();
        let client_isn = u32::MAX - 2;
        let mut f = TcpFlow::new(client_isn, 200, &[], 100, t);
        f.outer_connected();
        assert_eq!(f.window_seq, client_isn);
        assert!(f.on_ack(201, 400, u32::MAX, t));
        assert_eq!(f.peer_window, 400);
        // u32::MAX - 1 is older than u32::MAX in serial order.
        assert!(f.on_ack(201, 0, u32::MAX - 1, t));
        assert_eq!(f.peer_window, 400);
        // Sequence 0 follows u32::MAX in serial order.
        assert!(f.on_ack(201, 600, 0, t));
        assert_eq!(f.peer_window, 600);
        assert_eq!((f.window_seq, f.window_ack), (0, 201));
    }
    #[test]
    fn window_update_accepts_ack_wrap_with_the_same_sequence_number() {
        let t = Instant::now();
        let isn = u32::MAX - 2;
        let mut f = TcpFlow::new(100, isn, &[], 100, t);
        f.outer_connected();
        let una = isn.wrapping_add(1);
        assert!(f.on_ack(una, 300, 101, t));
        assert_eq!(f.peer_window, 300);
        f.outer_data(&[7u8; 10], t);
        f.actions();
        let nxt = f.next_seq();
        assert_eq!(nxt, isn.wrapping_add(11));
        // The new ACK is numerically small but newer than SND.UNA.
        assert!(f.on_ack(nxt, 800, 101, t));
        assert_eq!(f.acked_data, 10);
        assert_eq!(f.peer_window, 800);
        // A stale ACK before the wrap must not shrink the window.
        assert!(f.on_ack(una, 0, 101, t));
        assert_eq!(f.peer_window, 800);
    }
    #[test]
    fn stale_window_update_cannot_hide_a_newer_open_window() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[2, 4, 3, 232], 1000, t);
        f.outer_connected();
        f.actions();
        f.outer_data(&[9u8; 5000], t);
        assert_eq!(f.actions().len(), 1);
        assert_eq!(f.sent_data, 1000);

        // Accept the first 1000 bytes and open a large window.
        f.on_inner(&seg(11, 1101, packet::ACK, 5000, &[]), t);
        assert_eq!(f.acked_data, 1000);
        assert_eq!(f.peer_window, 5000);
        assert_eq!(f.actions().len(), 4);
        assert_eq!(f.sent_data, 5000);
        f.actions();

        // A delayed segment with an older acknowledgment carries a zero
        // window. It must not close the newer window.
        f.on_inner(
            &seg(11, 101, packet::ACK, 0, &[]),
            t + Duration::from_millis(1),
        );
        assert_eq!(f.peer_window, 5000);
        assert_eq!(f.state, State::Established);
        f.tick(t + Duration::from_millis(100));
        assert!(f.actions().is_empty());
    }
    #[test]
    fn reset_during_zero_window_persist_closes_and_stops_probes() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.outer_data(b"queued", t);
        f.actions();
        let at = t + PERSIST_MIN;
        f.tick(at);
        assert_eq!(f.actions().len(), 1);
        f.on_inner(&seg(101, 201, packet::RST, 0, &[]), at);
        assert_eq!(f.state, State::Closed);
        assert!(f.actions().contains(&Action::Close));
        f.tick(at + PERSIST_MAX * 8);
        assert!(f.actions().is_empty());
        assert!(f.persist_at.is_none());
        assert_eq!(f.persist_probes, 0);
    }
    #[test]
    fn zero_window_backpressure_keeps_the_output_bound() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.actions();
        f.outer_data(&vec![1; OUTBUF_HARD_LIMIT], t);
        assert_eq!(f.state, State::Established);
        assert_eq!(f.outbuf.len(), OUTBUF_HARD_LIMIT);
        assert!(f.actions().is_empty());
        // One byte more would exceed the bound. The flow resets and never
        // drops a prefix without a signal.
        f.outer_data(&[2], t);
        assert_eq!(f.state, State::Closed);
        assert_eq!(f.outbuf.len(), OUTBUF_HARD_LIMIT);
        let actions = f.actions();
        assert!(actions.iter().any(
            |action| matches!(action, Action::Send { flags, .. } if flags & packet::RST != 0)
        ));
        assert!(actions.contains(&Action::Close));
    }
    #[test]
    fn idle_probe_does_not_preempt_data_retransmission() {
        let t = Instant::now();
        let mut f = TcpFlow::new(10, 100, &[], 65535, t);
        f.outer_connected();
        f.outer_data(b"pending", t);
        f.actions();
        f.tick(t + IDLE_PROBE_AFTER + Duration::from_secs(1));
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert!(
            matches!(&actions[..], [Action::Send { data, .. }] if data == b"pending"),
            "the retransmit must run before an idle probe: {actions:?}"
        );
    }
    #[test]
    fn acked_fin_flow_is_still_probed_when_the_peer_goes_silent() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.outer_end(t);
        let fin = f.actions();
        assert!(
            fin.iter().any(
                |action| matches!(action, Action::Send { flags, .. } if flags & packet::FIN != 0)
            ),
            "{fin:?}"
        );
        // The inner peer acknowledges the FIN and then stays silent.
        f.on_inner(
            &TcpSegment {
                ack: 202,
                ..upload(101, &[])
            },
            t,
        );
        assert!(f.fin_acked);
        f.actions();
        f.tick(t + IDLE_PROBE_AFTER + Duration::from_secs(1));
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert!(
            matches!(&actions[..], [Action::Send { flags, data, .. }]
                if *flags == packet::ACK && data.is_empty()),
            "an acked FIN flow still needs idle probes: {actions:?}"
        );
    }
    #[test]
    fn silent_zero_window_without_work_is_probed_and_reset() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.actions();
        let first = t + IDLE_PROBE_AFTER + Duration::from_secs(1);
        for probe in 0..u32::from(MAX_IDLE_PROBES) {
            let at = first + IDLE_PROBE_INTERVAL * probe;
            f.tick(at);
            assert_eq!(f.state, State::Established, "probe {probe}");
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, seq, data, .. }]
                    if *flags == packet::ACK && *seq == 200 && data.is_empty()),
                "probe {probe}: {actions:?}"
            );
            assert_eq!(f.persist_probes, 0, "no work uses the idle probe");
        }
        f.tick(first + IDLE_PROBE_INTERVAL * u32::from(MAX_IDLE_PROBES));
        assert_eq!(f.state, State::Closed);
        let actions = f.actions();
        assert!(actions.iter().any(
            |action| matches!(action, Action::Send { flags, .. } if flags & packet::RST != 0)
        ));
        assert!(actions.contains(&Action::Close));
    }
    #[test]
    fn responsive_zero_window_without_work_stays_open() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 0, t);
        f.outer_connected();
        f.actions();
        let mut at = t + IDLE_PROBE_AFTER + Duration::from_secs(1);
        for cycle in 0..u32::from(MAX_IDLE_PROBES) + 3 {
            f.tick(at);
            assert_eq!(f.state, State::Established, "cycle {cycle}");
            let actions = f.actions();
            assert!(
                matches!(&actions[..], [Action::Send { flags, seq, data, .. }]
                    if *flags == packet::ACK && *seq == 200 && data.is_empty()),
                "cycle {cycle}: {actions:?}"
            );
            // A paused reader still answers with its current zero window.
            f.on_inner(&seg(101, 201, packet::ACK, 0, &[]), at);
            assert!(f.actions().is_empty(), "cycle {cycle}");
            assert_eq!(f.state, State::Established, "cycle {cycle}");
            at += IDLE_PROBE_AFTER + Duration::from_secs(1);
        }
    }
    #[test]
    fn acked_fin_with_a_zero_window_is_still_probed() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        f.actions();
        f.outer_end(t);
        let fin_seq = f.fin_sent_seq.expect("the FIN is sent");
        f.actions();
        f.on_inner(&seg(101, fin_seq.wrapping_add(1), packet::ACK, 0, &[]), t);
        assert!(f.fin_acked);
        assert_eq!(f.peer_window, 0);
        assert_eq!(f.state, State::Established);
        f.tick(t + IDLE_PROBE_AFTER + Duration::from_secs(1));
        assert_eq!(f.state, State::Established);
        let actions = f.actions();
        assert!(
            matches!(&actions[..], [Action::Send { flags, seq, data, .. }]
                if *flags == packet::ACK && *seq == fin_seq && data.is_empty()),
            "an acked FIN with a zero window still needs a probe: {actions:?}"
        );
    }
    #[test]
    fn half_closed_flow_is_probed_and_keeps_its_open_direction() {
        let t = Instant::now();
        let mut f = TcpFlow::new(100, 200, &[], 65535, t);
        f.outer_connected();
        let fin = TcpSegment {
            flags: packet::ACK | packet::FIN,
            ..upload(101, &[])
        };
        f.on_inner(&fin, t);
        assert!(f.client_fin);
        assert!(f.actions().contains(&Action::ShutdownWrite));
        f.tick(t + IDLE_PROBE_AFTER + Duration::from_secs(1));
        assert_eq!(f.state, State::Established);
        let probe = f.actions();
        assert!(
            matches!(&probe[..], [Action::Send { flags, data, .. }]
                if *flags == packet::ACK && data.is_empty()),
            "{probe:?}"
        );
        // The source direction still carries bytes after the probe.
        f.outer_data(b"response", t + IDLE_PROBE_AFTER + Duration::from_secs(2));
        let sent = f.actions();
        assert!(
            sent.iter()
                .any(|action| matches!(action, Action::Send { data, .. } if data == b"response")),
            "{sent:?}"
        );
        assert_eq!(f.state, State::Established);
    }
    #[test]
    fn unanswered_fin_retries_end_with_a_reset() {
        let t = Instant::now();
        let mut flow = TcpFlow::new(100, 200, &[], 65535, t);
        flow.outer_connected();
        flow.actions();
        flow.outer_end(t);
        let first = flow.actions();
        assert!(first.iter().any(|action| matches!(action,
            Action::Send { flags, .. } if flags & packet::FIN != 0)));
        for retry in 1..=u64::from(MAX_RETX) {
            flow.tick(t + Duration::from_secs(3 * retry));
            let actions = flow.actions();
            assert!(
                actions.iter().any(|action| matches!(action,
                Action::Send { flags, .. } if flags & packet::FIN != 0)),
                "retry {retry}: {actions:?}"
            );
            assert_eq!(flow.state, State::Established);
        }
        flow.tick(t + Duration::from_secs(3 * (u64::from(MAX_RETX) + 1)));
        let actions = flow.actions();
        assert_eq!(flow.state, State::Closed);
        assert!(actions.iter().any(|action| matches!(action,
            Action::Send { flags, .. } if flags & packet::RST != 0)));
        assert!(actions.contains(&Action::Close));
    }
}
