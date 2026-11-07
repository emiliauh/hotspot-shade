//! Bounded timing reservoirs, the established-flow timeline, and the
//! diagnostics JSON shape.
//!
//! The data path records samples with atomics only. A reader never blocks a
//! writer. The reservoir holds the last 512 samples of one metric. The timeline
//! holds the last 60 one-second buckets of established-flow events. All data
//! stays in target device memory and holds no address, host name, token, or
//! key.
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

/// The number of samples that one metric keeps.
pub const RESERVOIR: usize = 512;

/// The destination-privacy mode names. The engine, the desktop apps, the
/// phone apps, and the local page use these four names and no others.
pub const DESTINATION_PRIVACY_MODES: [&str; 4] = ["off", "shape", "hide", "cover"];

/// This build implements the mechanism.
pub const CAP_SUPPORTED: &str = "supported";
/// This build has no such code path.
pub const CAP_UNSUPPORTED: &str = "unsupported";
/// The platform or the build configuration cannot provide the mechanism.
pub const CAP_UNAVAILABLE: &str = "unavailable";
/// The code path exists, but this project has no live evidence for it.
pub const CAP_UNVERIFIED: &str = "unverified";

/// The length of one established-flow bucket.
pub const ESTABLISHED_BUCKET_SECONDS: u64 = 1;

/// The number of recent established-flow buckets.
pub const ESTABLISHED_WINDOW: usize = 60;

/// One event in the established-flow timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineEvent {
    /// A worker observed at least one established flow.
    Observed,
    /// The inner TCP flow retransmitted data or a FIN.
    TcpRetransmit,
    /// The inner TCP receive window stayed full for this many microseconds.
    WindowLimitedUs(u64),
    /// An established TCP flow closed.
    TcpTeardown,
    /// A UDP flow closed. A UDP flow has no handshake, so setup counts too.
    UdpTeardown,
    /// A UDP flow or datagram was dropped inside the relay.
    UdpDrop,
    /// A packet was dropped at a queue or could not be constructed.
    RelayDrop,
    /// An outer TCP socket read or write failed.
    OuterError,
}

/// One recent bucket with no address, host, or payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimelineBucket {
    /// The age in seconds. Zero is the current, partial bucket.
    pub age_s: u64,
    /// True when a worker observed an established flow in this second.
    pub observed: bool,
    pub tcp_retransmits: u64,
    pub window_limited_ms: u64,
    pub tcp_teardowns: u64,
    pub udp_teardowns: u64,
    pub udp_drops: u64,
    pub relay_drops: u64,
    pub outer_errors: u64,
}

/// One atomic slot. The high 32 bits hold the second. The low 32 bits hold the
/// count. A new second changes the high bits, so a stale count cannot leak into
/// a later bucket.
#[derive(Default)]
struct TimelineSlot {
    observed: AtomicU64,
    tcp_retransmits: AtomicU64,
    window_limited_us: AtomicU64,
    tcp_teardowns: AtomicU64,
    udp_teardowns: AtomicU64,
    udp_drops: AtomicU64,
    relay_drops: AtomicU64,
    outer_errors: AtomicU64,
}

impl TimelineSlot {
    fn cell(&self, event: TimelineEvent) -> &AtomicU64 {
        match event {
            TimelineEvent::Observed => &self.observed,
            TimelineEvent::TcpRetransmit => &self.tcp_retransmits,
            TimelineEvent::WindowLimitedUs(_) => &self.window_limited_us,
            TimelineEvent::TcpTeardown => &self.tcp_teardowns,
            TimelineEvent::UdpTeardown => &self.udp_teardowns,
            TimelineEvent::UdpDrop => &self.udp_drops,
            TimelineEvent::RelayDrop => &self.relay_drops,
            TimelineEvent::OuterError => &self.outer_errors,
        }
    }
    fn amount(&self, event: TimelineEvent) -> u64 {
        match event {
            TimelineEvent::WindowLimitedUs(us) => us,
            _ => 1,
        }
    }
}

/// Add one amount for a second without a lock. A writer never waits for a
/// reader. A later second resets the count in the same atomic step.
///
/// A delayed writer can arrive after a newer second used the same ring slot.
/// An older generation must not replace the newer one. Keep the newer count.
fn add(slot: &AtomicU64, second: u64, amount: u64) {
    if amount == 0 {
        return;
    }
    let second = second.min(u32::MAX as u64);
    let generation = second << 32;
    loop {
        let current = slot.load(Ordering::Relaxed);
        let current_second = current >> 32;
        if current_second > second {
            // A delayed writer from an older bucket must not erase a newer
            // bucket that reused the same ring slot.
            return;
        }
        let base = if current_second == second {
            current & 0xffff_ffff
        } else {
            0
        };
        let next = generation | base.saturating_add(amount).min(u32::MAX as u64);
        match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(_) => continue,
        }
    }
}

fn get(slot: &AtomicU64, second: u64) -> u64 {
    let value = slot.load(Ordering::Relaxed);
    if value >> 32 == second {
        value & 0xffff_ffff
    } else {
        0
    }
}

/// A bounded one-second timeline of established-flow events.
///
/// The data path records with atomics only. The reader sees real recent
/// values. A bucket with `observed == false` means that no worker saw an
/// established flow. It does not mean that the path was healthy.
pub struct EventTimeline {
    origin: Instant,
    slots: [TimelineSlot; ESTABLISHED_WINDOW],
}
impl Default for EventTimeline {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}
impl EventTimeline {
    pub fn new(origin: Instant) -> Self {
        Self {
            origin,
            slots: std::array::from_fn(|_| TimelineSlot::default()),
        }
    }
    /// Record one event at this time.
    pub fn record(&self, now: Instant, event: TimelineEvent) {
        self.record_count(now, event, 1);
    }
    /// Record `count` events at this time. A window sample uses count 1 and
    /// keeps its microsecond value in `TimelineEvent`.
    pub fn record_count(&self, now: Instant, event: TimelineEvent, count: u64) {
        let seconds =
            now.saturating_duration_since(self.origin).as_secs() / ESTABLISHED_BUCKET_SECONDS;
        let slot = &self.slots[(seconds as usize) % ESTABLISHED_WINDOW];
        let amount = slot.amount(event).saturating_mul(count);
        add(slot.cell(event), seconds, amount);
    }
    /// The recent buckets, oldest first. The last bucket is the current second.
    /// A relay that just started has fewer buckets. A bucket that is absent
    /// was before the relay started, so it is not an observation.
    pub fn snapshot(&self, now: Instant) -> Vec<TimelineBucket> {
        let current =
            now.saturating_duration_since(self.origin).as_secs() / ESTABLISHED_BUCKET_SECONDS;
        let first = current.saturating_sub(ESTABLISHED_WINDOW as u64 - 1);
        (first..=current)
            .map(|second| {
                let slot = &self.slots[(second as usize) % ESTABLISHED_WINDOW];
                TimelineBucket {
                    age_s: current - second,
                    observed: get(&slot.observed, second) > 0,
                    tcp_retransmits: get(&slot.tcp_retransmits, second),
                    window_limited_ms: get(&slot.window_limited_us, second) / 1000,
                    tcp_teardowns: get(&slot.tcp_teardowns, second),
                    udp_teardowns: get(&slot.udp_teardowns, second),
                    udp_drops: get(&slot.udp_drops, second),
                    relay_drops: get(&slot.relay_drops, second),
                    outer_errors: get(&slot.outer_errors, second),
                }
            })
            .collect()
    }
}

/// A lock-free ring of recent microsecond samples.
pub struct Reservoir {
    slots: [AtomicU32; RESERVOIR],
    next: AtomicUsize,
    count: AtomicU64,
}
impl Default for Reservoir {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU32::new(0)),
            next: AtomicUsize::new(0),
            count: AtomicU64::new(0),
        }
    }
}
impl Reservoir {
    /// Record one sample. This call never waits for a reader.
    pub fn record(&self, microseconds: u64) {
        let value = microseconds.min(u32::MAX as u64) as u32;
        let index = self.next.fetch_add(1, Ordering::Relaxed) % RESERVOIR;
        self.slots[index].store(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    /// The total number of recorded samples, including overwritten samples.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
    /// Copy the samples that are present. A concurrent writer can replace a
    /// slot during the copy. Every copied value is a real recent sample.
    fn samples(&self) -> Vec<u32> {
        let present = (self.count.load(Ordering::Relaxed) as usize).min(RESERVOIR);
        (0..present)
            .map(|index| self.slots[index].load(Ordering::Relaxed))
            .collect()
    }
    /// The last samples in no particular order. Tests use this form.
    pub fn values(&self) -> Vec<u32> {
        self.samples()
    }
    /// A `count`, `p50`, `p95`, `max` object in milliseconds.
    pub fn metric_ms(&self) -> Value {
        let mut values = self.samples();
        let count = self.count.load(Ordering::Relaxed);
        if values.is_empty() {
            return zero_metric();
        }
        values.sort_unstable();
        let pick = |percent: usize| -> u64 {
            let n = values.len();
            let rank = (percent * n).div_ceil(100).max(1);
            (values[rank - 1] / 1000) as u64
        };
        json!({
            "count": count,
            "p50": pick(50),
            "p95": pick(95),
            "max": (values[values.len() - 1] / 1000) as u64,
        })
    }
}

/// The zero object for one timing metric.
pub fn zero_metric() -> Value {
    json!({"count":0,"p50":0,"p95":0,"max":0})
}

/// The zero object for one queue.
pub fn zero_queue() -> Value {
    json!({"peak":0,"max_age_us":0})
}

/// The support state of every destination-privacy mode in this build.
///
/// Only `off` is supported. The relay copies bytes unchanged and the engine has
/// no TLS client, so `shape`, `hide`, and `cover` report `unsupported`. A build
/// that implements one mode changes that mode here. Never report a mode as
/// supported before its code path and its hermetic tests exist.
pub fn destination_privacy_modes() -> Value {
    json!({
        "off": CAP_SUPPORTED,
        "shape": CAP_UNSUPPORTED,
        "hide": CAP_UNSUPPORTED,
        "cover": CAP_UNSUPPORTED,
    })
}

/// Whether the target engine continues after its controlling app exits.
///
/// Parent-liveness handling shuts the engine down; this does not describe
/// hiding a window while its app remains open, such as a Linux tray session.
pub fn background_relay_capability() -> &'static str {
    CAP_UNSUPPORTED
}

/// The destination-privacy capability row that `probe`, `/api/status`, and the
/// local page report.
///
/// It holds fixed tokens only. It never holds a destination name, an address, a
/// certificate, or an ECH config. `mode` is the mode in effect now. Every build
/// starts at `off`, because every other mode is opt-in.
pub fn destination_privacy_capability() -> Value {
    json!({
        "mode": "off",
        "default_mode": "off",
        "modes": destination_privacy_modes(),
        "sni_override": CAP_UNSUPPORTED,
        "ech": CAP_UNSUPPORTED,
        "background_relay": background_relay_capability(),
    })
}

/// The zero destination-privacy counters.
///
/// Every counter stays zero while only `off` is supported: the engine never
/// records one of these events. The keys are the stable contract, so a reader
/// can rely on their presence. A counter is an event count only. It never
/// carries a name, an address, a certificate, or an ECH config.
pub fn zero_destination_privacy_counters() -> Value {
    json!({
        // Inner TCP flows that ran while a mode other than `off` was active.
        "flows": 0,
        // Flows whose first record or records were re-framed.
        "shaped_flows": 0,
        // Flows where re-framing did not complete and bytes went unchanged.
        "shaped_errors": 0,
        // Handshakes that started with an ECH config.
        "ech_attempts": 0,
        // Handshakes where the server accepted ECH.
        "ech_ok": 0,
        // Handshakes that sent GREASE because no config was available.
        "ech_grease": 0,
        // Handshakes where the server rejected ECH.
        "ech_rejected": 0,
        // Fresh-flow retries without ECH after a rejection or a stall.
        "ech_fallback": 0,
        // HTTPS or SVCB lookups over DoH.
        "doh_lookups": 0,
        "doh_ok": 0,
        "doh_failed": 0,
        // Flows sent through the endpoint the user owns.
        "cover_flows": 0,
        // Endpoint setups that failed.
        "cover_errors": 0,
    })
}

/// The destination-privacy diagnostics section.
///
/// `mode` is one of `DESTINATION_PRIVACY_MODES`. `counters` holds integers
/// only. The relay reports the same object with its own counters.
pub fn destination_privacy() -> Value {
    json!({
        "mode": "off",
        "counters": zero_destination_privacy_counters(),
    })
}

/// The complete diagnostics shape when no relay runs.
pub fn empty() -> Value {
    json!({
        "ok": true,
        "running": false,
        "engine": {
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_s": 0,
            "workers": 0,
        },
        "setup": {
            "connect_ms": zero_metric(),
            "greeting_ms": zero_metric(),
            "auth_ms": zero_metric(),
            "request_ms": zero_metric(),
        },
        "dns": {
            "lookups": 0,
            "ok": 0,
            "failed": 0,
            "ms": zero_metric(),
        },
        "queues": {
            "input": [zero_queue()],
            "output": zero_queue(),
        },
        "udp": {
            "flows": 0,
            "age_drops": 0,
            "evicted": 0,
        },
        "tcp": {
            "flows_active": 0,
            "flows_peak": 0,
            "retransmits": 0,
            "zero_window_ms": 0,
            "capacity_refused": 0,
        },
        "destination_privacy": destination_privacy(),
        "established": {
            "bucket_s": ESTABLISHED_BUCKET_SECONDS,
            "window_s": ESTABLISHED_WINDOW,
            "buckets": [],
        },
        "failures": {
            "total": 0,
            "dropped": 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn percentiles_use_nearest_rank() {
        let r = Reservoir::default();
        for value in 1..=100u64 {
            r.record(value * 1000);
        }
        let m = r.metric_ms();
        assert_eq!(m["count"], 100);
        assert_eq!(m["p50"], 50);
        assert_eq!(m["p95"], 95);
        assert_eq!(m["max"], 100);
    }

    #[test]
    fn reservoir_keeps_the_last_512_and_counts_every_sample() {
        let r = Reservoir::default();
        for value in 1..=600u64 {
            r.record(value);
        }
        assert_eq!(r.count(), 600);
        let values = r.values();
        assert_eq!(values.len(), RESERVOIR);
        assert!(values.iter().all(|value| *value > 87));
        let m = r.metric_ms();
        assert_eq!(m["count"], 600);
    }

    #[test]
    fn empty_shape_has_every_contract_key_and_no_data() {
        let value = empty();
        assert_eq!(value["ok"], true);
        assert_eq!(value["running"], false);
        for key in [
            "engine",
            "setup",
            "dns",
            "queues",
            "udp",
            "tcp",
            "established",
            "failures",
            "destination_privacy",
        ] {
            assert!(value.get(key).is_some(), "{key}");
        }
        assert_eq!(value["established"]["bucket_s"], ESTABLISHED_BUCKET_SECONDS);
        assert_eq!(value["established"]["window_s"], ESTABLISHED_WINDOW);
        assert_eq!(value["established"]["buckets"], json!([]));
        for key in ["connect_ms", "greeting_ms", "auth_ms", "request_ms"] {
            assert_eq!(value["setup"][key], zero_metric());
        }
        assert_eq!(value["queues"]["input"][0], zero_queue());
        assert_eq!(value["queues"]["output"], zero_queue());
        assert_eq!(value["dns"]["ms"], zero_metric());
        let text = value.to_string();
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains("token"));
    }

    #[test]
    fn destination_privacy_is_off_with_zero_counters() {
        let value = empty();
        let privacy = &value["destination_privacy"];
        assert_eq!(privacy["mode"], "off");
        let counters = privacy["counters"].as_object().unwrap();
        assert_eq!(counters.len(), 13);
        assert!(counters.values().all(|count| count.as_u64() == Some(0)));
        // The section is the same object that `empty()` embeds, so a reader
        // cannot meet two shapes for one contract.
        assert_eq!(privacy, &destination_privacy());
        let text = privacy.to_string();
        for forbidden in ["example.com", "127.0.0.1", "::1", "token", "BEGIN"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn destination_privacy_capability_claims_only_what_this_build_supports() {
        let capability = destination_privacy_capability();
        assert_eq!(capability["mode"], "off");
        assert_eq!(capability["default_mode"], "off");
        // Every mode name has a state.
        let modes = capability["modes"].as_object().unwrap();
        assert_eq!(modes.len(), DESTINATION_PRIVACY_MODES.len());
        for name in DESTINATION_PRIVACY_MODES {
            assert!(modes.get(name).is_some(), "{name}");
        }
        assert_eq!(capability["modes"]["off"], CAP_SUPPORTED);
        // No mode other than `off` has a code path today.
        for name in ["shape", "hide", "cover"] {
            assert_eq!(capability["modes"][name], CAP_UNSUPPORTED, "{name}");
        }
        assert_eq!(capability["sni_override"], CAP_UNSUPPORTED);
        assert_eq!(capability["ech"], CAP_UNSUPPORTED);
        assert_eq!(capability["background_relay"], CAP_UNSUPPORTED);
        assert!(DESTINATION_PRIVACY_MODES.contains(&capability["mode"].as_str().unwrap_or("")));
        // Every state token is part of the documented vocabulary.
        let vocabulary = [
            CAP_SUPPORTED,
            CAP_UNSUPPORTED,
            CAP_UNAVAILABLE,
            CAP_UNVERIFIED,
        ];
        let mut states = vec![
            capability["sni_override"].clone(),
            capability["ech"].clone(),
            capability["background_relay"].clone(),
        ];
        states.extend(modes.values().cloned());
        for state in states {
            assert!(vocabulary.contains(&state.as_str().unwrap()), "{state}");
        }
        let text = capability.to_string();
        assert!(!text.contains("token"));
        assert!(!text.contains("127.0.0.1"));
    }

    #[test]
    fn established_timeline_separates_observation_from_events() {
        let start = Instant::now();
        let timeline = EventTimeline::new(start);
        // Second 0: no flow was observed. A zero count is not a healthy path.
        let empty = timeline.snapshot(start + Duration::from_millis(900));
        assert_eq!(empty.len(), 1);
        assert!(!empty[0].observed);
        assert_eq!(
            (
                empty[0].tcp_retransmits,
                empty[0].tcp_teardowns,
                empty[0].udp_drops,
                empty[0].relay_drops,
                empty[0].outer_errors,
            ),
            (0, 0, 0, 0, 0)
        );
        // Second 1: one established flow, one retransmit, and backpressure.
        timeline.record(start + Duration::from_millis(1100), TimelineEvent::Observed);
        timeline.record(
            start + Duration::from_millis(1200),
            TimelineEvent::TcpRetransmit,
        );
        timeline.record(
            start + Duration::from_millis(1300),
            TimelineEvent::WindowLimitedUs(2_500),
        );
        let buckets = timeline.snapshot(start + Duration::from_millis(1900));
        assert_eq!(buckets.len(), 2);
        assert!(buckets[1].observed);
        assert_eq!(buckets[1].tcp_retransmits, 1);
        assert_eq!(buckets[1].window_limited_ms, 2);
        assert_eq!(buckets[1].tcp_teardowns, 0);
        assert!(!buckets[0].observed);
    }

    #[test]
    fn established_timeline_keeps_the_window_and_does_not_leak_stale_slots() {
        let start = Instant::now();
        let timeline = EventTimeline::new(start);
        timeline.record(start + Duration::from_millis(500), TimelineEvent::UdpDrop);
        timeline.record(start + Duration::from_millis(500), TimelineEvent::RelayDrop);
        timeline.record(
            start + Duration::from_millis(500),
            TimelineEvent::OuterError,
        );
        // The same slot index after one full window must read as fresh.
        let later = start + Duration::from_secs(ESTABLISHED_WINDOW as u64);
        timeline.record(later, TimelineEvent::TcpTeardown);
        let buckets = timeline.snapshot(later);
        assert_eq!(buckets.len(), ESTABLISHED_WINDOW);
        let newest = buckets.last().unwrap();
        assert_eq!(newest.age_s, 0);
        assert_eq!(newest.tcp_teardowns, 1);
        assert_eq!(newest.udp_drops, 0);
        assert_eq!(newest.relay_drops, 0);
        assert_eq!(newest.outer_errors, 0);
        // The old bucket left the window.
        assert!(buckets.iter().all(|bucket| bucket.udp_drops == 0));
    }

    #[test]
    fn delayed_older_writer_does_not_erase_a_newer_bucket() {
        let start = Instant::now();
        let timeline = EventTimeline::new(start);
        // Second 61 and second 1 use the same ring slot. A delayed writer from
        // second 1 must not replace the newer second 61.
        timeline.record(
            start + Duration::from_secs(61),
            TimelineEvent::TcpRetransmit,
        );
        timeline.record(start + Duration::from_secs(1), TimelineEvent::TcpRetransmit);
        let buckets = timeline.snapshot(start + Duration::from_secs(61));
        let newest = buckets.last().unwrap();
        assert_eq!(newest.age_s, 0);
        assert_eq!(newest.tcp_retransmits, 1);
    }

    #[test]
    fn concurrent_writers_and_readers_do_not_lose_events() {
        let r = Arc::new(Reservoir::default());
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let r = Arc::clone(&r);
                std::thread::spawn(move || {
                    for _ in 0..2500 {
                        r.record(7);
                    }
                })
            })
            .collect();
        let reader = {
            let r = Arc::clone(&r);
            std::thread::spawn(move || {
                for _ in 0..500 {
                    let _ = r.metric_ms();
                    let _ = r.values();
                }
            })
        };
        for writer in writers {
            writer.join().unwrap();
        }
        reader.join().unwrap();
        assert_eq!(r.count(), 10_000);
        assert_eq!(r.values().len(), RESERVOIR);
    }
}
