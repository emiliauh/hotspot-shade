//! Connect the local GUI to the Rust service and administrator helper.
#[cfg(test)]
use crate::privileged;
#[cfg(target_os = "macos")]
use crate::tunnel_grant::TunnelGrant;
use crate::{
    autostop, environment,
    gui::{phone_message, GuiBackend, PROBE_FRESH},
    normalization,
    pairing::{self, Identity, PairError, PairPhase, PairView, PhoneCredentials, PhoneInfo},
    phone::PhoneProxy,
    service::Service,
};
#[cfg(any(target_os = "macos", target_os = "linux", test))]
use crate::{
    dns,
    service::{Ipv6Policy, TunOptions},
};
use serde_json::{json, Value};
use std::io;
#[cfg(test)]
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
#[cfg(test)]
use std::process::Child;
#[cfg(test)]
use std::process::{Command, Stdio};
#[cfg(test)]
use std::sync::atomic::AtomicU8;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One privileged helper process. Only macOS starts a helper.
#[cfg(test)]
struct Helper {
    stream: UnixStream,
    launcher: Child,
}

#[cfg(test)]
fn io_stage(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "helper_timeout",
        _ => "helper_disconnected",
    }
}
#[cfg(test)]
fn stderr_class(text: &str) -> u8 {
    if text.contains("panicked at") || text.contains("fatal runtime error") {
        3
    } else if text.contains("Operation not permitted") || text.contains("Permission denied") {
        2
    } else if text.contains("error:") || text.contains("execution error:") {
        1
    } else {
        0
    }
}
/// Drain child stderr and retain only an allowlisted classification.
#[cfg(test)]
fn watch_stderr(
    mut input: impl Read + Send + 'static,
    result: Arc<AtomicU8>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let mut tail = Vec::new();
        while let Ok(n) = input.read(&mut buffer) {
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&buffer[..n]);
            let class = stderr_class(&String::from_utf8_lossy(&tail));
            result.fetch_max(class, Ordering::AcqRel);
            if tail.len() > 512 {
                tail.drain(..tail.len() - 512);
            }
        }
    })
}
/// Pairing state. The credentials stay in this process memory only. No
/// status, log, or response carries the token.
#[derive(Default)]
struct PairInner {
    view: PairView,
    cancel: Option<Arc<AtomicBool>>,
    generation: u64,
    credentials: Option<PhoneCredentials>,
}
impl PairInner {
    /// The view when no pairing runs: paired if credentials exist, else idle.
    fn resting_view(&self) -> PairView {
        match &self.credentials {
            Some(c) => PairView {
                phase: PairPhase::Paired,
                host: Some(c.host),
                port: Some(c.port),
                ..PairView::default()
            },
            None => PairView::default(),
        }
    }
}

/// The hotspot gateway and the interface index. The phone is the gateway.
type GatewayCache = Mutex<Option<(Instant, Option<(Ipv4Addr, u32)>)>>;
type IfaceCache = Mutex<Option<(Instant, Option<String>)>>;
type HelperSession = (Arc<AtomicBool>, Arc<Mutex<Option<UnixStream>>>);

/// The source device and physical interface that one phone tunnel started
/// with. A presence probe uses it for the whole run, so a changed default
/// route cannot point the probe at another network. The target holds no token.
/// A phone run always pins. `iface` is None when the pinned name is missing or
/// cannot be resolved to an index. That is an unknown pin, not permission to
/// probe without a pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProbeTarget {
    host: Ipv4Addr,
    iface: Option<u32>,
}

const UNKNOWN_PROBE_TARGET: ProbeTarget = ProbeTarget {
    host: Ipv4Addr::UNSPECIFIED,
    iface: None,
};

fn probe_target(host: Ipv4Addr, iface: Option<&str>) -> ProbeTarget {
    ProbeTarget {
        host,
        iface: iface.and_then(|name| normalization::interface_index(name).ok()),
    }
}

/// The physical default route at the moment a token-bearing connection starts.
/// The source device is always the current hotspot gateway. A saved gateway
/// from an earlier network is not evidence that the phone is still there.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HotspotRoute {
    host: Ipv4Addr,
    iface: String,
    index: u32,
}

/// Tests replace this with a route that does not depend on the host network.
type RouteLookup = Arc<dyn Fn() -> Option<HotspotRoute> + Send + Sync>;

/// Read the default route without the 30 second cache. The cached discovery
/// feeds status and presence, but a start or a token check must see the network
/// as it is now.
fn discover_hotspot_route() -> Option<HotspotRoute> {
    let route = environment::default_route().ok()?;
    let index = normalization::interface_index(&route.interface).ok()?;
    Some(HotspotRoute {
        host: route.gateway?,
        iface: route.interface,
        index,
    })
}

/// Cache a real answer for 30 seconds. The presence probe runs every 2 seconds
/// and would otherwise start `/sbin/route` on every probe. One route lookup
/// per 30 seconds is enough to notice a new hotspot, and the probe stays cheap.
const GATEWAY_CACHE_TTL: Duration = Duration::from_secs(30);
/// Cache a missing answer for one probe period only. A hotspot that is still
/// joining has no default route for a moment. A long negative cache would
/// report no hotspot for 30 seconds, and the auto-stop policy would turn off a
/// tunnel whose link is up.
const GATEWAY_MISS_TTL: Duration = Duration::from_secs(1);

fn gateway_ttl(value: &Option<(Ipv4Addr, u32)>) -> Duration {
    match value {
        Some(_) => GATEWAY_CACHE_TTL,
        None => GATEWAY_MISS_TTL,
    }
}

fn iface_ttl(value: &Option<String>) -> Duration {
    match value {
        Some(_) => GATEWAY_CACHE_TTL,
        None => GATEWAY_MISS_TTL,
    }
}

/// Return one cached value, or run the lookup. A missing value has its own
/// short lifetime, so a transient failure is retried soon. A poisoned cache
/// is treated as a miss.
fn cached_value<T: Clone>(
    cache: &Mutex<Option<(Instant, T)>>,
    now: Instant,
    ttl: impl Fn(&T) -> Duration,
    lookup: impl FnOnce() -> T,
) -> Option<T> {
    let mut cache = cache.lock().ok()?;
    if let Some((at, value)) = cache.as_ref() {
        if now.saturating_duration_since(*at) < ttl(value) {
            return Some(value.clone());
        }
    }
    let value = lookup();
    *cache = Some((now, value.clone()));
    Some(value)
}

fn discover_gateway() -> Option<(Ipv4Addr, u32)> {
    static CACHE: std::sync::OnceLock<GatewayCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    cached_value(cache, Instant::now(), gateway_ttl, || {
        environment::default_route().ok().and_then(|route| {
            let index = normalization::interface_index(&route.interface).ok()?;
            Some((route.gateway?, index))
        })
    })?
}

/// The name of the physical default interface. Cache it for 30 seconds so
/// that status reads do not start `/sbin/route` on every poll. A missing name
/// is cached for one second only, for the same reason as a missing gateway.
fn discover_iface() -> Option<String> {
    static CACHE: std::sync::OnceLock<IfaceCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    cached_value(cache, Instant::now(), iface_ttl, || {
        environment::default_route()
            .ok()
            .map(|route| route.interface)
    })?
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One pairing attempt. Tests replace it with a closure that uses no network.
type PairAttempt = Arc<
    dyn Fn(Arc<AtomicBool>, &mut dyn FnMut(&str)) -> Result<PhoneCredentials, PairError>
        + Send
        + Sync,
>;

/// Pair with the discovered source device over a normalized socket.
fn network_pair(
    cancel: Arc<AtomicBool>,
    on_code: &mut dyn FnMut(&str),
) -> Result<PhoneCredentials, PairError> {
    let identity = pairing::local_identity()?;
    let (host, index) = discover_gateway().ok_or(PairError::NoPhone)?;
    pairing::pair(
        host,
        &identity,
        Some(index),
        &normalization::Audit::default(),
        &cancel,
        on_code,
    )
}

/// Store the result of one pairing attempt. A successful attempt replaces the
/// stored credentials. A failed attempt keeps the old credentials.
fn store_pair_result(
    inner: &mut PairInner,
    result: &Result<PhoneCredentials, PairError>,
    forget: &Mutex<Forget>,
) {
    inner.cancel = None;
    match result {
        Ok(credentials) => {
            inner.credentials = Some(credentials.clone());
            inner.view = inner.resting_view();
            // A new pairing supersedes a local pending forget. Protocol v1
            // cannot order a request already sent against source-side trust.
            if let Ok(mut state) = forget.lock() {
                state.clear();
                state.generation = state.generation.wrapping_add(1);
            }
        }
        Err(PairError::Cancelled) => inner.view = inner.resting_view(),
        Err(error) => {
            inner.view = PairView {
                phase: PairPhase::Failed,
                error: Some(error.message()),
                ..PairView::default()
            };
        }
    }
}

fn pair_spawn_failed(shared: &Mutex<PairInner>, generation: u64) {
    if let Ok(mut inner) = shared.lock() {
        if inner.generation == generation {
            inner.cancel = None;
            inner.view = inner.resting_view();
        }
    }
}

fn run_pairing(
    shared: Arc<Mutex<PairInner>>,
    generation: u64,
    cancel: Arc<AtomicBool>,
    forget: Arc<Mutex<Forget>>,
    attempt: PairAttempt,
    drain: Duration,
) {
    let update = |change: &mut dyn FnMut(&mut PairInner)| {
        if let Ok(mut inner) = shared.lock() {
            if inner.generation == generation {
                change(&mut inner);
            }
        }
    };
    // Wait for the local network attempt to finish before pairing. This
    // reduces overlap, but a timeout does not prove that the source device
    // processed the request: protocol v1 has no remote ordering barrier.
    if !wait_for_forget_idle(&forget, drain, &cancel) {
        update(&mut |inner| {
            inner.cancel = None;
            inner.view = PairView {
                phase: PairPhase::Failed,
                error: Some(FORGET_DRAIN_ERROR),
                ..PairView::default()
            };
        });
        return;
    }
    // The old FORGET has finished. Clear a pending retry only while this
    // pairing still owns the state and was not cancelled. The pairing lock
    // keeps a new forget request from starting between the check and the
    // clear.
    if !clear_forget_for_pairing(&shared, &forget, generation, &cancel) {
        return;
    }
    let result = attempt(Arc::clone(&cancel), &mut |code| {
        update(&mut |inner| {
            inner.view = PairView {
                phase: PairPhase::Confirm,
                code: Some(code.to_owned()),
                ..PairView::default()
            };
        })
    });
    update(&mut |inner| store_pair_result(inner, &result, &forget));
}

#[derive(Default)]
struct Presence {
    last_request: Option<Instant>,
    state: Option<&'static str>,
    /// The connection count from the last valid authenticated status answer.
    connections: Option<u16>,
    /// Unix seconds of the last completed probe.
    checked_at: Option<u64>,
    /// The monotonic time of the last completed probe.
    checked: Option<Instant>,
    /// True when the last unpaired CHALLENGE said that the source device still
    /// trusts this target key. False for a CHALLENGE with known = 0. None when
    /// the last probe did not answer with a CHALLENGE.
    ///
    /// This is a plaintext claim, not proof. The auto-stop policy treats the
    /// answer as unverified even when this value is true.
    trusted_by_source: Option<bool>,
}

/// A token copy that zeroes itself when it goes out of scope.
struct ZeroToken(String);
impl ZeroToken {
    /// Move the token out. The caller must zero it or give it to a type with
    /// its own Drop. The wrapper stays empty and zeroes nothing.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}
impl Drop for ZeroToken {
    fn drop(&mut self) {
        unsafe {
            for byte in self.0.as_bytes_mut() {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// The maximum number of best-effort FORGET requests after one forget.
const MAX_FORGET_TRIES: u8 = 3;

/// The longest time a new pairing waits for an old FORGET network attempt to
/// finish. A FORGET connect and its exchange each have a 2 second bound. The
/// extra second covers route discovery and thread scheduling. If the attempt
/// does not finish in this time, the pairing fails closed instead of starting
/// while the old request may still reach the source device.
const FORGET_DRAIN_LIMIT: Duration = Duration::from_secs(5);

/// The fixed pairing text when an old FORGET is still in flight.
const FORGET_DRAIN_ERROR: &str = "The previous forget is still running. Try again.";

/// A best-effort FORGET that the source device has not confirmed yet.
#[derive(Default)]
struct Forget {
    pending: bool,
    in_flight: bool,
    attempts: u8,
    generation: u64,
    /// The last completed FORGET outcome. Both values stay until the next pair
    /// start or the next forget.
    outcome: ForgetOutcome,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum ForgetOutcome {
    #[default]
    None,
    Confirmed,
    NotDelivered,
}
impl Forget {
    /// True when the presence probe must try again. The attempt budget bounds
    /// an unreachable source device too, so the state always ends.
    fn should_retry(&self) -> bool {
        self.pending && !self.in_flight && self.attempts < MAX_FORGET_TRIES
    }
    fn state(&self) -> &'static str {
        if self.pending || self.in_flight {
            "pending"
        } else {
            match self.outcome {
                ForgetOutcome::None => "none",
                ForgetOutcome::Confirmed => "confirmed",
                ForgetOutcome::NotDelivered => "not_delivered",
            }
        }
    }
    fn clear(&mut self) {
        self.pending = false;
        self.outcome = ForgetOutcome::None;
    }
}

/// One best-effort FORGET over the network. True means the source device
/// confirmed it.
type ForgetNetwork = Arc<dyn Fn() -> bool + Send + Sync>;

fn network_forget() -> bool {
    let Some((host, iface)) = discover_gateway() else {
        return false;
    };
    let Ok(identity) = pairing::local_identity() else {
        return false;
    };
    pairing::forget(
        host,
        &identity,
        Some(iface),
        &normalization::Audit::default(),
        &AtomicBool::new(false),
    )
    .is_ok()
}

/// Mark one FORGET attempt finished. Only the generation that started the
/// attempt may change the attempt count or the outcome. The in-flight flag
/// always clears, so a newer forget can start after an older attempt.
fn finish_forget_attempt(forget: &Mutex<Forget>, generation: u64, confirmed: bool) {
    if let Ok(mut state) = forget.lock() {
        state.in_flight = false;
        if state.generation == generation {
            state.attempts = state.attempts.saturating_add(1);
            if confirmed {
                state.pending = false;
                state.outcome = ForgetOutcome::Confirmed;
            } else if state.attempts >= MAX_FORGET_TRIES {
                state.pending = false;
                state.outcome = ForgetOutcome::NotDelivered;
            }
        }
    }
}

/// A FORGET worker could not start. No request reached the source device.
/// End the pending state instead of leaving it set forever. A later Forget
/// action starts a new attempt.
fn forget_spawn_failed(forget: &Mutex<Forget>, generation: u64) {
    if let Ok(mut state) = forget.lock() {
        state.in_flight = false;
        if state.generation == generation {
            state.pending = false;
            state.outcome = ForgetOutcome::NotDelivered;
        }
    }
}

type ForgetJob = Box<dyn FnOnce() + Send + 'static>;

/// Start one FORGET attempt with an injected spawner. The test seam proves
/// that a failed spawn ends the pending state.
fn spawn_forget_with<F>(forget: Arc<Mutex<Forget>>, network: ForgetNetwork, spawn: F) -> bool
where
    F: FnOnce(ForgetJob) -> io::Result<()>,
{
    let generation = match forget.lock() {
        Ok(mut state) if state.pending && !state.in_flight => {
            state.in_flight = true;
            state.generation
        }
        _ => return false,
    };
    let worker = Arc::clone(&forget);
    let job: ForgetJob = Box::new(move || {
        let confirmed = network();
        finish_forget_attempt(&worker, generation, confirmed);
    });
    match spawn(job) {
        Ok(()) => true,
        Err(_) => {
            forget_spawn_failed(&forget, generation);
            false
        }
    }
}

/// Run one FORGET attempt in the background. A failed attempt stays pending,
/// so the presence probe can retry when the source device is reachable.
fn spawn_forget(forget: Arc<Mutex<Forget>>, network: ForgetNetwork) {
    spawn_forget_with(forget, network, |job| {
        std::thread::Builder::new()
            .name("hotspotshade-forget".into())
            .spawn(job)
            .map(|_| ())
    });
}

/// Wait until no FORGET attempt is in flight. Return false on timeout, a
/// poisoned lock, or a cancel request.
///
/// The wait never cancels the network attempt. A cancel flag cannot retract
/// bytes that were already sent, so a new pairing must wait for the attempt
/// to return instead.
fn wait_for_forget_idle(forget: &Mutex<Forget>, limit: Duration, cancel: &AtomicBool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if cancel.load(Ordering::Acquire) {
            return false;
        }
        let in_flight = match forget.lock() {
            Ok(state) => state.in_flight,
            Err(_) => return false,
        };
        if !in_flight {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(10)));
    }
}

/// Clear a pending FORGET after its attempt has finished. The pairing lock is
/// held across the check and the clear, so a forget request cannot start
/// between them. Return false when this pairing is stale or was cancelled.
fn clear_forget_for_pairing(
    shared: &Mutex<PairInner>,
    forget: &Mutex<Forget>,
    generation: u64,
    cancel: &AtomicBool,
) -> bool {
    let Ok(inner) = shared.lock() else {
        return false;
    };
    if inner.generation != generation || cancel.load(Ordering::Acquire) {
        return false;
    }
    let Ok(mut state) = forget.lock() else {
        return false;
    };
    state.clear();
    state.generation = state.generation.wrapping_add(1);
    true
}

/// One presence probe. The state is always fixed text. `info` is present only
/// after the authenticated STATUS exchange succeeds. A TCP connect alone does
/// not set it.
struct ProbeResult {
    state: &'static str,
    info: Option<PhoneInfo>,
    gateway: Option<Ipv4Addr>,
    /// The CHALLENGE `known` byte from an unpaired probe.
    trusted_by_source: Option<bool>,
    /// True when the caller set the cancel flag during the probe. A cancelled
    /// probe is not an answer. It must never be stored as a missing source
    /// device, or the auto-stop policy would see silence that did not happen.
    cancelled: bool,
}
impl ProbeResult {
    /// One probe that the cancel flag stopped. It keeps no address and no
    /// answer.
    fn cancelled() -> Self {
        Self {
            state: "cancelled",
            info: None,
            gateway: None,
            trusted_by_source: None,
            cancelled: true,
        }
    }

    /// One probe that did not run because the tunnel pin is unknown. It is not
    /// evidence that the source device is missing, and it must never be an
    /// unpinned probe.
    fn pin_unknown(host: Ipv4Addr) -> Self {
        Self {
            state: "pin_unknown",
            info: None,
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        }
    }
}

/// The presence probe periods. The observer keeps the fast period while a
/// phone tunnel runs, so the auto-stop observer always has a fresh result.
/// Without a phone tunnel the observer saves work when no page reads the API.
#[derive(Clone, Copy)]
struct PresenceSchedule {
    /// The probe period while a phone tunnel runs.
    running: Duration,
    /// The probe period while the API was read within 10 seconds.
    polling: Duration,
    /// The probe period after 10 seconds without an API read.
    unpolled: Duration,
    /// Stop probing after this long without an API read when no phone tunnel
    /// runs.
    idle_limit: Duration,
    /// How long the observer sleeps before it checks the stop flag again.
    poll: Duration,
}
impl Default for PresenceSchedule {
    fn default() -> Self {
        Self {
            running: Duration::from_secs(2),
            polling: Duration::from_secs(2),
            unpolled: Duration::from_secs(10),
            idle_limit: Duration::from_secs(300),
            poll: Duration::from_millis(250),
        }
    }
}

/// Return the probe period, or None when the observer must not probe.
///
/// A running phone tunnel always probes. The auto-stop observer needs a fresh
/// result to stop after 90 seconds without an answer. The page cannot supply
/// that result. A stopped tunnel keeps the idle limit, so the observer does
/// not probe forever.
fn probe_interval(
    idle: Duration,
    phone_running: bool,
    schedule: PresenceSchedule,
) -> Option<Duration> {
    if phone_running {
        Some(schedule.running)
    } else if idle >= schedule.idle_limit {
        None
    } else if idle < Duration::from_secs(10) {
        Some(schedule.polling)
    } else {
        Some(schedule.unpolled)
    }
}

/// Return the probe period for the observer. `last_request` is None until the
/// first API read. A running phone tunnel probes even then: the auto-stop
/// observer must not depend on a page read. With no tunnel, an observer that
/// no page has asked for stays quiet.
fn probe_period(
    now: Instant,
    last_request: Option<Instant>,
    phone_running: bool,
    schedule: PresenceSchedule,
) -> Option<Duration> {
    if phone_running {
        return Some(schedule.running);
    }
    let last = last_request?;
    probe_interval(now.saturating_duration_since(last), false, schedule)
}

/// True when one probe is due. `now` is the observer clock, so a test can use
/// fake times and no sleeps.
fn probe_due(
    now: Instant,
    last_request: Option<Instant>,
    last_probe: Option<Instant>,
    phone_running: bool,
    schedule: PresenceSchedule,
) -> bool {
    let Some(period) = probe_period(now, last_request, phone_running, schedule) else {
        return false;
    };
    last_probe.is_none_or(|at| now.saturating_duration_since(at) >= period)
}

/// One presence probe. Tests replace it with a local closure. The optional
/// target keeps a running phone tunnel on the source host and interface that
/// the tunnel started with.
type ProbeAttempt =
    Arc<dyn Fn(bool, &AtomicBool, Option<ProbeTarget>) -> ProbeResult + Send + Sync>;

/// One decision of the presence observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// No probe was due.
    Idle,
    /// One probe ran and its answer was stored.
    Probed,
    /// The stop flag cancelled the probe. Nothing was stored.
    Cancelled,
    /// The stop flag was set before the decision.
    Stopped,
}

/// The shared state that the presence observer reads. The server builds one
/// observer per run. The observer holds no credential of its own.
struct PresenceObserver {
    presence: Arc<Mutex<Presence>>,
    pairing: Arc<Mutex<PairInner>>,
    forget: Arc<Mutex<Forget>>,
    forget_network: ForgetNetwork,
    probe_attempt: ProbeAttempt,
    phone_running: Arc<AtomicBool>,
    probe_target: Arc<Mutex<Option<ProbeTarget>>>,
    run_id: Arc<AtomicU64>,
    schedule: PresenceSchedule,
}
impl PresenceObserver {
    /// Observe the source device until `stop` is set.
    ///
    /// The observer runs on its own thread. It reads no request body and holds
    /// no credential. It only stores the fixed probe state. A stopped observer
    /// exits after at most one probe and one poll period.
    fn run(self, stop: Arc<AtomicBool>) {
        let mut last_probe: Option<Instant> = None;
        while !stop.load(Ordering::Acquire) {
            if self.step(Instant::now(), &mut last_probe, &stop) == Step::Stopped {
                break;
            }
            std::thread::sleep(self.schedule.poll);
        }
    }

    /// Run at most one probe decision at `now`.
    ///
    /// A cancelled probe is not an answer. The observer drops it, so the last
    /// real answer stays visible and no missing source device is invented.
    fn step(&self, now: Instant, last_probe: &mut Option<Instant>, stop: &AtomicBool) -> Step {
        if stop.load(Ordering::Acquire) {
            return Step::Stopped;
        }
        let running = self.phone_running.load(Ordering::Acquire);
        let last_request = self.presence.lock().ok().and_then(|p| p.last_request);
        if !probe_due(now, last_request, *last_probe, running, self.schedule) {
            return Step::Idle;
        }
        let paired = self
            .pairing
            .lock()
            .map(|p| p.credentials.is_some())
            .unwrap_or(false);
        let run = self.run_id.load(Ordering::Acquire);
        // Read the run before the target. A start sets the target and then the
        // phone flag before it changes the run id, so a new run never probes
        // without its own target.
        let target = if self.phone_running.load(Ordering::Acquire) {
            Some(
                self.probe_target
                    .lock()
                    .ok()
                    .and_then(|target| *target)
                    .unwrap_or(UNKNOWN_PROBE_TARGET),
            )
        } else {
            None
        };
        let result = (self.probe_attempt)(paired, stop, target);
        *last_probe = Some(now);
        if result.cancelled {
            return Step::Cancelled;
        }
        // A start or a stop can replace the run while one probe is in flight.
        // A late answer must not affect the next run.
        if self.run_id.load(Ordering::Acquire) != run {
            return Step::Probed;
        }
        record_probe_for_run(&self.presence, &self.pairing, &self.run_id, run, &result);
        // Try again after every presence probe until the attempt budget ends,
        // even when the source device is unreachable. The state must reach a
        // final value.
        let retry = self
            .forget
            .lock()
            .map(|state| state.should_retry())
            .unwrap_or(false);
        if retry {
            spawn_forget(Arc::clone(&self.forget), Arc::clone(&self.forget_network));
        }
        Step::Probed
    }
}

/// How long the supervisor waits before it starts a failed observer again.
const OBSERVER_RETRY: Duration = Duration::from_secs(10);

/// The minimum gap between two fallback probes after an observer failure. The
/// running observer probes every 2 seconds. The fallback matches that rate.
const FALLBACK_RETRY: Duration = Duration::from_secs(2);

/// Clear the fallback in-flight flag on every exit, including a panic.
struct FallbackActive(Arc<AtomicBool>);
impl Drop for FallbackActive {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The lifecycle of the presence observer. The server starts one observer per
/// run. The supervisor starts a failed observer again after `retry`. A normal
/// stop is final: nothing runs the observer after the server stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObserverState {
    /// No server has asked for an observer.
    NotStarted,
    /// A thread start is in progress.
    Starting,
    /// The observer thread runs.
    Running,
    /// The thread could not start or panicked. The supervisor may retry.
    Failed,
    /// The observer ended because the stop flag was set.
    Stopped,
}

struct ObserverControl {
    state: ObserverState,
    stop: Option<Arc<AtomicBool>>,
    schedule: PresenceSchedule,
    last_attempt: Option<Instant>,
    /// The wait before the supervisor starts a failed observer again.
    retry: Duration,
    /// The number of observer threads that the supervisor started.
    starts: u32,
}
impl Default for ObserverControl {
    fn default() -> Self {
        Self {
            state: ObserverState::NotStarted,
            stop: None,
            schedule: PresenceSchedule::default(),
            last_attempt: None,
            retry: OBSERVER_RETRY,
            starts: 0,
        }
    }
}

/// The reason and time of the last stop. It stays for the engine lifetime and
/// clears when the next tunnel starts.
#[derive(Clone)]
struct LastStop {
    reason: &'static str,
    at: u64,
}

fn presence_probe(paired: bool, stop: &AtomicBool, target: Option<ProbeTarget>) -> ProbeResult {
    if stop.load(Ordering::Acquire) {
        return ProbeResult::cancelled();
    }
    let (host, iface) = match target {
        Some(target) => {
            // A phone run always pins. A target without an index is an
            // unresolved pin. Do not probe the source device unpinned.
            let Some(index) = target.iface else {
                return ProbeResult::pin_unknown(target.host);
            };
            (target.host, Some(index))
        }
        None => match discover_gateway() {
            Some((host, iface)) => (host, Some(iface)),
            None => {
                return ProbeResult {
                    state: "no_hotspot",
                    info: None,
                    gateway: None,
                    trusted_by_source: None,
                    cancelled: false,
                }
            }
        },
    };
    let address = SocketAddr::V4(SocketAddrV4::new(host, pairing::PAIRING_PORT));
    let Ok(identity) = pairing::local_identity() else {
        return ProbeResult {
            state: "not_responding",
            info: None,
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        };
    };
    probe_address(address, iface, paired, &identity, stop)
}

/// The presence state for a failed probe connect.
///
/// A refused connection suggests that the listener is not available. It does
/// not prove that the source app exited. A timeout says that the probe did not
/// finish. An unreachable network says that the path
/// did not work. A local error says nothing about the source device. Report
/// those as `not_responding`, so the target device never claims that the app
/// is off when the probe was merely slow or blocked.
fn connect_error_state(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "not_running",
        _ => "not_responding",
    }
}

/// The presence state for a status exchange that ended with an error.
///
/// The answers `Busy`, `NotActive`, and `LockedOut` are plaintext RESULT
/// frames that the listener sends before it authenticates anyone, so they say
/// that something answered, not that the app is ready or trusted:
///
/// - `Busy`: the listener is saturated or holds a prompt. `checking`.
/// - `NotActive` and `LockedOut`: the listener answers an unknown key this
///   way. It does not hold this target key, the same claim as `Rejected`.
///   A paired target reports `not_trusted`; an unpaired one reports
///   `unpaired`.
///
/// `checking`, `unpaired`, and `not_trusted` are unverified answers. The
/// auto-stop policy treats them as neither presence nor silence, and bounds a
/// continuous run with [`crate::autostop::UNVERIFIED_GRACE`]. A timeout, a
/// protocol or decrypt failure, a transport error, a missing identity,
/// `Denied`, `TimedOut`, and an unexpected `Ok` stay `not_responding`: none
/// of them is a valid answer to a status request.
fn status_failure_state(error: &PairError, paired: bool) -> &'static str {
    match error {
        PairError::Phone(pairing::PhoneStatus::Rejected) if paired => "not_trusted",
        PairError::Phone(pairing::PhoneStatus::Busy) => "checking",
        PairError::Phone(pairing::PhoneStatus::NotActive | pairing::PhoneStatus::LockedOut) => {
            if paired {
                "not_trusted"
            } else {
                "unpaired"
            }
        }
        _ => "not_responding",
    }
}

/// Probe one source device address. The probe is bounded: 2 seconds for the
/// connection and 2 seconds for the exchange.
fn probe_address(
    address: SocketAddr,
    iface: Option<u32>,
    paired: bool,
    identity: &Identity,
    stop: &AtomicBool,
) -> ProbeResult {
    let host = match address.ip() {
        std::net::IpAddr::V4(host) => host,
        std::net::IpAddr::V6(_) => {
            return ProbeResult {
                state: "not_responding",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        }
    };
    let audit = normalization::Audit::default();
    if let Err(error) = normalization::tcp_connect_cancellable(
        address,
        iface,
        &audit,
        Duration::from_secs(2),
        Some(stop),
    ) {
        // A cancelled connect is not a source device that is off. Keep the
        // two apart so that the observer never reports silence after a stop.
        if error.kind() == io::ErrorKind::Interrupted {
            return ProbeResult::cancelled();
        }
        return ProbeResult {
            state: connect_error_state(&error),
            info: None,
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        };
    }
    if !paired {
        return match pairing::probe_unpaired_at(address, identity, iface, &audit, stop) {
            Ok(trusted) => ProbeResult {
                state: "unpaired",
                info: None,
                gateway: Some(host),
                trusted_by_source: trusted,
                cancelled: false,
            },
            Err(PairError::Cancelled) => ProbeResult::cancelled(),
            Err(error) => ProbeResult {
                state: status_failure_state(&error, false),
                info: None,
                gateway: Some(host),
                trusted_by_source: None,
                cancelled: false,
            },
        };
    }
    match pairing::status_at(address, identity, iface, &audit, stop) {
        Ok(info) if !info.proxy_running => ProbeResult {
            state: "proxy_off",
            info: Some(info),
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        },
        Ok(info) => ProbeResult {
            state: "ready",
            info: Some(info),
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        },
        Err(PairError::Cancelled) => ProbeResult::cancelled(),
        Err(error) => ProbeResult {
            state: status_failure_state(&error, true),
            info: None,
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        },
    }
}

/// Store one probe result for the run that asked for it. The connection count
/// comes only from a valid authenticated status answer. A failed probe clears
/// it. A cancelled probe changes nothing: the caller stopped before an answer
/// arrived. A result from another run changes nothing either: a start resets
/// presence while an old probe can still be in flight.
fn record_probe_for_run(
    presence: &Mutex<Presence>,
    pairing: &Mutex<PairInner>,
    run_id: &AtomicU64,
    observed_run: u64,
    result: &ProbeResult,
) -> bool {
    if result.cancelled {
        return false;
    }
    let Ok(mut presence) = presence.lock() else {
        return false;
    };
    // Read the run id under the presence lock. A start increments the run id
    // before it resets presence, so this check cannot store a stale answer in
    // the new run.
    if run_id.load(Ordering::Acquire) != observed_run {
        return false;
    }
    if let (Some(gateway), Some(info)) = (result.gateway, result.info.as_ref()) {
        apply_probe(pairing, gateway, info);
    }
    // Store the answer unchanged. A plaintext `checking`, `unpaired`, or
    // `not_trusted` answer stays visible, but the auto-stop policy treats it
    // as unverified and bounds a continuous run. Do not turn it into presence
    // or into source device silence here.
    let now = Instant::now();
    presence.state = Some(result.state);
    presence.connections = result.info.as_ref().map(|info| info.connections);
    presence.checked_at = Some(now_unix());
    presence.checked = Some(now);
    presence.trusted_by_source = result.trusted_by_source;
    true
}

/// The state that the target app shows. While a phone tunnel runs, the real
/// probe result stays visible. `connected` means that the probe says `ready`,
/// or that no probe has completed yet.
fn phone_state(presence: Option<&'static str>, running_phone: bool) -> &'static str {
    match presence {
        Some("ready") if running_phone => "connected",
        Some(state) => state,
        None if running_phone => "connected",
        None => "not_responding",
    }
}

/// True when the stored monotonic probe time is still current. A result with
/// no time, or one older than `PROBE_FRESH`, is not current. The observer
/// probes every 2 seconds while a source device tunnel runs, so an older
/// result means that monitoring stopped.
fn probe_current(checked: Option<Instant>) -> bool {
    checked.is_some_and(|at| at.elapsed() <= PROBE_FRESH)
}

/// Apply one authenticated status answer to the stored credentials.
///
/// The caller passes only a `PhoneInfo` from the authenticated STATUS exchange.
/// The pairing lock is the only lock that this function holds.
fn apply_probe(
    shared: &Mutex<PairInner>,
    gateway: Ipv4Addr,
    info: &PhoneInfo,
) -> pairing::PortUpdate {
    let Ok(mut inner) = shared.lock() else {
        return pairing::PortUpdate::Rejected;
    };
    let (update, port) = match inner.credentials.as_mut() {
        Some(credentials) => {
            let update = pairing::learn_phone_info(credentials, gateway, info);
            (update, Some(credentials.port))
        }
        None => (pairing::PortUpdate::Rejected, None),
    };
    if inner.view.phase == PairPhase::Paired {
        if let Some(port) = port {
            inner.view.port = Some(port);
        }
    }
    update
}

enum Phase {
    Idle,
    Starting {
        cancel: Arc<AtomicBool>,
        socket: Arc<Mutex<Option<UnixStream>>>,
    },
    Local,
    /// A privileged helper owns the tunnel. The legacy Unix helper path is
    /// retained only for the hermetic tests; production uses XPC.
    #[cfg(test)]
    Remote(Arc<Mutex<Helper>>),
    Stopping,
}

/// The phase, port, source host, and pinned interface of one successful start.
type StartOutcome = (Phase, Option<u16>, Option<Ipv4Addr>, Option<String>);

#[cfg(test)]
thread_local! {
    /// One test can request a panic in the next tunnel start branch.
    static PANIC_NEXT_TUN_START: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Recover a start that panicked before it published its phase.
///
/// The guard is armed only while the phase is Starting. On drop it cancels the
/// run, closes the private start socket, stops the local service, and returns
/// the phase to Idle. A helper start owns its own cleanup guard: closing the
/// socket makes the helper stop. A panic must not leave a Starting phase, an
/// untracked local service, or a stale presence result.
struct StartRecovery<'a> {
    backend: &'a RustGuiBackend,
    cancel: Arc<AtomicBool>,
    socket: Arc<Mutex<Option<UnixStream>>>,
    armed: bool,
}
impl StartRecovery<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for StartRecovery<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancel.store(true, Ordering::Release);
        if let Ok(mut slot) = self.socket.lock() {
            if let Some(stream) = slot.take() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
        // A local service may already run. A helper start is stopped by its
        // own cleanup guard when the socket closes. A poisoned service lock
        // must not hide the phase recovery. The stop result stays in the
        // service's cleanup flag, so the next stop or process exit reports it.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.backend.service.stop_checked();
        }));
        self.backend.cancel_run();
        if let Ok(mut phase) = self.backend.phase.lock() {
            if matches!(*phase, Phase::Starting { .. }) {
                self.backend.clear_tunnel_run();
                self.backend.reset_presence();
                self.backend.bump_run();
                *phase = Phase::Idle;
            }
            self.backend.changed.notify_all();
        }
    }
}

/// Recover a stop that panicked before it published Idle.
///
/// The guard is armed only while the phase is Stopping for one run. On drop it
/// restores the original phase, so the tunnel stays tracked and a later stop
/// can retry. It never untracks a helper or a child. It then runs the cleanup
/// for that phase: stop the local service, or close the helper stream so its
/// cleanup guard stops the helper service.
struct StopRecovery<'a> {
    backend: &'a RustGuiBackend,
    run: u64,
    original: Option<Phase>,
}
impl StopRecovery<'_> {
    fn disarm(&mut self) {
        self.original = None;
    }
}
impl Drop for StopRecovery<'_> {
    fn drop(&mut self) {
        let Some(original) = self.original.take() else {
            return;
        };
        let local = matches!(original, Phase::Local);
        #[cfg(test)]
        let helper = match &original {
            Phase::Remote(helper) => Some(Arc::clone(helper)),
            _ => None,
        };
        if !self.backend.restore_stop_phase(self.run, original) {
            return;
        }
        if local {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = self.backend.service.stop_checked();
            }));
        }
        #[cfg(test)]
        if let Some(helper) = helper {
            if let Ok(helper) = helper.lock() {
                let _ = helper.stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// The backend. Lock order: `phase` before `tunnel_phone_port` and the start
/// socket. When both are needed, take `presence` before `pairing`.
pub struct RustGuiBackend {
    service: Arc<Service>,
    phase: Mutex<Phase>,
    pairing: Arc<Mutex<PairInner>>,
    presence: Arc<Mutex<Presence>>,
    /// True while a phone tunnel runs. The presence observer keeps the fast
    /// probe period while it is set, even when no page reads the API.
    phone_running: Arc<AtomicBool>,
    /// The proxy port of the running phone tunnel. Set on a start, cleared on
    /// a stop.
    tunnel_phone_port: Mutex<Option<u16>>,
    /// The interface that the running tunnel pins to. Set on a start, cleared
    /// on a stop.
    tunnel_iface: Mutex<Option<String>>,
    /// The source host and physical interface of a running phone tunnel. The
    /// presence probe uses them for the whole run.
    probe_target: Arc<Mutex<Option<ProbeTarget>>>,
    /// The current default route for a token-bearing start or check. It is a
    /// fresh lookup, not the cached status value. Tests replace it.
    route_lookup: RouteLookup,
    /// A FORGET that the source device has not confirmed yet.
    forget: Arc<Mutex<Forget>>,
    /// The network FORGET. Tests replace it with a local closure.
    forget_network: ForgetNetwork,
    /// The longest wait for an old FORGET before a new pairing fails closed.
    forget_drain: Duration,
    /// One pairing attempt. Tests replace it with a local closure.
    pair_attempt: PairAttempt,
    /// One presence probe. Tests replace it with a local closure.
    probe_attempt: ProbeAttempt,
    /// The presence observer lifecycle. The server starts one observer per
    /// run. The supervisor starts a failed observer again.
    observer: Arc<Mutex<ObserverControl>>,
    /// The time of the last API probe. It enforces the 500 ms rate limit.
    probe_gate: Mutex<Option<Instant>>,
    /// The last time the supervisor started a fallback probe, and whether one
    /// is still in flight. The fallback runs only after an observer failure.
    fallback_at: Mutex<Option<Instant>>,
    fallback_active: Arc<AtomicBool>,
    /// The cancel flag of the current run. A fallback worker from an older run
    /// sees it set and drops its late result.
    run_cancel: Mutex<Arc<AtomicBool>>,
    /// The lifecycle generation. It changes at start, stop start, and stop
    /// completion. A failed stop also invalidates earlier observations, so
    /// automatic-stop timers start again after monitoring resumes.
    run_id: Arc<AtomicU64>,
    /// The last completed stop. It stays for the engine lifetime.
    last_stop: Mutex<Option<LastStop>>,
    /// True while the engine believes that a tunnel runs. A stop that the
    /// engine did not start is reported as an error stop.
    was_running: AtomicBool,
    /// Set once when the HTTP server begins shutdown. A request that passed
    /// its own stop check before shutdown must not start a tunnel after the
    /// final stop.
    closing: AtomicBool,
    changed: Condvar,
    experimental_icmp: bool,
    experimental_icmp_persistent: bool,
    /// The one-time administrator grant that the protected helper writes for
    /// this engine. A start that changes routes consumes it. A manually
    /// started root GUI has no grant file and keeps the old root authority.
    #[cfg(target_os = "macos")]
    tunnel_grant: Option<TunnelGrant>,
    /// True when a route-changing start needs a grant even if no grant file is
    /// present. The helper-owned engine always sets it, including when it
    /// imports pairing credentials. An absent grant is then a refusal, not a
    /// fallback to root authority.
    #[cfg(target_os = "macos")]
    tunnel_grant_required: bool,
    /// True for a Linux root engine. The pkexec authorization covers a
    /// route-changing tunnel only, so any other start mode, such as a local
    /// SOCKS5 listener, is refused with `mode_not_allowed` instead of running
    /// as root. The unit tests build it on every Unix host.
    #[cfg(any(target_os = "linux", test))]
    tunnel_modes_only: bool,
    /// The private write descriptor for one pairing handoff to an elevated
    /// engine. Only the user-owned engine sets it. The root engine never
    /// exports a handoff.
    handoff_fd: Mutex<Option<RawFd>>,
    /// The identity bytes for the handoff. The user engine sets these once at
    /// launch after it reads its key file, so a handoff never reopens the user
    /// key on the request thread. A missing value falls back to the key file.
    /// The bytes are cleared when the backend drops.
    handoff_identity: Mutex<Option<zeroize::Zeroizing<[u8; 32]>>>,
}
impl RustGuiBackend {
    /// Start the local SOCKS5 service. A unit test uses the loopback seam;
    /// a production build can reach only the guarded service entry.
    fn start_socks_service(
        &self,
        address: SocketAddr,
        iface: Option<&str>,
        dns: Option<Vec<SocketAddr>>,
    ) -> io::Result<()> {
        #[cfg(test)]
        {
            self.service.start_socks_loopback(address, iface, dns)
        }
        #[cfg(not(test))]
        {
            self.service.start_socks(address, iface, dns)
        }
    }
    /// The default source device tunnel turns the echo relay on.
    pub fn new(service: Arc<Service>) -> Self {
        Self::with_icmp_options(service, true, true)
    }
    pub fn with_experimental_icmp(service: Arc<Service>, experimental_icmp: bool) -> Self {
        Self::with_icmp_options(service, experimental_icmp, experimental_icmp)
    }

    /// Use the one-time grant that the protected helper writes. The helper
    /// starts the engine without an administrator prompt, so the engine itself
    /// refuses a route-changing start until the grant proves that a person
    /// authorized that start.
    #[cfg(target_os = "macos")]
    pub fn with_tunnel_grant(service: Arc<Service>, grant: TunnelGrant) -> Self {
        let mut backend = Self::with_icmp_options(service, true, true);
        backend.tunnel_grant = Some(grant);
        backend.tunnel_grant_required = true;
        backend
    }
    /// Set the default echo relay values for a start request that does not
    /// name them. A request value wins.
    pub fn with_icmp_options(
        service: Arc<Service>,
        experimental_icmp: bool,
        experimental_icmp_persistent: bool,
    ) -> Self {
        Self {
            service,
            phase: Mutex::new(Phase::Idle),
            pairing: Arc::new(Mutex::new(PairInner::default())),
            presence: Arc::new(Mutex::new(Presence::default())),
            phone_running: Arc::new(AtomicBool::new(false)),
            tunnel_phone_port: Mutex::new(None),
            tunnel_iface: Mutex::new(None),
            probe_target: Arc::new(Mutex::new(None)),
            route_lookup: Arc::new(discover_hotspot_route),
            forget: Arc::new(Mutex::new(Forget::default())),
            forget_network: Arc::new(network_forget),
            forget_drain: FORGET_DRAIN_LIMIT,
            pair_attempt: Arc::new(network_pair),
            probe_attempt: Arc::new(presence_probe),
            observer: Arc::new(Mutex::new(ObserverControl::default())),
            probe_gate: Mutex::new(None),
            fallback_at: Mutex::new(None),
            fallback_active: Arc::new(AtomicBool::new(false)),
            run_cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            run_id: Arc::new(AtomicU64::new(0)),
            last_stop: Mutex::new(None),
            was_running: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            changed: Condvar::new(),
            experimental_icmp,
            experimental_icmp_persistent,
            #[cfg(target_os = "macos")]
            tunnel_grant: None,
            #[cfg(target_os = "macos")]
            tunnel_grant_required: false,
            #[cfg(any(target_os = "linux", test))]
            tunnel_modes_only: false,
            handoff_fd: Mutex::new(None),
            handoff_identity: Mutex::new(None),
        }
    }

    /// Build the root engine from the one pairing handoff that the helper
    /// passed on an inherited descriptor. The imported identity replaces the
    /// root HOME key so the source device sees the same target public key.
    /// The credentials stay in process memory and are never sent in a status
    /// answer.
    ///
    /// Imported credentials never relax the administrator boundary. The helper
    /// always passes the grant path that it writes after it verifies the
    /// authorization, so an imported engine still needs a fresh grant before
    /// it changes a route. A missing grant path is a refusal, not a fallback
    /// to root authority.
    #[cfg(target_os = "macos")]
    pub fn with_imported_credentials(
        service: Arc<Service>,
        identity: Identity,
        credentials: PhoneCredentials,
        grant: Option<TunnelGrant>,
    ) -> Result<Self, PairError> {
        // The imported key is process-wide and must be set before any probe,
        // pairing, or forget path runs. A second import with a different key is
        // refused, which keeps the first handoff authoritative.
        pairing::set_imported_identity(identity.secret_bytes())?;
        let mut backend = Self::with_icmp_options(service, true, true);
        let mut inner = PairInner {
            credentials: Some(credentials),
            ..PairInner::default()
        };
        inner.view = inner.resting_view();
        backend.pairing = Arc::new(Mutex::new(inner));
        backend.tunnel_grant = grant;
        backend.tunnel_grant_required = true;
        Ok(backend)
    }

    /// Build the Linux root engine from the one pairing handoff that the
    /// pkexec helper passed on an inherited descriptor. The imported identity
    /// replaces the root HOME key, so the source device sees the same target
    /// public key as the user engine. The credentials stay in process memory
    /// and are never sent in a status answer.
    ///
    /// polkit authorized the helper launch before this engine existed, so the
    /// Linux root engine has no separate grant file. The unit tests build it
    /// on every Unix host so the import path is checked on macOS too.
    #[cfg(any(target_os = "linux", test))]
    pub fn with_imported_pairing(
        service: Arc<Service>,
        identity: Identity,
        credentials: PhoneCredentials,
    ) -> Result<Self, PairError> {
        // Process-wide, set before any probe, pairing, or forget path runs. A
        // second import with a different key is refused.
        pairing::set_imported_identity(identity.secret_bytes())?;
        let mut backend = Self::with_icmp_options(service, true, true);
        let mut inner = PairInner {
            credentials: Some(credentials),
            ..PairInner::default()
        };
        inner.view = inner.resting_view();
        backend.pairing = Arc::new(Mutex::new(inner));
        backend.tunnel_modes_only = true;
        Ok(backend)
    }

    /// Accept only the tunnel start modes, `phone` and `tun`. The Linux entry
    /// point calls this for every root engine, including a direct mode engine
    /// that the helper starts with no pairing handoff.
    #[cfg(any(target_os = "linux", test))]
    pub fn restrict_to_tunnel_modes(&mut self) {
        self.tunnel_modes_only = true;
    }

    /// Give the user engine the private write end of the pairing handoff pipe.
    /// The app holds the read end. The engine writes the identity and the
    /// credentials on each start request. The descriptor stays open for later
    /// attempts and is closed when the engine exits.
    pub fn set_handoff_fd(&self, descriptor: RawFd) {
        if let Ok(mut slot) = self.handoff_fd.lock() {
            *slot = Some(descriptor);
        }
    }

    /// Give the user engine the identity that its handoff must carry. The
    /// caller reads this once from the user key file before the engine serves
    /// a request. The bytes stay in this process memory.
    pub fn set_handoff_identity(&self, secret: [u8; 32]) {
        if let Ok(mut slot) = self.handoff_identity.lock() {
            *slot = Some(zeroize::Zeroizing::new(secret));
        }
    }

    /// Test seam: store a pairing as if the pairing flow had completed, so a
    /// route test in another module can drive the real handoff.
    #[cfg(test)]
    pub(crate) fn set_pairing_for_test(&self, credentials: PhoneCredentials) {
        self.pairing.lock().unwrap().credentials = Some(credentials);
    }

    /// Write the current pairing to the private handoff descriptor. This is
    /// the only path that moves the token out of the user engine. The response
    /// reports success and never repeats the token, key, host, or port.
    pub fn pair_handoff(&self) -> Result<Value, String> {
        // A running tunnel already owns the routes. A handoff at that point
        // would start a second engine over a live one.
        let status = self.service.status();
        if status["running"] == true {
            return Err("tunnel_running".into());
        }
        let credentials = {
            let inner = self.pairing.lock().map_err(|_| "pairing_unavailable")?;
            inner
                .credentials
                .clone()
                .ok_or_else(|| "not_paired".to_string())?
        };
        let identity = match self
            .handoff_identity
            .lock()
            .map_err(|_| "handoff_unavailable".to_string())?
            .as_ref()
        {
            Some(secret) => Identity::from_bytes(**secret),
            None => pairing::local_identity().map_err(|error| error.message().to_string())?,
        };
        let descriptor = *self
            .handoff_fd
            .lock()
            .map_err(|_| "handoff_unavailable")?
            .as_ref()
            .ok_or_else(|| "handoff_unavailable".to_string())?;
        // The descriptor stays open for a later start attempt. The app only
        // calls this immediately before it asks the helper for an elevated
        // engine. A failed authorization leaves the same pairing queued, and a
        // later attempt reads the same credentials.
        let result = crate::credential_handoff::write_handoff(descriptor, &identity, &credentials);
        result.map_err(|error| error.message().to_string())?;
        Ok(json!({"ok": true}))
    }

    fn begin(&self) -> Result<HelperSession, String> {
        let mut phase = self.phase.lock().map_err(|_| "service state unavailable")?;
        // Check the shutdown flag under the phase lock. Shutdown sets the flag
        // before its first stop. A start that reaches this point after the
        // final stop sees the flag and starts nothing.
        if self.closing.load(Ordering::Acquire) {
            return Err("service is stopping".into());
        }
        let status = self.service.status();
        if status["state"] == "unknown" {
            return Err(crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE.into());
        }
        if !matches!(*phase, Phase::Idle) || status["running"] == true {
            return Err("service is running".into());
        }
        // A new run starts with no stale presence. An in-flight probe from the
        // last run sees the new run id and drops its answer.
        self.start_run_cancel();
        self.bump_run();
        self.reset_presence();
        // The phase lock keeps a new start from seeing the old tunnel data.
        self.forget_tunnel_port();
        self.forget_tunnel_iface();
        self.forget_probe_target();
        let cancel = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(None));
        *phase = Phase::Starting {
            cancel: Arc::clone(&cancel),
            socket: Arc::clone(&socket),
        };
        Ok((cancel, socket))
    }
    /// Publish one new start. The phase lock covers the port, the interface,
    /// the stop record, and the run id, so no stop can clear them halfway.
    #[cfg(test)]
    fn finish_start(
        &self,
        next: Phase,
        phone: bool,
        iface: Option<String>,
        port: Option<u16>,
    ) -> Result<(), String> {
        self.finish_start_with_target(next, phone, iface, port, None)
    }
    fn finish_start_with_target(
        &self,
        next: Phase,
        phone: bool,
        iface: Option<String>,
        port: Option<u16>,
        target: Option<ProbeTarget>,
    ) -> Result<(), String> {
        let mut phase = self.phase.lock().map_err(|_| "service state unavailable")?;
        if !matches!(*phase, Phase::Starting { .. }) {
            return Err("start cancelled".into());
        }
        self.clear_last_stop();
        if let Some(port) = port {
            self.remember_tunnel_port(port);
        }
        self.remember_tunnel_iface(iface);
        self.remember_probe_target(target);
        self.set_phone_running(phone);
        self.was_running.store(true, Ordering::Release);
        // A probe can run during the Starting window, before the new target and
        // phone flag exist. Invalidate every such probe, then clear any result
        // that won the race before the run id changed. A probe that starts after
        // this point sees the final run id, the target, and the phone flag.
        self.bump_run();
        self.reset_presence();
        *phase = next;
        self.changed.notify_all();
        Ok(())
    }
    #[cfg(test)]
    fn finish(&self, phase_value: Phase) {
        if let Ok(mut phase) = self.phase.lock() {
            *phase = phase_value;
            self.changed.notify_all();
        }
    }
    #[cfg(test)]
    fn active_helper(&self) -> Option<Arc<Mutex<Helper>>> {
        self.phase.lock().ok().and_then(|p| match &*p {
            Phase::Remote(h) => Some(Arc::clone(h)),
            _ => None,
        })
    }
    /// True when the launcher process has definitely exited.
    ///
    /// A socket error alone is not proof. The privileged engine keeps the
    /// tunnel, and the launcher waits for it. A reaped child is a definite
    /// death. A locked or unavailable state is not.
    #[cfg(test)]
    fn helper_exited(helper: &Arc<Mutex<Helper>>) -> bool {
        helper
            .lock()
            .map(|mut helper| matches!(helper.launcher.try_wait(), Ok(Some(_))))
            .unwrap_or(false)
    }
    /// True when this helper still owns the run that the caller observed.
    ///
    /// A status answer can finish after a stop or a new start replaced the
    /// helper. The run id and the helper identity must both match before any
    /// side effect touches a helper.
    #[cfg(test)]
    fn helper_is_current(&self, observed_run: u64, helper: &Arc<Mutex<Helper>>) -> bool {
        if self.run_id.load(Ordering::Acquire) != observed_run
            || !self.was_running.load(Ordering::Acquire)
        {
            return false;
        }
        self.phase
            .lock()
            .map(|phase| match &*phase {
                Phase::Remote(current) => Arc::ptr_eq(current, helper),
                _ => false,
            })
            .unwrap_or(false)
    }
    /// Send the final stop and close only to the helper that still owns the
    /// observed run. Return false when a newer run owns the phase.
    #[cfg(test)]
    fn finalize_helper_for_run(&self, observed_run: u64, helper: &Arc<Mutex<Helper>>) -> bool {
        if !self.helper_is_current(observed_run, helper) {
            return false;
        }
        finalize_helper(helper);
        true
    }
    /// Clear the start data of the run that just ended. The caller holds the
    /// phase lock, so a new start cannot observe half-cleared state.
    fn clear_tunnel_run(&self) {
        self.forget_tunnel_port();
        self.forget_tunnel_iface();
        self.forget_probe_target();
        // Cancel workers of the run that ended, then give the idle state a
        // fresh flag so a later fallback probe can still run.
        self.start_run_cancel();
    }
    /// Move one Remote phase to Idle after a definite helper exit.
    ///
    /// The helper must get its final stop and close before this call. The
    /// phase lock covers the tunnel data clear, the error stop record, and the
    /// run id. A start that follows cannot be corrupted by late cleanup.
    #[cfg(test)]
    fn retire_dead_helper(&self, helper: &Arc<Mutex<Helper>>) -> bool {
        let retired = match self.phase.lock() {
            Ok(mut phase) => match &*phase {
                Phase::Remote(current) if Arc::ptr_eq(current, helper) => {
                    // The tunnel lived in the helper process and is gone.
                    self.clear_tunnel_run();
                    self.record_stop("error");
                    self.bump_run();
                    *phase = Phase::Idle;
                    self.changed.notify_all();
                    true
                }
                _ => false,
            },
            Err(_) => false,
        };
        if retired {
            // Close the stream after the state is safe. The helper cleanup
            // guard stops the service on disconnect.
            if let Ok(helper) = helper.lock() {
                let _ = helper.stream.shutdown(std::net::Shutdown::Both);
            }
        }
        retired
    }
    /// Publish Idle after a stop. The phase lock keeps a new start out until
    /// the old tunnel data is gone and the stop is recorded.
    ///
    /// The returned value is the cleanup failure when the service cannot prove
    /// that routes and devices are gone. The phase is still published as Idle,
    /// because the tunnel is not running, but the caller must return that
    /// failure. The engine exit path turns it into a nonzero exit so the Swift
    /// helper does not clear its durable launch intent on an unclean stop.
    fn finish_stop(&self, reason: &'static str) -> Result<Option<String>, String> {
        let cleanup_error = self
            .service
            .cleanup_uncertain()
            .then_some(crate::service::CLEANUP_UNCERTAIN_MESSAGE);
        let mut phase = self.phase.lock().map_err(|_| "service state unavailable")?;
        self.clear_tunnel_run();
        if cleanup_error.is_some() {
            self.record_stop("error");
        } else {
            self.record_stop(reason);
        }
        self.bump_run();
        *phase = Phase::Idle;
        self.changed.notify_all();
        Ok(cleanup_error.map(str::to_owned))
    }
    /// Restore the phase of a stop that panicked before it published Idle.
    ///
    /// The run id and the Stopping phase must both still match. The restored
    /// phase keeps the tunnel tracked, so a later stop can retry. This call
    /// never publishes Idle.
    fn restore_stop_phase(&self, observed_run: u64, original: Phase) -> bool {
        let Ok(mut phase) = self.phase.lock() else {
            return false;
        };
        if self.run_id.load(Ordering::Acquire) == observed_run && matches!(*phase, Phase::Stopping)
        {
            *phase = original;
            self.changed.notify_all();
            true
        } else {
            false
        }
    }
    /// Record an error stop for the run that `observed_run` names.
    ///
    /// Return true only when this call ended that run. A stop that started, a
    /// stop that finished, or a new start changes `run_id`. The phase check
    /// keeps this call out of a start or a stop that is still in progress.
    fn finish_error_stop(&self, observed_run: u64) -> bool {
        let Ok(mut phase) = self.phase.lock() else {
            return false;
        };
        if self.run_id.load(Ordering::Acquire) != observed_run
            || !self.was_running.load(Ordering::Acquire)
        {
            return false;
        }
        #[cfg(test)]
        if !matches!(*phase, Phase::Local | Phase::Remote(_)) {
            return false;
        }
        #[cfg(not(test))]
        if !matches!(*phase, Phase::Local) {
            return false;
        }
        self.clear_tunnel_run();
        self.record_stop("error");
        self.bump_run();
        *phase = Phase::Idle;
        self.changed.notify_all();
        true
    }
    /// Record the port that the phone tunnel started with.
    fn remember_tunnel_port(&self, port: u16) {
        if let Ok(mut stored) = self.tunnel_phone_port.lock() {
            *stored = Some(port);
        }
    }
    /// Clear the recorded tunnel port. No phone tunnel runs after this call.
    fn forget_tunnel_port(&self) {
        if let Ok(mut stored) = self.tunnel_phone_port.lock() {
            *stored = None;
        }
        self.phone_running.store(false, Ordering::Release);
    }
    /// Record whether a phone tunnel runs. The presence observer reads this
    /// flag. Only the start and stop paths set it.
    fn set_phone_running(&self, running: bool) {
        self.phone_running.store(running, Ordering::Release);
    }
    /// Drop every stored probe result. A new run must not inherit a ready or a
    /// silent result from the run that ended.
    fn reset_presence(&self) {
        if let Ok(mut presence) = self.presence.lock() {
            presence.state = None;
            presence.connections = None;
            presence.checked_at = None;
            presence.checked = None;
            presence.trusted_by_source = None;
        }
    }
    /// Serialize a run change with probe results and credential updates.
    fn bump_run(&self) -> u64 {
        let _presence = self
            .presence
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.run_id.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
    }
    /// Record the source host and physical interface of a running phone
    /// tunnel.
    fn remember_probe_target(&self, target: Option<ProbeTarget>) {
        if let Ok(mut stored) = self.probe_target.lock() {
            *stored = target;
        }
    }
    /// Clear the target of the run that ended.
    fn forget_probe_target(&self) {
        self.remember_probe_target(None);
    }
    /// The target for a probe while a phone tunnel runs. A probe outside a
    /// phone run uses the current default route.
    fn probe_target_now(&self) -> Option<ProbeTarget> {
        if !self.phone_running.load(Ordering::Acquire) {
            return None;
        }
        Some(
            self.probe_target
                .lock()
                .ok()
                .and_then(|target| *target)
                .unwrap_or(UNKNOWN_PROBE_TARGET),
        )
    }
    /// Replace the cancel flag of the run. The old flag is set first, so a
    /// fallback worker from the last run stops or drops its result.
    fn start_run_cancel(&self) {
        let cancel = Arc::new(AtomicBool::new(false));
        if let Ok(mut current) = self.run_cancel.lock() {
            current.store(true, Ordering::Release);
            *current = cancel;
        }
    }
    /// Set the cancel flag of the current run.
    fn cancel_run(&self) {
        if let Ok(current) = self.run_cancel.lock() {
            current.store(true, Ordering::Release);
        }
    }
    fn current_run_cancel(&self) -> Arc<AtomicBool> {
        self.run_cancel
            .lock()
            .map(|current| Arc::clone(&current))
            .unwrap_or_else(|_| Arc::new(AtomicBool::new(true)))
    }
    /// Build one observer over the shared state. It reads no credential.
    fn observer(&self, schedule: PresenceSchedule) -> PresenceObserver {
        PresenceObserver {
            presence: Arc::clone(&self.presence),
            pairing: Arc::clone(&self.pairing),
            forget: Arc::clone(&self.forget),
            forget_network: Arc::clone(&self.forget_network),
            probe_attempt: Arc::clone(&self.probe_attempt),
            phone_running: Arc::clone(&self.phone_running),
            probe_target: Arc::clone(&self.probe_target),
            run_id: Arc::clone(&self.run_id),
            schedule,
        }
    }
    /// Start one observer thread. The supervisor records whether the thread
    /// started and whether it ended in a panic.
    fn spawn_presence(
        &self,
        stop: Arc<AtomicBool>,
        schedule: PresenceSchedule,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let observer = self.observer(schedule);
        let control = Arc::clone(&self.observer);
        std::thread::Builder::new()
            .name("hotspotshade-presence".into())
            .spawn(move || {
                if let Ok(mut state) = control.lock() {
                    state.state = ObserverState::Running;
                }
                // A panic in one probe must not end the observation for the
                // engine lifetime. The supervisor records the failure and can
                // start a fresh observer.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    observer.run(stop);
                }));
                if let Ok(mut state) = control.lock() {
                    state.state = if outcome.is_err() {
                        ObserverState::Failed
                    } else {
                        ObserverState::Stopped
                    };
                }
            })
    }
    /// Start the presence observer with one schedule. The server uses the
    /// default schedule. A test uses a short schedule and joins the thread.
    fn start_presence_with(
        &self,
        stop: Arc<AtomicBool>,
        schedule: PresenceSchedule,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        if let Ok(mut control) = self.observer.lock() {
            control.state = ObserverState::Starting;
            control.stop = Some(Arc::clone(&stop));
            control.schedule = schedule;
            control.last_attempt = Some(Instant::now());
            control.starts = control.starts.saturating_add(1);
        }
        let spawned = self.spawn_presence(stop, schedule);
        if spawned.is_err() {
            if let Ok(mut control) = self.observer.lock() {
                control.state = ObserverState::Failed;
            }
        }
        spawned
    }
    /// Start the observer again after a spawn failure or a panic.
    ///
    /// A running observer is left alone. A normal stop is final. A retry
    /// waits `retry` after the last attempt, so a broken spawn does not spin.
    fn ensure_observer_at(&self, now: Instant) -> bool {
        let (stop, schedule) = {
            let Ok(mut control) = self.observer.lock() else {
                return false;
            };
            match control.state {
                ObserverState::Running | ObserverState::Starting => return true,
                ObserverState::NotStarted | ObserverState::Stopped => return false,
                ObserverState::Failed => (),
            }
            let Some(stop) = control.stop.clone() else {
                return false;
            };
            if stop.load(Ordering::Acquire) {
                return false;
            }
            if control
                .last_attempt
                .is_some_and(|at| now.saturating_duration_since(at) < control.retry)
            {
                return false;
            }
            control.state = ObserverState::Starting;
            control.last_attempt = Some(now);
            control.starts = control.starts.saturating_add(1);
            (stop, control.schedule)
        };
        if self.spawn_presence(stop, schedule).is_err() {
            if let Ok(mut control) = self.observer.lock() {
                if control.state == ObserverState::Starting {
                    control.state = ObserverState::Failed;
                }
            }
            return false;
        }
        true
    }
    fn ensure_observer(&self) -> bool {
        self.ensure_observer_at(Instant::now())
    }
    /// True when the observer could not start or panicked and has not
    /// recovered. Missing probe data is not proof that the source device is
    /// fine in that state.
    fn observer_failed(&self) -> bool {
        matches!(
            self.observer.lock().map(|state| state.state),
            Ok(ObserverState::Failed)
        )
    }
    /// Run one fallback probe after the observer failed. This restores source
    /// device monitoring for the auto-stop policy. It never starts or stops a
    /// tunnel, and a failed spawn records nothing.
    ///
    /// The probe runs on its own thread, so a status read does not wait for
    /// the bounded probe. The fallback is rate limited and one probe runs at a
    /// time.
    fn start_fallback_probe_at(&self, now: Instant) -> bool {
        if !self.observer_failed() {
            return false;
        }
        let watching = self.phone_running.load(Ordering::Acquire)
            || self
                .presence
                .lock()
                .ok()
                .and_then(|presence| presence.last_request)
                .is_some_and(|at| {
                    now.saturating_duration_since(at) < PresenceSchedule::default().idle_limit
                });
        if !watching {
            return false;
        }
        {
            let Ok(mut gate) = self.fallback_at.lock() else {
                return false;
            };
            if gate.is_some_and(|at| now.saturating_duration_since(at) < FALLBACK_RETRY) {
                return false;
            }
            if self.fallback_active.swap(true, Ordering::AcqRel) {
                return false;
            }
            *gate = Some(now);
        }
        let paired = self
            .pairing
            .lock()
            .map(|inner| inner.credentials.is_some())
            .unwrap_or(false);
        let presence = Arc::clone(&self.presence);
        let pairing = Arc::clone(&self.pairing);
        let attempt = Arc::clone(&self.probe_attempt);
        let active = Arc::clone(&self.fallback_active);
        let run_id = Arc::clone(&self.run_id);
        let run = run_id.load(Ordering::Acquire);
        let cancel = self.current_run_cancel();
        let target = self.probe_target_now();
        let spawned = std::thread::Builder::new()
            .name("hotspotshade-fallback".into())
            .spawn(move || {
                // The guard clears the in-flight flag on every exit, including
                // a panic outside the probe.
                let _active = FallbackActive(active);
                // A panic in one fallback probe must not end the engine.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    attempt(paired, cancel.as_ref(), target)
                }));
                // A late answer belongs to the run that asked for it. A stop
                // or a new start sets the cancel flag and changes the run id.
                if cancel.load(Ordering::Acquire) || run_id.load(Ordering::Acquire) != run {
                    return;
                }
                if let Ok(result) = outcome {
                    if !result.cancelled {
                        record_probe_for_run(&presence, &pairing, &run_id, run, &result);
                    }
                }
            });
        if spawned.is_err() {
            self.fallback_active.store(false, Ordering::Release);
            return false;
        }
        true
    }
    fn start_fallback_probe(&self) -> bool {
        self.start_fallback_probe_at(Instant::now())
    }
    /// Record the interface that the tunnel pins to.
    fn remember_tunnel_iface(&self, iface: Option<String>) {
        if let Ok(mut stored) = self.tunnel_iface.lock() {
            *stored = iface;
        }
    }
    /// Clear the recorded tunnel interface.
    fn forget_tunnel_iface(&self) {
        if let Ok(mut stored) = self.tunnel_iface.lock() {
            *stored = None;
        }
    }
    /// Record one completed stop and keep it for the engine lifetime.
    fn record_stop(&self, reason: &'static str) {
        if let Ok(mut last) = self.last_stop.lock() {
            *last = Some(LastStop {
                reason,
                at: now_unix(),
            });
        }
        self.phone_running.store(false, Ordering::Release);
        self.was_running.store(false, Ordering::Release);
    }
    /// Clear the last stop when a new tunnel starts.
    fn clear_last_stop(&self) {
        if let Ok(mut last) = self.last_stop.lock() {
            *last = None;
        }
    }
    /// Stop with one reason. The stop path is the same as a user stop.
    fn stop_with_reason(&self, reason: &'static str) -> Result<Value, String> {
        self.stop_until_for(Instant::now() + Duration::from_secs(30), None, reason)
    }
    /// Use a token from the request when one is present. Otherwise use the
    /// paired credentials.
    fn phone_target(&self, options: &Value) -> Result<(Ipv4Addr, u16, String), String> {
        let manual = options
            .get("token")
            .and_then(Value::as_str)
            .is_some_and(|t| !t.is_empty());
        if manual {
            return phone_options(options);
        }
        let inner = self.pairing.lock().map_err(|_| "pair_first")?;
        inner
            .credentials
            .as_ref()
            .map(|c| (c.host, c.port, c.token.clone()))
            .ok_or_else(|| "pair_first".into())
    }
    /// Require `host` to be the gateway of the current physical default route.
    ///
    /// A saved credential can name the gateway of a network that is gone. A
    /// manual request can name any address. The proxy token crosses the
    /// hotspot link in cleartext, so it may go only to the source device on the
    /// hotspot that is connected now. The route is read fresh and the caller
    /// pins the connection to that interface. A public gateway is refused: a
    /// hotspot gateway is always a private address, so a public address cannot
    /// be the source device.
    ///
    /// The stored credential holds only the gateway address. Two different
    /// networks that use the same private gateway address cannot be told
    /// apart here. Storing a network identity with the credential is open
    /// work; this check removes the old-network and arbitrary-host paths, not
    /// that same-address case.
    fn require_hotspot_gateway(&self, host: Ipv4Addr) -> Result<HotspotRoute, String> {
        let route = (self.route_lookup)().ok_or("no_hotspot")?;
        if !route.host.is_private() || route.host != host {
            return Err("source_device_moved".into());
        }
        Ok(route)
    }
    fn with_pairing(&self, mut status: Value) -> Value {
        // A poisoned service cannot establish whether a tunnel is running.
        // Cached presence, interface, and stop data cannot fill that gap.
        if status.get("state").and_then(Value::as_str) == Some("unknown") {
            return status;
        }
        // Read each lock alone. The pairing lock is not held with another lock.
        let observer_failed = self.observer_failed();
        let tunnel_port = self
            .tunnel_phone_port
            .lock()
            .ok()
            .and_then(|stored| *stored);
        let (presence_state, connections, checked_at, trusted_by_source, checked) = self
            .presence
            .lock()
            .ok()
            .map(|p| {
                (
                    p.state,
                    p.connections,
                    p.checked_at,
                    p.trusted_by_source,
                    p.checked,
                )
            })
            .unwrap_or((None, None, None, None, None));
        // The service or helper status names the interface that the running
        // tunnel actually pinned to. Prefer it over a cached default route.
        let status_iface = status
            .get("iface")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        let iface = self
            .tunnel_iface
            .lock()
            .ok()
            .and_then(|stored| stored.clone())
            .or(status_iface)
            .or_else(|| {
                (status.get("running") != Some(&json!(true)))
                    .then(discover_iface)
                    .flatten()
            });
        let (forget_state, forget_attempts) = self
            .forget
            .lock()
            .ok()
            .map(|state| (state.state(), state.attempts))
            .unwrap_or(("none", 0));
        let service_last_stop = status.get("last_stop").cloned();
        let last_stop = self
            .last_stop
            .lock()
            .ok()
            .and_then(|last| last.clone())
            .or_else(|| {
                let value = service_last_stop.as_ref()?;
                let reason = crate::autostop::reason(value.get("reason")?.as_str()?)?;
                let at = value.get("at")?.as_u64()?;
                Some(LastStop { reason, at })
            });
        let (stop_reason, stop_at) = match &last_stop {
            Some(last) => (json!(last.reason), json!(last.at)),
            None => (Value::Null, Value::Null),
        };
        let stop_message = last_stop
            .as_ref()
            .and_then(|last| autostop::stop_message(last.reason));
        if let Some(map) = status.as_object_mut() {
            map.insert("iface".into(), json!(iface));
            map.insert(
                "forget".into(),
                json!({"state":forget_state,"attempts":forget_attempts}),
            );
            map.insert(
                "last_stop".into(),
                json!({"reason":stop_reason,"at":stop_at}),
            );
            map.insert("last_stop_message".into(), json!(stop_message));
        }
        if let (Some(map), Ok(inner)) = (status.as_object_mut(), self.pairing.lock()) {
            let credentials = inner.credentials.as_ref();
            let running_phone = map.get("running") == Some(&json!(true))
                && map.get("mode") == Some(&json!("phone"));
            // A failed observer with no probe data, or a probe result from
            // before monitoring stopped, is not proof of a connection. The
            // auto-stop policy ignores an old `checked_at`, so this state
            // cannot stop the tunnel by itself.
            let stale = checked.is_some() && !probe_current(checked);
            let state = if running_phone && (stale || (presence_state.is_none() && observer_failed))
            {
                // The last probe is old, or monitoring failed before it
                // produced an answer. That is not proof that the source device
                // is off. Report a separate state so the app does not claim a
                // failure that it cannot see.
                "checking"
            } else {
                phone_state(presence_state, running_phone)
            };
            // A running tunnel keeps the port that it started with. Compare the
            // learned port with the start port. Do not change the tunnel.
            let port_changed =
                credentials.is_some_and(|c| tunnel_port.is_some_and(|started| started != c.port));
            let message = if port_changed {
                pairing::PORT_CHANGED_MESSAGE
            } else {
                phone_message(state)
            };
            map.insert("api".into(), json!(1));
            map.insert(
                "phone".into(),
                json!({"state":state,"message":message,"port_changed":port_changed,
                    "connections":connections,"checked_at":checked_at,
                    "trusted_by_source":trusted_by_source}),
            );
            map.insert("paired".into(), json!(credentials.is_some()));
            map.insert(
                "phone_host".into(),
                json!(credentials.map(|c| c.host.to_string())),
            );
            map.insert("phone_port".into(), json!(credentials.map(|c| c.port)));
        }
        status
    }
    fn start_phone(
        &self,
        options: &Value,
        (icmp_enabled, icmp_persistent): (bool, bool),
        cancel: Arc<AtomicBool>,
        slot: Arc<Mutex<Option<UnixStream>>>,
    ) -> Result<(Phase, Option<u16>, Ipv4Addr, Option<String>), String> {
        // The port-change notice applies only to a tunnel that uses the paired
        // credentials. The user chooses the port in a manual token request.
        let manual = options
            .get("token")
            .and_then(Value::as_str)
            .is_some_and(|t| !t.is_empty());
        let (host, port, token) = self.phone_target(options)?;
        /* Wrap the token before the check. Every early return then zeroes this
         * copy instead of dropping a plain String. */
        let token = ZeroToken(token);
        let route = self.require_hotspot_gateway(host)?;
        let started_port = (!manual).then_some(port);
        // A root engine starts the tunnel in its own process. The macOS app
        // opens a helper to gain root; the Linux app starts the packaged
        // engine through pkexec, so that engine is already root.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if unsafe { libc::geteuid() } == 0 {
            let proxy = PhoneProxy {
                address: SocketAddr::V4(SocketAddrV4::new(host, port)),
                username: "hotspotshade".into(),
                token: token.into_inner(),
                iface: Some(route.index),
                timeout: Duration::from_secs(5),
            };
            let options = TunOptions {
                iface: Some(route.iface.clone()),
                ipv6: Ipv6Policy::Forward,
                icmp_phone: icmp_enabled,
                icmp_persistent,
                ..TunOptions::default()
            };
            self.service
                .start_tun_options_cancellable(options, Some(proxy), worker_count(), &cancel)
                .map_err(phone_start_error)?;
            if cancel.load(Ordering::Acquire) {
                self.service.stop();
                return Err("start_cancelled".into());
            }
            // Read the interface that the service actually pinned to. A cached
            // pre-start default is not evidence for the presence probe.
            let pinned = match started_status_iface(&self.service.status(), "phone") {
                Ok(pinned) => pinned,
                Err(error) => {
                    self.service.stop();
                    return Err(error);
                }
            };
            return Ok((Phase::Local, started_port, host, pinned));
        }
        // A non-root Linux engine cannot open the TUN device or change the
        // routing table. Report the privilege requirement instead of trying a
        // helper that does not exist on this platform.
        #[cfg(target_os = "linux")]
        {
            let _ = (
                token,
                cancel,
                slot,
                started_port,
                icmp_enabled,
                icmp_persistent,
            );
            Err("admin_required".into())
        }
        #[cfg(target_os = "macos")]
        {
            // The macOS app starts real-mode engines through the installed
            // protected XPC helper. This process is not root, so it cannot
            // create a utun or change routes. Do not run a copy of this
            // user-writable binary as root. Report the missing helper.
            let _ = (
                token,
                cancel,
                slot,
                started_port,
                icmp_enabled,
                icmp_persistent,
            );
            Err("protected_helper_required".into())
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 4))
        .unwrap_or(2)
}
/// Map a source device start failure to a fixed code. The text is not a
/// secret. The HTTP layer maps `phone_auth` to its own fixed message.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn phone_start_error(error: io::Error) -> String {
    match error.to_string().as_str() {
        "phone_auth" => "phone_auth".into(),
        "source_device_moved" => "source_device_moved".into(),
        _ if error.kind() == io::ErrorKind::Interrupted => "start_cancelled".into(),
        _ if error.kind() == io::ErrorKind::PermissionDenied => "admin_required".into(),
        _ => "source device start failed".into(),
    }
}
/// Map a direct tunnel start failure to a fixed code. The page has its own
/// text for each known code. The service is the authority on the privilege
/// check and on the route and device stages, so this mapping must not hide a
/// real service code behind one generic failure.
#[cfg(any(unix, test))]
fn direct_start_error(error: io::Error) -> String {
    match error.kind() {
        io::ErrorKind::Interrupted => "start_cancelled".into(),
        io::ErrorKind::PermissionDenied => "admin_required".into(),
        _ => match error.to_string().as_str() {
            "route_setup" => "route_setup".into(),
            "tunnel_setup" => "tunnel_setup".into(),
            _ => "service_start".into(),
        },
    }
}
#[cfg(test)]
fn phone_start_request(
    host: Ipv4Addr,
    port: u16,
    token: &str,
    experimental_icmp: bool,
    experimental_icmp_persistent: bool,
) -> Value {
    json!({"action":"start","phone":[host.to_string(),port,"hotspotshade",token],"experimental_icmp":experimental_icmp,"experimental_icmp_persistent":experimental_icmp_persistent})
}

/// The physical interface that a successful start pinned to.
///
/// The start path reads this value from the service or helper status answer.
/// It never uses a cached default route. A status that does not describe the
/// expected running mode is a failed start. A missing name stays None: the
/// caller must treat the pin as unknown, never as permission to probe without
/// a pin.
fn started_status_iface(status: &Value, mode: &str) -> Result<Option<String>, String> {
    if status.get("running") != Some(&json!(true)) || status.get("mode") != Some(&json!(mode)) {
        return Err("service_start".into());
    }
    Ok(status
        .get("iface")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned))
}

/// The echo relay values for a start request. Direct modes ignore the fields.
fn mode_icmp_options(
    mode: &str,
    options: &Value,
    default_enabled: bool,
    default_persistent: bool,
) -> Result<Option<(bool, bool)>, String> {
    if mode == "phone" {
        crate::gui::phone_icmp_options(options, default_enabled, default_persistent).map(Some)
    } else {
        Ok(None)
    }
}
/// Parse the GUI SOCKS5 DNS server array with the same grammar as the CLI.
///
/// Each entry is one numeric IP literal with an optional port, including an
/// IPv6 literal in brackets or bare form. The result is deduplicated and
/// bounded by [`dns::normalize_servers`], so the GUI and `--dns-servers` accept
/// and reject the same values in the same order.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn socks_dns_servers(v: &Value) -> Result<Option<Vec<SocketAddr>>, String> {
    match v.get("dns_servers") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut servers = Vec::with_capacity(items.len());
            for item in items {
                let text = item.as_str().ok_or("DNS servers must be IP addresses")?;
                let server =
                    dns::parse_server(text).map_err(|_| "DNS servers must be IP addresses")?;
                servers.push(server);
            }
            dns::normalize_servers(servers)
                .map(Some)
                .map_err(|_| "invalid DNS servers".into())
        }
        _ => Err("invalid DNS servers".into()),
    }
}
fn phone_options(v: &Value) -> Result<(Ipv4Addr, u16, String), String> {
    let host = v
        .get("host")
        .and_then(Value::as_str)
        .ok_or("invalid source device host")?
        .parse::<Ipv4Addr>()
        .map_err(|_| "invalid source device host")?;
    if host.is_unspecified() || host.is_multicast() || host.is_broadcast() || host.is_loopback() {
        return Err("invalid source device host".into());
    }
    let port = v
        .get("port")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0 && *n <= 65535)
        .ok_or("invalid source device port")? as u16;
    let token = v
        .get("token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or("invalid source device token")?
        .to_owned();
    Ok((host, port, token))
}
fn options(payload: &Value) -> Result<&Value, String> {
    let o = payload.get("options").ok_or("missing options")?;
    if o.is_object() {
        Ok(o)
    } else {
        Err("invalid options".into())
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn tun_options(v: &Value) -> Result<TunOptions, String> {
    if !v.is_object() {
        return Err("invalid tunnel options".into());
    }
    let unit = match v.get("unit") {
        None => 0,
        Some(x) => x
            .as_u64()
            .filter(|n| *n <= 255)
            .ok_or("invalid tunnel unit")? as u32,
    };
    let addr = match v.get("addr") {
        None => Ipv4Addr::new(198, 18, 0, 1),
        Some(x) => x
            .as_str()
            .ok_or("invalid tunnel address")?
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid tunnel address")?,
    };
    let iface = match v.get("iface") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        _ => return Err("invalid interface".into()),
    };
    let dns_upstream = match v.get("dns_upstream") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s)) => {
            Some(dns::parse_server(s.trim()).map_err(|_| "invalid DNS upstream")?)
        }
        _ => return Err("invalid DNS upstream".into()),
    };
    let ipv6 = match v.get("ipv6") {
        None => Ipv6Policy::Block,
        Some(Value::String(s)) if s == "block" => Ipv6Policy::Block,
        Some(Value::String(s)) if s == "inherit" => Ipv6Policy::Inherit,
        Some(Value::String(s)) if s == "forward" => Ipv6Policy::Forward,
        _ => return Err("invalid IPv6 policy".into()),
    };
    let no_routes = match v.get("no_routes") {
        None => false,
        Some(Value::Bool(b)) => *b,
        _ => return Err("invalid route option".into()),
    };
    let options = TunOptions {
        unit,
        addr,
        iface,
        dns_upstream,
        no_routes,
        no_pin: false,
        ipv6,
        icmp_phone: false,
        icmp_persistent: false,
        #[cfg(any(windows, test))]
        wintun_dll: None,
    };
    options
        .validate(false, worker_count())
        .map_err(|_| "invalid tunnel options")?;
    Ok(options)
}
#[cfg(test)]
fn request(helper: &Arc<Mutex<Helper>>, message: &Value) -> Result<Value, String> {
    let mut helper = helper.lock().map_err(|_| "helper unavailable")?;
    privileged::send(&mut helper.stream, message).map_err(|_| "helper disconnected")?;
    let response = privileged::receive(&mut helper.stream).map_err(|_| "helper disconnected")?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        return Err("helper failed".into());
    }
    Ok(response)
}
#[cfg(test)]
fn close_helper(helper: &Arc<Mutex<Helper>>) -> Result<(), String> {
    let mut helper = helper.lock().map_err(|_| "helper unavailable")?;
    let _ = helper.stream.shutdown(std::net::Shutdown::Both);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match helper.launcher.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Err(_) => return Err("helper cleanup failed".into()),
            Ok(None) if Instant::now() >= deadline => return Err("helper is still stopping".into()),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// How long one final helper request may wait. The caller is already on an
/// error path and must not hang the status answer.
#[cfg(test)]
const HELPER_FINALIZE: Duration = Duration::from_secs(2);

/// Give one failed helper a bounded stop request, then close its stream.
///
/// This runs without the phase lock. The stream close makes the helper cleanup
/// guard stop the service and remove its routes. It never starts a tunnel.
#[cfg(test)]
fn finalize_helper(helper: &Arc<Mutex<Helper>>) {
    if let Ok(mut helper) = helper.lock() {
        let _ = helper.stream.set_read_timeout(Some(HELPER_FINALIZE));
        let _ = helper.stream.set_write_timeout(Some(HELPER_FINALIZE));
        if privileged::send(&mut helper.stream, &json!({"action":"stop"})).is_ok() {
            let _ = privileged::receive(&mut helper.stream);
        }
        let _ = helper.stream.shutdown(std::net::Shutdown::Both);
    }
}
#[cfg(all(test, target_os = "macos"))]
fn shell_quote(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c.is_control()) {
        return Err("invalid path".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

impl GuiBackend for RustGuiBackend {
    /// `POST /api/pairing/handoff` reaches the user engine through the trait.
    /// Without this override the route returns the trait default,
    /// `handoff_unsupported`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn pair_handoff(&self) -> Result<Value, String> {
        RustGuiBackend::pair_handoff(self)
    }
    fn api_request(&self) {
        if let Ok(mut presence) = self.presence.lock() {
            presence.last_request = Some(Instant::now());
        }
    }
    fn mark_closing(&self) {
        // Set before the server's first stop. begin() and pair_start() read it
        // under the phase lock, so a late request cannot start work after the
        // final stop.
        self.closing.store(true, Ordering::Release);
    }
    fn start_presence(&self, stop: Arc<AtomicBool>) {
        // The supervisor records a failed thread start. `status` starts the
        // observer again after the retry period. The tunnel is not touched.
        let _ = self.start_presence_with(stop, PresenceSchedule::default());
    }

    fn status(&self) -> Result<Value, String> {
        // A failed or panicked observer is started again on a status read.
        self.ensure_observer();
        // If the supervisor cannot restart it, one bounded fallback probe
        // keeps the source device monitored. It never touches the tunnel.
        self.start_fallback_probe();
        // Remember which run this answer describes. A stop or a new start
        // changes the id, so a late error stop cannot clear newer state.
        let observed_run = self.run_id.load(Ordering::Acquire);
        #[cfg(test)]
        let status = if let Some(helper) = self.active_helper() {
            match request(&helper, &json!({"action":"status"})) {
                Ok(value) => {
                    let status = value
                        .get("status")
                        .cloned()
                        .ok_or("helper status missing")?;
                    // A stop or a new start can replace the helper while the
                    // answer is in flight. Do not report the old run.
                    if !self.helper_is_current(observed_run, &helper) {
                        return Err("service state unavailable".into());
                    }
                    status
                }
                Err(error) => {
                    // A socket error can be transient. Only a reaped launcher
                    // process is proof that the tunnel is gone.
                    if !Self::helper_exited(&helper) {
                        return Err(error);
                    }
                    // The launcher is gone. Send one final stop and close the
                    // stream so the helper cleanup guard removes any routes.
                    // The run id and the helper identity must still match: a
                    // stop or a new start may own a newer helper now.
                    if !self.finalize_helper_for_run(observed_run, &helper) {
                        return Err(error);
                    }
                    if !self.retire_dead_helper(&helper) {
                        // A stop or a new start owns the phase now.
                        return Err(error);
                    }
                    // The tunnel lived in the helper. Report the stopped
                    // service. The error stop is already recorded.
                    self.service.status()
                }
            }
        } else {
            self.service.status()
        };
        #[cfg(not(test))]
        let status = self.service.status();
        // A tunnel that stops without a stop request is an error stop. A user
        // stop and an auto stop claim the transition first. A live helper that
        // reports no tunnel gets one final stop before the state is cleared.
        let running = status.get("running") == Some(&json!(true));
        if self.was_running.load(Ordering::Acquire) && !running {
            #[cfg(test)]
            {
                if let Some(helper) = self.active_helper() {
                    // Never touch a helper that a newer run owns.
                    if !self.finalize_helper_for_run(observed_run, &helper) {
                        return Err("service state unavailable".into());
                    }
                    // Keep the helper in the phase until its launcher exits. A
                    // later status read reaps it without blocking this request.
                    if !Self::helper_exited(&helper) {
                        return Err("helper is still stopping".into());
                    }
                }
            }
            self.finish_error_stop(observed_run);
        }
        Ok(self.with_pairing(status))
    }
    fn failures(&self) -> Result<Value, String> {
        #[cfg(test)]
        {
            if let Some(helper) = self.active_helper() {
                return request(&helper, &json!({"action":"failures"})).and_then(|v| {
                    v.get("failures")
                        .cloned()
                        .ok_or_else(|| "helper failures missing".into())
                });
            }
        }
        Ok(self.service.failures())
    }
    fn diagnostics(&self) -> Result<Value, String> {
        #[cfg(test)]
        {
            if let Some(helper) = self.active_helper() {
                return request(&helper, &json!({"action":"diagnostics"})).and_then(|v| {
                    v.get("diagnostics")
                        .cloned()
                        .ok_or_else(|| "helper diagnostics missing".into())
                });
            }
        }
        Ok(self.service.diagnostics())
    }
    fn pair_start(&self) -> Result<Value, String> {
        // Take the phase lock first, in the same order as pair_forget. The
        // shutdown flag is checked while the phase lock is held, so a pairing
        // cannot start after shutdown's final stop.
        let phase = self.phase.lock().map_err(|_| "pair_state")?;
        if self.closing.load(Ordering::Acquire) {
            return Err("service is stopping".into());
        }
        let mut inner = self.pairing.lock().map_err(|_| "pair_state")?;
        if inner.cancel.is_some() {
            return Err("pair_busy".into());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        inner.generation += 1;
        let generation = inner.generation;
        inner.cancel = Some(Arc::clone(&cancel));
        inner.view = PairView {
            phase: PairPhase::Connecting,
            ..PairView::default()
        };
        // A new pairing clears a completed forget state and a pending retry
        // that has no request in flight. A request that is already in flight
        // stays pending: the pairing thread waits for it before it sends its
        // own exchange, because a generation bump cannot undo bytes that have
        // already left this device.
        if let Ok(mut forget) = self.forget.lock() {
            if !forget.in_flight {
                forget.clear();
                forget.generation = forget.generation.wrapping_add(1);
            }
        }
        let view = inner.view.to_json();
        drop(inner);
        drop(phase);
        let shared = Arc::clone(&self.pairing);
        let forget = Arc::clone(&self.forget);
        let attempt = Arc::clone(&self.pair_attempt);
        let drain = self.forget_drain;
        let spawned = std::thread::Builder::new()
            .name("hotspotshade-pair".into())
            .spawn(move || run_pairing(shared, generation, cancel, forget, attempt, drain));
        if spawned.is_err() {
            pair_spawn_failed(&self.pairing, generation);
            return Err("pair_start".into());
        }
        Ok(view)
    }
    fn pair_status(&self) -> Result<Value, String> {
        let inner = self.pairing.lock().map_err(|_| "pair_state")?;
        Ok(inner.view.to_json())
    }
    fn pair_forget(&self) -> Result<Value, String> {
        // A running tunnel keeps the proxy token. Refuse the forget instead of
        // clearing the credentials that the tunnel still uses.
        let phase = self.phase.lock().map_err(|_| "pair_state")?;
        if !matches!(*phase, Phase::Idle) || self.service.status()["running"] == true {
            return Err("tunnel_running".into());
        }
        let mut inner = self.pairing.lock().map_err(|_| "pair_state")?;
        // Cancel a pairing that is in progress before the state is cleared.
        if let Some(cancel) = inner.cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        inner.generation += 1;
        inner.credentials = None;
        inner.view = inner.resting_view();
        // Send a FORGET even when this target device holds no credentials. The
        // source device can still trust the old key.
        if let Ok(mut forget) = self.forget.lock() {
            forget.pending = true;
            forget.attempts = 0;
            forget.outcome = ForgetOutcome::None;
            forget.generation = forget.generation.wrapping_add(1);
        }
        drop(inner);
        drop(phase);
        spawn_forget(Arc::clone(&self.forget), Arc::clone(&self.forget_network));
        // Probe at once so that the page shows the real source device state
        // and whether the old key is still trusted.
        let run = self.run_id.load(Ordering::Acquire);
        let result = (self.probe_attempt)(false, &AtomicBool::new(false), None);
        if self.run_id.load(Ordering::Acquire) == run {
            record_probe_for_run(&self.presence, &self.pairing, &self.run_id, run, &result);
        }
        Ok(json!({"ok":true}))
    }
    fn phone_probe(&self) -> Result<Value, String> {
        // Serialize the probes and skip a second probe inside 500 ms. A
        // concurrent caller waits for the first probe and then reads the
        // cached phone object.
        let mut gate = self.probe_gate.lock().map_err(|_| "probe_state")?;
        let run = gate.is_none_or(|at| at.elapsed() >= Duration::from_millis(500));
        if run {
            *gate = Some(Instant::now());
            let paired = self
                .pairing
                .lock()
                .map(|p| p.credentials.is_some())
                .unwrap_or(false);
            let observed_run = self.run_id.load(Ordering::Acquire);
            let target = self.probe_target_now();
            let result = (self.probe_attempt)(paired, &AtomicBool::new(false), target);
            if self.run_id.load(Ordering::Acquire) == observed_run {
                record_probe_for_run(
                    &self.presence,
                    &self.pairing,
                    &self.run_id,
                    observed_run,
                    &result,
                );
            }
        }
        drop(gate);
        let status = self.status()?;
        Ok(json!({"ok":true,"phone":status["phone"].clone()}))
    }
    fn pair_cancel(&self) -> Result<Value, String> {
        let mut inner = self.pairing.lock().map_err(|_| "pair_state")?;
        if let Some(cancel) = inner.cancel.take() {
            cancel.store(true, Ordering::Release);
            // Ignore the late result of the cancelled thread.
            inner.generation += 1;
            inner.view = inner.resting_view();
        }
        Ok(inner.view.to_json())
    }
    fn probe(&self) -> Result<Value, String> {
        let status = self.service.status();
        let udp = normalization::Audit::default();
        let udp_ok =
            normalization::udp_socket(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), None, &udp)
                .is_ok();
        let tcp = normalization::Audit::default();
        let _ = normalization::tcp_start(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
            None,
            &tcp,
        );
        let (tcp_total, tcp_bad) = tcp.snapshot();
        let bound = environment::default_route()
            .ok()
            .and_then(|r| normalization::interface_index(&r.interface).ok())
            .is_some_and(|index| {
                normalization::udp_socket(
                    std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some(index),
                    &normalization::Audit::default(),
                )
                .is_ok()
            });
        Ok(
            json!({"available":true,"platform":status["platform"],"admin":unsafe { libc::geteuid()==0 },"capabilities":{"ip_ttl_udp":udp_ok,"ip_ttl_tcp":tcp_total>0 && tcp_bad==0,"bound_if":bound,"utun_needs_root":true}}),
        )
    }
    fn phone_discover(&self) -> Result<Value, String> {
        let route = environment::default_route().map_err(|_| "no physical interface")?;
        let index = normalization::interface_index(&route.interface)
            .map_err(|_| "no physical interface")?;
        let host = match route.gateway {
            Some(ip) => ip,
            None => {
                return Ok(
                    json!({"host":null,"port":1080,"reachable":false,"message":"Connect this device to the source device hotspot."}),
                )
            }
        };
        let audit = normalization::Audit::default();
        for port in [1080u16, 18080] {
            if normalization::tcp_connect(
                SocketAddr::V4(SocketAddrV4::new(host, port)),
                Some(index),
                &audit,
                Duration::from_secs(1),
            )
            .is_ok()
            {
                return Ok(
                    json!({"host":host.to_string(),"port":port,"reachable":true,"message":"A gateway accepted a TCP connection. Check the token to verify the proxy."}),
                );
            }
        }
        Ok(
            json!({"host":host.to_string(),"port":1080,"reachable":false,"message":"No proxy answered on ports 1080 or 18080."}),
        )
    }
    fn phone_check(&self, payload: Value) -> Result<Value, String> {
        let (host, port, token) = phone_options(&payload)?;
        let token = ZeroToken(token);
        /* Do not send the token to any host except the gateway of the current
         * default route. A manual check is not a general TCP test. */
        let route = self.require_hotspot_gateway(host)?;
        let proxy = PhoneProxy {
            address: SocketAddr::V4(SocketAddrV4::new(host, port)),
            username: "hotspotshade".into(),
            token: token.into_inner(),
            iface: Some(route.index),
            timeout: Duration::from_secs(5),
        };
        proxy
            .check(&normalization::Audit::default())
            .map_err(|_| "source device authentication failed")?;
        Ok(json!({"ok":true,"message":"The source device proxy accepted the token."}))
    }
    fn start(&self, payload: Value) -> Result<Value, String> {
        let mode = payload
            .get("mode")
            .and_then(Value::as_str)
            .ok_or("missing mode")?;
        // The helper-owned engine starts without an administrator prompt. A
        // start that changes routes must present the one-time grant that the
        // helper wrote after it verified the administrator authorization. The
        // grant is consumed before any option or route work, so one
        // authorization covers one attempt. A manually started root GUI has no
        // grant file; root is already the authorization for that path. An
        // engine that imported pairing credentials is still a helper engine,
        // so it never falls back to that root authority when its grant is
        // missing. The helper engine runs only the grant-checked modes. Any
        // other mode, such as a local SOCKS5 listener, would run as root
        // without a prompt, so it is refused before the grant is touched.
        #[cfg(target_os = "macos")]
        if self.tunnel_grant_required && mode != "phone" && mode != "tun" {
            return Err("mode_not_allowed".into());
        }
        // A Linux root engine runs only the tunnel that pkexec authorized.
        #[cfg(any(target_os = "linux", test))]
        if self.tunnel_modes_only && mode != "phone" && mode != "tun" {
            return Err("mode_not_allowed".into());
        }
        #[cfg(target_os = "macos")]
        if (mode == "phone" || mode == "tun") && self.tunnel_grant_required {
            match &self.tunnel_grant {
                Some(grant) => grant.consume().map_err(|_| "authorization_required")?,
                None => return Err("authorization_required".into()),
            }
        }
        let opts = options(&payload)?;
        let icmp = mode_icmp_options(
            mode,
            opts,
            self.experimental_icmp,
            self.experimental_icmp_persistent,
        )?;
        let (cancel, slot) = self.begin()?;
        // A panic in a start stage must not leave a Starting phase, an
        // untracked local service, or a stale presence result.
        let mut recovery = StartRecovery {
            backend: self,
            cancel: Arc::clone(&cancel),
            socket: Arc::clone(&slot),
            armed: true,
        };
        let (result, panicked) =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (|| -> Result<StartOutcome, String> {
                    match mode {
                        "phone" => self
                            .start_phone(
                                opts,
                                icmp.unwrap_or((false, false)),
                                Arc::clone(&cancel),
                                Arc::clone(&slot),
                            )
                            .map(|(phase, port, host, pinned)| (phase, port, Some(host), pinned)),
                        "socks5" => {
                            let host = opts
                                .get("host")
                                .and_then(Value::as_str)
                                .unwrap_or("127.0.0.1")
                                .parse::<Ipv4Addr>()
                                .map_err(|_| "invalid host")?;
                            if host != Ipv4Addr::LOCALHOST {
                                return Err("listener must use loopback".into());
                            }
                            let port = opts.get("port").and_then(Value::as_u64).unwrap_or(1080);
                            if port == 0 || port > 65535 {
                                return Err("invalid port".into());
                            }
                            let iface = opts
                                .get("iface")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty());
                            let dns = socks_dns_servers(opts)?;
                            self.start_socks_service(
                                SocketAddr::V4(SocketAddrV4::new(host, port as u16)),
                                iface,
                                dns,
                            )
                            .map_err(direct_start_error)?;
                            if cancel.load(Ordering::Acquire) {
                                self.service.stop();
                                return Err("start cancelled".into());
                            }
                            let pinned =
                                match started_status_iface(&self.service.status(), "socks5") {
                                    Ok(pinned) => pinned,
                                    Err(error) => {
                                        self.service.stop();
                                        return Err(error);
                                    }
                                };
                            Ok((Phase::Local, None, None, pinned))
                        }
                        "tun" => {
                            #[cfg(test)]
                            if PANIC_NEXT_TUN_START.with(|flag| flag.replace(false)) {
                                // No panic hook: this is an injected fault, not
                                // a test failure.
                                std::panic::resume_unwind(Box::new("injected tunnel start panic"));
                            }
                            #[cfg(target_os = "macos")]
                            {
                                let parsed = tun_options(opts)?;
                                self.service
                                    .start_tun_options(parsed, None, worker_count())
                                    .map_err(direct_start_error)?;
                                if cancel.load(Ordering::Acquire) {
                                    self.service.stop();
                                    return Err("start cancelled".into());
                                }
                                let pinned =
                                    match started_status_iface(&self.service.status(), "tun") {
                                        Ok(pinned) => pinned,
                                        Err(error) => {
                                            self.service.stop();
                                            return Err(error);
                                        }
                                    };
                                Ok((Phase::Local, None, None, pinned))
                            }
                            #[cfg(target_os = "linux")]
                            {
                                // The service checks the privilege before it creates a
                                // TUN device or changes a route. Do not duplicate that
                                // check here: the service is the authority, and its
                                // PermissionDenied becomes admin_required below.
                                let parsed = tun_options(opts)?;
                                self.service
                                    .start_tun_options_cancellable(
                                        parsed,
                                        None,
                                        worker_count(),
                                        &cancel,
                                    )
                                    .map_err(direct_start_error)?;
                                if cancel.load(Ordering::Acquire) {
                                    self.service.stop();
                                    return Err("start cancelled".into());
                                }
                                let pinned =
                                    match started_status_iface(&self.service.status(), "tun") {
                                        Ok(pinned) => pinned,
                                        Err(error) => {
                                            self.service.stop();
                                            return Err(error);
                                        }
                                    };
                                Ok((Phase::Local, None, None, pinned))
                            }
                            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                            {
                                Err("tun unavailable".into())
                            }
                        }
                        _ => Err("invalid mode".into()),
                    }
                })()
            })) {
                Ok(result) => (result, false),
                Err(_) => {
                    if mode == "tun" || mode == "phone" {
                        self.service.mark_start_panic();
                    }
                    (Err("start failed".into()), true)
                }
            };
        match result {
            Ok((next, port, phone_host, pinned_iface)) => {
                // Use the interface that the successful start actually pinned
                // to. A missing or unresolvable name stays None, so the
                // presence probe reports an unknown pin and never runs
                // unpinned.
                let target = phone_host
                    .filter(|_| mode == "phone")
                    .map(|host| probe_target(host, pinned_iface.as_deref()));
                // Publish the start only after every field is ready. The phase
                // lock keeps a stop from clearing the new data halfway.
                if let Err(error) =
                    self.finish_start_with_target(next, mode == "phone", pinned_iface, port, target)
                {
                    // No phase owns this service now. Stop it instead of
                    // leaving an untracked tunnel behind.
                    self.service.stop();
                    recovery.disarm();
                    return Err(error);
                }
                recovery.disarm();
                Ok(json!({"mode":mode}))
            }
            Err(e) => {
                if let Ok(mut phase) = self.phase.lock() {
                    if matches!(*phase, Phase::Starting { .. }) {
                        self.clear_tunnel_run();
                        self.reset_presence();
                        *phase = Phase::Idle;
                    }
                    self.changed.notify_all();
                }
                if !panicked {
                    recovery.disarm();
                }
                Err(e)
            }
        }
    }
    fn stop_for(&self, reason: &'static str) -> Result<Value, String> {
        self.stop_with_reason(reason)
    }
    fn monitor_generation(&self) -> Option<u64> {
        Some(self.run_id.load(Ordering::Acquire))
    }
    fn stop_for_generation(
        &self,
        reason: &'static str,
        generation: Option<u64>,
    ) -> Result<Value, String> {
        self.stop_until_for(Instant::now() + Duration::from_secs(30), generation, reason)
    }
    fn stop(&self) -> Result<Value, String> {
        self.stop_until(Instant::now() + Duration::from_secs(30))
    }
}

impl RustGuiBackend {
    fn stop_until(&self, deadline: Instant) -> Result<Value, String> {
        self.stop_until_for(deadline, None, "user")
    }
    fn stop_until_for(
        &self,
        deadline: Instant,
        expected_run: Option<u64>,
        reason: &'static str,
    ) -> Result<Value, String> {
        loop {
            let mut phase = self.phase.lock().map_err(|_| "service state unavailable")?;
            if expected_run.is_some_and(|run| self.run_id.load(Ordering::Acquire) != run) {
                drop(phase);
                if self.service.cleanup_uncertain() {
                    return Err(crate::service::CLEANUP_UNCERTAIN_MESSAGE.into());
                }
                return Ok(json!({"stopped":false}));
            }
            match &*phase {
                Phase::Idle => {
                    self.forget_tunnel_port();
                    self.forget_tunnel_iface();
                    self.forget_probe_target();
                    self.start_run_cancel();
                    drop(phase);
                    // A worker can fail after the phase is already Idle, or a
                    // stop can have published Idle after a failed cleanup. The
                    // service flag is the durable answer for this process. Do
                    // not hold the phase lock across the service lock: a start
                    // in flight holds it for the whole start.
                    if self.service.cleanup_uncertain() {
                        return Err(crate::service::CLEANUP_UNCERTAIN_MESSAGE.into());
                    }
                    return Ok(json!({"stopped":false}));
                }
                Phase::Starting { cancel, socket } => {
                    cancel.store(true, Ordering::Release);
                    self.cancel_run();
                    if let Ok(s) = socket.lock() {
                        if let Some(stream) = s.as_ref() {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                        }
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err("helper is still stopping".into());
                    }
                    let (_guard, timeout) = self
                        .changed
                        .wait_timeout(phase, remaining)
                        .map_err(|_| "service state unavailable")?;
                    if timeout.timed_out() {
                        return Err("helper is still stopping".into());
                    }
                }
                Phase::Stopping => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err("service is still stopping".into());
                    }
                    let (_guard, timeout) = self
                        .changed
                        .wait_timeout(phase, remaining)
                        .map_err(|_| "service state unavailable")?;
                    if timeout.timed_out() {
                        return Err("service is still stopping".into());
                    }
                }
                Phase::Local => {
                    *phase = Phase::Stopping;
                    // A status read that started before this stop must not
                    // record an error stop for the run that this stop owns.
                    let stop_run = self.bump_run();
                    self.cancel_run();
                    drop(phase);
                    // A panic in the stop path must not leave Stopping forever.
                    // The guard restores Local and retries the local stop.
                    let mut recovery = StopRecovery {
                        backend: self,
                        run: stop_run,
                        original: Some(Phase::Local),
                    };
                    self.service.stop();
                    let finished = self.finish_stop(reason);
                    if finished.is_ok() {
                        recovery.disarm();
                    }
                    if let Some(cleanup_error) = finished? {
                        return Err(cleanup_error);
                    }
                    return Ok(json!({"stopped":true}));
                }
                #[cfg(test)]
                Phase::Remote(helper) => {
                    let helper = Arc::clone(helper);
                    *phase = Phase::Stopping;
                    let stop_run = self.bump_run();
                    self.cancel_run();
                    drop(phase);
                    let mut recovery = StopRecovery {
                        backend: self,
                        run: stop_run,
                        original: Some(Phase::Remote(Arc::clone(&helper))),
                    };
                    // A helper that already exited has no tunnel to stop. The
                    // cleanup below reaps it. A helper that is alive gets the
                    // normal stop request.
                    let dead = Self::helper_exited(&helper);
                    let result = if dead {
                        Ok(json!({"ok":true}))
                    } else {
                        request(&helper, &json!({"action":"stop"}))
                    };
                    let cleanup = close_helper(&helper);
                    if cleanup.is_err() {
                        self.finish(Phase::Remote(helper));
                        recovery.disarm();
                        return cleanup.map(|_| json!({"stopped":false}));
                    }
                    let finished = self.finish_stop(reason);
                    if finished.is_ok() {
                        recovery.disarm();
                    }
                    if let Some(cleanup_error) = finished? {
                        return Err(cleanup_error);
                    }
                    result?;
                    return Ok(json!({"stopped":true}));
                }
            }
        }
    }
}

impl Drop for RustGuiBackend {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use crate::gui::start_error_message;

    #[cfg(target_os = "macos")]
    #[test]
    fn a_helper_engine_refuses_a_tunnel_start_without_a_grant() {
        use crate::gui::GuiBackend;
        use crate::service::Service;
        use crate::tunnel_grant::TunnelGrant;
        use serde_json::json;
        use std::sync::Arc;
        let backend = RustGuiBackend::with_tunnel_grant(
            Arc::new(Service::new()),
            TunnelGrant::new(std::env::temp_dir().join("hotspotshade-missing-grant")),
        );
        let error = backend
            .start(json!({"mode":"phone"}))
            .expect_err("a helper engine must refuse a start without a grant");
        assert_eq!(error, "authorization_required");
    }

    #[cfg(target_os = "macos")]
    fn imported_backend(grant: Option<TunnelGrant>) -> RustGuiBackend {
        let mut backend = RustGuiBackend::with_imported_credentials(
            Arc::new(Service::new()),
            Identity::from_bytes([0x47; 32]),
            PhoneCredentials {
                // TEST-NET-1 is never a hotspot gateway. Even if a failing
                // route lookup were not in place, the gateway check refuses it.
                host: Ipv4Addr::new(192, 0, 2, 1),
                port: 18080,
                token: "public-test-token".into(),
            },
            grant,
        )
        .expect("the test identity is the first import");
        // No route in a hermetic test. A phone start fails at the gateway
        // check before it opens a socket, whatever network the host uses.
        backend.route_lookup = Arc::new(|| None);
        backend
    }

    /// One private grant directory owned by the test user. The production
    /// path is root-owned; the test seam lets a hermetic test exercise the
    /// same freshness and permission checks without root.
    #[cfg(target_os = "macos")]
    fn grant_fixture() -> (std::path::PathBuf, std::path::PathBuf, u32) {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hotspotshade-gui-grant-{}-{}-{}",
            std::process::id(),
            nanos,
            unique
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("tunnel-grant");
        let owner = unsafe { libc::geteuid() } as u32;
        (directory, path, owner)
    }

    #[cfg(target_os = "macos")]
    fn write_grant(path: &std::path::Path, timestamp: u64) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("{} {timestamp}\n", "a".repeat(64))).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn imported_credentials_refuse_a_second_identity() {
        // The first import is the process-wide handoff identity. A second
        // engine with a different key must not replace it.
        let _first = imported_backend(None);
        let error = RustGuiBackend::with_imported_credentials(
            Arc::new(Service::new()),
            Identity::from_bytes([0x48; 32]),
            PhoneCredentials {
                host: Ipv4Addr::new(192, 0, 2, 1),
                port: 18080,
                token: "public-test-token".into(),
            },
            None,
        )
        .err()
        .expect("a different imported identity must be refused");
        assert!(matches!(error, crate::pairing::PairError::Identity));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn imported_credentials_refuse_phone_and_tun_without_a_grant() {
        // No grant option at all: the engine was not launched by the helper
        // with a grant path. Imported credentials must not become authority.
        let backend = imported_backend(None);
        for mode in ["phone", "tun"] {
            let error = backend
                .start(json!({"mode":mode}))
                .expect_err("imported credentials still need a grant");
            assert_eq!(error, "authorization_required", "mode {mode}");
        }

        // A grant path that does not exist yet is the normal state before the
        // person authorizes the first start. It is a refusal, not a bypass.
        let (directory, path, owner) = grant_fixture();
        let backend = imported_backend(Some(TunnelGrant::with_expected_owner(path, owner)));
        for mode in ["phone", "tun"] {
            let error = backend
                .start(json!({"mode":mode}))
                .expect_err("a missing grant must refuse the start");
            assert_eq!(error, "authorization_required", "mode {mode}");
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_helper_engine_refuses_every_mode_without_a_grant_check() {
        // A root engine started by the helper must not open a local SOCKS5
        // listener, or any other mode, without the administrator grant. The
        // refusal comes before the grant is read, so a fresh grant survives.
        let (directory, path, owner) = grant_fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_grant(&path, now);
        let helper = RustGuiBackend::with_tunnel_grant(
            Arc::new(Service::new()),
            TunnelGrant::with_expected_owner(path.clone(), owner),
        );
        let imported =
            imported_backend(Some(TunnelGrant::with_expected_owner(path.clone(), owner)));
        for backend in [&helper, &imported] {
            for payload in [
                json!({"mode":"socks5","options":{"host":"127.0.0.1","port":1080}}),
                json!({"mode":"socks5","options":{"host":"127.0.0.1","port":80}}),
                json!({"mode":"other"}),
            ] {
                let error = backend
                    .start(payload.clone())
                    .expect_err("a helper engine must refuse an unchecked mode");
                assert_eq!(error, "mode_not_allowed", "payload {payload}");
                assert!(path.exists(), "the refusal must not consume the grant");
                assert_eq!(backend.service.status()["running"], json!(false));
            }
        }
        assert_eq!(
            start_error_message("mode_not_allowed"),
            Some("The protected engine starts only the tunnel.")
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn imported_credentials_refuse_phone_and_tun_with_a_stale_grant() {
        let (directory, path, owner) = grant_fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_grant(&path, now.saturating_sub(61));
        let backend = imported_backend(Some(TunnelGrant::with_expected_owner(path.clone(), owner)));
        for mode in ["phone", "tun"] {
            let error = backend
                .start(json!({"mode":mode}))
                .expect_err("a stale grant must refuse the start");
            assert_eq!(error, "authorization_required", "mode {mode}");
        }
        // A refused stale grant stays for a person to inspect. It cannot be
        // retried into a valid grant.
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn imported_credentials_consume_a_fresh_grant_before_the_route_check() {
        let (directory, path, owner) = grant_fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_grant(&path, now);
        let backend = imported_backend(Some(TunnelGrant::with_expected_owner(path.clone(), owner)));
        // The grant is consumed before option validation, so this start reaches
        // the phone gateway check and fails there. The test route lookup is
        // empty, so it fails before any socket or route code on the host.
        let first = backend
            .start(json!({"mode":"phone","options":{}}))
            .expect_err("a phone start without options still fails");
        assert_eq!(first, "no_hotspot");
        assert!(!path.exists(), "the fresh grant is single use");
        // One authorization covers one attempt. The next start refuses.
        let second = backend
            .start(json!({"mode":"phone","options":{}}))
            .expect_err("the consumed grant must refuse the next start");
        assert_eq!(second, "authorization_required");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn presence_schedule_stops_and_resumes() {
        use super::{probe_interval, PresenceSchedule};
        use std::time::Duration;
        let schedule = PresenceSchedule::default();
        assert_eq!(
            probe_interval(Duration::from_secs(9), false, schedule),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            probe_interval(Duration::from_secs(10), false, schedule),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            probe_interval(Duration::from_secs(299), false, schedule),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            probe_interval(Duration::from_secs(300), false, schedule),
            None
        );
        assert_eq!(
            probe_interval(Duration::ZERO, false, schedule),
            Some(Duration::from_secs(2))
        );
        // A running phone tunnel always probes. The page does not matter.
        for idle in [0, 9, 10, 300, 3_600] {
            assert_eq!(
                probe_interval(Duration::from_secs(idle), true, schedule),
                Some(Duration::from_secs(2)),
                "idle {idle}"
            );
        }
    }

    use super::*;
    use crate::pairing::tests::{spawn_phone, Decide, MockPhone};
    use std::net::TcpListener;
    use std::os::fd::IntoRawFd;

    fn backend() -> RustGuiBackend {
        RustGuiBackend::new(Arc::new(Service::new()))
    }

    /// A backend whose default route is fixed, so the test does not depend on
    /// the network of the machine that runs it.
    fn backend_with_route(route: Option<super::HotspotRoute>) -> RustGuiBackend {
        let mut backend = backend();
        backend.route_lookup = Arc::new(move || route.clone());
        backend
    }

    #[test]
    fn pairing_handoff_writes_the_pairing_and_the_answer_holds_no_secret() {
        let backend = backend();
        backend.set_handoff_identity([0x42; 32]);
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 18080,
            token: "public-test-token".into(),
        });
        let (writer, reader) = UnixStream::pair().unwrap();
        backend.set_handoff_fd(writer.into_raw_fd());
        let answer = backend.pair_handoff().unwrap();
        assert_eq!(answer["ok"], true);
        assert!(!answer.to_string().contains("public-test-token"));
        let read_fd = reader.into_raw_fd();
        let (identity, credentials) =
            crate::credential_handoff::read_handoff(read_fd).expect("one valid handoff");
        assert_eq!(identity.public(), Identity::from_bytes([0x42; 32]).public());
        assert_eq!(credentials.host, Ipv4Addr::new(172, 20, 10, 1));
        assert_eq!(credentials.port, 18080);
        assert_eq!(credentials.token, "public-test-token");
        // A later attempt writes the same pairing again. The descriptor is
        // not consumed by one authorization failure.
        let answer = backend.pair_handoff().unwrap();
        assert_eq!(answer["ok"], true);
        let (_, again) = crate::credential_handoff::read_handoff(read_fd)
            .expect("the same pairing is available for a retry");
        assert_eq!(again.token, "public-test-token");
        unsafe {
            libc::close(read_fd);
        }
    }

    #[test]
    fn pairing_handoff_requires_a_pairing() {
        let backend = backend();
        backend.set_handoff_identity([0x42; 32]);
        let (writer, _reader) = UnixStream::pair().unwrap();
        backend.set_handoff_fd(writer.into_raw_fd());
        assert_eq!(backend.pair_handoff().unwrap_err(), "not_paired");
    }

    /// A Linux root engine, with or without an imported pairing, starts only
    /// the tunnel modes. A SOCKS5 listener or any other mode is refused before
    /// options are parsed or a listener exists. The tun mode is not started
    /// here, because a hermetic test must not try to create a device.
    #[test]
    fn linux_root_engines_refuse_every_mode_but_the_tunnel() {
        let mut imported = RustGuiBackend::with_imported_pairing(
            Arc::new(Service::new()),
            Identity::from_bytes([0x47; 32]),
            PhoneCredentials {
                host: Ipv4Addr::new(192, 0, 2, 1),
                port: 18080,
                token: "public-test-token".into(),
            },
        )
        .expect("the test identity matches the process-wide import");
        imported.route_lookup = Arc::new(|| None);
        let mut direct = backend_with_route(None);
        direct.restrict_to_tunnel_modes();
        for backend in [&imported, &direct] {
            for payload in [
                json!({"mode":"socks5","options":{"host":"127.0.0.1","port":1080}}),
                json!({"mode":"socks5"}),
                json!({"mode":"anything"}),
            ] {
                let error = backend.start(payload.clone()).unwrap_err();
                assert_eq!(error, "mode_not_allowed", "payload {payload}");
            }
            assert_eq!(backend.service.status()["running"], false);
        }
        // A phone start passes the mode check and stops at the gateway check,
        // because the hermetic route lookup finds no hotspot.
        let error = imported
            .start(json!({"mode":"phone","options":{}}))
            .unwrap_err();
        assert_ne!(error, "mode_not_allowed");
        assert_eq!(
            crate::gui::start_error_message("mode_not_allowed"),
            Some("The protected engine starts only the tunnel.")
        );
    }

    /// The Linux path: the user engine writes frames into its standard input
    /// socket, a cancelled start leaves an older frame queued, and the root
    /// engine reads the newest frame from the peer socket and imports it. The
    /// identity matches the macOS import tests, because the imported identity
    /// is process-wide.
    #[test]
    fn linux_handoff_imports_the_newest_pairing_into_a_root_backend() {
        let user = backend();
        user.set_handoff_identity([0x47; 32]);
        let (user_end, app_end) = UnixStream::pair().unwrap();
        user.set_handoff_fd(user_end.into_raw_fd());
        user.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: Ipv4Addr::new(192, 0, 2, 1),
            port: 18080,
            token: "public-old-token".into(),
        });
        // A start that the person cancelled at the prompt.
        assert_eq!(user.pair_handoff().unwrap()["ok"], true);
        user.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: Ipv4Addr::new(192, 0, 2, 1),
            port: 18081,
            token: "public-test-token".into(),
        });
        let answer = user.pair_handoff().unwrap();
        assert!(!answer.to_string().contains("public-test-token"));
        let read_fd = app_end.into_raw_fd();
        let (identity, credentials) = crate::credential_handoff::read_latest_handoff(read_fd)
            .expect("the newest queued frame");
        assert_eq!(credentials.port, 18081);
        assert_eq!(credentials.token, "public-test-token");
        // The channel is drained. A second root engine on the same socket
        // with no new frame fails its launch instead of waiting.
        assert!(crate::credential_handoff::read_latest_handoff(read_fd).is_err());
        unsafe {
            libc::close(read_fd);
        }
        assert_eq!(identity.public(), Identity::from_bytes([0x47; 32]).public());

        let mut root =
            RustGuiBackend::with_imported_pairing(Arc::new(Service::new()), identity, credentials)
                .expect("the test identity matches the process-wide import");
        root.route_lookup = Arc::new(|| None);
        let view = root.pair_status().unwrap();
        assert_eq!(view["state"], "paired");
        assert!(!view.to_string().contains("public-test-token"));
        assert_eq!(
            pairing::local_identity().unwrap().public(),
            Identity::from_bytes([0x47; 32]).public(),
            "the root engine uses the imported key, not a root HOME key"
        );
        // The root engine never exports a handoff of its own.
        assert_eq!(root.pair_handoff().unwrap_err(), "handoff_unavailable");
        // A different identity cannot replace the imported one.
        assert!(RustGuiBackend::with_imported_pairing(
            Arc::new(Service::new()),
            Identity::from_bytes([0x48; 32]),
            PhoneCredentials {
                host: Ipv4Addr::new(192, 0, 2, 1),
                port: 18080,
                token: "public-test-token".into(),
            },
        )
        .is_err());
    }

    #[test]
    fn closing_blocks_a_late_start_and_pairing() {
        let backend = backend();
        // A normal request may start before shutdown.
        let _session = backend.begin().expect("an idle backend accepts a start");
        backend.closing.store(false, Ordering::Release);
        // Return the phase to Idle without touching a real service.
        *backend.phase.lock().unwrap() = Phase::Idle;
        backend.mark_closing();
        assert!(matches!(
            backend.begin(),
            Err(ref error) if error == "service is stopping"
        ));
        assert!(matches!(
            backend.pair_start(),
            Err(ref error) if error == "service is stopping"
        ));
    }

    fn hotspot() -> super::HotspotRoute {
        super::HotspotRoute {
            host: "172.20.10.1".parse().unwrap(),
            iface: "hs-test5".into(),
            index: 5,
        }
    }

    fn identity() -> Identity {
        Identity::from_bytes([0x55; 32])
    }

    fn wait_pair_state(backend: &RustGuiBackend, done: &[&str]) -> Value {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let view = backend.pair_status().unwrap();
            if done.contains(&view["state"].as_str().unwrap_or("")) {
                return view;
            }
            if Instant::now() >= end {
                panic!("pairing did not finish: {view}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn probe_once(address: SocketAddr, paired: bool, identity: &Identity) -> ProbeResult {
        let stop = AtomicBool::new(false);
        probe_address(address, None, paired, identity, &stop)
    }

    #[test]
    fn probe_maps_unpaired_not_trusted_ready_and_proxy_off() {
        let identity = identity();
        let public = identity.public();
        // No credentials and an unknown target device: the app answers Rejected.
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().answer_status(true, 7, 31000);
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        let result = probe_once(address, false, &identity);
        assert_eq!(result.state, "unpaired");
        assert!(result.info.is_none());
        handle.join().unwrap();
        // Credentials for a target device that the app no longer trusts.
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().answer_status(true, 7, 31000);
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        let result = probe_once(address, true, &identity);
        assert_eq!(result.state, "not_trusted");
        assert!(result.info.is_none());
        handle.join().unwrap();
        // A trusted target device with the proxy on and off.
        for (running, expected, connections) in [(true, "ready", 7u16), (false, "proxy_off", 4)] {
            let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
            {
                let mut phone = phone.lock().unwrap();
                phone.trust(public);
                phone.answer_status(running, connections, 31000);
            }
            let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
            let result = probe_once(address, true, &identity);
            assert_eq!(result.state, expected);
            let info = result.info.expect("authenticated status");
            assert_eq!(info.connections, connections);
            assert_eq!(info.port, 31000);
            handle.join().unwrap();
        }
    }

    #[test]
    fn probe_reports_a_closed_or_silent_source_device() {
        let identity = identity();
        // A closed port: the app is not running.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(probe_once(address, false, &identity).state, "not_running");
        assert_eq!(probe_once(address, true, &identity).state, "not_running");
        // A listener that closes every connection: the app does not answer.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                drop(stream);
            }
        });
        assert_eq!(
            probe_once(address, false, &identity).state,
            "not_responding"
        );
        server.join().unwrap();
    }

    #[test]
    fn a_slow_or_blocked_connect_is_not_a_stopped_source_device() {
        // A refusal reports the listener as unavailable.
        assert_eq!(
            connect_error_state(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            "not_running"
        );
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::NotConnected,
        ] {
            assert_eq!(
                connect_error_state(&io::Error::from(kind)),
                "not_responding",
                "{kind:?} must not claim that the source device app is off"
            );
        }
    }

    #[test]
    fn status_json_reports_new_states_paired_and_connections() {
        let backend = backend();
        backend.presence.lock().unwrap().state = Some("unpaired");
        let status = backend.status().unwrap();
        assert_eq!(status["phone"]["state"], "unpaired");
        assert_eq!(
            status["phone"]["message"],
            "Not paired. Open HotspotShade on your source device, then pair."
        );
        assert_eq!(status["phone"]["connections"], Value::Null);
        assert_eq!(status["paired"], false);
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: "172.20.10.1".parse().unwrap(),
            port: 1080,
            token: "paired-secret-token".into(),
        });
        backend.presence.lock().unwrap().state = Some("not_trusted");
        backend.presence.lock().unwrap().connections = None;
        let status = backend.status().unwrap();
        assert_eq!(status["phone"]["state"], "not_trusted");
        assert_eq!(
            status["phone"]["message"],
            "The source device does not know this target device. Pair again."
        );
        assert_eq!(status["paired"], true);
        assert!(!status.to_string().contains("paired-secret-token"));
        // The connection count comes through unchanged.
        backend.presence.lock().unwrap().state = Some("ready");
        backend.presence.lock().unwrap().connections = Some(7);
        let status = backend.status().unwrap();
        assert_eq!(status["phone"]["state"], "ready");
        assert_eq!(status["phone"]["connections"], json!(7));
        assert_eq!(status["phone"]["port_changed"], false);
    }

    #[test]
    fn status_keeps_icmp_enabled_from_the_service() {
        let backend = backend();
        assert_eq!(backend.status().unwrap()["icmp_enabled"], false);
        let status =
            backend.with_pairing(json!({"running":true,"mode":"phone","icmp_enabled":true}));
        assert_eq!(status["icmp_enabled"], true);
        let status =
            backend.with_pairing(json!({"running":true,"mode":"phone","icmp_enabled":false}));
        assert_eq!(status["icmp_enabled"], false);
    }

    #[test]
    fn poisoned_service_refuses_start_and_does_not_publish_cached_presence() {
        let service = Arc::new(Service::new());
        let backend = RustGuiBackend::new(Arc::clone(&service));
        backend.presence.lock().unwrap().state = Some("ready");
        service.poison_state_for_test();

        let status = backend.status().unwrap();
        assert_eq!(status["state"], "unknown");
        assert_eq!(
            status["error"],
            crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE
        );
        assert!(status.get("phone").is_none());
        assert!(status.get("paired").is_none());
        assert!(matches!(backend.begin(), Err(ref error)
            if error == crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE));
        assert_eq!(
            backend.stop().unwrap_err(),
            crate::service::CLEANUP_UNCERTAIN_MESSAGE
        );
    }

    #[test]
    fn a_running_phone_tunnel_reports_the_real_probe_result() {
        assert_eq!(phone_state(Some("ready"), true), "connected");
        assert_eq!(phone_state(Some("unpaired"), true), "unpaired");
        assert_eq!(phone_state(Some("not_trusted"), true), "not_trusted");
        assert_eq!(phone_state(Some("proxy_off"), true), "proxy_off");
        assert_eq!(phone_state(None, true), "connected");
        assert_eq!(phone_state(Some("not_responding"), true), "not_responding");
        assert_eq!(phone_state(Some("not_running"), true), "not_running");
        assert_eq!(phone_state(Some("ready"), false), "ready");
        assert_eq!(phone_state(None, false), "not_responding");
        let backend = backend();
        backend.presence.lock().unwrap().state = Some("ready");
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "connected");
        assert_eq!(
            status["phone"]["message"],
            "Connected to the source device."
        );
        let status = backend.with_pairing(json!({"running":true,"mode":"socks5"}));
        assert_eq!(status["phone"]["state"], "ready");
        // A real probe result stays visible while the tunnel runs.
        backend.presence.lock().unwrap().state = Some("not_responding");
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "not_responding");
        assert_eq!(
            status["phone"]["message"],
            "Open HotspotShade on your source device and keep it open."
        );
        backend.presence.lock().unwrap().state = Some("not_running");
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "not_running");
        for (probe, expected) in [
            (
                "unpaired",
                "Not paired. Open HotspotShade on your source device, then pair.",
            ),
            (
                "not_trusted",
                "The source device does not know this target device. Pair again.",
            ),
            ("proxy_off", "Start the proxy on your source device."),
        ] {
            backend.presence.lock().unwrap().state = Some(probe);
            let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
            assert_eq!(status["phone"]["state"], probe);
            assert_eq!(status["phone"]["message"], expected);
        }
    }

    #[test]
    fn pairing_replaces_stale_credentials_and_a_failure_keeps_them() {
        let mut backend = backend();
        let old = PhoneCredentials {
            host: "172.20.10.1".parse().unwrap(),
            port: 1080,
            token: "old-secret-token".into(),
        };
        backend.pairing.lock().unwrap().credentials = Some(old);
        backend.presence.lock().unwrap().state = Some("not_trusted");
        // A failed attempt keeps the old credentials.
        backend.pair_attempt =
            Arc::new(|_, _| Err(PairError::Phone(pairing::PhoneStatus::Rejected)));
        let view = backend.pair_start().unwrap();
        assert_eq!(view["state"], "connecting");
        let failed = wait_pair_state(&backend, &["failed"]);
        assert_eq!(failed["state"], "failed");
        assert_eq!(
            backend
                .pairing
                .lock()
                .unwrap()
                .credentials
                .as_ref()
                .unwrap()
                .token,
            "old-secret-token"
        );
        assert_eq!(backend.status().unwrap()["phone"]["state"], "not_trusted");
        // A successful attempt replaces them, while paired stays true.
        backend.pair_attempt = Arc::new(|_, _| {
            Ok(PhoneCredentials {
                host: "172.20.10.2".parse().unwrap(),
                port: 41000,
                token: "new-secret-token".into(),
            })
        });
        assert!(backend.pair_start().is_ok());
        let paired = wait_pair_state(&backend, &["paired"]);
        assert_eq!(paired["port"], 41000);
        let inner = backend.pairing.lock().unwrap();
        let credentials = inner.credentials.as_ref().unwrap();
        assert_eq!(
            (credentials.port, credentials.token.as_str()),
            (41000, "new-secret-token")
        );
        assert_eq!(credentials.host.to_string(), "172.20.10.2");
    }

    #[test]
    fn phone_ping_option_defaults_on_and_reaches_the_private_request() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        assert!(backend.experimental_icmp);
        assert!(backend.experimental_icmp_persistent);
        let parse = |options: &Value| {
            crate::gui::phone_icmp_options(
                options,
                backend.experimental_icmp,
                backend.experimental_icmp_persistent,
            )
        };
        assert_eq!(parse(&json!({})).unwrap(), (true, true));
        assert_eq!(
            parse(&json!({"experimental_icmp":true})).unwrap(),
            (true, true)
        );
        assert_eq!(
            parse(&json!({"experimental_icmp":false})).unwrap(),
            (false, false)
        );
        assert_eq!(
            parse(&json!({"experimental_icmp":true,"experimental_icmp_persistent":false})).unwrap(),
            (true, false)
        );
        assert_eq!(
            parse(&json!({"experimental_icmp":false,"experimental_icmp_persistent":false}))
                .unwrap(),
            (false, false)
        );
        for bad in [
            json!({"experimental_icmp":"true"}),
            json!({"experimental_icmp":1}),
            json!({"experimental_icmp_persistent":"true"}),
            json!({"experimental_icmp":false,"experimental_icmp_persistent":true}),
        ] {
            assert_eq!(parse(&bad).unwrap_err(), "invalid_ping_option");
        }
        let (enabled, persistent) = parse(&json!({})).unwrap();
        let request = phone_start_request(
            "172.20.10.1".parse().unwrap(),
            18080,
            "test-token",
            enabled,
            persistent,
        );
        assert_eq!(request["experimental_icmp"], true);
        assert_eq!(request["experimental_icmp_persistent"], true);
        assert_eq!(request["phone"][3], "test-token");
        let (enabled, persistent) = parse(&json!({"experimental_icmp":false})).unwrap();
        let request = phone_start_request(
            "172.20.10.1".parse().unwrap(),
            18080,
            "test-token",
            enabled,
            persistent,
        );
        assert_eq!(request["experimental_icmp"], false);
        assert_eq!(request["experimental_icmp_persistent"], false);
    }

    #[test]
    fn direct_modes_ignore_ping_options() {
        let bad = json!({"experimental_icmp":"true"});
        assert_eq!(mode_icmp_options("socks5", &bad, true, true), Ok(None));
        assert_eq!(mode_icmp_options("tun", &bad, true, true), Ok(None));
        assert_eq!(
            mode_icmp_options("phone", &bad, true, true).unwrap_err(),
            "invalid_ping_option"
        );
        assert_eq!(
            mode_icmp_options("phone", &json!({}), true, true),
            Ok(Some((true, true)))
        );
        assert_eq!(
            mode_icmp_options("phone", &json!({"experimental_icmp":false}), true, true),
            Ok(Some((false, false)))
        );
    }
    #[test]
    fn phone_options_require_numeric_unicast_and_nonempty_token() {
        assert!(phone_options(&json!({"host":"172.20.10.1","port":18080,"token":"x"})).is_ok());
        for host in ["localhost", "127.0.0.1", "0.0.0.0", "224.0.0.1"] {
            assert!(phone_options(&json!({"host":host,"port":1080,"token":"x"})).is_err());
        }
        assert!(phone_options(&json!({"host":"172.20.10.1","port":0,"token":"x"})).is_err());
        assert!(phone_options(&json!({"host":"172.20.10.1","port":1080,"token":""})).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn quoting_handles_apostrophe_and_rejects_controls() {
        assert_eq!(shell_quote("a'b").unwrap(), "'a'\\''b'");
        assert!(shell_quote("a\nb").is_err());
    }
    #[test]
    fn error_messages_only_accept_known_stage_codes() {
        assert!(start_error_message("phone_auth")
            .unwrap()
            .contains("authentication"));
        assert!(start_error_message("invalid_ping_option")
            .unwrap()
            .contains("true or false"));
        assert!(start_error_message("route_setup")
            .unwrap()
            .contains("routes"));
        assert!(start_error_message("secret-token-in-error").is_none());
    }
    #[test]
    fn startup_timeout_and_stderr_are_classified_without_retaining_text() {
        assert_eq!(
            io_stage(&io::Error::new(io::ErrorKind::TimedOut, "private-token")),
            "helper_timeout"
        );
        assert_eq!(
            io_stage(&io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "private-token"
            )),
            "helper_disconnected"
        );
        let code = Arc::new(AtomicU8::new(0));
        let reader =
            std::io::Cursor::new(b"thread 'main' panicked at private-token-value".to_vec());
        watch_stderr(reader, Arc::clone(&code)).join().unwrap();
        assert_eq!(code.load(Ordering::Acquire), 3);
        assert!(!start_error_message("helper_panic")
            .unwrap()
            .contains("private-token-value"));
    }
    #[test]
    fn gui_and_cli_dns_lists_parse_and_deduplicate_alike() {
        let tokens = [
            "192.0.2.53",
            "[2001:db8::53]:5353",
            "192.0.2.53:53",
            "[2001:db8::53]:5353",
            "2001:db8::53",
        ];
        let cli = dns::parse_server_list(&tokens.join(", ")).unwrap();
        let gui = socks_dns_servers(&json!({"dns_servers":tokens}))
            .unwrap()
            .unwrap();
        assert_eq!(gui, cli);
        // Both forms of an IPv6 literal are accepted, and the port defaults to
        // 53 in each parser.
        assert!(cli.contains(&"[2001:db8::53]:53".parse().unwrap()));
        assert!(cli.contains(&"[2001:db8::53]:5353".parse().unwrap()));
        // Both reject an empty list, a name, a non-unicast address, and an
        // oversized unique list. The count bound applies after deduplication.
        for value in [
            json!({"dns_servers":[]}),
            json!({"dns_servers":["dns.example"]}),
            json!({"dns_servers":["0.0.0.0"]}),
            json!({"dns_servers":["[fe80::1]"]}),
        ] {
            assert!(socks_dns_servers(&value).is_err(), "accepted {value}");
        }
        assert!(dns::parse_server_list("").is_err());
        let mut many = Vec::new();
        for index in 0..=dns::MAX_EXPLICIT_SERVERS {
            many.push(format!("192.0.2.{index}"));
        }
        assert!(socks_dns_servers(&json!({"dns_servers":many})).is_err());
        assert!(dns::parse_server_list(&many.join(",")).is_err());
        // An explicit null keeps the discovery path, and a non-array value is
        // rejected rather than treated as empty.
        assert!(socks_dns_servers(&json!({})).unwrap().is_none());
        assert!(socks_dns_servers(&json!({"dns_servers":null}))
            .unwrap()
            .is_none());
        assert!(socks_dns_servers(&json!({"dns_servers":"192.0.2.53"})).is_err());
    }
    #[test]
    fn tunnel_options_parse_and_preserve_defaults_and_explicit_values() {
        let default = tun_options(&json!({})).unwrap();
        assert_eq!(default.ipv6, Ipv6Policy::Block);
        assert!(!default.no_routes);
        assert!(!default.no_pin);
        let parsed = tun_options(&json!({"unit":3,"addr":"198.18.1.5","iface":"en5",
            "dns_upstream":"1.1.1.1:5353","ipv6":"inherit","no_routes":true}))
        .unwrap();
        assert_eq!(parsed.unit, 3);
        assert_eq!(parsed.addr, Ipv4Addr::new(198, 18, 1, 5));
        assert_eq!(parsed.iface.as_deref(), Some("en5"));
        assert_eq!(
            parsed.dns_upstream.unwrap(),
            "1.1.1.1:5353".parse().unwrap()
        );
        assert_eq!(parsed.ipv6, Ipv6Policy::Inherit);
        assert!(parsed.no_routes);
        assert!(tun_options(&json!({"unit":256})).is_err());
        assert!(tun_options(&json!({"addr":"198.18.0.0"})).is_err());
        assert!(tun_options(&json!({"dns_upstream":"dns.example"})).is_err());
        assert!(tun_options(&json!({"ipv6":"invalid"})).is_err());
        assert!(tun_options(&json!({"no_routes":"true"})).is_err());
        assert!(tun_options(&json!({"ipv6":"forward","no_routes":true})).is_err());
    }
    // The packaged Linux engine is the root process that owns the tunnel. The
    // GUI must reach the in-process start path for both modes. A development
    // engine that runs as the desktop user must refuse before it touches a TUN
    // device or a route. Run this test as a normal user only: as root it would
    // create a real tunnel.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_start_reaches_the_local_path_and_requires_root() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: this test must run as a normal user");
            return;
        }
        let backend = backend_with_route(Some(hotspot()));
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: "172.20.10.1".parse().unwrap(),
            port: 1080,
            token: "paired-secret-token".into(),
        });
        assert_eq!(
            backend
                .start(json!({"mode":"phone","options":{}}))
                .unwrap_err(),
            "admin_required"
        );
        assert_eq!(backend.status().unwrap()["running"], json!(false));
        assert_eq!(
            backend
                .start(json!({"mode":"tun","options":{}}))
                .unwrap_err(),
            "admin_required"
        );
        assert_eq!(backend.status().unwrap()["running"], json!(false));
    }

    #[test]
    fn a_saved_gateway_from_an_old_network_never_receives_the_token() {
        let backend = backend_with_route(Some(hotspot()));
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: "192.168.1.1".parse().unwrap(),
            port: 1080,
            token: "paired-secret-token".into(),
        });
        let error = backend
            .start(json!({"mode":"phone","options":{}}))
            .unwrap_err();
        assert_eq!(error, "source_device_moved");
        assert!(!error.contains("paired-secret-token"));
        let status = backend.status().unwrap();
        assert_eq!(status["running"], json!(false));
        assert!(!status.to_string().contains("paired-secret-token"));
        // The credential stays for a return to the network that it names.
        assert!(backend.pairing.lock().unwrap().credentials.is_some());
    }

    #[test]
    fn a_route_change_invalidates_the_saved_gateway_until_it_returns() {
        let route = Arc::new(Mutex::new(Some(hotspot())));
        let mut backend = backend();
        let source = Arc::clone(&route);
        backend.route_lookup = Arc::new(move || source.lock().unwrap().clone());
        let saved: Ipv4Addr = "172.20.10.1".parse().unwrap();
        assert!(backend.require_hotspot_gateway(saved).is_ok());
        // The same saved gateway on a different network is not the source
        // device. The token check must fail before any connection.
        *route.lock().unwrap() = Some(super::HotspotRoute {
            host: "192.168.1.1".parse().unwrap(),
            iface: "hs-test6".into(),
            index: 6,
        });
        assert_eq!(
            backend.require_hotspot_gateway(saved).unwrap_err(),
            "source_device_moved"
        );
        // Returning to the hotspot makes the saved credential usable again.
        *route.lock().unwrap() = Some(hotspot());
        assert_eq!(backend.require_hotspot_gateway(saved).unwrap().index, 5);
    }

    #[test]
    fn a_manual_start_requires_the_current_private_gateway() {
        let backend = backend_with_route(Some(hotspot()));
        for host in ["203.0.113.10", "192.168.1.1"] {
            let error = backend
                .start(json!({"mode":"phone","options":{
                    "host":host,"port":1080,"token":"manual-secret-token"}}))
                .unwrap_err();
            assert_eq!(error, "source_device_moved", "{host}");
            assert!(!error.contains("manual-secret-token"));
        }
        assert_eq!(backend.status().unwrap()["running"], json!(false));
        // A public default gateway is not a hotspot source device, even when
        // the manual host matches it.
        let public = backend_with_route(Some(super::HotspotRoute {
            host: "203.0.113.10".parse().unwrap(),
            iface: "hs-test5".into(),
            index: 5,
        }));
        assert_eq!(
            public
                .start(json!({"mode":"phone","options":{
                    "host":"203.0.113.10","port":1080,"token":"manual-secret-token"}}))
                .unwrap_err(),
            "source_device_moved"
        );
    }

    #[test]
    fn a_source_device_check_refuses_a_host_that_is_not_the_gateway() {
        let backend = backend_with_route(Some(hotspot()));
        let error = backend
            .phone_check(json!({
                "host":"203.0.113.10","port":1080,"token":"manual-secret-token"
            }))
            .unwrap_err();
        assert_eq!(error, "source_device_moved");
        assert!(!error.contains("manual-secret-token"));
    }

    #[test]
    fn a_missing_default_route_does_not_send_the_token() {
        let backend = backend_with_route(None);
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: "172.20.10.1".parse().unwrap(),
            port: 1080,
            token: "paired-secret-token".into(),
        });
        assert_eq!(
            backend
                .start(json!({"mode":"phone","options":{}}))
                .unwrap_err(),
            "no_hotspot"
        );
        assert_eq!(
            backend
                .phone_check(json!({
                    "host":"172.20.10.1","port":1080,"token":"manual-secret-token"
                }))
                .unwrap_err(),
            "no_hotspot"
        );
    }

    #[test]
    fn pending_start_can_be_cancelled_without_a_helper() {
        let backend = Arc::new(RustGuiBackend::new(Arc::new(Service::new())));
        let (cancel, _) = backend.begin().unwrap();
        let copy = Arc::clone(&backend);
        let waiter = std::thread::spawn(move || copy.stop());
        let end = Instant::now() + Duration::from_secs(2);
        while !cancel.load(Ordering::Acquire) && Instant::now() < end {
            std::thread::yield_now();
        }
        assert!(cancel.load(Ordering::Acquire));
        backend.finish(Phase::Idle);
        assert!(waiter.join().unwrap().is_ok());
    }
    #[test]
    fn paired_credentials_start_the_phone_and_never_reach_status() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        assert_eq!(backend.phone_target(&json!({})).unwrap_err(), "pair_first");
        assert_eq!(
            start_error_message("pair_first"),
            Some("Pair with the source device first.")
        );
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: "172.20.10.1".parse().unwrap(),
            port: 1080,
            token: "paired-secret-token".into(),
        });
        let (host, port, token) = backend.phone_target(&json!({"token":""})).unwrap();
        assert_eq!((host.to_string(), port), ("172.20.10.1".into(), 1080));
        assert_eq!(token, "paired-secret-token");
        // A token in the request wins over the paired credentials.
        let manual = backend
            .phone_target(&json!({"host":"172.20.10.1","port":18080,"token":"manual"}))
            .unwrap();
        assert_eq!((manual.1, manual.2.as_str()), (18080, "manual"));
        let status = backend.status().unwrap();
        assert_eq!(status["paired"], true);
        assert_eq!(status["phone_host"], "172.20.10.1");
        assert_eq!(status["phone_port"], 1080);
        assert!(!status.to_string().contains("paired-secret-token"));
        let view = backend.pair_cancel().unwrap();
        assert_eq!(view["state"], "idle");
        assert!(!view.to_string().contains("paired-secret-token"));
    }
    #[test]
    fn learned_phone_port_updates_status_and_flags_a_running_tunnel() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        let gateway: Ipv4Addr = "172.20.10.1".parse().unwrap();
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: gateway,
            port: 1080,
            token: "paired-secret-token".into(),
        });
        let info = PhoneInfo {
            proxy_running: true,
            foreground: true,
            connections: 1,
            port: 31000,
            host: "172.20.10.1".into(),
        };
        assert_eq!(
            apply_probe(&backend.pairing, gateway, &info),
            pairing::PortUpdate::PortChanged {
                old: 1080,
                new: 31000
            }
        );
        assert_eq!(
            backend
                .pairing
                .lock()
                .unwrap()
                .credentials
                .as_ref()
                .unwrap()
                .token,
            "paired-secret-token"
        );
        let status = backend.status().unwrap();
        assert_eq!(status["phone_port"], 31000);
        assert_eq!(status["phone"]["port_changed"], false);
        assert!(!status.to_string().contains("paired-secret-token"));
        // A tunnel that started with the old port must not use the new one.
        *backend.tunnel_phone_port.lock().unwrap() = Some(1080);
        let status = backend.status().unwrap();
        assert_eq!(status["phone"]["port_changed"], true);
        assert_eq!(
            status["phone"]["message"],
            "The source device changed its port. Turn the tunnel off and on."
        );
        assert_eq!(status["phone_port"], 31000);
        // A tunnel that started after the change has the learned port.
        *backend.tunnel_phone_port.lock().unwrap() = Some(31000);
        assert_eq!(backend.status().unwrap()["phone"]["port_changed"], false);
        // A status that names another host changes nothing.
        let other = PhoneInfo {
            host: "172.20.10.2".into(),
            port: 22000,
            ..info.clone()
        };
        assert_eq!(
            apply_probe(&backend.pairing, gateway, &other),
            pairing::PortUpdate::Rejected
        );
        assert_eq!(backend.status().unwrap()["phone_port"], 31000);
        backend.forget_tunnel_port();
        assert_eq!(backend.status().unwrap()["phone"]["port_changed"], false);
    }
    #[test]
    fn forget_is_refused_while_the_tunnel_runs_and_retries_when_off() {
        let mut backend = RustGuiBackend::new(Arc::new(Service::new()));
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        backend.forget_network = Arc::new(move || {
            counter.fetch_add(1, Ordering::AcqRel);
            false
        });
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host: "172.20.10.1".parse().unwrap(),
            port: 1080,
            token: "paired-secret-token".into(),
        });
        *backend.phase.lock().unwrap() = Phase::Local;
        assert_eq!(backend.pair_forget().unwrap_err(), "tunnel_running");
        assert!(backend.pairing.lock().unwrap().credentials.is_some());
        assert_eq!(attempts.load(Ordering::Acquire), 0);
        assert_eq!(
            crate::pairing::forget_error("tunnel_running"),
            (409, "Turn off the tunnel first.")
        );
        *backend.phase.lock().unwrap() = Phase::Idle;
        assert!(backend.pair_forget().is_ok());
        assert!(backend.pairing.lock().unwrap().credentials.is_none());
        let wait = |count: usize| {
            let end = Instant::now() + Duration::from_secs(2);
            while attempts.load(Ordering::Acquire) < count && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        // The first FORGET fails. The flag keeps the retry pending.
        wait(1);
        let pending = backend.forget.lock().unwrap();
        assert!(pending.pending);
        assert!(!pending.in_flight);
        assert_eq!(pending.attempts, 1);
        assert!(pending.should_retry());
        drop(pending);
        // The last allowed attempt clears the flag.
        backend.forget.lock().unwrap().attempts = MAX_FORGET_TRIES - 1;
        spawn_forget(
            Arc::clone(&backend.forget),
            Arc::clone(&backend.forget_network),
        );
        wait(usize::from(MAX_FORGET_TRIES));
        let pending = backend.forget.lock().unwrap();
        assert_eq!(pending.attempts, MAX_FORGET_TRIES);
        assert!(!pending.pending);
    }

    #[test]
    fn a_second_pair_start_is_refused_while_one_runs() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        backend.pairing.lock().unwrap().cancel = Some(Arc::new(AtomicBool::new(false)));
        assert_eq!(backend.pair_start().unwrap_err(), "pair_busy");
        let cancel = backend.pairing.lock().unwrap().cancel.clone().unwrap();
        backend.pair_cancel().unwrap();
        assert!(cancel.load(Ordering::Acquire));
        assert!(backend.pairing.lock().unwrap().cancel.is_none());
    }

    #[test]
    fn a_stale_pair_spawn_failure_preserves_the_new_attempt() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        let current_cancel = Arc::new(AtomicBool::new(false));
        {
            let mut inner = backend.pairing.lock().unwrap();
            inner.generation = 2;
            inner.cancel = Some(Arc::clone(&current_cancel));
            inner.view.phase = PairPhase::Connecting;
        }
        pair_spawn_failed(&backend.pairing, 1);
        let inner = backend.pairing.lock().unwrap();
        assert!(Arc::ptr_eq(inner.cancel.as_ref().unwrap(), &current_cancel));
        assert_eq!(inner.view.phase, PairPhase::Connecting);
    }

    #[test]
    fn a_current_pair_spawn_failure_clears_the_failed_attempt() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        {
            let mut inner = backend.pairing.lock().unwrap();
            inner.generation = 2;
            inner.cancel = Some(Arc::new(AtomicBool::new(false)));
            inner.view.phase = PairPhase::Connecting;
        }
        pair_spawn_failed(&backend.pairing, 2);
        let inner = backend.pairing.lock().unwrap();
        assert!(inner.cancel.is_none());
        assert_eq!(inner.view.phase, PairPhase::Idle);
    }

    #[test]
    fn a_new_pairing_waits_for_an_in_flight_forget_before_it_sends_its_request() {
        let mut backend = backend();
        backend.forget_drain = Duration::from_secs(2);
        backend.probe_attempt = Arc::new(|_paired, _stop, _target| ProbeResult {
            state: "unpaired",
            info: None,
            gateway: None,
            trusted_by_source: None,
            cancelled: false,
        });
        let (forget_started_tx, forget_started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let forget_done = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&forget_done);
        backend.forget_network = Arc::new(move || {
            forget_started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            done.store(true, Ordering::Release);
            true
        });
        let pair_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&pair_calls);
        let saw_forget_done = Arc::new(AtomicBool::new(false));
        let saw = Arc::clone(&saw_forget_done);
        let done_flag = Arc::clone(&forget_done);
        backend.pair_attempt = Arc::new(move |_cancel, _on_code| {
            calls.fetch_add(1, Ordering::AcqRel);
            saw.store(done_flag.load(Ordering::Acquire), Ordering::Release);
            Ok(PhoneCredentials {
                host: "172.20.10.1".parse().unwrap(),
                port: 1080,
                token: "test-token".into(),
            })
        });
        // Start a FORGET and hold its network call open.
        backend.pair_forget().unwrap();
        forget_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        // A new pairing may be requested while the old FORGET is in flight.
        backend.pair_start().unwrap();
        assert!(
            backend.forget.lock().unwrap().pending,
            "pair start cleared a FORGET that was already on the wire"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            pair_calls.load(Ordering::Acquire),
            0,
            "the pairing sent a request while the old FORGET was in flight"
        );
        // Release the old FORGET. The pairing starts only after it returns.
        release_tx.send(()).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        while pair_calls.load(Ordering::Acquire) == 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pair_calls.load(Ordering::Acquire), 1);
        assert!(
            saw_forget_done.load(Ordering::Acquire),
            "the pairing ran before the old FORGET finished"
        );
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let phase = backend.pairing.lock().unwrap().view.phase;
            if phase == PairPhase::Paired {
                break;
            }
            assert!(Instant::now() < end, "pairing did not complete: {phase:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(backend.forget.lock().unwrap().state(), "none");
    }

    #[test]
    fn a_new_pairing_fails_closed_when_the_old_forget_does_not_finish() {
        let mut backend = backend();
        backend.forget_drain = Duration::from_millis(50);
        backend.probe_attempt = Arc::new(|_paired, _stop, _target| ProbeResult {
            state: "unpaired",
            info: None,
            gateway: None,
            trusted_by_source: None,
            cancelled: false,
        });
        let (forget_started_tx, forget_started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        backend.forget_network = Arc::new(move || {
            forget_started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            true
        });
        let pair_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&pair_calls);
        backend.pair_attempt = Arc::new(move |_cancel, _on_code| {
            calls.fetch_add(1, Ordering::AcqRel);
            Ok(PhoneCredentials {
                host: "172.20.10.1".parse().unwrap(),
                port: 1080,
                token: "test-token".into(),
            })
        });
        backend.pair_forget().unwrap();
        forget_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        backend.pair_start().unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let view = backend.pairing.lock().unwrap().view.clone();
            if view.phase == PairPhase::Failed {
                assert_eq!(view.error, Some(FORGET_DRAIN_ERROR));
                break;
            }
            assert!(
                Instant::now() < end,
                "pairing stayed {:?} while the old FORGET was in flight",
                view.phase
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // The pairing must not send a request after the wait timed out, and
        // the in-flight FORGET must stay pending so it can finish.
        assert_eq!(pair_calls.load(Ordering::Acquire), 0);
        assert!(backend.forget.lock().unwrap().pending);
        release_tx.send(()).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        while backend.forget.lock().unwrap().state() != "confirmed" && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(backend.forget.lock().unwrap().state(), "confirmed");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(pair_calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_forget_worker_that_cannot_start_does_not_stay_pending() {
        let forget = Arc::new(Mutex::new(Forget::default()));
        {
            let mut state = forget.lock().unwrap();
            state.pending = true;
            state.generation = 7;
        }
        let network_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&network_called);
        let network: ForgetNetwork = Arc::new(move || {
            called.store(true, Ordering::Release);
            false
        });
        let started = spawn_forget_with(Arc::clone(&forget), network, |_job| {
            Err(io::Error::other("test thread spawn failure"))
        });
        assert!(!started);
        let state = forget.lock().unwrap();
        assert!(!state.pending);
        assert!(!state.in_flight);
        assert_eq!(state.state(), "not_delivered");
        assert_eq!(state.attempts, 0);
        assert!(!network_called.load(Ordering::Acquire));
        drop(state);
        // A failure for an older generation must not clear a newer forget.
        {
            let mut state = forget.lock().unwrap();
            state.pending = true;
            state.outcome = ForgetOutcome::None;
            state.generation = 8;
        }
        forget_spawn_failed(&forget, 7);
        let state = forget.lock().unwrap();
        assert!(state.pending);
        assert_eq!(state.generation, 8);
    }

    fn wait_for_forget(backend: &RustGuiBackend, wanted: &str) -> Value {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let state = backend.forget.lock().unwrap().state();
            if state == wanted {
                break;
            }
            assert!(
                Instant::now() < end,
                "forget stayed {state}, wanted {wanted}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        backend.status().unwrap()
    }

    #[test]
    fn status_exposes_forget_probe_times_and_trust() {
        let mut backend = backend();
        backend.presence.lock().unwrap().state = Some("unpaired");
        backend.presence.lock().unwrap().checked_at = Some(1_760_000_000);
        backend.presence.lock().unwrap().trusted_by_source = Some(true);
        let status = backend.with_pairing(json!({"running":false}));
        assert_eq!(status["phone"]["checked_at"], 1_760_000_000u64);
        assert_eq!(status["phone"]["trusted_by_source"], true);
        assert_eq!(status["forget"], json!({"state":"none","attempts":0}));
        assert!(status["iface"].is_string() || status["iface"].is_null());
        assert_eq!(status["last_stop"], json!({"reason":null,"at":null}));
        assert_eq!(status["last_stop_message"], Value::Null);
        // A pending FORGET stays visible while retries remain.
        {
            let mut forget = backend.forget.lock().unwrap();
            forget.pending = true;
            forget.attempts = 1;
        }
        assert_eq!(
            backend.with_pairing(json!({}))["forget"],
            json!({"state":"pending","attempts":1})
        );
        // A confirmed FORGET stays until the next pair start.
        {
            let mut forget = backend.forget.lock().unwrap();
            forget.pending = false;
            forget.outcome = ForgetOutcome::Confirmed;
        }
        assert_eq!(
            backend.with_pairing(json!({}))["forget"],
            json!({"state":"confirmed","attempts":1})
        );
        {
            let mut forget = backend.forget.lock().unwrap();
            forget.outcome = ForgetOutcome::NotDelivered;
            forget.attempts = MAX_FORGET_TRIES;
        }
        assert_eq!(
            backend.with_pairing(json!({}))["forget"],
            json!({"state":"not_delivered","attempts":3})
        );
        backend.pair_attempt = Arc::new(|_, _| Err(PairError::Cancelled));
        backend.pair_start().unwrap();
        assert_eq!(backend.forget.lock().unwrap().state(), "none");
        backend.pair_cancel().unwrap();
    }

    #[test]
    fn immediate_probe_returns_the_phone_object_and_honors_the_rate_limit() {
        let mut backend = backend();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            counter.fetch_add(1, Ordering::AcqRel);
            ProbeResult {
                state: "unpaired",
                info: None,
                gateway: None,
                trusted_by_source: Some(true),
                cancelled: false,
            }
        });
        let first = backend.phone_probe().unwrap();
        assert_eq!(first["ok"], true);
        assert_eq!(first["phone"]["state"], "unpaired");
        assert_eq!(first["phone"]["trusted_by_source"], true);
        assert!(first["phone"]["checked_at"].as_u64().is_some());
        assert_eq!(calls.load(Ordering::Acquire), 1);
        // A second call within 500 ms returns the cached object.
        let second = backend.phone_probe().unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(second["phone"], first["phone"]);
        std::thread::sleep(Duration::from_millis(510));
        let third = backend.phone_probe().unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(third["phone"]["state"], "unpaired");
        assert!(!third.to_string().contains("token"));
    }

    #[test]
    fn trusted_by_source_comes_from_the_challenge_byte() {
        let identity = identity();
        let public = identity.public();
        // A source device that trusts the key answers CHALLENGE known = 1.
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().trust(public);
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        let result = probe_once(address, false, &identity);
        assert_eq!(result.state, "unpaired");
        assert_eq!(result.trusted_by_source, Some(true));
        handle.join().unwrap();
        // An unknown key gets RESULT Rejected. The answer is not a CHALLENGE,
        // so the trust value is unknown.
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(MockPhone::new(Decide::Allow))), 2);
        let result = probe_once(address, false, &identity);
        assert_eq!(result.state, "unpaired");
        assert_eq!(result.trusted_by_source, None);
        handle.join().unwrap();
        // A CHALLENGE with known = 0 reports false.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            use std::io::Write;
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = [0u8; 2];
                if stream.read_exact(&mut header).is_err() {
                    // The probe opens one plain connection first.
                    continue;
                }
                let mut hello = vec![0u8; u16::from_be_bytes(header) as usize];
                stream.read_exact(&mut hello).unwrap();
                let challenge = pairing::encode_challenge(&[0x33; 32], false);
                stream
                    .write_all(&pairing::frame(&challenge).unwrap())
                    .unwrap();
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte);
            }
        });
        let result = probe_once(address, false, &identity);
        assert_eq!(result.state, "unpaired");
        assert_eq!(result.trusted_by_source, Some(false));
        worker.join().unwrap();
    }

    #[test]
    fn forget_state_moves_from_pending_to_confirmed_or_not_delivered() {
        let forget = Arc::new(Mutex::new(Forget::default()));
        let confirmed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&confirmed);
        let network: ForgetNetwork = Arc::new(move || flag.load(Ordering::Acquire));
        assert_eq!(forget.lock().unwrap().state(), "none");
        {
            let mut state = forget.lock().unwrap();
            state.pending = true;
            state.attempts = 0;
            state.generation = state.generation.wrapping_add(1);
        }
        spawn_forget(Arc::clone(&forget), Arc::clone(&network));
        let wait = |wanted: &str| {
            let end = Instant::now() + Duration::from_secs(2);
            while forget.lock().unwrap().state() != wanted {
                assert!(Instant::now() < end, "wanted {wanted}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        let wait_attempts = |wanted: u8| {
            let end = Instant::now() + Duration::from_secs(2);
            while forget.lock().unwrap().attempts != wanted {
                assert!(Instant::now() < end, "wanted {wanted} attempts");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        wait_attempts(1);
        assert_eq!(forget.lock().unwrap().state(), "pending");
        confirmed.store(true, Ordering::Release);
        spawn_forget(Arc::clone(&forget), Arc::clone(&network));
        wait("confirmed");
        assert_eq!(forget.lock().unwrap().attempts, 2);
        // A new forget clears the old outcome.
        {
            let mut state = forget.lock().unwrap();
            assert_eq!(state.state(), "confirmed");
            state.pending = true;
            state.attempts = MAX_FORGET_TRIES - 1;
            state.outcome = ForgetOutcome::None;
            state.generation = state.generation.wrapping_add(1);
        }
        confirmed.store(false, Ordering::Release);
        spawn_forget(Arc::clone(&forget), Arc::clone(&network));
        wait("not_delivered");
        assert_eq!(forget.lock().unwrap().attempts, MAX_FORGET_TRIES);
        assert!(!forget.lock().unwrap().should_retry());
        assert_eq!(forget.lock().unwrap().state(), "not_delivered");
    }

    #[test]
    fn forget_cancels_a_pairing_and_probes_even_without_credentials() {
        let mut backend = backend();
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&probes);
        backend.probe_attempt = Arc::new(move |_, _, _| {
            counter.fetch_add(1, Ordering::AcqRel);
            ProbeResult {
                state: "unpaired",
                info: None,
                gateway: None,
                trusted_by_source: Some(false),
                cancelled: false,
            }
        });
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        backend.forget_network = Arc::new(move || {
            counter.fetch_add(1, Ordering::AcqRel);
            false
        });
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut inner = backend.pairing.lock().unwrap();
            inner.cancel = Some(Arc::clone(&cancel));
            inner.view = PairView {
                phase: PairPhase::Connecting,
                ..PairView::default()
            };
        }
        assert!(backend.pairing.lock().unwrap().credentials.is_none());
        backend.pair_forget().unwrap();
        assert!(cancel.load(Ordering::Acquire));
        assert!(backend.pairing.lock().unwrap().cancel.is_none());
        assert_eq!(backend.pairing.lock().unwrap().view.phase, PairPhase::Idle);
        assert_eq!(probes.load(Ordering::Acquire), 1);
        assert!(backend.forget.lock().unwrap().pending);
        let status = wait_for_forget(&backend, "pending");
        assert_eq!(status["forget"]["state"], "pending");
        assert!(!status.to_string().contains("token"));
        let end = Instant::now() + Duration::from_secs(2);
        while attempts.load(Ordering::Acquire) == 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(attempts.load(Ordering::Acquire), 1);
    }

    #[test]
    fn start_error_mapping_keeps_source_device_auth_distinct() {
        assert_eq!(
            phone_start_error(io::Error::other("phone_auth")),
            "phone_auth"
        );
        assert_eq!(
            phone_start_error(io::Error::other("source_device_moved")),
            "source_device_moved"
        );
        assert_eq!(
            phone_start_error(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
            "admin_required"
        );
        assert_eq!(
            phone_start_error(io::Error::new(io::ErrorKind::Interrupted, "stopped")),
            "start_cancelled"
        );
        assert_eq!(
            phone_start_error(io::Error::other("private detail")),
            "source device start failed"
        );
        assert!(!phone_start_error(io::Error::other("secret-token")).contains("secret-token"));
    }

    #[test]
    fn a_service_cleanup_fault_makes_every_gui_stop_error() {
        let service = Arc::new(Service::new());
        service.inject_cleanup_fault_for_test();
        let backend = RustGuiBackend::new(Arc::clone(&service));
        // A local run owns the service. The injected fault represents a route
        // cleanup or worker join failure that no test can create hermetically.
        backend.finish(Phase::Local);
        let first = backend.stop();
        assert!(
            first.is_err(),
            "a cleanup fault must fail the stop that heard it"
        );
        // The GUI server stops twice, and main stops once more. None of those
        // calls may turn the recorded fault into a clean engine exit, because
        // the Swift helper clears its durable intent on a zero exit.
        let second = backend.stop();
        assert!(
            second.is_err(),
            "the final GUI stop must keep reporting the cleanup fault"
        );
        let status = backend.status().unwrap();
        assert_eq!(status["cleanup_blocked"], true);
        assert_eq!(status["running"], false);
        assert_eq!(status["last_stop"]["reason"], "error");
    }

    #[test]
    fn a_panicked_tunnel_start_blocks_a_clean_gui_exit() {
        let service = Arc::new(Service::new());
        let backend = RustGuiBackend::new(Arc::clone(&service));
        PANIC_NEXT_TUN_START.with(|flag| flag.set(true));
        let error = backend.start(json!({
            "mode":"tun",
            "options":{"iface":"lo0"}
        }));
        assert!(error.is_err(), "the caught start panic is a start failure");
        // The start guard stopped whatever the start had already created, but
        // the panic is not proof of a clean cleanup. Every exit path reports it.
        assert!(service.cleanup_uncertain());
        assert!(backend.stop().is_err());
        assert!(backend.stop().is_err());
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        assert_eq!(backend.status().unwrap()["cleanup_blocked"], true);
    }

    #[test]
    fn a_clean_gui_stop_still_reports_stopped_false_after_idle() {
        let backend = backend();
        backend.finish(Phase::Local);
        let first = backend.stop().unwrap();
        assert_eq!(first["stopped"], true);
        let second = backend.stop().unwrap();
        assert_eq!(second["stopped"], false);
    }

    #[test]
    fn direct_start_errors_keep_the_real_service_stage() {
        assert_eq!(
            direct_start_error(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
            "admin_required"
        );
        assert_eq!(
            direct_start_error(io::Error::new(io::ErrorKind::Interrupted, "stopped")),
            "start_cancelled"
        );
        assert_eq!(
            direct_start_error(io::Error::other("route_setup")),
            "route_setup"
        );
        assert_eq!(
            direct_start_error(io::Error::other("tunnel_setup")),
            "tunnel_setup"
        );
        assert_eq!(
            direct_start_error(io::Error::other("route cleanup failed")),
            "service_start"
        );
        assert_eq!(
            direct_start_error(io::Error::other("secret-token")),
            "service_start"
        );
    }

    #[test]
    fn auto_stop_and_user_stop_set_last_stop_until_the_next_start() {
        let backend = RustGuiBackend::new(Arc::new(Service::new()));
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let free_port = || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let start = |port: u16| {
            backend
                .start(json!({"mode":"socks5","options":{
                    "host":"127.0.0.1","port":port,"iface":iface,
                    "dns_servers":["127.0.0.1"]
                }}))
                .unwrap();
        };
        start(free_port());
        let status = backend.status().unwrap();
        assert_eq!(status["running"], true);
        assert_eq!(status["iface"], iface);
        assert_eq!(status["last_stop"]["reason"], Value::Null);
        let stopped = backend.stop_for("hotspot_lost").unwrap();
        assert_eq!(stopped["stopped"], true);
        let status = backend.status().unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["last_stop"]["reason"], "hotspot_lost");
        assert!(status["last_stop"]["at"].as_u64().is_some());
        assert_eq!(
            status["last_stop_message"],
            autostop::stop_message("hotspot_lost").unwrap()
        );
        // The record stays across status reads.
        assert_eq!(
            backend.status().unwrap()["last_stop"]["reason"],
            "hotspot_lost"
        );
        // A new start clears it.
        start(free_port());
        assert_eq!(
            backend.status().unwrap()["last_stop"]["reason"],
            Value::Null
        );
        backend.stop().unwrap();
        let status = backend.status().unwrap();
        assert_eq!(status["last_stop"]["reason"], "user");
        assert_eq!(status["last_stop_message"], Value::Null);
    }

    #[test]
    fn a_stop_that_the_engine_did_not_start_is_an_error_stop() {
        let backend = backend();
        // The engine started a local run. The service stopped on its own, so
        // the phase still names the run.
        *backend.phase.lock().unwrap() = Phase::Local;
        backend.was_running.store(true, Ordering::Release);
        let status = backend.status().unwrap();
        assert_eq!(status["last_stop"]["reason"], "error");
        assert_eq!(status["last_stop_message"], Value::Null);
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        // A second read does not move the time or the reason.
        let at = status["last_stop"]["at"].clone();
        assert_eq!(backend.status().unwrap()["last_stop"]["at"], at);
    }

    /// A short schedule for the presence tests. The production periods are
    /// seconds. A test must finish in a moment.
    fn fast_schedule(running: Duration) -> PresenceSchedule {
        PresenceSchedule {
            running,
            polling: Duration::from_millis(5),
            unpolled: Duration::from_millis(5),
            idle_limit: Duration::from_secs(300),
            poll: Duration::from_millis(5),
        }
    }

    /// A presence observer that counts probes and returns one fixed state.
    fn counting_backend(
        state: &'static str,
    ) -> (RustGuiBackend, Arc<std::sync::atomic::AtomicUsize>) {
        let mut backend = backend();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            counter.fetch_add(1, Ordering::AcqRel);
            ProbeResult {
                state,
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        (backend, calls)
    }

    /// The page has not read the API for 20 minutes. This is the idle page
    /// that stopped the observer before the fix.
    fn idle_page(backend: &RustGuiBackend) {
        backend.presence.lock().unwrap().last_request =
            Some(Instant::now() - Duration::from_secs(1200));
    }

    #[test]
    fn presence_observer_keeps_probing_while_a_phone_tunnel_runs_with_an_idle_page() {
        let (backend, calls) = counting_backend("ready");
        idle_page(&backend);
        backend.set_phone_running(true);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = backend
            .start_presence_with(Arc::clone(&stop), fast_schedule(Duration::from_millis(10)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while calls.load(Ordering::Acquire) < 3 {
            assert!(
                Instant::now() < deadline,
                "the observer stopped while the tunnel ran"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        {
            let presence = backend.presence.lock().unwrap();
            assert_eq!(presence.state, Some("ready"));
            assert!(presence
                .checked
                .is_some_and(|at| at.elapsed() < Duration::from_secs(1)));
        }
        stop.store(true, Ordering::Release);
        let began = Instant::now();
        handle.join().unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "the observer did not stop"
        );
        let after = calls.load(Ordering::Acquire);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            calls.load(Ordering::Acquire),
            after,
            "a probe ran after the stop"
        );
    }

    #[test]
    fn presence_observer_goes_quiet_when_the_tunnel_stops() {
        // Drive the decisions with a fake clock. A fixed sleep cannot show
        // that no probe starts after the stop, because an in-flight probe can
        // finish at any moment.
        let (backend, calls) = counting_backend("not_responding");
        idle_page(&backend);
        backend.set_phone_running(true);
        let stop = AtomicBool::new(false);
        let observer = backend.observer(fast_schedule(Duration::from_millis(10)));
        let now = Instant::now();
        let mut last_probe = None;
        assert_eq!(observer.step(now, &mut last_probe, &stop), Step::Probed);
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            backend.presence.lock().unwrap().state,
            Some("not_responding")
        );
        // Inside the period no probe is due.
        assert_eq!(
            observer.step(now + Duration::from_millis(5), &mut last_probe, &stop),
            Step::Idle
        );
        // The tunnel stops. The idle page must not keep the observer probing.
        backend.set_phone_running(false);
        assert_eq!(
            observer.step(now + Duration::from_secs(1), &mut last_probe, &stop),
            Step::Idle
        );
        assert_eq!(
            observer.step(now + Duration::from_secs(120), &mut last_probe, &stop),
            Step::Idle
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        // The stop flag ends the observer before another probe.
        stop.store(true, Ordering::Release);
        assert_eq!(
            observer.step(now + Duration::from_secs(121), &mut last_probe, &stop),
            Step::Stopped
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn presence_observer_probes_a_running_tunnel_without_an_api_read() {
        // The page never reads the API, so `last_request` is None. A running
        // phone tunnel must still probe for the auto-stop policy.
        let mut backend = backend();
        let (tx, rx) = std::sync::mpsc::channel();
        let sender = Arc::new(Mutex::new(tx));
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            let _ = sender.lock().map(|sender| sender.send(()));
            ProbeResult {
                state: "ready",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        assert!(backend.presence.lock().unwrap().last_request.is_none());
        backend.set_phone_running(true);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = backend
            .start_presence_with(Arc::clone(&stop), fast_schedule(Duration::from_millis(5)))
            .unwrap();
        for _ in 0..2 {
            assert!(
                rx.recv_timeout(Duration::from_secs(2)).is_ok(),
                "the observer did not probe without an API read"
            );
        }
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    /// Serve one connection: read the HELLO frame, then send `reply` raw.
    fn raw_reply_listener(reply: Vec<u8>) -> (SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // The probe first opens a bare connection to test the listener, then a
        // second one for the exchange. Serve both the same way.
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                // One length-prefixed HELLO frame.
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_ok() {
                    let mut hello = vec![0u8; usize::from(u16::from_be_bytes(length))];
                    let _ = stream.read_exact(&mut hello);
                }
                let _ = stream.write_all(&reply);
            }
        });
        (address, handle)
    }

    fn result_frame(status: pairing::PhoneStatus) -> Vec<u8> {
        pairing::frame(&pairing::encode_result_status(status)).unwrap()
    }

    #[test]
    fn a_valid_source_answer_is_not_source_silence() {
        use pairing::PhoneStatus::*;
        let identity = identity();
        // (status, state when paired, state when unpaired)
        let cases = [
            (Busy, "checking", "checking"),
            (NotActive, "not_trusted", "unpaired"),
            (LockedOut, "not_trusted", "unpaired"),
            (Rejected, "not_trusted", "unpaired"),
            // Not valid answers to a status request.
            (Denied, "not_responding", "not_responding"),
            (TimedOut, "not_responding", "not_responding"),
        ];
        for (status, paired_state, unpaired_state) in cases {
            for (paired, expected) in [(true, paired_state), (false, unpaired_state)] {
                let (address, handle) = raw_reply_listener(result_frame(status));
                let result = probe_once(address, paired, &identity);
                handle.join().unwrap();
                assert_eq!(result.state, expected, "{status:?} paired={paired}");
                assert!(
                    result.info.is_none(),
                    "an unauthenticated answer has no info"
                );
                assert!(!result.cancelled);
                let silent = crate::autostop::sample_from(true, true, Some(result.state))
                    == crate::autostop::HotspotSample::DeviceGone;
                assert_eq!(silent, expected == "not_responding", "{status:?}");
            }
        }
        // A protocol error and a closed connection are not answers.
        for reply in [vec![0, 1, 0x09], vec![0, 2, 0x04, 0x63], Vec::new()] {
            for paired in [true, false] {
                let (address, handle) = raw_reply_listener(reply.clone());
                let result = probe_once(address, paired, &identity);
                handle.join().unwrap();
                assert_eq!(result.state, "not_responding", "reply {reply:?}");
            }
        }
        // A plaintext Busy frame with trailing bytes is malformed.
        let (address, handle) = raw_reply_listener(vec![0, 3, 0x04, 0x02, 0x00]);
        assert_eq!(probe_once(address, true, &identity).state, "not_responding");
        handle.join().unwrap();
    }

    #[test]
    fn a_busy_answer_shows_checking_without_claiming_presence() {
        let backend = backend();
        let run = backend.run_id.load(Ordering::Acquire);
        let record = |state| {
            let result = ProbeResult {
                state,
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            };
            assert!(record_probe_for_run(
                &backend.presence,
                &backend.pairing,
                &backend.run_id,
                run,
                &result
            ));
            backend.presence.lock().unwrap().state
        };
        // A Busy answer is recorded as checking, and the status JSON says so
        // while a tunnel runs. Auto-stop reads checking as unverified, never
        // as presence and never as immediate silence.
        assert_eq!(record("checking"), Some("checking"));
        assert_eq!(phone_state(Some("checking"), true), "checking");
        assert_eq!(
            crate::autostop::sample_from(true, true, Some("checking")),
            crate::autostop::HotspotSample::Unverified
        );
        // A timeout is silence. A later Busy answer must not erase that
        // silence evidence; the policy keeps the timer.
        assert_eq!(record("not_responding"), Some("not_responding"));
        assert_eq!(record("checking"), Some("checking"));
        // A real authenticated answer is presence and clears the unverified
        // run. The policy owns the bound, so the presence value stays exact.
        assert_eq!(record("ready"), Some("ready"));
        assert_eq!(
            crate::autostop::sample_from(true, true, Some("ready")),
            crate::autostop::HotspotSample::Good
        );
        assert_eq!(record("checking"), Some("checking"));
        // A new run drops the stored answer.
        backend.reset_presence();
        assert_eq!(backend.presence.lock().unwrap().state, None);
    }

    #[test]
    fn a_cancelled_probe_is_not_recorded_as_silence() {
        let mut backend = backend();
        backend.probe_attempt = Arc::new(|_paired, _stop, _target| ProbeResult::cancelled());
        idle_page(&backend);
        backend.set_phone_running(true);
        let stop = AtomicBool::new(false);
        let observer = backend.observer(fast_schedule(Duration::from_millis(5)));
        let now = Instant::now();
        let mut last_probe = None;
        assert_eq!(observer.step(now, &mut last_probe, &stop), Step::Cancelled);
        {
            let presence = backend.presence.lock().unwrap();
            assert_eq!(presence.state, None, "a cancellation is not an answer");
            assert_eq!(presence.checked, None);
            assert_eq!(presence.checked_at, None);
        }
        // The engine still treats the tunnel as running. A cancelled probe
        // must not turn into an auto stop.
        assert!(backend.phone_running.load(Ordering::Acquire));
    }

    #[test]
    fn a_panicked_observer_is_restarted_and_keeps_the_tunnel() {
        let mut backend = backend();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let (tx, rx) = std::sync::mpsc::channel();
        let sender = Arc::new(Mutex::new(tx));
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            if counter.fetch_add(1, Ordering::AcqRel) == 0 {
                panic!("test observer panic");
            }
            let _ = sender.lock().map(|sender| sender.send(()));
            ProbeResult {
                state: "ready",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        backend.set_phone_running(true);
        let stop = Arc::new(AtomicBool::new(false));
        let first = backend
            .start_presence_with(Arc::clone(&stop), fast_schedule(Duration::from_millis(5)))
            .unwrap();
        // The supervisor catches the panic, so the thread ends normally.
        first.join().unwrap();
        assert!(backend.observer_failed());
        // The supervisor starts the observer again after its period.
        backend.observer.lock().unwrap().retry = Duration::ZERO;
        assert!(backend.ensure_observer_at(Instant::now()));
        assert_eq!(
            backend.observer.lock().unwrap().starts,
            2,
            "the supervisor did not start a new observer"
        );
        assert!(
            rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "the observer did not run again"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while backend.presence.lock().unwrap().state != Some("ready") {
            assert!(Instant::now() < deadline, "the new probe was not stored");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            backend.phone_running.load(Ordering::Acquire),
            "the supervisor touched the tunnel"
        );
        stop.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while backend.observer.lock().unwrap().state != ObserverState::Stopped {
            assert!(Instant::now() < deadline, "the observer did not stop");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn a_stopped_observer_is_not_restarted() {
        let backend = backend();
        let stop = Arc::new(AtomicBool::new(true));
        let handle = backend
            .start_presence_with(Arc::clone(&stop), fast_schedule(Duration::from_millis(5)))
            .unwrap();
        handle.join().unwrap();
        assert_eq!(
            backend.observer.lock().unwrap().state,
            ObserverState::Stopped
        );
        assert!(!backend.ensure_observer_at(Instant::now()));
        assert_eq!(
            backend.observer.lock().unwrap().starts,
            1,
            "the supervisor started an observer after the stop"
        );
    }

    #[test]
    fn a_failed_observer_does_not_report_missing_data_as_connected() {
        let backend = backend();
        // A failed observer with no completed probe proves nothing about the
        // source device. The state must not claim a connection.
        {
            let mut control = backend.observer.lock().unwrap();
            control.state = ObserverState::Failed;
            control.stop = Some(Arc::new(AtomicBool::new(false)));
            control.last_attempt = Some(Instant::now());
            control.retry = Duration::from_secs(3600);
        }
        let status = backend.status().unwrap();
        assert_eq!(status["phone"]["state"], "not_responding");
        assert_eq!(
            status["phone"]["message"],
            "Open HotspotShade on your source device and keep it open."
        );
        // A completed answer stays visible.
        backend.presence.lock().unwrap().state = Some("ready");
        assert_eq!(
            backend.with_pairing(json!({"running":true,"mode":"phone"}))["phone"]["state"],
            "connected"
        );
        // Without a failed observer, the start grace still reports connected
        // until the first probe completes.
        let fresh = RustGuiBackend::new(Arc::new(Service::new()));
        assert_eq!(
            fresh.with_pairing(json!({"running":true,"mode":"phone"}))["phone"]["state"],
            "connected"
        );
    }

    #[test]
    fn presence_observer_stays_idle_without_a_tunnel_and_an_idle_page() {
        let (backend, calls) = counting_backend("ready");
        idle_page(&backend);
        assert!(!backend.phone_running.load(Ordering::Acquire));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = backend
            .start_presence_with(Arc::clone(&stop), fast_schedule(Duration::from_millis(5)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(
            calls.load(Ordering::Acquire),
            0,
            "the observer probed an idle page with no tunnel"
        );
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn presence_observer_honors_stop_during_an_in_flight_probe() {
        let mut backend = backend();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let started = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&started);
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            counter.fetch_add(1, Ordering::AcqRel);
            flag.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(150));
            ProbeResult {
                state: "ready",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        idle_page(&backend);
        backend.set_phone_running(true);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = backend
            .start_presence_with(Arc::clone(&stop), fast_schedule(Duration::from_millis(5)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !started.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "the probe did not start");
            std::thread::sleep(Duration::from_millis(2));
        }
        stop.store(true, Ordering::Release);
        let began = Instant::now();
        handle.join().unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "the observer did not stop after the in-flight probe"
        );
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "the observer started a second probe after the stop"
        );
    }

    #[test]
    fn a_running_tunnel_is_due_without_an_api_read() {
        use super::{probe_due, PresenceSchedule};
        use std::time::{Duration, Instant};
        let schedule = PresenceSchedule::default();
        let now = Instant::now();
        // The page has never read the API. A running tunnel still probes.
        assert!(probe_due(now, None, None, true, schedule));
        assert!(!probe_due(now, None, None, false, schedule));
        // A stopped tunnel needs a recent API read.
        assert!(probe_due(
            now,
            Some(now - Duration::from_secs(1)),
            None,
            false,
            schedule
        ));
        // The period still applies with a running tunnel.
        assert!(!probe_due(
            now,
            None,
            Some(now - Duration::from_millis(500)),
            true,
            schedule
        ));
        assert!(probe_due(
            now,
            None,
            Some(now - Duration::from_secs(2)),
            true,
            schedule
        ));
        // A long idle page stops the observer when no tunnel runs.
        assert!(!probe_due(
            now,
            Some(now - Duration::from_secs(300)),
            None,
            false,
            schedule
        ));
    }

    #[test]
    fn a_definitely_exited_helper_is_retired_without_a_restart() {
        let backend = backend();
        let (stream, peer) = UnixStream::pair().unwrap();
        // The peer is gone, so the status request fails at once.
        drop(peer);
        let launcher = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        // Reap the child so that the death is definite.
        helper.lock().unwrap().launcher.wait().unwrap();
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&helper));
        backend.was_running.store(true, Ordering::Release);
        backend.set_phone_running(true);
        backend.remember_tunnel_port(31000);
        backend.remember_tunnel_iface(Some("lo0".into()));
        let status = backend.status().unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["last_stop"]["reason"], "error");
        assert_eq!(status["phone_port"], Value::Null);
        assert!(!backend.phone_running.load(Ordering::Acquire));
        assert!(backend.tunnel_phone_port.lock().unwrap().is_none());
        assert!(backend.tunnel_iface.lock().unwrap().is_none());
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        // The record stays across the next read.
        let at = status["last_stop"]["at"].clone();
        assert_eq!(backend.status().unwrap()["last_stop"]["at"], at);
    }

    #[test]
    fn a_stop_with_an_exited_helper_completes_cleanly() {
        let backend = backend();
        let (stream, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let launcher = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        helper.lock().unwrap().launcher.wait().unwrap();
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&helper));
        backend.was_running.store(true, Ordering::Release);
        backend.set_phone_running(true);
        backend.remember_tunnel_port(31000);
        let stopped = backend.stop().unwrap();
        assert_eq!(stopped["stopped"], true);
        assert_eq!(
            backend.last_stop.lock().unwrap().as_ref().unwrap().reason,
            "user"
        );
        assert!(!backend.phone_running.load(Ordering::Acquire));
        assert!(backend.tunnel_phone_port.lock().unwrap().is_none());
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
    }

    #[test]
    fn a_transient_helper_error_keeps_the_tunnel_and_the_presence_mode() {
        let backend = backend();
        let (stream, peer) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let launcher = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&helper));
        backend.was_running.store(true, Ordering::Release);
        backend.set_phone_running(true);
        // The child is alive, so a read timeout proves nothing.
        assert!(backend.status().is_err());
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Remote(_)));
        assert!(backend.phone_running.load(Ordering::Acquire));
        assert!(
            backend
                .last_stop
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(|stop| stop.reason != "error"),
            "a transient error stopped the tunnel"
        );
        // Remove the test process by hand. The backend must not stop it.
        {
            let mut helper = helper.lock().unwrap();
            let _ = helper.stream.shutdown(std::net::Shutdown::Both);
            let _ = helper.launcher.kill();
            let _ = helper.launcher.wait();
        }
        *backend.phase.lock().unwrap() = Phase::Idle;
        drop(peer);
    }

    #[test]
    fn a_stop_clears_the_phone_presence_mode() {
        let backend = backend();
        backend.set_phone_running(true);
        backend.forget_tunnel_port();
        assert!(!backend.phone_running.load(Ordering::Acquire));
        backend.set_phone_running(true);
        backend.record_stop("error");
        assert!(!backend.phone_running.load(Ordering::Acquire));
        // A stop on an idle backend is still a stop.
        backend.set_phone_running(true);
        assert_eq!(backend.stop().unwrap()["stopped"], false);
        assert!(!backend.phone_running.load(Ordering::Acquire));
    }

    #[test]
    fn a_missing_gateway_or_interface_is_cached_briefly() {
        let gateway = (Ipv4Addr::new(172, 20, 10, 1), 5u32);
        assert_eq!(gateway_ttl(&None), GATEWAY_MISS_TTL);
        assert_eq!(gateway_ttl(&Some(gateway)), GATEWAY_CACHE_TTL);
        assert_eq!(iface_ttl(&None), GATEWAY_MISS_TTL);
        assert_eq!(iface_ttl(&Some("en0".into())), GATEWAY_CACHE_TTL);
        // A miss must expire before the auto-stop link-down limit can fire.
        assert!(GATEWAY_MISS_TTL < crate::autostop::LINK_DOWN_LIMIT);
        let cache: GatewayCache = Mutex::new(None);
        let t0 = Instant::now();
        let mut calls = 0;
        assert_eq!(
            cached_value(&cache, t0, gateway_ttl, || {
                calls += 1;
                None
            }),
            Some(None)
        );
        // A miss stays for one second, not 30 seconds.
        assert_eq!(
            cached_value(&cache, t0 + Duration::from_millis(500), gateway_ttl, || {
                calls += 1;
                Some(gateway)
            }),
            Some(None)
        );
        assert_eq!(calls, 1);
        assert_eq!(
            cached_value(&cache, t0 + Duration::from_secs(2), gateway_ttl, || {
                calls += 1;
                Some(gateway)
            }),
            Some(Some(gateway))
        );
        assert_eq!(calls, 2);
        // A real answer stays for 30 seconds.
        assert_eq!(
            cached_value(&cache, t0 + Duration::from_secs(20), gateway_ttl, || {
                calls += 1;
                None
            }),
            Some(Some(gateway))
        );
        assert_eq!(calls, 2);
        assert_eq!(
            cached_value(&cache, t0 + Duration::from_secs(33), gateway_ttl, || {
                calls += 1;
                Some(gateway)
            }),
            Some(Some(gateway))
        );
        assert_eq!(calls, 3);
    }

    #[test]
    fn retirement_records_the_error_stop_before_a_new_start_can_begin() {
        let backend = backend();
        let (stream, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let launcher = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        helper.lock().unwrap().launcher.wait().unwrap();
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&helper));
        backend.was_running.store(true, Ordering::Release);
        backend.set_phone_running(true);
        backend.remember_tunnel_port(31000);
        backend.remember_tunnel_iface(Some("lo0".into()));
        let old_run = backend.run_id.load(Ordering::Acquire);
        // The status path finalizes the helper before it retires it.
        finalize_helper(&helper);
        assert!(backend.retire_dead_helper(&helper));
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        // The old order published Idle first and cleared the state later. A
        // start in that window lost its new port. The stop record and the
        // clear are now part of the same critical section.
        assert_eq!(
            backend.last_stop.lock().unwrap().as_ref().unwrap().reason,
            "error"
        );
        assert!(!backend.was_running.load(Ordering::Acquire));
        assert!(!backend.phone_running.load(Ordering::Acquire));
        assert!(backend.tunnel_phone_port.lock().unwrap().is_none());
        assert!(backend.tunnel_iface.lock().unwrap().is_none());
        assert_ne!(backend.run_id.load(Ordering::Acquire), old_run);
        // A start that follows keeps its own state. A late status answer from
        // the old run cannot clear it.
        let (_cancel, _slot) = backend.begin().unwrap();
        backend
            .finish_start(Phase::Local, true, Some("en9".into()), Some(42000))
            .unwrap();
        assert!(!backend.finish_error_stop(old_run));
        assert_eq!(*backend.tunnel_phone_port.lock().unwrap(), Some(42000));
        assert_eq!(backend.tunnel_iface.lock().unwrap().as_deref(), Some("en9"));
        assert!(backend.was_running.load(Ordering::Acquire));
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Local));
    }

    #[test]
    fn a_dead_helper_gets_a_final_stop_before_the_status_retires_it() {
        let backend = backend();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let launcher = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        helper.lock().unwrap().launcher.wait().unwrap();
        let worker = std::thread::spawn(move || {
            use std::io::Read as _;
            let status = privileged::receive(&mut peer).unwrap();
            assert_eq!(status["action"], "status");
            // Do not answer. The caller read times out.
            let stop = privileged::receive(&mut peer).unwrap();
            assert_eq!(stop["action"], "stop");
            privileged::send(&mut peer, &json!({"ok":true})).unwrap();
            // The caller closes the stream after the answer.
            let mut byte = [0u8; 1];
            let _ = peer.read(&mut byte);
        });
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&helper));
        backend.was_running.store(true, Ordering::Release);
        backend.set_phone_running(true);
        backend.remember_tunnel_port(31000);
        backend.remember_tunnel_iface(Some("lo0".into()));
        let status = backend.status().unwrap();
        worker.join().unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["last_stop"]["reason"], "error");
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        assert!(backend.tunnel_phone_port.lock().unwrap().is_none());
        assert!(!backend.phone_running.load(Ordering::Acquire));
    }

    #[test]
    fn a_stopped_helper_stays_tracked_until_its_launcher_is_reaped() {
        let backend = backend();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut launcher = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = launcher.stdin.take().unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        let worker = std::thread::spawn(move || {
            let status = privileged::receive(&mut peer).unwrap();
            assert_eq!(status["action"], "status");
            privileged::send(&mut peer, &json!({"ok":true,"status":{"running":false}})).unwrap();
            let stop = privileged::receive(&mut peer).unwrap();
            assert_eq!(stop["action"], "stop");
            privileged::send(&mut peer, &json!({"ok":true})).unwrap();
        });
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&helper));
        backend.was_running.store(true, Ordering::Release);
        assert_eq!(backend.status().unwrap_err(), "helper is still stopping");
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Remote(_)));
        worker.join().unwrap();
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match backend.status() {
                Ok(status) => break status,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("launcher did not exit: {error}"),
            }
        };
        assert_eq!(status["running"], false);
        assert_eq!(status["last_stop"]["reason"], "error");
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        assert!(helper
            .lock()
            .unwrap()
            .launcher
            .try_wait()
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_failed_observer_with_a_stale_ready_result_reports_checking() {
        let backend = backend();
        backend.set_phone_running(true);
        {
            let mut control = backend.observer.lock().unwrap();
            control.state = ObserverState::Failed;
            control.stop = Some(Arc::new(AtomicBool::new(false)));
            control.last_attempt = Some(Instant::now());
            control.retry = Duration::from_secs(3600);
        }
        {
            let mut presence = backend.presence.lock().unwrap();
            presence.state = Some("ready");
            presence.checked = Some(Instant::now() - PROBE_FRESH - Duration::from_secs(1));
            presence.checked_at = Some(1_000);
        }
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "checking");
        assert_eq!(status["phone"]["message"], "Checking the source device.");
        // A fresh result stays visible.
        backend.presence.lock().unwrap().checked = Some(Instant::now());
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "connected");
        // The stale time stays honest for the auto-stop policy.
        backend.presence.lock().unwrap().checked =
            Some(Instant::now() - PROBE_FRESH - Duration::from_secs(1));
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "checking");
        assert_eq!(status["phone"]["checked_at"], 1_000u64);
        // A fresh failed probe is still a real failure.
        {
            let mut presence = backend.presence.lock().unwrap();
            presence.state = Some("not_responding");
            presence.checked = Some(Instant::now());
            presence.checked_at = Some(now_unix());
        }
        let status = backend.with_pairing(json!({"running":true,"mode":"phone"}));
        assert_eq!(status["phone"]["state"], "not_responding");
    }

    #[test]
    fn a_failed_observer_gets_one_bounded_fallback_probe() {
        let mut backend = backend();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            counter.fetch_add(1, Ordering::AcqRel);
            ProbeResult {
                state: "ready",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        backend.set_phone_running(true);
        {
            let mut control = backend.observer.lock().unwrap();
            control.state = ObserverState::Failed;
            control.stop = Some(Arc::new(AtomicBool::new(false)));
            control.last_attempt = Some(Instant::now());
            control.retry = Duration::from_secs(3600);
        }
        let started = Instant::now();
        assert!(backend.start_fallback_probe_at(started));
        let deadline = Instant::now() + Duration::from_secs(2);
        while backend.presence.lock().unwrap().state != Some("ready") {
            assert!(
                Instant::now() < deadline,
                "the fallback probe was not stored"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        // The fallback never starts or stops the tunnel.
        assert!(backend.phone_running.load(Ordering::Acquire));
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        assert!(backend.last_stop.lock().unwrap().is_none());
        // The rate limit keeps a failed supervisor from spinning.
        assert!(!backend.start_fallback_probe_at(started + Duration::from_millis(500)));
        let deadline = Instant::now() + Duration::from_secs(2);
        while backend.fallback_active.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "the fallback probe did not finish"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            backend.start_fallback_probe_at(started + FALLBACK_RETRY + Duration::from_millis(1))
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while calls.load(Ordering::Acquire) < 2 {
            assert!(
                Instant::now() < deadline,
                "the second fallback probe did not run"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn the_fallback_probe_stays_quiet_without_a_tunnel_or_a_page() {
        let mut backend = backend();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            counter.fetch_add(1, Ordering::AcqRel);
            ProbeResult {
                state: "ready",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        {
            let mut control = backend.observer.lock().unwrap();
            control.state = ObserverState::Failed;
            control.stop = Some(Arc::new(AtomicBool::new(false)));
            control.last_attempt = Some(Instant::now());
            control.retry = Duration::from_secs(3600);
        }
        idle_page(&backend);
        assert!(!backend.start_fallback_probe_at(Instant::now()));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn an_error_stop_clears_the_phone_port_and_publishes_idle() {
        let backend = backend();
        let (_cancel, _slot) = backend.begin().unwrap();
        backend
            .finish_start(Phase::Local, true, Some("en7".into()), Some(31000))
            .unwrap();
        // The service stopped on its own. The phase still names the run.
        let status = backend.status().unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["last_stop"]["reason"], "error");
        assert!(backend.tunnel_phone_port.lock().unwrap().is_none());
        assert!(backend.tunnel_iface.lock().unwrap().is_none());
        assert!(!backend.phone_running.load(Ordering::Acquire));
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        // A new start is accepted at once.
        let (_cancel, _slot) = backend.begin().unwrap();
        backend.finish(Phase::Idle);
    }

    #[test]
    fn a_late_status_cannot_record_an_error_stop_for_a_replaced_run() {
        let backend = backend();
        let (_cancel, _slot) = backend.begin().unwrap();
        backend
            .finish_start(Phase::Local, true, Some("en0".into()), Some(1080))
            .unwrap();
        let observed_run = backend.run_id.load(Ordering::Acquire);
        // The user stops the old run and starts a new one before the late
        // status answer records its error stop.
        backend.stop().unwrap();
        let (_cancel, _slot) = backend.begin().unwrap();
        backend
            .finish_start(Phase::Local, true, Some("en9".into()), Some(42000))
            .unwrap();
        assert!(!backend.finish_error_stop(observed_run));
        assert_eq!(*backend.tunnel_phone_port.lock().unwrap(), Some(42000));
        assert_eq!(backend.tunnel_iface.lock().unwrap().as_deref(), Some("en9"));
        assert!(backend.was_running.load(Ordering::Acquire));
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Local));
    }

    #[test]
    fn a_running_phone_tunnel_probes_its_start_host_and_interface() {
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let index = normalization::interface_index(iface).unwrap();
        // The paired target and a manual token target both keep the host that
        // the start used. The probe never reads the current default route.
        for host in ["172.20.10.1", "192.168.16.20"] {
            let mut backend = backend();
            let seen = Arc::new(Mutex::new(None::<ProbeTarget>));
            let slot = Arc::clone(&seen);
            backend.probe_attempt = Arc::new(move |_paired, _stop, target| {
                *slot.lock().unwrap() = target;
                ProbeResult {
                    state: "ready",
                    info: None,
                    gateway: None,
                    trusted_by_source: None,
                    cancelled: false,
                }
            });
            let host: Ipv4Addr = host.parse().unwrap();
            let target = probe_target(host, Some(iface));
            let (_cancel, _slot) = backend.begin().unwrap();
            backend
                .finish_start_with_target(
                    Phase::Local,
                    true,
                    Some(iface.into()),
                    Some(31_000),
                    Some(target),
                )
                .unwrap();
            assert_eq!(backend.probe_target_now(), Some(target));
            let observer = backend.observer(fast_schedule(Duration::from_millis(5)));
            let stop = AtomicBool::new(false);
            let mut last_probe = None;
            assert_eq!(
                observer.step(Instant::now(), &mut last_probe, &stop),
                Step::Probed
            );
            assert_eq!(
                *seen.lock().unwrap(),
                Some(ProbeTarget {
                    host,
                    iface: Some(index)
                })
            );
            backend.finish(Phase::Idle);
        }
    }

    #[test]
    fn status_finalization_never_touches_a_newer_helper() {
        let backend = backend();
        let exited = || {
            let mut child = Command::new("/bin/sh")
                .arg("-c")
                .arg("exit 0")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child.wait().unwrap();
            child
        };
        let (old_stream, _old_peer) = UnixStream::pair().unwrap();
        let old = Arc::new(Mutex::new(Helper {
            stream: old_stream,
            launcher: exited(),
        }));
        let (new_stream, mut new_peer) = UnixStream::pair().unwrap();
        let new = Arc::new(Mutex::new(Helper {
            stream: new_stream,
            launcher: exited(),
        }));
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&old));
        backend.was_running.store(true, Ordering::Release);
        let observed_run = backend.run_id.load(Ordering::Acquire);
        // A stop and a new start replace the helper before the old status
        // answer finalizes its run.
        *backend.phase.lock().unwrap() = Phase::Remote(Arc::clone(&new));
        backend.run_id.fetch_add(1, Ordering::AcqRel);
        assert!(!backend.finalize_helper_for_run(observed_run, &new));
        // The current run still rejects a helper that does not own it.
        assert!(!backend.finalize_helper_for_run(backend.run_id.load(Ordering::Acquire), &old));
        // The newer helper got neither a stop request nor a stream close.
        use std::io::Read as _;
        new_peer
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut byte = [0u8; 1];
        let error = new_peer.read(&mut byte).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{error:?}"
        );
        *backend.phase.lock().unwrap() = Phase::Idle;
        backend.was_running.store(false, Ordering::Release);
    }

    #[test]
    fn a_panicked_fallback_clears_the_in_flight_flag() {
        let mut backend = backend();
        backend.probe_attempt = Arc::new(|_paired, _stop, _target| {
            panic!("test fallback panic");
        });
        backend.set_phone_running(true);
        {
            let mut control = backend.observer.lock().unwrap();
            control.state = ObserverState::Failed;
            control.stop = Some(Arc::new(AtomicBool::new(false)));
            control.last_attempt = Some(Instant::now());
            control.retry = Duration::from_secs(3_600);
        }
        assert!(backend.start_fallback_probe_at(Instant::now()));
        let deadline = Instant::now() + Duration::from_secs(2);
        while backend.fallback_active.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "the fallback in-flight flag stayed set after a panic"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(backend.presence.lock().unwrap().state.is_none());
    }

    #[test]
    fn a_late_fallback_result_cannot_contaminate_a_new_run() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let started = Arc::new(Mutex::new(started_tx));
        let release = Arc::new(Mutex::new(release_rx));
        let mut backend = backend();
        backend.probe_attempt = Arc::new(move |_paired, _stop, _target| {
            let _ = started.lock().map(|sender| sender.send(()));
            let _ = release
                .lock()
                .map(|receiver| receiver.recv_timeout(Duration::from_secs(2)));
            ProbeResult {
                state: "ready",
                info: None,
                gateway: None,
                trusted_by_source: None,
                cancelled: false,
            }
        });
        backend.set_phone_running(true);
        {
            let mut control = backend.observer.lock().unwrap();
            control.state = ObserverState::Failed;
            control.stop = Some(Arc::new(AtomicBool::new(false)));
            control.last_attempt = Some(Instant::now());
            control.retry = Duration::from_secs(3_600);
        }
        assert!(backend.start_fallback_probe_at(Instant::now()));
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the fallback probe did not start");
        // A new run starts before the old worker answers.
        let (_cancel, _slot) = backend.begin().unwrap();
        backend
            .finish_start_with_target(Phase::Local, true, None, Some(31_000), None)
            .unwrap();
        backend.presence.lock().unwrap().state = Some("unpaired");
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while backend.fallback_active.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "the fallback probe did not finish"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let presence = backend.presence.lock().unwrap();
        assert_eq!(presence.state, Some("unpaired"));
        assert!(presence.checked.is_none());
        drop(presence);
        backend.finish(Phase::Idle);
    }

    #[test]
    fn a_failed_stop_does_not_record_a_reason() {
        let backend = backend();
        *backend.phase.lock().unwrap() = Phase::Starting {
            cancel: Arc::new(AtomicBool::new(false)),
            socket: Arc::new(Mutex::new(None)),
        };
        assert!(backend
            .stop_until_for(Instant::now(), None, "hotspot_lost")
            .is_err());
        assert!(backend.last_stop.lock().unwrap().is_none());
        *backend.phase.lock().unwrap() = Phase::Stopping;
        assert!(backend
            .stop_until_for(Instant::now(), None, "source_device_gone")
            .is_err());
        assert!(backend.last_stop.lock().unwrap().is_none());
        *backend.phase.lock().unwrap() = Phase::Idle;
    }

    #[test]
    fn a_new_run_clears_the_previous_presence() {
        let backend = backend();
        {
            let mut presence = backend.presence.lock().unwrap();
            presence.state = Some("ready");
            presence.connections = Some(7);
            presence.checked_at = Some(1_000);
            presence.checked = Some(Instant::now());
            presence.trusted_by_source = Some(true);
            presence.last_request = Some(Instant::now());
        }
        let (_cancel, _slot) = backend.begin().unwrap();
        let presence = backend.presence.lock().unwrap();
        assert!(presence.state.is_none());
        assert!(presence.connections.is_none());
        assert!(presence.checked_at.is_none());
        assert!(presence.checked.is_none());
        assert!(presence.trusted_by_source.is_none());
        // The API read time belongs to the page, not to the tunnel run.
        assert!(presence.last_request.is_some());
        drop(presence);
        backend.finish(Phase::Idle);
    }

    fn loopback_iface() -> &'static str {
        if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        }
    }

    #[test]
    fn an_unresolved_pin_is_unknown_and_never_probes_unpinned() {
        let host: Ipv4Addr = "172.20.10.1".parse().unwrap();
        let iface = loopback_iface();
        let index = normalization::interface_index(iface).unwrap();
        // A real name resolves to the exact index.
        assert_eq!(
            probe_target(host, Some(iface)),
            ProbeTarget {
                host,
                iface: Some(index)
            }
        );
        // A missing, empty, or invalid name stays unresolved. The probe must
        // report an unknown pin and must not open an unpinned socket.
        for missing in [None, Some(""), Some("hs-no-such-interface")] {
            let target = probe_target(host, missing);
            assert_eq!(target.iface, None, "{missing:?}");
            let stop = AtomicBool::new(false);
            let result = presence_probe(false, &stop, Some(target));
            assert_eq!(result.state, "pin_unknown");
            assert!(result.info.is_none());
            assert_eq!(result.gateway, Some(host));
            assert!(!result.cancelled);
        }
    }

    #[test]
    fn a_start_uses_the_interface_that_the_service_pinned() {
        // The status names the real pin. The platform default is a different
        // interface, so a cached pre-start default cannot be mistaken for it.
        let status = json!({"running":true,"mode":"phone","iface":"en9",
            "platform":{"default_iface":"en0"}});
        assert_eq!(
            started_status_iface(&status, "phone"),
            Ok(Some("en9".into()))
        );
        // A status for another mode, or one that is not running, is a failed
        // start.
        assert_eq!(
            started_status_iface(&status, "socks5"),
            Err("service_start".into())
        );
        assert_eq!(
            started_status_iface(&json!({"running":false,"mode":null,"iface":null}), "phone"),
            Err("service_start".into())
        );
        // A running status without a name is an unknown pin, not an unpinned
        // run.
        assert_eq!(
            started_status_iface(
                &json!({"running":true,"mode":"phone","iface":null}),
                "phone"
            ),
            Ok(None)
        );
        // The start path stores the status pin, including an unresolvable one.
        let backend = backend();
        let host: Ipv4Addr = "172.20.10.1".parse().unwrap();
        let iface = loopback_iface();
        let index = normalization::interface_index(iface).unwrap();
        let (_cancel, _slot) = backend.begin().unwrap();
        let target = probe_target(host, Some(iface));
        backend
            .finish_start_with_target(
                Phase::Local,
                true,
                Some(iface.into()),
                Some(31_000),
                Some(target),
            )
            .unwrap();
        assert_eq!(
            backend.probe_target_now(),
            Some(ProbeTarget {
                host,
                iface: Some(index)
            })
        );
        assert_eq!(backend.tunnel_iface.lock().unwrap().as_deref(), Some(iface));
        backend.finish(Phase::Idle);
        let (_cancel, _slot) = backend.begin().unwrap();
        let unresolved = probe_target(host, Some("hs-no-such-interface"));
        backend
            .finish_start_with_target(
                Phase::Local,
                true,
                Some("hs-no-such-interface".into()),
                Some(31_000),
                Some(unresolved),
            )
            .unwrap();
        assert_eq!(
            backend.probe_target_now(),
            Some(ProbeTarget { host, iface: None })
        );
        let result = presence_probe(false, &AtomicBool::new(false), backend.probe_target_now());
        assert_eq!(result.state, "pin_unknown");
        backend.finish(Phase::Idle);
    }

    #[test]
    fn a_probe_from_the_starting_window_cannot_enter_the_new_run() {
        let backend = backend();
        let iface = loopback_iface();
        let host: Ipv4Addr = "172.20.10.1".parse().unwrap();
        let (_cancel, _slot) = backend.begin().unwrap();
        let starting_run = backend.run_id.load(Ordering::Acquire);
        // The observer probed during Starting, before the new target existed.
        {
            let mut presence = backend.presence.lock().unwrap();
            presence.state = Some("ready");
            presence.checked_at = Some(1_000);
            presence.checked = Some(Instant::now());
        }
        let target = probe_target(host, Some(iface));
        backend
            .finish_start_with_target(
                Phase::Local,
                true,
                Some(iface.into()),
                Some(31_000),
                Some(target),
            )
            .unwrap();
        assert_ne!(backend.run_id.load(Ordering::Acquire), starting_run);
        // A late answer from the Starting probe still names the old run.
        let late = ProbeResult {
            state: "not_responding",
            info: None,
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        };
        assert!(!record_probe_for_run(
            &backend.presence,
            &backend.pairing,
            &backend.run_id,
            starting_run,
            &late
        ));
        {
            let presence = backend.presence.lock().unwrap();
            assert!(
                presence.state.is_none(),
                "a Starting-window probe leaked into the new run"
            );
            assert!(presence.checked.is_none());
            assert!(presence.checked_at.is_none());
        }
        // A probe for the current run is stored.
        let current = backend.run_id.load(Ordering::Acquire);
        assert!(record_probe_for_run(
            &backend.presence,
            &backend.pairing,
            &backend.run_id,
            current,
            &late
        ));
        assert_eq!(
            backend.presence.lock().unwrap().state,
            Some("not_responding")
        );
        backend.finish(Phase::Idle);
    }

    #[test]
    fn an_old_auto_stop_cannot_stop_a_new_run() {
        let backend = backend();
        let old = backend.monitor_generation();
        let (cancel, _socket) = backend.begin().unwrap();
        let result = backend.stop_for_generation("hotspot_lost", old).unwrap();
        assert_eq!(result["stopped"], false);
        assert!(matches!(
            *backend.phase.lock().unwrap(),
            Phase::Starting { .. }
        ));
        assert!(!cancel.load(Ordering::Acquire));
        assert!(backend.last_stop.lock().unwrap().is_none());
        backend
            .finish_start(Phase::Local, false, None, None)
            .unwrap();
        assert_eq!(backend.stop().unwrap()["stopped"], true);
        assert_eq!(
            backend.last_stop.lock().unwrap().as_ref().unwrap().reason,
            "user"
        );
    }

    #[test]
    fn a_current_auto_stop_stops_the_run_with_its_reason() {
        let backend = backend();
        let (_cancel, _socket) = backend.begin().unwrap();
        backend
            .finish_start(Phase::Local, false, None, None)
            .unwrap();
        let generation = backend.monitor_generation();
        assert_eq!(
            backend
                .stop_for_generation("hotspot_lost", generation)
                .unwrap()["stopped"],
            true
        );
        assert_eq!(
            backend.last_stop.lock().unwrap().as_ref().unwrap().reason,
            "hotspot_lost"
        );
    }

    #[test]
    fn a_late_auto_stop_does_not_relabel_an_inflight_user_stop() {
        let backend = Arc::new(backend());
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut launcher = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = launcher.stdin.take().unwrap();
        let helper = Arc::new(Mutex::new(Helper { stream, launcher }));
        *backend.phase.lock().unwrap() = Phase::Remote(helper);
        backend.was_running.store(true, Ordering::Release);
        let generation = backend.monitor_generation();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let request = privileged::receive(&mut peer).unwrap();
            assert_eq!(request["action"], "stop");
            entered_tx.send(()).unwrap();
            reply_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            privileged::send(&mut peer, &json!({"ok":true})).unwrap();
        });
        let stopping = Arc::clone(&backend);
        let user_stop = std::thread::spawn(move || stopping.stop());
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            backend
                .stop_for_generation("hotspot_lost", generation)
                .unwrap()["stopped"],
            false
        );
        drop(input);
        reply_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(user_stop.join().unwrap().unwrap()["stopped"], true);
        assert_eq!(
            backend.last_stop.lock().unwrap().as_ref().unwrap().reason,
            "user"
        );
    }

    #[test]
    fn a_stale_probe_cannot_change_the_paired_port() {
        let backend = backend();
        let host = Ipv4Addr::new(172, 20, 10, 1);
        backend.pairing.lock().unwrap().credentials = Some(PhoneCredentials {
            host,
            port: 31000,
            token: "test-token".into(),
        });
        let old_run = backend.run_id.load(Ordering::Acquire);
        backend.bump_run();
        let result = ProbeResult {
            state: "ready",
            info: Some(PhoneInfo {
                proxy_running: true,
                foreground: true,
                connections: 1,
                port: 1080,
                host: host.to_string(),
            }),
            gateway: Some(host),
            trusted_by_source: Some(true),
            cancelled: false,
        };
        assert!(!record_probe_for_run(
            &backend.presence,
            &backend.pairing,
            &backend.run_id,
            old_run,
            &result
        ));
        assert_eq!(
            backend
                .pairing
                .lock()
                .unwrap()
                .credentials
                .as_ref()
                .unwrap()
                .port,
            31000
        );
    }

    #[test]
    fn a_panicked_start_returns_the_phase_to_idle() {
        let backend = backend();
        let (cancel, slot) = backend.begin().unwrap();
        {
            let _recovery = StartRecovery {
                backend: &backend,
                cancel: Arc::clone(&cancel),
                socket: Arc::clone(&slot),
                armed: true,
            };
        }
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        assert!(cancel.load(Ordering::Acquire));
        assert!(!backend.was_running.load(Ordering::Acquire));
        assert!(!backend.phone_running.load(Ordering::Acquire));
        assert!(backend.tunnel_phone_port.lock().unwrap().is_none());
        assert!(backend.tunnel_iface.lock().unwrap().is_none());
        assert!(backend.probe_target.lock().unwrap().is_none());
        assert!(backend.presence.lock().unwrap().state.is_none());
    }

    #[test]
    fn a_panicked_stop_restores_the_phase_for_a_retry() {
        let backend = backend();
        *backend.phase.lock().unwrap() = Phase::Local;
        backend.was_running.store(true, Ordering::Release);
        // Simulate the stop path after it published Stopping and bumped the
        // run id, then panicked before it published Idle.
        *backend.phase.lock().unwrap() = Phase::Stopping;
        let stopped_run = backend
            .run_id
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        {
            let _recovery = StopRecovery {
                backend: &backend,
                run: stopped_run,
                original: Some(Phase::Local),
            };
        }
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Local));
        assert_eq!(backend.run_id.load(Ordering::Acquire), stopped_run);
        assert!(backend.was_running.load(Ordering::Acquire));
        // The tunnel stays tracked, so a later stop still works.
        assert_eq!(backend.stop().unwrap()["stopped"], true);
        assert!(matches!(*backend.phase.lock().unwrap(), Phase::Idle));
        assert_eq!(
            backend.last_stop.lock().unwrap().as_ref().unwrap().reason,
            "user"
        );
    }
}
