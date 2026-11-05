//! Connect the local GUI to the Rust service and administrator helper.
use crate::{
    autostop, environment,
    gui::{phone_message, GuiBackend, PROBE_FRESH},
    normalization,
    pairing::{self, Identity, PairError, PairPhase, PairView, PhoneCredentials, PhoneInfo},
    phone::PhoneProxy,
    service::Service,
};
#[cfg(any(target_os = "macos", test))]
use crate::{
    dns, privileged,
    service::{Ipv6Policy, TunOptions},
};
use serde_json::{json, Value};
use std::io;
#[cfg(any(target_os = "macos", test))]
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(any(target_os = "macos", test))]
use std::process::{Child, Command, Stdio};
#[cfg(any(target_os = "macos", test))]
use std::sync::atomic::AtomicU8;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One privileged helper process. Only macOS starts a helper.
#[cfg(any(target_os = "macos", test))]
struct Helper {
    stream: UnixStream,
    launcher: Child,
}

#[cfg(any(target_os = "macos", test))]
fn io_stage(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "helper_timeout",
        _ => "helper_disconnected",
    }
}
#[cfg(any(target_os = "macos", test))]
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
#[cfg(any(target_os = "macos", test))]
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
    let identity = Identity::load_or_create(&Identity::default_path()?)?;
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
            // A new pairing supersedes a pending forget. A later FORGET must
            // not revoke the new trust on the source device.
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

fn run_pairing(
    shared: Arc<Mutex<PairInner>>,
    generation: u64,
    cancel: Arc<AtomicBool>,
    forget: Arc<Mutex<Forget>>,
    attempt: PairAttempt,
) {
    let update = |change: &mut dyn FnMut(&mut PairInner)| {
        if let Ok(mut inner) = shared.lock() {
            if inner.generation == generation {
                change(&mut inner);
            }
        }
    };
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
    trusted_by_source: Option<bool>,
}

/// A token copy that zeroes itself when it goes out of scope.
struct ZeroToken(String);
impl ZeroToken {
    /// Move the token out. The caller must zero it or give it to a type with
    /// its own Drop. The wrapper stays empty and zeroes nothing.
    #[cfg(target_os = "macos")]
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
    let Ok(identity) = Identity::default_path().and_then(|path| Identity::load_or_create(&path))
    else {
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

/// Run one FORGET attempt in the background. A failed attempt stays pending,
/// so the presence probe can retry when the source device is reachable.
fn spawn_forget(forget: Arc<Mutex<Forget>>, network: ForgetNetwork) {
    let generation = match forget.lock() {
        Ok(mut state) if state.pending && !state.in_flight => {
            state.in_flight = true;
            state.generation
        }
        _ => return,
    };
    let worker = Arc::clone(&forget);
    let spawned = std::thread::Builder::new()
        .name("hotspotshade-forget".into())
        .spawn(move || {
            let confirmed = network();
            if let Ok(mut state) = worker.lock() {
                // Clear the in-flight flag for the next generation too. Only
                // this generation may change the attempt count.
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
        });
    if spawned.is_err() {
        if let Ok(mut state) = forget.lock() {
            state.in_flight = false;
        }
    }
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
    let Ok(identity) = Identity::default_path().and_then(|path| Identity::load_or_create(&path))
    else {
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
            Err(_) => ProbeResult {
                state: "not_responding",
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
        Err(PairError::Phone(pairing::PhoneStatus::Rejected)) => ProbeResult {
            state: "not_trusted",
            info: None,
            gateway: Some(host),
            trusted_by_source: None,
            cancelled: false,
        },
        Err(PairError::Cancelled) => ProbeResult::cancelled(),
        Err(_) => ProbeResult {
            state: "not_responding",
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
    presence.state = Some(result.state);
    presence.connections = result.info.as_ref().map(|info| info.connections);
    presence.checked_at = Some(now_unix());
    presence.checked = Some(Instant::now());
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
    /// A privileged helper owns the tunnel. Only macOS starts a helper.
    #[cfg(any(target_os = "macos", test))]
    Remote(Arc<Mutex<Helper>>),
    /// A helper process did not exit after a failed start. Only macOS starts a
    /// helper.
    #[cfg(target_os = "macos")]
    Stuck(Arc<Mutex<Child>>),
    Stopping,
}

/// The phase, port, source host, and pinned interface of one successful start.
type StartOutcome = (Phase, Option<u16>, Option<Ipv4Addr>, Option<String>);

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
        // must not hide the phase recovery.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.backend.service.stop();
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
        #[cfg(any(target_os = "macos", test))]
        let helper = match &original {
            Phase::Remote(helper) => Some(Arc::clone(helper)),
            _ => None,
        };
        if !self.backend.restore_stop_phase(self.run, original) {
            return;
        }
        if local {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.backend.service.stop();
            }));
        }
        #[cfg(any(target_os = "macos", test))]
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
    /// A FORGET that the source device has not confirmed yet.
    forget: Arc<Mutex<Forget>>,
    /// The network FORGET. Tests replace it with a local closure.
    forget_network: ForgetNetwork,
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
    changed: Condvar,
    experimental_icmp: bool,
    experimental_icmp_persistent: bool,
}
impl RustGuiBackend {
    /// The default source device tunnel turns the echo relay on.
    pub fn new(service: Arc<Service>) -> Self {
        Self::with_icmp_options(service, true, true)
    }
    pub fn with_experimental_icmp(service: Arc<Service>, experimental_icmp: bool) -> Self {
        Self::with_icmp_options(service, experimental_icmp, experimental_icmp)
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
            forget: Arc::new(Mutex::new(Forget::default())),
            forget_network: Arc::new(network_forget),
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
            changed: Condvar::new(),
            experimental_icmp,
            experimental_icmp_persistent,
        }
    }

    fn begin(&self) -> Result<HelperSession, String> {
        let mut phase = self.phase.lock().map_err(|_| "service state unavailable")?;
        if !matches!(*phase, Phase::Idle) || self.service.status()["running"] == true {
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
    #[cfg(any(target_os = "macos", test))]
    fn finish(&self, phase_value: Phase) {
        if let Ok(mut phase) = self.phase.lock() {
            *phase = phase_value;
            self.changed.notify_all();
        }
    }
    #[cfg(any(target_os = "macos", test))]
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
    #[cfg(any(target_os = "macos", test))]
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
    #[cfg(any(target_os = "macos", test))]
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
    #[cfg(any(target_os = "macos", test))]
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
    #[cfg(any(target_os = "macos", test))]
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
    fn finish_stop(&self, reason: &'static str) -> Result<(), String> {
        let mut phase = self.phase.lock().map_err(|_| "service state unavailable")?;
        self.clear_tunnel_run();
        self.record_stop(reason);
        self.bump_run();
        *phase = Phase::Idle;
        self.changed.notify_all();
        Ok(())
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
        #[cfg(any(target_os = "macos", test))]
        if !matches!(*phase, Phase::Local | Phase::Remote(_)) {
            return false;
        }
        #[cfg(not(any(target_os = "macos", test)))]
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
    fn with_pairing(&self, mut status: Value) -> Value {
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
        let token = ZeroToken(token);
        let started_port = (!manual).then_some(port);
        #[cfg(target_os = "macos")]
        if unsafe { libc::geteuid() } == 0 {
            let proxy = PhoneProxy {
                address: SocketAddr::V4(SocketAddrV4::new(host, port)),
                username: "hotspotshade".into(),
                token: token.into_inner(),
                iface: None,
                timeout: Duration::from_secs(5),
            };
            let options = TunOptions {
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
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                host,
                port,
                token,
                cancel,
                slot,
                started_port,
                icmp_enabled,
                icmp_persistent,
            );
            Err("administrator helper is available on macOS only".into())
        }
        #[cfg(target_os = "macos")]
        {
            if cancel.load(Ordering::Acquire) {
                return Err("start_cancelled".into());
            }
            let listener = privileged::PrivateListener::create().map_err(|_| "private_listener")?;
            let uid = unsafe { libc::getuid() } as u32;
            if uid == 0 {
                return Err("expected an unprivileged user".into());
            }
            let script = admin_script(listener.path(), uid).map_err(|_| "launcher_start")?;
            if cancel.load(Ordering::Acquire) {
                return Err("start_cancelled".into());
            }
            let mut child = Command::new("/usr/bin/osascript")
                .arg("-e")
                .arg(script)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| "launcher_start")?;
            let diagnostics = Arc::new(AtomicU8::new(0));
            let stderr = child
                .stderr
                .take()
                .map(|stream| watch_stderr(stream, Arc::clone(&diagnostics)));
            let mut connected = false;
            let mut pinned_iface: Option<String> = None;
            let result = (|| -> Result<UnixStream, String> {
                let deadline = Instant::now() + Duration::from_secs(90);
                loop {
                    if cancel.load(Ordering::Acquire) {
                        return Err("start_cancelled".into());
                    }
                    if Instant::now() >= deadline {
                        return Err("authorization_timeout".into());
                    }
                    if child.try_wait().map_err(|_| "launcher_start")?.is_some() {
                        return Err("authorization_cancelled".into());
                    }
                    match listener.accept(0, Duration::from_millis(100)) {
                        Ok(mut stream) => {
                            connected = true;
                            stream
                                .set_read_timeout(Some(Duration::from_secs(20)))
                                .map_err(|_| "helper_connection")?;
                            stream
                                .set_write_timeout(Some(Duration::from_secs(20)))
                                .map_err(|_| "helper_connection")?;
                            *slot.lock().map_err(|_| "helper_connection")? =
                                Some(stream.try_clone().map_err(|_| "helper_connection")?);
                            if cancel.load(Ordering::Acquire) {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                return Err("start_cancelled".into());
                            }
                            let mut request = phone_start_request(
                                host,
                                port,
                                &token.0,
                                icmp_enabled,
                                icmp_persistent,
                            );
                            let sent = privileged::send(&mut stream, &request);
                            zero_request_token(&mut request);
                            sent.map_err(|e| io_stage(&e))?;
                            let response =
                                privileged::receive(&mut stream).map_err(|e| io_stage(&e))?;
                            if response.get("ok") != Some(&Value::Bool(true)) {
                                let code = response
                                    .get("error_code")
                                    .and_then(Value::as_str)
                                    .unwrap_or("service_start");
                                return Err(match code {
                                    "phone_auth" => "phone_auth",
                                    "route_setup" => "route_setup",
                                    "tunnel_setup" => "tunnel_setup",
                                    _ => "service_start",
                                }
                                .into());
                            }
                            // Inspect the helper status, not the pre-start
                            // default route. A helper that answers ok but is not
                            // running the expected mode is a failed start.
                            let status = response.get("status").cloned().unwrap_or(Value::Null);
                            pinned_iface = match started_status_iface(&status, "phone") {
                                Ok(pinned) => pinned,
                                Err(error) => {
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                    return Err(error);
                                }
                            };
                            if cancel.load(Ordering::Acquire) {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                return Err("start_cancelled".into());
                            }
                            return Ok(stream);
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                        Err(_) => return Err("helper_connection".into()),
                    }
                }
            })();
            match result {
                Ok(stream) => {
                    if let Ok(mut s) = slot.lock() {
                        *s = None;
                    }
                    Ok((
                        Phase::Remote(Arc::new(Mutex::new(Helper {
                            stream,
                            launcher: child,
                        }))),
                        started_port,
                        host,
                        pinned_iface,
                    ))
                }
                Err(mut e) => {
                    if let Ok(mut s) = slot.lock() {
                        if let Some(stream) = s.take() {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                        }
                    }
                    let mut exited = false;
                    if !connected {
                        let _ = child.kill();
                        exited = child.wait().is_ok();
                    } else {
                        let deadline = Instant::now() + Duration::from_secs(20);
                        while Instant::now() < deadline {
                            match child.try_wait() {
                                Ok(Some(_)) => {
                                    exited = true;
                                    break;
                                }
                                Err(_) => break,
                                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                            }
                        }
                        if !exited {
                            self.finish(Phase::Stuck(Arc::new(Mutex::new(child))));
                        }
                    }
                    if exited {
                        if let Some(reader) = stderr {
                            let _ = reader.join();
                        }
                        if e == "helper_disconnected" {
                            e = match diagnostics.load(Ordering::Acquire) {
                                3 => "helper_panic",
                                2 => "helper_permission",
                                1 => "helper_error",
                                _ => "helper_disconnected",
                            }
                            .into();
                        }
                    }
                    Err(e)
                }
            }
        }
    }
}
#[cfg(any(target_os = "macos", test))]
fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 4))
        .unwrap_or(2)
}
/// Map a source device start failure to a fixed code. The text is not a
/// secret. The HTTP layer maps `phone_auth` to its own fixed message.
#[cfg(any(target_os = "macos", test))]
fn phone_start_error(error: io::Error) -> String {
    if error.to_string() == "phone_auth" {
        "phone_auth".into()
    } else {
        "source device start failed".into()
    }
}
#[cfg(any(target_os = "macos", test))]
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

/// Zero the token copy inside a start request after the request is sent.
#[cfg(target_os = "macos")]
fn zero_request_token(request: &mut Value) {
    if let Some(Value::String(token)) = request
        .get_mut("phone")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.get_mut(3))
    {
        unsafe {
            for byte in token.as_bytes_mut() {
                std::ptr::write_volatile(byte, 0);
            }
        }
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
#[cfg(any(target_os = "macos", test))]
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
#[cfg(any(target_os = "macos", test))]
fn request(helper: &Arc<Mutex<Helper>>, message: &Value) -> Result<Value, String> {
    let mut helper = helper.lock().map_err(|_| "helper unavailable")?;
    privileged::send(&mut helper.stream, message).map_err(|_| "helper disconnected")?;
    let response = privileged::receive(&mut helper.stream).map_err(|_| "helper disconnected")?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        return Err("helper failed".into());
    }
    Ok(response)
}
#[cfg(any(target_os = "macos", test))]
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
#[cfg(any(target_os = "macos", test))]
const HELPER_FINALIZE: Duration = Duration::from_secs(2);

/// Give one failed helper a bounded stop request, then close its stream.
///
/// This runs without the phase lock. The stream close makes the helper cleanup
/// guard stop the service and remove its routes. It never starts a tunnel.
#[cfg(any(target_os = "macos", test))]
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
#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c.is_control()) {
        return Err("invalid path".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
#[cfg(target_os = "macos")]
fn admin_script(path: &Path, uid: u32) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|_| "cannot find executable")?;
    let exe = exe.to_str().ok_or("invalid executable path")?;
    let path = path.to_str().ok_or("invalid helper path")?;
    let cmd = format!(
        "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin {} --privileged-helper {} {}",
        shell_quote(exe)?,
        shell_quote(path)?,
        uid
    );
    let escaped = cmd.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("with timeout of 604800 seconds\ndo shell script \"{}\" with administrator privileges\nend timeout",escaped))
}

impl GuiBackend for RustGuiBackend {
    fn api_request(&self) {
        if let Ok(mut presence) = self.presence.lock() {
            presence.last_request = Some(Instant::now());
        }
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
        #[cfg(any(target_os = "macos", test))]
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
        #[cfg(not(any(target_os = "macos", test)))]
        let status = self.service.status();
        // A tunnel that stops without a stop request is an error stop. A user
        // stop and an auto stop claim the transition first. A live helper that
        // reports no tunnel gets one final stop before the state is cleared.
        let running = status.get("running") == Some(&json!(true));
        if self.was_running.load(Ordering::Acquire) && !running {
            #[cfg(any(target_os = "macos", test))]
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
        #[cfg(any(target_os = "macos", test))]
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
        #[cfg(any(target_os = "macos", test))]
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
        // A new pairing clears a completed forget state and cancels a pending
        // FORGET. The old FORGET must not revoke the new trust.
        if let Ok(mut forget) = self.forget.lock() {
            forget.clear();
            forget.generation = forget.generation.wrapping_add(1);
        }
        let view = inner.view.to_json();
        drop(inner);
        let shared = Arc::clone(&self.pairing);
        let forget = Arc::clone(&self.forget);
        let attempt = Arc::clone(&self.pair_attempt);
        let spawned = std::thread::Builder::new()
            .name("hotspotshade-pair".into())
            .spawn(move || run_pairing(shared, generation, cancel, forget, attempt));
        if spawned.is_err() {
            if let Ok(mut inner) = self.pairing.lock() {
                inner.cancel = None;
                inner.view = inner.resting_view();
            }
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
        let route = environment::default_route().map_err(|_| "no physical interface")?;
        let index = normalization::interface_index(&route.interface)
            .map_err(|_| "no physical interface")?;
        let proxy = PhoneProxy {
            address: SocketAddr::V4(SocketAddrV4::new(host, port)),
            username: "hotspotshade".into(),
            token,
            iface: Some(index),
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
        let result = (|| -> Result<StartOutcome, String> {
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
                    let dns = match opts.get("dns_servers") {
                        None | Some(Value::Null) => None,
                        Some(Value::Array(items)) => {
                            let mut servers = Vec::new();
                            for item in items {
                                let text =
                                    item.as_str().ok_or("DNS servers must be IP addresses")?;
                                let server = text
                                    .parse::<SocketAddr>()
                                    .or_else(|_| {
                                        text.parse::<Ipv4Addr>()
                                            .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, 53)))
                                    })
                                    .map_err(|_| "DNS servers must be IP addresses")?;
                                servers.push(server);
                            }
                            Some(servers)
                        }
                        _ => return Err("invalid DNS servers".into()),
                    };
                    self.service
                        .start_socks(
                            SocketAddr::V4(SocketAddrV4::new(host, port as u16)),
                            iface,
                            dns,
                        )
                        .map_err(|_| "start failed")?;
                    if cancel.load(Ordering::Acquire) {
                        self.service.stop();
                        return Err("start cancelled".into());
                    }
                    let pinned = match started_status_iface(&self.service.status(), "socks5") {
                        Ok(pinned) => pinned,
                        Err(error) => {
                            self.service.stop();
                            return Err(error);
                        }
                    };
                    Ok((Phase::Local, None, None, pinned))
                }
                "tun" => {
                    #[cfg(target_os = "macos")]
                    {
                        let parsed = tun_options(opts)?;
                        self.service
                            .start_tun_options(parsed, None, worker_count())
                            .map_err(|_| "start failed")?;
                        if cancel.load(Ordering::Acquire) {
                            self.service.stop();
                            return Err("start cancelled".into());
                        }
                        let pinned = match started_status_iface(&self.service.status(), "tun") {
                            Ok(pinned) => pinned,
                            Err(error) => {
                                self.service.stop();
                                return Err(error);
                            }
                        };
                        Ok((Phase::Local, None, None, pinned))
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        Err("tun unavailable".into())
                    }
                }
                _ => Err("invalid mode".into()),
            }
        })();
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
                recovery.disarm();
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
                return Ok(json!({"stopped":false}));
            }
            match &*phase {
                Phase::Idle => {
                    self.forget_tunnel_port();
                    self.forget_tunnel_iface();
                    self.forget_probe_target();
                    self.start_run_cancel();
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
                    finished?;
                    return Ok(json!({"stopped":true}));
                }
                #[cfg(any(target_os = "macos", test))]
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
                    finished?;
                    result?;
                    return Ok(json!({"stopped":true}));
                }
                #[cfg(target_os = "macos")]
                Phase::Stuck(child) => {
                    let child = Arc::clone(child);
                    *phase = Phase::Stopping;
                    let stop_run = self.bump_run();
                    self.cancel_run();
                    drop(phase);
                    let mut recovery = StopRecovery {
                        backend: self,
                        run: stop_run,
                        original: Some(Phase::Stuck(Arc::clone(&child))),
                    };
                    let result = (|| -> Result<(), String> {
                        let mut child = child.lock().map_err(|_| "helper unavailable")?;
                        let until = Instant::now() + Duration::from_secs(20);
                        loop {
                            match child.try_wait() {
                                Ok(Some(_)) => return Ok(()),
                                Err(_) => return Err("helper cleanup failed".into()),
                                Ok(None) if Instant::now() >= until => {
                                    return Err("helper is still stopping".into())
                                }
                                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                            }
                        }
                    })();
                    if result.is_err() {
                        self.finish(Phase::Stuck(child));
                        recovery.disarm();
                        return result.map(|_| json!({"stopped":false}));
                    }
                    let finished = self.finish_stop(reason);
                    if finished.is_ok() {
                        recovery.disarm();
                    }
                    finished?;
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

    fn backend() -> RustGuiBackend {
        RustGuiBackend::new(Arc::new(Service::new()))
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
            phone_start_error(io::Error::other("private detail")),
            "source device start failed"
        );
        assert!(!phone_start_error(io::Error::other("secret-token")).contains("secret-token"));
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
                    "host":"127.0.0.1","port":port,"iface":iface
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
