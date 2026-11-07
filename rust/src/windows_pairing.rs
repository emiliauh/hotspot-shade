//! Pairing state for the Windows engine.
//!
//! The Windows GUI backend pairs with the source device in the same way as
//! the macOS and Linux backend in `gui_backend.rs`: it runs the protocol in
//! `pairing.rs`, holds the proxy credentials in process memory, and reports
//! the pairing state with the same JSON. The token never leaves this module in
//! a status answer, an error text, a log line, or Debug output.
//!
//! The code is portable so the hermetic tests run on every host. Only the
//! Windows backend uses it in a production build. The network steps are
//! injected: the backend passes a pairing attempt and a FORGET attempt that
//! discover the hotspot gateway and run the Windows token gate first. A test
//! passes closures that talk to a loopback mock source device.
//!
//! The rules match the macOS and Linux backend:
//!
//! - One pairing runs at a time. A second start returns `pair_busy`.
//! - The pairing target is the discovered gateway, never a host from the
//!   client. The backend attempt closure owns that discovery.
//! - A successful pairing replaces the stored credentials. A failed or
//!   cancelled pairing keeps the old credentials.
//! - Forget clears the credentials at once and sends a best-effort FORGET up
//!   to three times. Protocol v1 cannot prove remote deletion, so a FORGET
//!   that no source device confirms ends as `not_delivered`.
//! - A new pairing waits for an in-flight FORGET to finish, so the old request
//!   cannot reach the source device after the new pairing.
//! - The caller refuses forget while a tunnel runs or starts.

use crate::pairing::{self, Identity, PairError, PairPhase, PairView, PhoneCredentials, PhoneInfo};
use serde_json::{json, Value};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One pairing attempt. The backend discovers the gateway and runs the token
/// gate inside it. Tests pass a closure that pairs with a loopback mock.
pub(crate) type PairAttempt = Arc<
    dyn Fn(Arc<AtomicBool>, &mut dyn FnMut(&str)) -> Result<PhoneCredentials, PairError>
        + Send
        + Sync,
>;

/// One best-effort FORGET over the network. True means the source device
/// confirmed it. Protocol v1 has no proof of remote deletion, so the live
/// attempt returns false.
pub(crate) type ForgetNetwork = Arc<dyn Fn() -> bool + Send + Sync>;

/// The maximum number of best-effort FORGET requests after one forget.
pub(crate) const MAX_FORGET_TRIES: u8 = 3;

/// The longest time a new pairing waits for an old FORGET network attempt.
/// A FORGET connect and its exchange each have a 2 second bound, and the gate
/// reads add a little more.
pub(crate) const FORGET_DRAIN_LIMIT: Duration = Duration::from_secs(5);

/// The fixed pairing text when an old FORGET is still in flight.
pub(crate) const FORGET_DRAIN_ERROR: &str = "The previous forget is still running. Try again.";

/// Pairing state. The credentials stay in process memory only.
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
            Some(credentials) => PairView {
                phase: PairPhase::Paired,
                host: Some(credentials.host),
                port: Some(credentials.port),
                ..PairView::default()
            },
            None => PairView::default(),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum ForgetOutcome {
    #[default]
    None,
    Confirmed,
    NotDelivered,
}

/// A best-effort FORGET that the source device has not confirmed yet.
#[derive(Default)]
struct Forget {
    pending: bool,
    in_flight: bool,
    attempts: u8,
    generation: u64,
    outcome: ForgetOutcome,
}

impl Forget {
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

/// The pairing controller of one Windows engine.
pub(crate) struct Pairing {
    inner: Arc<Mutex<PairInner>>,
    forget: Arc<Mutex<Forget>>,
    attempt: PairAttempt,
    forget_network: ForgetNetwork,
    forget_drain: Duration,
}

impl Pairing {
    pub(crate) fn new(attempt: PairAttempt, forget_network: ForgetNetwork) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PairInner::default())),
            forget: Arc::new(Mutex::new(Forget::default())),
            attempt,
            forget_network,
            forget_drain: FORGET_DRAIN_LIMIT,
        }
    }

    /// Install credentials that an elevated engine imported from the pairing
    /// handoff. The view becomes `paired`.
    pub(crate) fn import(&self, credentials: PhoneCredentials) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.credentials = Some(credentials);
            inner.view = inner.resting_view();
        }
    }

    /// Start a pairing in the background. `closing` refuses a start after the
    /// server began shutdown.
    pub(crate) fn start(&self, closing: bool) -> Result<Value, String> {
        if closing {
            return Err("service is stopping".into());
        }
        let mut inner = self.inner.lock().map_err(|_| "pair_state")?;
        if inner.cancel.is_some() {
            return Err("pair_busy".into());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        inner.generation = inner.generation.wrapping_add(1);
        let generation = inner.generation;
        inner.cancel = Some(Arc::clone(&cancel));
        inner.view = PairView {
            phase: PairPhase::Connecting,
            ..PairView::default()
        };
        // A new pairing clears a completed forget state and a pending retry
        // with no request in flight. A request in flight stays pending: the
        // pairing thread waits for it before it sends its own exchange.
        if let Ok(mut forget) = self.forget.lock() {
            if !forget.in_flight {
                forget.clear();
                forget.generation = forget.generation.wrapping_add(1);
            }
        }
        let view = inner.view.to_json();
        drop(inner);
        let shared = Arc::clone(&self.inner);
        let forget = Arc::clone(&self.forget);
        let attempt = Arc::clone(&self.attempt);
        let drain = self.forget_drain;
        let spawned = std::thread::Builder::new()
            .name("hotspotshade-pair".into())
            .spawn(move || run_pairing(shared, generation, cancel, forget, attempt, drain));
        if spawned.is_err() {
            if let Ok(mut inner) = self.inner.lock() {
                if inner.generation == generation {
                    inner.cancel = None;
                    inner.view = inner.resting_view();
                }
            }
            return Err("pair_start".into());
        }
        Ok(view)
    }

    /// The pairing view. It holds the code during the confirmation and never
    /// the token.
    pub(crate) fn status(&self) -> Result<Value, String> {
        let inner = self.inner.lock().map_err(|_| "pair_state")?;
        Ok(inner.view.to_json())
    }

    /// Cancel a pairing in progress. A completed pairing is not changed.
    pub(crate) fn cancel(&self) -> Result<Value, String> {
        let mut inner = self.inner.lock().map_err(|_| "pair_state")?;
        if let Some(cancel) = inner.cancel.take() {
            cancel.store(true, Ordering::Release);
            inner.generation = inner.generation.wrapping_add(1);
            inner.view = inner.resting_view();
        }
        Ok(inner.view.to_json())
    }

    /// Cancel a pairing in progress during shutdown.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn close(&self) {
        let _ = self.cancel();
    }

    /// Forget the pairing. The caller holds its start lock and passes whether
    /// a tunnel runs; a running tunnel keeps the token and refuses forget.
    pub(crate) fn forget(&self, tunnel_running: bool) -> Result<Value, String> {
        if tunnel_running {
            return Err("tunnel_running".into());
        }
        let mut inner = self.inner.lock().map_err(|_| "pair_state")?;
        if let Some(cancel) = inner.cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        inner.generation = inner.generation.wrapping_add(1);
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
        self.retry_forget();
        Ok(json!({"ok": true}))
    }

    /// Start one FORGET attempt when a forget is pending and none is in
    /// flight. The presence probe calls this, so an unreachable source device
    /// gets up to [`MAX_FORGET_TRIES`] attempts.
    pub(crate) fn retry_forget(&self) {
        let generation = match self.forget.lock() {
            Ok(mut state) if state.should_retry() => {
                state.in_flight = true;
                state.generation
            }
            _ => return,
        };
        let worker = Arc::clone(&self.forget);
        let network = Arc::clone(&self.forget_network);
        let spawned = std::thread::Builder::new()
            .name("hotspotshade-forget".into())
            .spawn(move || {
                let confirmed = network();
                finish_forget_attempt(&worker, generation, confirmed);
            });
        if spawned.is_err() {
            if let Ok(mut state) = self.forget.lock() {
                state.in_flight = false;
                if state.generation == generation {
                    state.pending = false;
                    state.outcome = ForgetOutcome::NotDelivered;
                }
            }
        }
    }

    /// The forget state and attempt count for `GET /api/status`.
    pub(crate) fn forget_state(&self) -> (&'static str, u8) {
        self.forget
            .lock()
            .map(|state| (state.state(), state.attempts))
            .unwrap_or(("none", 0))
    }

    /// A copy of the stored credentials for a start or a handoff. The copy
    /// clears its token when it drops.
    pub(crate) fn credentials(&self) -> Option<PhoneCredentials> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.credentials.clone())
    }

    /// True when credentials are stored.
    pub(crate) fn paired(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.credentials.is_some())
            .unwrap_or(false)
    }

    /// The stored host and port without the token, for the status answer.
    pub(crate) fn endpoint(&self) -> Option<(std::net::Ipv4Addr, u16)> {
        self.inner.lock().ok().and_then(|inner| {
            inner
                .credentials
                .as_ref()
                .map(|credentials| (credentials.host, credentials.port))
        })
    }

    /// Apply one authenticated status answer to the stored port.
    pub(crate) fn learn(
        &self,
        gateway: std::net::Ipv4Addr,
        info: &PhoneInfo,
    ) -> pairing::PortUpdate {
        let Ok(mut inner) = self.inner.lock() else {
            return pairing::PortUpdate::Rejected;
        };
        let (update, port) = match inner.credentials.as_mut() {
            Some(credentials) => (
                pairing::learn_phone_info(credentials, gateway, info),
                Some(credentials.port),
            ),
            None => (pairing::PortUpdate::Rejected, None),
        };
        if inner.view.phase == PairPhase::Paired {
            if let Some(port) = port {
                inner.view.port = Some(port);
            }
        }
        update
    }
}

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

/// Wait until no FORGET attempt is in flight. Return false on timeout, a
/// poisoned lock, or a cancel request. The wait never cancels the network
/// attempt, because a cancel flag cannot retract bytes already sent.
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
    // pairing still owns the state and was not cancelled. The pairing lock is
    // held across the check and the clear.
    {
        let Ok(inner) = shared.lock() else {
            return;
        };
        if inner.generation != generation || cancel.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut state) = forget.lock() else {
            return;
        };
        state.clear();
        state.generation = state.generation.wrapping_add(1);
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
    update(&mut |inner| {
        inner.cancel = None;
        match &result {
            Ok(credentials) => {
                inner.credentials = Some(credentials.clone());
                inner.view = inner.resting_view();
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
    });
}

/// The state that the target app shows. It is the macOS and Linux mapping:
/// while a source device tunnel runs, `ready` shows as `connected`, and a run
/// with no probe yet shows `connected`. A stale probe during a run shows
/// `checking`, because an old answer is not proof that the source device is
/// gone. There is no static unavailable state: the token gate runs at each
/// token use, and a refusal shows as `no_hotspot`.
pub(crate) fn phone_state(
    observed: Option<&'static str>,
    running_phone: bool,
    fresh: bool,
) -> &'static str {
    match observed {
        Some(_) if running_phone && !fresh => "checking",
        Some("ready") if running_phone => "connected",
        Some(state) => state,
        None if running_phone => "connected",
        None => "not_responding",
    }
}

/// One presence answer from the pairing listener. The state is fixed text.
/// `info` is present only after the authenticated STATUS exchange.
#[derive(Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct ListenerAnswer {
    pub state: &'static str,
    pub info: Option<PhoneInfo>,
    /// The CHALLENGE `known` byte from an unpaired probe. A plaintext claim,
    /// not proof.
    pub trusted_by_source: Option<bool>,
}

/// The presence state for a failed probe connect. A refused connection says
/// that the listener is not available. Every other error says only that the
/// probe did not finish.
fn connect_error_state(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "not_running",
        _ => "not_responding",
    }
}

/// The presence state for a status exchange that ended with an error. The
/// mapping is the macOS and Linux mapping: plaintext answers are unverified.
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

/// Probe the pairing listener once over a normalized outer socket pinned to
/// `iface`. The interface is not optional: every egress socket carries the
/// physical pin, so no caller can open an unpinned probe. The probe sends no
/// proxy token. It is bounded: 2 seconds for the connection and 2 seconds for
/// the exchange. Return None when `cancel` stopped the probe; a cancelled
/// probe is not an answer.
pub(crate) fn probe_listener(
    address: SocketAddr,
    iface: u32,
    paired: bool,
    identity: &Identity,
    cancel: &AtomicBool,
) -> Option<ListenerAnswer> {
    let answer = |state| ListenerAnswer {
        state,
        info: None,
        trusted_by_source: None,
    };
    let audit = crate::normalization::Audit::default();
    if let Err(error) = crate::normalization::tcp_connect_cancellable(
        address,
        Some(iface),
        &audit,
        Duration::from_secs(2),
        Some(cancel),
    ) {
        if error.kind() == io::ErrorKind::Interrupted {
            return None;
        }
        return Some(answer(connect_error_state(&error)));
    }
    if !paired {
        return match pairing::probe_unpaired_at(address, identity, Some(iface), &audit, cancel) {
            Ok(trusted) => Some(ListenerAnswer {
                state: "unpaired",
                info: None,
                trusted_by_source: trusted,
            }),
            Err(PairError::Cancelled) => None,
            Err(error) => Some(answer(status_failure_state(&error, false))),
        };
    }
    match pairing::status_at(address, identity, Some(iface), &audit, cancel) {
        Ok(info) => Some(ListenerAnswer {
            state: if info.proxy_running {
                "ready"
            } else {
                "proxy_off"
            },
            info: Some(info),
            trusted_by_source: None,
        }),
        Err(PairError::Cancelled) => None,
        Err(error) => Some(answer(status_failure_state(&error, true))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::tests::{spawn_phone, Decide, MockPhone};
    use crate::pairing::{pair_at, PairTimeouts};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::AtomicUsize;

    fn identity() -> Identity {
        Identity::from_bytes([0x5a; 32])
    }

    fn timeouts() -> PairTimeouts {
        PairTimeouts {
            connect: Duration::from_secs(2),
            challenge: Duration::from_secs(2),
            result: Duration::from_secs(2),
        }
    }

    /// A pairing attempt against one loopback mock source device.
    fn mock_attempt(address: SocketAddr) -> PairAttempt {
        Arc::new(move |cancel, on_code| {
            pair_at(
                address,
                &identity(),
                None,
                &crate::normalization::Audit::default(),
                &cancel,
                timeouts(),
                |code| on_code(code),
            )
        })
    }

    fn no_forget() -> ForgetNetwork {
        Arc::new(|| false)
    }

    fn wait_state(pairing: &Pairing, done: &[&str]) -> Value {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let view = pairing.status().unwrap();
            if done.contains(&view["state"].as_str().unwrap_or("")) {
                return view;
            }
            assert!(Instant::now() < end, "pairing did not finish: {view}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_forget(pairing: &Pairing, state: &str) {
        let end = Instant::now() + Duration::from_secs(5);
        while pairing.forget_state().0 != state {
            assert!(
                Instant::now() < end,
                "forget state {:?}",
                pairing.forget_state()
            );
            pairing.retry_forget();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn pairing_with_the_mock_source_device_stores_credentials_without_showing_the_token() {
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 1);
        let pairing = Pairing::new(mock_attempt(address), no_forget());
        let started = pairing.start(false).unwrap();
        assert_eq!(started["state"], "connecting");
        let view = wait_state(&pairing, &["paired", "failed"]);
        handle.join().unwrap();
        assert_eq!(view["state"], "paired");
        assert!(pairing.paired());
        let credentials = pairing.credentials().unwrap();
        assert!(!credentials.token.is_empty());
        let text = view.to_string();
        assert!(!text.contains(&credentials.token));
        assert_eq!(view["host"], credentials.host.to_string());
        assert_eq!(view["port"], credentials.port);
        assert!(!format!("{credentials:?}").contains(&credentials.token));
    }

    #[test]
    fn a_denied_pairing_fails_and_keeps_the_old_credentials() {
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 1);
        let pairing = Pairing::new(mock_attempt(address), no_forget());
        pairing.start(false).unwrap();
        wait_state(&pairing, &["paired"]);
        handle.join().unwrap();
        let before = pairing.credentials().unwrap();

        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Deny)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 1);
        let pairing_again = Pairing {
            attempt: mock_attempt(address),
            ..pairing
        };
        pairing_again.start(false).unwrap();
        let view = wait_state(&pairing_again, &["failed", "paired"]);
        handle.join().unwrap();
        assert_eq!(view["state"], "failed");
        assert_eq!(
            view["error"],
            PairError::Phone(pairing::PhoneStatus::Denied).message()
        );
        assert_eq!(pairing_again.credentials(), Some(before));
    }

    #[test]
    fn a_second_start_is_busy_and_cancel_restores_the_resting_view() {
        let release = Arc::new(AtomicBool::new(false));
        let gate = Arc::clone(&release);
        let attempt: PairAttempt = Arc::new(move |cancel, on_code| {
            on_code("123 456");
            while !cancel.load(Ordering::Acquire) && !gate.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(PairError::Cancelled)
        });
        let pairing = Pairing::new(attempt, no_forget());
        pairing.start(false).unwrap();
        let view = wait_state(&pairing, &["confirm"]);
        assert_eq!(view["code"], "123 456");
        assert_eq!(pairing.start(false).unwrap_err(), "pair_busy");
        let view = pairing.cancel().unwrap();
        assert_eq!(view["state"], "idle");
        assert!(view["code"].is_null());
        // A late result from the cancelled thread changes nothing.
        release.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(pairing.status().unwrap()["state"], "idle");
        assert!(pairing.start(true).is_err(), "closing refuses a start");
    }

    #[test]
    fn forget_is_refused_while_a_tunnel_runs() {
        let pairing = Pairing::new(Arc::new(|_, _| Err(PairError::NoPhone)), no_forget());
        pairing.import(PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 31000,
            token: "public-test-token".into(),
        });
        assert_eq!(pairing.forget(true).unwrap_err(), "tunnel_running");
        assert!(pairing.paired());
        assert_eq!(pairing.forget_state(), ("none", 0));
    }

    #[test]
    fn forget_clears_the_credentials_and_retries_at_most_three_times() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let pairing = Pairing::new(
            Arc::new(|_, _| Err(PairError::NoPhone)),
            Arc::new(move || {
                counter.fetch_add(1, Ordering::AcqRel);
                false
            }),
        );
        pairing.import(PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 31000,
            token: "public-test-token".into(),
        });
        assert_eq!(pairing.status().unwrap()["state"], "paired");
        pairing.forget(false).unwrap();
        assert!(!pairing.paired());
        assert_eq!(pairing.status().unwrap()["state"], "idle");
        wait_forget(&pairing, "not_delivered");
        assert_eq!(calls.load(Ordering::Acquire), MAX_FORGET_TRIES as usize);
        assert_eq!(pairing.forget_state(), ("not_delivered", MAX_FORGET_TRIES));
        pairing.retry_forget();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(calls.load(Ordering::Acquire), MAX_FORGET_TRIES as usize);
    }

    #[test]
    fn a_confirmed_forget_ends_the_retries() {
        let pairing = Pairing::new(Arc::new(|_, _| Err(PairError::NoPhone)), Arc::new(|| true));
        pairing.forget(false).unwrap();
        wait_forget(&pairing, "confirmed");
        assert_eq!(pairing.forget_state(), ("confirmed", 1));
    }

    #[test]
    fn a_new_pairing_clears_a_finished_forget_state() {
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 1);
        let pairing = Pairing::new(mock_attempt(address), no_forget());
        pairing.forget(false).unwrap();
        wait_forget(&pairing, "not_delivered");
        pairing.start(false).unwrap();
        wait_state(&pairing, &["paired"]);
        handle.join().unwrap();
        assert_eq!(pairing.forget_state().0, "none");
    }

    #[test]
    fn learning_a_port_needs_the_gateway_and_updates_the_paired_view() {
        let pairing = Pairing::new(Arc::new(|_, _| Err(PairError::NoPhone)), no_forget());
        let gateway = Ipv4Addr::new(172, 20, 10, 1);
        pairing.import(PhoneCredentials {
            host: gateway,
            port: 31000,
            token: "public-test-token".into(),
        });
        let info = |host: &str, port| PhoneInfo {
            proxy_running: true,
            foreground: true,
            connections: 1,
            port,
            host: host.into(),
        };
        assert_eq!(
            pairing.learn(gateway, &info("172.20.10.1", 32000)),
            pairing::PortUpdate::PortChanged {
                old: 31000,
                new: 32000
            }
        );
        assert_eq!(pairing.status().unwrap()["port"], 32000);
        assert_eq!(
            pairing.learn(gateway, &info("172.20.10.9", 33000)),
            pairing::PortUpdate::Rejected
        );
        assert_eq!(pairing.endpoint(), Some((gateway, 32000)));
    }

    #[test]
    fn the_status_state_follows_the_macos_mapping_without_an_unavailable_state() {
        assert_eq!(phone_state(None, false, false), "not_responding");
        assert_eq!(phone_state(Some("unpaired"), false, true), "unpaired");
        assert_eq!(phone_state(Some("no_hotspot"), false, true), "no_hotspot");
        assert_eq!(phone_state(None, true, false), "connected");
        assert_eq!(phone_state(Some("ready"), true, true), "connected");
        assert_eq!(phone_state(Some("ready"), true, false), "checking");
        assert_eq!(phone_state(Some("not_trusted"), true, true), "not_trusted");
        for observed in [None, Some("ready"), Some("no_hotspot")] {
            for running in [false, true] {
                assert_ne!(
                    phone_state(observed, running, true),
                    "source_proxy_unavailable"
                );
            }
        }
    }

    fn loopback_iface() -> u32 {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        crate::normalization::interface_index(name).unwrap()
    }

    fn probe(address: SocketAddr, paired: bool) -> ListenerAnswer {
        probe_listener(
            address,
            loopback_iface(),
            paired,
            &identity(),
            &AtomicBool::new(false),
        )
        .unwrap()
    }

    #[test]
    fn the_listener_probe_maps_unpaired_not_trusted_ready_and_proxy_off() {
        let public = identity().public();
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().answer_status(true, 7, 31000);
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        let answer = probe(address, false);
        assert_eq!(answer.state, "unpaired");
        assert!(answer.info.is_none());
        handle.join().unwrap();

        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().answer_status(true, 7, 31000);
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        assert_eq!(probe(address, true).state, "not_trusted");
        handle.join().unwrap();

        for (running, expected) in [(true, "ready"), (false, "proxy_off")] {
            let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
            {
                let mut phone = phone.lock().unwrap();
                phone.trust(public);
                phone.answer_status(running, 4, 31000);
            }
            let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
            let answer = probe(address, true);
            assert_eq!(answer.state, expected);
            assert_eq!(answer.info.unwrap().port, 31000);
            handle.join().unwrap();
        }
    }

    #[test]
    fn the_listener_probe_reports_a_closed_listener_and_a_cancel() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(probe(address, false).state, "not_running");
        assert_eq!(probe(address, true).state, "not_running");
        let cancelled = AtomicBool::new(true);
        assert!(probe_listener(address, loopback_iface(), true, &identity(), &cancelled).is_none());
    }
}
