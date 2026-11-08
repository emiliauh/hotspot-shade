//! Connect the Windows GUI to the real Rust service.
//!
//! The backend serves the same HTTP API and JSON as the macOS and Linux
//! backend, so one front end can use both. It pairs with the source device
//! through `pairing.rs` (`POST /api/phone/pair`, `GET /api/phone/pair`,
//! `POST /api/phone/pair/cancel`, `POST /api/phone/forget`), reports `paired`
//! and `phone.trusted_by_source` in `GET /api/status`, and writes the pairing
//! handoff to an elevated engine (`POST /api/pairing/handoff`). The manual
//! address and token fields stay as a fallback.
//!
//! The service holds the credentials in memory and never sends them back. No
//! status, log, error text, or Debug output holds the token or the identity
//! key. The pairing target is the discovered hotspot gateway, never a host
//! from the client.
//!
//! Every token use runs the Windows token gate first. The service runs it in
//! the start check right before the token leaves the process, and records the
//! run binding: the tunnel adapter, the physical adapter that the gate
//! proved, the destination, and the pinned index. The backend runs it before
//! every presence probe and every manual check. Pairing, FORGET, and the
//! pairing listener probe send no token, and they still run the gate so that
//! they reach only the proven gateway. During a run the presence probe runs
//! the gate for the run's own binding, and the first refusal stops the
//! tunnel with the reason `hotspot_lost`, because the relay keeps using the
//! token for new flows. New flows between two probes, at most one probe
//! period, use the destination and pin that the last gate proved.
//!
//! The gate does not authenticate the source device. Any device at the
//! gateway address can accept the v1 token, and the token crosses the hotspot
//! link in cleartext. Direct mode and SOCKS5 mode are not implemented on
//! Windows.
use crate::gui::{
    apply_last_stop, phone_message, presence_probe, GuiBackend, RunPresence, RunStartError, RunStop,
};
use crate::windows_pairing::{self, ForgetNetwork, PairAttempt, Pairing};
use crate::windows_route_verify::TOKEN_DESTINATION_REFUSED;
use crate::{
    normalization::{self, Audit},
    pairing::{self, Identity, PairError, PhoneCredentials, PAIRING_PORT},
    phone::PhoneProxy,
    service::{Ipv6Policy, Service, TunOptions},
};
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// One overall deadline for each source device check. `check_cancellable`
/// applies it to the connect, the method answer, and the authentication answer
/// together. A per-operation timeout could need several times this value and
/// leave the stored result stale between probes, which resets the silence
/// timer on every gap.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

const _: () = assert!(crate::gui::probe_cadence_fits(
    PROBE_INTERVAL,
    PROBE_TIMEOUT
));

/// The longest time a request waits for one pairing handoff write. A pipe
/// write blocks while the pipe buffer is full. One write may stay blocked in
/// its own thread; a later handoff is refused until it finishes.
const HANDOFF_WRITE_LIMIT: Duration = Duration::from_secs(2);

/// A source device that a person typed into the manual fields.
#[derive(Clone)]
struct ManualTarget {
    host: Ipv4Addr,
    port: u16,
    token: Zeroizing<String>,
    iface: u32,
}

/// The source device of the running tunnel. A paired run keeps no token here,
/// because its presence probe uses the authenticated pairing STATUS. A manual
/// run keeps the token for its SOCKS presence check. `run` is the run id that
/// the start published; a probe from another run does not use this target.
#[derive(Clone)]
struct RunTarget {
    run: u64,
    host: Ipv4Addr,
    port: u16,
    paired: bool,
    token: Option<Zeroizing<String>>,
}

/// Probe details that only the current run may show.
#[derive(Clone, Copy, Default)]
struct ProbeExtra {
    run: u64,
    connections: Option<u16>,
    trusted_by_source: Option<bool>,
}

/// State that the request threads, the presence thread, and the pairing
/// threads share.
struct Shared {
    service: Arc<Service>,
    manual: Mutex<Option<ManualTarget>>,
    run_target: Mutex<Option<RunTarget>>,
    pairing: Pairing,
    /// Run-scoped probe results. Its run id scopes automatic stops.
    presence: RunPresence,
    extra: Mutex<ProbeExtra>,
    last_stop: Mutex<Option<(&'static str, u64)>>,
    /// The last presence discovery failure, as a fixed-vocabulary string. It
    /// holds no address, interface name or index, GUID, LUID, MAC, or token.
    /// It is cleared when a discovery succeeds.
    presence_failure: Mutex<Option<String>>,
    /// Set once when the HTTP server begins shutdown. It cancels a probe or a
    /// start in progress and refuses a later start.
    closing: AtomicBool,
}

/// The real Windows backend. The service owns the tunnel and the credentials.
pub struct WindowsGuiBackend {
    shared: Arc<Shared>,
    /// Held for a whole start. Forget refuses while it is held, so a start
    /// cannot use credentials that a forget removes.
    start_lock: Mutex<()>,
    wintun_dll: Option<std::path::PathBuf>,
    /// The write end of the pairing handoff pipe, in the standard-user engine.
    handoff: Option<Arc<crate::windows_credential_handoff::HandoffHandle>>,
    /// True while one handoff write runs. A blocked write keeps it set.
    handoff_busy: Arc<AtomicBool>,
    /// The identity bytes that a handoff carries, read once at launch.
    handoff_identity: Mutex<Option<Zeroizing<[u8; 32]>>>,
    /// The time of the last API probe. It enforces the 500 ms rate limit.
    probe_gate: Mutex<Option<Instant>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn probe_fresh(checked_at: u64, now: u64) -> bool {
    checked_at <= now && now - checked_at <= crate::gui::PROBE_FRESH.as_secs()
}

/// Confirm that a source device address is the gateway on the physical
/// hotspot interface. The browser must not be able to aim the engine at an
/// arbitrary host.
fn gateway_target_matches(
    host: Ipv4Addr,
    requested_iface: Option<u32>,
    gateway: Ipv4Addr,
    gateway_iface: u32,
) -> bool {
    host == gateway && requested_iface.is_none_or(|iface| iface == gateway_iface)
}

fn is_private_gateway(gateway: Ipv4Addr) -> bool {
    gateway.is_private()
}

/// A gateway discovery failure. `message` is the fixed user-facing code and
/// `reason` is the fixed-vocabulary diagnostic detail, which holds no address
/// or interface identity.
struct GatewayError {
    message: &'static str,
    reason: String,
}

impl From<GatewayError> for String {
    fn from(error: GatewayError) -> Self {
        error.message.to_string()
    }
}

/// Return the physical default gateway and its interface index. This is the
/// unscoped default route, so it works only while no tunnel runs.
fn hotspot_gateway() -> Result<(Ipv4Addr, u32), GatewayError> {
    let (gateway, index) =
        crate::windows_route_verify::default_ipv4_gateway().map_err(|error| GatewayError {
            message: "no physical hotspot gateway",
            reason: format!("gateway: {}", error.presence_kind()),
        })?;
    // A hotspot gateway is always a private address. A public default
    // gateway is a local network, not a source device.
    if !is_private_gateway(gateway) {
        return Err(GatewayError {
            message: "no private hotspot gateway",
            reason: "gateway: not_private".to_string(),
        });
    }
    let name = normalization::interface_name(index).map_err(|_| GatewayError {
        message: "no physical hotspot interface",
        reason: "gateway: interface_name_unavailable".to_string(),
    })?;
    if name.starts_with("HotspotShade-Tunnel") {
        return Err(GatewayError {
            message: "no physical hotspot gateway",
            reason: "gateway: tunnel_interface".to_string(),
        });
    }
    Ok((gateway, index))
}

fn require_gateway_target(host: Ipv4Addr, requested_iface: Option<u32>) -> Result<u32, String> {
    let (gateway, gateway_iface) = hotspot_gateway()?;
    if !gateway_target_matches(host, requested_iface, gateway, gateway_iface) {
        return Err("source device must be the hotspot gateway".into());
    }
    Ok(gateway_iface)
}

fn parse_target(options: &Value) -> Result<ManualTarget, String> {
    let host = options
        .get("host")
        .and_then(Value::as_str)
        .ok_or("invalid source device host")?
        .parse::<Ipv4Addr>()
        .map_err(|_| "invalid source device host")?;
    if host.is_unspecified() || host.is_multicast() || host.is_broadcast() || host.is_loopback() {
        return Err("invalid source device host".into());
    }
    let port = options
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= 65535)
        .ok_or("invalid source device port")? as u16;
    let token = options
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty() && token.len() <= 255)
        .ok_or("manual_phone")?;
    let requested_iface = match options.get("iface").and_then(Value::as_str) {
        Some(name) if !name.is_empty() => {
            Some(normalization::interface_index(name).map_err(|_| "invalid hotspot interface")?)
        }
        _ => None,
    };
    let iface = require_gateway_target(host, requested_iface)?;
    Ok(ManualTarget {
        host,
        port,
        token: Zeroizing::new(token.to_owned()),
        iface,
    })
}

fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(2)
        .clamp(1, 4)
}

fn start_error(error: io::Error) -> String {
    let message = error.to_string();
    match message.as_str() {
        "phone_auth" | "route_setup" | "tunnel_setup" | "service_start" => message,
        _ if message == TOKEN_DESTINATION_REFUSED => message,
        _ => match error.kind() {
            io::ErrorKind::NotFound if message.contains("wintun.dll") => "wintun_missing".into(),
            io::ErrorKind::PermissionDenied => "admin_required".into(),
            io::ErrorKind::Unsupported => "windows_phone_only".into(),
            io::ErrorKind::Interrupted => "start_cancelled".into(),
            _ => "service_start".into(),
        },
    }
}

fn proxy(host: Ipv4Addr, port: u16, token: &str, iface: u32) -> PhoneProxy {
    PhoneProxy {
        address: SocketAddr::V4(SocketAddrV4::new(host, port)),
        username: "hotspotshade".into(),
        token: token.to_owned(),
        iface: Some(iface),
        timeout: PROBE_TIMEOUT,
    }
}

/// A token gate failure. `message` is the fixed `source_gateway_unproven` code
/// and `reason` is the fixed-vocabulary diagnostic detail, which holds no
/// address or interface identity.
struct TokenGateError {
    message: &'static str,
    reason: String,
}

impl From<TokenGateError> for String {
    fn from(error: TokenGateError) -> Self {
        error.message.to_string()
    }
}

/// Run the token gate for one destination and pinned interface. The service
/// chooses the run binding while a tunnel runs. The error carries the fixed
/// `source_gateway_unproven` code and, for diagnostics, a fixed-vocabulary
/// reason that names the physical path failure without any address or
/// identity.
fn token_gate(
    service: &Service,
    destination: SocketAddrV4,
    iface: u32,
) -> Result<(), TokenGateError> {
    let run = if service.is_running() {
        Some(
            service
                .windows_phone_run()
                .map(|current| current.run)
                .ok_or_else(|| TokenGateError {
                    message: TOKEN_DESTINATION_REFUSED,
                    reason: "token_gate: no run binding".to_string(),
                })?,
        )
    } else {
        None
    };
    // Keep the shape checks of the service gate (IPv4, a valid pinned index,
    // a nonzero port) and record only the physical path reason.
    let mut reason: Option<String> = None;
    crate::windows_route_verify::require_token_destination_with(
        SocketAddr::V4(destination),
        Some(iface),
        |address, index| {
            crate::windows_physical_path::observe_token_destination(address, index, run.as_ref())
                .inspect_err(|error| {
                    reason = Some(format!("token_gate: {}", error.presence_reason()));
                })
        },
    )
    .map(|_| ())
    .map_err(|_| TokenGateError {
        message: TOKEN_DESTINATION_REFUSED,
        reason: reason.unwrap_or_else(|| "token_gate: invalid destination".to_string()),
    })
}

/// A source device discovery failure. `message` is the fixed user-facing code
/// and `reason` is the fixed-vocabulary diagnostic detail, which holds no
/// address or interface identity.
struct DiscoverFailure {
    message: &'static str,
    reason: String,
}

impl From<DiscoverFailure> for String {
    fn from(error: DiscoverFailure) -> Self {
        error.message.to_string()
    }
}

/// Find the pairing listener: the running tunnel's source device, or the
/// current physical default gateway. Then run the token gate for the pairing
/// port. The host never comes from the client.
fn discover_listener(service: &Service) -> Result<(Ipv4Addr, u32), DiscoverFailure> {
    let (host, iface) = if service.is_running() {
        let current = service.windows_phone_run().ok_or(DiscoverFailure {
            message: "no_hotspot",
            reason: "discovery: no run binding".to_string(),
        })?;
        let SocketAddr::V4(destination) = current.destination else {
            return Err(DiscoverFailure {
                message: "no_hotspot",
                reason: "discovery: the run destination is not IPv4".to_string(),
            });
        };
        (*destination.ip(), current.iface)
    } else {
        hotspot_gateway().map_err(|error| DiscoverFailure {
            message: error.message,
            reason: error.reason,
        })?
    };
    token_gate(service, SocketAddrV4::new(host, PAIRING_PORT), iface).map_err(|error| {
        DiscoverFailure {
            message: error.message,
            reason: error.reason,
        }
    })?;
    Ok((host, iface))
}

impl Shared {
    fn stop_scoped(&self, expected: Option<u64>, reason: Option<&'static str>) -> Value {
        let outcome = self.presence.stop(
            expected,
            || self.service.is_running(),
            || self.service.stop(),
            |outcome| {
                // This runs under the lifecycle lock, so a start that begins
                // after this stop cannot lose its target here.
                if let Ok(mut target) = self.run_target.lock() {
                    *target = None;
                }
                // Record a reason only for a run that this call stopped. An
                // idle service or a newer run keeps the previous record.
                if let (RunStop::Stopped, Some(reason)) = (outcome, reason) {
                    if let Ok(mut last) = self.last_stop.lock() {
                        *last = Some((reason, now()));
                    }
                }
            },
        );
        json!({"stopped": outcome == RunStop::Stopped})
    }

    /// Store the fixed-vocabulary reason for the last presence failure.
    fn record_presence_failure(&self, reason: String) {
        if let Ok(mut slot) = self.presence_failure.lock() {
            *slot = Some(reason);
        }
    }

    /// Clear the last presence failure reason after a successful discovery.
    fn clear_presence_failure(&self) {
        if let Ok(mut slot) = self.presence_failure.lock() {
            *slot = None;
        }
    }

    /// Probe the source device once and store the answer for the run that was
    /// current when the probe began. Return None when the probe was
    /// cancelled.
    fn probe_once(&self, cancel: &AtomicBool) -> Option<&'static str> {
        let run = self.presence.run();
        let running = self.service.is_running();
        let (state, connections, trusted, refused) = if running {
            self.probe_running(run, cancel)?
        } else {
            let (state, connections, trusted) = self.probe_idle(cancel)?;
            (state, connections, trusted, false)
        };
        if self.presence.record(run, state, now()) {
            if let Ok(mut extra) = self.extra.lock() {
                *extra = ProbeExtra {
                    run,
                    connections,
                    trusted_by_source: trusted,
                };
            }
        }
        // A pending FORGET is retried while the presence probe runs.
        self.pairing.retry_forget();
        if refused {
            // The relay keeps using the token for new flows, so a refusal
            // stops the run at once. A newer run is not touched.
            let _ = self.stop_scoped(Some(run), Some("hotspot_lost"));
        }
        Some(state)
    }

    /// Probe a running tunnel. The fourth value is true when the token gate
    /// refused the run's own binding.
    fn probe_running(
        &self,
        run: u64,
        cancel: &AtomicBool,
    ) -> Option<(&'static str, Option<u16>, Option<bool>, bool)> {
        let target = self
            .run_target
            .lock()
            .ok()
            .and_then(|target| target.clone())
            .filter(|target| target.run == run);
        let (Some(target), Some(current)) = (target, self.service.windows_phone_run()) else {
            // The start has not published this run yet. Send nothing.
            return Some(("pin_unknown", None, None, false));
        };
        if current.destination != SocketAddr::V4(SocketAddrV4::new(target.host, target.port)) {
            return Some(("pin_unknown", None, None, false));
        }
        if self.service.windows_run_token_gate().is_err() {
            return Some(("no_hotspot", None, None, true));
        }
        if target.paired {
            let identity = match pairing::local_identity() {
                Ok(identity) => identity,
                Err(_) => return Some(("not_responding", None, None, false)),
            };
            let answer = windows_pairing::probe_listener(
                SocketAddr::V4(SocketAddrV4::new(target.host, PAIRING_PORT)),
                current.iface,
                self.pairing.paired(),
                &identity,
                cancel,
            )?;
            if let Some(info) = answer.info.as_ref() {
                self.pairing.learn(target.host, info);
            }
            let connections = answer.info.as_ref().map(|info| info.connections);
            return Some((answer.state, connections, answer.trusted_by_source, false));
        }
        let Some(token) = target.token.as_ref() else {
            return Some(("pin_unknown", None, None, false));
        };
        let state = presence_probe(
            &proxy(target.host, target.port, token, current.iface),
            cancel,
        )?;
        Some((state, None, None, false))
    }

    fn probe_idle(&self, cancel: &AtomicBool) -> Option<(&'static str, Option<u16>, Option<bool>)> {
        if let Some(manual) = self.manual.lock().ok().and_then(|manual| manual.clone()) {
            if let Err(error) = token_gate(
                &self.service,
                SocketAddrV4::new(manual.host, manual.port),
                manual.iface,
            ) {
                self.record_presence_failure(error.reason);
                return Some(("no_hotspot", None, None));
            }
            self.clear_presence_failure();
            let state = presence_probe(
                &proxy(manual.host, manual.port, &manual.token, manual.iface),
                cancel,
            )?;
            return Some((state, None, None));
        }
        let (gateway, iface) = match discover_listener(&self.service) {
            Ok(found) => found,
            Err(error) => {
                self.record_presence_failure(error.reason);
                return Some(("no_hotspot", None, None));
            }
        };
        self.clear_presence_failure();
        let identity = match pairing::local_identity() {
            Ok(identity) => identity,
            Err(_) => return Some(("not_responding", None, None)),
        };
        let answer = windows_pairing::probe_listener(
            SocketAddr::V4(SocketAddrV4::new(gateway, PAIRING_PORT)),
            iface,
            self.pairing.paired(),
            &identity,
            cancel,
        )?;
        if let Some(info) = answer.info.as_ref() {
            self.pairing.learn(gateway, info);
        }
        let connections = answer.info.as_ref().map(|info| info.connections);
        Some((answer.state, connections, answer.trusted_by_source))
    }
}

impl WindowsGuiBackend {
    pub fn new(service: Arc<Service>) -> Self {
        Self::with_wintun(service, None)
    }

    pub fn with_wintun(service: Arc<Service>, wintun_dll: Option<std::path::PathBuf>) -> Self {
        let attempt_service = Arc::clone(&service);
        let attempt: PairAttempt = Arc::new(move |cancel, on_code| {
            let identity = pairing::local_identity()?;
            let (host, iface) =
                discover_listener(&attempt_service).map_err(|_| PairError::NoPhone)?;
            pairing::pair(
                host,
                &identity,
                Some(iface),
                &Audit::default(),
                &cancel,
                |code| on_code(code),
            )
        });
        let forget_service = Arc::clone(&service);
        let forget_network: ForgetNetwork = Arc::new(move || {
            let Ok((host, iface)) = discover_listener(&forget_service) else {
                return false;
            };
            let Ok(identity) = pairing::local_identity() else {
                return false;
            };
            pairing::forget(
                host,
                &identity,
                Some(iface),
                &Audit::default(),
                &AtomicBool::new(false),
            )
            .is_ok()
        });
        Self {
            shared: Arc::new(Shared {
                service,
                manual: Mutex::new(None),
                run_target: Mutex::new(None),
                pairing: Pairing::new(attempt, forget_network),
                presence: RunPresence::new(),
                extra: Mutex::new(ProbeExtra::default()),
                last_stop: Mutex::new(None),
                presence_failure: Mutex::new(None),
                closing: AtomicBool::new(false),
            }),
            start_lock: Mutex::new(()),
            wintun_dll,
            handoff: None,
            handoff_busy: Arc::new(AtomicBool::new(false)),
            handoff_identity: Mutex::new(None),
            probe_gate: Mutex::new(None),
        }
    }

    /// Build the elevated engine from the one pairing handoff that the
    /// launcher passed on an inherited pipe. The imported identity replaces
    /// the local key, so the source device sees the same target public key.
    /// The credentials stay in process memory and are never sent in a status
    /// answer. This engine exports no handoff of its own.
    pub fn with_imported_pairing(
        service: Arc<Service>,
        wintun_dll: Option<std::path::PathBuf>,
        identity: Identity,
        credentials: PhoneCredentials,
    ) -> Result<Self, PairError> {
        pairing::set_imported_identity(identity.secret_bytes())?;
        let backend = Self::with_wintun(service, wintun_dll);
        backend.shared.pairing.import(credentials);
        Ok(backend)
    }

    /// Give the standard-user engine the write end of the pairing handoff
    /// pipe, and read the identity once so a handoff never reopens the key
    /// file on a request thread.
    pub fn set_handoff(&mut self, handle: crate::windows_credential_handoff::HandoffHandle) {
        self.handoff = Some(Arc::new(handle));
        if let Ok(identity) = pairing::local_identity() {
            if let Ok(mut slot) = self.handoff_identity.lock() {
                *slot = Some(Zeroizing::new(identity.secret_bytes()));
            }
        }
    }

    fn phone_status(&self, running_phone: bool) -> Value {
        let shared = &self.shared;
        let run = shared.presence.run();
        let (observed, checked_at) = shared.presence.snapshot();
        let current = now();
        let fresh = checked_at.is_some_and(|at| probe_fresh(at, current));
        let state = windows_pairing::phone_state(observed, running_phone, fresh);
        let extra = shared
            .extra
            .lock()
            .ok()
            .map(|extra| *extra)
            .filter(|extra| extra.run == run)
            .unwrap_or_default();
        // A running paired tunnel keeps the port that it started with.
        let started = shared
            .run_target
            .lock()
            .ok()
            .and_then(|target| target.as_ref().map(|target| (target.paired, target.port)));
        let port_changed = running_phone
            && started.is_some_and(|(paired, port)| {
                paired
                    && shared
                        .pairing
                        .endpoint()
                        .is_some_and(|(_, learned)| learned != port)
            });
        let message = if port_changed {
            pairing::PORT_CHANGED_MESSAGE
        } else {
            phone_message(state)
        };
        json!({
            "state": state,
            "message": message,
            "port_changed": port_changed,
            "connections": extra.connections,
            "checked_at": checked_at.filter(|_| fresh),
            "trusted_by_source": extra.trusted_by_source,
        })
    }

    /// The source device for a start: a typed token, then a stored manual
    /// target, then the paired credentials. Return the host, port, token,
    /// pinned interface, and whether the paired credentials are used.
    fn start_target(
        &self,
        options: &Value,
    ) -> Result<(Ipv4Addr, u16, Zeroizing<String>, u32, bool), String> {
        let typed = options
            .get("token")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty());
        if typed {
            let target = parse_target(options)?;
            if let Ok(mut stored) = self.shared.manual.lock() {
                *stored = Some(target.clone());
            }
            return Ok((target.host, target.port, target.token, target.iface, false));
        }
        if let Some(target) = self
            .shared
            .manual
            .lock()
            .ok()
            .and_then(|stored| stored.clone())
        {
            // Recheck a stored target before a start. A previous hotspot can
            // reuse the same address, and the default gateway can change.
            let iface = require_gateway_target(target.host, Some(target.iface))?;
            return Ok((target.host, target.port, target.token, iface, false));
        }
        let credentials = self.shared.pairing.credentials().ok_or("pair_first")?;
        // The paired source device must be the current hotspot gateway. A
        // saved gateway from an earlier network is not evidence.
        let (gateway, iface) =
            hotspot_gateway().map_err(|_| TOKEN_DESTINATION_REFUSED.to_string())?;
        if gateway != credentials.host {
            return Err(TOKEN_DESTINATION_REFUSED.into());
        }
        Ok((
            credentials.host,
            credentials.port,
            Zeroizing::new(credentials.token.clone()),
            iface,
            true,
        ))
    }
}

impl GuiBackend for WindowsGuiBackend {
    fn status(&self) -> Result<Value, String> {
        let shared = &self.shared;
        let mut status = shared.service.status();
        // A poisoned service cannot establish whether a tunnel is running.
        if status.get("state").and_then(Value::as_str) == Some("unknown") {
            return Ok(status);
        }
        let running = status.get("running") == Some(&json!(true));
        let running_phone = running && status.get("mode") == Some(&json!("phone"));
        status["api"] = json!(1);
        status["phone"] = self.phone_status(running_phone);
        let endpoint = shared.pairing.endpoint();
        status["paired"] = json!(endpoint.is_some());
        status["phone_host"] = json!(endpoint.map(|(host, _)| host.to_string()));
        status["phone_port"] = json!(endpoint.map(|(_, port)| port));
        let (forget_state, attempts) = shared.pairing.forget_state();
        status["forget"] = json!({"state": forget_state, "attempts": attempts});
        let last = shared.last_stop.lock().ok().and_then(|last| *last);
        apply_last_stop(&mut status, last);
        Ok(status)
    }

    fn start_presence(&self, stop: Arc<AtomicBool>) {
        let shared = Arc::clone(&self.shared);
        let _ = std::thread::Builder::new()
            .name("hotspotshade-probe".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    // The server stop flag cancels a probe in progress. One
                    // overall deadline bounds the rest, so the stored answer
                    // stays fresh between probes.
                    let _ = shared.probe_once(&stop);
                    for _ in 0..(PROBE_INTERVAL.as_millis() / 100) {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            });
    }

    fn probe(&self) -> Result<Value, String> {
        let audit = Audit::default();
        let udp_ok =
            normalization::udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), None, &audit).is_ok();
        let tcp = Audit::default();
        let _ = normalization::tcp_start(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
            None,
            &tcp,
        );
        let (tcp_total, tcp_bad) = tcp.snapshot();
        let bound = crate::platform::default_interface_index().is_ok_and(|index| {
            normalization::interface_name(index)
                .is_ok_and(|name| !name.starts_with("HotspotShade-Tunnel"))
                && normalization::udp_socket(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some(index),
                    &Audit::default(),
                )
                .is_ok()
        });
        Ok(json!({
            "available": true,
            "platform": self.shared.service.status()["platform"],
            "admin": crate::platform::is_elevated(),
            "capabilities": {
                "ip_ttl_udp": udp_ok,
                "ip_ttl_tcp": tcp_total > 0 && tcp_bad == 0,
                "bound_if": bound,
                "utun_needs_root": true
            }
        }))
    }

    fn phone_discover(&self) -> Result<Value, String> {
        // The same answer shape as macOS and Linux. The connect sends no
        // token and uses a normalized outer socket pinned to the hotspot.
        let Ok((host, index)) = hotspot_gateway() else {
            return Ok(json!({
                "host": Value::Null,
                "port": 1080,
                "reachable": false,
                "message": "Connect this device to the source device hotspot."
            }));
        };
        let audit = Audit::default();
        for port in [1080u16, 18080] {
            if normalization::tcp_connect(
                SocketAddr::V4(SocketAddrV4::new(host, port)),
                Some(index),
                &audit,
                Duration::from_secs(1),
            )
            .is_ok()
            {
                return Ok(json!({
                    "host": host.to_string(),
                    "port": port,
                    "reachable": true,
                    "message": "A gateway accepted a TCP connection. Check the token to verify the proxy."
                }));
            }
        }
        Ok(json!({
            "host": host.to_string(),
            "port": 1080,
            "reachable": false,
            "message": "No proxy answered on ports 1080 or 18080."
        }))
    }

    fn phone_check(&self, payload: Value) -> Result<Value, String> {
        let shared = &self.shared;
        let options = payload.get("options").ok_or("missing options")?;
        let run = shared.presence.run();
        let target = parse_target(options)?;
        token_gate(
            &shared.service,
            SocketAddrV4::new(target.host, target.port),
            target.iface,
        )?;
        proxy(target.host, target.port, &target.token, target.iface)
            .check_cancellable(&Audit::default(), &shared.closing)
            .map_err(|_| "source device authentication failed")?;
        // Keep the target only after the source device accepted the token.
        if let Ok(mut stored) = shared.manual.lock() {
            *stored = Some(target);
        }
        shared.presence.record(run, "ready", now());
        Ok(json!({"ok":true,"message":"The source device proxy accepted the token."}))
    }

    fn start(&self, payload: Value) -> Result<Value, String> {
        let shared = &self.shared;
        let mode = payload
            .get("mode")
            .and_then(Value::as_str)
            .ok_or("missing mode")?;
        if mode != "phone" {
            return Err("windows_phone_only".into());
        }
        let options = payload.get("options").ok_or("missing options")?;
        if !options.is_object() {
            return Err("invalid options".into());
        }
        if shared.closing.load(Ordering::Acquire) {
            return Err("start_cancelled".into());
        }
        let (icmp_phone, icmp_persistent) = crate::gui::phone_icmp_options(options, true, true)?;
        let _start = self.start_lock.lock().map_err(|_| "service_start")?;
        if shared.service.is_running() {
            return Err("service_start".into());
        }
        let (host, port, token, iface, paired) = self.start_target(options)?;
        let iface_name =
            normalization::interface_name(iface).map_err(|_| "no physical hotspot interface")?;
        let tun_options = TunOptions {
            iface: Some(iface_name),
            ipv6: Ipv6Policy::Forward,
            icmp_phone,
            icmp_persistent,
            wintun_dll: self.wintun_dll.clone(),
            ..TunOptions::default()
        };
        let mut start_proxy = proxy(host, port, &token, iface);
        start_proxy.timeout = Duration::from_secs(5);
        let token = (!paired).then(|| token.clone());
        // The service runs the token gate right before the token check and
        // records the run binding. The run id changes around the attempt, so
        // an observation or a probe from the previous run cannot act on this
        // one. A stop or shutdown during the attempt cancels it, and the start
        // then reports `start_cancelled` instead of success.
        shared
            .presence
            .start(
                || shared.service.is_running(),
                |cancel| {
                    shared.service.start_tun_options_cancellable(
                        tun_options,
                        Some(start_proxy),
                        worker_count(),
                        cancel,
                    )
                },
                || shared.service.stop(),
                |run| {
                    if let Ok(mut target) = shared.run_target.lock() {
                        *target = Some(RunTarget {
                            run,
                            host,
                            port,
                            paired,
                            token,
                        });
                    }
                    shared.presence.record(run, "connected", now());
                    if let Ok(mut last) = shared.last_stop.lock() {
                        *last = None;
                    }
                },
            )
            .map_err(|error| match error {
                RunStartError::Service(error) => start_error(error),
                RunStartError::Interrupted | RunStartError::Closed => "start_cancelled".into(),
                RunStartError::Busy => "service_start".into(),
            })?;
        Ok(json!({"mode":"phone"}))
    }

    fn stop(&self) -> Result<Value, String> {
        // A person stopping the tunnel records no automatic stop reason.
        let _ = self.shared.stop_scoped(None, None);
        Ok(json!({"stopped":true}))
    }

    fn stop_for(&self, reason: &'static str) -> Result<Value, String> {
        Ok(self.shared.stop_scoped(None, Some(reason)))
    }

    fn monitor_generation(&self) -> Option<u64> {
        Some(self.shared.presence.run())
    }

    fn stop_for_generation(
        &self,
        reason: &'static str,
        generation: Option<u64>,
    ) -> Result<Value, String> {
        Ok(self.shared.stop_scoped(generation, Some(reason)))
    }

    fn mark_closing(&self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.presence.close();
        self.shared.pairing.close();
    }

    fn failures(&self) -> Result<Value, String> {
        Ok(self.shared.service.failures())
    }

    fn diagnostics(&self) -> Result<Value, String> {
        let mut value = self.shared.service.diagnostics();
        // Surface the Windows identity-store failure detail, if any, so the
        // Copy diagnostics report carries the first failing step without
        // changing any user-facing message. The string holds only a fixed step
        // word, a component index, and a Win32 error number; it never holds a
        // path, a SID, or key material.
        value["identity"] = match pairing::last_identity_failure() {
            Some(detail) => json!(detail),
            None => Value::Null,
        };
        // Surface the last presence discovery failure as a fixed-vocabulary
        // string. It holds only a step word, an error variant, a fixed static
        // reason, and at most a Win32 error number; it never holds an address,
        // port, interface name or index, GUID, LUID, MAC, or token.
        value["presence"] = match self
            .shared
            .presence_failure
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
        {
            Some(reason) => json!(reason),
            None => Value::Null,
        };
        Ok(value)
    }

    fn phone_probe(&self) -> Result<Value, String> {
        // Serialize the probes and skip a second probe inside 500 ms.
        let mut gate = self.probe_gate.lock().map_err(|_| "probe_state")?;
        if gate.is_none_or(|at| at.elapsed() >= Duration::from_millis(500)) {
            *gate = Some(Instant::now());
            let _ = self.shared.probe_once(&self.shared.closing);
        }
        drop(gate);
        let status = self.status()?;
        Ok(json!({"ok":true,"phone":status["phone"].clone()}))
    }

    fn pair_start(&self) -> Result<Value, String> {
        let shared = &self.shared;
        let view = shared
            .pairing
            .start(shared.closing.load(Ordering::Acquire))?;
        // A person who pairs wants the paired credentials, not an older typed
        // token.
        if let Ok(mut manual) = shared.manual.lock() {
            *manual = None;
        }
        Ok(view)
    }

    fn pair_status(&self) -> Result<Value, String> {
        self.shared.pairing.status()
    }

    fn pair_cancel(&self) -> Result<Value, String> {
        self.shared.pairing.cancel()
    }

    fn pair_forget(&self) -> Result<Value, String> {
        // A start in progress or a running tunnel keeps the proxy token.
        let result = {
            let Ok(_start) = self.start_lock.try_lock() else {
                return Err("tunnel_running".into());
            };
            let shared = &self.shared;
            let result = shared.pairing.forget(shared.service.is_running())?;
            if let Ok(mut manual) = shared.manual.lock() {
                *manual = None;
            }
            result
        };
        // Probe at once, as on macOS and Linux, so the page shows the real
        // source device state and whether the old key is still trusted.
        let _ = self.shared.probe_once(&self.shared.closing);
        Ok(result)
    }

    fn pair_handoff(&self) -> Result<Value, String> {
        // A running tunnel already owns the routes. A handoff at that point
        // would start a second engine over a live one.
        if self.shared.service.is_running() {
            return Err("tunnel_running".into());
        }
        let handle = Arc::clone(self.handoff.as_ref().ok_or("handoff_unavailable")?);
        let credentials = self.shared.pairing.credentials().ok_or("not_paired")?;
        let identity = match self
            .handoff_identity
            .lock()
            .map_err(|_| "handoff_unavailable")?
            .as_ref()
        {
            Some(secret) => Identity::from_bytes(**secret),
            None => pairing::local_identity().map_err(|error| error.message().to_string())?,
        };
        // One write at a time. A write that the reader never drains stays in
        // its own thread, and later handoffs are refused until it ends.
        if self.handoff_busy.swap(true, Ordering::AcqRel) {
            return Err("handoff_busy".into());
        }
        let busy = Arc::clone(&self.handoff_busy);
        let (done, result) = std::sync::mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("hotspotshade-handoff".into())
            .spawn(move || {
                let outcome = handle.write(&identity, &credentials);
                busy.store(false, Ordering::Release);
                let _ = done.send(outcome);
            });
        if spawned.is_err() {
            self.handoff_busy.store(false, Ordering::Release);
            return Err("handoff_unavailable".into());
        }
        match result.recv_timeout(HANDOFF_WRITE_LIMIT) {
            Ok(Ok(())) => Ok(json!({"ok": true})),
            Ok(Err(error)) => Err(error.message().to_string()),
            Err(_) => Err("handoff_unavailable".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{gateway_target_matches, is_private_gateway, start_error, WindowsGuiBackend};
    use crate::gui::GuiBackend;
    use crate::pairing::PhoneCredentials;
    use crate::service::Service;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn backend() -> WindowsGuiBackend {
        WindowsGuiBackend::new(Arc::new(Service::new()))
    }

    fn credentials() -> PhoneCredentials {
        PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 31000,
            token: "public-test-windows-token".into(),
        }
    }

    #[test]
    fn status_has_the_macos_pairing_fields_and_no_unavailable_state() {
        let backend = backend();
        let status = backend.status().unwrap();
        assert_eq!(status["paired"], false);
        assert_eq!(status["api"], 1);
        assert!(status["phone"].get("trusted_by_source").is_some());
        assert!(status["phone"].get("checked_at").is_some());
        assert_eq!(status["forget"]["state"], "none");
        assert_ne!(status["phone"]["state"], "source_proxy_unavailable");
        assert_eq!(backend.pair_status().unwrap()["state"], "idle");
    }

    #[test]
    fn paired_credentials_show_as_paired_without_the_token() {
        let backend = backend();
        backend.shared.pairing.import(credentials());
        let status = backend.status().unwrap();
        assert_eq!(status["paired"], true);
        assert_eq!(status["phone_host"], "172.20.10.1");
        assert_eq!(status["phone_port"], 31000);
        let view = backend.pair_status().unwrap();
        assert_eq!(view["state"], "paired");
        for text in [status.to_string(), view.to_string()] {
            assert!(!text.contains("public-test-windows-token"), "{text}");
        }
    }

    #[test]
    fn forget_is_refused_while_a_start_holds_the_start_lock() {
        let backend = backend();
        backend.shared.pairing.import(credentials());
        let start = backend.start_lock.lock().unwrap();
        assert_eq!(backend.pair_forget().unwrap_err(), "tunnel_running");
        drop(start);
        assert!(backend.shared.pairing.paired());
    }

    #[test]
    fn a_handoff_needs_a_handle_and_the_engine_refuses_other_modes() {
        let backend = backend();
        backend.shared.pairing.import(credentials());
        assert_eq!(backend.pair_handoff().unwrap_err(), "handoff_unavailable");
        let error = backend
            .start(serde_json::json!({"mode":"tun","options":{}}))
            .unwrap_err();
        assert_eq!(error, "windows_phone_only");
    }

    #[test]
    fn a_source_device_must_be_the_hotspot_gateway() {
        let gateway = Ipv4Addr::new(172, 20, 10, 1);
        let other = Ipv4Addr::new(192, 0, 2, 10);
        assert!(gateway_target_matches(gateway, None, gateway, 7));
        assert!(gateway_target_matches(gateway, Some(7), gateway, 7));
        assert!(!gateway_target_matches(other, None, gateway, 7));
        assert!(!gateway_target_matches(gateway, Some(8), gateway, 7));
    }

    #[test]
    fn a_public_gateway_is_not_a_hotspot_source_device() {
        assert!(is_private_gateway(Ipv4Addr::new(172, 20, 10, 1)));
        assert!(is_private_gateway(Ipv4Addr::new(192, 168, 43, 1)));
        assert!(!is_private_gateway(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn the_token_gate_code_reaches_the_page() {
        let error = std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            crate::windows_route_verify::TOKEN_DESTINATION_REFUSED,
        );
        assert_eq!(start_error(error), "source_gateway_unproven");
    }
}
