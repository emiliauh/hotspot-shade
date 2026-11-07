//! Local HTTP bridge for the hotspotshade UI.
//!
//! The backend owns service lifecycle and network operations. It must not put
//! credentials in status, logs, or returned values. The HTTP server does not
//! log request bodies or backend errors.
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
// Windows can buffer a large blocking send in one call even if the peer never
// reads. Limit each call so the deadline is checked between bounded writes.
const MAX_RESPONSE_WRITE_CHUNK: usize = 64 * 1024;
/// One absolute deadline covers the headers and the body of one request. A
/// client that sends one byte at a time cannot hold a request slot forever.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
/// The cap for one socket read. The absolute request deadline is usually
/// shorter.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long shutdown waits for request workers after it closes their sockets.
/// A worker that does not stop in this window is detached; the process then
/// exits after the normal cleanup path.
const WORKER_JOIN_GRACE: Duration = Duration::from_secs(2);
const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const INDEX: &[u8] = include_bytes!("../../gui_assets/index.html");
const STYLE: &[u8] = include_bytes!("../../gui_assets/styles.css");
const SCRIPT: &[u8] = include_bytes!("../../gui_assets/app.js");
const FAVICON: &[u8] = include_bytes!("../../assets/logo/favicon.svg");

/// Map a service error code to text for the browser. Return None for an
/// unknown code so the caller can show a generic message.
pub(crate) fn start_error_message(code: &str) -> Option<&'static str> {
    match code {
        crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE => {
            Some(crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE)
        }
        crate::service::CLEANUP_UNCERTAIN_MESSAGE => {
            Some(crate::service::CLEANUP_UNCERTAIN_MESSAGE)
        }
        "private_listener" => Some("Could not create the private administrator helper connection."),
        "launcher_start" => Some("Could not open the macOS administrator prompt."),
        "authorization_cancelled" => Some("Administrator authorization was cancelled or failed."),
        "authorization_timeout" => Some("Administrator authorization timed out."),
        "helper_connection" => Some("The administrator helper could not connect."),
        "helper_disconnected" => Some("The administrator helper disconnected during startup."),
        "helper_timeout" => Some("The administrator helper did not respond within 20 seconds."),
        "helper_panic" => Some("The administrator helper failed unexpectedly during startup."),
        "helper_permission" => Some("The administrator helper encountered a permission error."),
        "helper_error" => Some("The administrator helper exited with an error during startup."),
        "phone_auth" => {
            Some("Source device authentication failed. Check the token and hotspot connection.")
        }
        "invalid_ping_option" => Some("The ping setting must be true or false."),
        "route_setup" => Some("The tunnel could not configure its routes."),
        "tunnel_setup" => Some("The tunnel could not create its virtual interface."),
        "service_start" => Some("The tunnel could not start."),
        "start_cancelled" => Some("The start was cancelled."),
        "pair_first" => Some("Pair with the source device first."),
        "manual_phone" => {
            Some("Enter the source device address and token from the HotspotShade app.")
        }
        "wintun_missing" => Some(
            "The wintun.dll file is missing. Install it next to the HotspotShade program, then start again.",
        ),
        "admin_required" => Some("Start HotspotShade as Administrator to use the tunnel."),
        "protected_helper_required" => Some(
            "The protected helper is not available. Install the signed HotspotShade helper package, then try again.",
        ),
        "authorization_required" => Some(
            "Administrator authorization is required to start the tunnel.",
        ),
        "mode_not_allowed" => Some("The protected engine starts only the tunnel."),
        "windows_phone_only" => {
            Some("This Windows build runs source device proxy mode only.")
        }
        "source_gateway_unproven" => Some(SOURCE_GATEWAY_UNPROVEN_MESSAGE),
        "pair_unsupported" => Some(
            "Pairing is not available in the Windows command-line interface. Enter the source device address and token.",
        ),
        _ => None,
    }
}

/// The fixed text for each source device presence state. The text is plain and
/// holds no secret. The target app and the web page show it unchanged.
pub(crate) fn phone_message(state: &str) -> &'static str {
    match state {
        "no_hotspot" => "Turn on Personal Hotspot on your source device.",
        "not_running" => "HotspotShade is not running on your source device.",
        "proxy_off" => "Start the proxy on your source device.",
        "ready" => "The source device is ready.",
        "connected" => "Connected to the source device.",
        "checking" => "Checking the source device.",
        "unpaired" => "Not paired. Open HotspotShade on your source device, then pair.",
        "not_trusted" => "The source device does not know this target device. Pair again.",
        "pin_unknown" => "The tunnel interface is unknown. Turn the tunnel off and on.",
        _ => "Open HotspotShade on your source device and keep it open.",
    }
}

/// The fixed text for a Windows token gate refusal. It names no address,
/// interface, or Windows error.
pub(crate) const SOURCE_GATEWAY_UNPROVEN_MESSAGE: &str =
    "The source device must be the default gateway of a physical hotspot adapter. Turn off any VPN, connect to the source device hotspot, then try again.";

/// A source device probe result stays current for this long. An observer that
/// probes on a fixed pause must replace its answer inside this limit, so its
/// pause plus its overall probe deadline must fit. See `probe_cadence_fits`.
/// The auto-stop policy and the status answer use the same limit.
pub(crate) const PROBE_FRESH: Duration = Duration::from_secs(10);

/// True when a probe result with this wall clock time is still current. A
/// timestamp from the future is not current: the clock moved back and the age
/// is unknown.
pub(crate) fn probe_fresh(checked_at: u64, now_unix: u64) -> bool {
    checked_at <= now_unix && now_unix - checked_at <= PROBE_FRESH.as_secs()
}

/// True when a probe loop with this pause and this overall probe deadline
/// always replaces its result before the result stops being fresh.
///
/// The worst gap between two stored results is one pause plus one full
/// deadline. Allow one second for whole-second timestamps and one second for
/// the local gateway lookup and thread scheduling. The deadline must cover the
/// whole probe: a per-operation timeout can repeat for each step and exceed it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const fn probe_cadence_fits(interval: Duration, deadline: Duration) -> bool {
    interval.as_secs() + deadline.as_secs() + 2 <= PROBE_FRESH.as_secs()
        && interval.subsec_nanos() == 0
        && deadline.subsec_nanos() == 0
}

/// Run one source device presence probe with one overall deadline.
///
/// `proxy.timeout` is the deadline for the whole check: connect, method
/// negotiation, and authentication share it. Return None when `cancel` stopped
/// the probe. A cancelled probe is not an answer and must not be stored.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn presence_probe(
    proxy: &crate::phone::PhoneProxy,
    cancel: &AtomicBool,
) -> Option<&'static str> {
    let result = proxy.check_cancellable(&crate::normalization::Audit::default(), cancel);
    if cancel.load(Ordering::Acquire) {
        return None;
    }
    Some(match result {
        Ok(()) => "ready",
        Err(error) if crate::phone::authentication_rejected(&error) => "not_trusted",
        Err(_) => "not_responding",
    })
}

/// Write the automatic stop record in the shared status shape:
/// `last_stop` is `{reason, at}` and `last_stop_message` is the fixed text for
/// the reason. A backend record replaces the service record. Without one, the
/// service record stays.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn apply_last_stop(status: &mut Value, last: Option<(&'static str, u64)>) {
    if let Some((reason, at)) = last {
        status["last_stop"] = json!({"reason": reason, "at": at});
    } else if !status["last_stop"].is_object() {
        status["last_stop"] = json!({"reason": null, "at": null});
    }
    let message = status
        .pointer("/last_stop/reason")
        .and_then(Value::as_str)
        .and_then(crate::autostop::stop_message);
    status["last_stop_message"] = json!(message);
}

/// The outcome of a stop that names the run it observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum RunStop {
    /// The observed run is gone. A later run is not touched.
    Stale,
    /// The service had no tunnel. No stop reason is recorded.
    Idle,
    /// The observed run was running and the stop path ran.
    Stopped,
}

#[derive(Default)]
struct RunRecord {
    run: u64,
    state: Option<&'static str>,
    checked_at: Option<u64>,
}

#[derive(Default)]
struct Lifecycle {
    /// The cancel flag of the start attempt in progress.
    attempt: Option<Arc<AtomicBool>>,
    /// Set once when the backend begins shutdown.
    closed: bool,
}

/// Run-scoped presence results for a backend that drives the service
/// directly.
///
/// The run id changes around every start attempt on an idle service, after
/// every successful start, and after every stop. A probe stores its result
/// only when the run that it started under is still current, so a slow probe
/// from an older run cannot mark a restarted tunnel. A stop that names a run
/// acts only on that run. The lifecycle lock serializes the run check with
/// the stop, so a restart cannot slip between them. The lock order is
/// lifecycle, then the service, then the record.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Default)]
pub(crate) struct RunPresence {
    lifecycle: Mutex<Lifecycle>,
    record: Mutex<RunRecord>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl RunPresence {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The current run id.
    pub(crate) fn run(&self) -> u64 {
        self.record.lock().map(|record| record.run).unwrap_or(0)
    }

    /// Start a new run scope. Earlier results and observations are dropped.
    fn advance(&self) -> u64 {
        match self.record.lock() {
            Ok(mut record) => {
                record.run = record.run.wrapping_add(1);
                record.state = None;
                record.checked_at = None;
                record.run
            }
            Err(_) => 0,
        }
    }

    /// Store one probe result when `run` is still current. Return false and
    /// store nothing for a result from an older run.
    pub(crate) fn record(&self, run: u64, state: &'static str, checked_at: u64) -> bool {
        match self.record.lock() {
            Ok(mut record) if record.run == run => {
                record.state = Some(state);
                record.checked_at = Some(checked_at);
                true
            }
            _ => false,
        }
    }

    /// The stored state and its wall clock time.
    pub(crate) fn snapshot(&self) -> (Option<&'static str>, Option<u64>) {
        self.record
            .lock()
            .map(|record| (record.state, record.checked_at))
            .unwrap_or((None, None))
    }

    fn lifecycle(&self) -> std::sync::MutexGuard<'_, Lifecycle> {
        // The state is two plain values. A panic cannot leave it half written.
        self.lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Mark the backend as closing. Cancel a start in progress and refuse a
    /// later start.
    pub(crate) fn close(&self) {
        let mut lifecycle = self.lifecycle();
        lifecycle.closed = true;
        if let Some(cancel) = &lifecycle.attempt {
            cancel.store(true, Ordering::Release);
        }
    }

    /// Run one start attempt.
    ///
    /// Only one attempt runs at a time. `start` gets a cancel flag for this
    /// attempt; a stop or `close` sets it. An attempt on an idle service runs
    /// in a fresh run scope, and the run id changes again when it ends, so a
    /// status read that overlapped the start belongs to no run. A refused
    /// attempt on a running service changes nothing: the live run keeps its
    /// id, its presence answer, and its automatic-stop timers.
    ///
    /// `started` runs under the lifecycle lock with the new run id, only for a
    /// success that no stop interrupted. When a stop interrupted the attempt,
    /// the result is `Interrupted` even if the service reported success, and
    /// `abandon` stops what the attempt may have left running. A stop and a
    /// start are never both reported as successful.
    pub(crate) fn start<E>(
        &self,
        is_running: impl FnOnce() -> bool,
        start: impl FnOnce(&AtomicBool) -> Result<(), E>,
        abandon: impl FnOnce(),
        started: impl FnOnce(u64),
    ) -> Result<u64, RunStartError<E>> {
        let cancel = Arc::new(AtomicBool::new(false));
        let fresh = {
            let mut lifecycle = self.lifecycle();
            if lifecycle.closed {
                return Err(RunStartError::Closed);
            }
            if lifecycle.attempt.is_some() {
                return Err(RunStartError::Busy);
            }
            lifecycle.attempt = Some(Arc::clone(&cancel));
            let fresh = !is_running();
            if fresh {
                self.advance();
            }
            fresh
        };
        let result = start(&cancel);
        let mut lifecycle = self.lifecycle();
        lifecycle.attempt = None;
        if cancel.load(Ordering::Acquire) {
            if result.is_ok() {
                abandon();
            }
            self.advance();
            return Err(RunStartError::Interrupted);
        }
        match result {
            Ok(()) => {
                let run = self.advance();
                started(run);
                Ok(run)
            }
            Err(error) => {
                if fresh {
                    self.advance();
                }
                Err(RunStartError::Service(error))
            }
        }
    }

    /// Stop the service for the observed run.
    ///
    /// `expected` None stops whatever runs or starts now. Some(run) stops only
    /// that run: a later run returns `Stale` and is not touched. A start in
    /// progress is cancelled first, so it cannot report success after this
    /// stop. `stop` runs for an idle service too, so a finished worker is
    /// reaped, but the result is `Idle`. `publish` runs under the lifecycle
    /// lock with the outcome, so a stop reason and a later start clear it in
    /// order.
    pub(crate) fn stop(
        &self,
        expected: Option<u64>,
        is_running: impl FnOnce() -> bool,
        stop: impl FnOnce(),
        publish: impl FnOnce(RunStop),
    ) -> RunStop {
        let lifecycle = self.lifecycle();
        if expected.is_some_and(|run| run != self.run()) {
            return RunStop::Stale;
        }
        if let Some(cancel) = &lifecycle.attempt {
            cancel.store(true, Ordering::Release);
        }
        let running = is_running();
        stop();
        self.advance();
        let outcome = if running {
            RunStop::Stopped
        } else {
            RunStop::Idle
        };
        publish(outcome);
        outcome
    }
}

/// Why a start attempt did not produce a running tunnel.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RunStartError<E> {
    /// The service refused or failed the start.
    Service(E),
    /// A stop or shutdown cancelled the attempt.
    Interrupted,
    /// Another start attempt is in progress.
    Busy,
    /// The backend is closing.
    Closed,
}

/// Parse the optional echo relay settings for a phone start request.
///
/// `experimental_icmp` defaults to `default_enabled`. When the request names
/// `experimental_icmp` but not `experimental_icmp_persistent`, the persistent
/// value follows the enabled value. Otherwise it uses `default_persistent`.
/// A non-boolean value is an error. The error text is fixed and does not echo
/// the value.
pub(crate) fn phone_icmp_options(
    options: &Value,
    default_enabled: bool,
    default_persistent: bool,
) -> Result<(bool, bool), String> {
    let enabled = match options.get("experimental_icmp") {
        None => default_enabled,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err("invalid_ping_option".into()),
    };
    let persistent = match options.get("experimental_icmp_persistent") {
        None if options.get("experimental_icmp").is_some() => enabled,
        None => default_persistent,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err("invalid_ping_option".into()),
    };
    if persistent && !enabled {
        return Err("invalid_ping_option".into());
    }
    Ok((enabled, persistent))
}

/// Implementations own the service and enforce the network invariants.
/// Return errors without secrets. They are not sent to the browser.
pub trait GuiBackend: Send + Sync + 'static {
    fn status(&self) -> Result<Value, String>;
    fn api_request(&self) {}
    fn start_presence(&self, _stop: Arc<AtomicBool>) {}
    /// Set once when the HTTP server begins shutdown. A request that already
    /// passed its own stop check must not start a tunnel after the final stop.
    fn mark_closing(&self) {}

    fn probe(&self) -> Result<Value, String>;
    fn phone_discover(&self) -> Result<Value, String>;
    fn phone_check(&self, payload: Value) -> Result<Value, String>;
    fn start(&self, payload: Value) -> Result<Value, String>;
    fn stop(&self) -> Result<Value, String>;
    /// Failed source device setups for the current tunnel. It holds no token.
    fn failures(&self) -> Result<Value, String> {
        Ok(crate::failures::empty_snapshot())
    }
    /// The bounded relay counters and timing reservoirs. It holds no address.
    fn diagnostics(&self) -> Result<Value, String> {
        Ok(crate::diagnostics::empty())
    }
    /// Run one source device presence probe now. Respect the 500 ms limit.
    fn phone_probe(&self) -> Result<Value, String> {
        Err("probe_unsupported".into())
    }
    /// Stop with one reason. The default uses the normal stop path.
    fn stop_for(&self, _reason: &'static str) -> Result<Value, String> {
        self.stop()
    }
    /// Identify the lifecycle generation of an automatic-stop observation.
    /// A backend that returns None does not provide run-scoped protection.
    fn monitor_generation(&self) -> Option<u64> {
        None
    }
    /// Stop only the observed generation when supported. The default ignores
    /// the generation and uses the normal stop path.
    fn stop_for_generation(
        &self,
        reason: &'static str,
        _generation: Option<u64>,
    ) -> Result<Value, String> {
        self.stop_for(reason)
    }
    /// Start a pairing with the discovered phone in the background. Refuse a
    /// second start while one runs. Never take a host from the browser.
    fn pair_start(&self) -> Result<Value, String> {
        Err("pair_unsupported".into())
    }
    /// The pairing state. It never holds the token.
    fn pair_status(&self) -> Result<Value, String> {
        Ok(crate::pairing::PairView::default().to_json())
    }
    fn pair_forget(&self) -> Result<Value, String> {
        Err("pair_unsupported".into())
    }
    fn pair_cancel(&self) -> Result<Value, String> {
        self.pair_status()
    }
    /// Write the current pairing to the private handoff descriptor that the
    /// app gave the user engine at launch. The root engine refuses this.
    fn pair_handoff(&self) -> Result<Value, String> {
        Err("handoff_unsupported".into())
    }
}

struct Request {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}
/// Headers can hold a bearer token and the body can hold a manual source
/// device token, so Debug shows header names and the body length only.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&str> = self.headers.keys().map(String::as_str).collect();
        names.sort_unstable();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("header_names", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        if let Some(value) = self.headers.get_mut("authorization") {
            unsafe {
                for byte in value.as_bytes_mut() {
                    std::ptr::write_volatile(byte, 0);
                }
            }
        }
        // The request body can hold a manual source device token.
        unsafe {
            for byte in &mut self.body {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}
struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    csp: bool,
    no_store: bool,
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}
fn json_response(status: u16, body: Value) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8",
        body: body.to_string().into_bytes(),
        csp: false,
        no_store: true,
    }
}
fn error(status: u16, message: &str) -> Response {
    json_response(status, json!({"ok":false,"error":message}))
}
fn asset(body: &'static [u8], ty: &'static str, csp: bool) -> Response {
    Response {
        status: 200,
        content_type: ty,
        body: body.to_vec(),
        csp,
        no_store: true,
    }
}

/// Set the next read timeout to the time left before the absolute request
/// deadline. The timeout is never longer than one read cap.
fn set_request_timeout(stream: &TcpStream, deadline: Instant) -> Result<(), Response> {
    let now = Instant::now();
    if now >= deadline {
        return Err(error(408, "request timed out"));
    }
    let remaining = deadline
        .saturating_duration_since(now)
        .min(REQUEST_READ_TIMEOUT);
    stream
        .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
        .map_err(|_| error(400, "request failed"))
}

fn read_request(stream: &mut TcpStream) -> Result<Request, Response> {
    read_request_with_deadline(stream, REQUEST_DEADLINE)
}

/// Read one request. The deadline is absolute and covers the complete header
/// and body. A slow client cannot extend it by sending one byte before each
/// per-read timeout. The timeout only bounds a single blocking read.
fn read_request_with_deadline(
    stream: &mut TcpStream,
    limit: Duration,
) -> Result<Request, Response> {
    let deadline = Instant::now() + limit;
    let mut reader = BufReader::new(stream);
    let mut header = Vec::new();
    loop {
        if header.len() >= MAX_HEADER {
            return Err(error(431, "request headers too large"));
        }
        set_request_timeout(reader.get_ref(), deadline)?;
        let mut b = [0u8; 1];
        match reader.read_exact(&mut b) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(error(408, "request timed out"));
            }
            Err(_) => return Err(error(400, "invalid request")),
        }
        header.push(b[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = std::str::from_utf8(&header).map_err(|_| error(400, "invalid request"))?;
    let mut lines = header.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let method = first.next().ok_or_else(|| error(400, "invalid request"))?;
    let target = first.next().ok_or_else(|| error(400, "invalid request"))?;
    let version = first.next().ok_or_else(|| error(400, "invalid request"))?;
    if first.next().is_some()
        || version != "HTTP/1.1"
        || !target.starts_with('/')
        || target.starts_with("//")
    {
        return Err(error(400, "invalid request"));
    }
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| error(400, "invalid headers"))?;
        if key.is_empty() || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(error(400, "invalid headers"));
        }
        let key = key.to_ascii_lowercase();
        if headers.insert(key, value.trim().to_owned()).is_some() {
            return Err(error(400, "duplicate header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(error(400, "transfer encoding is not supported"));
    }
    let length = match headers.get("content-length") {
        Some(value) if !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()) => value
            .parse::<usize>()
            .map_err(|_| error(400, "invalid Content-Length"))?,
        Some(_) => return Err(error(400, "invalid Content-Length")),
        None => 0,
    };
    if length > MAX_BODY {
        return Err(error(413, "request body too large"));
    }
    let mut body = vec![0; length];
    let mut filled = 0;
    while filled < body.len() {
        set_request_timeout(reader.get_ref(), deadline)?;
        match reader.read(&mut body[filled..]) {
            Ok(0) => return Err(error(400, "incomplete request body")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(error(408, "request timed out"));
            }
            Err(_) => return Err(error(400, "incomplete request body")),
        }
    }
    Ok(Request {
        method: method.into(),
        target: target.into(),
        headers,
        body,
    })
}

use crate::redact::redact_json as redact;
fn safe_json(result: Result<Value, String>) -> Response {
    match result {
        Ok(mut value) => {
            redact(&mut value);
            json_response(200, value)
        }
        Err(_) => error(400, "The service could not complete the request."),
    }
}
fn object_body(req: &Request) -> Result<Value, Response> {
    let value = if req.body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&req.body)
            .map_err(|_| error(400, "request body must be valid JSON"))?
    };
    if !value.is_object() {
        return Err(error(400, "request body must be a JSON object"));
    }
    Ok(value)
}
fn route(mut req: Request, expected_host: &str, backend: &dyn GuiBackend) -> Response {
    if req.headers.get("host").map(String::as_str) != Some(expected_host) {
        return error(403, "forbidden: invalid Host");
    }
    if let Some(origin) = req.headers.get("origin") {
        if origin != &format!("http://{}", expected_host) {
            return error(403, "forbidden: invalid Origin");
        }
    }
    if req.method == "OPTIONS" {
        return Response {
            status: 204,
            content_type: "text/plain; charset=utf-8",
            body: Vec::new(),
            csp: false,
            no_store: true,
        };
    }
    if req.method == "HEAD" {
        req.method = "GET".into();
    }
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    match (req.method.as_str(), path) {
        ("GET", "/" | "/index.html") => asset(INDEX, "text/html; charset=utf-8", true),
        ("GET", "/styles.css") => asset(STYLE, "text/css; charset=utf-8", false),
        ("GET", "/app.js") => asset(SCRIPT, "application/javascript; charset=utf-8", false),
        ("GET", "/favicon.svg") => asset(FAVICON, "image/svg+xml", false),
        ("GET", "/favicon.ico") => Response {
            status: 204,
            content_type: "image/x-icon",
            body: Vec::new(),
            csp: false,
            no_store: true,
        },
        ("GET", "/api/status") => safe_json(backend.status()),
        ("GET", "/api/failures") => safe_json(backend.failures()),
        ("GET", "/api/diagnostics") => safe_json(backend.diagnostics()),
        ("GET", "/api/probe") => safe_json(backend.probe()),
        ("GET", "/api/phone/discover") => safe_json(backend.phone_discover()),
        ("GET", "/api/phone/pair") => safe_json(backend.pair_status()),
        (
            "POST",
            "/api/phone/pair" | "/api/phone/pair/cancel" | "/api/phone/forget" | "/api/phone/probe",
        ) => {
            let json_type = req
                .headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json");
            if !json_type
                && !(path == "/api/phone/probe"
                    && req.body.is_empty()
                    && req
                        .headers
                        .get("content-type")
                        .map(String::as_str)
                        .unwrap_or("")
                        .is_empty())
            {
                return error(
                    415,
                    "unsupported media type: POST requires application/json",
                );
            }
            if let Err(r) = object_body(&req) {
                return r;
            }
            let result = if path == "/api/phone/pair" {
                backend.pair_start()
            } else if path == "/api/phone/forget" {
                backend.pair_forget()
            } else if path == "/api/phone/probe" {
                backend.phone_probe()
            } else {
                backend.pair_cancel()
            };
            match result {
                Ok(value) => safe_json(Ok(value)),
                Err(code) if path == "/api/phone/forget" => {
                    let (status, message) = crate::pairing::forget_error(&code);
                    error(status, message)
                }
                Err(code) => error(400, crate::pairing::request_error_message(&code)),
            }
        }
        ("POST", "/api/pairing/handoff") => {
            // The app sends this once, immediately before it asks the helper
            // to start the elevated engine. The body is empty JSON. The
            // response never carries the token or the identity key.
            let json_type = req
                .headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json");
            if !json_type {
                return error(
                    415,
                    "unsupported media type: POST requires application/json",
                );
            }
            if let Err(r) = object_body(&req) {
                return r;
            }
            match backend.pair_handoff() {
                Ok(value) => safe_json(Ok(value)),
                Err(code) => error(409, code.as_str()),
            }
        }
        ("GET", "/api/logs") => {
            let mut since = 0u64;
            for item in query.split('&').filter(|s| !s.is_empty()) {
                if let Some(value) = item.strip_prefix("since=") {
                    since = match value.parse() {
                        Ok(n) => n,
                        Err(_) => return error(400, "since must be an integer"),
                    };
                    break;
                }
            }
            match backend.status() {
                Ok(mut status) => {
                    redact(&mut status);
                    let mut next = since;
                    let mut logs = Vec::new();
                    if let Some(entries) = status.get("logs").and_then(Value::as_array) {
                        for entry in entries {
                            if let Some(seq) = entry.get("seq").and_then(Value::as_u64) {
                                next = next.max(seq);
                                if seq > since {
                                    logs.push(entry.clone());
                                }
                            }
                        }
                    }
                    if logs.len() > 800 {
                        logs.drain(..logs.len() - 800);
                    }
                    json_response(200, json!({"logs":logs,"next":next}))
                }
                Err(_) => error(500, "The service status is unavailable."),
            }
        }
        ("POST", "/api/start" | "/api/stop" | "/api/phone/check") => {
            let content_type = req
                .headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("");
            let json_type = content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json");
            if !json_type
                && !(path == "/api/stop" && req.body.is_empty() && content_type.is_empty())
            {
                return error(
                    415,
                    "unsupported media type: POST requires application/json",
                );
            }
            let payload = match object_body(&req) {
                Ok(p) => p,
                Err(r) => return r,
            };
            match path {
                "/api/phone/check" => match backend.phone_check(payload) {
                    Ok(result) => safe_json(Ok(result)),
                    Err(message) if message == "source_gateway_unproven" => {
                        error(400, SOURCE_GATEWAY_UNPROVEN_MESSAGE)
                    }
                    Err(_) => error(
                        400,
                        "Source device authentication failed. Check the token and hotspot connection.",
                    ),
                },
                "/api/start" => match backend.start(payload) {
                    Ok(mut result) => {
                        redact(&mut result);
                        match backend.status() {
                            Ok(mut status) => {
                                redact(&mut status);
                                json_response(
                                    200,
                                    json!({"ok":true,"status":status,"result":result}),
                                )
                            }
                            Err(_) => error(500, "The service status is unavailable."),
                        }
                    }
                    Err(message) if message == "phone_auth" => json_response(
                        409,
                        json!({"ok":false,"code":"phone_token_rejected",
                            "error":"The source device changed its token. Open HotspotShade on your source device, then pair again."}),
                    ),
                    Err(message) => error(
                        400,
                        crate::gui::start_error_message(&message)
                            .unwrap_or("The service could not start. Check the settings."),
                    ),
                },
                _ => match backend.stop() {
                    Ok(mut result) => {
                        redact(&mut result);
                        match backend.status() {
                            Ok(mut status) => {
                                redact(&mut status);
                                json_response(
                                    200,
                                    json!({"ok":true,"status":status,"result":result}),
                                )
                            }
                            Err(_) => error(500, "The service status is unavailable."),
                        }
                    }
                    Err(message) => error(
                        400,
                        crate::gui::start_error_message(&message)
                            .unwrap_or("The service could not stop."),
                    ),
                },
            }
        }
        ("GET" | "POST", _) => error(404, "not found"),
        _ => error(405, "method not allowed"),
    }
}
struct BearerSecret([u8; 64]);
impl Drop for BearerSecret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Bound the entire response write, even when a peer reads a few bytes before
/// each individual socket timeout. Header and body share the same deadline.
fn write_by_deadline(stream: &mut TcpStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    write_with_deadline(&mut data, deadline, |remaining, bytes| {
        stream.set_write_timeout(Some(remaining))?;
        stream.write(bytes)
    })
}

fn write_with_deadline(
    data: &mut &[u8],
    deadline: Instant,
    mut write: impl FnMut(Duration, &[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    while !data.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "response timed out"))?;
        let chunk = &data[..data.len().min(MAX_RESPONSE_WRITE_CHUNK)];
        match write(remaining.max(Duration::from_millis(1)), chunk) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "response closed")),
            Ok(count) => *data = &data[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn respond(
    mut stream: TcpStream,
    backend: Arc<dyn GuiBackend>,
    expected_host: String,
    stop: Arc<AtomicBool>,
    token: Option<Arc<BearerSecret>>,
) {
    let mut head = false;
    let response = match read_request(&mut stream) {
        Ok(_) if stop.load(Ordering::Acquire) => error(503, "The service is stopping."),
        Ok(req) => {
            head = req.method == "HEAD";
            let path = req.target.split('?').next().unwrap_or("");
            let authorized = token.as_ref().is_none_or(|secret| {
                let value = req
                    .headers
                    .get("authorization")
                    .map(String::as_bytes)
                    .unwrap_or_default();
                let mut difference = value.len() ^ 71;
                let prefix = b"Bearer ";
                let expected = prefix
                    .iter()
                    .map(|byte| byte.to_ascii_lowercase())
                    .chain(secret.0.iter().copied());
                for (i, expected) in expected.enumerate() {
                    let actual = value.get(i).copied().unwrap_or(0);
                    let actual = if i < prefix.len() {
                        actual.to_ascii_lowercase()
                    } else {
                        actual
                    };
                    difference |= usize::from(actual ^ expected);
                }
                difference == 0
            });
            if path.starts_with("/api/") && !authorized {
                Response {
                    status: 401,
                    content_type: "application/json; charset=utf-8",
                    body: br#"{"ok":false,"error":"unauthorized"}"#.to_vec(),
                    csp: false,
                    no_store: true,
                }
            } else {
                if path.starts_with("/api/") {
                    backend.api_request();
                }
                route(req, &expected_host, backend.as_ref())
            }
        }
        Err(r) => r,
    };
    let mut header = format!("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n", response.status, reason(response.status), response.content_type, response.body.len());
    if response.no_store {
        header.push_str("Cache-Control: no-store, max-age=0\r\n");
    }
    if response.csp {
        header.push_str("Content-Security-Policy: ");
        header.push_str(CSP);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    let deadline = Instant::now() + Duration::from_secs(5);
    if write_by_deadline(&mut stream, header.as_bytes(), deadline).is_ok() && !head {
        let _ = write_by_deadline(&mut stream, &response.body, deadline);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Observe the link state for one interface alias or numeric index. `None`
/// means unknown: the name is missing, or the interface tables could not be
/// read. An unknown link is not link loss.
///
/// Unix reads `getifaddrs`. Windows reports unknown until its observer has
/// passed review and native testing. The auto-stop policy still uses a fresh
/// source device probe there.
fn observe_link(iface: Option<&str>) -> Option<bool> {
    iface.and_then(|name| crate::autostop::link_observation(name).ok())
}

/// Whether the running platform can prove the hotspot link state.
///
/// The GUI never invents link loss. A platform without a reviewed link
/// observer still gets source device probe evidence, so a silent source
/// device stops the tunnel in source device proxy mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkWatch {
    /// The platform reads the pinned interface. An unavailable reading is
    /// unknown and breaks both continuous timers.
    Observable,
    /// The platform reports unknown for every interface sample. A source
    /// device probe answer is the only evidence, and an interface reading
    /// never stops the tunnel. This is stricter than the Windows command line,
    /// which treats a missing interface name as up.
    Unobservable,
}

/// The link capability of the running platform.
///
/// Windows has no reviewed link observer, so its GUI uses the source device
/// probe alone. Change this value only together with that observer and its
/// native test.
const PLATFORM_LINK_WATCH: LinkWatch = if cfg!(windows) {
    LinkWatch::Unobservable
} else {
    LinkWatch::Observable
};

/// Feed one status answer to the auto-stop policy with the running platform's
/// link capability.
///
/// The link observation is separate, so a test can replace it. On Windows the
/// platform reports unknown for every interface, so only a fresh source device
/// answer can count. The policy still stops after 90 seconds of continuous
/// silence and never restarts the tunnel.
fn auto_stop_sample(
    status: &Value,
    link: Option<bool>,
    now_unix: u64,
    now: Instant,
    policy: &mut crate::autostop::AutoStopPolicy,
) -> Option<&'static str> {
    auto_stop_sample_watch(PLATFORM_LINK_WATCH, status, link, now_unix, now, policy)
}

/// Feed one status answer to the auto-stop policy for one link capability.
///
/// An unknown link on a platform that can observe the link breaks a continuous
/// failure interval: a missing interface or a `getifaddrs` error is not proof
/// that the link stayed down. A phone probe result counts only while it is
/// fresh. An unobservable link never reports link loss, but a fresh silent
/// probe still proves continuous source device silence. A plaintext status
/// frame is unverified: it keeps an existing silence interval and starts one
/// only after the bounded unverified grace. It never counts as presence.
fn auto_stop_sample_watch(
    watch: LinkWatch,
    status: &Value,
    link: Option<bool>,
    now_unix: u64,
    now: Instant,
    policy: &mut crate::autostop::AutoStopPolicy,
) -> Option<&'static str> {
    if status.get("running") != Some(&json!(true)) {
        policy.reset();
        return None;
    }
    let phone = status.get("mode").and_then(Value::as_str) == Some("phone");
    let checked = status
        .pointer("/phone/checked_at")
        .and_then(Value::as_u64)
        .filter(|at| probe_fresh(*at, now_unix));
    let probe = checked.and_then(|_| status.pointer("/phone/state").and_then(Value::as_str));
    let probe = match probe {
        // A running tunnel reports `connected` only for a ready probe.
        Some("connected") => Some("ready"),
        other => other,
    };
    let sample = match watch {
        LinkWatch::Unobservable => {
            // The platform cannot prove the link, so an interface or route
            // answer is never link loss. A fresh silent probe is the only stop
            // evidence. A plaintext or local no-evidence answer is bounded by
            // the policy instead of resetting the silence timer. A positive,
            // stale, missing, `no_hotspot`, or other non-answer result resets
            // both timers.
            if phone {
                match probe {
                    Some("not_running" | "not_responding") => {
                        crate::autostop::HotspotSample::DeviceGone
                    }
                    Some(state) if crate::autostop::unverified_probe_state(state) => {
                        crate::autostop::HotspotSample::Unverified
                    }
                    _ => {
                        policy.reset();
                        return None;
                    }
                }
            } else {
                policy.reset();
                return None;
            }
        }
        LinkWatch::Observable => match link {
            Some(true) if phone && probe.is_none() => {
                // The link is up, but no fresh source device answer exists.
                // This cannot establish continuous silence across the gap.
                policy.link_recovered();
                policy.source_device_unobserved();
                return None;
            }
            Some(link_up) => crate::autostop::sample_from(link_up, phone, probe),
            // The presence probe reports `no_hotspot` when the local route
            // lookup finds no hotspot gateway. That is link evidence on a
            // platform that can read the route table, even when the interface
            // lookup failed.
            None if phone && probe == Some("no_hotspot") => {
                crate::autostop::HotspotSample::LinkDown
            }
            // No link evidence. Do not count an unobserved gap as continuous
            // loss.
            None => {
                policy.reset();
                return None;
            }
        },
    };
    policy.observe(now, sample)
}

/// Keep the last good status when a status read fails.
///
/// A transient helper error must not look like a stopped tunnel. Treating the
/// error as `running: false` resets the auto-stop timers and disables link
/// monitoring. A good answer always replaces the stored one, including a good
/// answer that says the tunnel stopped.
fn auto_stop_status(last: &mut Option<Value>, result: Result<Value, String>) -> Value {
    match result {
        Ok(status) => {
            *last = Some(status.clone());
            status
        }
        Err(_) => last.clone().unwrap_or(Value::Null),
    }
}

/// Discard cached observations and timers when the active run changes.
fn reset_monitor_for_generation(
    last: &mut Option<u64>,
    before: Option<u64>,
    after: Option<u64>,
    status: &mut Option<Value>,
    policy: &mut crate::autostop::AutoStopPolicy,
) -> bool {
    if after != *last || before != after {
        *status = None;
        policy.reset();
        *last = after;
    }
    before == after
}

/// Observe the hotspot every 2 seconds while a tunnel runs. Stop with the
/// normal stop path when the policy fires. This path never kills a process.
fn auto_stop_loop(backend: Arc<dyn GuiBackend>, stop: Arc<AtomicBool>) {
    let mut policy = crate::autostop::AutoStopPolicy::new();
    let mut last_status: Option<Value> = None;
    let mut last_generation = backend.monitor_generation();
    let mut next = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= next {
            // A status error is not a stopped tunnel. Keep the last good
            // answer so a transient helper error does not reset the timers or
            // disable link monitoring.
            let before = backend.monitor_generation();
            let result = backend.status();
            let generation = backend.monitor_generation();
            // A status answer that overlaps a run change belongs to neither
            // run. Wait for the next sample before making a stop decision.
            if !reset_monitor_for_generation(
                &mut last_generation,
                before,
                generation,
                &mut last_status,
                &mut policy,
            ) {
                next = now + Duration::from_secs(2);
                continue;
            }
            let status = auto_stop_status(&mut last_status, result);
            let running = status.get("running") == Some(&json!(true));
            let iface = status.get("iface").and_then(Value::as_str);
            // A missing interface or a getifaddrs error is unknown, not a
            // link-down sample. An auto stop must not invent link loss. On
            // Windows every interface sample is unknown, so a fresh silent
            // source device answer is the only stop evidence there.
            let link = observe_link(iface);
            let reason = auto_stop_sample(&status, link, now_unix(), now, &mut policy);
            if let Some(reason) = reason {
                let _ = backend.stop_for_generation(reason, generation);
            } else if !running {
                policy.reset();
            }
            next = now + Duration::from_secs(2);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// Bind to loopback only. Use `local_addr` to report a dynamic port.
pub struct GuiServer {
    listener: TcpListener,
    token: Option<Arc<BearerSecret>>,
}
impl GuiServer {
    pub fn bind(port: u16) -> io::Result<Self> {
        // On Windows a same-user socket with SO_REUSEADDR could otherwise
        // share the port and receive a request with the bearer secret.
        #[cfg(windows)]
        let listener = crate::normalization::exclusive_loopback_listener(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))?;
        #[cfg(not(windows))]
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            token: None,
        })
    }
    pub fn set_token(&mut self, token: [u8; 64]) {
        self.token = Some(Arc::new(BearerSecret(token)));
    }
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
    /// Stop accepting when `stop` becomes true. Each request has one absolute
    /// deadline. Shutdown closes open sockets and waits a bounded time for
    /// request workers.
    pub fn run(self, backend: Arc<dyn GuiBackend>, stop: Arc<AtomicBool>) -> io::Result<()> {
        let expected = self.listener.local_addr()?.to_string();
        backend.start_presence(Arc::clone(&stop));
        let auto_backend = Arc::clone(&backend);
        let auto_stop = Arc::clone(&stop);
        let auto = thread::Builder::new()
            .name("hotspotshade-auto-stop".into())
            .spawn(move || auto_stop_loop(auto_backend, auto_stop))
            .ok();
        let active = Arc::new(AtomicUsize::new(0));
        let watched: Arc<Mutex<HashMap<u64, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
        let next_id = Arc::new(AtomicU64::new(1));
        let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
        while !stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::AcqRel);
                        continue;
                    }
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    let watch = match stream.try_clone() {
                        Ok(watch) => watch,
                        Err(_) => {
                            active.fetch_sub(1, Ordering::AcqRel);
                            continue;
                        }
                    };
                    match watched.lock() {
                        Ok(mut watched) => {
                            watched.insert(id, watch);
                        }
                        Err(_) => {
                            active.fetch_sub(1, Ordering::AcqRel);
                            continue;
                        }
                    }
                    let b = Arc::clone(&backend);
                    let n = Arc::clone(&active);
                    let h = expected.clone();
                    let closing = Arc::clone(&stop);
                    let token = self.token.clone();
                    let registry = Arc::clone(&watched);
                    let cleanup_registry = Arc::clone(&watched);
                    match thread::Builder::new()
                        .name("hotspotshade-http".into())
                        .spawn(move || {
                            struct Guard {
                                active: Arc<AtomicUsize>,
                                id: u64,
                                registry: Arc<Mutex<HashMap<u64, TcpStream>>>,
                            }
                            impl Drop for Guard {
                                fn drop(&mut self) {
                                    self.active.fetch_sub(1, Ordering::AcqRel);
                                    if let Ok(mut registry) = self.registry.lock() {
                                        registry.remove(&self.id);
                                    }
                                }
                            }
                            let _guard = Guard {
                                active: n,
                                id,
                                registry,
                            };
                            respond(stream, b, h, closing, token);
                        }) {
                        Ok(worker) => workers.push(worker),
                        Err(_) => {
                            active.fetch_sub(1, Ordering::AcqRel);
                            if let Ok(mut registry) = cleanup_registry.lock() {
                                registry.remove(&id);
                            }
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        // Close every open connection first. A slow request worker gets a read
        // or write error instead of holding shutdown open.
        if let Ok(watched) = watched.lock() {
            for stream in watched.values() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        // Cancel a pending authorization before waiting for request threads.
        // Set the closing flag first so a request that passed its own stop
        // check cannot start work after the final stop below.
        backend.mark_closing();
        let _ = backend.stop();
        let _ = backend.pair_cancel();
        join_request_workers(workers);
        // A request can race with the first stop. Stop it after it completes.
        let _ = backend.stop();
        if let Some(auto) = auto {
            let _ = auto.join();
        }
        Ok(())
    }
}

/// Wait a bounded time for request workers after their sockets are closed.
///
/// A thread that ignores the stop flag and the socket shutdown cannot be
/// killed. It is detached instead of delaying parent-loss or process shutdown.
fn join_request_workers(mut workers: Vec<thread::JoinHandle<()>>) {
    let deadline = Instant::now() + WORKER_JOIN_GRACE;
    loop {
        let mut i = 0;
        while i < workers.len() {
            if workers[i].is_finished() {
                let _ = workers.swap_remove(i).join();
            } else {
                i += 1;
            }
        }
        if workers.is_empty() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake;
    impl GuiBackend for Fake {
        fn status(&self) -> Result<Value, String> {
            Ok(json!({"running":false,"logs":[],"token":"private"}))
        }
        fn probe(&self) -> Result<Value, String> {
            Ok(json!({"available":true}))
        }
        fn phone_discover(&self) -> Result<Value, String> {
            Ok(json!({"reachable":false}))
        }
        fn phone_check(&self, _: Value) -> Result<Value, String> {
            Err("sensitive".into())
        }
        fn start(&self, _: Value) -> Result<Value, String> {
            Ok(json!({"started":true}))
        }
        fn stop(&self) -> Result<Value, String> {
            Ok(json!({"stopped":true}))
        }
    }
    fn req(
        method: &str,
        target: &str,
        host: &str,
        origin: Option<&str>,
        ty: Option<&str>,
        body: &[u8],
    ) -> Request {
        let mut headers = HashMap::new();
        headers.insert("host".into(), host.into());
        if let Some(o) = origin {
            headers.insert("origin".into(), o.into());
        }
        if let Some(t) = ty {
            headers.insert("content-type".into(), t.into());
        }
        Request {
            method: method.into(),
            target: target.into(),
            headers,
            body: body.into(),
        }
    }
    #[test]
    fn phone_state_text_is_fixed_and_named() {
        for state in [
            "no_hotspot",
            "not_running",
            "not_responding",
            "proxy_off",
            "ready",
            "connected",
            "checking",
            "unpaired",
            "not_trusted",
        ] {
            let message = phone_message(state);
            assert!(!message.is_empty(), "{state}");
            assert!(!message.contains("Hotspot Proxy"), "{state}");
            assert!(!message.to_ascii_lowercase().contains("token"), "{state}");
        }
        assert_eq!(
            phone_message("unpaired"),
            "Not paired. Open HotspotShade on your source device, then pair."
        );
        assert_eq!(
            phone_message("not_trusted"),
            "The source device does not know this target device. Pair again."
        );
        assert_eq!(
            phone_message("not_responding"),
            "Open HotspotShade on your source device and keep it open."
        );
        assert_eq!(
            phone_message("proxy_off"),
            "Start the proxy on your source device."
        );
        assert_eq!(phone_message("ready"), "The source device is ready.");
        assert_eq!(
            phone_message("connected"),
            "Connected to the source device."
        );
        assert_eq!(phone_message("checking"), "Checking the source device.");
        assert_eq!(
            phone_message("no_hotspot"),
            "Turn on Personal Hotspot on your source device."
        );
        assert_eq!(
            phone_message("not_running"),
            "HotspotShade is not running on your source device."
        );
    }
    #[test]
    fn the_windows_token_gate_refusal_has_fixed_text() {
        // Source device proxy mode is available on Windows. The token gate
        // runs at each token use, so no static unavailable code remains.
        assert_eq!(start_error_message("source_proxy_unavailable"), None);
        assert_eq!(
            start_error_message("source_gateway_unproven"),
            Some(SOURCE_GATEWAY_UNPROVEN_MESSAGE)
        );
        assert!(!SOURCE_GATEWAY_UNPROVEN_MESSAGE.contains("172."));
    }
    #[test]
    fn tunnel_authorization_error_has_plain_text() {
        assert_eq!(
            start_error_message("authorization_required"),
            Some("Administrator authorization is required to start the tunnel.")
        );
    }
    #[test]
    fn reject_cross_origin_and_untrusted_host() {
        assert_eq!(
            route(
                req("GET", "/api/status", "attacker.invalid", None, None, b""),
                "127.0.0.1:8787",
                &Fake
            )
            .status,
            403
        );
        assert_eq!(
            route(
                req(
                    "POST",
                    "/api/start",
                    "127.0.0.1:8787",
                    Some("https://evil.invalid"),
                    Some("application/json"),
                    b"{}"
                ),
                "127.0.0.1:8787",
                &Fake
            )
            .status,
            403
        );
        assert_eq!(
            route(
                req(
                    "POST",
                    "/api/start",
                    "127.0.0.1:8787",
                    None,
                    Some("text/plain"),
                    b"{}"
                ),
                "127.0.0.1:8787",
                &Fake
            )
            .status,
            415
        );
    }
    #[test]
    fn statuses_are_redacted_and_service_errors_are_generic() {
        let r = route(
            req("GET", "/api/status", "127.0.0.1:8787", None, None, b""),
            "127.0.0.1:8787",
            &Fake,
        );
        let s = String::from_utf8(r.body).unwrap();
        assert!(!s.contains("private"));
        assert!(s.contains("[redacted]"));
        let r = route(
            req(
                "POST",
                "/api/phone/check",
                "127.0.0.1:8787",
                None,
                Some("application/json"),
                b"{}",
            ),
            "127.0.0.1:8787",
            &Fake,
        );
        assert!(!String::from_utf8(r.body).unwrap().contains("sensitive"));
    }
    #[test]
    fn a_non_boolean_ping_option_is_a_fixed_400_error() {
        let backend = crate::demo::DemoBackend::new();
        let host = "127.0.0.1:8787";
        let response = route(
            req(
                "POST",
                "/api/start",
                host,
                None,
                Some("application/json"),
                br#"{"mode":"phone","options":{"experimental_icmp":"yes"}}"#,
            ),
            host,
            &backend,
        );
        assert_eq!(response.status, 400);
        let text = String::from_utf8(response.body).unwrap();
        assert!(text.contains("The ping setting must be true or false."));
        assert!(!text.contains("yes"));
        assert!(!text.contains("experimental_icmp"));
    }
    #[test]
    fn known_start_stage_is_visible_and_arbitrary_errors_are_not() {
        struct Failure(&'static str);
        impl GuiBackend for Failure {
            fn status(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn probe(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_discover(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_check(&self, _: Value) -> Result<Value, String> {
                Err(self.0.into())
            }
            fn start(&self, _: Value) -> Result<Value, String> {
                Err(self.0.into())
            }
            fn stop(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
        }
        let make = || {
            req(
                "POST",
                "/api/start",
                "127.0.0.1:8787",
                None,
                Some("application/json"),
                b"{}",
            )
        };
        let known = String::from_utf8(route(make(), "127.0.0.1:8787", &Failure("phone_auth")).body)
            .unwrap();
        assert!(known.contains("\"code\":\"phone_token_rejected\""));
        assert!(known.contains(
            "The source device changed its token. Open HotspotShade on your source device, then pair again."
        ));
        assert_eq!(
            route(make(), "127.0.0.1:8787", &Failure("phone_auth")).status,
            409
        );
        let secret = String::from_utf8(
            route(make(), "127.0.0.1:8787", &Failure("private-token-value")).body,
        )
        .unwrap();
        assert!(!secret.contains("private-token-value"));
        for endpoint in ["/api/start", "/api/phone/check"] {
            let request = req(
                "POST",
                endpoint,
                "127.0.0.1:8787",
                None,
                Some("application/json"),
                b"{}",
            );
            let response = route(
                request,
                "127.0.0.1:8787",
                &Failure("source_gateway_unproven"),
            );
            assert_eq!(response.status, 400);
            assert!(String::from_utf8(response.body)
                .unwrap()
                .contains(SOURCE_GATEWAY_UNPROVEN_MESSAGE));
        }
    }

    #[test]
    fn unavailable_service_errors_are_visible_at_the_action_boundary() {
        struct Unavailable;
        impl GuiBackend for Unavailable {
            fn status(&self) -> Result<Value, String> {
                Ok(json!({"state":"unknown"}))
            }
            fn probe(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_discover(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_check(&self, _: Value) -> Result<Value, String> {
                Err("private".into())
            }
            fn start(&self, _: Value) -> Result<Value, String> {
                Err(crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE.into())
            }
            fn stop(&self) -> Result<Value, String> {
                Err(crate::service::CLEANUP_UNCERTAIN_MESSAGE.into())
            }
        }
        let host = "127.0.0.1:8787";
        for (path, message) in [
            (
                "/api/start",
                crate::service::SERVICE_STATE_UNAVAILABLE_MESSAGE,
            ),
            ("/api/stop", crate::service::CLEANUP_UNCERTAIN_MESSAGE),
        ] {
            let response = route(
                req("POST", path, host, None, Some("application/json"), b"{}"),
                host,
                &Unavailable,
            );
            assert_eq!(response.status, 400);
            let value: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(value["error"], message);
        }
    }
    #[test]
    fn pairing_routes_need_json_and_return_fixed_text() {
        struct Pairing;
        impl GuiBackend for Pairing {
            fn status(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn probe(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_discover(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_check(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn start(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn stop(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn pair_start(&self) -> Result<Value, String> {
                Err("pair_busy private-detail".into())
            }
            fn pair_status(&self) -> Result<Value, String> {
                Ok(
                    json!({"state":"paired","code":null,"host":"172.20.10.1","port":1080,"error":null,"token":"leak"}),
                )
            }
            fn pair_forget(&self) -> Result<Value, String> {
                Err("tunnel_running".into())
            }
        }
        let host = "127.0.0.1:8787";
        let get = route(
            req("GET", "/api/phone/pair", host, None, None, b""),
            host,
            &Pairing,
        );
        let body = String::from_utf8(get.body).unwrap();
        assert_eq!(get.status, 200);
        assert!(body.contains("\"state\":\"paired\""));
        assert!(!body.contains("leak"));
        for path in [
            "/api/phone/pair",
            "/api/phone/pair/cancel",
            "/api/phone/forget",
        ] {
            let plain = route(req("POST", path, host, None, None, b""), host, &Pairing);
            assert_eq!(plain.status, 415);
            let foreign = route(
                req(
                    "POST",
                    path,
                    host,
                    Some("http://evil.invalid"),
                    Some("application/json"),
                    b"{}",
                ),
                host,
                &Pairing,
            );
            assert_eq!(foreign.status, 403);
        }
        // Forget is refused while the tunnel runs. The credentials stay.
        let refused = route(
            req(
                "POST",
                "/api/phone/forget",
                host,
                None,
                Some("application/json"),
                b"{}",
            ),
            host,
            &Pairing,
        );
        assert_eq!(refused.status, 409);
        let body: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "Turn off the tunnel first.");
        let busy = route(
            req(
                "POST",
                "/api/phone/pair",
                host,
                None,
                Some("application/json"),
                b"{}",
            ),
            host,
            &Pairing,
        );
        let text = String::from_utf8(busy.body).unwrap();
        assert_eq!(busy.status, 400);
        assert!(text.contains("The pairing could not start."));
        assert!(!text.contains("private-detail"));
        assert_eq!(
            crate::pairing::request_error_message("pair_busy"),
            "A pairing is already running."
        );
        // The default trait methods report an idle pairing.
        let idle = route(
            req("GET", "/api/phone/pair", host, None, None, b""),
            host,
            &Fake,
        );
        assert!(String::from_utf8(idle.body)
            .unwrap()
            .contains("\"state\":\"idle\""));
        let cancel = route(
            req(
                "POST",
                "/api/phone/pair/cancel",
                host,
                None,
                Some("application/json"),
                b"{}",
            ),
            host,
            &Fake,
        );
        assert_eq!(cancel.status, 200);
    }
    #[test]
    fn failures_route_has_the_empty_shape_and_a_simulated_demo() {
        let host = "127.0.0.1:8787";
        let response = route(
            req("GET", "/api/failures", host, None, None, b""),
            host,
            &Fake,
        );
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            value,
            json!({"ok":true,"since":null,"total":0,"dropped":0,"groups":[],"recent":[]})
        );
        let demo = crate::demo::DemoBackend::new();
        let response = route(
            req("GET", "/api/failures", host, None, None, b""),
            host,
            &demo,
        );
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["demo"], true);
        assert_eq!(value["groups"][0]["proto"], "tcp");
        assert_eq!(value["groups"][0]["name"], "example.com");
        assert!(!value["groups"].as_array().unwrap().is_empty());
        assert!(!value["recent"].as_array().unwrap().is_empty());
        assert!(!value.to_string().contains("token"));
    }
    #[test]
    fn embedded_ui_and_empty_stop() {
        let r = route(
            req("GET", "/", "127.0.0.1:8787", None, None, b""),
            "127.0.0.1:8787",
            &Fake,
        );
        assert!(r.csp);
        assert!(!r.body.is_empty());
        let r = route(
            req("POST", "/api/stop", "127.0.0.1:8787", None, None, b""),
            "127.0.0.1:8787",
            &Fake,
        );
        assert_eq!(r.status, 200);
    }
    #[test]
    fn socket_parser_rejects_duplicate_headers_and_oversized_body() {
        fn exchange(request: &str) -> String {
            let server = GuiServer::bind(0).unwrap();
            let addr = server.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_worker = Arc::clone(&stop);
            let worker = thread::spawn(move || server.run(Arc::new(Fake), stop_worker).unwrap());
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            stop.store(true, Ordering::Release);
            worker.join().unwrap();
            answer
        }
        let duplicate = exchange("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: attacker\r\n\r\n");
        assert!(duplicate.starts_with("HTTP/1.1 400"));
        let big = exchange(
            "POST /api/start HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1048577\r\n\r\n",
        );
        assert!(big.starts_with("HTTP/1.1 413"));
    }
    #[test]
    fn authenticated_head_has_no_body_and_options_is_204() {
        let mut server = GuiServer::bind(0).unwrap();
        server.set_token([b'a'; 64]);
        let addr = server.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || server.run(Arc::new(Fake), shutdown).unwrap());
        let send = |request: String| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            answer
        };
        let auth = format!("Authorization: Bearer {}\r\n", "a".repeat(64));
        let head = send(format!(
            "HEAD /api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n"
        ));
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("Content-Length: "), "{head}");
        assert!(!head.contains("Content-Length: 0"), "{head}");
        assert_eq!(head.split("\r\n\r\n").nth(1).unwrap(), "");
        let options = send(format!(
            "OPTIONS /api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n"
        ));
        assert!(options.starts_with("HTTP/1.1 204 No Content"), "{options}");
        assert!(options.contains("Content-Length: 0"), "{options}");
        assert_eq!(options.split("\r\n\r\n").nth(1).unwrap(), "");
        // A plain GET needs the secret too, and the secret opens the route.
        let refused_get = send(format!(
            "GET /api/failures HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        ));
        assert!(refused_get.starts_with("HTTP/1.1 401"), "{refused_get}");
        let allowed_get = send(format!(
            "GET /api/failures HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n"
        ));
        assert!(allowed_get.starts_with("HTTP/1.1 200"), "{allowed_get}");
        assert!(allowed_get.contains("\"ok\":true"), "{allowed_get}");
        // Both methods still need the bearer secret on an API path.
        for path in ["/api/status", "/api/failures"] {
            for method in ["HEAD", "OPTIONS"] {
                let refused = send(format!(
                    "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                ));
                assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");
            }
        }
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn shutdown_cancels_an_active_start_before_joining_requests() {
        struct Waiting {
            started: AtomicBool,
            cancelled: AtomicBool,
        }
        impl GuiBackend for Waiting {
            fn status(&self) -> Result<Value, String> {
                Ok(json!({"running":false}))
            }
            fn probe(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_discover(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_check(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn start(&self, _: Value) -> Result<Value, String> {
                self.started.store(true, Ordering::Release);
                while !self.cancelled.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(5));
                }
                Err("cancelled".into())
            }
            fn stop(&self) -> Result<Value, String> {
                self.cancelled.store(true, Ordering::Release);
                Ok(json!({}))
            }
        }
        let server = GuiServer::bind(0).unwrap();
        let addr = server.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let backend = Arc::new(Waiting {
            started: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        });
        let worker_backend = Arc::clone(&backend);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            server.run(worker_backend, shutdown).unwrap();
            let _ = tx.send(());
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let req=format!("POST /api/start HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",addr);
        stream.write_all(req.as_bytes()).unwrap();
        let limit = std::time::Instant::now() + Duration::from_secs(3);
        while !backend.started.load(Ordering::Acquire) && std::time::Instant::now() < limit {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(backend.started.load(Ordering::Acquire));
        stop.store(true, Ordering::Release);
        assert!(rx.recv_timeout(Duration::from_secs(3)).is_ok());
        worker.join().unwrap();
    }
    #[test]
    fn accepted_http_connection_waits_for_a_delayed_request() {
        let server = GuiServer::bind(0).unwrap();
        let addr = server.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || server.run(Arc::new(Fake), shutdown).unwrap());
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        thread::sleep(Duration::from_millis(150));
        stream
            .write_all(format!("GET /api/status HTTP/1.1\r\nHost: {}\r\n\r\n", addr).as_bytes())
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn a_slow_header_cannot_extend_the_request_deadline() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
            for _ in 0..40 {
                thread::sleep(Duration::from_millis(10));
                if stream.write_all(b"a").is_err() {
                    break;
                }
            }
        });
        let (mut server, _) = listener.accept().unwrap();
        let started = Instant::now();
        let response =
            read_request_with_deadline(&mut server, Duration::from_millis(150)).unwrap_err();
        assert_eq!(response.status, 408);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the request deadline took {:?}",
            started.elapsed()
        );
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn a_slow_body_cannot_extend_the_request_deadline() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 40\r\n\r\n")
                .unwrap();
            for _ in 0..40 {
                thread::sleep(Duration::from_millis(20));
                if stream.write_all(b"a").is_err() {
                    break;
                }
            }
        });
        let (mut server, _) = listener.accept().unwrap();
        let started = Instant::now();
        let response =
            read_request_with_deadline(&mut server, Duration::from_millis(150)).unwrap_err();
        assert_eq!(response.status, 408);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn a_buffered_request_body_is_read_in_full() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let request = read_request_with_deadline(&mut server, Duration::from_secs(1))
            .ok()
            .expect("the buffered request is valid");
        assert_eq!(request.body, b"hello");
    }

    #[test]
    fn a_client_that_does_not_read_cannot_hold_a_response_indefinitely() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let body = vec![0u8; 16 * 1024 * 1024];
        let started = Instant::now();
        let result = write_by_deadline(&mut server, &body, started + Duration::from_millis(150));
        assert!(result.is_err(), "the unread response should time out");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn partial_response_writes_share_one_deadline() {
        let mut data = &b"a long enough response"[..];
        let start = Instant::now();
        let mut writes = 0;
        let result = write_with_deadline(&mut data, start + Duration::from_millis(120), |_, _| {
            thread::sleep(Duration::from_millis(35));
            writes += 1;
            Ok(1)
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(writes > 1 && !data.is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn response_writes_are_bounded_per_call() {
        let body = vec![0u8; MAX_RESPONSE_WRITE_CHUNK * 2 + 1];
        let mut remaining = body.as_slice();
        let mut lengths = Vec::new();
        write_with_deadline(
            &mut remaining,
            Instant::now() + Duration::from_secs(1),
            |_, bytes| {
                lengths.push(bytes.len());
                Ok(bytes.len())
            },
        )
        .unwrap();
        assert_eq!(
            lengths,
            [MAX_RESPONSE_WRITE_CHUNK, MAX_RESPONSE_WRITE_CHUNK, 1]
        );
        assert!(remaining.is_empty());
    }

    #[test]
    fn an_authorized_request_is_served_while_a_slow_client_holds_a_slot() {
        let mut server = GuiServer::bind(0).unwrap();
        server.set_token([b'a'; 64]);
        let addr = server.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || server.run(Arc::new(Fake), shutdown).unwrap());
        let mut slow = TcpStream::connect(addr).unwrap();
        slow.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
        let (slow_stop, slow_rx) = std::sync::mpsc::channel();
        let slow_thread = thread::spawn(move || loop {
            match slow_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if slow.write_all(b"a").is_err() {
                        break;
                    }
                }
            }
        });
        thread::sleep(Duration::from_millis(50));
        let auth = format!("Authorization: Bearer {}\r\n", "a".repeat(64));
        let mut fast = TcpStream::connect(addr).unwrap();
        fast.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let started = Instant::now();
        fast.write_all(
            format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut response = String::new();
        fast.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the authorized request waited {:?}",
            started.elapsed()
        );
        stop.store(true, Ordering::Release);
        let _ = slow_stop.send(());
        slow_thread.join().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn shutdown_closes_a_slow_request_and_does_not_wait_for_it() {
        let server = GuiServer::bind(0).unwrap();
        let addr = server.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let (done, finished) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            server.run(Arc::new(Fake), shutdown).unwrap();
            let _ = done.send(());
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
        let (client_stop, client_stop_rx) = std::sync::mpsc::channel();
        let slow = thread::spawn(move || loop {
            match client_stop_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if client.write_all(b"a").is_err() {
                        break;
                    }
                }
            }
        });
        thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        stop.store(true, Ordering::Release);
        assert!(
            finished.recv_timeout(Duration::from_secs(3)).is_ok(),
            "the GUI did not stop after a slow client"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited {:?} for a slow request",
            started.elapsed()
        );
        let _ = client_stop.send(());
        slow.join().unwrap();
        worker.join().unwrap();
    }

    fn running_status(mode: &str, probe: &str, checked_at: u64) -> Value {
        json!({"running":true,"mode":mode,"iface":"en5",
            "phone":{"state":probe,"checked_at":checked_at}})
    }

    /// The interface rule for a platform that can observe the link. Tests on
    /// every host use this, so the Unix policy is checked on Windows too.
    fn observed_sample(
        status: &Value,
        link: Option<bool>,
        now_unix: u64,
        now: Instant,
        policy: &mut crate::autostop::AutoStopPolicy,
    ) -> Option<&'static str> {
        auto_stop_sample_watch(LinkWatch::Observable, status, link, now_unix, now, policy)
    }

    /// The rule for a platform that cannot prove the link, as on Windows. It
    /// never reports hotspot loss from the interface, but a fresh silent
    /// source device answer still counts.
    fn unobserved_sample(
        status: &Value,
        link: Option<bool>,
        now_unix: u64,
        now: Instant,
        policy: &mut crate::autostop::AutoStopPolicy,
    ) -> Option<&'static str> {
        auto_stop_sample_watch(LinkWatch::Unobservable, status, link, now_unix, now, policy)
    }

    #[test]
    fn auto_stop_policy_matches_the_status_shape() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // Link down for 20 seconds, not 19.
        let status = running_status("phone", "ready", 100);
        assert_eq!(
            observed_sample(&status, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(19),
                &mut policy
            ),
            None
        );
        assert_eq!(
            observed_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(20),
                &mut policy
            ),
            Some("hotspot_lost")
        );
        // A good sample resets the timer.
        policy.reset();
        assert_eq!(
            observed_sample(&status, Some(true), 100, t, &mut policy),
            None
        );
        // The source device is silent for 90 seconds, not 89.
        let silent = running_status("phone", "not_responding", 200);
        assert_eq!(
            observed_sample(&silent, Some(true), 200, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                200,
                t + Duration::from_secs(89),
                &mut policy
            ),
            None
        );
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                200,
                t + Duration::from_secs(90),
                &mut policy
            ),
            Some("source_device_gone")
        );
        // A good probe resets the device timer.
        let ready = running_status("phone", "ready", 300);
        assert_eq!(
            observed_sample(
                &ready,
                Some(true),
                300,
                t + Duration::from_secs(91),
                &mut policy
            ),
            None
        );
        let silent_late = running_status("phone", "not_responding", 301);
        assert_eq!(
            observed_sample(
                &silent_late,
                Some(true),
                301,
                t + Duration::from_secs(92),
                &mut policy
            ),
            None,
            "the timer starts again after a good sample"
        );
        assert_eq!(
            observed_sample(
                &silent_late,
                Some(true),
                301,
                t + Duration::from_secs(182),
                &mut policy
            ),
            Some("source_device_gone")
        );
    }

    #[test]
    fn a_stale_probe_breaks_continuous_source_device_silence() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        let silent = running_status("phone", "not_responding", 100);
        // A fresh failure starts the source device timer.
        assert_eq!(
            observed_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        // The probe is now stale. The link is up, so the link timer clears,
        // and the source device silence interval cannot span the gap.
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                150,
                t + Duration::from_secs(50),
                &mut policy
            ),
            None
        );
        // A fresh failure starts a new silence interval.
        let fresh = running_status("phone", "not_responding", 190);
        assert_eq!(
            observed_sample(
                &fresh,
                Some(true),
                190,
                t + Duration::from_secs(90),
                &mut policy
            ),
            None
        );
    }

    #[test]
    fn auto_stop_uses_only_answered_and_fresh_probe_states() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // An authenticated answer is presence. A plaintext `unpaired` or
        // `not_trusted` answer is not presence and does not start a stop by
        // itself, but the next tests show that it is bounded.
        for probe in ["ready", "proxy_off", "connected", "unpaired", "not_trusted"] {
            let status = running_status("phone", probe, 100);
            assert_eq!(
                observed_sample(&status, Some(true), 100, t, &mut policy),
                None,
                "{probe}"
            );
        }
        // A stale probe is no evidence. The link stays up, so no stop.
        let stale = running_status("phone", "not_responding", 100);
        for second in [0u64, 45, 90] {
            assert_eq!(
                observed_sample(
                    &stale,
                    Some(true),
                    200,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None
            );
        }
        // `no_hotspot` is a link failure even when the interface has an address.
        let lost = running_status("phone", "no_hotspot", 300);
        assert_eq!(
            observed_sample(&lost, Some(true), 300, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &lost,
                Some(true),
                300,
                t + Duration::from_secs(20),
                &mut policy
            ),
            Some("hotspot_lost")
        );
        // Direct mode ignores the phone probe.
        let direct = running_status("tun", "not_responding", 400);
        assert_eq!(
            observed_sample(&direct, Some(true), 400, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &direct,
                Some(true),
                400,
                t + Duration::from_secs(100),
                &mut policy
            ),
            None
        );
        // A tunnel that is starting or stopping has running = false.
        let stopped = json!({"running":false,"mode":null,"iface":null,
            "phone":{"state":"not_responding","checked_at":500}});
        assert_eq!(
            observed_sample(&stopped, Some(false), 500, t, &mut policy),
            None
        );
    }

    #[test]
    fn auto_stop_uses_fresh_presence_samples_while_the_page_is_idle() {
        use crate::autostop::AutoStopPolicy;
        let start = Instant::now();
        let mut policy = AutoStopPolicy::new();
        let mut stopped_at = None;
        // The presence observer probes every 2 seconds while the phone tunnel
        // runs. The page never reads the API. One bounded probe can need 4
        // seconds, so a result can be 6 seconds old and still be evidence.
        for second in (0..=94u64).step_by(2) {
            let wall = 1_000 + second;
            let status = running_status("phone", "not_responding", wall - 6);
            let reason = observed_sample(
                &status,
                Some(true),
                wall,
                start + Duration::from_secs(second),
                &mut policy,
            );
            if let Some(reason) = reason {
                stopped_at = Some((second, reason));
                break;
            }
        }
        assert_eq!(stopped_at, Some((90, "source_device_gone")));
    }

    #[test]
    fn auto_stop_ignores_unknown_and_missing_probe_data() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // No probe has completed. An empty probe section proves nothing about
        // the source device, so it must not stop the tunnel.
        let no_probe = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":null,"checked_at":null}});
        for second in [0u64, 30, 89, 90, 300] {
            assert_eq!(
                observed_sample(
                    &no_probe,
                    Some(true),
                    1_000,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // A state without a timestamp is unknown, not silence.
        let no_time = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":"not_responding"}});
        for second in [0u64, 90, 300] {
            assert_eq!(
                observed_sample(
                    &no_time,
                    Some(true),
                    1_000,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // A probe result that is too old is no evidence.
        let stale = running_status("phone", "not_responding", 1_000 - 11);
        assert_eq!(
            observed_sample(&stale, Some(true), 1_000, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &stale,
                Some(true),
                1_000,
                t + Duration::from_secs(200),
                &mut policy
            ),
            None
        );
        // A lost link is still evidence, even with no probe data.
        assert_eq!(
            observed_sample(&no_probe, Some(false), 1_000, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &no_probe,
                Some(false),
                1_000,
                t + Duration::from_secs(20),
                &mut policy
            ),
            Some("hotspot_lost")
        );
    }

    #[test]
    fn auto_stop_treats_an_unknown_link_as_no_evidence() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        let status = running_status("phone", "ready", 100);
        // A missing interface or a getifaddrs error is unknown. It must not
        // count as a link-down sample, even after a long time.
        for second in [0u64, 20, 90, 300] {
            assert_eq!(
                observed_sample(
                    &status,
                    None,
                    100,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // Unknown breaks the link failure interval. Loss must be observed
        // continuously for a new full interval after the gap.
        policy.reset();
        assert_eq!(
            observed_sample(&status, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(&status, None, 100, t + Duration::from_secs(10), &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(20),
                &mut policy
            ),
            None
        );
        assert_eq!(
            observed_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(40),
                &mut policy
            ),
            Some("hotspot_lost")
        );
        // Source silence also requires continuous evidence. An unknown link
        // cannot prove that the source device stayed unreachable.
        policy.reset();
        let silent = running_status("phone", "not_responding", 100);
        assert_eq!(
            observed_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(&silent, None, 100, t + Duration::from_secs(80), &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                100,
                t + Duration::from_secs(90),
                &mut policy
            ),
            None
        );
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                100,
                t + Duration::from_secs(180),
                &mut policy
            ),
            Some("source_device_gone")
        );
        // A fresh source device answer still reports its own hotspot loss.
        policy.reset();
        let lost = running_status("phone", "no_hotspot", 200);
        assert_eq!(observed_sample(&lost, None, 200, t, &mut policy), None);
        assert_eq!(
            observed_sample(&lost, None, 200, t + Duration::from_secs(20), &mut policy),
            Some("hotspot_lost")
        );
    }

    #[test]
    fn an_unobservable_link_still_counts_continuous_source_device_silence() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        // Windows reports unknown for every interface sample. A fresh silent
        // answer is still evidence, so the 90 second timer runs there too.
        for probe in ["not_running", "not_responding"] {
            let mut policy = AutoStopPolicy::new();
            let silent = running_status("phone", probe, 100);
            assert_eq!(
                unobserved_sample(&silent, None, 100, t, &mut policy),
                None,
                "{probe}"
            );
            assert_eq!(
                unobserved_sample(&silent, None, 100, t + Duration::from_secs(89), &mut policy),
                None,
                "{probe}"
            );
            assert_eq!(
                unobserved_sample(&silent, None, 100, t + Duration::from_secs(90), &mut policy),
                Some("source_device_gone"),
                "{probe}"
            );
        }
        // An interface answer is not proof on a platform that cannot observe
        // the link, so it never reports hotspot loss.
        let mut policy = AutoStopPolicy::new();
        let ready = running_status("phone", "ready", 100);
        for second in [0u64, 20, 300] {
            assert_eq!(
                unobserved_sample(
                    &ready,
                    Some(false),
                    100,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // Direct mode has no source device probe, so an unobservable link
        // gives no stop evidence.
        let mut policy = AutoStopPolicy::new();
        let direct = running_status("tun", "not_responding", 300);
        for second in [0u64, 90, 300] {
            assert_eq!(
                unobserved_sample(
                    &direct,
                    None,
                    300,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
    }

    #[test]
    fn an_unobservable_link_resets_on_answers_gaps_and_non_answers() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let silent = running_status("phone", "not_responding", 100);
        // A positive answer resets the silence interval, which then needs a
        // fresh full 90 seconds.
        let mut policy = AutoStopPolicy::new();
        let ready = running_status("phone", "ready", 100);
        assert_eq!(unobserved_sample(&silent, None, 100, t, &mut policy), None);
        assert_eq!(
            unobserved_sample(&ready, None, 100, t + Duration::from_secs(80), &mut policy),
            None
        );
        assert_eq!(
            unobserved_sample(&silent, None, 100, t + Duration::from_secs(91), &mut policy),
            None,
            "the timer starts again after a good answer"
        );
        assert_eq!(
            unobserved_sample(
                &silent,
                None,
                100,
                t + Duration::from_secs(180),
                &mut policy
            ),
            None
        );
        assert_eq!(
            unobserved_sample(
                &silent,
                None,
                100,
                t + Duration::from_secs(181),
                &mut policy
            ),
            Some("source_device_gone")
        );
        // A stale probe is no evidence, even after a long time.
        let mut policy = AutoStopPolicy::new();
        let stale = running_status("phone", "not_responding", 100);
        for second in [0u64, 90, 300] {
            assert_eq!(
                unobserved_sample(
                    &stale,
                    None,
                    200,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "stale {second}"
            );
        }
        // A missing probe section and a state without a timestamp are no
        // evidence either.
        let no_probe = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":null,"checked_at":null}});
        let no_time = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":"not_responding"}});
        for second in [0u64, 90, 300] {
            assert_eq!(
                unobserved_sample(
                    &no_probe,
                    None,
                    1_000,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "empty {second}"
            );
            assert_eq!(
                unobserved_sample(
                    &no_time,
                    None,
                    1_000,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "no time {second}"
            );
        }
        // `checking` is a plaintext answer. It does not reset a silence
        // interval, and a continuous run is bounded. The first sample after
        // the 120 second unverified grace starts the normal 90 second source
        // device timer.
        let checking = running_status("phone", "checking", 100);
        let mut policy = AutoStopPolicy::new();
        for second in [0u64, 119, 120, 209] {
            assert_eq!(
                unobserved_sample(
                    &checking,
                    None,
                    100,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        assert_eq!(
            unobserved_sample(
                &checking,
                None,
                100,
                t + Duration::from_secs(210),
                &mut policy
            ),
            Some("source_device_gone")
        );
        // `pin_unknown` is a local failure to probe, not a source answer. It
        // must not start a timer, and it breaks a silence interval.
        let pin_unknown = running_status("phone", "pin_unknown", 100);
        let mut policy = AutoStopPolicy::new();
        let silent = running_status("phone", "not_responding", 100);
        assert_eq!(unobserved_sample(&silent, None, 100, t, &mut policy), None);
        for second in [80u64, 180, 300] {
            assert_eq!(
                unobserved_sample(
                    &pin_unknown,
                    None,
                    100,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // An unobserved gap breaks the interval. Silence must be continuous
        // for a new full 90 seconds after the gap.
        let mut policy = AutoStopPolicy::new();
        assert_eq!(unobserved_sample(&silent, None, 100, t, &mut policy), None);
        assert_eq!(
            unobserved_sample(&silent, None, 150, t + Duration::from_secs(80), &mut policy),
            None,
            "the stale gap resets the timer"
        );
        assert_eq!(
            unobserved_sample(&silent, None, 100, t + Duration::from_secs(90), &mut policy),
            None
        );
        assert_eq!(
            unobserved_sample(
                &silent,
                None,
                100,
                t + Duration::from_secs(179),
                &mut policy
            ),
            None
        );
        assert_eq!(
            unobserved_sample(
                &silent,
                None,
                100,
                t + Duration::from_secs(180),
                &mut policy
            ),
            Some("source_device_gone")
        );
        // `no_hotspot` comes from local route discovery in the GUI. A platform
        // that cannot prove the link must not turn that into hotspot loss, so
        // it is another non-answer and resets the timers.
        let mut policy = AutoStopPolicy::new();
        let lost = running_status("phone", "no_hotspot", 200);
        for second in [0u64, 20, 300] {
            assert_eq!(
                unobserved_sample(
                    &lost,
                    None,
                    200,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // A stopped or starting tunnel clears the timers.
        let stopped = json!({"running":false,"mode":null,"iface":null,
            "phone":{"state":"not_responding","checked_at":300}});
        assert_eq!(unobserved_sample(&stopped, None, 300, t, &mut policy), None);
    }

    #[test]
    fn alternating_busy_and_timeout_stops_the_tunnel() {
        use crate::autostop::AutoStopPolicy;
        let start = Instant::now();
        for watch in [true, false] {
            let mut policy = AutoStopPolicy::new();
            let mut stopped = None;
            // A timeout starts the silence timer. Every other probe is a
            // plaintext Busy answer. Busy must not reset the timer, so the
            // alternating pair still stops at 90 seconds.
            for step in 0..=45u64 {
                let second = step * 2;
                let probe = if second % 4 == 0 {
                    "not_responding"
                } else {
                    "checking"
                };
                let wall = 1_000 + second;
                let status = running_status("phone", probe, wall);
                let now = start + Duration::from_secs(second);
                let reason = if watch {
                    observed_sample(&status, Some(true), wall, now, &mut policy)
                } else {
                    unobserved_sample(&status, None, wall, now, &mut policy)
                };
                if let Some(reason) = reason {
                    stopped = Some((second, reason));
                    break;
                }
            }
            assert_eq!(
                stopped,
                Some((90, "source_device_gone")),
                "observable watch {watch}"
            );
        }
    }

    #[test]
    fn continuous_plaintext_answers_are_bounded() {
        use crate::autostop::AutoStopPolicy;
        let start = Instant::now();
        for probe in ["checking", "unpaired", "not_trusted"] {
            for watch in [true, false] {
                let mut policy = AutoStopPolicy::new();
                let mut stopped = None;
                for second in 0..=210u64 {
                    let wall = 1_000 + second;
                    let status = running_status("phone", probe, wall);
                    let now = start + Duration::from_secs(second);
                    let reason = if watch {
                        observed_sample(&status, Some(true), wall, now, &mut policy)
                    } else {
                        unobserved_sample(&status, None, wall, now, &mut policy)
                    };
                    if let Some(reason) = reason {
                        stopped = Some((second, reason));
                        break;
                    }
                }
                assert_eq!(
                    stopped,
                    Some((210, "source_device_gone")),
                    "{probe} observable watch {watch}"
                );
            }
        }
    }

    #[test]
    fn a_plaintext_trust_claim_does_not_hold_off_auto_stop() {
        use crate::autostop::AutoStopPolicy;
        let start = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // A CHALLENGE known=1 claim is plaintext. It can be forged. It must
        // not count as an authenticated answer for the auto-stop policy.
        for second in 0..=210u64 {
            let wall = 1_000 + second;
            let status = json!({"running":true,"mode":"phone","iface":"en5",
                "phone":{"state":"unpaired","checked_at":wall,
                    "trusted_by_source":true}});
            let reason = observed_sample(
                &status,
                Some(true),
                wall,
                start + Duration::from_secs(second),
                &mut policy,
            );
            if second < 210 {
                assert_eq!(reason, None, "{second}");
            } else {
                assert_eq!(reason, Some("source_device_gone"));
            }
        }
    }

    #[test]
    fn an_authenticated_answer_clears_the_unverified_run() {
        use crate::autostop::AutoStopPolicy;
        let start = Instant::now();
        for watch in [true, false] {
            let mut policy = AutoStopPolicy::new();
            let feed = |policy: &mut AutoStopPolicy, second: u64, probe: &str| {
                let wall = 1_000 + second;
                let status = running_status("phone", probe, wall);
                let now = start + Duration::from_secs(second);
                if watch {
                    observed_sample(&status, Some(true), wall, now, policy)
                } else {
                    unobserved_sample(&status, None, wall, now, policy)
                }
            };
            for second in 0..=119u64 {
                assert_eq!(feed(&mut policy, second, "checking"), None, "{second}");
            }
            // A real authenticated status answer clears the unverified run.
            assert_eq!(feed(&mut policy, 120, "ready"), None);
            // The next unverified run starts again from zero.
            assert_eq!(feed(&mut policy, 121, "checking"), None);
            assert_eq!(feed(&mut policy, 240, "checking"), None);
            assert_eq!(feed(&mut policy, 241, "checking"), None);
            assert_eq!(feed(&mut policy, 330, "checking"), None);
            assert_eq!(
                feed(&mut policy, 331, "checking"),
                Some("source_device_gone"),
                "observable watch {watch}"
            );
        }
    }

    #[test]
    fn an_observable_unknown_link_keeps_the_unix_reset_policy() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let silent = running_status("phone", "not_responding", 100);
        // Unix treats an unknown interface as no evidence. Even a long run of
        // fresh silent probes cannot stop the tunnel from an unknown link.
        let mut policy = AutoStopPolicy::new();
        for second in [0u64, 90, 300] {
            assert_eq!(
                observed_sample(
                    &silent,
                    None,
                    100,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // With a proven link, the same silent probe stops at 90 seconds.
        let mut policy = AutoStopPolicy::new();
        assert_eq!(
            observed_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                100,
                t + Duration::from_secs(90),
                &mut policy
            ),
            Some("source_device_gone")
        );
    }

    #[test]
    fn the_platform_link_watch_matches_the_platform_observer() {
        #[cfg(windows)]
        {
            assert_eq!(PLATFORM_LINK_WATCH, LinkWatch::Unobservable);
            // The Windows observer must stay unknown until it passes review.
            assert_eq!(
                crate::autostop::link_observation("").unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
        }
        #[cfg(not(windows))]
        {
            use crate::autostop::AutoStopPolicy;
            assert_eq!(PLATFORM_LINK_WATCH, LinkWatch::Observable);
            // The production entry point keeps the Unix rule: an unknown link
            // is not evidence, even with a fresh silent probe.
            let t = Instant::now();
            let mut policy = AutoStopPolicy::new();
            let silent = running_status("phone", "not_responding", 100);
            assert_eq!(auto_stop_sample(&silent, None, 100, t, &mut policy), None);
            assert_eq!(
                auto_stop_sample(
                    &silent,
                    None,
                    100,
                    t + Duration::from_secs(300),
                    &mut policy
                ),
                None
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_gui_auto_stop_uses_source_device_silence() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        let silent = running_status("phone", "not_responding", 100);
        // The production entry point reads the platform watch. On Windows the
        // unknown link no longer resets the source device timer.
        assert_eq!(auto_stop_sample(&silent, None, 100, t, &mut policy), None);
        assert_eq!(
            auto_stop_sample(&silent, None, 100, t + Duration::from_secs(90), &mut policy),
            Some("source_device_gone")
        );
        // An unproven route answer never reports hotspot loss.
        let lost = running_status("phone", "no_hotspot", 100);
        let mut policy = AutoStopPolicy::new();
        assert_eq!(auto_stop_sample(&lost, None, 100, t, &mut policy), None);
        assert_eq!(
            auto_stop_sample(&lost, None, 100, t + Duration::from_secs(20), &mut policy),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn observe_link_reports_unknown_for_a_missing_or_invalid_interface() {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        assert_eq!(observe_link(Some(name)), Some(true));
        assert_eq!(observe_link(None), None);
        // An invalid name makes getifaddrs-backed validation fail. That is
        // unknown, not a link-down observation.
        assert_eq!(observe_link(Some("")), None);
    }

    #[cfg(windows)]
    #[test]
    fn observe_link_reports_unknown_for_an_invalid_windows_alias() {
        assert_eq!(observe_link(None), None);
        // An invalid alias is unknown, not a link-down observation.
        assert_eq!(observe_link(Some("")), None);
        // The experimental observer is gated, including for absent aliases.
        assert_eq!(observe_link(Some("hs-no-such-interface-8f3c1d7e")), None);
    }

    #[test]
    fn auto_stop_ignores_a_stale_ready_result_after_observer_failure() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // The observer failed. The backend reports unavailable with the old
        // probe time, so the auto-stop policy has no evidence to act on.
        let stale = running_status("phone", "not_responding", 100);
        for second in [0u64, 30, 89, 90, 300] {
            assert_eq!(
                observed_sample(
                    &stale,
                    Some(true),
                    200,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // A stale ready result is no evidence either.
        let stale_ready = running_status("phone", "ready", 100);
        for second in [0u64, 90, 300] {
            assert_eq!(
                observed_sample(
                    &stale_ready,
                    Some(true),
                    200,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        // A fresh answered silence is evidence.
        let fresh = running_status("phone", "not_responding", 300);
        assert_eq!(
            observed_sample(&fresh, Some(true), 300, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &fresh,
                Some(true),
                300,
                t + Duration::from_secs(90),
                &mut policy
            ),
            Some("source_device_gone")
        );
    }

    #[test]
    fn probe_freshness_is_ten_seconds() {
        assert!(probe_fresh(100, 100));
        assert!(probe_fresh(100, 110));
        assert!(!probe_fresh(100, 111));
        // A clock that moves back must not make an old result fresh.
        assert!(!probe_fresh(200, 100));
    }

    #[test]
    fn partial_observations_clear_only_the_recovered_timer() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let unknown_pin = running_status("phone", "pin_unknown", 100);
        let silence = running_status("phone", "not_responding", 100);
        let ready = running_status("phone", "ready", 100);
        let mut policy = AutoStopPolicy::new();
        assert_eq!(
            observed_sample(&unknown_pin, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &unknown_pin,
                Some(true),
                100,
                t + Duration::from_secs(10),
                &mut policy
            ),
            None
        );
        assert_eq!(
            observed_sample(
                &unknown_pin,
                Some(false),
                100,
                t + Duration::from_secs(20),
                &mut policy
            ),
            None
        );
        policy.reset();
        assert_eq!(
            observed_sample(&silence, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(&ready, None, 100, t + Duration::from_secs(45), &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &silence,
                Some(true),
                100,
                t + Duration::from_secs(90),
                &mut policy
            ),
            None
        );
    }

    #[test]
    fn a_new_run_discards_cached_monitor_status_and_timers() {
        use crate::autostop::{AutoStopPolicy, HotspotSample};
        let now = Instant::now();
        let mut policy = AutoStopPolicy::new();
        assert_eq!(policy.observe(now, HotspotSample::LinkDown), None);
        let mut last = Some(1);
        let mut status = Some(json!({"running":true,"iface":"old"}));
        assert!(reset_monitor_for_generation(
            &mut last,
            Some(2),
            Some(2),
            &mut status,
            &mut policy
        ));
        assert!(status.is_none());
        assert_eq!(
            policy.observe(now + Duration::from_secs(20), HotspotSample::LinkDown),
            None
        );
        status = Some(json!({"running":true}));
        assert!(!reset_monitor_for_generation(
            &mut last,
            Some(2),
            Some(3),
            &mut status,
            &mut policy
        ));
        assert!(status.is_none());
    }

    #[test]
    fn the_probe_cadence_keeps_each_answer_fresh() {
        // The Windows presence loop: a 2 second pause and one 4 second
        // deadline for the whole check.
        assert!(probe_cadence_fits(
            Duration::from_secs(2),
            Duration::from_secs(4)
        ));
        // Three 4 second per-operation timeouts can need 12 seconds. The
        // answer would go stale and reset the silence timer on every gap.
        assert!(!probe_cadence_fits(
            Duration::from_secs(2),
            Duration::from_secs(12)
        ));
        assert!(!probe_cadence_fits(
            Duration::from_secs(2),
            Duration::from_secs(7)
        ));
        assert!(!probe_cadence_fits(
            Duration::from_secs(2),
            Duration::from_millis(4_500)
        ));
    }

    fn mock_proxy(port: u16, timeout: Duration) -> crate::phone::PhoneProxy {
        crate::phone::PhoneProxy {
            address: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            username: "hotspotshade".into(),
            token: "public-test-token".into(),
            iface: None,
            timeout,
        }
    }

    #[test]
    fn a_presence_probe_has_one_overall_deadline() {
        // Each step of this source answers inside the probe timeout, so a
        // per-operation timeout would wait for all of them and report ready.
        // The overall deadline must end the probe first.
        let timeout = Duration::from_secs(1);
        let step = Duration::from_millis(800);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut hello = [0u8; 3];
            if socket.read_exact(&mut hello).is_err() {
                return;
            }
            thread::sleep(step);
            if socket.write_all(&[5, 2]).is_err() {
                return;
            }
            let mut auth = [0u8; 64];
            let _ = socket.read(&mut auth);
            thread::sleep(step);
            let _ = socket.write_all(&[1, 0]);
        });
        let started = Instant::now();
        let state = presence_probe(&mock_proxy(port, timeout), &AtomicBool::new(false));
        let elapsed = started.elapsed();
        assert_eq!(state, Some("not_responding"));
        assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
        assert!(elapsed < step * 2, "the probe took {elapsed:?}");
        let _ = server.join();
    }

    #[test]
    fn a_cancelled_presence_probe_is_not_an_answer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            // Accept and stay silent until the client closes.
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0u8; 64];
            while matches!(socket.read(&mut buffer), Ok(n) if n > 0) {}
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            flag.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let state = presence_probe(&mock_proxy(port, Duration::from_secs(10)), &cancel);
        assert_eq!(state, None);
        assert!(started.elapsed() < Duration::from_secs(2));
        canceller.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn a_presence_probe_reports_a_ready_source() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0u8; 3];
            socket.read_exact(&mut hello).unwrap();
            socket.write_all(&[5, 2]).unwrap();
            let mut head = [0u8; 2];
            socket.read_exact(&mut head).unwrap();
            let mut rest = vec![0u8; head[1] as usize + 1];
            socket.read_exact(&mut rest).unwrap();
            let mut token = vec![0u8; rest[head[1] as usize] as usize];
            socket.read_exact(&mut token).unwrap();
            socket.write_all(&[1, 0]).unwrap();
        });
        let state = presence_probe(
            &mock_proxy(port, Duration::from_secs(2)),
            &AtomicBool::new(false),
        );
        assert_eq!(state, Some("ready"));
        server.join().unwrap();
    }

    /// A fake service for the run-scope tests: one flag under one lock, like
    /// the Windows service inner state.
    #[derive(Default)]
    struct FakeService {
        active: Mutex<bool>,
        stops: AtomicUsize,
    }

    impl FakeService {
        fn is_running(&self) -> bool {
            *self.active.lock().unwrap()
        }
        fn set(&self, value: bool) {
            *self.active.lock().unwrap() = value;
        }
        fn stop(&self) {
            self.stops.fetch_add(1, Ordering::AcqRel);
            self.set(false);
        }
    }

    fn start_ok(presence: &RunPresence, service: &FakeService) -> u64 {
        presence
            .start(
                || service.is_running(),
                |_| {
                    service.set(true);
                    Ok::<(), &str>(())
                },
                || service.stop(),
                |run| {
                    presence.record(run, "connected", 1);
                },
            )
            .unwrap()
    }

    fn stop_run(presence: &RunPresence, service: &FakeService, expected: Option<u64>) -> RunStop {
        presence.stop(expected, || service.is_running(), || service.stop(), |_| ())
    }

    #[test]
    fn a_probe_from_an_older_run_cannot_mark_a_restarted_run() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let old = start_ok(&presence, &service);
        assert!(presence.record(old, "ready", 10));
        // A slow probe began under the old run. The tunnel stops and starts
        // again before it finishes.
        assert_eq!(stop_run(&presence, &service, Some(old)), RunStop::Stopped);
        assert_eq!(presence.snapshot(), (None, None));
        let run = start_ok(&presence, &service);
        assert_eq!(presence.snapshot(), (Some("connected"), Some(1)));
        assert!(!presence.record(old, "not_responding", 21));
        assert_eq!(presence.snapshot(), (Some("connected"), Some(1)));
        assert!(presence.record(run, "ready", 22));
    }

    #[test]
    fn a_start_on_an_idle_service_changes_the_run_around_the_attempt() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let idle = presence.run();
        let seen = std::cell::Cell::new(0);
        let result = presence.start(
            || service.is_running(),
            |_| {
                seen.set(presence.run());
                Err::<(), &str>("failed")
            },
            || panic!("nothing to abandon"),
            |_| panic!("a failed start is not started"),
        );
        assert_eq!(result, Err(RunStartError::Service("failed")));
        // A status read during the attempt has a run id that matches neither
        // the idle run nor the run after it, so the monitor discards it.
        assert_ne!(seen.get(), idle);
        assert_ne!(seen.get(), presence.run());
    }

    #[test]
    fn a_refused_start_keeps_the_live_run_and_its_answer() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let live = start_ok(&presence, &service);
        assert!(presence.record(live, "not_responding", 50));
        let seen = std::cell::Cell::new(0);
        let result = presence.start(
            || service.is_running(),
            |_| {
                seen.set(presence.run());
                Err::<(), &str>("already running")
            },
            || panic!("nothing to abandon"),
            |_| panic!("a refused start is not started"),
        );
        assert_eq!(result, Err(RunStartError::Service("already running")));
        // The live run keeps its id and its fresh silent answer, so the
        // automatic-stop timers are not reset.
        assert_eq!(seen.get(), live);
        assert_eq!(presence.run(), live);
        assert_eq!(presence.snapshot(), (Some("not_responding"), Some(50)));
    }

    #[test]
    fn a_start_after_a_self_ended_run_gets_a_new_run() {
        // The service looked busy, but its worker ended before the start, so
        // the start succeeded. The new tunnel must not share the old run id.
        let presence = RunPresence::new();
        let service = FakeService::default();
        let old = start_ok(&presence, &service);
        let run = presence
            .start(
                || true,
                |_| Ok::<(), &str>(()),
                || panic!("not interrupted"),
                |_| (),
            )
            .unwrap();
        assert_ne!(run, old);
        assert!(!presence.record(old, "not_responding", 3));
    }

    #[test]
    fn a_stop_during_a_start_wins_over_a_late_success() {
        // The service start finished, but a stop ran before the start
        // reported. The start must not report success or record `connected`.
        let presence = RunPresence::new();
        let service = FakeService::default();
        let reported = AtomicBool::new(false);
        let result = presence.start(
            || service.is_running(),
            |cancel| {
                service.set(true);
                assert_eq!(stop_run(&presence, &service, None), RunStop::Stopped);
                assert!(cancel.load(Ordering::Acquire));
                Ok::<(), &str>(())
            },
            || service.stop(),
            |_| reported.store(true, Ordering::Release),
        );
        assert_eq!(result, Err(RunStartError::Interrupted));
        assert!(!reported.load(Ordering::Acquire));
        assert!(!service.is_running());
        assert_eq!(presence.snapshot(), (None, None));
    }

    #[test]
    fn a_stop_before_the_service_start_cancels_it() {
        // The stop arrives after the attempt began but before the service took
        // its lock. The service sees the cancel flag and starts nothing.
        let presence = RunPresence::new();
        let service = FakeService::default();
        let result = presence.start(
            || service.is_running(),
            |cancel| {
                assert_eq!(stop_run(&presence, &service, None), RunStop::Idle);
                if cancel.load(Ordering::Acquire) {
                    return Err("start cancelled");
                }
                service.set(true);
                Ok(())
            },
            || service.stop(),
            |_| panic!("a cancelled start is not started"),
        );
        assert_eq!(result, Err(RunStartError::Interrupted));
        assert!(!service.is_running());
    }

    #[test]
    fn a_stop_waits_for_a_start_that_holds_the_service() {
        // A start holds the service lock for its whole attempt. A stop that
        // arrives then cancels the attempt and waits; it never reports a stop
        // while the new tunnel keeps running.
        let presence = Arc::new(RunPresence::new());
        let service = Arc::new(FakeService::default());
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let starter = {
            let presence = Arc::clone(&presence);
            let service = Arc::clone(&service);
            thread::spawn(move || {
                presence.start(
                    || service.is_running(),
                    |cancel| {
                        let mut active = service.active.lock().unwrap();
                        held_tx.send(()).unwrap();
                        let until = Instant::now() + Duration::from_secs(5);
                        while !cancel.load(Ordering::Acquire) && Instant::now() < until {
                            thread::sleep(Duration::from_millis(10));
                        }
                        // Like the Windows start, a cancelled attempt cleans
                        // up and reports the cancellation.
                        *active = false;
                        Err::<(), &str>("start cancelled")
                    },
                    || service.stop(),
                    |_| panic!("a cancelled start is not started"),
                )
            })
        };
        held_rx.recv().unwrap();
        let outcome = stop_run(&presence, &service, None);
        assert_eq!(outcome, RunStop::Idle);
        assert_eq!(starter.join().unwrap(), Err(RunStartError::Interrupted));
        assert!(!service.is_running());
    }

    #[test]
    fn close_cancels_a_start_and_refuses_the_next_one() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let result = presence.start(
            || service.is_running(),
            |_| {
                service.set(true);
                presence.close();
                Ok::<(), &str>(())
            },
            || service.stop(),
            |_| panic!("a cancelled start is not started"),
        );
        assert_eq!(result, Err(RunStartError::Interrupted));
        // The abandoned tunnel was stopped.
        assert!(!service.is_running());
        assert_eq!(
            presence.start(
                || false,
                |_| -> Result<(), &str> { panic!("a closed backend starts nothing") },
                || (),
                |_| (),
            ),
            Err(RunStartError::Closed)
        );
    }

    #[test]
    fn only_one_start_attempt_runs_at_a_time() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let inner = std::cell::Cell::new(None);
        let outer = presence.start(
            || service.is_running(),
            |_| {
                inner.set(Some(presence.start(
                    || false,
                    |_| -> Result<(), &str> { panic!("a second attempt must not run") },
                    || (),
                    |_| (),
                )));
                service.set(true);
                Ok::<(), &str>(())
            },
            || service.stop(),
            |_| (),
        );
        assert!(outer.is_ok());
        assert_eq!(inner.take(), Some(Err(RunStartError::Busy)));
    }

    #[test]
    fn a_stale_auto_stop_does_not_touch_a_restarted_run() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let observed = start_ok(&presence, &service);
        // The person stops and starts the tunnel while the monitor holds an
        // observation of the first run.
        stop_run(&presence, &service, None);
        start_ok(&presence, &service);
        let before = service.stops.load(Ordering::Acquire);
        let published = AtomicBool::new(false);
        assert_eq!(
            presence.stop(
                Some(observed),
                || service.is_running(),
                || service.stop(),
                |_| published.store(true, Ordering::Release),
            ),
            RunStop::Stale
        );
        assert_eq!(service.stops.load(Ordering::Acquire), before);
        assert!(service.is_running());
        assert!(!published.load(Ordering::Acquire));
    }

    #[test]
    fn an_idle_auto_stop_is_not_a_stop() {
        let presence = RunPresence::new();
        let service = FakeService::default();
        let run = presence.run();
        let outcome = std::cell::Cell::new(None);
        // The service still runs its idempotent stop so a finished worker is
        // reaped, but the outcome says no run was stopped.
        assert_eq!(
            presence.stop(
                Some(run),
                || service.is_running(),
                || service.stop(),
                |stopped| outcome.set(Some(stopped)),
            ),
            RunStop::Idle
        );
        assert_eq!(service.stops.load(Ordering::Acquire), 1);
        assert_eq!(outcome.get(), Some(RunStop::Idle));
    }

    #[test]
    fn a_restart_cannot_slip_between_the_run_check_and_the_stop() {
        // The auto stop checks its run and then stops. A start that arrives in
        // that window must wait, so the stop never hits the new run.
        let presence = Arc::new(RunPresence::new());
        let service = Arc::new(FakeService::default());
        let observed = start_ok(&presence, &service);
        let order = Arc::new(Mutex::new(Vec::new()));
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let starter = {
            let presence = Arc::clone(&presence);
            let service = Arc::clone(&service);
            let order = Arc::clone(&order);
            thread::spawn(move || {
                go_rx.recv().unwrap();
                presence.start(
                    || service.is_running(),
                    |_| {
                        order.lock().unwrap().push("start");
                        service.set(true);
                        Ok::<(), &str>(())
                    },
                    || service.stop(),
                    |_| (),
                )
            })
        };
        let outcome = presence.stop(
            Some(observed),
            || {
                // Let the restart begin, then give it time to try to run.
                go_tx.send(()).unwrap();
                thread::sleep(Duration::from_millis(150));
                service.is_running()
            },
            || {
                order.lock().unwrap().push("stop");
                service.stop();
            },
            |_| (),
        );
        assert_eq!(outcome, RunStop::Stopped);
        let new_run = starter.join().unwrap().unwrap();
        assert_eq!(*order.lock().unwrap(), vec!["stop", "start"]);
        assert!(service.is_running());
        // The old observation cannot stop the new run.
        assert_eq!(
            presence.stop(
                Some(observed),
                || true,
                || panic!("stopped a new run"),
                |_| ()
            ),
            RunStop::Stale
        );
        assert_eq!(presence.run(), new_run);
    }

    #[test]
    fn the_last_stop_record_has_the_shared_status_shape() {
        let mut status = json!({"running":false,
            "last_stop":{"reason":null,"at":null}});
        apply_last_stop(&mut status, Some(("source_device_gone", 42)));
        assert_eq!(status["last_stop"]["reason"], "source_device_gone");
        assert_eq!(status["last_stop"]["at"], 42);
        assert_eq!(
            status["last_stop_message"],
            crate::autostop::stop_message("source_device_gone").unwrap()
        );
        let mut status = json!({"running":false,
            "last_stop":{"reason":"hotspot_lost","at":7}});
        apply_last_stop(&mut status, None);
        assert_eq!(status["last_stop"]["reason"], "hotspot_lost");
        assert_eq!(
            status["last_stop_message"],
            crate::autostop::stop_message("hotspot_lost").unwrap()
        );
        let mut status = json!({"running":false});
        apply_last_stop(&mut status, None);
        assert!(status["last_stop"]["reason"].is_null());
        assert!(status["last_stop"]["at"].is_null());
        assert!(status["last_stop_message"].is_null());
    }

    #[test]
    fn a_status_error_does_not_disable_link_monitoring() {
        use crate::autostop::AutoStopPolicy;
        let running = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":"ready","checked_at":1_000}});
        let stopped = json!({"running":false,"mode":null,"iface":null,
            "phone":{"state":null,"checked_at":null}});
        let mut last = None;
        // A good answer is stored.
        assert_eq!(
            auto_stop_status(&mut last, Ok(running.clone()))["running"],
            true
        );
        // A status error keeps the last good answer. It must not look like a
        // stopped tunnel and reset the auto-stop timers.
        assert_eq!(
            auto_stop_status(&mut last, Err("helper_timeout".into()))["running"],
            true
        );
        assert_eq!(
            auto_stop_status(&mut last, Err("helper_timeout".into()))["iface"],
            "en5"
        );
        // The link timer still fires while the status path keeps failing.
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        assert_eq!(
            observed_sample(&running, Some(false), 1_000, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &running,
                Some(false),
                1_000,
                t + Duration::from_secs(20),
                &mut policy
            ),
            Some("hotspot_lost")
        );
        // A good stopped answer replaces the stored running answer, so a later
        // error cannot keep monitoring a stopped run.
        assert_eq!(
            auto_stop_status(&mut last, Ok(stopped.clone()))["running"],
            false
        );
        assert_eq!(
            auto_stop_status(&mut last, Err("helper_timeout".into()))["running"],
            false
        );
    }

    #[test]
    fn an_unknown_pin_is_not_a_good_source_device_sample() {
        use crate::autostop::AutoStopPolicy;
        let status = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":"pin_unknown","checked_at":100}});
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // The probe did not run because the pin is unknown. It is not a good
        // sample, so it does not start a source-device timer.
        for second in [0u64, 90, 300] {
            assert_eq!(
                observed_sample(
                    &status,
                    Some(true),
                    100,
                    t + Duration::from_secs(second),
                    &mut policy
                ),
                None,
                "{second}"
            );
        }
        let silent = json!({"running":true,"mode":"phone","iface":"en5",
            "phone":{"state":"not_responding","checked_at":100}});
        let mut policy = AutoStopPolicy::new();
        assert_eq!(
            observed_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &status,
                Some(true),
                100,
                t + Duration::from_secs(80),
                &mut policy
            ),
            None
        );
        assert_eq!(
            observed_sample(
                &silent,
                Some(true),
                100,
                t + Duration::from_secs(91),
                &mut policy
            ),
            None
        );
        // The link check is still evidence.
        assert_eq!(
            observed_sample(&status, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            observed_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(20),
                &mut policy
            ),
            Some("hotspot_lost")
        );
        assert_eq!(
            phone_message("pin_unknown"),
            "The tunnel interface is unknown. Turn the tunnel off and on."
        );
    }

    #[test]
    fn auto_stop_observer_calls_the_stop_path_once() {
        use crate::autostop::AutoStopPolicy;
        struct AutoFake {
            running: AtomicBool,
            stops: AtomicUsize,
        }
        impl GuiBackend for AutoFake {
            fn status(&self) -> Result<Value, String> {
                Ok(json!({"running":self.running.load(Ordering::Acquire),
                    "mode":"phone","iface":"en5",
                    "phone":{"state":"ready","checked_at":now_unix()}}))
            }
            fn probe(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_discover(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_check(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn start(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn stop(&self) -> Result<Value, String> {
                self.stops.fetch_add(1, Ordering::AcqRel);
                self.running.store(false, Ordering::Release);
                Ok(json!({"stopped":true}))
            }
            fn stop_for(&self, _: &'static str) -> Result<Value, String> {
                self.stop()
            }
        }
        let fake = AutoFake {
            running: AtomicBool::new(true),
            stops: AtomicUsize::new(0),
        };
        let mut policy = AutoStopPolicy::with_limits(Duration::ZERO, Duration::ZERO);
        let mut loops = 0;
        for _ in 0..3 {
            let status = fake.status().unwrap();
            let reason = observed_sample(
                &status,
                Some(false),
                now_unix(),
                Instant::now(),
                &mut policy,
            );
            if let Some(reason) = reason {
                fake.stop_for(reason).unwrap();
                loops += 1;
            }
        }
        assert_eq!(loops, 1);
        assert_eq!(fake.stops.load(Ordering::Acquire), 1);
        // No stop when the tunnel is already off.
        assert_eq!(
            observed_sample(
                &fake.status().unwrap(),
                Some(false),
                now_unix(),
                Instant::now(),
                &mut policy
            ),
            None
        );
        assert_eq!(fake.stops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn diagnostics_route_has_the_contract_shape() {
        let host = "127.0.0.1:8787";
        let response = route(
            req("GET", "/api/diagnostics", host, None, None, b""),
            host,
            &Fake,
        );
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["running"], false);
        assert_eq!(value["engine"]["version"], env!("CARGO_PKG_VERSION"));
        for key in ["connect_ms", "greeting_ms", "auth_ms", "request_ms"] {
            assert_eq!(value["setup"][key]["count"], 0);
        }
        assert_eq!(value["queues"]["input"][0]["peak"], 0);
        assert_eq!(value["queues"]["output"]["max_age_us"], 0);
        assert_eq!(value["udp"]["age_drops"], 0);
        assert_eq!(value["tcp"]["retransmits"], 0);
        assert_eq!(value["failures"]["total"], 0);
        assert!(!value.to_string().contains("token"));
    }

    #[test]
    fn probe_route_requires_json_and_returns_the_phone_shape() {
        struct Probe;
        impl GuiBackend for Probe {
            fn status(&self) -> Result<Value, String> {
                Ok(json!({"running":false}))
            }
            fn probe(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_discover(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_check(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn start(&self, _: Value) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn stop(&self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn phone_probe(&self) -> Result<Value, String> {
                Ok(json!({"ok":true,"phone":{"state":"ready","checked_at":7,
                    "trusted_by_source":null}}))
            }
        }
        let host = "127.0.0.1:8787";
        // An empty POST is accepted, like /api/stop. A non-JSON body is not.
        let plain = route(
            req("POST", "/api/phone/probe", host, None, None, b""),
            host,
            &Probe,
        );
        assert_eq!(plain.status, 200);
        let wrong_type = route(
            req(
                "POST",
                "/api/phone/probe",
                host,
                None,
                Some("text/plain"),
                b"{}",
            ),
            host,
            &Probe,
        );
        assert_eq!(wrong_type.status, 415);
        let response = route(
            req(
                "POST",
                "/api/phone/probe",
                host,
                None,
                Some("application/json"),
                b"{}",
            ),
            host,
            &Probe,
        );
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["phone"]["state"], "ready");
        assert_eq!(value["phone"]["checked_at"], 7);
    }

    /// The macOS app's Turn on writes the pairing handoff through this route.
    /// A trait override that is compiled out on macOS answers with the trait
    /// default, `handoff_unsupported`, and the start fails. Drive the real
    /// route with the real user-engine backend.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn pairing_handoff_route_reaches_the_user_engine_backend() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        let host = "127.0.0.1:8787";
        let backend =
            crate::gui_backend::RustGuiBackend::new(Arc::new(crate::service::Service::new()));
        backend.set_handoff_identity([0x42; 32]);
        let (writer, reader) = UnixStream::pair().unwrap();
        backend.set_handoff_fd(writer.into_raw_fd());
        let handoff = || {
            route(
                req(
                    "POST",
                    "/api/pairing/handoff",
                    host,
                    None,
                    Some("application/json"),
                    b"{}",
                ),
                host,
                &backend,
            )
        };
        // Before a pairing the backend answers with its own refusal, not the
        // trait default.
        let unpaired = handoff();
        let text = String::from_utf8_lossy(&unpaired.body).to_string();
        assert_eq!(unpaired.status, 409, "{text}");
        assert!(!text.contains("handoff_unsupported"), "{text}");
        backend.set_pairing_for_test(crate::pairing::PhoneCredentials {
            host: std::net::Ipv4Addr::new(172, 20, 10, 1),
            port: 18080,
            token: "public-route-test-token".into(),
        });
        let answer = handoff();
        let text = String::from_utf8_lossy(&answer.body).to_string();
        assert_eq!(answer.status, 200, "{text}");
        assert!(!text.contains("handoff_unsupported"), "{text}");
        assert!(!text.contains("public-route-test-token"), "{text}");
        let value: Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(value["ok"], true);
        let read_fd = reader.into_raw_fd();
        let (identity, credentials) =
            crate::credential_handoff::read_handoff(read_fd).expect("one valid handoff frame");
        unsafe {
            libc::close(read_fd);
        }
        assert_eq!(
            identity.public(),
            crate::pairing::Identity::from_bytes([0x42; 32]).public()
        );
        assert_eq!(credentials.host, std::net::Ipv4Addr::new(172, 20, 10, 1));
        assert_eq!(credentials.port, 18080);
        assert_eq!(credentials.token, "public-route-test-token");
    }
}

#[cfg(test)]
mod secret_debug_tests {
    use super::*;

    #[test]
    fn request_debug_shows_header_names_and_body_length_only() {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Bearer secret-bearer-value".to_string(),
        );
        headers.insert("host".to_string(), "127.0.0.1:8787".to_string());
        let request = Request {
            method: "POST".into(),
            target: "/api/phone/check".into(),
            headers,
            body: br#"{"token":"secret-body-token"}"#.to_vec(),
        };
        let text = format!("{request:?}");
        assert!(!text.contains("secret-bearer-value"), "{text}");
        assert!(!text.contains("secret-body-token"), "{text}");
        assert!(!text.contains("127.0.0.1:8787"), "{text}");
        assert!(text.contains("POST"));
        assert!(text.contains("/api/phone/check"));
        assert!(text.contains("authorization"));
        assert!(text.contains("host"));
        assert!(text.contains(&format!("body_len: {}", request.body.len())));
    }

    #[test]
    fn redaction_covers_nested_credential_names() {
        let mut value =
            json!({"a": {"credential": "secret-c", "b": [{"api_key": "secret-k", "ok": 1}]}});
        redact(&mut value);
        assert_eq!(value["a"]["credential"], "[redacted]");
        assert_eq!(value["a"]["b"][0]["api_key"], "[redacted]");
        assert_eq!(value["a"]["b"][0]["ok"], 1);
    }
}
