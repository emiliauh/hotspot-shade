//! Local HTTP bridge for the hotspotshade UI.
//!
//! The backend owns service lifecycle and network operations. It must not put
//! credentials in status, logs, or returned values. The HTTP server does not
//! log request bodies or backend errors.
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const INDEX: &[u8] = include_bytes!("../../gui_assets/index.html");
const STYLE: &[u8] = include_bytes!("../../gui_assets/styles.css");
const SCRIPT: &[u8] = include_bytes!("../../gui_assets/app.js");
const FAVICON: &[u8] = include_bytes!("../../assets/logo/favicon.svg");

/// Map a service error code to text for the browser. Return None for an
/// unknown code so the caller can show a generic message.
pub(crate) fn start_error_message(code: &str) -> Option<&'static str> {
    match code {
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
        "windows_phone_only" => {
            Some("This Windows build runs source device proxy mode only.")
        }
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

/// A source device probe result stays current for this long. The observer
/// probes every 2 seconds while a source device tunnel runs. One bounded probe
/// can need 4 seconds, so a result can be 6 seconds old and still be evidence.
/// The auto-stop policy and the status answer use the same limit.
pub(crate) const PROBE_FRESH: Duration = Duration::from_secs(10);

/// True when a probe result with this wall clock time is still current. A
/// timestamp from the future is not current: the clock moved back and the age
/// is unknown.
pub(crate) fn probe_fresh(checked_at: u64, now_unix: u64) -> bool {
    checked_at <= now_unix && now_unix - checked_at <= PROBE_FRESH.as_secs()
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
}

#[derive(Debug)]
struct Request {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
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

fn read_request(stream: &mut TcpStream) -> Result<Request, Response> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| error(400, "request failed"))?;
    let mut reader = BufReader::new(stream);
    let mut header = Vec::new();
    loop {
        if header.len() >= MAX_HEADER {
            return Err(error(431, "request headers too large"));
        }
        let mut b = [0u8; 1];
        if reader.read_exact(&mut b).is_err() {
            return Err(error(400, "invalid request"));
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
    reader
        .read_exact(&mut body)
        .map_err(|_| error(400, "incomplete request body"))?;
    Ok(Request {
        method: method.into(),
        target: target.into(),
        headers,
        body,
    })
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                let lower = key.to_ascii_lowercase();
                if lower.contains("token")
                    || lower.contains("password")
                    || lower.contains("authorization")
                    || lower.contains("secret")
                {
                    *value = Value::String("[redacted]".into());
                } else {
                    redact(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item);
            }
        }
        _ => (),
    }
}
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
                    Err(_) => error(400, "The service could not stop."),
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
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
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
    let _ = stream.write_all(header.as_bytes());
    if !head {
        let _ = stream.write_all(&response.body);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Observe the link state for one interface name. `None` means unknown: the
/// name is missing, or `getifaddrs` failed. An unknown link is not link loss.
fn observe_link(iface: Option<&str>) -> Option<bool> {
    #[cfg(unix)]
    {
        iface.and_then(|name| crate::autostop::link_observation(name).ok())
    }
    #[cfg(not(unix))]
    {
        iface.map(|_| true)
    }
}

/// Feed one status answer to the auto-stop policy.
///
/// The link observation is separate, so a test can replace it. `None` means
/// unknown. An unknown link breaks a continuous failure interval: a missing
/// interface or a `getifaddrs` error is not proof that the link stayed down.
/// A phone probe result counts only while it is fresh.
fn auto_stop_sample(
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
    let sample = match link {
        Some(true) if phone && probe.is_none() => {
            // The link is up, but no fresh source device answer exists. This
            // cannot establish continuous silence across the gap.
            policy.link_recovered();
            policy.source_device_unobserved();
            return None;
        }
        Some(link_up) => {
            // An unresolved tunnel pin is not an answer about the source
            // device. A `checking` result is also a non-answer. Neither can
            // establish continuous source device silence across this gap.
            if link_up && matches!(probe, Some("checking" | "pin_unknown")) {
                policy.link_recovered();
                policy.source_device_unobserved();
                return None;
            }
            crate::autostop::sample_from(link_up, phone, probe)
        }
        // The source device can still report that its own hotspot is off. That
        // is real evidence even when the local interface lookup failed.
        None if phone && probe == Some("no_hotspot") => crate::autostop::HotspotSample::LinkDown,
        // No link evidence. Do not count an unobserved gap as continuous loss.
        None => {
            policy.reset();
            return None;
        }
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
            // link-down sample. An auto stop must not invent link loss.
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
    /// Stop accepting when `stop` becomes true. Each request has a timeout.
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
                    let b = Arc::clone(&backend);
                    let n = Arc::clone(&active);
                    let h = expected.clone();
                    let closing = Arc::clone(&stop);
                    let token = self.token.clone();
                    match thread::Builder::new()
                        .name("hotspotshade-http".into())
                        .spawn(move || {
                            struct Guard(Arc<AtomicUsize>);
                            impl Drop for Guard {
                                fn drop(&mut self) {
                                    self.0.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                            let _guard = Guard(n);
                            respond(stream, b, h, closing, token);
                        }) {
                        Ok(worker) => workers.push(worker),
                        Err(_) => {
                            active.fetch_sub(1, Ordering::AcqRel);
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
        // Cancel a pending authorization before waiting for request threads.
        let _ = backend.stop();
        let _ = backend.pair_cancel();
        for worker in workers {
            let _ = worker.join();
        }
        // A request can race with the first stop. Stop it after it completes.
        let _ = backend.stop();
        if let Some(auto) = auto {
            let _ = auto.join();
        }
        Ok(())
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
                Ok(json!({}))
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

    fn running_status(mode: &str, probe: &str, checked_at: u64) -> Value {
        json!({"running":true,"mode":mode,"iface":"en5",
            "phone":{"state":probe,"checked_at":checked_at}})
    }

    #[test]
    fn auto_stop_policy_matches_the_status_shape() {
        use crate::autostop::AutoStopPolicy;
        let t = Instant::now();
        let mut policy = AutoStopPolicy::new();
        // Link down for 20 seconds, not 19.
        let status = running_status("phone", "ready", 100);
        assert_eq!(
            auto_stop_sample(&status, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(19),
                &mut policy
            ),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&status, Some(true), 100, t, &mut policy),
            None
        );
        // The source device is silent for 90 seconds, not 89.
        let silent = running_status("phone", "not_responding", 200);
        assert_eq!(
            auto_stop_sample(&silent, Some(true), 200, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
                &silent,
                Some(true),
                200,
                t + Duration::from_secs(89),
                &mut policy
            ),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(
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
            auto_stop_sample(
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
            auto_stop_sample(
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
            auto_stop_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        // The probe is now stale. The link is up, so the link timer clears,
        // and the source device silence interval cannot span the gap.
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(
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
        // Rejected is not a probe answer: the target device has no trust.
        for probe in ["ready", "proxy_off", "connected", "unpaired", "not_trusted"] {
            let status = running_status("phone", probe, 100);
            assert_eq!(
                auto_stop_sample(&status, Some(true), 100, t, &mut policy),
                None,
                "{probe}"
            );
        }
        // A stale probe is no evidence. The link stays up, so no stop.
        let stale = running_status("phone", "not_responding", 100);
        for second in [0u64, 45, 90] {
            assert_eq!(
                auto_stop_sample(
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
            auto_stop_sample(&lost, Some(true), 300, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&direct, Some(true), 400, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&stopped, Some(false), 500, t, &mut policy),
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
            let reason = auto_stop_sample(
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
                auto_stop_sample(
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
                auto_stop_sample(
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
            auto_stop_sample(&stale, Some(true), 1_000, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&no_probe, Some(false), 1_000, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
                auto_stop_sample(
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
            auto_stop_sample(&status, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(&status, None, 100, t + Duration::from_secs(10), &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
                &status,
                Some(false),
                100,
                t + Duration::from_secs(20),
                &mut policy
            ),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(&silent, None, 100, t + Duration::from_secs(80), &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
                &silent,
                Some(true),
                100,
                t + Duration::from_secs(90),
                &mut policy
            ),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
        assert_eq!(auto_stop_sample(&lost, None, 200, t, &mut policy), None);
        assert_eq!(
            auto_stop_sample(&lost, None, 200, t + Duration::from_secs(20), &mut policy),
            Some("hotspot_lost")
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
                auto_stop_sample(
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
                auto_stop_sample(
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
            auto_stop_sample(&fresh, Some(true), 300, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&unknown_pin, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
                &unknown_pin,
                Some(true),
                100,
                t + Duration::from_secs(10),
                &mut policy
            ),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&silence, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(&ready, None, 100, t + Duration::from_secs(45), &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&running, Some(false), 1_000, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
                auto_stop_sample(
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
            auto_stop_sample(&silent, Some(true), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
                &status,
                Some(true),
                100,
                t + Duration::from_secs(80),
                &mut policy
            ),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            auto_stop_sample(&status, Some(false), 100, t, &mut policy),
            None
        );
        assert_eq!(
            auto_stop_sample(
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
            let reason = auto_stop_sample(
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
            auto_stop_sample(
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
}
