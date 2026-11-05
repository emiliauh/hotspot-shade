//! Narrow demo API bridge for the desktop shell.
//!
//! The page can call only the routes in this allowlist. The bridge does not
//! accept a destination URL or command name. Request bodies can include a
//! manual token, but the in-memory demo does not use it to contact a device.
//! The bridge cannot start the real engine or change a route.

use hotspotshade::demo::DemoBackend;
use hotspotshade::gui::GuiBackend;
use serde::Serialize;
use serde_json::{json, Value};

/// The largest request body the bridge accepts, in bytes.
pub const MAX_BODY: usize = 1024 * 1024;

/// The largest query string the bridge accepts, in bytes.
pub const MAX_QUERY: usize = 4096;

/// Every path that the demo bridge knows. The UI contract test checks that the
/// page names only these paths. A known path with a wrong method gets 405.
pub const ALLOWED_PATHS: &[&str] = &[
    "/api/status",
    "/api/failures",
    "/api/diagnostics",
    "/api/probe",
    "/api/logs",
    "/api/start",
    "/api/stop",
    "/api/phone/discover",
    "/api/phone/pair",
    "/api/phone/pair/cancel",
    "/api/phone/forget",
    "/api/phone/probe",
    "/api/phone/check",
];

/// One answer for the page. It holds a status code and a JSON body.
#[derive(Debug, Serialize)]
pub struct ApiReply {
    pub status: u16,
    pub body: Value,
}

/// The bridge owns one concrete demo backend. The type fixes the demo boundary:
/// the shell has no constructor for a real service backend. The demo state
/// stays in memory.
pub struct DemoBridge {
    backend: DemoBackend,
}

impl Default for DemoBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DemoBridge {
    pub fn new() -> Self {
        Self {
            backend: DemoBackend::new(),
        }
    }

    /// Handle one request from the page.
    ///
    /// The method and path are checked against a fixed allowlist. An unknown
    /// method or path gets a fixed error. A body must hold a JSON object.
    pub fn handle(&self, method: &str, path: &str, query: &str, body: Option<Value>) -> ApiReply {
        let method = method.to_ascii_uppercase();
        if !safe_path(path) {
            return error(404, "not found");
        }
        if query.len() > MAX_QUERY {
            return error(414, "request query too long");
        }
        if body.as_ref().is_some_and(|value| {
            serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_BODY)
        }) {
            return error(413, "request body too large");
        }
        match (method.as_str(), path) {
            ("GET", "/api/status") => safe_json(self.backend.status()),
            ("GET", "/api/failures") => safe_json(self.backend.failures()),
            ("GET", "/api/diagnostics") => safe_json(self.backend.diagnostics()),
            ("GET", "/api/probe") => safe_json(self.backend.probe()),
            ("GET", "/api/phone/discover") => safe_json(self.backend.phone_discover()),
            ("GET", "/api/phone/pair") => safe_json(self.backend.pair_status()),
            ("GET", "/api/logs") => logs(&self.backend, query),
            ("POST", "/api/start") => {
                let payload = match object_body(body) {
                    Ok(value) => value,
                    Err(reply) => return reply,
                };
                match self.backend.start(payload) {
                    Ok(mut result) => {
                        redact(&mut result);
                        match self.backend.status() {
                            Ok(mut status) => {
                                redact(&mut status);
                                ApiReply {
                                    status: 200,
                                    body: json!({"ok": true, "status": status, "result": result}),
                                }
                            }
                            Err(_) => error(500, "The service status is unavailable."),
                        }
                    }
                    Err(code) if code == "phone_auth" => ApiReply {
                        status: 409,
                        body: json!({
                            "ok": false,
                            "code": "phone_token_rejected",
                            "error": "The source device changed its token. Open HotspotShade on your source device, then pair again."
                        }),
                    },
                    Err(code) => error(400, start_error(&code)),
                }
            }
            ("POST", "/api/stop") => {
                if let Err(reply) = object_body(body) {
                    return reply;
                }
                match self.backend.stop() {
                    Ok(mut result) => {
                        redact(&mut result);
                        match self.backend.status() {
                            Ok(mut status) => {
                                redact(&mut status);
                                ApiReply {
                                    status: 200,
                                    body: json!({"ok": true, "status": status, "result": result}),
                                }
                            }
                            Err(_) => error(500, "The service status is unavailable."),
                        }
                    }
                    Err(_) => error(400, "The service could not stop."),
                }
            }
            ("POST", "/api/phone/check") => {
                let payload = match object_body(body) {
                    Ok(value) => value,
                    Err(reply) => return reply,
                };
                match self.backend.phone_check(payload) {
                    Ok(mut value) => {
                        redact(&mut value);
                        ApiReply {
                            status: 200,
                            body: value,
                        }
                    }
                    Err(_) => error(
                        400,
                        "Source device authentication failed. Check the token and hotspot connection.",
                    ),
                }
            }
            ("POST", "/api/phone/pair") => {
                if let Err(reply) = object_body(body) {
                    return reply;
                }
                match self.backend.pair_start() {
                    Ok(mut value) => {
                        redact(&mut value);
                        ApiReply {
                            status: 200,
                            body: value,
                        }
                    }
                    Err(code) if code == "pair_busy" => {
                        error(400, "Pairing is already in progress.")
                    }
                    Err(_) => error(400, "The pairing request failed."),
                }
            }
            ("POST", "/api/phone/pair/cancel") => {
                if let Err(reply) = object_body(body) {
                    return reply;
                }
                safe_json(self.backend.pair_cancel())
            }
            ("POST", "/api/phone/forget") => {
                if let Err(reply) = object_body(body) {
                    return reply;
                }
                match self.backend.pair_forget() {
                    Ok(mut value) => {
                        redact(&mut value);
                        ApiReply {
                            status: 200,
                            body: value,
                        }
                    }
                    Err(code) if code == "tunnel_running" => {
                        error(409, "Stop the tunnel before you forget the source device.")
                    }
                    Err(_) => error(400, "The forget request failed."),
                }
            }
            ("POST", "/api/phone/probe") => {
                if let Err(reply) = object_body(body) {
                    return reply;
                }
                safe_json(self.backend.phone_probe())
            }
            (_, _) if known_path(path) => error(405, "method not allowed"),
            (_, _) => error(404, "not found"),
        }
    }
}

/// Accept only a plain API path. Reject a query, a percent escape, a parent
/// segment, a backslash, and a doubled slash.
fn safe_path(path: &str) -> bool {
    path.starts_with("/api/")
        && !path.contains("//")
        && !path.contains("..")
        && !path.contains('\\')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
}

/// The set of paths that the bridge knows. A known path with a wrong method
/// gets 405. An unknown path gets 404.
fn known_path(path: &str) -> bool {
    ALLOWED_PATHS.contains(&path)
}

fn logs(backend: &DemoBackend, query: &str) -> ApiReply {
    let mut since = 0u64;
    for item in query.split('&').filter(|item| !item.is_empty()) {
        if let Some(value) = item.strip_prefix("since=") {
            since = match value.parse() {
                Ok(value) => value,
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
            ApiReply {
                status: 200,
                body: json!({"logs": logs, "next": next}),
            }
        }
        Err(_) => error(500, "The service status is unavailable."),
    }
}

fn object_body(body: Option<Value>) -> Result<Value, ApiReply> {
    match body {
        None | Some(Value::Null) => Ok(json!({})),
        Some(value) if value.is_object() => Ok(value),
        Some(_) => Err(error(400, "request body must be a JSON object")),
    }
}

fn safe_json(result: Result<Value, String>) -> ApiReply {
    match result {
        Ok(mut value) => {
            redact(&mut value);
            ApiReply {
                status: 200,
                body: value,
            }
        }
        Err(_) => error(400, "The service could not complete the request."),
    }
}

fn error(status: u16, message: &str) -> ApiReply {
    ApiReply {
        status,
        body: json!({"ok": false, "error": message}),
    }
}

/// Replace any field that looks like a credential. The demo does not hold a
/// real token, but the rule keeps the bridge safe if the demo shape changes.
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

fn start_error(code: &str) -> &'static str {
    match code {
        "pair_first" => "Pair with the source device first.",
        "invalid_ping_option" => "The ping setting must be true or false.",
        "missing mode" | "invalid mode" => "Choose a mode for the demo.",
        "invalid options" => "The demo options are not valid.",
        "service is running" => "The demo tunnel is already running.",
        "start_cancelled" => "The start was cancelled.",
        _ => "The service could not start. Check the settings.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> DemoBridge {
        DemoBridge::new()
    }

    #[test]
    fn the_read_only_routes_are_reachable() {
        let bridge = bridge();
        for path in [
            "/api/status",
            "/api/failures",
            "/api/diagnostics",
            "/api/probe",
            "/api/phone/discover",
            "/api/phone/pair",
        ] {
            let reply = bridge.handle("GET", path, "", None);
            assert_eq!(reply.status, 200, "{path}");
            assert!(reply.body.is_object(), "{path}");
        }
        let probe = bridge.handle("POST", "/api/phone/probe", "", Some(json!({})));
        assert_eq!(probe.status, 200);
        let check = bridge.handle(
            "POST",
            "/api/phone/check",
            "",
            Some(json!({"token": "secret-test-value"})),
        );
        assert_eq!(check.status, 200);
        assert!(!check.body.to_string().contains("secret-test-value"));
    }

    #[test]
    fn unknown_paths_and_methods_are_rejected() {
        let bridge = bridge();
        assert_eq!(bridge.handle("GET", "/api/nope", "", None).status, 404);
        assert_eq!(bridge.handle("GET", "/api", "", None).status, 404);
        assert_eq!(bridge.handle("GET", "/index.html", "", None).status, 404);
        assert_eq!(bridge.handle("GET", "/api/../status", "", None).status, 404);
        assert_eq!(bridge.handle("GET", "/api//status", "", None).status, 404);
        assert_eq!(bridge.handle("GET", "/api/%73tatus", "", None).status, 404);
        assert_eq!(
            bridge.handle("GET", "/api/status?x=1", "", None).status,
            404
        );
        assert_eq!(bridge.handle("POST", "/api/status", "", None).status, 405);
        assert_eq!(bridge.handle("DELETE", "/api/status", "", None).status, 405);
        assert_eq!(bridge.handle("DELETE", "/api/nope", "", None).status, 404);
    }

    #[test]
    fn the_demo_status_is_labeled_and_has_no_credentials() {
        let reply = bridge().handle("GET", "/api/status", "", None);
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["demo"], true);
        assert_eq!(reply.body["running"], false);
        assert!(!reply.body.to_string().contains("secret"));
    }

    #[test]
    fn start_and_stop_stay_in_the_demo() {
        let bridge = bridge();
        let started = bridge.handle("POST", "/api/start", "", Some(json!({"mode": "tun"})));
        assert_eq!(started.status, 200);
        assert_eq!(started.body["ok"], true);
        assert_eq!(started.body["status"]["running"], true);
        assert_eq!(started.body["status"]["demo"], true);

        let stopped = bridge.handle("POST", "/api/stop", "", None);
        assert_eq!(stopped.status, 200);
        assert_eq!(stopped.body["status"]["running"], false);
        assert_eq!(stopped.body["result"]["demo"], true);
    }

    #[test]
    fn a_manual_token_is_not_returned() {
        let bridge = bridge();
        let started = bridge.handle(
            "POST",
            "/api/start",
            "",
            Some(json!({"mode": "phone", "options": {"token": "secret-test-value"}})),
        );
        assert_eq!(started.status, 200);
        assert!(!started.body.to_string().contains("secret-test-value"));

        let status = bridge.handle("GET", "/api/status", "", None);
        assert!(!status.body.to_string().contains("secret-test-value"));
        let logs = bridge.handle("GET", "/api/logs", "since=0", None);
        assert!(!logs.body.to_string().contains("secret-test-value"));
    }

    #[test]
    fn forget_is_refused_while_the_demo_runs() {
        let bridge = bridge();
        assert_eq!(
            bridge
                .handle("POST", "/api/start", "", Some(json!({"mode": "tun"})))
                .status,
            200
        );
        let reply = bridge.handle("POST", "/api/phone/forget", "", Some(json!({})));
        assert_eq!(reply.status, 409);
        assert!(reply.body["error"]
            .as_str()
            .is_some_and(|text| text.contains("Stop the tunnel")));
    }

    #[test]
    fn the_logs_query_and_body_types_are_checked() {
        let bridge = bridge();
        assert_eq!(
            bridge
                .handle("POST", "/api/start", "", Some(json!({"mode": "tun"})))
                .status,
            200
        );
        let logs = bridge.handle("GET", "/api/logs", "since=0", None);
        assert_eq!(logs.status, 200);
        assert!(!logs.body["logs"].as_array().unwrap().is_empty());
        assert!(logs.body["next"].as_u64().unwrap() > 0);
        assert_eq!(
            bridge.handle("GET", "/api/logs", "since=abc", None).status,
            400
        );
        assert_eq!(
            bridge
                .handle("POST", "/api/start", "", Some(json!("not an object")))
                .status,
            400
        );
        assert_eq!(
            bridge
                .handle("POST", "/api/start", "", Some(json!({"mode": "nope"})))
                .status,
            400
        );
    }

    #[test]
    fn the_query_length_is_bounded() {
        let bridge = bridge();
        let at_limit = "a".repeat(MAX_QUERY);
        assert_eq!(
            bridge.handle("GET", "/api/logs", &at_limit, None).status,
            200
        );
        let over_limit = "a".repeat(MAX_QUERY + 1);
        assert_eq!(
            bridge.handle("GET", "/api/logs", &over_limit, None).status,
            414
        );
        assert_eq!(
            bridge
                .handle("GET", "/api/status", &over_limit, None)
                .status,
            414
        );
    }

    #[test]
    fn pairing_routes_are_narrow_and_labeled() {
        let bridge = bridge();
        let view = bridge.handle("GET", "/api/phone/pair", "", None);
        assert_eq!(view.status, 200);
        assert_eq!(view.body["demo"], true);
        let started = bridge.handle("POST", "/api/phone/pair", "", Some(json!({})));
        assert_eq!(started.status, 200);
        assert_eq!(started.body["demo"], true);
        let cancelled = bridge.handle("POST", "/api/phone/pair/cancel", "", Some(json!({})));
        assert_eq!(cancelled.status, 200);
    }
}
