//! In-memory demo backend. All counters and logs are simulated.
use crate::autostop;
use crate::gui::{phone_message, GuiBackend};
use crate::pairing::{PairPhase, PairView, PORT_CHANGED_MESSAGE};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct State {
    running: bool,
    mode: Option<String>,
    started_at: Option<u64>,
    last_tick: Instant,
    ticks: u64,
    logs: Vec<Value>,
    /// A simulated pairing. No connection is made.
    pair_started: Option<Instant>,
    paired: bool,
    /// The simulated source-device proxy port. The source device owns it.
    phone_port: u16,
    /// The port of the simulated running tunnel.
    tunnel_port: u16,
    /// The number of status reads in the running simulated tunnel.
    tunnel_checks: u64,
    /// The simulated source device changed its port in this session.
    port_change_done: bool,
    /// The simulated ping relay is on.
    icmp_on: bool,
    /// The simulated presence state while the tunnel is off.
    phone_state: &'static str,
    /// When the simulated presence state last changed.
    phone_state_at: Instant,
    /// Unix seconds of the last simulated probe.
    checked_at: Option<u64>,
    /// The simulated CHALLENGE `known` value.
    trusted_by_source: Option<bool>,
    /// The simulated forget state.
    forget_state: &'static str,
    forget_attempts: u64,
    /// The last simulated stop.
    last_stop: Option<(&'static str, u64)>,
    /// A demo-only automatic stop after 3 seconds of run time.
    auto_stop_reason: Option<&'static str>,
    auto_stop_at: Option<Instant>,
}
pub struct DemoBackend {
    state: Mutex<State>,
}
impl Default for DemoBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl DemoBackend {
    pub fn new() -> Self {
        let mut state = State {
            running: false,
            mode: None,
            started_at: None,
            last_tick: Instant::now(),
            ticks: 0,
            logs: Vec::new(),
            pair_started: None,
            paired: false,
            phone_port: DEMO_PHONE_PORT,
            tunnel_port: 0,
            tunnel_checks: 0,
            port_change_done: false,
            icmp_on: false,
            phone_state: "unpaired",
            phone_state_at: Instant::now(),
            checked_at: None,
            trusted_by_source: None,
            forget_state: "none",
            forget_attempts: 0,
            last_stop: None,
            auto_stop_reason: None,
            auto_stop_at: None,
        };
        log(
            &mut state,
            "Demo backend ready. Counters and logs are simulated.",
        );
        Self {
            state: Mutex::new(state),
        }
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn log(state: &mut State, message: &str) {
    let seq = state
        .logs
        .last()
        .and_then(|v| v.get("seq"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    state
        .logs
        .push(json!({"seq":seq,"ts":now(),"level":"info","msg":message}));
    if state.logs.len() > 800 {
        state.logs.drain(..state.logs.len() - 800);
    }
}
// The simulated pairing connects for 1 second, shows a code for 3 seconds,
// and then reports paired.
const DEMO_CONNECT: Duration = Duration::from_millis(1000);
const DEMO_CONFIRM: Duration = Duration::from_millis(4000);
const DEMO_CODE: &str = "123 456";
/// The first simulated proxy port of the source device.
const DEMO_PHONE_PORT: u16 = 31000;
/// The simulated proxy port after the source device changes it.
const DEMO_PHONE_PORT_CHANGED: u16 = 41234;
/// The source device changes its port after this many status reads.
const DEMO_PORT_CHANGE_READS: u64 = 3;
/// The simulated presence state stays for this long before it changes.
const DEMO_PHONE_STATE_DWELL: Duration = Duration::from_secs(6);
/// The simulated states while the target device holds no credentials.
const DEMO_UNPAIRED_STATES: [&str; 4] = ["no_hotspot", "not_running", "not_responding", "unpaired"];
/// The simulated states while the target device holds credentials.
const DEMO_PAIRED_STATES: [&str; 3] = ["not_trusted", "proxy_off", "ready"];
/// Move the simulated presence state to the next value in its cycle.
fn advance_phone_state(state: &mut State) {
    if state.running || state.phone_state_at.elapsed() < DEMO_PHONE_STATE_DWELL {
        return;
    }
    let cycle: &[&'static str] = if state.paired {
        &DEMO_PAIRED_STATES
    } else {
        &DEMO_UNPAIRED_STATES
    };
    let position = cycle
        .iter()
        .position(|value| *value == state.phone_state)
        .unwrap_or(0);
    state.phone_state = cycle[(position + 1) % cycle.len()];
    state.phone_state_at = Instant::now();
    log(
        state,
        &format!(
            "Simulated source device state: {}. No connection was made.",
            state.phone_state
        ),
    );
}
/// The simulated number of source device proxy connections.
fn demo_connections(state: &str) -> Value {
    match state {
        "ready" | "connected" => json!(2),
        _ => Value::Null,
    }
}
/// The phone object in the status shape. The web page and the tests use it.
fn phone_object(s: &State, phone_state: &str) -> Value {
    let port_changed = s.running && s.tunnel_port != 0 && s.tunnel_port != s.phone_port;
    json!({
        "state": phone_state,
        "message": if port_changed { PORT_CHANGED_MESSAGE } else { phone_message(phone_state) },
        "port_changed": port_changed,
        "connections": demo_connections(phone_state),
        "checked_at": s.checked_at,
        "trusted_by_source": s.trusted_by_source,
    })
}
/// Stop the simulated session and record the reason.
fn stop_state(state: &mut State, reason: &'static str) {
    if !state.running {
        return;
    }
    state.running = false;
    state.mode = None;
    state.started_at = None;
    state.tunnel_port = 0;
    state.tunnel_checks = 0;
    state.port_change_done = false;
    state.icmp_on = false;
    state.auto_stop_reason = None;
    state.auto_stop_at = None;
    state.last_stop = Some((reason, now()));
    log(
        state,
        match reason {
            "hotspot_lost" => "Simulated automatic stop: the hotspot turned off.",
            "source_device_gone" => {
                "Simulated automatic stop: the source device stopped answering."
            }
            _ => "Demo session stopped. No routes were changed.",
        },
    );
}
fn pair_view(state: &mut State) -> Value {
    if let Some(started) = state.pair_started {
        if started.elapsed() >= DEMO_CONFIRM {
            state.pair_started = None;
            state.paired = true;
            state.phone_state = "not_trusted";
            state.phone_state_at = Instant::now();
            log(state, "Simulated pairing finished. No connection was made.");
        }
    }
    let view = match state.pair_started {
        Some(started) if started.elapsed() < DEMO_CONNECT => PairView {
            phase: PairPhase::Connecting,
            ..PairView::default()
        },
        Some(_) => PairView {
            phase: PairPhase::Confirm,
            code: Some(DEMO_CODE.into()),
            ..PairView::default()
        },
        None if state.paired => PairView {
            phase: PairPhase::Paired,
            host: Some(Ipv4Addr::new(172, 20, 10, 1)),
            port: Some(state.phone_port),
            ..PairView::default()
        },
        None => PairView::default(),
    };
    let mut value = view.to_json();
    value["demo"] = json!(true);
    value["message"] = json!("Simulated pairing. No connection was made.");
    value
}
fn platform() -> Value {
    json!({"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"admin":false,
    "default_iface":"en0","default_iface_name":"en0",
    "capabilities":{"ip_ttl_tcp":true,"ip_ttl_udp":true,"bound_if":true,"v6_hop_limit":true,"utun_needs_root":true},
    "destination_privacy":crate::diagnostics::destination_privacy_capability()})
}
impl GuiBackend for DemoBackend {
    fn status(&self) -> Result<Value, String> {
        let mut s = self.state.lock().map_err(|_| "demo unavailable")?;
        if s.running && s.last_tick.elapsed() >= Duration::from_millis(700) {
            s.ticks += 1;
            s.last_tick = Instant::now();
        }
        if s.running && s.mode.as_deref() == Some("phone") && !s.port_change_done {
            s.tunnel_checks += 1;
            if s.tunnel_checks >= DEMO_PORT_CHANGE_READS {
                s.port_change_done = true;
                s.phone_port = if s.phone_port == DEMO_PHONE_PORT {
                    DEMO_PHONE_PORT_CHANGED
                } else {
                    DEMO_PHONE_PORT
                };
                log(
                    &mut s,
                    "Simulated port change. The source device changed its port.",
                );
            }
        }
        // A demo start can ask for one simulated automatic stop.
        if s.running
            && s.auto_stop_at
                .is_some_and(|at| at.elapsed() >= Duration::from_secs(3))
        {
            let reason = s.auto_stop_reason.unwrap_or("hotspot_lost");
            stop_state(&mut s, reason);
        }
        let ticks = s.ticks;
        advance_phone_state(&mut s);
        let pair = pair_view(&mut s);
        let paired = pair["state"] == "paired";
        let phone_state = if s.running {
            "connected"
        } else {
            s.phone_state
        };
        let phone = phone_object(&s, phone_state);
        let last_stop = s.last_stop;
        let last_stop_json = match last_stop {
            Some((reason, at)) => json!({"reason":reason,"at":at}),
            None => json!({"reason":null,"at":null}),
        };
        let last_stop_message = last_stop.and_then(|(reason, _)| autostop::stop_message(reason));
        Ok(
            json!({"running":s.running,"mode":s.mode,"started_at":s.started_at,
            "icmp_enabled":s.running && s.mode.as_deref()==Some("phone") && s.icmp_on,
            "platform":platform(),
            "iface":"en0",
            "stats":{"tcp_flows":ticks/2,"udp_flows":ticks/3,"packets_in":ticks*24,"packets_out":ticks*20,
                "bytes_in":ticks*14400,"bytes_out":ticks*9600,"ttl_bad":0,
                "dns_flows":ticks/4,"dns_setup_ok":ticks/4,"dns_setup_failed":0},
            "error":null,"logs":s.logs,"demo":true,"api":1,
            "phone":phone,
            "forget":{"state":s.forget_state,"attempts":s.forget_attempts},
            "last_stop":last_stop_json,
            "last_stop_message":last_stop_message,
            "paired":paired,"phone_host":if paired { json!("172.20.10.1") } else { Value::Null },
            "phone_port":if paired { json!(s.phone_port) } else { Value::Null }}),
        )
    }
    fn failures(&self) -> Result<Value, String> {
        let state = self.state.lock().map_err(|_| "demo unavailable")?;
        let since = state
            .started_at
            .unwrap_or_else(|| now().saturating_sub(600));
        Ok(json!({
            "ok": true,
            "since": since,
            "total": 135,
            "dropped": 0,
            "demo": true,
            "groups": [
                {"proto":"tcp","family":"ipv4","port":443,"reason":"unreachable","phase":"request","count":84,"name":"example.com","example_ip":"203.0.113.5","code":4},
                {"proto":"tcp","family":"ipv4","port":443,"reason":"refused","phase":"connect","count":21,"name":Value::Null,"example_ip":"198.51.100.9","code":5},
                {"proto":"dns","family":"ipv4","port":53,"reason":"timed_out","phase":Value::Null,"count":12,"name":Value::Null,"example_ip":"1.1.1.1","code":Value::Null},
                {"proto":"udp","family":"ipv4","port":443,"reason":"unreachable","phase":"request","count":9,"name":"cdn.example.net","example_ip":"203.0.113.9","code":4},
                {"proto":"tcp","family":"ipv6","port":443,"reason":"unreachable","phase":"greeting","count":6,"name":Value::Null,"example_ip":"2001:db8::5","code":4},
                {"proto":"tcp","family":"ipv4","port":8443,"reason":"other","phase":"auth","count":3,"name":"api.example.org","example_ip":"198.51.100.20","code":Value::Null}
            ],
            "recent": [
                {"ts":since+9,"proto":"tcp","family":"ipv4","ip":"203.0.113.5","port":443,"reason":"unreachable","phase":"request","name":"example.com","code":4},
                {"ts":since+8,"proto":"tcp","family":"ipv4","ip":"198.51.100.9","port":443,"reason":"refused","phase":"connect","name":Value::Null,"code":5},
                {"ts":since+7,"proto":"dns","family":"ipv4","ip":"1.1.1.1","port":53,"reason":"timed_out","phase":Value::Null,"name":Value::Null,"code":Value::Null},
                {"ts":since+6,"proto":"udp","family":"ipv4","ip":"203.0.113.9","port":443,"reason":"unreachable","phase":"request","name":"cdn.example.net","code":4},
                {"ts":since+5,"proto":"tcp","family":"ipv6","ip":"2001:db8::5","port":443,"reason":"unreachable","phase":"greeting","name":Value::Null,"code":4},
                {"ts":since+4,"proto":"tcp","family":"ipv4","ip":"198.51.100.20","port":8443,"reason":"other","phase":"auth","name":"api.example.org","code":Value::Null}
            ],
        }))
    }
    fn probe(&self) -> Result<Value, String> {
        let p = platform();
        Ok(
            json!({"available":true,"os":p["os"],"arch":p["arch"],"admin":false,
            "default_iface":"en0","capabilities":p["capabilities"],
            "platform":p,
            "notes":["Demo probe. Values are simulated."],"demo":true}),
        )
    }
    fn diagnostics(&self) -> Result<Value, String> {
        let state = self.state.lock().map_err(|_| "demo unavailable")?;
        let mut value = crate::diagnostics::empty();
        value["demo"] = json!(true);
        if !state.running {
            return Ok(value);
        }
        let ticks = state.ticks.max(1);
        let metric = |count: u64, p50: u64, p95: u64, max: u64| json!({"count": count, "p50": p50, "p95": p95, "max": max});
        value["running"] = json!(true);
        value["engine"]["uptime_s"] = json!(state
            .started_at
            .map_or(0, |start| now().saturating_sub(start)));
        value["engine"]["workers"] = json!(4);
        value["setup"]["connect_ms"] = metric(ticks, 4, 9, 18);
        value["setup"]["greeting_ms"] = metric(ticks, 1, 3, 7);
        value["setup"]["auth_ms"] = metric(ticks, 6, 14, 30);
        value["setup"]["request_ms"] = metric(ticks, 21, 48, 95);
        value["dns"]["lookups"] = json!(ticks / 4);
        value["dns"]["ok"] = json!(ticks / 4);
        value["dns"]["failed"] = json!(0);
        value["dns"]["ms"] = metric(ticks / 4, 12, 30, 55);
        value["queues"]["input"] = json!([{"peak":ticks % 9,"max_age_us":400 + ticks * 5}]);
        value["queues"]["output"] = json!({"peak":ticks % 6,"max_age_us":250 + ticks * 3});
        value["udp"]["flows"] = json!(ticks / 3);
        value["udp"]["age_drops"] = json!(ticks / 50);
        value["tcp"]["flows_peak"] = json!((ticks / 2).min(12));
        value["tcp"]["retransmits"] = json!(ticks / 7);
        value["tcp"]["zero_window_ms"] = json!(ticks * 3);
        value["failures"]["total"] = json!(135);
        value["failures"]["dropped"] = json!(0);
        Ok(value)
    }
    fn phone_discover(&self) -> Result<Value, String> {
        Ok(
            json!({"host":"172.20.10.1","port":1080,"reachable":true,"message":"Simulated gateway and TCP result. The source device identity is not verified.","demo":true}),
        )
    }
    fn phone_check(&self, _: Value) -> Result<Value, String> {
        Ok(
            json!({"ok":true,"message":"Simulated source device authentication. No connection was made.","demo":true}),
        )
    }
    fn start(&self, payload: Value) -> Result<Value, String> {
        let mode = payload
            .get("mode")
            .and_then(Value::as_str)
            .ok_or("missing mode")?;
        if !matches!(mode, "socks5" | "tun" | "phone") {
            return Err("invalid mode".into());
        }
        if payload.get("options").is_some_and(|v| !v.is_object()) {
            return Err("invalid options".into());
        }
        // The phone echo relay follows the request. Direct modes ignore it.
        let icmp = if mode == "phone" {
            Some(crate::gui::phone_icmp_options(
                payload.get("options").unwrap_or(&Value::Null),
                true,
                true,
            )?)
        } else {
            None
        };
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        if state.running {
            return Err("service is running".into());
        }
        let manual = payload
            .get("options")
            .and_then(|o| o.get("token"))
            .and_then(Value::as_str)
            .is_some_and(|t| !t.is_empty());
        if mode == "phone" && !manual {
            pair_view(&mut state);
            if !state.paired {
                return Err("pair_first".into());
            }
        }
        state.running = true;
        state.mode = Some(mode.into());
        state.started_at = Some(now());
        state.ticks = 0;
        state.last_tick = Instant::now();
        state.tunnel_port = if mode == "phone" { state.phone_port } else { 0 };
        state.tunnel_checks = 0;
        state.port_change_done = false;
        state.last_stop = None;
        state.auto_stop_reason = match payload
            .get("options")
            .and_then(|options| options.get("demo_auto_stop"))
            .and_then(Value::as_str)
        {
            Some("hotspot_lost") => Some("hotspot_lost"),
            Some("source_device_gone") => Some("source_device_gone"),
            _ => None,
        };
        state.auto_stop_at = state.auto_stop_reason.map(|_| Instant::now());
        let icmp_on = icmp.map(|(enabled, _)| enabled).unwrap_or(false);
        state.icmp_on = icmp_on;
        log(
            &mut state,
            "Demo session started. Counters and logs are simulated.",
        );
        if mode == "phone" {
            log(
                &mut state,
                if icmp_on {
                    "Simulated ping relay is on."
                } else {
                    "Simulated ping relay is off."
                },
            );
        }
        Ok(json!({"ok":true,"mode":mode,"demo":true}))
    }
    fn stop(&self) -> Result<Value, String> {
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        let stopped = state.running;
        if stopped {
            stop_state(&mut state, "user");
        }
        Ok(json!({"ok":true,"stopped":stopped,"demo":true}))
    }
    fn pair_start(&self) -> Result<Value, String> {
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        pair_view(&mut state);
        if state.pair_started.is_some() {
            return Err("pair_busy".into());
        }
        state.pair_started = Some(Instant::now());
        state.forget_state = "none";
        state.forget_attempts = 0;
        state.checked_at = Some(now());
        log(
            &mut state,
            "Simulated pairing started. No connection was made.",
        );
        Ok(pair_view(&mut state))
    }
    fn pair_status(&self) -> Result<Value, String> {
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        Ok(pair_view(&mut state))
    }
    fn pair_forget(&self) -> Result<Value, String> {
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        // A running tunnel keeps the proxy token. The demo follows the same rule.
        if state.running {
            return Err("tunnel_running".into());
        }
        state.pair_started = None;
        state.paired = false;
        state.phone_port = DEMO_PHONE_PORT;
        state.phone_state = "unpaired";
        state.phone_state_at = Instant::now();
        state.forget_state = "confirmed";
        state.forget_attempts = 1;
        state.checked_at = Some(now());
        state.trusted_by_source = Some(false);
        log(
            &mut state,
            "Simulated forget. The source device removed this target device.",
        );
        Ok(json!({"ok":true,"demo":true}))
    }
    fn phone_probe(&self) -> Result<Value, String> {
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        state.checked_at = Some(now());
        if !state.paired {
            // Alternate the simulated CHALLENGE `known` value so that both
            // states are visible without a connection.
            state.trusted_by_source = Some(!state.trusted_by_source.unwrap_or(false));
        }
        let phone_state = if state.running {
            "connected"
        } else {
            state.phone_state
        };
        let phone = phone_object(&state, phone_state);
        log(
            &mut state,
            "Simulated source device check. No connection was made.",
        );
        Ok(json!({"ok":true,"phone":phone,"demo":true}))
    }
    fn pair_cancel(&self) -> Result<Value, String> {
        let mut state = self.state.lock().map_err(|_| "demo unavailable")?;
        if state.pair_started.take().is_some() {
            log(&mut state, "Simulated pairing cancelled.");
        }
        Ok(pair_view(&mut state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn demo_lifecycle_is_labeled_and_does_not_return_credentials() {
        let d = DemoBackend::new();
        assert_eq!(d.status().unwrap()["running"], false);
        let start = d
            .start(json!({"mode":"phone","options":{"token":"secret-test-value"}}))
            .unwrap();
        assert_eq!(start["demo"], true);
        let status = d.status().unwrap();
        assert_eq!(status["running"], true);
        assert_eq!(status["mode"], "phone");
        assert!(!status.to_string().contains("secret-test-value"));
        assert!(d.start(json!({"mode":"tun"})).is_err());
        d.stop().unwrap();
        assert_eq!(d.status().unwrap()["running"], false);
    }
    #[test]
    fn demo_ping_option_defaults_on_and_can_be_turned_off() {
        let d = DemoBackend::new();
        d.state.lock().unwrap().pair_started = Some(Instant::now() - DEMO_CONFIRM);
        assert_eq!(d.pair_status().unwrap()["state"], "paired");
        d.start(json!({"mode":"phone","options":{}})).unwrap();
        let status = d.status().unwrap();
        assert_eq!(status["icmp_enabled"], true);
        assert!(status["logs"]
            .to_string()
            .contains("Simulated ping relay is on."));
        d.stop().unwrap();
        assert_eq!(d.status().unwrap()["icmp_enabled"], false);
        d.start(json!({"mode":"phone","options":{"experimental_icmp":false}}))
            .unwrap();
        let status = d.status().unwrap();
        assert_eq!(status["icmp_enabled"], false);
        assert!(status["logs"]
            .to_string()
            .contains("Simulated ping relay is off."));
        d.stop().unwrap();
        d.start(json!({
            "mode":"phone",
            "options":{"experimental_icmp":true,"experimental_icmp_persistent":false}
        }))
        .unwrap();
        assert_eq!(d.status().unwrap()["icmp_enabled"], true);
        d.stop().unwrap();
    }

    #[test]
    fn demo_rejects_a_non_boolean_ping_option_and_direct_modes_ignore_it() {
        let d = DemoBackend::new();
        for bad in [
            json!({"experimental_icmp":"true"}),
            json!({"experimental_icmp":null}),
            json!({"experimental_icmp_persistent":"true"}),
            json!({"experimental_icmp":false,"experimental_icmp_persistent":true}),
        ] {
            assert_eq!(
                d.start(json!({"mode":"phone","options":bad})).unwrap_err(),
                "invalid_ping_option"
            );
        }
        assert_eq!(d.status().unwrap()["running"], false);
        // A direct mode ignores the option and never reports ping as on.
        d.start(json!({"mode":"tun","options":{"experimental_icmp":"true"}}))
            .unwrap();
        let status = d.status().unwrap();
        assert_eq!(status["running"], true);
        assert_eq!(status["icmp_enabled"], false);
        d.stop().unwrap();
    }

    #[test]
    fn demo_pairing_is_simulated_and_gates_phone_start() {
        let d = DemoBackend::new();
        assert_eq!(d.pair_status().unwrap()["state"], "idle");
        assert_eq!(
            d.start(json!({"mode":"phone","options":{}})).unwrap_err(),
            "pair_first"
        );
        let started = d.pair_start().unwrap();
        assert_eq!(started["state"], "connecting");
        assert_eq!(started["demo"], true);
        assert_eq!(d.pair_start().unwrap_err(), "pair_busy");
        assert_eq!(d.pair_cancel().unwrap()["state"], "idle");
        d.pair_start().unwrap();
        d.state.lock().unwrap().pair_started = Some(Instant::now() - DEMO_CONNECT);
        let confirm = d.pair_status().unwrap();
        assert_eq!(confirm["state"], "confirm");
        assert_eq!(confirm["code"], DEMO_CODE);
        d.state.lock().unwrap().pair_started = Some(Instant::now() - DEMO_CONFIRM);
        let paired = d.pair_status().unwrap();
        assert_eq!(paired["state"], "paired");
        assert_eq!(paired["port"], DEMO_PHONE_PORT);
        let status = d.status().unwrap();
        assert_eq!(status["paired"], true);
        assert_eq!(status["phone_host"], "172.20.10.1");
        assert!(status.get("token").is_none());
        d.start(json!({"mode":"phone","options":{}})).unwrap();
        assert_eq!(d.status().unwrap()["running"], true);
    }
    #[test]
    fn demo_simulates_a_port_change_without_a_sleep() {
        let d = DemoBackend::new();
        d.state.lock().unwrap().pair_started = Some(Instant::now() - DEMO_CONFIRM);
        assert_eq!(d.pair_status().unwrap()["port"], DEMO_PHONE_PORT);
        d.start(json!({"mode":"phone","options":{}})).unwrap();
        for _ in 0..DEMO_PORT_CHANGE_READS - 1 {
            assert_eq!(d.status().unwrap()["phone"]["port_changed"], false);
        }
        let changed = d.status().unwrap();
        assert_eq!(changed["demo"], true);
        assert_eq!(changed["phone_port"], DEMO_PHONE_PORT_CHANGED);
        assert_eq!(changed["phone"]["port_changed"], true);
        assert_eq!(
            changed["phone"]["message"],
            "The source device changed its port. Turn the tunnel off and on."
        );
        assert!(changed["logs"]
            .to_string()
            .contains("Simulated port change"));
        d.stop().unwrap();
        let stopped = d.status().unwrap();
        assert_eq!(stopped["phone"]["port_changed"], false);
        assert_eq!(stopped["phone_port"], DEMO_PHONE_PORT_CHANGED);
    }
    #[test]
    fn demo_forget_is_refused_while_running_and_clears_when_off() {
        let d = DemoBackend::new();
        d.state.lock().unwrap().pair_started = Some(Instant::now() - DEMO_CONFIRM);
        assert_eq!(d.pair_status().unwrap()["state"], "paired");
        d.start(json!({"mode":"phone","options":{}})).unwrap();
        assert_eq!(d.pair_forget().unwrap_err(), "tunnel_running");
        assert_eq!(d.pair_status().unwrap()["state"], "paired");
        d.stop().unwrap();
        assert!(d.pair_forget().is_ok());
        assert_eq!(d.pair_status().unwrap()["state"], "idle");
    }

    #[test]
    fn demo_failures_are_simulated_and_labeled() {
        let d = DemoBackend::new();
        let value = d.failures().unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["demo"], true);
        assert!(value["since"].as_u64().is_some());
        assert_eq!(value["total"], 135);
        let groups = value["groups"].as_array().unwrap();
        assert!(groups.len() <= 50);
        assert!(value["recent"].as_array().unwrap().len() <= 100);
        let sum: u64 = groups
            .iter()
            .map(|group| group["count"].as_u64().unwrap())
            .sum();
        assert_eq!(sum, value["total"].as_u64().unwrap());
        let phases: Vec<Option<&str>> =
            groups.iter().map(|group| group["phase"].as_str()).collect();
        assert_eq!(
            phases,
            vec![
                Some("request"),
                Some("connect"),
                None,
                Some("request"),
                Some("greeting"),
                Some("auth")
            ]
        );
        for group in groups {
            let phase = &group["phase"];
            assert!(phase.is_null() || phase.as_str().is_some(), "{phase}");
            if let Some(word) = phase.as_str() {
                assert!(
                    ["connect", "greeting", "auth", "request"].contains(&word),
                    "{word}"
                );
            }
        }
        let recent = value["recent"].as_array().unwrap();
        assert_eq!(recent.len(), 6);
        assert_eq!(recent[2]["phase"], Value::Null);
        assert_eq!(recent[4]["phase"], "greeting");
        assert!(!value.to_string().contains("token"));
        d.start(json!({"mode":"tun"})).unwrap();
        let started = d.status().unwrap()["started_at"].as_u64().unwrap();
        let first = d.failures().unwrap();
        assert_eq!(first["since"], started);
        assert_eq!(first, d.failures().unwrap());
        d.stop().unwrap();
    }
    #[test]
    fn demo_rejects_invalid_mode() {
        assert!(DemoBackend::new().start(json!({"mode":"other"})).is_err());
    }

    #[test]
    fn demo_simulates_every_presence_state_with_fixed_text() {
        let d = DemoBackend::new();
        for state in DEMO_UNPAIRED_STATES {
            {
                let mut inner = d.state.lock().unwrap();
                inner.phone_state = state;
                inner.phone_state_at = Instant::now();
            }
            let status = d.status().unwrap();
            assert_eq!(status["demo"], true);
            assert_eq!(status["phone"]["state"], state);
            assert_eq!(status["phone"]["message"], phone_message(state));
            assert_eq!(status["paired"], false);
            assert_eq!(status["phone"]["connections"], Value::Null);
        }
        {
            let mut inner = d.state.lock().unwrap();
            inner.paired = true;
            inner.pair_started = None;
        }
        for state in DEMO_PAIRED_STATES {
            {
                let mut inner = d.state.lock().unwrap();
                inner.phone_state = state;
                inner.phone_state_at = Instant::now();
            }
            let status = d.status().unwrap();
            assert_eq!(status["phone"]["state"], state);
            assert_eq!(status["phone"]["message"], phone_message(state));
            assert_eq!(status["paired"], true);
            let expected = if state == "ready" {
                json!(2)
            } else {
                Value::Null
            };
            assert_eq!(status["phone"]["connections"], expected);
        }
        d.start(json!({"mode":"phone","options":{}})).unwrap();
        let status = d.status().unwrap();
        assert_eq!(status["phone"]["state"], "connected");
        assert_eq!(
            status["phone"]["message"],
            "Connected to the source device."
        );
        assert_eq!(status["phone"]["connections"], json!(2));
        d.stop().unwrap();
    }

    #[test]
    fn demo_presence_state_cycles_without_a_sleep() {
        let d = DemoBackend::new();
        {
            let mut inner = d.state.lock().unwrap();
            inner.phone_state = "unpaired";
            inner.phone_state_at = Instant::now() - DEMO_PHONE_STATE_DWELL;
        }
        assert_eq!(d.status().unwrap()["phone"]["state"], "no_hotspot");
        {
            let mut inner = d.state.lock().unwrap();
            inner.phone_state_at = Instant::now() - DEMO_PHONE_STATE_DWELL;
        }
        assert_eq!(d.status().unwrap()["phone"]["state"], "not_running");
        assert!(d
            .status()
            .unwrap()
            .to_string()
            .contains("Simulated source device state"));
    }

    #[test]
    fn demo_exposes_probe_forget_iface_and_stop_fields() {
        let d = DemoBackend::new();
        d.state.lock().unwrap().pair_started = Some(Instant::now() - DEMO_CONFIRM);
        assert_eq!(d.pair_status().unwrap()["state"], "paired");
        let status = d.status().unwrap();
        assert_eq!(status["iface"], "en0");
        assert!(status["phone"].get("checked_at").is_some());
        assert!(status["phone"].get("trusted_by_source").is_some());
        assert_eq!(status["forget"], json!({"state":"none","attempts":0}));
        assert_eq!(status["last_stop"], json!({"reason":null,"at":null}));
        let checked = d.phone_probe().unwrap();
        assert_eq!(checked["ok"], true);
        assert!(checked["phone"]["checked_at"].as_u64().is_some());
        assert_eq!(checked["demo"], true);
        assert!(d.pair_forget().is_ok());
        let status = d.status().unwrap();
        assert_eq!(status["forget"], json!({"state":"confirmed","attempts":1}));
        assert!(status["phone"]["checked_at"].as_u64().is_some());
        assert_eq!(status["phone"]["trusted_by_source"], false);
        assert!(!status.to_string().contains("token"));
        // A simulated check flips the unpaired trust value so both states are
        // visible in the demo.
        assert_eq!(d.phone_probe().unwrap()["phone"]["trusted_by_source"], true);
    }

    #[test]
    fn demo_diagnostics_are_simulated_and_labeled() {
        let d = DemoBackend::new();
        let empty = d.diagnostics().unwrap();
        assert_eq!(empty["demo"], true);
        assert_eq!(empty["running"], false);
        d.start(json!({"mode":"tun"})).unwrap();
        d.state.lock().unwrap().ticks = 28;
        let value = d.diagnostics().unwrap();
        assert_eq!(value["demo"], true);
        assert_eq!(value["running"], true);
        assert_eq!(value["engine"]["workers"], 4);
        assert_eq!(value["setup"]["connect_ms"]["count"], 28);
        assert_eq!(value["dns"]["lookups"], 7);
        assert_eq!(value["tcp"]["flows_peak"], 12);
        assert!(value["queues"]["input"].as_array().unwrap().len() == 1);
        assert!(!value.to_string().contains("token"));
        d.stop().unwrap();
        assert_eq!(d.diagnostics().unwrap()["running"], false);
    }

    #[test]
    fn demo_status_and_probe_report_the_shared_destination_privacy_capability() {
        let d = DemoBackend::new();
        // The demo derives the row from the same constructor as the service,
        // so the page cannot meet a second shape in demo mode.
        let expected = crate::diagnostics::destination_privacy_capability();
        let status = d.status().unwrap();
        assert_eq!(status["demo"], true);
        let status_privacy = &status["platform"]["destination_privacy"];
        assert_eq!(status_privacy, &expected);
        assert_eq!(status_privacy["mode"], "off");
        assert_eq!(status_privacy["default_mode"], "off");
        assert_eq!(status_privacy["modes"]["off"], "supported");
        for name in ["shape", "hide", "cover"] {
            assert_eq!(status_privacy["modes"][name], "unsupported", "{name}");
        }
        assert_eq!(status_privacy["sni_override"], "unsupported");
        assert_eq!(status_privacy["ech"], "unsupported");
        let probe = d.probe().unwrap();
        assert_eq!(probe["demo"], true);
        assert_eq!(probe["platform"]["destination_privacy"], expected);
        // The earlier flattened probe keys stay for compatibility.
        assert_eq!(probe["available"], true);
        assert_eq!(probe["os"], std::env::consts::OS);
        assert_eq!(probe["default_iface"], "en0");
        assert_eq!(probe["notes"], json!(["Demo probe. Values are simulated."]));
        // A simulated probe does not claim an active mode, ECH, or a leak.
        let text = format!(
            "{status_privacy} {}",
            probe["platform"]["destination_privacy"]
        );
        for forbidden in [
            "token",
            "identity",
            "example.com",
            "127.0.0.1",
            "::1",
            "active",
            "leak",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn demo_diagnostics_keep_destination_privacy_off_with_zero_counters() {
        let d = DemoBackend::new();
        let expected = crate::diagnostics::destination_privacy();
        let stopped = d.diagnostics().unwrap();
        assert_eq!(stopped["demo"], true);
        assert_eq!(stopped["running"], false);
        assert_eq!(stopped["destination_privacy"], expected);
        d.start(json!({"mode":"tun"})).unwrap();
        let running = d.diagnostics().unwrap();
        assert_eq!(running["demo"], true);
        assert_eq!(running["running"], true);
        // A simulated tunnel never turns a mode on and never records a
        // privacy event. The section keeps the engine contract.
        assert_eq!(running["destination_privacy"], expected);
        let privacy = &running["destination_privacy"];
        assert_eq!(privacy["mode"], "off");
        let counters = privacy["counters"].as_object().unwrap();
        assert_eq!(counters.len(), 13);
        assert!(counters.values().all(|count| count.as_u64() == Some(0)));
        assert_eq!(privacy["counters"]["ech_ok"], 0);
        let text = privacy.to_string();
        for forbidden in ["token", "example.com", "127.0.0.1", "::1", "active", "leak"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
        d.stop().unwrap();
    }

    #[test]
    fn demo_simulates_both_automatic_stop_reasons() {
        for (reason, message) in [
            (
                "hotspot_lost",
                "The hotspot turned off, so HotspotShade turned the tunnel off.",
            ),
            (
                "source_device_gone",
                "The source device stopped answering, so HotspotShade turned the tunnel off.",
            ),
        ] {
            let d = DemoBackend::new();
            d.start(json!({"mode":"tun","options":{"demo_auto_stop":reason}}))
                .unwrap();
            assert_eq!(d.status().unwrap()["running"], true);
            d.state.lock().unwrap().auto_stop_at = Some(Instant::now() - Duration::from_secs(4));
            let status = d.status().unwrap();
            assert_eq!(status["running"], false);
            assert_eq!(status["last_stop"]["reason"], reason);
            assert!(status["last_stop"]["at"].as_u64().is_some());
            assert_eq!(status["last_stop_message"], message);
            assert!(status["logs"]
                .to_string()
                .contains("Simulated automatic stop"));
            // The stop reason stays until the next start.
            assert_eq!(d.status().unwrap()["last_stop"]["reason"], reason);
            d.start(json!({"mode":"tun"})).unwrap();
            assert_eq!(d.status().unwrap()["last_stop"]["reason"], Value::Null);
            d.stop().unwrap();
            let status = d.status().unwrap();
            assert_eq!(status["last_stop"]["reason"], "user");
            assert_eq!(status["last_stop_message"], Value::Null);
        }
    }
}
