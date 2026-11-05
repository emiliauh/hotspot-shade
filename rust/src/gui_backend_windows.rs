//! Connect the Windows command-line GUI to the real Rust service.
//!
//! This backend has no pairing. The page uses the manual source device fields.
//! The service holds the token in memory and never sends it back. A start uses
//! source device proxy mode only. Direct mode and SOCKS5 mode are not
//! implemented on Windows.
use crate::gui::{phone_message, GuiBackend};
use crate::{
    normalization::{self, Audit},
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Clone)]
struct StoredTarget {
    host: Ipv4Addr,
    port: u16,
    token: Zeroizing<String>,
    iface: u32,
}

#[derive(Default)]
struct Presence {
    state: Option<&'static str>,
    checked_at: Option<u64>,
}

/// The real Windows backend. The service owns the tunnel and the credentials.
pub struct WindowsGuiBackend {
    service: Arc<Service>,
    target: Arc<Mutex<Option<StoredTarget>>>,
    presence: Arc<Mutex<Presence>>,
    last_stop: Mutex<Option<(&'static str, u64)>>,
    wintun_dll: Option<std::path::PathBuf>,
}

impl WindowsGuiBackend {
    pub fn new(service: Arc<Service>) -> Self {
        Self::with_wintun(service, None)
    }

    pub fn with_wintun(service: Arc<Service>, wintun_dll: Option<std::path::PathBuf>) -> Self {
        Self {
            service,
            target: Arc::new(Mutex::new(None)),
            presence: Arc::new(Mutex::new(Presence::default())),
            last_stop: Mutex::new(None),
            wintun_dll,
        }
    }

    fn phone_status(&self, running_phone: bool) -> Value {
        let (state, checked_at) = self
            .presence
            .lock()
            .ok()
            .map(|presence| (presence.state, presence.checked_at))
            .unwrap_or((None, None));
        let has_target = self
            .target
            .lock()
            .map(|target| target.is_some())
            .unwrap_or(false);
        let state = if running_phone {
            state.unwrap_or("connected")
        } else if has_target {
            state.unwrap_or("proxy_off")
        } else {
            "not_running"
        };
        let checked = checked_at.filter(|at| probe_fresh(*at, now()));
        json!({
            "state": state,
            "message": phone_message(state),
            "port_changed": false,
            "connections": Value::Null,
            "checked_at": checked,
            "trusted_by_source": Value::Null,
        })
    }

    fn target(&self) -> Option<StoredTarget> {
        self.target.lock().ok().and_then(|target| target.clone())
    }

    fn set_target(&self, options: &Value) -> Result<StoredTarget, String> {
        let target = parse_target(options)?;
        if let Ok(mut stored) = self.target.lock() {
            *stored = Some(target.clone());
        }
        Ok(target)
    }

    fn default_iface() -> Result<u32, String> {
        let index = crate::platform::default_interface_index()
            .map_err(|_| "no physical hotspot interface".to_string())?;
        let name = normalization::interface_name(index)
            .map_err(|_| "no physical hotspot interface".to_string())?;
        // After the /1 routes are installed, the default lookup can return the
        // tunnel adapter. It is not a physical hotspot interface.
        if name.starts_with("HotspotShade-Tunnel") {
            return Err("no physical hotspot interface".into());
        }
        Ok(index)
    }

    fn interface_name(index: u32) -> Result<String, String> {
        normalization::interface_name(index).map_err(|_| "no physical hotspot interface".into())
    }

    fn remember_probe(&self, state: &'static str) {
        if let Ok(mut presence) = self.presence.lock() {
            presence.state = Some(state);
            presence.checked_at = Some(now());
        }
    }

    fn probe_once(&self) -> Result<Value, String> {
        let Some(target) = self.target() else {
            return Err("manual_phone".into());
        };
        let proxy = PhoneProxy {
            address: SocketAddr::V4(SocketAddrV4::new(target.host, target.port)),
            username: "hotspotshade".into(),
            token: target.token.to_string(),
            iface: Some(target.iface),
            timeout: PROBE_TIMEOUT,
        };
        let audit = Audit::default();
        match proxy.check(&audit) {
            Ok(()) => self.remember_probe("ready"),
            Err(error) if crate::phone::authentication_rejected(&error) => {
                self.remember_probe("not_trusted")
            }
            Err(_) => self.remember_probe("not_responding"),
        }
        Ok(json!({"ok":true,"phone":self.phone_status(false)}))
    }
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

fn parse_target(options: &Value) -> Result<StoredTarget, String> {
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
    let iface = match options.get("iface").and_then(Value::as_str) {
        Some(name) if !name.is_empty() => {
            normalization::interface_index(name).map_err(|_| "invalid hotspot interface")?
        }
        _ => WindowsGuiBackend::default_iface()?,
    };
    Ok(StoredTarget {
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
        _ => match error.kind() {
            io::ErrorKind::NotFound if message.contains("wintun.dll") => "wintun_missing".into(),
            io::ErrorKind::PermissionDenied => "admin_required".into(),
            io::ErrorKind::Unsupported => "windows_phone_only".into(),
            _ => "service_start".into(),
        },
    }
}

impl GuiBackend for WindowsGuiBackend {
    fn status(&self) -> Result<Value, String> {
        let mut status = self.service.status();
        let running = status.get("running") == Some(&json!(true));
        let running_phone = running && status.get("mode") == Some(&json!("phone"));
        status["phone"] = self.phone_status(running_phone);
        status["forget"] = json!({"state":"none","attempts":0});
        let (reason, at) = self
            .last_stop
            .lock()
            .ok()
            .and_then(|last| *last)
            .map(|(reason, at)| (json!(reason), json!(at)))
            .unwrap_or((Value::Null, Value::Null));
        status["last_stop"] = reason;
        status["last_stop_at"] = at;
        status["last_stop_message"] = match status["last_stop"].as_str() {
            Some("hotspot_lost") => {
                json!("The hotspot turned off, so HotspotShade stopped the tunnel.")
            }
            Some("source_device_gone") => {
                json!("The source device stopped answering, so HotspotShade stopped the tunnel.")
            }
            _ => Value::Null,
        };
        Ok(status)
    }

    fn start_presence(&self, stop: Arc<AtomicBool>) {
        let target = self.target.clone();
        let presence = self.presence.clone();
        let _ = std::thread::Builder::new()
            .name("hotspotshade-probe".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let probe = target.lock().ok().and_then(|target| target.clone());
                    if let Some(target) = probe {
                        let proxy = PhoneProxy {
                            address: SocketAddr::V4(SocketAddrV4::new(target.host, target.port)),
                            username: "hotspotshade".into(),
                            token: target.token.to_string(),
                            iface: Some(target.iface),
                            timeout: PROBE_TIMEOUT,
                        };
                        let state = match proxy.check(&Audit::default()) {
                            Ok(()) => Some("ready"),
                            Err(error) if crate::phone::authentication_rejected(&error) => {
                                Some("not_trusted")
                            }
                            Err(_) => Some("not_responding"),
                        };
                        if let Ok(mut presence) = presence.lock() {
                            presence.state = state;
                            presence.checked_at = Some(now());
                        }
                    }
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
        let bound = WindowsGuiBackend::default_iface().is_ok_and(|index| {
            normalization::udp_socket(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(index),
                &Audit::default(),
            )
            .is_ok()
        });
        Ok(json!({
            "available": true,
            "platform": self.service.status()["platform"],
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
        Ok(json!({
            "host": Value::Null,
            "port": 0,
            "reachable": false,
            "message": "Source device discovery is not available on Windows. Enter the address and token from the source device app."
        }))
    }

    fn phone_check(&self, payload: Value) -> Result<Value, String> {
        let options = payload.get("options").ok_or("missing options")?;
        let target = self.set_target(options)?;
        let proxy = PhoneProxy {
            address: SocketAddr::V4(SocketAddrV4::new(target.host, target.port)),
            username: "hotspotshade".into(),
            token: target.token.to_string(),
            iface: Some(target.iface),
            timeout: PROBE_TIMEOUT,
        };
        proxy
            .check(&Audit::default())
            .map_err(|_| "source device authentication failed")?;
        self.remember_probe("ready");
        Ok(json!({"ok":true,"message":"The source device proxy accepted the token."}))
    }

    fn start(&self, payload: Value) -> Result<Value, String> {
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
        let (icmp_phone, icmp_persistent) = crate::gui::phone_icmp_options(options, true, true)?;
        let target = if options
            .get("token")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty())
        {
            self.set_target(options)?
        } else {
            self.target().ok_or("manual_phone")?
        };
        let iface = WindowsGuiBackend::interface_name(target.iface)?;
        let tun_options = TunOptions {
            iface: Some(iface),
            ipv6: Ipv6Policy::Forward,
            icmp_phone,
            icmp_persistent,
            wintun_dll: self.wintun_dll.clone(),
            ..TunOptions::default()
        };
        let proxy = PhoneProxy {
            address: SocketAddr::V4(SocketAddrV4::new(target.host, target.port)),
            username: "hotspotshade".into(),
            token: target.token.to_string(),
            iface: Some(target.iface),
            timeout: PROBE_TIMEOUT,
        };
        self.service
            .start_tun_options_cancellable(
                tun_options,
                Some(proxy),
                worker_count(),
                &AtomicBool::new(false),
            )
            .map_err(start_error)?;
        self.remember_probe("connected");
        if let Ok(mut last) = self.last_stop.lock() {
            *last = None;
        }
        Ok(json!({"mode":"phone"}))
    }

    fn stop(&self) -> Result<Value, String> {
        self.service.stop();
        if let Ok(mut presence) = self.presence.lock() {
            presence.state = None;
            presence.checked_at = None;
        }
        Ok(json!({"stopped":true}))
    }

    fn stop_for(&self, reason: &'static str) -> Result<Value, String> {
        self.service.stop();
        if let Ok(mut presence) = self.presence.lock() {
            presence.state = None;
            presence.checked_at = None;
        }
        if let Ok(mut last) = self.last_stop.lock() {
            *last = Some((reason, now()));
        }
        Ok(json!({"stopped":true}))
    }

    fn failures(&self) -> Result<Value, String> {
        Ok(self.service.failures())
    }

    fn diagnostics(&self) -> Result<Value, String> {
        Ok(self.service.diagnostics())
    }

    fn phone_probe(&self) -> Result<Value, String> {
        self.probe_once()
    }

    fn pair_start(&self) -> Result<Value, String> {
        Err("pair_unsupported".into())
    }

    fn pair_forget(&self) -> Result<Value, String> {
        Err("pair_unsupported".into())
    }
}
