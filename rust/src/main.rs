use hotspotshade::gui::{GuiBackend, GuiServer};
#[cfg(windows)]
use hotspotshade::gui_backend_windows::WindowsGuiBackend;
use hotspotshade::{
    autostop,
    normalization::{self, Audit},
    phone::PhoneProxy,
    service::{Ipv6Policy, Service, TunOptions},
};
#[cfg(unix)]
use hotspotshade::{
    environment, gui_backend::RustGuiBackend, phone_server::PhoneServer, privileged,
};
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[cfg(unix)]
fn probe() -> io::Result<()> {
    println!("uid={} root={}", unsafe { libc::geteuid() }, unsafe {
        libc::geteuid() == 0
    });
    let route = environment::default_route()?;
    println!("default IPv4 interface: {}", route.interface);
    println!(
        "system IPv4 DNS servers: {:?}",
        environment::system_dns().unwrap_or_default()
    );
    let audit = Audit::default();
    let sock = normalization::udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), None, &audit)?;
    println!("UDP TTL: {}", sock.ttl()?);
    println!("TTL audit failures: {}", audit.snapshot().1);
    println!("utun and route changes require administrator privileges.");
    Ok(())
}

/// Print read-only platform values. This command changes no adapter, route, or
/// socket option. It does not examine Wintun or start a tunnel.
#[cfg(windows)]
fn probe() -> io::Result<()> {
    println!("administrator={}", hotspotshade::platform::is_elevated());
    let index = hotspotshade::platform::default_interface_index()?;
    let name = normalization::interface_name(index).unwrap_or_else(|_| "unknown".into());
    println!("default IPv4 interface: {name} (index {index})");
    let audit = Audit::default();
    let sock = normalization::udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), None, &audit)?;
    println!("UDP TTL: {}", sock.ttl()?);
    println!("TTL audit failures: {}", audit.snapshot().1);
    println!("Wintun and route changes require Administrator rights.");
    Ok(())
}

#[cfg(any(unix, windows))]
fn phone_from_values(values: &[Value]) -> Result<PhoneProxy, String> {
    if values.len() != 4 {
        return Err("invalid source device settings".into());
    }
    let host: Ipv4Addr = values[0]
        .as_str()
        .ok_or("invalid source device address")?
        .parse()
        .map_err(|_| "invalid source device address")?;
    if host.is_unspecified() || host.is_loopback() || host.is_multicast() || host.is_broadcast() {
        return Err("invalid source device address".into());
    }
    let port = values[1]
        .as_u64()
        .filter(|p| *p > 0 && *p <= 65535)
        .ok_or("invalid source device port")? as u16;
    let username = values[2]
        .as_str()
        .filter(|v| *v == "hotspotshade")
        .ok_or("invalid source device user")?;
    let token = values[3]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 255)
        .ok_or("invalid source device token")?;
    Ok(PhoneProxy {
        address: SocketAddr::new(host.into(), port),
        username: username.into(),
        token: token.into(),
        iface: None,
        timeout: Duration::from_secs(5),
    })
}

#[cfg(unix)]
struct Helper {
    service: Service,
}
#[cfg(unix)]
impl privileged::PrivilegedService for Helper {
    fn start(
        &mut self,
        phone: &Value,
        experimental_icmp: bool,
        experimental_icmp_persistent: bool,
        cancel: &AtomicBool,
    ) -> Result<Value, String> {
        let proxy = phone_from_values(phone.as_array().ok_or("invalid source device settings")?)?;
        let options = TunOptions {
            ipv6: Ipv6Policy::Forward,
            icmp_phone: experimental_icmp,
            icmp_persistent: experimental_icmp_persistent,
            ..TunOptions::default()
        };
        self.service
            .start_tun_options_cancellable(options, Some(proxy), default_workers(), cancel)
            .map_err(|error| {
                let message = error.to_string();
                match message.as_str() {
                    "phone_auth" | "route_setup" | "tunnel_setup" => message,
                    _ => "service_start".to_string(),
                }
            })?;
        Ok(json!({"mode":"phone"}))
    }
    fn status(&mut self) -> Result<Value, String> {
        Ok(self.service.status())
    }
    fn failures(&mut self) -> Result<Value, String> {
        Ok(self.service.failures())
    }
    fn diagnostics(&mut self) -> Result<Value, String> {
        Ok(self.service.diagnostics())
    }
    fn stop(&mut self) -> Result<Value, String> {
        self.service.stop();
        Ok(json!({"stopped":true}))
    }
}
fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(2)
        .clamp(1, 4)
}

#[cfg(unix)]
fn helper(path: &str, owner: u32) -> io::Result<()> {
    let stream = privileged::connect_as_root(Path::new(path), owner)?;
    let signal_stream = stream.try_clone()?;
    let mut signals = signal_hook::iterator::Signals::new([libc::SIGINT, libc::SIGTERM])?;
    let signal_handle = signals.handle();
    let thread = std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            let _ = signal_stream.shutdown(std::net::Shutdown::Both);
        }
    });
    let result = privileged::serve_connection(
        stream,
        owner,
        &mut Helper {
            service: Service::new(),
        },
    );
    signal_handle.close();
    let _ = thread.join();
    result
}

#[cfg(unix)]
fn stop_signal() -> io::Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(libc::SIGINT, stop.clone())?;
    signal_hook::flag::register(libc::SIGTERM, stop.clone())?;
    Ok(stop)
}

/// Stop flag set by a Windows console control event.
#[cfg(windows)]
static CONSOLE_STOP: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

#[cfg(windows)]
unsafe extern "system" fn console_control(_event: u32) -> i32 {
    if let Some(stop) = CONSOLE_STOP.get() {
        stop.store(true, Ordering::Release);
    }
    // Handle the event here so the main thread can remove the routes and
    // close the adapter. Do not let the default handler end the process.
    1
}

/// Register one console control handler for the stop flag.
///
/// Ctrl-C, Ctrl-Break, Ctrl-Close, logoff, and shutdown set the flag. The main
/// thread then stops the service. A second call does nothing.
#[cfg(windows)]
fn register_console_stop(stop: Arc<AtomicBool>) -> io::Result<()> {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    if CONSOLE_STOP.set(stop).is_err() {
        return Ok(());
    }
    if unsafe { SetConsoleCtrlHandler(Some(console_control), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn stop_signal() -> io::Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    register_console_stop(stop.clone())?;
    Ok(stop)
}

/// Read the source device token from the environment or a private prompt.
///
/// The token is never an argument. The prompt turns off console echo while the
/// line is read. A redirected input has no echo, so it needs no console mode.
#[cfg(windows)]
fn read_windows_token(args: &[String]) -> Result<String, String> {
    if option(args, "--secrets-fd").is_some() {
        return Err("--secrets-fd is not supported on Windows".into());
    }
    if let Ok(token) = std::env::var("HOTSPOTSHADE_PHONE_TOKEN") {
        if !token.is_empty() && token.len() <= 255 {
            return Ok(token);
        }
        return Err("source device token must be 1 to 255 bytes".into());
    }
    read_console_secret()
}

#[cfg(windows)]
fn read_console_secret() -> Result<String, String> {
    use std::io::Write;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(kind: u32) -> *mut std::ffi::c_void;
        fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut std::ffi::c_void, mode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = 0xffff_fff6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    struct EchoGuard {
        handle: *mut std::ffi::c_void,
        mode: u32,
        active: bool,
    }
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            if self.active {
                unsafe {
                    SetConsoleMode(self.handle, self.mode);
                }
            }
        }
    }
    print!("Source device token: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode: u32 = 0;
    let console = !handle.is_null()
        && handle != (-1isize as *mut std::ffi::c_void)
        && unsafe { GetConsoleMode(handle, &mut mode) } != 0;
    let mut guard = EchoGuard {
        handle,
        mode,
        active: false,
    };
    if console
        && mode & ENABLE_ECHO_INPUT != 0
        && unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } != 0
    {
        guard.active = true;
    }
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    drop(guard);
    println!();
    read.map_err(|e| e.to_string())?;
    let token = line.trim_end_matches(['\r', '\n']).to_owned();
    if token.is_empty() || token.len() > 255 {
        return Err("source device token must be 1 to 255 bytes".into());
    }
    Ok(token)
}

// Install the signal handler before calling this function. If a signal
// arrives during startup, finish cleanup before returning to the caller.
fn guarded_start<S, C>(stop: &AtomicBool, start: S, cleanup: C) -> io::Result<bool>
where
    S: FnOnce() -> io::Result<()>,
    C: FnOnce(),
{
    if stop.load(Ordering::Acquire) {
        return Ok(false);
    }
    let result = start();
    if stop.load(Ordering::Acquire) {
        cleanup();
        return Ok(false);
    }
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            cleanup();
            Err(error)
        }
    }
}

/// How often the auto-stop observer reads the hotspot link and the tunnel
/// state. The probe runs on its own period. The value keeps Ctrl-C responsive.
#[cfg(any(unix, windows))]
const AUTO_STOP_TICK: Duration = Duration::from_secs(1);
/// How often the observer probes the source device while the tunnel runs.
#[cfg(any(unix, windows))]
const SOURCE_DEVICE_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// The deadline for one source device probe. This value is shorter than the
/// relay timeout, so a silent source device does not delay the link check.
#[cfg(any(unix, windows))]
const SOURCE_DEVICE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// One answer from the source device probe.
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeAnswer {
    /// The source device answered. A rejected token is an answer.
    Answered,
    /// The source device did not answer within the deadline.
    Silent,
    /// A local error prevents the probe from measuring presence.
    Unavailable,
    /// The stop flag cancelled the probe. This is no evidence either way.
    Cancelled,
}

#[cfg(any(unix, windows))]
impl ProbeAnswer {
    /// The fixed probe state for the auto-stop policy.
    fn state(self) -> Option<&'static str> {
        match self {
            ProbeAnswer::Answered => Some("ready"),
            ProbeAnswer::Silent => Some("not_responding"),
            ProbeAnswer::Cancelled | ProbeAnswer::Unavailable => None,
        }
    }
}

/// One probe of the source device proxy.
///
/// The probe uses a normalized outer socket with TTL 65 and the hotspot
/// interface. It sends the token to the source device for authentication.
/// It never writes the token to a log or an error text.
#[cfg(any(unix, windows))]
fn probe_source_device(proxy: &PhoneProxy, audit: &Audit, stop: &AtomicBool) -> ProbeAnswer {
    let (sockets_before, bad_before) = audit.snapshot();
    match proxy.check_cancellable(audit, stop) {
        Ok(()) => ProbeAnswer::Answered,
        // Either authentication rejection proves that the source device answered.
        Err(error) if hotspotshade::phone::authentication_rejected(&error) => ProbeAnswer::Answered,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => ProbeAnswer::Cancelled,
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                || audit.snapshot().1 > bad_before
                || audit.snapshot().0 == sockets_before =>
        {
            ProbeAnswer::Unavailable
        }
        Err(_) => ProbeAnswer::Silent,
    }
}

/// The auto-stop observer for one running CLI tunnel.
///
/// The monitor feeds the existing policy. The caller supplies the link and
/// probe observations, so tests use a fake clock, a fake link, and a fake
/// probe. A missing probe is not evidence of loss. The monitor never restarts
/// anything.
#[cfg(any(unix, windows))]
struct AutoStopMonitor {
    policy: autostop::AutoStopPolicy,
    phone_mode: bool,
    probe_interval: Duration,
    last_probe: Option<Instant>,
    /// The last answer. The observer reuses it until the next probe, so the
    /// 90 second timer measures continuous silence. A probe result is never
    /// older than the probe interval.
    last_answer: Option<ProbeAnswer>,
}

#[cfg(any(unix, windows))]
impl AutoStopMonitor {
    fn new(phone_mode: bool) -> Self {
        Self {
            policy: autostop::AutoStopPolicy::new(),
            phone_mode,
            probe_interval: SOURCE_DEVICE_PROBE_INTERVAL,
            last_probe: None,
            last_answer: None,
        }
    }

    /// True when the source device is due for a probe.
    fn probe_due(&self, now: Instant) -> bool {
        self.phone_mode
            && self
                .last_probe
                .is_none_or(|at| now.saturating_duration_since(at) >= self.probe_interval)
    }

    fn probed(&mut self, now: Instant) {
        self.last_probe = Some(now);
    }

    /// Feed one observation to the policy.
    ///
    /// `answer` is `None` when no probe ran, and the last answer stays. A
    /// cancelled probe is no evidence, so the timers keep their values.
    fn observe(
        &mut self,
        now: Instant,
        link_up: bool,
        answer: Option<ProbeAnswer>,
    ) -> Option<&'static str> {
        match answer {
            Some(ProbeAnswer::Cancelled) => return None,
            Some(ProbeAnswer::Unavailable) => self.last_answer = None,
            Some(answer) => self.last_answer = Some(answer),
            None => {}
        }
        let state = self.last_answer.and_then(ProbeAnswer::state);
        self.policy
            .observe(now, autostop::sample_from(link_up, self.phone_mode, state))
    }
}

/// Observe the hotspot and, in source device proxy mode, the source device
/// until the tunnel stops.
///
/// Return the auto-stop reason. Return `None` when the caller asked to stop or
/// the tunnel is no longer running. The caller runs its normal cleanup in both
/// cases. The clock, link, probe, and running checks are injected for tests.
#[cfg(any(unix, windows))]
fn auto_stop_wait<C, L, P, R>(
    monitor: &mut AutoStopMonitor,
    tick: Duration,
    mut clock: C,
    mut link: L,
    mut probe: P,
    mut running: R,
    stop: &AtomicBool,
) -> Option<&'static str>
where
    C: FnMut() -> Instant,
    L: FnMut() -> Option<bool>,
    P: FnMut(&AtomicBool) -> ProbeAnswer,
    R: FnMut() -> bool,
{
    while !stop.load(Ordering::Acquire) {
        if !running() {
            return None;
        }
        let now = clock();
        let mut link_up = link();
        let mut answer = None;
        if link_up == Some(true) && monitor.probe_due(now) {
            monitor.probed(now);
            answer = Some(probe(stop));
            // A probe can take time. Read the link again, so a link loss
            // during the probe stays a link loss.
            link_up = link();
        }
        match link_up {
            Some(link_up) => {
                if let Some(reason) = monitor.observe(clock(), link_up, answer) {
                    return Some(reason);
                }
            }
            None => {
                // A failed observation cannot establish continuous loss.
                monitor.policy.reset();
                monitor.last_answer = None;
            }
        }
        if !tick.is_zero() {
            std::thread::sleep(tick);
        }
    }
    None
}

/// The physical interface name to observe for auto-stop.
///
/// Return `None` when the process cannot name one. A missing name is not proof
/// of link loss, so the caller turns auto-stop off.
#[cfg(unix)]
fn hotspot_interface(iface: Option<&str>) -> Option<String> {
    let name = match iface {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => {
            return environment::default_route()
                .ok()
                .map(|route| route.interface)
        }
    };
    // A numeric value names an interface index. Convert it to a name, so the
    // link observer can match it. An unknown index is not a link loss.
    match name.parse::<u32>() {
        Ok(index) => interface_name(index),
        Err(_) => Some(name),
    }
}

/// Convert one interface index to its name. This reads the kernel table only.
#[cfg(unix)]
fn interface_name(index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    if unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) }.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    name.to_str().ok().map(str::to_owned)
}

/// The physical interface name to observe for auto-stop.
///
/// Windows has no link observer yet. The name still pins the source device
/// probe, so a silent source device stops the tunnel. A missing name turns
/// auto-stop off.
#[cfg(windows)]
fn hotspot_interface(iface: Option<&str>) -> Option<String> {
    if let Some(name) = iface.filter(|value| !value.is_empty()) {
        return Some(name.to_owned());
    }
    let index = hotspotshade::platform::default_interface_index().ok()?;
    normalization::interface_name(index).ok()
}

/// Print the fixed stop message for one reason. The text holds no secret.
#[cfg(any(unix, windows))]
fn print_auto_stop(reason: Option<&'static str>, target: &str) {
    match reason {
        Some("hotspot_lost") => {
            eprintln!("The hotspot turned off, so HotspotShade stopped the {target}.")
        }
        Some("source_device_gone") => {
            eprintln!("The source device stopped answering, so HotspotShade stopped the {target}.")
        }
        _ => {}
    }
}

fn option(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

/// Reject unrecognized options before starting a service or changing routes.
fn validate_options(args: &[String], values: &[&str], switches: &[&str]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !values.contains(&flag) && !switches.contains(&flag) {
            return Err("unsupported option or argument".into());
        }
        if !seen.insert(flag) {
            return Err(format!("duplicate option: {flag}"));
        }
        if values.contains(&flag) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            if value.is_empty() || value.starts_with('-') {
                return Err(format!("missing or invalid value for {flag}"));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

// The tunnel commands are unix only. The option tests run on Windows.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
struct PhoneOptions {
    phone: SocketAddr,
    listen: SocketAddr,
    iface: Option<String>,
    check: bool,
    secrets_fd: Option<i32>,
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_phone_options(args: &[String]) -> Result<PhoneOptions, String> {
    validate_options(
        args,
        &["--phone", "--listen", "--iface", "--secrets-fd"],
        &["--check"],
    )?;
    let phone = option(args, "--phone")
        .ok_or("source device address is required")?
        .parse::<SocketAddr>()
        .map_err(|_| "source device must be a numeric IPv4 address and port")?;
    match phone {
        SocketAddr::V4(v4)
            if v4.port() != 0
                && !v4.ip().is_unspecified()
                && !v4.ip().is_loopback()
                && !v4.ip().is_multicast()
                && !v4.ip().is_broadcast() => {}
        _ => return Err("source device must be a numeric unicast IPv4 address and port".into()),
    }
    let listen = option(args, "--listen")
        .unwrap_or_else(|| "127.0.0.1:1081".into())
        .parse::<SocketAddr>()
        .map_err(|_| "listen address must be 127.0.0.1:port")?;
    if listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || listen.port() == 0 {
        return Err("listen address must be 127.0.0.1 with a nonzero port".into());
    }
    let iface = option(args, "--iface");
    if iface.as_deref().is_some_and(|s| {
        s.starts_with("utun")
            || s.starts_with("lo")
            || s == "none"
            || s.chars().any(char::is_whitespace)
    }) {
        return Err("a physical hotspot interface is required".into());
    }
    Ok(PhoneOptions {
        phone,
        listen,
        iface,
        check: args.iter().any(|s| s == "--check"),
        secrets_fd: option(args, "--secrets-fd")
            .map(|v| {
                v.parse::<i32>()
                    .ok()
                    .filter(|fd| *fd >= 0)
                    .ok_or("invalid secret descriptor")
            })
            .transpose()?,
    })
}

/// Scoped phone UDP diagnostic. It pins outer sockets to the hotspot
/// interface and changes no route. Secrets come from a hidden prompt or a
/// private descriptor, never from arguments or the environment.
#[cfg(unix)]
fn phone_udp_diag(args: &[String]) -> Result<(), String> {
    use hotspotshade::udp_diag;
    let options = udp_diag::parse_options(args)?;
    let (index, link) = udp_diag::link_report(&options)?;
    let stop = stop_signal().map_err(|e| e.to_string())?;
    let secrets = match options.secrets_fd {
        Some(fd) => udp_diag::read_secrets_fd(fd)?,
        None => udp_diag::prompt_secrets(&stop)?,
    };
    let run_id = udp_diag::random_run_id().map_err(|_| "could not read random bytes")?;
    let config = udp_diag::config_from(&options, index, run_id);
    let results = udp_diag::run_diag(&config, &secrets, Some(&options.iface), &stop);
    drop(secrets);
    let mut link = link;
    udp_diag::finish_link(
        &mut link,
        &options.iface,
        options.phone.ip(),
        &[options.target.ip()],
    );
    let report = json!({
        "diagnostic": "phone-udp-diag",
        "routes_changed": false,
        "target": options.target.to_string(),
        "target_family": if options.target.is_ipv6() {"IPv6"} else {"IPv4"},
        "rate": options.rate, "seconds": options.seconds, "burst": options.burst,
        "pad": options.pad, "drop_percent": options.drop_percent,
        "own_responder": options.own_responder, "wait": options.wait,
        "interrupted": stop.load(Ordering::Acquire),
        "link": link, "results": results,
    });
    if options.json {
        println!("{report}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| "internal report error")?
        );
    }
    let any_received = report["results"]
        .as_array()
        .is_some_and(|r| r.iter().any(|m| m["received"].as_u64().unwrap_or(0) > 0));
    if any_received {
        Ok(())
    } else {
        Err("no STUN reply was received".into())
    }
}

/// Scoped TCP throughput and loaded-latency diagnostic. No route change.
#[cfg(unix)]
fn phone_speed_diag(args: &[String]) -> Result<(), String> {
    use hotspotshade::{speed_diag, udp_diag};
    let options = speed_diag::parse_options(args)?;
    let mut targets = Vec::new();
    if let Some(ip) = options.address {
        targets.push(ip);
    }
    if let Some(t) = options.udp_target {
        targets.push(t.ip());
    }
    let (index, mut link) = udp_diag::link_facts(&options.iface, options.phone, &targets)?;
    let stop = stop_signal().map_err(|e| e.to_string())?;
    let secrets = if options.needs_phone() {
        Some(match options.secrets_fd {
            Some(fd) => udp_diag::read_secrets_fd(fd)?,
            None => udp_diag::prompt_secrets(&stop)?,
        })
    } else {
        None
    };
    let config = speed_diag::config_from(&options, index);
    let runs = speed_diag::run_all(
        &options.paths,
        options.repeat,
        &config,
        secrets.as_ref(),
        Some(&options.iface),
        &stop,
    );
    drop(secrets);
    udp_diag::finish_link(&mut link, &options.iface, options.phone.ip(), &targets);
    let summary = speed_diag::summarize(&runs, &options.paths);
    let report = json!({
        "diagnostic": "phone-speed-diag",
        "routes_changed": false,
        "protocol": "TCP, plain HTTP/1.1",
        "host": options.host,
        "address_family": options.address.map(|a| if a.is_ipv6() {"IPv6"} else {"IPv4"}),
        "port": options.port,
        "paths": options.paths.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "streams": options.streams, "seconds": options.seconds, "idle_seconds": options.idle_seconds,
        "warmup": options.warmup, "probe_interval_ms": options.probe_interval_ms,
        "repeat": options.repeat, "max_mb_per_phase": options.max_mb,
        "planned_max_bytes": options.planned_max_bytes(),
        "interrupted": stop.load(Ordering::Acquire),
        "link": link, "summary": summary, "runs": runs,
    });
    if options.json {
        println!("{report}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| "internal report error")?
        );
    }
    let moved = report["runs"].as_array().is_some_and(|runs| {
        runs.iter().any(|r| {
            r["phases"].as_array().is_some_and(|p| {
                p.iter()
                    .any(|p| p["throughput"]["bytes_counted"].as_u64().unwrap_or(0) > 0)
            })
        })
    });
    if moved {
        Ok(())
    } else {
        Err("no load data was transferred".into())
    }
}

/// Bounded same-size UDP responder for a host that the user controls.
fn udp_responder(args: &[String]) -> Result<(), String> {
    use hotspotshade::udp_responder;
    let options = udp_responder::parse_options(args)?;
    let socket = std::net::UdpSocket::bind(options.listen)
        .map_err(|_| "could not bind the listen address")?;
    let stop = stop_signal().map_err(|e| e.to_string())?;
    eprintln!(
        "UDP responder on {} for at most {} seconds. Press Ctrl-C to stop.",
        options.listen, options.seconds
    );
    let (stats, elapsed, locked) =
        udp_responder::serve(&socket, &options, &stop).map_err(|_| "socket error")?;
    let report = json!({"diagnostic": "udp-responder", "stats": stats.to_json(elapsed, locked)});
    if options.json {
        println!("{report}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| "internal report error")?
        );
    }
    Ok(())
}

#[cfg(unix)]
fn read_gui_token(fd: i32) -> Result<[u8; 64], String> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    if fd < 0 {
        return Err("invalid token fd".into());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buffer = [0u8; 65];
    let mut count = 0;
    while count < buffer.len() {
        match file.read(&mut buffer[count..count + 1]) {
            Ok(0) => break,
            Ok(_) => {
                count += 1;
                if buffer[count - 1] == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                for byte in &mut buffer {
                    unsafe {
                        std::ptr::write_volatile(byte, 0);
                    }
                }
                return Err("invalid token fd".into());
            }
        }
    }
    let valid = count == 65
        && buffer[64] == b'\n'
        && buffer[..64]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
    let mut token = [0u8; 64];
    if valid {
        token.copy_from_slice(&buffer[..64]);
    }
    for byte in &mut buffer {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    if valid {
        Ok(token)
    } else {
        Err("invalid token".into())
    }
}

#[cfg(not(unix))]
fn read_gui_token(_fd: i32) -> Result<[u8; 64], String> {
    Err("token fd is unsupported".into())
}

#[cfg(unix)]
fn write_gui_port(path: &Path, port: u16) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    let temp = std::path::PathBuf::from(name);
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        writeln!(file, "{port}")?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(not(unix))]
fn write_gui_port(_path: &Path, _port: u16) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "port file is unsupported",
    ))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        #[cfg(any(unix, windows))]
        Some("probe") => { validate_options(&args[1..],&[],&[])?; probe().map_err(|e|e.to_string()) },
        Some("gui") => {
            validate_options(&args[1..],&["--port","--port-file","--token-fd","--parent-fd","--wintun"],&["--demo","--no-open","--experimental-icmp","--experimental-icmp-persistent"])?;
            #[cfg(not(windows))]
            if option(&args,"--wintun").is_some() { return Err("--wintun is supported on Windows only".into()); }
            if args.iter().any(|arg|arg=="--experimental-icmp-persistent") && !args.iter().any(|arg|arg=="--experimental-icmp") {return Err("persistent ICMP requires --experimental-icmp".into());}
            let port=option(&args,"--port").unwrap_or_else(||"8787".into()).parse::<u16>().map_err(|_|"invalid port")?;
            let mut server=GuiServer::bind(port).map_err(|e|e.to_string())?;
            if let Some(fd) = option(&args,"--token-fd") {
                let fd=fd.parse::<i32>().map_err(|_|"invalid token fd")?;
                server.set_token(read_gui_token(fd)?);
            }
            let port=server.local_addr().map_err(|e|e.to_string())?.port();
            if let Some(path) = option(&args,"--port-file") { write_gui_port(Path::new(&path), port).map_err(|e|e.to_string())?; }
            let stop=Arc::new(AtomicBool::new(false));
            let port_path=option(&args,"--port-file").map(std::path::PathBuf::from);
            struct PortGuard(Option<std::path::PathBuf>);
            impl Drop for PortGuard {
                fn drop(&mut self) {
                    if let Some(path) = &self.0 {
                        let _ = std::fs::remove_file(path);
                        let mut temp = path.as_os_str().to_os_string();
                        temp.push(".tmp");
                        let _ = std::fs::remove_file(temp);
                    }
                }
            }
            let _port_guard=PortGuard(port_path);
            #[cfg(unix)]
            if let Some(fd) = option(&args,"--parent-fd") {
                let fd=fd.parse::<i32>().map_err(|_|"invalid parent fd")?;
                if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 { return Err("invalid parent fd".into()); }
                let parent_stop=Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !parent_stop.load(Ordering::Acquire) {
                        let mut pfd=libc::pollfd { fd, events: libc::POLLHUP, revents: 0 };
                        let n=unsafe { libc::poll(&mut pfd, 1, 250) };
                        if n > 0 && pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                            parent_stop.store(true, Ordering::Release);
                            break;
                        }
                    }
                });
            }
            #[cfg(not(unix))]
            if option(&args,"--parent-fd").is_some() { return Err("parent fd is unsupported".into()); }
            #[cfg(unix)]
            {
                signal_hook::flag::register(libc::SIGINT,stop.clone()).map_err(|e|e.to_string())?;
                signal_hook::flag::register(libc::SIGTERM,stop.clone()).map_err(|e|e.to_string())?;
            }
            #[cfg(windows)]
            register_console_stop(Arc::clone(&stop)).map_err(|e|e.to_string())?;
            let backend:Arc<dyn GuiBackend>=if args.iter().any(|arg|arg=="--demo") {
                Arc::new(hotspotshade::demo::DemoBackend::new())
            } else {
                #[cfg(unix)]
                {
                    // Phone mode turns ping on by default. The web page can turn
                    // it off. The old flags stay accepted for launch scripts.
                    Arc::new(RustGuiBackend::new(Arc::new(Service::new())))
                }
                #[cfg(windows)]
                {
                    Arc::new(WindowsGuiBackend::with_wintun(
                        Arc::new(Service::new()),
                        option(&args, "--wintun").map(std::path::PathBuf::from),
                    ))
                }
            };
            println!("GUI listening on http://127.0.0.1:{port}/");
            let result=server.run(Arc::clone(&backend),stop);
            let cleanup=backend.stop();
            result.map_err(|e|e.to_string())?;
            cleanup.map(|_|())
        }
        #[cfg(unix)]
        Some("--privileged-helper") if args.len()==3 => {
            let owner=args[2].parse().map_err(|_|"invalid owner")?;
            helper(&args[1],owner).map_err(|e|e.to_string())
        }
        #[cfg(unix)]
        Some("socks5") => {
            validate_options(&args[1..],&["--port","--iface"],&[])?;
            let port=option(&args,"--port").unwrap_or_else(||"1080".into()).parse::<u16>().map_err(|_|"invalid port")?;
            if port==0 { return Err("invalid port".into()); }
            let iface=option(&args,"--iface");
            let auto_iface=hotspot_interface(iface.as_deref());
            let service_iface=iface.as_deref().or(auto_iface.as_deref());
            if auto_iface.is_none() { eprintln!("Warning: hotspot link auto-stop is off because the interface name is unknown."); }
            let service=Service::new();
            let stop=stop_signal().map_err(|e|e.to_string())?;
            if !guarded_start(&stop,||service.start_socks(SocketAddr::from(([127,0,0,1],port)),service_iface,None),||service.stop()).map_err(|e|e.to_string())? { return Ok(()); }
            println!("SOCKS5 listening on 127.0.0.1:{port}. Press Ctrl-C to stop.");
            let mut monitor=AutoStopMonitor::new(false);
            let reason=auto_stop_wait(&mut monitor,AUTO_STOP_TICK,Instant::now,
                ||auto_iface.as_deref().map_or(Some(true), |name| autostop::link_observation(name).ok()),
                |_|ProbeAnswer::Silent,
                ||service.is_running(),
                &stop);
            let listener_failed=reason.is_none() && !stop.load(Ordering::Acquire) && !service.is_running();
            service.stop();
            print_auto_stop(reason,"SOCKS5 proxy");
            if let Some(error)=service.status()["error"].as_str() { return Err(error.to_owned()); }
            if listener_failed { return Err("The SOCKS5 listener stopped unexpectedly.".into()); }
            Ok(())
        }
        #[cfg(unix)]
        Some("phone") => {
            let options=parse_phone_options(&args[1..])?;
            let stop=stop_signal().map_err(|e|e.to_string())?;
            // Prefer a private descriptor. Keep the environment variable for compatibility.
            // Otherwise prompt on the terminal with echo disabled.
            let token=match options.secrets_fd {
                Some(fd)=>hotspotshade::udp_diag::read_secrets_fd(fd)?.token().to_owned(),
                None=>match std::env::var("HOTSPOTSHADE_PHONE_TOKEN") {
                    Ok(token)=>token,
                    Err(_)=>hotspotshade::udp_diag::prompt_secrets(&stop)?.token().to_owned(),
                },
            };
            if token.is_empty() || token.len()>255 {return Err("source device token must be 1 to 255 bytes".into());}
            let iface=match options.iface {Some(name)=>name,None=>environment::default_route().map_err(|_|"no physical hotspot interface")?.interface};
            let index=normalization::interface_index(&iface).map_err(|_|"invalid hotspot interface")?;
            let auto_iface=hotspot_interface(Some(&iface));
            if auto_iface.is_none() { eprintln!("Warning: hotspot link auto-stop is off because the interface name is unknown."); }
            let phone=Arc::new(PhoneProxy {address:options.phone,username:"hotspotshade".into(),token,iface:Some(index),timeout:Duration::from_secs(5)});
            if stop.load(Ordering::Acquire) {return Ok(());}
            let audit=Arc::new(Audit::default());
            if options.check {
                let result=phone.check(&audit);
                if stop.load(Ordering::Acquire) {return Ok(());}
                result.map_err(|_|"Source device authentication failed. Check the token and hotspot connection.")?;
                println!("The source device proxy accepted the token.");
                return Ok(());
            }
            // The probe uses a second credential copy with a short deadline.
            // It is pinned to the hotspot interface, so it never follows the
            // tunnel route.
            let probe=PhoneProxy {address:phone.address,username:phone.username.clone(),token:phone.token.clone(),iface:Some(index),timeout:SOURCE_DEVICE_PROBE_TIMEOUT};
            let mut server=PhoneServer::start(options.listen,phone,audit.clone()).map_err(|_|"Could not start the source device adapter.")?;
            if !stop.load(Ordering::Acquire) {
                println!("Source device adapter listening on {}. Press Ctrl-C to stop.",server.address);
            }
            let mut monitor=AutoStopMonitor::new(true);
            let probe_audit=Audit::default();
            let reason=auto_stop_wait(&mut monitor,AUTO_STOP_TICK,Instant::now,
                ||auto_iface.as_deref().map_or(Some(true), |name| autostop::link_observation(name).ok()),
                |stop|probe_source_device(&probe,&probe_audit,stop),
                ||server.is_running(),
                &stop);
            let listener_failed=reason.is_none() && !stop.load(Ordering::Acquire) && !server.is_running();
            server.stop();
            print_auto_stop(reason,"source device adapter");
            if listener_failed { return Err("The source device adapter stopped unexpectedly.".into()); }
            Ok(())
        }
        #[cfg(unix)]
        Some("phone-udp-diag") => {
            validate_options(&args[1..],hotspotshade::udp_diag::VALUE_FLAGS,hotspotshade::udp_diag::SWITCHES)?;
            phone_udp_diag(&args[1..])
        }
        #[cfg(unix)]
        Some("phone-speed-diag") => {
            validate_options(&args[1..],hotspotshade::speed_diag::VALUE_FLAGS,hotspotshade::speed_diag::SWITCHES)?;
            phone_speed_diag(&args[1..])
        }
        Some("udp-responder") => {
            validate_options(&args[1..],hotspotshade::udp_responder::VALUE_FLAGS,hotspotshade::udp_responder::SWITCHES)?;
            udp_responder(&args[1..])
        }
        #[cfg(unix)]
        Some("tun") => {
            validate_options(&args[1..],&["--iface","--ipv6","--phone","--workers","--unit","--addr","--dns-upstream","--secrets-fd"],&["--no-pin","--no-routes","--experimental-icmp","--experimental-icmp-persistent"])?;
            let iface=option(&args,"--iface");
            let endpoint=option(&args,"--phone");
            let secrets_fd=option(&args,"--secrets-fd").map(|v|v.parse::<i32>().ok().filter(|fd|*fd>=0).ok_or("invalid secret descriptor")).transpose()?;
            if secrets_fd.is_some() && endpoint.is_none() {return Err("--secrets-fd needs --phone".into());}
            let proxy=if let Some(endpoint) = endpoint {
                let address=endpoint.parse::<SocketAddr>().map_err(|_|"source device must be a numeric IPv4 address and port")?;
                // Prefer a private descriptor. Keep the environment variable for compatibility.
                // Otherwise prompt on the terminal with echo disabled. Never take the token from arguments.
                let token=match secrets_fd {
                    Some(fd)=>hotspotshade::udp_diag::read_secrets_fd(fd)?.token().to_owned(),
                    None=>match std::env::var("HOTSPOTSHADE_PHONE_TOKEN") {
                        Ok(token)=>token,
                        Err(_)=>{
                            // Ctrl-C at the prompt restores terminal echo. No route exists yet.
                            let prompt_stop=stop_signal().map_err(|e|e.to_string())?;
                            hotspotshade::udp_diag::prompt_secrets(&prompt_stop)?.token().to_owned()
                        }
                    },
                };
                Some(phone_from_values(&[json!(address.ip().to_string()),json!(address.port()),json!("hotspotshade"),json!(token)])?)
            } else { None };
            let v6=match option(&args,"--ipv6").as_deref() {
                Some("forward") => Ipv6Policy::Forward, Some("block") => Ipv6Policy::Block,
                Some("inherit") => Ipv6Policy::Inherit,
                Some(_) => return Err("IPv6 policy must be block, forward, or inherit".into()),
                None => if proxy.is_some() {Ipv6Policy::Forward} else {Ipv6Policy::Block},
            };
            let workers=option(&args,"--workers").map(|v|v.parse::<usize>()).transpose().map_err(|_|"invalid worker count")?.unwrap_or_else(default_workers);
            if !(1..=8).contains(&workers) { return Err("worker count must be 1 to 8".into()); }
            let unit=option(&args,"--unit").map(|v|v.parse::<u32>()).transpose().map_err(|_|"invalid tunnel unit")?.unwrap_or(0);
            let addr=option(&args,"--addr").map(|v|v.parse::<Ipv4Addr>()).transpose().map_err(|_|"invalid tunnel address")?.unwrap_or(Ipv4Addr::new(198,18,0,1));
            let dns_upstream=option(&args,"--dns-upstream").map(|v|hotspotshade::dns::parse_server(&v)).transpose().map_err(|_|"invalid DNS upstream")?;
            let mut options=TunOptions {unit,addr,iface,dns_upstream,ipv6:v6,
                no_routes:args.iter().any(|v|v=="--no-routes"),no_pin:args.iter().any(|v|v=="--no-pin"),
                icmp_phone:args.iter().any(|v|v=="--experimental-icmp"),icmp_persistent:args.iter().any(|v|v=="--experimental-icmp-persistent")};
            options.validate(proxy.is_some(),workers).map_err(|e|e.to_string())?;
            if options.no_pin {eprintln!("Warning: outer sockets are not pinned. Traffic can loop.");}
            if options.no_routes {eprintln!("Warning: routes are not managed. IPv6 blocking is not installed.");}
            if options.ipv6==Ipv6Policy::Inherit {eprintln!("Warning: IPv6 uses the existing network path and can bypass the tunnel.");}
            let service=Service::new();
            let stop=stop_signal().map_err(|e|e.to_string())?;
            // Read the physical interface before the route change. The observer
            // must check the hotspot, not the tunnel device.
            let auto_iface=hotspot_interface(options.iface.as_deref());
            if options.iface.is_none() { options.iface=auto_iface.clone(); }
            let probe=match (proxy.as_ref(),auto_iface.as_deref()) {
                (Some(proxy),Some(name))=>normalization::interface_index(name).ok().map(|index|PhoneProxy {
                    address:proxy.address,username:proxy.username.clone(),token:proxy.token.clone(),
                    iface:Some(index),timeout:SOURCE_DEVICE_PROBE_TIMEOUT,
                }),
                _=>None,
            };
            if auto_iface.is_none() {
                eprintln!("Warning: auto-stop is off because no physical hotspot interface is known.");
            } else if proxy.is_some() && probe.is_none() {
                eprintln!("Warning: a silent source device does not stop the tunnel because the hotspot interface is invalid.");
            }
            if !guarded_start(&stop,||service.start_tun_options_cancellable(options,proxy,workers,&stop),||service.stop()).map_err(|e|e.to_string())? { return Ok(()); }
            println!("Tunnel is running. Press Ctrl-C to stop and remove routes.");
            let mut monitor=AutoStopMonitor::new(probe.is_some());
            let probe_audit=Audit::default();
            let reason=auto_stop_wait(&mut monitor,AUTO_STOP_TICK,Instant::now,
                ||auto_iface.as_deref().map_or(Some(true), |name| autostop::link_observation(name).ok()),
                |stop|match &probe {Some(proxy)=>probe_source_device(proxy,&probe_audit,stop),None=>ProbeAnswer::Silent},
                ||service.is_running(),
                &stop);
            service.stop();
            let status=service.status();
            let reason=reason.or_else(||status.pointer("/last_stop/reason").and_then(Value::as_str).and_then(autostop::reason));
            print_auto_stop(reason,"tunnel");
            if let Some(error)=status["error"].as_str() { return Err(error.to_owned()); }
            Ok(())
        }
        // The Windows start path uses source device proxy mode only. The Wintun
        // DLL path is explicit, and the token comes from the environment or a
        // private console prompt. The token never appears in an argument.
        #[cfg(windows)]
        Some("tun") => {
            if option(&args, "--secrets-fd").is_some() {
                return Err("--secrets-fd is not supported on Windows. Use the token prompt.".into());
            }
            validate_options(
                &args[1..],
                &["--iface", "--phone", "--workers", "--unit", "--addr", "--wintun"],
                &["--experimental-icmp", "--experimental-icmp-persistent"],
            )?;
            let endpoint = option(&args, "--phone")
                .ok_or("source device proxy mode requires --phone IPv4:PORT")?;
            let address = endpoint
                .parse::<SocketAddr>()
                .map_err(|_| "source device must be a numeric IPv4 address and port")?;
            let token = read_windows_token(&args)?;
            let proxy = phone_from_values(&[
                json!(address.ip().to_string()),
                json!(address.port()),
                json!("hotspotshade"),
                json!(token),
            ])?;
            let workers = option(&args, "--workers")
                .map(|value| value.parse::<usize>())
                .transpose()
                .map_err(|_| "invalid worker count")?
                .unwrap_or_else(default_workers);
            if !(1..=8).contains(&workers) {
                return Err("worker count must be 1 to 8".into());
            }
            let unit = option(&args, "--unit")
                .map(|value| value.parse::<u32>())
                .transpose()
                .map_err(|_| "invalid tunnel unit")?
                .unwrap_or(0);
            let addr = option(&args, "--addr")
                .map(|value| value.parse::<Ipv4Addr>())
                .transpose()
                .map_err(|_| "invalid tunnel address")?
                .unwrap_or(Ipv4Addr::new(198, 18, 0, 1));
            let mut options = TunOptions {
                unit,
                addr,
                iface: option(&args, "--iface"),
                dns_upstream: None,
                no_routes: false,
                no_pin: false,
                ipv6: Ipv6Policy::Forward,
                icmp_phone: args.iter().any(|value| value == "--experimental-icmp"),
                icmp_persistent: args
                    .iter()
                    .any(|value| value == "--experimental-icmp-persistent"),
                wintun_dll: option(&args, "--wintun").map(std::path::PathBuf::from),
            };
            options.validate(true, workers).map_err(|e| e.to_string())?;
            let service = Service::new();
            let stop = stop_signal().map_err(|e| e.to_string())?;
            // Resolve the physical interface before the route change. The
            // source device probe stays pinned to it for the whole run.
            let auto_iface = hotspot_interface(options.iface.as_deref());
            if options.iface.is_none() {
                options.iface = auto_iface.clone();
            }
            let probe = match auto_iface.as_deref() {
                Some(name) => normalization::interface_index(name).ok().map(|index| PhoneProxy {
                    address: proxy.address,
                    username: proxy.username.clone(),
                    token: proxy.token.clone(),
                    iface: Some(index),
                    timeout: SOURCE_DEVICE_PROBE_TIMEOUT,
                }),
                None => None,
            };
            if auto_iface.is_none() {
                eprintln!("Warning: auto-stop is off because no physical hotspot interface is known.");
            } else if probe.is_none() {
                eprintln!("Warning: a silent source device does not stop the tunnel because the hotspot interface is invalid.");
            }
            if !guarded_start(
                &stop,
                || {
                    service.start_tun_options_cancellable(
                        options,
                        Some(proxy),
                        workers,
                        &stop,
                    )
                },
                || service.stop(),
            )
            .map_err(|e| e.to_string())?
            {
                return Ok(());
            }
            println!("Tunnel is running. Press Ctrl-C to stop and remove routes.");
            let mut monitor = AutoStopMonitor::new(probe.is_some());
            let probe_audit = Audit::default();
            // Windows has no hotspot link observer yet. A source device that
            // stops answering still stops the tunnel. A hotspot loss is not
            // detected by this path.
            let reason = auto_stop_wait(
                &mut monitor,
                AUTO_STOP_TICK,
                Instant::now,
                || Some(true),
                |stop| match &probe {
                    Some(proxy) => probe_source_device(proxy, &probe_audit, stop),
                    None => ProbeAnswer::Silent,
                },
                || service.is_running(),
                &stop,
            );
            service.stop();
            print_auto_stop(reason, "tunnel");
            if let Some(error) = service.status()["error"].as_str() {
                return Err(error.to_owned());
            }
            Ok(())
        }
        #[cfg(windows)]
        Some("--privileged-helper" | "socks5" | "phone" | "phone-udp-diag" | "phone-speed-diag") => {
            Err(hotspotshade::WINDOWS_NOT_IMPLEMENTED.into())
        }
        _ => Err("Usage: hotspotshade probe | gui [--port N] [--wintun PATH] [--experimental-icmp] [--experimental-icmp-persistent] | socks5 [--port N] [--iface NAME] | phone --phone IPv4:PORT [--listen 127.0.0.1:PORT] [--iface NAME] [--secrets-fd N] [--check] | phone-udp-diag --phone 172.20.10.1:PORT --iface NAME --target IP:PORT [--rate N] [--seconds N] [--burst N] [--pad N] [--wait N] [--drop-percent N] [--secrets-fd N] [--own-responder] [--json] | phone-speed-diag --phone IPv4:PORT --iface NAME --host NAME|IP [--address IP] [--port N] [--download-path /P] [--upload-path /P] [--probe-path /P] [--paths phone|direct|phone,direct|direct,phone] [--streams N] [--seconds N] [--idle-seconds N] [--warmup N] [--probe-interval-ms N] [--repeat N] [--max-mb N] [--udp-target IP:PORT] [--secrets-fd N] [--json] | udp-responder --listen IP:PORT [--seconds N] [--max-pps N] [--peer IP] [--json] | tun [--iface NAME] [--unit N] [--addr IPv4] [--wintun PATH] [--dns-upstream IPv4[:PORT]] [--ipv6 block|forward|inherit] [--no-pin] [--no-routes] [--phone IP:PORT] [--secrets-fd N] [--experimental-icmp] [--experimental-icmp-persistent] [--workers N]".into()),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::sync::atomic::AtomicUsize;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn invalid_options_do_not_run_start_action() {
        for input in [
            vec!["--unknown"],
            vec!["--dns-servers", "1.1.1.1"],
            vec!["--workers"],
            vec!["--workers", "--iface", "en0"],
            vec!["--workers", "2", "--workers", "4"],
            vec!["unexpected"],
        ] {
            let called = AtomicBool::new(false);
            let result = validate_options(
                &args(&input),
                &["--iface", "--ipv6", "--phone", "--workers"],
                &[],
            )
            .map(|_| called.store(true, Ordering::Release));
            assert!(result.is_err());
            assert!(!called.load(Ordering::Acquire));
        }
    }

    #[test]
    fn direct_tun_options_are_accepted() {
        let values = [
            "--iface",
            "--ipv6",
            "--phone",
            "--workers",
            "--unit",
            "--addr",
            "--dns-upstream",
        ];
        assert!(validate_options(
            &args(&[
                "--no-routes",
                "--no-pin",
                "--ipv6",
                "inherit",
                "--unit",
                "8",
                "--addr",
                "198.18.0.1",
                "--dns-upstream",
                "1.1.1.1"
            ]),
            &values,
            &["--no-pin", "--no-routes"]
        )
        .is_ok());
    }

    #[test]
    fn gui_options_accept_supported_flags_only() {
        assert!(validate_options(
            &args(&["--demo", "--no-open", "--port", "8796"]),
            &["--port"],
            &["--demo", "--no-open"]
        )
        .is_ok());
        assert!(validate_options(
            &args(&["--demo", "--demo"]),
            &["--port"],
            &["--demo", "--no-open"]
        )
        .is_err());
        assert!(validate_options(
            &args(&["--port", "8796", "unexpected"]),
            &["--port"],
            &["--demo", "--no-open"]
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_port_temp_file_is_removed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "hs-port-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("port");
        let mut temp = path.as_os_str().to_os_string();
        temp.push(".tmp");
        let temp = std::path::PathBuf::from(temp);
        std::fs::write(&temp, "stale").unwrap();
        write_gui_port(&path, 8793).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "8793\n");
        assert!(!temp.exists());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn experimental_icmp_flag_is_explicit_and_not_repeatable() {
        assert!(validate_options(
            &args(&["--experimental-icmp"]),
            &["--port"],
            &["--demo", "--no-open", "--experimental-icmp"]
        )
        .is_ok());
        assert!(validate_options(
            &args(&["--phone", "172.20.10.1:18080", "--experimental-icmp"]),
            &["--phone"],
            &["--experimental-icmp"]
        )
        .is_ok());
        assert!(validate_options(
            &args(&["--experimental-icmp", "--experimental-icmp"]),
            &["--phone"],
            &["--experimental-icmp"]
        )
        .is_err());
    }

    #[test]
    fn phone_options_require_numeric_remote_and_loopback_listener() {
        let parsed = parse_phone_options(&args(&["--phone", "172.20.10.1:18080"])).unwrap();
        assert_eq!(parsed.phone, "172.20.10.1:18080".parse().unwrap());
        assert_eq!(parsed.listen, "127.0.0.1:1081".parse().unwrap());
        assert_eq!(parsed.iface, None);
        assert!(!parsed.check);
        let parsed = parse_phone_options(&args(&[
            "--phone",
            "172.20.10.1:1080",
            "--listen",
            "127.0.0.1:9000",
            "--iface",
            "en5",
            "--check",
        ]))
        .unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(parsed.iface.as_deref(), Some("en5"));
        assert!(parsed.check);
        for input in [
            vec![],
            vec!["--phone", "localhost:1080"],
            vec!["--phone", "127.0.0.1:1080"],
            vec!["--phone", "[::1]:1080"],
            vec!["--phone", "172.20.10.1:0"],
            vec!["--phone", "172.20.10.1:1080", "--listen", "0.0.0.0:1081"],
            vec!["--phone", "172.20.10.1:1080", "--listen", "127.0.0.1:0"],
            vec!["--phone", "172.20.10.1:1080", "--iface", "utun2"],
            vec!["--phone", "172.20.10.1:1080", "--token", "not-accepted"],
            vec!["--phone", "172.20.10.1:1080", "--check", "--check"],
            vec!["--phone", "172.20.10.1:1080", "--listen"],
        ] {
            assert!(
                parse_phone_options(&args(&input)).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn guarded_start_skips_or_cleans_up() {
        let stop = AtomicBool::new(true);
        let called = AtomicBool::new(false);
        assert!(!guarded_start(
            &stop,
            || {
                called.store(true, Ordering::Release);
                Ok(())
            },
            || {}
        )
        .unwrap());
        assert!(!called.load(Ordering::Acquire));
        stop.store(false, Ordering::Release);
        let cleaned = AtomicBool::new(false);
        let result = guarded_start(
            &stop,
            || Err(io::Error::other("startup failed")),
            || cleaned.store(true, Ordering::Release),
        );
        assert!(result.is_err());
        assert!(cleaned.load(Ordering::Acquire));
    }

    // The subprocess keeps signal handlers out of the parent test runner.
    #[cfg(unix)]
    #[test]
    fn signal_during_start_runs_cleanup() {
        const CHILD: &str = "HOTSPOTSHADE_SIGNAL_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let stop = stop_signal().unwrap();
            for signal in [libc::SIGINT, libc::SIGTERM] {
                stop.store(false, Ordering::Release);
                let cleaned = AtomicBool::new(false);
                let started = guarded_start(
                    &stop,
                    || {
                        assert_eq!(unsafe { libc::raise(signal) }, 0);
                        Ok(())
                    },
                    || cleaned.store(true, Ordering::Release),
                )
                .unwrap();
                assert!(!started);
                assert!(cleaned.load(Ordering::Acquire));
            }
        } else {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::signal_during_start_runs_cleanup",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    /// A clock that moves forward by a fixed step on every read. It stops the
    /// test if the monitor never returns.
    #[cfg(unix)]
    fn fake_clock(step: Duration) -> impl FnMut() -> Instant {
        let mut now = Instant::now();
        let mut reads = 0u32;
        move || {
            reads += 1;
            assert!(reads < 10_000, "the auto-stop monitor did not return");
            now += step;
            now
        }
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_link_loss_uses_the_twenty_second_limit() {
        let t = Instant::now();
        let mut monitor = AutoStopMonitor::new(false);
        assert_eq!(monitor.observe(t, false, None), None);
        assert_eq!(
            monitor.observe(t + Duration::from_millis(19_999), false, None),
            None
        );
        assert_eq!(
            monitor.observe(t + Duration::from_secs(20), false, None),
            Some("hotspot_lost")
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_source_device_loss_uses_the_ninety_second_limit() {
        let t = Instant::now();
        let mut monitor = AutoStopMonitor::new(true);
        assert_eq!(monitor.observe(t, true, Some(ProbeAnswer::Answered)), None);
        // The timer starts at the first silent sample, not at the last answer.
        assert_eq!(
            monitor.observe(t + Duration::from_secs(1), true, Some(ProbeAnswer::Silent)),
            None
        );
        assert_eq!(
            monitor.observe(t + Duration::from_secs(90), true, Some(ProbeAnswer::Silent)),
            None
        );
        assert_eq!(
            monitor.observe(t + Duration::from_secs(91), true, Some(ProbeAnswer::Silent)),
            Some("source_device_gone")
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_keeps_a_silent_answer_until_the_next_probe() {
        let t = Instant::now();
        let mut monitor = AutoStopMonitor::new(true);
        assert_eq!(monitor.observe(t, true, Some(ProbeAnswer::Silent)), None);
        // No probe is due for the rest of the limit. The last answer still
        // counts, so the timer measures continuous silence.
        assert_eq!(
            monitor.observe(t + Duration::from_secs(89), true, None),
            None
        );
        assert_eq!(
            monitor.observe(t + Duration::from_secs(90), true, None),
            Some("source_device_gone")
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_missing_or_cancelled_probes_are_no_evidence() {
        let t = Instant::now();
        let mut monitor = AutoStopMonitor::new(true);
        // No probe was due.
        assert_eq!(monitor.observe(t, true, None), None);
        assert_eq!(
            monitor.observe(t + Duration::from_secs(90), true, Some(ProbeAnswer::Silent)),
            None
        );
        // A cancelled probe keeps the timers as they are.
        let mut monitor = AutoStopMonitor::new(true);
        assert_eq!(monitor.observe(t, true, Some(ProbeAnswer::Cancelled)), None);
        assert_eq!(
            monitor.observe(t + Duration::from_secs(90), true, Some(ProbeAnswer::Silent)),
            None
        );
        assert_eq!(
            monitor.observe(
                t + Duration::from_secs(180),
                true,
                Some(ProbeAnswer::Silent)
            ),
            Some("source_device_gone")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_probe_clears_stale_silence_but_keeps_link_monitoring() {
        let t = Instant::now();
        let mut monitor = AutoStopMonitor::new(true);
        assert_eq!(monitor.observe(t, true, Some(ProbeAnswer::Silent)), None);
        assert_eq!(
            monitor.observe(
                t + Duration::from_secs(89),
                true,
                Some(ProbeAnswer::Unavailable)
            ),
            None
        );
        assert_eq!(
            monitor.observe(t + Duration::from_secs(100), true, None),
            None
        );
        assert_eq!(
            monitor.observe(
                t + Duration::from_secs(101),
                false,
                Some(ProbeAnswer::Unavailable)
            ),
            None
        );
        assert_eq!(
            monitor.observe(t + Duration::from_secs(121), false, None),
            Some("hotspot_lost")
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_wait_does_not_probe_a_down_link() {
        let stop = AtomicBool::new(false);
        let probes = AtomicUsize::new(0);
        let mut monitor = AutoStopMonitor::new(true);
        let mut clock = fake_clock(Duration::from_millis(500));
        let mut link = || Some(false);
        let mut probe = |_: &AtomicBool| {
            probes.fetch_add(1, Ordering::Relaxed);
            ProbeAnswer::Silent
        };
        let mut running = || true;
        let reason = auto_stop_wait(
            &mut monitor,
            Duration::ZERO,
            &mut clock,
            &mut link,
            &mut probe,
            &mut running,
            &stop,
        );
        assert_eq!(reason, Some("hotspot_lost"));
        assert_eq!(probes.load(Ordering::Relaxed), 0);
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_wait_does_not_treat_unknown_link_as_loss() {
        let stop = AtomicBool::new(false);
        let mut monitor = AutoStopMonitor::new(true);
        let start = Instant::now();
        let mut calls = 0;
        let reason = auto_stop_wait(
            &mut monitor,
            Duration::ZERO,
            || {
                calls += 1;
                if calls == 110 {
                    stop.store(true, Ordering::Release);
                }
                start + Duration::from_secs(calls)
            },
            || None,
            |_| panic!("an unknown link must not be probed"),
            || true,
            &stop,
        );
        assert_eq!(reason, None);
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_wait_stops_when_the_source_device_is_silent() {
        let stop = AtomicBool::new(false);
        let probes = AtomicUsize::new(0);
        let mut monitor = AutoStopMonitor::new(true);
        let mut clock = fake_clock(Duration::from_millis(500));
        let mut link = || Some(true);
        let mut probe = |_: &AtomicBool| {
            probes.fetch_add(1, Ordering::Relaxed);
            ProbeAnswer::Silent
        };
        let mut running = || true;
        let reason = auto_stop_wait(
            &mut monitor,
            Duration::ZERO,
            &mut clock,
            &mut link,
            &mut probe,
            &mut running,
            &stop,
        );
        assert_eq!(reason, Some("source_device_gone"));
        assert!(probes.load(Ordering::Relaxed) > 1);
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_wait_keeps_an_answered_source_device_running() {
        let base = Instant::now();
        let mut now = base;
        let mut reads = 0u32;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clock = Arc::clone(&stop);
        let mut clock = move || {
            reads += 1;
            now += Duration::from_millis(500);
            // 400 reads is 200 fake seconds.
            if reads >= 400 {
                stop_clock.store(true, Ordering::Release);
            }
            now
        };
        let probes = AtomicUsize::new(0);
        let mut monitor = AutoStopMonitor::new(true);
        let mut link = || Some(true);
        let mut probe = |_: &AtomicBool| {
            probes.fetch_add(1, Ordering::Relaxed);
            ProbeAnswer::Answered
        };
        let mut running = || true;
        let reason = auto_stop_wait(
            &mut monitor,
            Duration::ZERO,
            &mut clock,
            &mut link,
            &mut probe,
            &mut running,
            &stop,
        );
        assert_eq!(reason, None);
        assert!(probes.load(Ordering::Relaxed) > 10);
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_wait_returns_on_the_stop_flag_or_a_stopped_tunnel() {
        let probes = AtomicUsize::new(0);
        let mut monitor = AutoStopMonitor::new(true);
        let mut clock = fake_clock(Duration::from_millis(500));
        let mut link = || Some(true);
        let mut probe = |_: &AtomicBool| {
            probes.fetch_add(1, Ordering::Relaxed);
            ProbeAnswer::Silent
        };
        let stop = AtomicBool::new(true);
        let mut running = || true;
        assert_eq!(
            auto_stop_wait(
                &mut monitor,
                Duration::ZERO,
                &mut clock,
                &mut link,
                &mut probe,
                &mut running,
                &stop
            ),
            None
        );
        assert_eq!(probes.load(Ordering::Relaxed), 0);

        let stop = AtomicBool::new(false);
        let mut running = || false;
        assert_eq!(
            auto_stop_wait(
                &mut monitor,
                Duration::ZERO,
                &mut clock,
                &mut link,
                &mut probe,
                &mut running,
                &stop
            ),
            None
        );
        assert_eq!(probes.load(Ordering::Relaxed), 0);
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_wait_reads_the_link_again_after_a_probe() {
        let stop = AtomicBool::new(false);
        let probes = AtomicUsize::new(0);
        let mut monitor = AutoStopMonitor::new(true);
        let mut clock = fake_clock(Duration::from_millis(500));
        let mut reads = 0u32;
        let mut link = || {
            reads += 1;
            Some(reads == 1)
        };
        let mut probe = |_: &AtomicBool| {
            probes.fetch_add(1, Ordering::Relaxed);
            ProbeAnswer::Silent
        };
        let mut running = || true;
        let reason = auto_stop_wait(
            &mut monitor,
            Duration::ZERO,
            &mut clock,
            &mut link,
            &mut probe,
            &mut running,
            &stop,
        );
        // The link failed during the probe. That is a link loss, not a silent
        // source device.
        assert_eq!(reason, Some("hotspot_lost"));
        assert_eq!(probes.load(Ordering::Relaxed), 1);
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_observes_the_named_interface() {
        assert_eq!(hotspot_interface(Some("en0")).as_deref(), Some("en0"));
    }

    #[cfg(unix)]
    #[test]
    fn auto_stop_converts_an_interface_index_to_a_name() {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let index = normalization::interface_index(name).unwrap();
        assert_eq!(interface_name(index).as_deref(), Some(name));
        assert_eq!(interface_name(0), None);
        assert_eq!(
            hotspot_interface(Some(&index.to_string())).as_deref(),
            Some(name)
        );
    }

    /// One fake source device proxy on loopback. It answers the greeting and
    /// the token exchange with `reply`.
    #[cfg(unix)]
    fn fake_source_device(
        reply: [u8; 2],
        token: &str,
    ) -> (SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // [version, user length] + user name + [token length] + token
        let token = token.as_bytes().to_vec();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = vec![0u8; 15 + token.len()];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(&auth[..2], &[1, 12]);
            assert_eq!(&auth[2..14], b"hotspotshade");
            assert_eq!(auth[14] as usize, token.len());
            assert_eq!(&auth[15..], token);
            stream.write_all(&reply).unwrap();
        });
        (address, handle)
    }

    #[cfg(unix)]
    fn probe_proxy(address: SocketAddr, token: &str) -> PhoneProxy {
        PhoneProxy {
            address,
            username: "hotspotshade".into(),
            token: token.into(),
            iface: None,
            timeout: Duration::from_secs(2),
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_device_probe_accepts_an_answer_and_a_rejected_token() {
        let (address, server) = fake_source_device([1, 0], "test-token");
        let audit = Audit::default();
        assert_eq!(
            probe_source_device(
                &probe_proxy(address, "test-token"),
                &audit,
                &AtomicBool::new(false)
            ),
            ProbeAnswer::Answered
        );
        server.join().unwrap();
        let (total, bad) = audit.snapshot();
        assert_eq!(total, 1);
        assert_eq!(bad, 0);

        let (address, server) = fake_source_device([1, 1], "test-token");
        assert_eq!(
            probe_source_device(
                &probe_proxy(address, "test-token"),
                &Audit::default(),
                &AtomicBool::new(false)
            ),
            ProbeAnswer::Answered
        );
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn source_device_probe_counts_a_rejected_method_as_an_answer() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 255]).unwrap();
        });
        let audit = Audit::default();
        assert_eq!(
            probe_source_device(
                &probe_proxy(address, "test-token"),
                &audit,
                &AtomicBool::new(false)
            ),
            ProbeAnswer::Answered
        );
        server.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[cfg(unix)]
    #[test]
    fn source_device_probe_maps_a_closed_port_and_a_cancel() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(
            probe_source_device(
                &probe_proxy(address, "test-token"),
                &Audit::default(),
                &AtomicBool::new(false)
            ),
            ProbeAnswer::Silent
        );
        // A cancelled probe creates no outer socket and is no evidence.
        let audit = Audit::default();
        assert_eq!(
            probe_source_device(
                &probe_proxy(address, "test-token"),
                &audit,
                &AtomicBool::new(true)
            ),
            ProbeAnswer::Cancelled
        );
        assert_eq!(audit.snapshot().0, 0);
    }

    #[cfg(unix)]
    #[test]
    fn source_device_probe_treats_an_unknown_interface_as_unavailable() {
        let mut proxy = probe_proxy("127.0.0.1:9".parse().unwrap(), "test-token");
        proxy.iface = Some(u32::MAX);
        let audit = Audit::default();
        assert_eq!(
            probe_source_device(&proxy, &audit, &AtomicBool::new(false)),
            ProbeAnswer::Unavailable
        );
        assert_eq!(audit.snapshot(), (0, 0));
    }

    #[cfg(unix)]
    #[test]
    fn source_device_probe_stops_when_the_stop_flag_arrives() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            // Keep the connection open until the test observes cancellation.
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::clone(&stop);
        let trigger = std::thread::spawn(move || {
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            cancel.store(true, Ordering::Release);
        });
        let answer = probe_source_device(
            &probe_proxy(address, "test-token"),
            &Audit::default(),
            &stop,
        );
        trigger.join().unwrap();
        release_tx.send(()).unwrap();
        server.join().unwrap();
        assert_eq!(answer, ProbeAnswer::Cancelled);
    }
}
