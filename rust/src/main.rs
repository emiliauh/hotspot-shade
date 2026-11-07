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
use hotspotshade::{environment, gui_backend::RustGuiBackend, phone_server::PhoneServer};
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

mod version;

/// The helper's fixed start-exclusion handoff contract.
///
/// These values mirror `rust/src/macos_upgrade_lock.rs` and
/// `HelperStartExclusionProtocol`. The binary entry point seals the inherited
/// descriptor before any child process exists. The library still validates the
/// same descriptor at tunnel start. The values here are constants, so an
/// environment value can never select a different descriptor.
#[cfg(target_os = "macos")]
const HANDOFF_DESCRIPTOR: std::os::fd::RawFd = 5;
#[cfg(target_os = "macos")]
const HANDOFF_FD_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_FD";
#[cfg(target_os = "macos")]
const HANDOFF_VERSION_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_VERSION";
#[cfg(target_os = "macos")]
const HANDOFF_DEVICE_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_DEVICE";
#[cfg(target_os = "macos")]
const HANDOFF_INODE_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_INODE";

/// The result of the early handoff seal.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EarlyHandoffSeal {
    /// No handoff variable is present. Descriptor 5 was not touched.
    NotHandoff,
    /// A handoff was claimed and the fixed descriptor now has `FD_CLOEXEC`.
    Sealed,
    /// A handoff was claimed but the fixed descriptor is not open. The start
    /// path will refuse the partial or closed handoff.
    Absent,
}

/// True when any helper handoff variable is present.
///
/// Presence only. The values are never parsed here, so a forged value cannot
/// choose a descriptor or stand in for validation. This function is separate
/// so a test can exercise the marker without changing the process environment.
#[cfg(target_os = "macos")]
fn handoff_claim_present(values: [Option<&std::ffi::OsStr>; 4]) -> bool {
    values.iter().any(Option::is_some)
}

/// Set `FD_CLOEXEC` on the fixed inherited handoff descriptor.
///
/// Every GUI and default-route subprocess can start before the tunnel start
/// path validates the handoff. This seal runs first, so those children cannot
/// inherit the helper's locked open file description. The step is hardening
/// only. It grants no trust and does not prove that the descriptor is the
/// handoff: the start path still checks the version, device, inode, owner,
/// link count, mode, and access control list.
///
/// An ordinary invocation with no handoff variable returns immediately and
/// never touches descriptor 5. A forged marker can make this function seal
/// descriptor 5 in a process that is not a helper engine. That only removes
/// inheritance of a descriptor in an invocation that already claims a handoff;
/// it grants no access and does not bypass the start checks. A failure to seal
/// an open descriptor is an error, so the caller can stop before it starts a
/// child.
#[cfg(target_os = "macos")]
fn seal_inherited_handoff(
    descriptor: std::os::fd::RawFd,
    handoff_claimed: bool,
) -> io::Result<EarlyHandoffSeal> {
    if !handoff_claimed {
        return Ok(EarlyHandoffSeal::NotHandoff);
    }
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            // Nothing to inherit. The start path refuses the handoff later.
            return Ok(EarlyHandoffSeal::Absent);
        }
        return Err(io::Error::other(format!(
            "cannot inspect the inherited helper start-exclusion descriptor: {error}"
        )));
    }
    if flags & libc::FD_CLOEXEC == 0
        && unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        let error = io::Error::last_os_error();
        return Err(io::Error::other(format!(
            "cannot set close-on-exec on the inherited helper start-exclusion descriptor: {error}"
        )));
    }
    let sealed = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if sealed < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::other(format!(
            "cannot confirm close-on-exec on the inherited helper start-exclusion descriptor: {error}"
        )));
    }
    if sealed & libc::FD_CLOEXEC == 0 {
        return Err(io::Error::other(
            "the inherited helper start-exclusion descriptor is still inheritable",
        ));
    }
    Ok(EarlyHandoffSeal::Sealed)
}

/// Read the handoff marker and seal the fixed descriptor before any child.
#[cfg(target_os = "macos")]
fn seal_handoff_before_spawn() -> io::Result<EarlyHandoffSeal> {
    let claimed = handoff_claim_present([
        std::env::var_os(HANDOFF_FD_ENV).as_deref(),
        std::env::var_os(HANDOFF_VERSION_ENV).as_deref(),
        std::env::var_os(HANDOFF_DEVICE_ENV).as_deref(),
        std::env::var_os(HANDOFF_INODE_ENV).as_deref(),
    ]);
    seal_inherited_handoff(HANDOFF_DESCRIPTOR, claimed)
}

/// Set `FD_CLOEXEC` on the GUI control descriptors named on the command line.
///
/// A launcher clears close-on-exec when it places a descriptor on a fixed
/// number. The engine later starts `route`, `scutil`, and other children. A
/// child must not inherit the token, parent, pairing handoff, or credentials
/// descriptor, so this runs right after argument parsing and before any child
/// exists. A descriptor that is not open is skipped here; `check_control_descriptor`
/// or the token or pairing read refuses it before the listener binds. A failure to seal
/// an open descriptor stops the launch. The messages carry no descriptor
/// number.
#[cfg(unix)]
fn seal_control_descriptors(descriptors: &[(Option<i64>, &str)]) -> Result<(), String> {
    for (descriptor, label) in descriptors {
        let Some(Ok(descriptor)) = descriptor.map(libc::c_int::try_from) else {
            continue;
        };
        if descriptor < 0 {
            continue;
        }
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(format!("cannot inspect the {label} descriptor"));
        }
        if flags & libc::FD_CLOEXEC == 0
            && unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(format!(
                "cannot set close-on-exec on the {label} descriptor"
            ));
        }
        let sealed = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if sealed < 0 || sealed & libc::FD_CLOEXEC == 0 {
            return Err(format!("the {label} descriptor is still inheritable"));
        }
    }
    Ok(())
}

/// The descriptor kind that a launcher passes for one GUI control channel.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlDescriptorKind {
    /// A pipe or a socket. The parent watcher polls for a hang-up on either.
    PipeOrSocket,
    /// A socket only.
    Socket,
}

#[cfg(unix)]
impl ControlDescriptorKind {
    /// The macOS app passes the pairing handoff as one end of a Unix socket
    /// pair (`BackendProcess.swift`). The Linux app's handoff kind is owned by
    /// the Linux launcher, so Linux keeps the wider pipe-or-socket check.
    #[cfg(target_os = "macos")]
    const HANDOFF: Self = Self::Socket;
    #[cfg(not(target_os = "macos"))]
    const HANDOFF: Self = Self::PipeOrSocket;
}

/// Refuse a named control descriptor that is not open or that is not the kind
/// its launcher passes. The launch runs this right after it seals the
/// descriptors, before the token read and the listener bind. The messages
/// carry no descriptor number.
#[cfg(unix)]
fn check_control_descriptor(
    descriptor: i64,
    label: &str,
    kind: ControlDescriptorKind,
) -> Result<(), String> {
    let descriptor = libc::c_int::try_from(descriptor)
        .ok()
        .filter(|descriptor| *descriptor >= 0)
        .ok_or_else(|| format!("invalid {label} descriptor"))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(format!("the {label} descriptor is not open"));
    }
    let format = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
    let socket = format == libc::S_IFSOCK;
    let allowed = match kind {
        ControlDescriptorKind::PipeOrSocket => socket || format == libc::S_IFIFO,
        ControlDescriptorKind::Socket => socket,
    };
    if !allowed {
        return Err(match kind {
            ControlDescriptorKind::PipeOrSocket => {
                format!("the {label} descriptor is not a pipe or a socket")
            }
            ControlDescriptorKind::Socket => format!("the {label} descriptor is not a socket"),
        });
    }
    Ok(())
}

/// The GUI startup step that is running. A launch that fails before the
/// engine serves requests prints one fixed reason line for this step on
/// standard error, `hotspotshade-start-failure: <code>`. The protected macOS
/// helper reads only that line and only a code from this fixed list, so the
/// reason it records and shows can never carry a token, a path, an address, or
/// other free text. The codes match `EngineStartFailureReason` in the Swift
/// helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum StartupStage {
    /// Not a GUI launch, or the GUI already serves requests.
    None = 0,
    Arguments,
    ControlDescriptors,
    CredentialsDescriptor,
    Token,
    CredentialsHandoff,
    Listener,
    PortFile,
    CredentialsImport,
}

static STARTUP_STAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn set_startup_stage(stage: StartupStage) {
    STARTUP_STAGE.store(stage as u8, Ordering::Release);
}

impl StartupStage {
    fn current() -> Self {
        match STARTUP_STAGE.load(Ordering::Acquire) {
            1 => Self::Arguments,
            2 => Self::ControlDescriptors,
            3 => Self::CredentialsDescriptor,
            4 => Self::Token,
            5 => Self::CredentialsHandoff,
            6 => Self::Listener,
            7 => Self::PortFile,
            8 => Self::CredentialsImport,
            _ => Self::None,
        }
    }

    /// The fixed code for this step, or `None` when no startup is running.
    fn reason(self) -> Option<&'static str> {
        Some(match self {
            Self::None => return None,
            Self::Arguments => "arguments_invalid",
            Self::ControlDescriptors => "control_descriptor_invalid",
            Self::CredentialsDescriptor => "credentials_descriptor_invalid",
            Self::Token => "token_invalid",
            Self::CredentialsHandoff => "credentials_handoff_invalid",
            Self::Listener => "listener_failed",
            Self::PortFile => "port_file_failed",
            Self::CredentialsImport => "credentials_import_failed",
        })
    }
}

/// The one fixed line a failed GUI startup prints. It never includes the
/// error text.
fn startup_failure_line(stage: StartupStage) -> Option<String> {
    stage
        .reason()
        .map(|code| format!("hotspotshade-start-failure: {code}"))
}

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

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(2)
        .clamp(1, 4)
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
    let token = std::env::var("HOTSPOTSHADE_PHONE_TOKEN");
    // Do not let later children, including netsh, inherit the credential.
    // Removing it does not erase copies held by the caller or the OS.
    std::env::remove_var("HOTSPOTSHADE_PHONE_TOKEN");
    if let Ok(token) = token {
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
// arrives during startup, finish cleanup before returning to the caller. A
// cleanup that cannot prove that routes and devices are gone is an error, not
// a quiet cancellation: the Swift helper clears its durable launch intent only
// on a zero engine exit.
fn guarded_start<S, C>(stop: &AtomicBool, start: S, cleanup: C) -> io::Result<bool>
where
    S: FnOnce() -> io::Result<()>,
    C: FnOnce() -> io::Result<()>,
{
    if stop.load(Ordering::Acquire) {
        return Ok(false);
    }
    let result = start();
    if stop.load(Ordering::Acquire) {
        cleanup()?;
        return Ok(false);
    }
    match result {
        Ok(()) => Ok(true),
        Err(error) => match cleanup() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(io::Error::new(
                error.kind(),
                format!("{error}; {cleanup_error}"),
            )),
        },
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

/// Read one 64-character lowercase hex secret followed by one newline.
///
/// A GUI secret is never taken from a command line. The launcher writes it to
/// a private descriptor or handle and passes only the descriptor number.
fn parse_gui_token(buffer: &[u8]) -> Option<[u8; 64]> {
    if buffer.len() != 65 || buffer[64] != b'\n' {
        return None;
    }
    if !buffer[..64]
        .iter()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return None;
    }
    let mut token = [0u8; 64];
    token.copy_from_slice(&buffer[..64]);
    Some(token)
}

fn zero_buffer(buffer: &mut [u8]) {
    for byte in buffer {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

#[cfg(unix)]
fn read_gui_token(handle: u64) -> Result<[u8; 64], String> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    let fd = i32::try_from(handle).map_err(|_| "invalid token descriptor")?;
    if fd < 0 {
        return Err("invalid token descriptor".into());
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
                zero_buffer(&mut buffer);
                return Err("invalid token descriptor".into());
            }
        }
    }
    let token = parse_gui_token(&buffer[..count]);
    zero_buffer(&mut buffer);
    token.ok_or_else(|| "invalid token".into())
}

/// How long the GUI waits for the launcher to write its secret. The trusted
/// broker writes at most one 64-character secret and one newline, directly
/// after a successful launch. A silent writer must not keep the engine alive.
#[cfg(windows)]
const GUI_TOKEN_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval for the secret read. The launcher writes the secret right
/// after a successful launch, so the read stays responsive. It only looks at
/// bytes that are already buffered, so it never leaves a blocking or overlapped
/// read behind, and the stop flag can end it.
#[cfg(windows)]
const CONTROL_TOKEN_POLL: Duration = Duration::from_millis(10);

/// How long the parent watcher polls quickly after startup. A parent that
/// exits during startup is noticed before the watcher backs off.
#[cfg(windows)]
const CONTROL_PARENT_STARTUP: Duration = Duration::from_secs(1);

/// Poll interval for the parent watcher during startup.
#[cfg(windows)]
const CONTROL_PARENT_POLL_STARTUP: Duration = Duration::from_millis(10);

/// Poll interval for the parent watcher once startup is over. Liveness does
/// not need a 10 ms wakeup for the life of the tunnel. A parent exit is still
/// noticed within this interval, and the secret read checks its own stop flag
/// at the faster token interval, so cancellation stays bounded.
#[cfg(windows)]
const CONTROL_PARENT_POLL_IDLE: Duration = Duration::from_millis(150);

/// Windows kernel handles are four-byte aligned. A value with a low tag bit set
/// is not a handle table entry. Reject it before any cast: an odd value can
/// compare unequal to the real handle while a kernel API masks the tag and
/// reads or closes the same object.
#[cfg(windows)]
const CONTROL_HANDLE_TAG_MASK: u64 = 3;

/// Check one inherited Windows handle number before any cast.
///
/// A 32-bit build must reject a value that does not fit in `usize` instead of
/// truncating it to a different handle. The maximum value is
/// `INVALID_HANDLE_VALUE` and is never a pipe. A low tag bit is rejected too:
/// the operating system does not return tagged pipe handles, and a tagged
/// alias must not slip past the numeric token and parent comparison.
#[cfg(windows)]
fn control_handle_address(handle: u64, label: &str) -> Result<*mut std::ffi::c_void, String> {
    if handle == 0 || handle >= usize::MAX as u64 || handle & CONTROL_HANDLE_TAG_MASK != 0 {
        return Err(format!("invalid {label} handle"));
    }
    Ok(handle as usize as *mut std::ffi::c_void)
}

/// One inherited control pipe. Closing it on drop covers every exit path.
#[cfg(windows)]
struct OwnedControlHandle(*mut std::ffi::c_void);

// The handle is owned by exactly one thread and is used only on that thread.
#[cfg(windows)]
unsafe impl Send for OwnedControlHandle {}

#[cfg(windows)]
impl OwnedControlHandle {
    /// Read the wrapped handle. A method call keeps the whole wrapper in a
    /// closure capture, so the `Send` impl applies instead of a bare pointer
    /// field that a disjoint field capture would move.
    fn raw(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedControlHandle {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// The buffered state of one inherited control pipe.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlPipeState {
    /// At least this many bytes are buffered. A read cannot block.
    Data(u32),
    /// The pipe is open and buffered no byte yet.
    Empty,
    /// Every writer closed the pipe.
    Closed,
    /// The handle is not a usable pipe.
    Failed,
}

/// Report the buffered state of one control pipe without blocking.
///
/// `PeekNamedPipe` works on the synchronous anonymous pipe that the trusted
/// broker creates. It returns at once in every state, so a polling loop can
/// honor a deadline and a stop flag.
#[cfg(windows)]
fn control_pipe_state(handle: *mut std::ffi::c_void) -> ControlPipeState {
    #[link(name = "kernel32")]
    extern "system" {
        fn PeekNamedPipe(
            handle: *mut std::ffi::c_void,
            buffer: *mut std::ffi::c_void,
            length: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }
    const ERROR_BROKEN_PIPE: u32 = 109;
    const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
    let mut available = 0u32;
    let ok = unsafe {
        PeekNamedPipe(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return match unsafe { GetLastError() } {
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => ControlPipeState::Closed,
            _ => ControlPipeState::Failed,
        };
    }
    if available == 0 {
        ControlPipeState::Empty
    } else {
        ControlPipeState::Data(available)
    }
}

/// Read up to `want` buffered bytes from a control pipe. The caller first
/// confirmed that the pipe holds data and passes at most that many bytes, so
/// this read cannot block. A zero-length read or a broken pipe is `Closed`.
/// A read error is `Failed`, which the caller must treat as a failure, not as
/// an idle pipe.
#[cfg(windows)]
fn read_control_chunk(
    handle: *mut std::ffi::c_void,
    buffer: &mut [u8],
    want: u32,
) -> ControlPipeState {
    #[link(name = "kernel32")]
    extern "system" {
        fn ReadFile(
            handle: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            read: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
        fn GetLastError() -> u32;
    }
    const ERROR_BROKEN_PIPE: u32 = 109;
    const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
    let want = want.min(u32::try_from(buffer.len()).unwrap_or(u32::MAX));
    if want == 0 {
        return ControlPipeState::Empty;
    }
    let mut read = 0u32;
    let ok = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            want,
            &mut read,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return match unsafe { GetLastError() } {
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => ControlPipeState::Closed,
            _ => ControlPipeState::Failed,
        };
    }
    if read == 0 {
        ControlPipeState::Closed
    } else {
        ControlPipeState::Data(read)
    }
}

/// Drain buffered bytes from the parent liveness pipe. The launcher writes
/// nothing. Discarding a stray byte keeps a future writer from filling the
/// pipe and blocking.
///
/// The read requests only bytes that `PeekNamedPipe` reported, so it returns at
/// once. A read error or an unexpected end of file is reported to the caller as
/// a closed or failed channel, never as a clean idle poll.
#[cfg(windows)]
fn drain_control_pipe(handle: *mut std::ffi::c_void, available: u32) -> ControlPipeState {
    let mut buffer = [0u8; 512];
    read_control_chunk(handle, &mut buffer, available)
}

/// Validate one inherited Windows GUI control handle.
///
/// The launcher creates the handle. It must be a pipe with read access. A type
/// check alone cannot establish that: `GetFileType` reports `FILE_TYPE_PIPE`
/// for a socket handle too, so it cannot tell an anonymous pipe from a socket.
/// The check is the pair. `GetNamedPipeInfo` succeeds only on a pipe and needs
/// only `FILE_READ_ATTRIBUTES`, so it rejects a socket and accepts the
/// synchronous anonymous pipe that the trusted broker creates. `PeekNamedPipe`
/// then proves the access rule that the control channel needs: the handle must
/// be open for reading, which means `GENERIC_READ` (it includes `FILE_READ_DATA`
/// and `FILE_READ_ATTRIBUTES`). A write-only end is refused, because the secret
/// cannot be read and a parent close cannot be observed. A handle that passes
/// is therefore a readable pipe, and the caller clears its inherit flag before
/// any child process starts.
#[cfg(windows)]
fn validate_windows_control_pipe(handle: *mut std::ffi::c_void, label: &str) -> Result<(), String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileType(handle: *mut std::ffi::c_void) -> u32;
        fn GetNamedPipeInfo(
            handle: *mut std::ffi::c_void,
            flags: *mut u32,
            out_size: *mut u32,
            in_size: *mut u32,
            instances: *mut u32,
        ) -> i32;
    }
    const FILE_TYPE_PIPE: u32 = 3;
    let named_pipe = unsafe {
        GetNamedPipeInfo(
            handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE || named_pipe == 0 {
        return Err(format!("{label} handle must be a pipe"));
    }
    if control_pipe_state(handle) == ControlPipeState::Failed {
        return Err(format!("{label} handle must be readable"));
    }
    Ok(())
}

/// Clear the inherit flag on one inherited Windows GUI control handle.
///
/// Clear the flag before this process starts any child, because Rust creates
/// children with inherit-handles enabled. The engine starts `netsh` on a route
/// change, so an inheritable token or parent handle would outlive the engine in
/// that child. Clearing the flag changes neither the pipe data nor the
/// parent-close signal.
///
/// This clears only the read handle that the engine owns. The launcher must
/// create or hold the write ends without `HANDLE_FLAG_INHERIT` and must close
/// them before it starts other children. A child that inherits a token write end
/// can keep the secret pipe alive past the read deadline; the read then fails
/// closed. A child that inherits a parent write end can hide the parent exit
/// until that child closes. The engine cannot clear a flag on a handle that it
/// does not own, so the write-end rule is part of the launcher contract.
#[cfg(windows)]
fn seal_windows_control_handle(handle: u64, label: &str) -> Result<*mut std::ffi::c_void, String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetHandleInformation(handle: *mut std::ffi::c_void, mask: u32, flags: u32) -> i32;
    }
    const HANDLE_FLAG_INHERIT: u32 = 1;

    let handle = control_handle_address(handle, label)?;
    // Test the pipe type and read access before changing any handle state.
    validate_windows_control_pipe(handle, label)?;
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(format!("could not clear {label} handle inheritance"));
    }
    Ok(handle)
}

/// Read the GUI secret from an inherited Windows pipe handle without a blocking
/// read.
///
/// The launcher must pass a readable pipe handle. The handle number is not a
/// secret. An unrelated process cannot read this process handle table. The read
/// polls buffered bytes and stops at a deadline, so a writer that stays open
/// without writing cannot keep the process alive. A set `parent_gone` flag ends
/// the read at once, so a parent exit during startup is not missed. The caller
/// maps that case to a graceful shutdown. The handle closes on every path and
/// the buffer is zeroed before it returns.
///
/// Each read asks only for bytes that `PeekNamedPipe` already reported, so a
/// peek and read cannot race with another reader on this pipe. The caller
/// rejects a token and parent handle that name the same pipe before this read
/// or the parent watcher starts. The launcher must also pass the only readable
/// token handle and must not duplicate it into another process: a second reader
/// in another process could consume a byte between the peek and the read, and a
/// synchronous anonymous pipe has no nonblocking read to fall back on.
#[cfg(windows)]
fn read_gui_token_until(
    handle: u64,
    timeout: Duration,
    parent_gone: Option<&AtomicBool>,
) -> Result<[u8; 64], String> {
    let pipe = OwnedControlHandle(seal_windows_control_handle(handle, "token")?);
    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 65];
    let mut count = 0;
    while count < buffer.len() {
        if parent_gone.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            zero_buffer(&mut buffer);
            return Err("token read cancelled".into());
        }
        match control_pipe_state(pipe.raw()) {
            ControlPipeState::Failed => {
                zero_buffer(&mut buffer);
                return Err("invalid token handle".into());
            }
            ControlPipeState::Closed => break,
            ControlPipeState::Empty => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    zero_buffer(&mut buffer);
                    return Err("token read timed out".into());
                }
                std::thread::sleep(CONTROL_TOKEN_POLL.min(remaining));
            }
            ControlPipeState::Data(available) => {
                let want = (buffer.len() - count).min(available as usize);
                let want = u32::try_from(want).unwrap_or(u32::MAX);
                match read_control_chunk(pipe.raw(), &mut buffer[count..], want) {
                    ControlPipeState::Data(read) => {
                        count += read as usize;
                        if buffer[..count].contains(&b'\n') {
                            break;
                        }
                    }
                    ControlPipeState::Closed => break,
                    ControlPipeState::Failed => {
                        zero_buffer(&mut buffer);
                        return Err("invalid token handle".into());
                    }
                    ControlPipeState::Empty => {
                        // A peek reported data but the read returned none. Do
                        // not spin; check the deadline and try again.
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            zero_buffer(&mut buffer);
                            return Err("token read timed out".into());
                        }
                        std::thread::sleep(CONTROL_TOKEN_POLL.min(remaining));
                    }
                }
            }
        }
    }
    let token = parse_gui_token(&buffer[..count]);
    zero_buffer(&mut buffer);
    token.ok_or_else(|| "invalid token".into())
}

#[cfg(not(any(unix, windows)))]
fn read_gui_token(_handle: u64) -> Result<[u8; 64], String> {
    Err("token handles are unsupported".into())
}

/// Watch one inherited pipe handle. The parent holds the write end for its
/// whole life. End-of-file or a read error means the parent is gone, so the
/// tunnel must stop and remove its routes and adapter. The handle loses its
/// inherit flag before the watcher starts.
///
/// The watcher polls buffered bytes instead of blocking in `ReadFile`. It stops
/// when the parent closes, when the pipe is unusable, or when the stop flag is
/// set, and then closes its own handle. The caller may start it before the
/// secret read so a parent exit interrupts a stalled read.
///
/// The watcher validates the handle and its read access before it starts the
/// thread. A write-only or otherwise unreadable parent handle fails the start
/// synchronously instead of turning into a false success followed by an
/// asynchronous parent-loss report.
#[cfg(windows)]
fn watch_parent_handle(handle: u64, stop: Arc<AtomicBool>) -> Result<(), String> {
    let pipe = OwnedControlHandle(seal_windows_control_handle(handle, "parent")?);
    // Fail closed before the thread starts. The seal already rejects a
    // write-only or non-pipe handle; keep this check for a handle that becomes
    // unusable between the two calls.
    match control_pipe_state(pipe.raw()) {
        ControlPipeState::Failed => return Err("invalid parent handle".into()),
        ControlPipeState::Closed => {
            // The parent is already gone. Start no thread and report the loss
            // now; the drop of `pipe` closes the read handle.
            stop.store(true, Ordering::Release);
            return Ok(());
        }
        ControlPipeState::Empty | ControlPipeState::Data(_) => {}
    }
    std::thread::Builder::new()
        .name("hotspotshade-parent".into())
        .spawn(move || {
            let started = Instant::now();
            while !stop.load(Ordering::Acquire) {
                let poll = if started.elapsed() < CONTROL_PARENT_STARTUP {
                    CONTROL_PARENT_POLL_STARTUP
                } else {
                    CONTROL_PARENT_POLL_IDLE
                };
                match control_pipe_state(pipe.raw()) {
                    ControlPipeState::Empty => std::thread::sleep(poll),
                    ControlPipeState::Data(available) => {
                        match drain_control_pipe(pipe.raw(), available) {
                            ControlPipeState::Closed | ControlPipeState::Failed => {
                                stop.store(true, Ordering::Release);
                                break;
                            }
                            // Bytes were drained, or no byte remained after the
                            // peek. Sleep so a writer cannot spin this thread.
                            ControlPipeState::Data(_) | ControlPipeState::Empty => {
                                std::thread::sleep(poll);
                            }
                        }
                    }
                    ControlPipeState::Closed | ControlPipeState::Failed => {
                        stop.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|_| "could not watch the parent handle".into())
}

/// A real GUI that can control a privileged tunnel needs a per-launch secret
/// from an authenticated launcher. Windows always needs one because its tunnel
/// runs in the GUI process. A Unix GUI needs one only when it is root. The demo
/// backend changes nothing, so it stays available for UI review.
fn gui_requires_token(demo: bool, windows: bool, elevated: bool) -> bool {
    !demo && (windows || elevated)
}

/// A Windows real GUI always runs behind an authenticated launcher, so that
/// launcher can also pass the parent-liveness pipe that invariant 12 requires.
/// The Unix browser GUI can be started by hand, so its parent descriptor stays
/// optional. Demo mode changes nothing and needs neither channel.
#[cfg(windows)]
fn gui_requires_parent(demo: bool, windows: bool) -> bool {
    !demo && windows
}

/// Reject one descriptor or handle reused as both control channels.
///
/// The secret read owns and closes its handle. If the same value were also the
/// parent handle, the operating system could reuse the value for the listening
/// socket, and the parent watcher would then watch that socket. Check this
/// before either value is consumed and before the listener binds.
///
/// This compares numbers only. On Windows, `verify_windows_control_handles`
/// also compares the underlying pipe objects, because two different handle
/// entries can name one pipe.
fn reject_shared_control_handle(token: Option<u64>, parent: Option<u64>) -> Result<(), String> {
    if let (Some(token), Some(parent)) = (token, parent) {
        if token == parent {
            return Err("token and parent handles must be different".into());
        }
    }
    Ok(())
}

/// Reject a Windows token and parent handle that name the same pipe object,
/// even through two different handle table entries.
///
/// Numeric inequality is not enough: a launcher can duplicate one handle and
/// pass both entries. `CompareObjectHandles` compares the underlying kernel
/// object, so a duplicate cannot make the parent watcher drain the secret or
/// race the secret read with a peek. Both channels are also checked for
/// alignment, pipe type, and read access here, before either is consumed and
/// before the listener binds.
#[cfg(windows)]
fn verify_windows_control_handles(token: Option<u64>, parent: Option<u64>) -> Result<(), String> {
    let token = token
        .map(|value| control_handle_address(value, "token"))
        .transpose()?;
    let parent = parent
        .map(|value| control_handle_address(value, "parent"))
        .transpose()?;
    if let Some(handle) = token {
        validate_windows_control_pipe(handle, "token")?;
    }
    if let Some(handle) = parent {
        validate_windows_control_pipe(handle, "parent")?;
    }
    if let (Some(token), Some(parent)) = (token, parent) {
        if token == parent {
            return Err("token and parent handles must be different".into());
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn CompareObjectHandles(
                first: *mut std::ffi::c_void,
                second: *mut std::ffi::c_void,
            ) -> i32;
            fn SetLastError(error: u32);
            fn GetLastError() -> u32;
        }
        // WinError.h: ERROR_NOT_SAME_OBJECT is 1656. The CompareObjectHandles
        // documentation names this value for two different kernel objects.
        // 192 is ERROR_EXE_MARKED_INVALID and must not be accepted here.
        const ERROR_NOT_SAME_OBJECT: u32 = 1656;
        unsafe {
            SetLastError(0);
        }
        let same = unsafe { CompareObjectHandles(token, parent) };
        if same != 0 {
            return Err("token and parent handles must refer to different pipes".into());
        }
        let error = unsafe { GetLastError() };
        if error != 0 && error != ERROR_NOT_SAME_OBJECT {
            return Err("could not compare token and parent handles".into());
        }
    }
    Ok(())
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
        Some("--version") => {
            validate_options(&args[1..], &[], &[])?;
            println!("hotspotshade {}", version::text());
            Ok(())
        }
        #[cfg(any(unix, windows))]
        Some("probe") => { validate_options(&args[1..],&[],&[])?; probe().map_err(|e|e.to_string()) },
        Some("gui") => {
            set_startup_stage(StartupStage::Arguments);
            validate_options(&args[1..],&["--port","--port-file","--token-fd","--parent-fd","--wintun","--grant-file","--handoff-fd","--credentials-fd"],&["--demo","--no-open","--experimental-icmp","--experimental-icmp-persistent"])?;
            #[cfg(not(windows))]
            if option(&args,"--wintun").is_some() { return Err("--wintun is supported on Windows only".into()); }
            #[cfg(not(target_os = "macos"))]
            if option(&args,"--grant-file").is_some() { return Err("--grant-file is supported on macOS only".into()); }
            #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
            if option(&args,"--handoff-fd").is_some() || option(&args,"--credentials-fd").is_some() {
                return Err("the pairing handoff is supported on macOS, Linux, and Windows only".into());
            }
            if args.iter().any(|arg|arg=="--experimental-icmp-persistent") && !args.iter().any(|arg|arg=="--experimental-icmp") {return Err("persistent ICMP requires --experimental-icmp".into());}
            let demo=args.iter().any(|arg|arg=="--demo");
            let token_handle=match option(&args,"--token-fd") {
                Some(value)=>Some(value.parse::<u64>().map_err(|_|"invalid token handle")?),
                None=>None,
            };
            let parent_handle=match option(&args,"--parent-fd") {
                Some(value)=>Some(value.parse::<u64>().map_err(|_|"invalid parent handle")?),
                None=>None,
            };
            // The user engine writes one pairing handoff into this descriptor.
            // The root engine reads one at launch. Both are private inherited
            // descriptors, never a command-line value, a file, or a token.
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let handoff_fd=match option(&args,"--handoff-fd") {
                Some(value)=>Some(value.parse::<i32>().map_err(|_|"invalid handoff descriptor")?),
                None=>None,
            };
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let credentials_fd=match option(&args,"--credentials-fd") {
                Some(value)=>Some(value.parse::<i32>().map_err(|_|"invalid credentials descriptor")?),
                None=>None,
            };
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if handoff_fd.is_some() && credentials_fd.is_some() {
                return Err("one engine cannot export and import a pairing handoff".into());
            }
            // A pairing descriptor must not also be the token or the parent
            // descriptor: the token read closes its descriptor, and the parent
            // watcher treats a hang-up as a stop.
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            for pairing_fd in [handoff_fd, credentials_fd].into_iter().flatten() {
                let shared = |handle: Option<u64>| handle.is_some_and(|value| i64::try_from(value).ok() == Some(i64::from(pairing_fd)));
                if pairing_fd < 0 || shared(token_handle) || shared(parent_handle) {
                    return Err("a pairing descriptor must be a separate descriptor".into());
                }
            }
            // One value must not carry both control channels. The secret read
            // closes its handle, so a shared value could be reused for the
            // listening socket and then watched as the parent. Reject it before
            // either value is read or the listener binds. On Windows, also
            // compare the underlying pipe objects: a duplicated handle entry is
            // a different number for the same pipe.
            reject_shared_control_handle(token_handle,parent_handle)?;
            #[cfg(windows)]
            verify_windows_control_handles(token_handle,parent_handle)?;
            // The standard-user engine gets the write end of the pairing
            // handoff pipe. The elevated engine gets the read end. Each is a
            // separate pipe from the token and parent handles, and both have
            // their inherit flag cleared here, before any child starts.
            #[cfg(windows)]
            let (windows_handoff, windows_credentials) = {
                let parse=|name: &str| option(&args,name).map(|value| value.parse::<u64>().map_err(|_| format!("invalid {name} handle"))).transpose();
                let handoff=parse("--handoff-fd")?;
                let credentials=parse("--credentials-fd")?;
                if handoff.is_some() && credentials.is_some() {
                    return Err("one engine cannot export and import a pairing handoff".into());
                }
                let others=[token_handle,parent_handle];
                let handoff=handoff.map(|value| hotspotshade::windows_credential_handoff::HandoffHandle::claim(value,false,&others)).transpose()?;
                let credentials=credentials.map(|value| hotspotshade::windows_credential_handoff::HandoffHandle::claim(value,true,&others)).transpose()?;
                (handoff,credentials)
            };
            // No child may inherit a control descriptor. Seal them before the
            // token read, the listener, or any route or resolver child.
            set_startup_stage(StartupStage::ControlDescriptors);
            #[cfg(unix)]
            {
                let as_number=|handle: Option<u64>| handle.and_then(|value| i64::try_from(value).ok());
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                let pairing=[(handoff_fd.map(i64::from),"pairing handoff"),(credentials_fd.map(i64::from),"credentials")];
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                let pairing=[];
                seal_control_descriptors(&[(as_number(token_handle),"token"),(as_number(parent_handle),"parent")])?;
                seal_control_descriptors(&pairing)?;
                // A named parent or pairing handoff descriptor must be open
                // and of the kind its launcher passes. Refuse it here, before
                // the token read and the listener bind, so a bad launch never
                // publishes a port or serves a request.
                if let Some(parent)=parent_handle {
                    check_control_descriptor(i64::try_from(parent).unwrap_or(-1),"parent",ControlDescriptorKind::PipeOrSocket)?;
                }
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                if let Some(handoff)=handoff_fd {
                    check_control_descriptor(i64::from(handoff),"pairing handoff",ControlDescriptorKind::HANDOFF)?;
                }
                // The root engine reads its pairing from this descriptor. The
                // macOS app passes one end of a Unix socket pair, so a pipe here is
                // a launcher that placed the token or parent pipe on this number.
                // Refuse it before the token read, with its own fixed reason.
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                if let Some(credentials)=credentials_fd {
                    set_startup_stage(StartupStage::CredentialsDescriptor);
                    check_control_descriptor(i64::from(credentials),"credentials",ControlDescriptorKind::HANDOFF)?;
                }
            }
            set_startup_stage(StartupStage::Token);
            #[cfg(unix)]
            let elevated=unsafe { libc::geteuid() == 0 };
            #[cfg(not(unix))]
            let elevated=false;
            if gui_requires_token(demo, cfg!(windows), elevated) && token_handle.is_none() {
                if cfg!(windows) {
                    return Err("The Windows GUI needs an authenticated launcher. Pass a 64-character secret with --token-fd, or use --demo for the simulated UI.".into());
                }
                return Err("The GUI is running as root. Pass a 64-character secret with --token-fd, or run it as your desktop account.".into());
            }
            // A Windows real GUI already needs an authenticated launcher, so
            // that launcher can also provide the parent-liveness pipe that
            // invariant 12 requires. The Unix browser GUI can be started by
            // hand, so its parent descriptor stays optional. Demo mode keeps
            // the unauthenticated browser UI available.
            #[cfg(windows)]
            if gui_requires_parent(demo, true) && parent_handle.is_none() {
                return Err("The Windows GUI needs a launcher parent pipe. Pass --parent-fd N.".into());
            }
            let stop=Arc::new(AtomicBool::new(false));
            // Start the parent watcher before the secret read on Windows. A
            // parent that exits while a silent writer holds the secret pipe
            // open then ends the read instead of leaving the engine blocked.
            #[cfg(windows)]
            if let Some(handle)=parent_handle { watch_parent_handle(handle,Arc::clone(&stop))?; }
            // Read and seal the secret before the listener exists. No child can
            // inherit the token handle after this point.
            #[cfg(windows)]
            let token=match token_handle {
                Some(handle)=>match read_gui_token_until(handle,GUI_TOKEN_READ_TIMEOUT,Some(&stop)) {
                    Ok(token)=>Some(token),
                    Err(error)=>{
                        // A parent exit ends the read as a graceful shutdown.
                        if stop.load(Ordering::Acquire) { return Ok(()); }
                        // End the parent watcher and close its handle on failure.
                        stop.store(true,Ordering::Release);
                        return Err(error);
                    }
                },
                None=>None,
            };
            #[cfg(not(windows))]
            let token=token_handle.map(read_gui_token).transpose()?;
            // The parent closed during startup. Nothing is bound or started.
            if stop.load(Ordering::Acquire) { return Ok(()); }
            set_startup_stage(StartupStage::CredentialsHandoff);
            // A root engine reads the one pairing handoff before it binds its
            // listener. A malformed frame is a failed launch, not a request
            // for a fresh identity.
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let imported_credentials = match credentials_fd {
                Some(fd) => {
                    let value =
                        hotspotshade::credential_handoff::read_latest_handoff(fd)
                            .map_err(|error| error.message().to_string());
                    unsafe { libc::close(fd); }
                    Some(value?)
                }
                None => None,
            };
            // The elevated Windows engine reads the newest queued handoff
            // frame before it binds its listener. An empty or malformed
            // channel is a failed launch. The handle closes after the read.
            #[cfg(windows)]
            let windows_imported = match windows_credentials {
                Some(handle) => Some(handle.read_latest().map_err(|error| error.message().to_string())?),
                None => None,
            };
            set_startup_stage(StartupStage::Arguments);
            let port=option(&args,"--port").unwrap_or_else(||"8787".into()).parse::<u16>().map_err(|_|"invalid port")?;
            set_startup_stage(StartupStage::Listener);
            let mut server=GuiServer::bind(port).map_err(|e|e.to_string())?;
            if let Some(token) = token {
                server.set_token(token);
            }
            let port=server.local_addr().map_err(|e|e.to_string())?.port();
            set_startup_stage(StartupStage::PortFile);
            if let Some(path) = option(&args,"--port-file") { write_gui_port(Path::new(&path), port).map_err(|e|e.to_string())?; }
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
            set_startup_stage(StartupStage::ControlDescriptors);
            #[cfg(unix)]
            if let Some(handle) = parent_handle {
                let fd=i32::try_from(handle).map_err(|_|"invalid parent fd")?;
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
            // The Windows watcher starts before the secret read, so nothing is
            // left to do here on Windows.
            #[cfg(not(any(unix, windows)))]
            if parent_handle.is_some() {
                return Err("parent handles are unsupported".into());
            }
            #[cfg(unix)]
            {
                signal_hook::flag::register(libc::SIGINT,stop.clone()).map_err(|e|e.to_string())?;
                signal_hook::flag::register(libc::SIGTERM,stop.clone()).map_err(|e|e.to_string())?;
            }
            #[cfg(windows)]
            register_console_stop(Arc::clone(&stop)).map_err(|e|e.to_string())?;
            set_startup_stage(StartupStage::CredentialsImport);
            let backend:Arc<dyn GuiBackend>=if args.iter().any(|arg|arg=="--demo") {
                Arc::new(hotspotshade::demo::DemoBackend::new())
            } else {
                #[cfg(unix)]
                {
                    // Phone mode turns ping on by default. The web page can turn
                    // it off. The old flags stay accepted for launch scripts.
                    let service = Arc::new(Service::new());
                    // The protected helper starts this engine without an
                    // administrator prompt. It passes the path of the one-time
                    // grant that a verified tunnel authorization writes. The
                    // engine refuses a route-changing start without it.
                    #[cfg(target_os = "macos")]
                    {
                        let concrete = match imported_credentials {
                            Some((identity, credentials)) => RustGuiBackend::with_imported_credentials(
                                service,
                                identity,
                                credentials,
                                // The helper passes the same grant path with
                                // the credentials. An imported engine still
                                // needs the one-time grant, so a missing
                                // option is a refusal at start, not a bypass.
                                option(&args, "--grant-file").map(|path| {
                                    hotspotshade::tunnel_grant::TunnelGrant::new(
                                        std::path::PathBuf::from(path),
                                    )
                                }),
                            )
                            .map_err(|error| error.message().to_string())?,
                            None => match option(&args, "--grant-file") {
                                Some(path) => RustGuiBackend::with_tunnel_grant(
                                    service,
                                    hotspotshade::tunnel_grant::TunnelGrant::new(
                                        std::path::PathBuf::from(path),
                                    ),
                                ),
                                None => RustGuiBackend::new(service),
                            },
                        };
                        if let Some(fd) = handoff_fd {
                            concrete.set_handoff_fd(fd);
                            // Read the user key once, before any handoff. A
                            // missing or unsafe key file leaves the fallback
                            // path in place and does not stop the engine.
                            if let Ok(identity) = hotspotshade::pairing::local_identity() {
                                concrete.set_handoff_identity(identity.secret_bytes());
                            }
                        }
                        Arc::new(concrete)
                    }
                    // Linux: the app runs this engine as the signed-in user
                    // and gives it a private handoff descriptor. A pkexec
                    // helper starts the root engine with the frame on the
                    // credentials descriptor. polkit authorized that launch,
                    // so the Linux root engine needs no separate grant file.
                    #[cfg(target_os = "linux")]
                    {
                        let mut concrete = match imported_credentials {
                            Some((identity, credentials)) => RustGuiBackend::with_imported_pairing(
                                service,
                                identity,
                                credentials,
                            )
                            .map_err(|error| error.message().to_string())?,
                            None => RustGuiBackend::new(service),
                        };
                        // A root engine runs only the route-changing tunnel
                        // that the authorization covers. A SOCKS5 listener
                        // needs no root, so it runs in the user engine.
                        if elevated {
                            concrete.restrict_to_tunnel_modes();
                        }
                        if let Some(fd) = handoff_fd {
                            concrete.set_handoff_fd(fd);
                            // Read the user key once, before any handoff. A
                            // missing or unsafe key file leaves the fallback
                            // path in place and does not stop the engine.
                            if let Ok(identity) = hotspotshade::pairing::local_identity() {
                                concrete.set_handoff_identity(identity.secret_bytes());
                            }
                        }
                        Arc::new(concrete)
                    }
                    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                    {
                        Arc::new(RustGuiBackend::new(service))
                    }
                }
                #[cfg(windows)]
                {
                    let wintun = option(&args, "--wintun").map(std::path::PathBuf::from);
                    let mut concrete = match windows_imported {
                        Some((identity, credentials)) => WindowsGuiBackend::with_imported_pairing(
                            Arc::new(Service::new()),
                            wintun,
                            identity,
                            credentials,
                        )
                        .map_err(|error| error.message().to_string())?,
                        None => WindowsGuiBackend::with_wintun(Arc::new(Service::new()), wintun),
                    };
                    if let Some(handle) = windows_handoff {
                        concrete.set_handoff(handle);
                    }
                    Arc::new(concrete)
                }
            };
            set_startup_stage(StartupStage::None);
            println!("GUI listening on http://127.0.0.1:{port}/");
            let result=server.run(Arc::clone(&backend),stop);
            let cleanup=backend.stop();
            result.map_err(|e|e.to_string())?;
            cleanup.map(|_|())
        }
        #[cfg(unix)]
        Some("--privileged-helper") => Err(
            "The legacy administrator helper is not available. Install the signed protected helper."
                .into(),
        ),
        #[cfg(unix)]
        Some("socks5") => {
            validate_options(&args[1..],&["--port","--iface","--dns-servers"],&[])?;
            let port=option(&args,"--port").unwrap_or_else(||"1080".into()).parse::<u16>().map_err(|_|"invalid port")?;
            if port==0 { return Err("invalid port".into()); }
            let iface=option(&args,"--iface");
            // Linux system resolver files are one aggregate list and do not
            // prove which link a server belongs to, so a Linux run needs an
            // explicit list. macOS still discovers an unambiguous interface
            // resolver when this option is absent.
            let dns_servers=match option(&args,"--dns-servers") {
                Some(value)=>Some(hotspotshade::dns::parse_server_list(&value).map_err(|_|"invalid DNS servers")?),
                None=>None,
            };
            let auto_iface=hotspot_interface(iface.as_deref());
            let service_iface=iface.as_deref().or(auto_iface.as_deref());
            if auto_iface.is_none() { eprintln!("Warning: hotspot link auto-stop is off because the interface name is unknown."); }
            let service=Service::new();
            let stop=stop_signal().map_err(|e|e.to_string())?;
            if !guarded_start(&stop,||service.start_socks(SocketAddr::from(([127,0,0,1],port)),service_iface,dns_servers),||service.stop_checked()).map_err(|e|e.to_string())? { return Ok(()); }
            println!("SOCKS5 listening on 127.0.0.1:{port}. Press Ctrl-C to stop.");
            let mut monitor=AutoStopMonitor::new(false);
            let reason=auto_stop_wait(&mut monitor,AUTO_STOP_TICK,Instant::now,
                ||auto_iface.as_deref().map_or(Some(true), |name| autostop::link_observation(name).ok()),
                |_|ProbeAnswer::Silent,
                ||service.is_running(),
                &stop);
            let listener_failed=reason.is_none() && !stop.load(Ordering::Acquire) && !service.is_running();
            let cleanup=service.stop_checked();
            print_auto_stop(reason,"SOCKS5 proxy");
            cleanup.map_err(|e|e.to_string())?;
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
            // Remove the variable now, at the single-threaded point, so no later thread
            // or child inherits it and /proc/<pid>/environ no longer shows it.
            let env_token=hotspotshade::secret_env::take_phone_token_env();
            let token=match options.secrets_fd {
                Some(fd)=>hotspotshade::udp_diag::read_secrets_fd(fd)?.token().to_owned(),
                None=>match env_token {
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
            // Remove the variable now, at the single-threaded point, so no later thread
            // or child inherits it and /proc/<pid>/environ no longer shows it.
            let env_token=hotspotshade::secret_env::take_phone_token_env();
            let proxy=if let Some(endpoint) = endpoint {
                let address=endpoint.parse::<SocketAddr>().map_err(|_|"source device must be a numeric IPv4 address and port")?;
                // Prefer a private descriptor. Keep the environment variable for compatibility.
                // Otherwise prompt on the terminal with echo disabled. Never take the token from arguments.
                let token=match secrets_fd {
                    Some(fd)=>hotspotshade::udp_diag::read_secrets_fd(fd)?.token().to_owned(),
                    None=>match env_token {
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
            if !guarded_start(&stop,||service.start_tun_options_cancellable(options,proxy,workers,&stop),||service.stop_checked()).map_err(|e|e.to_string())? { return Ok(()); }
            println!("Tunnel is running. Press Ctrl-C to stop and remove routes.");
            let mut monitor=AutoStopMonitor::new(probe.is_some());
            let probe_audit=Audit::default();
            let reason=auto_stop_wait(&mut monitor,AUTO_STOP_TICK,Instant::now,
                ||auto_iface.as_deref().map_or(Some(true), |name| autostop::link_observation(name).ok()),
                |stop|match &probe {Some(proxy)=>probe_source_device(proxy,&probe_audit,stop),None=>ProbeAnswer::Silent},
                ||service.is_running(),
                &stop);
            let cleanup=service.stop_checked();
            let status=service.status();
            let reason=reason.or_else(||status.pointer("/last_stop/reason").and_then(Value::as_str).and_then(autostop::reason));
            print_auto_stop(reason,"tunnel");
            cleanup.map_err(|e|e.to_string())?;
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
                || service.stop_checked(),
            )
            .map_err(|e| e.to_string())?
            {
                return Ok(());
            }
            println!("Tunnel is running. Press Ctrl-C to stop and remove routes.");
            let mut monitor = AutoStopMonitor::new(probe.is_some());
            let probe_audit = Audit::default();
            // The relay keeps using the token for new flows. Rerun the token
            // gate for this run's own binding every 2 seconds, and before
            // each probe, and stop the run at the first refusal.
            let gate_refused = AtomicBool::new(false);
            let last_gate = std::cell::Cell::new(Instant::now());
            let gate = || {
                if service.windows_run_token_gate().is_err() {
                    gate_refused.store(true, Ordering::Release);
                    service.stop();
                    return false;
                }
                last_gate.set(Instant::now());
                true
            };
            // Windows has no hotspot link observer yet. A source device that
            // stops answering still stops the tunnel. A hotspot loss is not
            // detected by this path.
            let reason = auto_stop_wait(
                &mut monitor,
                AUTO_STOP_TICK,
                Instant::now,
                || Some(true),
                |stop| match &probe {
                    Some(proxy) if gate() => probe_source_device(proxy, &probe_audit, stop),
                    Some(_) => ProbeAnswer::Cancelled,
                    None => ProbeAnswer::Silent,
                },
                || {
                    if last_gate.get().elapsed() >= Duration::from_secs(2) && !gate() {
                        return false;
                    }
                    service.is_running()
                },
                &stop,
            );
            let cleanup = service.stop_checked();
            print_auto_stop(reason, "tunnel");
            cleanup.map_err(|e| e.to_string())?;
            if gate_refused.load(Ordering::Acquire) {
                return Err("The source device is no longer the proven hotspot gateway on the physical adapter, so the tunnel stopped.".into());
            }
            if let Some(error) = service.status()["error"].as_str() {
                return Err(error.to_owned());
            }
            Ok(())
        }
        #[cfg(windows)]
        Some("--privileged-helper" | "socks5" | "phone" | "phone-udp-diag" | "phone-speed-diag") => {
            Err(hotspotshade::WINDOWS_NOT_IMPLEMENTED.into())
        }
        _ => Err("Usage: hotspotshade --version | probe | gui [--port N] [--port-file PATH] [--token-fd N] [--parent-fd N] [--wintun PATH] [--grant-file PATH] [--handoff-fd N] [--credentials-fd N] [--experimental-icmp] [--experimental-icmp-persistent] | socks5 [--port N] [--iface NAME] [--dns-servers IP[:PORT][,IP[:PORT]...]] | phone --phone IPv4:PORT [--listen 127.0.0.1:PORT] [--iface NAME] [--secrets-fd N] [--check] | phone-udp-diag --phone 172.20.10.1:PORT --iface NAME --target IP:PORT [--rate N] [--seconds N] [--burst N] [--pad N] [--wait N] [--drop-percent N] [--secrets-fd N] [--own-responder] [--json] | phone-speed-diag --phone IPv4:PORT --iface NAME --host NAME|IP [--address IP] [--port N] [--download-path /P] [--upload-path /P] [--probe-path /P] [--paths phone|direct|phone,direct|direct,phone] [--streams N] [--seconds N] [--idle-seconds N] [--warmup N] [--probe-interval-ms N] [--repeat N] [--max-mb N] [--udp-target IP:PORT] [--secrets-fd N] [--json] | udp-responder --listen IP:PORT [--seconds N] [--max-pps N] [--peer IP] [--json] | tun [--iface NAME] [--unit N] [--addr IPv4] [--wintun PATH] [--dns-upstream IPv4[:PORT]] [--ipv6 block|forward|inherit] [--no-pin] [--no-routes] [--phone IP:PORT] [--secrets-fd N] [--experimental-icmp] [--experimental-icmp-persistent] [--workers N]".into()),
    }
}
/// The engine exit status for one completed run.
///
/// A cleanup failure is carried as `Err` and becomes status 1. The Swift helper
/// treats a nonzero engine exit as an unclean stop and keeps its durable launch
/// intent. Do not map an uncertain cleanup to a zero exit.
fn engine_exit_code(result: &Result<(), String>) -> i32 {
    if result.is_ok() {
        0
    } else {
        1
    }
}

fn main() {
    // A helper-started engine reaches this point with the helper's locked
    // descriptor on a fixed number. Seal it before run() can start a GUI or
    // default-route subprocess that would otherwise inherit it. A normal
    // invocation has no handoff variable and leaves descriptor 5 alone. The
    // tunnel start path still validates the descriptor, so this seal is
    // hardening rather than trust.
    #[cfg(target_os = "macos")]
    if let Err(error) = seal_handoff_before_spawn() {
        eprintln!("error: {error}");
        // Only a helper launch sets the handoff variables, so this fixed line
        // reaches the helper that reads it.
        eprintln!("hotspotshade-start-failure: start_exclusion_descriptor_invalid");
        std::process::exit(1);
    }
    let result = run();
    if let Err(error) = &result {
        eprintln!("error: {error}");
        // A GUI that failed before it served a request also prints one fixed
        // reason line. A launcher reads only this line, never the text above.
        if let Some(line) = startup_failure_line(StartupStage::current()) {
            eprintln!("{line}");
        }
    }
    let code = engine_exit_code(&result);
    if code != 0 {
        std::process::exit(code);
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
    fn a_failed_gui_startup_prints_one_fixed_reason_line() {
        assert_eq!(startup_failure_line(StartupStage::None), None);
        for (stage, code) in [
            (StartupStage::Arguments, "arguments_invalid"),
            (
                StartupStage::ControlDescriptors,
                "control_descriptor_invalid",
            ),
            (
                StartupStage::CredentialsDescriptor,
                "credentials_descriptor_invalid",
            ),
            (StartupStage::Token, "token_invalid"),
            (
                StartupStage::CredentialsHandoff,
                "credentials_handoff_invalid",
            ),
            (StartupStage::Listener, "listener_failed"),
            (StartupStage::PortFile, "port_file_failed"),
            (StartupStage::CredentialsImport, "credentials_import_failed"),
        ] {
            assert_eq!(
                startup_failure_line(stage).as_deref(),
                Some(format!("hotspotshade-start-failure: {code}").as_str())
            );
            // The stored value maps back to the same stage.
            STARTUP_STAGE.store(stage as u8, Ordering::Release);
            assert_eq!(StartupStage::current(), stage);
        }
        set_startup_stage(StartupStage::None);
    }

    /// One anonymous synchronous pipe for the Windows control-handle tests.
    /// Each end has one owner so a test closes every handle exactly once.
    #[cfg(windows)]
    mod win_control {
        use std::ffi::c_void;

        #[link(name = "kernel32")]
        extern "system" {
            pub fn CreatePipe(
                read: *mut *mut c_void,
                write: *mut *mut c_void,
                attributes: *mut c_void,
                size: u32,
            ) -> i32;
            pub fn CloseHandle(handle: *mut c_void) -> i32;
            pub fn WriteFile(
                handle: *mut c_void,
                buffer: *const u8,
                length: u32,
                written: *mut u32,
                overlapped: *mut c_void,
            ) -> i32;
            pub fn PeekNamedPipe(
                handle: *mut c_void,
                buffer: *mut c_void,
                length: u32,
                read: *mut u32,
                available: *mut u32,
                left: *mut u32,
            ) -> i32;
            pub fn DuplicateHandle(
                source_process: *mut c_void,
                source: *mut c_void,
                target_process: *mut c_void,
                target: *mut *mut c_void,
                access: u32,
                inherit: i32,
                options: u32,
            ) -> i32;
            pub fn GetCurrentProcess() -> *mut c_void;
        }

        const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

        pub struct Pipe {
            pub read: *mut c_void,
            pub write: *mut c_void,
        }

        impl Pipe {
            pub fn new() -> Pipe {
                let mut read = std::ptr::null_mut();
                let mut write = std::ptr::null_mut();
                assert_ne!(
                    unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) },
                    0,
                    "CreatePipe failed"
                );
                Pipe { read, write }
            }

            pub fn write(&self, bytes: &[u8]) {
                let mut written = 0u32;
                assert_ne!(
                    unsafe {
                        WriteFile(
                            self.write,
                            bytes.as_ptr(),
                            bytes.len() as u32,
                            &mut written,
                            std::ptr::null_mut(),
                        )
                    },
                    0,
                    "WriteFile failed"
                );
                assert_eq!(written as usize, bytes.len());
            }

            pub fn close_write(&mut self) {
                if !self.write.is_null() {
                    unsafe {
                        CloseHandle(self.write);
                    }
                    self.write = std::ptr::null_mut();
                }
            }

            /// Give the read end to another owner. The reader closes it.
            pub fn detach_read(&mut self) -> u64 {
                let value = self.read as usize as u64;
                self.read = std::ptr::null_mut();
                value
            }

            /// True when a write no longer reaches a reader. The test keeps the
            /// write end open, so this observes the read end closing without
            /// querying a handle number after its owner may have closed it.
            pub fn write_fails(&self) -> bool {
                assert!(!self.write.is_null(), "the write handle is closed");
                raw_write_fails(self.write)
            }
        }

        impl Drop for Pipe {
            fn drop(&mut self) {
                self.close_write();
                if !self.read.is_null() {
                    unsafe {
                        CloseHandle(self.read);
                    }
                    self.read = std::ptr::null_mut();
                }
            }
        }

        /// True when a write to this handle fails. A closed read end makes a
        /// write fail, which is safe evidence that the reader closed its handle.
        pub fn raw_write_fails(handle: *mut c_void) -> bool {
            let mut written = 0u32;
            (unsafe { WriteFile(handle, b"x".as_ptr(), 1, &mut written, std::ptr::null_mut()) })
                == 0
        }

        /// Count buffered bytes without consuming them, or `None` on an error.
        /// Callers must own a live handle for this call.
        pub fn buffered_bytes(handle: *mut c_void) -> Option<u32> {
            let mut available = 0u32;
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                None
            } else {
                Some(available)
            }
        }

        /// Duplicate one handle entry. The duplicate names the same kernel
        /// object but has a different value.
        pub fn duplicate(handle: *mut c_void) -> *mut c_void {
            let mut target = std::ptr::null_mut();
            assert_ne!(
                unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        handle,
                        GetCurrentProcess(),
                        &mut target,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                },
                0,
                "DuplicateHandle failed"
            );
            target
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_token_is_not_inherited_by_children() {
        const MARKER: &str = "HOTSPOTSHADE_TOKEN_TEST_CHILD";
        if std::env::var_os(MARKER).is_some() {
            assert_eq!(read_windows_token(&[]).unwrap(), "public-test-token");
            assert!(std::env::var_os("HOTSPOTSHADE_PHONE_TOKEN").is_none());
            let status = std::process::Command::new("cmd.exe")
                .args([
                    "/C",
                    "if defined HOTSPOTSHADE_PHONE_TOKEN (exit /b 1) else (exit /b 0)",
                ])
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::windows_token_is_not_inherited_by_children",
            ])
            .env(MARKER, "1")
            .env("HOTSPOTSHADE_PHONE_TOKEN", "public-test-token")
            .status()
            .unwrap();
        assert!(status.success());
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
    fn socks5_dns_servers_option_is_bounded_and_numeric() {
        let values = ["--port", "--iface", "--dns-servers"];
        assert!(
            validate_options(&args(&["--dns-servers", "1.1.1.1,9.9.9.9"]), &values, &[]).is_ok()
        );
        // A repeated flag is still refused, so the bound cannot be bypassed
        // by appending lists.
        assert!(validate_options(
            &args(&["--dns-servers", "1.1.1.1", "--dns-servers", "9.9.9.9"]),
            &values,
            &[]
        )
        .is_err());
        assert!(hotspotshade::dns::parse_server_list("1.1.1.1,9.9.9.9:5353").is_ok());
        assert!(hotspotshade::dns::parse_server_list("[2001:db8::53]:5353,2001:db8::53").is_ok());
        for text in ["dns.example", "1.1.1.1:0", ""] {
            assert!(
                hotspotshade::dns::parse_server_list(text).is_err(),
                "{text:?}"
            );
        }
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
        // A GUI secret is never taken from the command line.
        assert!(validate_options(
            &args(&["--demo", "--token", "0123456789abcdef"]),
            &["--port", "--token-fd"],
            &["--demo", "--no-open"]
        )
        .is_err());
    }

    #[test]
    fn gui_token_needs_exactly_64_lowercase_hex_bytes_and_one_newline() {
        let valid = format!("{}\n", "0123456789abcdef".repeat(4));
        assert!(parse_gui_token(valid.as_bytes()).is_some());
        assert!(parse_gui_token(format!("{}\n", "A".repeat(64)).as_bytes()).is_none());
        assert!(parse_gui_token(&b"a".repeat(64)).is_none());
        assert!(parse_gui_token(&b"a".repeat(66)).is_none());
        assert!(parse_gui_token(&b"a".repeat(63)).is_none());
        assert!(parse_gui_token(&[b'g'; 64]).is_none());
        assert!(parse_gui_token(b"").is_none());
    }

    #[test]
    fn a_privileged_real_gui_requires_a_token_but_demo_does_not() {
        assert!(gui_requires_token(false, true, false));
        assert!(gui_requires_token(false, false, true));
        assert!(!gui_requires_token(false, false, false));
        assert!(!gui_requires_token(true, true, true));
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_real_gui_requires_a_parent_but_demo_does_not() {
        assert!(gui_requires_parent(false, true));
        assert!(!gui_requires_parent(true, true));
        assert!(!gui_requires_parent(false, false));
    }

    #[cfg(windows)]
    #[test]
    fn windows_write_only_token_end_is_rejected() {
        let pipe = win_control::Pipe::new();
        let error = read_gui_token_until(pipe.write as usize as u64, GUI_TOKEN_READ_TIMEOUT, None)
            .unwrap_err();
        assert_eq!(error, "token handle must be readable");
    }

    #[cfg(windows)]
    #[test]
    fn windows_gui_token_reads_from_a_handle() {
        let value = format!("{}\n", "0123456789abcdef".repeat(4));
        let mut pipe = win_control::Pipe::new();
        let handle = pipe.detach_read();
        pipe.write(value.as_bytes());
        let token = read_gui_token_until(handle, GUI_TOKEN_READ_TIMEOUT, None).unwrap();
        assert_eq!(&token, &value.as_bytes()[..64]);
        // The read owns and closes the read handle. The write end stays open,
        // so a failed write observes the close without reusing a handle number.
        assert!(pipe.write_fails());
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_pipe_close_sets_the_stop_flag() {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetHandleInformation(handle: *mut c_void, flags: *mut u32) -> i32;
            fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        }
        const HANDLE_FLAG_INHERIT: u32 = 1;
        let mut pipe = win_control::Pipe::new();
        assert_ne!(
            unsafe { SetHandleInformation(pipe.read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        let handle = pipe.detach_read();
        let stop = Arc::new(AtomicBool::new(false));
        watch_parent_handle(handle, Arc::clone(&stop)).unwrap();
        // The watcher must clear the inherit flag before it starts any child.
        let mut flags = 0u32;
        assert_ne!(
            unsafe { GetHandleInformation(handle as usize as *mut c_void, &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        assert!(!stop.load(Ordering::Acquire));
        pipe.close_write();
        for _ in 0..100 {
            if stop.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(stop.load(Ordering::Acquire));
    }

    #[cfg(windows)]
    #[test]
    fn windows_control_handle_number_rejects_zero_overflow_and_tags() {
        assert!(control_handle_address(0, "token").is_err());
        assert!(control_handle_address(4, "token").is_ok());
        // Low tag bits are not part of a handle table entry.
        assert!(control_handle_address(5, "token").is_err());
        assert!(control_handle_address(6, "token").is_err());
        assert!(control_handle_address(7, "token").is_err());
        // INVALID_HANDLE_VALUE is never a pipe.
        assert!(control_handle_address(usize::MAX as u64, "token").is_err());
        #[cfg(target_pointer_width = "32")]
        {
            // A 64-bit value must not truncate to a different 32-bit handle.
            assert!(control_handle_address(u64::from(u32::MAX), "token").is_err());
            assert!(control_handle_address(u64::from(u32::MAX) + 1, "token").is_err());
            // The largest aligned value below INVALID_HANDLE_VALUE still fits.
            assert!(control_handle_address(u64::from(u32::MAX) - 3, "token").is_ok());
            // An unaligned value below it is still a tagged alias.
            assert!(control_handle_address(u64::from(u32::MAX) - 1, "token").is_err());
        }
        #[cfg(target_pointer_width = "64")]
        {
            assert!(control_handle_address(u64::from(u32::MAX) + 1, "token").is_ok());
            assert!(control_handle_address(u64::from(u32::MAX) + 2, "token").is_err());
            assert!(control_handle_address(u64::MAX, "token").is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_control_handle_rejects_tagged_pipe_aliases() {
        let pipe = win_control::Pipe::new();
        let handle = pipe.read as usize as u64;
        assert!(control_handle_address(handle, "token").is_ok());
        for tag in 1..4 {
            assert_eq!(
                control_handle_address(handle + tag, "token").unwrap_err(),
                "invalid token handle"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_control_handle_rejects_sockets_but_accepts_anonymous_pipes() {
        use std::os::windows::io::AsRawSocket;
        // `GetFileType` reports FILE_TYPE_PIPE for a socket, so the pipe test
        // needs `GetNamedPipeInfo` to tell the two apart.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // `RawSocket` is `u64` on x64 and `u32` on x86.
        let socket = listener.as_raw_socket() as usize as u64;
        assert_eq!(
            seal_windows_control_handle(socket, "token").unwrap_err(),
            "token handle must be a pipe"
        );
        drop(listener);
        let mut pipe = win_control::Pipe::new();
        let handle = pipe.detach_read();
        let sealed = seal_windows_control_handle(handle, "token").unwrap();
        assert_eq!(sealed as usize as u64, handle);
        unsafe {
            win_control::CloseHandle(sealed);
        }
        assert!(pipe.write_fails());
    }

    #[cfg(windows)]
    #[test]
    fn windows_token_and_parent_must_not_share_one_handle() {
        let mut pipe = win_control::Pipe::new();
        let handle = pipe.detach_read();
        // A shared value cannot be both the secret and the parent channel.
        assert_eq!(
            reject_shared_control_handle(Some(handle), Some(handle)).unwrap_err(),
            "token and parent handles must be different"
        );
        assert!(reject_shared_control_handle(Some(handle), Some(handle + 4)).is_ok());
        assert!(reject_shared_control_handle(None, Some(handle)).is_ok());
        assert!(reject_shared_control_handle(Some(handle), None).is_ok());
        // The rejected pair consumed nothing: the same handle still reads the
        // secret, and the reader closes it.
        let secret = "0123456789abcdef".repeat(4);
        pipe.write(format!("{secret}\n").as_bytes());
        let token = read_gui_token_until(handle, GUI_TOKEN_READ_TIMEOUT, None).unwrap();
        assert_eq!(&token[..], secret.as_bytes());
        assert!(pipe.write_fails());
    }

    #[cfg(windows)]
    #[test]
    fn windows_token_and_parent_must_not_alias_through_a_duplicate() {
        let pipe = win_control::Pipe::new();
        let duplicate = win_control::duplicate(pipe.read);
        let token = pipe.read as usize as u64;
        let parent = duplicate as usize as u64;
        // A duplicate entry has a different number but names the same pipe.
        assert_ne!(token, parent);
        assert_eq!(
            verify_windows_control_handles(Some(token), Some(parent)).unwrap_err(),
            "token and parent handles must refer to different pipes"
        );
        // Two independent readable pipes are accepted.
        let other = win_control::Pipe::new();
        assert!(
            verify_windows_control_handles(Some(token), Some(other.read as usize as u64)).is_ok()
        );
        unsafe {
            win_control::CloseHandle(duplicate);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_write_end_is_rejected_before_the_watcher_starts() {
        let pipe = win_control::Pipe::new();
        let stop = Arc::new(AtomicBool::new(false));
        let error = watch_parent_handle(pipe.write as usize as u64, Arc::clone(&stop)).unwrap_err();
        assert_eq!(error, "parent handle must be readable");
        assert!(!stop.load(Ordering::Acquire));
        // The rejected write end was not consumed by the watcher.
        pipe.write(b"still writable");
    }

    #[cfg(windows)]
    #[test]
    fn windows_buffered_token_survives_writer_close() {
        let mut pipe = win_control::Pipe::new();
        let handle = pipe.detach_read();
        let secret = "0123456789abcdef".repeat(4);
        pipe.write(format!("{secret}\n").as_bytes());
        // The writer closes after the secret is buffered. The read must return
        // the buffered token, not treat the later EOF as a missing secret.
        pipe.close_write();
        let token = read_gui_token_until(handle, GUI_TOKEN_READ_TIMEOUT, None).unwrap();
        assert_eq!(&token[..], secret.as_bytes());
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_watcher_drains_stray_bytes_without_stopping() {
        let mut pipe = win_control::Pipe::new();
        let read = pipe.detach_read();
        let stop = Arc::new(AtomicBool::new(false));
        watch_parent_handle(read, Arc::clone(&stop)).unwrap();
        pipe.write(b"stray");
        let deadline = Instant::now() + Duration::from_secs(2);
        while win_control::buffered_bytes(read as usize as *mut std::ffi::c_void).unwrap_or(0) != 0
        {
            assert!(
                Instant::now() < deadline,
                "the watcher did not drain the parent pipe"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!stop.load(Ordering::Acquire));
        pipe.close_write();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !stop.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "the parent close was not noticed after a drain"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_watcher_closes_its_handle_on_stop() {
        let mut pipe = win_control::Pipe::new();
        let read = pipe.detach_read();
        let stop = Arc::new(AtomicBool::new(false));
        watch_parent_handle(read, Arc::clone(&stop)).unwrap();
        // Stop the watcher while the write end stays open. A later write must
        // fail because the watcher closed its read handle.
        stop.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !pipe.write_fails() {
            assert!(
                Instant::now() < deadline,
                "the watcher did not close its handle"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_drain_reports_a_write_only_handle_as_failed() {
        let pipe = win_control::Pipe::new();
        // A read on a write-only end fails instead of reporting idle.
        assert_eq!(drain_control_pipe(pipe.write, 1), ControlPipeState::Failed);
    }

    #[cfg(windows)]
    #[test]
    fn windows_silent_token_writer_times_out_and_closes_the_handle() {
        let mut pipe = win_control::Pipe::new();
        let handle = pipe.detach_read();
        // The writer stays open and silent, so only the deadline can end this.
        let started = Instant::now();
        let error = read_gui_token_until(handle, Duration::from_millis(200), None).unwrap_err();
        assert_eq!(error, "token read timed out");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the secret read was not bounded"
        );
        assert!(pipe.write_fails());
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_close_interrupts_a_silent_token_read() {
        let mut parent = win_control::Pipe::new();
        let stop = Arc::new(AtomicBool::new(false));
        watch_parent_handle(parent.detach_read(), Arc::clone(&stop)).unwrap();
        let mut token = win_control::Pipe::new();
        let handle = token.detach_read();
        // The token writer stays open and silent. Only the parent close can end
        // the read before its thirty second deadline.
        let started = Instant::now();
        let reader_stop = Arc::clone(&stop);
        let reader = std::thread::spawn(move || {
            read_gui_token_until(handle, Duration::from_secs(30), Some(reader_stop.as_ref()))
        });
        std::thread::sleep(Duration::from_millis(100));
        parent.close_write();
        let error = reader.join().unwrap().unwrap_err();
        assert_eq!(error, "token read cancelled");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the parent close did not end the secret read"
        );
        assert!(stop.load(Ordering::Acquire));
        assert!(token.write_fails());
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_already_closed_stops_the_watcher() {
        let mut parent = win_control::Pipe::new();
        let handle = parent.detach_read();
        parent.close_write();
        let stop = Arc::new(AtomicBool::new(false));
        watch_parent_handle(handle, Arc::clone(&stop)).unwrap();
        assert!(stop.load(Ordering::Acquire));
    }

    #[cfg(windows)]
    #[test]
    fn windows_control_handle_is_sealed_and_must_be_a_pipe() {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn CreatePipe(
                read: *mut *mut c_void,
                write: *mut *mut c_void,
                attributes: *mut c_void,
                size: u32,
            ) -> i32;
            fn CloseHandle(handle: *mut c_void) -> i32;
            fn GetHandleInformation(handle: *mut c_void, flags: *mut u32) -> i32;
            fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        }
        const HANDLE_FLAG_INHERIT: u32 = 1;
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) },
            0
        );
        assert_ne!(
            unsafe { SetHandleInformation(read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        let sealed = seal_windows_control_handle(read as usize as u64, "token").unwrap();
        assert_eq!(sealed, read);
        let mut flags = 0u32;
        assert_ne!(unsafe { GetHandleInformation(read, &mut flags) }, 0);
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        assert!(seal_windows_control_handle(0, "token").is_err());
        // Close only the read end; a later write observes the close without
        // querying a handle number that another thread could reuse.
        unsafe {
            CloseHandle(read);
        }
        assert!(win_control::raw_write_fails(write));
        unsafe {
            CloseHandle(write);
        }
    }

    #[cfg(windows)]
    fn temp_handle_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hs-handle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(windows)]
    #[test]
    fn windows_gui_token_rejects_a_handle_that_is_not_a_pipe() {
        use std::ffi::c_void;
        use std::os::windows::io::IntoRawHandle;
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        let path = temp_handle_path();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let raw = file.into_raw_handle();
        let error =
            read_gui_token_until(raw as usize as u64, GUI_TOKEN_READ_TIMEOUT, None).unwrap_err();
        assert_eq!(error, "token handle must be a pipe");
        unsafe {
            CloseHandle(raw);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_rejects_a_handle_that_is_not_a_pipe() {
        use std::ffi::c_void;
        use std::os::windows::io::IntoRawHandle;
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        let path = temp_handle_path();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let raw = file.into_raw_handle();
        let stop = Arc::new(AtomicBool::new(false));
        let error = watch_parent_handle(raw as usize as u64, Arc::clone(&stop)).unwrap_err();
        assert_eq!(error, "parent handle must be a pipe");
        assert!(!stop.load(Ordering::Acquire));
        unsafe {
            CloseHandle(raw);
        }
        std::fs::remove_file(&path).unwrap();
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
    fn a_cleanup_failure_is_a_nonzero_engine_exit() {
        assert_eq!(engine_exit_code(&Ok(())), 0);
        let cleanup = Err("Tunnel cleanup did not finish.".into());
        assert_eq!(engine_exit_code(&cleanup), 1);
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
            || Ok(())
        )
        .unwrap());
        assert!(!called.load(Ordering::Acquire));
        stop.store(false, Ordering::Release);
        let cleaned = AtomicBool::new(false);
        let result = guarded_start(
            &stop,
            || Err(io::Error::other("startup failed")),
            || {
                cleaned.store(true, Ordering::Release);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(cleaned.load(Ordering::Acquire));
    }

    #[test]
    fn a_cancelled_start_reports_a_cleanup_failure() {
        let stop = AtomicBool::new(false);
        let result = guarded_start(
            &stop,
            || {
                // A signal arrives after the start installed routes.
                stop.store(true, Ordering::Release);
                Ok(())
            },
            || Err(io::Error::other("tunnel cleanup did not finish")),
        );
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("cleanup did not finish"),
            "{error}"
        );
    }

    #[test]
    fn a_failed_start_does_not_hide_a_cleanup_failure() {
        let stop = AtomicBool::new(false);
        let error = guarded_start(
            &stop,
            || Err(io::Error::other("startup failed")),
            || Err(io::Error::other("tunnel cleanup did not finish")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("startup failed"), "{error}");
        assert!(
            error.to_string().contains("cleanup did not finish"),
            "{error}"
        );
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
                    || {
                        cleaned.store(true, Ordering::Release);
                        Ok(())
                    },
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

    #[cfg(target_os = "macos")]
    mod macos_handoff {
        use super::*;
        use std::ffi::OsStr;
        use std::os::fd::{AsRawFd, RawFd};
        use std::path::PathBuf;
        use std::sync::atomic::AtomicU64;

        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

        /// One empty file whose descriptor stands in for the inherited handoff.
        struct TempDescriptorFile {
            path: PathBuf,
            file: std::fs::File,
        }

        impl TempDescriptorFile {
            fn new() -> Self {
                let unique = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "hotspotshade-handoff-{}-{}",
                    std::process::id(),
                    unique
                ));
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                Self { path, file }
            }
        }

        impl Drop for TempDescriptorFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        /// `F_DUPFD` picks a number above the low descriptors that std and a
        /// shell use, and it clears `FD_CLOEXEC`, matching an inherited handoff.
        fn duplicate_without_close_on_exec(file: &std::fs::File) -> RawFd {
            let descriptor = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 64) };
            assert!(descriptor >= 64, "{}", io::Error::last_os_error());
            assert_eq!(
                unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            descriptor
        }

        fn child_can_see(descriptor: RawFd) -> bool {
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("test -e /dev/fd/{descriptor}"))
                .status()
                .expect("run /bin/sh")
                .success()
        }

        #[test]
        fn an_inherited_handoff_is_sealed_before_a_child_runs() {
            let file = TempDescriptorFile::new();
            let descriptor = duplicate_without_close_on_exec(&file.file);
            assert!(
                child_can_see(descriptor),
                "the unsealed descriptor must reach a child"
            );
            assert_eq!(
                seal_inherited_handoff(descriptor, true).unwrap(),
                EarlyHandoffSeal::Sealed
            );
            let after = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            assert!(
                after >= 0,
                "the handoff must stay open for the engine's lifetime"
            );
            assert_ne!(after & libc::FD_CLOEXEC, 0);
            assert!(
                !child_can_see(descriptor),
                "the sealed descriptor must not reach a child"
            );
            unsafe { libc::close(descriptor) };
        }

        #[test]
        fn an_ordinary_invocation_leaves_descriptor_five_alone() {
            let file = TempDescriptorFile::new();
            let descriptor = duplicate_without_close_on_exec(&file.file);
            // This descriptor stands in for an unrelated descriptor 5 in a
            // process that has no handoff environment.
            assert_eq!(
                seal_inherited_handoff(descriptor, false).unwrap(),
                EarlyHandoffSeal::NotHandoff
            );
            assert_eq!(
                unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0,
                "an ordinary invocation must not add close-on-exec"
            );
            assert!(
                child_can_see(descriptor),
                "an unrelated descriptor must stay inheritable"
            );
            unsafe { libc::close(descriptor) };
        }

        #[test]
        fn a_claimed_handoff_without_the_descriptor_is_reported_absent() {
            assert_eq!(
                seal_inherited_handoff(1_000_000, true).unwrap(),
                EarlyHandoffSeal::Absent
            );
            assert_eq!(
                seal_inherited_handoff(1_000_000, false).unwrap(),
                EarlyHandoffSeal::NotHandoff
            );
        }

        #[test]
        fn the_handoff_marker_is_presence_only() {
            assert!(!handoff_claim_present([None, None, None, None]));
            assert!(handoff_claim_present([
                Some(OsStr::new("5")),
                None,
                None,
                None
            ]));
            assert!(handoff_claim_present([
                None,
                None,
                None,
                Some(OsStr::new("")),
            ]));
            // A forged value selects no descriptor and proves nothing. The
            // fixed number is sealed and the start path still validates it.
            assert!(handoff_claim_present([
                Some(OsStr::new("not-a-number")),
                Some(OsStr::new("x")),
                Some(OsStr::new("y")),
                Some(OsStr::new("z")),
            ]));
        }

        #[test]
        fn an_already_sealed_descriptor_stays_sealed() {
            let file = TempDescriptorFile::new();
            let descriptor = duplicate_without_close_on_exec(&file.file);
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
                0
            );
            assert_eq!(
                seal_inherited_handoff(descriptor, true).unwrap(),
                EarlyHandoffSeal::Sealed
            );
            assert_ne!(
                unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            unsafe { libc::close(descriptor) };
        }
    }

    #[cfg(unix)]
    mod control_descriptors {
        use super::*;

        /// A pipe pair moved above the low descriptors, with close-on-exec
        /// clear, as a launcher's dup2 leaves it.
        fn inheritable_pipe() -> [libc::c_int; 2] {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let mut moved = [-1; 2];
            for (index, fd) in fds.iter().enumerate() {
                moved[index] = unsafe { libc::fcntl(*fd, libc::F_DUPFD, 64) };
                assert!(moved[index] >= 64, "{}", io::Error::last_os_error());
                unsafe { libc::close(*fd) };
                assert_eq!(
                    unsafe { libc::fcntl(moved[index], libc::F_GETFD) } & libc::FD_CLOEXEC,
                    0
                );
            }
            moved
        }

        /// True when a spawned child has the descriptor open. The shell
        /// duplicates it onto its output, which fails when it is closed.
        fn child_inherits(descriptor: libc::c_int) -> bool {
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{{ : >&{descriptor}; }} 2>/dev/null"))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("run /bin/sh")
                .success()
        }

        #[test]
        fn a_spawned_child_does_not_inherit_the_control_descriptors() {
            let token = inheritable_pipe();
            let parent = inheritable_pipe();
            let handoff = inheritable_pipe();
            let credentials = inheritable_pipe();
            let named = [token[0], parent[0], handoff[1], credentials[0]];
            for descriptor in named {
                assert!(
                    child_inherits(descriptor),
                    "the unsealed descriptor must reach a child, or the check proves nothing"
                );
            }
            seal_control_descriptors(&[
                (Some(i64::from(token[0])), "token"),
                (Some(i64::from(parent[0])), "parent"),
                (Some(i64::from(handoff[1])), "pairing handoff"),
                (Some(i64::from(credentials[0])), "credentials"),
            ])
            .unwrap();
            for descriptor in named {
                let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
                assert!(flags >= 0, "the descriptor stays open for the engine");
                assert_ne!(flags & libc::FD_CLOEXEC, 0);
                assert!(
                    !child_inherits(descriptor),
                    "a sealed control descriptor must not reach a child"
                );
            }
            // The engine keeps using the sealed descriptors. A write on the
            // sealed handoff still reaches the reader.
            assert_eq!(
                unsafe { libc::write(handoff[1], b"x".as_ptr().cast(), 1) },
                1
            );
            let mut byte = [0u8; 1];
            assert_eq!(
                unsafe { libc::read(handoff[0], byte.as_mut_ptr().cast(), 1) },
                1
            );
            for fd in token
                .iter()
                .chain(&parent)
                .chain(&handoff)
                .chain(&credentials)
            {
                unsafe { libc::close(*fd) };
            }
        }

        #[test]
        fn a_missing_or_invalid_control_descriptor_is_left_to_the_later_check() {
            // A closed number, a negative value, and a value outside the
            // descriptor range are not sealed here. The token read or parent
            // check refuses them later with its usual error.
            seal_control_descriptors(&[
                (None, "token"),
                (Some(1_000_000), "parent"),
                (Some(-1), "pairing handoff"),
                (Some(i64::MAX), "credentials"),
            ])
            .unwrap();
        }

        #[test]
        fn a_named_parent_descriptor_must_be_an_open_pipe_or_socket() {
            let pipe = inheritable_pipe();
            check_control_descriptor(
                i64::from(pipe[0]),
                "parent",
                ControlDescriptorKind::PipeOrSocket,
            )
            .unwrap();
            let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
            check_control_descriptor(
                i64::from(std::os::fd::AsRawFd::as_raw_fd(&socket)),
                "parent",
                ControlDescriptorKind::PipeOrSocket,
            )
            .unwrap();
            // A closed number is a failed launch, not a skipped watcher.
            // Other tests allocate the lowest free numbers, so a closed copy above
            // them stays closed while this check runs.
            let closed = unsafe { libc::fcntl(pipe[1], libc::F_DUPFD, 900) };
            assert!(closed >= 900);
            unsafe { libc::close(pipe[1]) };
            unsafe { libc::close(pipe[0]) };
            unsafe { libc::close(closed) };
            let error = check_control_descriptor(
                i64::from(closed),
                "parent",
                ControlDescriptorKind::PipeOrSocket,
            )
            .unwrap_err();
            assert_eq!(error, "the parent descriptor is not open");
            assert!(!error.contains(&closed.to_string()));
            // A regular file never hangs up, so it cannot be a parent.
            let file = std::fs::File::open("/dev/null").unwrap();
            let error = check_control_descriptor(
                i64::from(std::os::fd::AsRawFd::as_raw_fd(&file)),
                "parent",
                ControlDescriptorKind::PipeOrSocket,
            )
            .unwrap_err();
            assert_eq!(error, "the parent descriptor is not a pipe or a socket");
            for value in [-1, i64::MAX] {
                assert_eq!(
                    check_control_descriptor(value, "parent", ControlDescriptorKind::PipeOrSocket)
                        .unwrap_err(),
                    "invalid parent descriptor"
                );
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn the_macos_handoff_descriptor_must_be_an_open_socket() {
            // The app passes one end of a Unix socket pair.
            assert_eq!(
                ControlDescriptorKind::HANDOFF,
                ControlDescriptorKind::Socket
            );
            let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
            check_control_descriptor(
                i64::from(std::os::fd::AsRawFd::as_raw_fd(&socket)),
                "pairing handoff",
                ControlDescriptorKind::HANDOFF,
            )
            .unwrap();
            let pipe = inheritable_pipe();
            let error = check_control_descriptor(
                i64::from(pipe[1]),
                "pairing handoff",
                ControlDescriptorKind::HANDOFF,
            )
            .unwrap_err();
            assert_eq!(error, "the pairing handoff descriptor is not a socket");
            unsafe { libc::close(pipe[0]) };
            let (socket_copy, _) = std::os::unix::net::UnixStream::pair().unwrap();
            let closed = unsafe {
                libc::fcntl(
                    std::os::fd::AsRawFd::as_raw_fd(&socket_copy),
                    libc::F_DUPFD,
                    900,
                )
            };
            assert!(closed >= 900);
            unsafe { libc::close(pipe[1]) };
            unsafe { libc::close(closed) };
            let error = check_control_descriptor(
                i64::from(closed),
                "pairing handoff",
                ControlDescriptorKind::HANDOFF,
            )
            .unwrap_err();
            assert_eq!(error, "the pairing handoff descriptor is not open");
        }
    }
}
