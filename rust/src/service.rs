//! Service lifecycle for the Rust backend.
use crate::{diagnostics, failures, normalization, phone};
#[cfg(unix)]
use crate::{dns, environment, socks};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(any(windows, test))]
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Inconclusive IPv6 route checks (timeout, spawn error) in a row that stop the tunnel.
/// The check runs every 5 seconds. A route that does not match stops the tunnel at once.
#[cfg(target_os = "macos")]
const ROUTE_CHECK_INCONCLUSIVE_LIMIT: u32 = 3;

#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn icmp_failure_stats(s: &crate::relay::RelayStats) -> Value {
    json!({"icmp_setup_errors":s.icmp_setup_errors,"icmp_timeouts":s.icmp_timeouts,
        "icmp_phone_no_cellular":s.icmp_phone_no_cellular,"icmp_phone_busy":s.icmp_phone_busy,
        "icmp_phone_timeout":s.icmp_phone_timeout,"icmp_phone_failed":s.icmp_phone_failed,
        "icmp_phone_path_no_update":s.icmp_phone_path_no_update,"icmp_phone_path_unsatisfied":s.icmp_phone_path_unsatisfied,
        "icmp_phone_path_not_cellular":s.icmp_phone_path_not_cellular,"icmp_phone_path_no_interface":s.icmp_phone_path_no_interface,
        "icmp_phone_path_ambiguous":s.icmp_phone_path_ambiguous,
        "icmp_malformed":s.icmp_malformed,"icmp_payload_mismatch":s.icmp_payload_mismatch,
        "icmp_io_errors":s.icmp_io_errors,"icmp_output_errors":s.icmp_output_errors})
}

#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn tcp_setup_timeout_stats(s: &crate::relay::RelayStats) -> Value {
    json!({"tcp_setup_timeout_phone_connect":s.tcp_setup_timeout_phone_connect,
        "tcp_setup_timeout_phone_auth":s.tcp_setup_timeout_phone_auth,
        "tcp_setup_timeout_phone_destination":s.tcp_setup_timeout_phone_destination,
        "tcp_setup_timeout_direct_connect":s.tcp_setup_timeout_direct_connect})
}

#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn tcp_performance_stats(s: &crate::relay::RelayStats) -> Value {
    json!({"tcp_ack_rtt_samples":s.tcp_ack_rtt_samples,"tcp_ack_rtt_sum_us":s.tcp_ack_rtt_sum_us,
        "tcp_ack_rtt_max_us":s.tcp_ack_rtt_max_us,"tcp_window_limited_us":s.tcp_window_limited_us,
        "tcp_upload_buffer_peak_bytes":s.tcp_upload_buffer_peak_bytes,
        "tcp_download_buffer_peak_bytes":s.tcp_download_buffer_peak_bytes})
}

/// The tunnel status counters for Linux and Windows. The shape matches the
/// macOS counters. `device_errors` counts failed device reads and writes.
#[cfg(any(target_os = "linux", windows, test))]
fn tunnel_relay_stats(s: &crate::relay::RelayStats, device_errors: u64) -> Value {
    let mut stats = json!({"packets_in":s.packets_in,"packets_out":s.packets_out,
        "bytes_in":s.bytes_in,"bytes_out":s.bytes_out,"tcp_flows":s.tcp_flows,"tcp_flows_closed":s.tcp_flows_closed,
        "udp_flows_closed":s.udp_flows_closed,"udp_datagrams_in":s.udp_datagrams_in,"udp_datagrams_out":s.udp_datagrams_out,
        "udp_errors":s.udp_errors,"udp_dropped":s.udp_dropped,"udp_reply_too_big":s.udp_reply_too_big,
        "ttl_bad":s.ttl_bad,"ipv6_dropped":s.ipv6_dropped,"fragments_dropped":s.fragments_dropped,
        "icmp_dropped":s.icmp_dropped,"icmp_requests":s.icmp_requests,"icmp_replies":s.icmp_replies,"icmp_errors":s.icmp_errors,
        "send_dropped":s.send_dropped + device_errors,
        "flow_errors":s.flow_errors,"queue_dropped":s.queue_dropped,
        "tcp_setup_errors":s.tcp_setup_errors,"tcp_io_errors":s.tcp_io_errors,
        "tcp_setup_refused":s.tcp_setup_refused,"tcp_setup_timed_out":s.tcp_setup_timed_out,
        "tcp_setup_permission_denied":s.tcp_setup_permission_denied,"tcp_setup_other":s.tcp_setup_other,"tcp_setup_phone_unreachable":s.tcp_setup_phone_unreachable,
        "dns_flows":s.dns_flows,"dns_setup_ok":s.dns_setup_ok,"dns_setup_failed":s.dns_setup_failed,
        "input_queues":s.input_queues.iter().map(|q|json!({"packets_current":q.packets_current,"packets_peak":q.packets_peak,"max_age_us":q.max_age_us})).collect::<Vec<_>>(),
        "output_queue":{"packets_current":s.output_queue.packets_current,"packets_peak":s.output_queue.packets_peak,"max_age_us":s.output_queue.max_age_us}});
    if let Some(target) = stats.as_object_mut() {
        let icmp = icmp_failure_stats(s);
        if let Some(values) = icmp.as_object() {
            target.extend(values.clone());
        }
        let tcp = tcp_setup_timeout_stats(s);
        if let Some(values) = tcp.as_object() {
            target.extend(values.clone());
        }
        let performance = tcp_performance_stats(s);
        if let Some(values) = performance.as_object() {
            target.extend(values.clone());
        }
    }
    stats
}

/// Only a rejected token is an authentication failure at start.
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn auth_error_code(error: &io::Error) -> &'static str {
    if phone::credentials_rejected(error) {
        "phone_auth"
    } else {
        "service_start"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Policy {
    Block,
    Forward,
    Inherit,
}

/// Direct tunnel options. IPv6 blocking and interface pinning are default.
#[derive(Clone, Debug)]
pub struct TunOptions {
    pub unit: u32,
    pub addr: Ipv4Addr,
    pub iface: Option<String>,
    pub dns_upstream: Option<SocketAddr>,
    pub no_routes: bool,
    pub no_pin: bool,
    pub ipv6: Ipv6Policy,
    pub icmp_phone: bool,
    pub icmp_persistent: bool,
    /// An explicit absolute path to `wintun.dll`. `None` uses the file next to
    /// the executable. The library never bundles or commits the DLL.
    #[cfg(any(windows, test))]
    pub wintun_dll: Option<PathBuf>,
}
impl Default for TunOptions {
    fn default() -> Self {
        Self {
            unit: 0,
            addr: Ipv4Addr::new(198, 18, 0, 1),
            iface: None,
            dns_upstream: None,
            no_routes: false,
            no_pin: false,
            ipv6: Ipv6Policy::Block,
            icmp_phone: false,
            icmp_persistent: false,
            #[cfg(any(windows, test))]
            wintun_dll: None,
        }
    }
}
impl TunOptions {
    pub fn validate(&self, phone_mode: bool, workers: usize) -> io::Result<()> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
        if self.unit > 255 {
            return Err(invalid("tunnel unit must be 0 to 255"));
        }
        if !(1..=8).contains(&workers) {
            return Err(invalid("worker count must be 1 to 8"));
        }
        let host = self.addr.octets()[3] & 3;
        if host != 1 && host != 2 {
            return Err(invalid("tunnel address must be a host in a /30"));
        }
        if self
            .dns_upstream
            .is_some_and(|s| !s.is_ipv4() || s.port() == 0)
        {
            return Err(invalid(
                "tunnel DNS upstream must be a numeric IPv4 address",
            ));
        }
        if phone_mode
            && (self.no_pin
                || self.no_routes
                || self.ipv6 != Ipv6Policy::Forward
                || self.dns_upstream.is_some())
        {
            return Err(invalid(
                "source device proxy mode requires pinning, routes, IPv6 forwarding, and the source device DNS path",
            ));
        }
        if self.icmp_phone && !phone_mode {
            return Err(invalid(
                "experimental ICMP requires source device proxy mode",
            ));
        }
        if self.icmp_persistent && !self.icmp_phone {
            return Err(invalid(
                "persistent ICMP requires experimental source device ICMP",
            ));
        }
        if self.no_routes && self.ipv6 == Ipv6Policy::Forward {
            return Err(invalid("IPv6 forwarding requires managed routes"));
        }
        Ok(())
    }
}

enum Active {
    #[cfg(unix)]
    Socks {
        server: socks::SocksServer,
        audit: Arc<normalization::Audit>,
    },
    /// A tunnel worker. macOS, Linux, and Windows implement the tunnel.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    Tun {
        stop: Arc<AtomicBool>,
        handle: JoinHandle<()>,
        stats: Arc<Mutex<Value>>,
        diag: Arc<Mutex<Value>>,
        fault: Arc<Mutex<Option<(String, bool)>>>,
        /// The reason that the worker stopped itself, when it did.
        auto_stop: Arc<Mutex<Option<&'static str>>>,
    },
}

/// True while a tunnel worker runs. A SOCKS5 listener is not a tunnel.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn tunnel_worker_running(inner: &Inner) -> bool {
    matches!(&inner.active, Some(Active::Tun { handle, .. }) if !handle.is_finished())
}

/// True while a tunnel worker runs. No tunnel is implemented here.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn tunnel_worker_running(_inner: &Inner) -> bool {
    false
}

struct Inner {
    active: Option<Active>,
    mode: Option<&'static str>,
    started: Option<u64>,
    error: Option<String>,
    cleanup_blocked: bool,
    /// True while a phone tunnel runs with the echo relay on.
    icmp_enabled: bool,
    /// The worker count of the running tunnel. macOS, Linux, and Windows run a
    /// tunnel.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    workers: usize,
    /// The physical interface name that the running tunnel pins to. None when
    /// no tunnel runs, or when the run is explicitly unpinned for diagnostics.
    pinned_iface: Option<String>,
    /// The reason for the most recent automatic stop. It stays until the next
    /// successful start.
    last_stop_reason: Option<&'static str>,
    /// The time of the most recent automatic stop, in Unix seconds.
    last_stop_at: Option<u64>,
    logs: VecDeque<Value>,
    next_log_seq: u64,
}
impl Inner {
    fn log(&mut self, level: &str, message: &str) {
        self.next_log_seq = self.next_log_seq.saturating_add(1);
        if self.logs.len() >= 256 {
            self.logs.pop_front();
        }
        self.logs
            .push_back(json!({"seq":self.next_log_seq,"ts":now(),"level":level,"msg":message}));
    }
}
/// One Wintun adapter behind a test seam.
///
/// The real adapter wraps the Wintun device in `crate::platform`. A test uses
/// an in-memory device and creates no adapter.
#[cfg(any(windows, test))]
trait WindowsWintunDevice: Send {
    /// Return the validated adapter name.
    fn ifname(&self) -> &str;
    /// Return the current interface index.
    fn ifindex(&self) -> u32;
    /// Set the IPv4 address and the MTU on this adapter.
    fn configure_link(&mut self, addr: Ipv4Addr, mtu: u32) -> io::Result<()>;
    /// Return the retained adapter identity for the route boundary.
    fn route_identity(&mut self) -> io::Result<crate::windows_native_routes::AdapterIdentity>;
    /// Read one raw IP packet. `WouldBlock` means that no packet is ready.
    fn read_packet(&mut self) -> io::Result<Vec<u8>>;
    /// Write one raw IP packet.
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize>;
    /// Wait for a packet or for the timeout.
    fn wait_readable(&self, timeout: Duration) -> io::Result<bool>;
}

/// One route controller behind a test seam.
///
/// The real controller wraps `crate::windows_native_routes::RouteBoundary`.
/// Every create and delete proves the retained adapter LUID and GUID first.
/// A test uses a fake controller and changes no route.
#[cfg(any(windows, test))]
trait WindowsRouteController: Send {
    /// Install the two IPv4 `/1` routes and the IPv6 `2000::/3` route.
    fn install(&mut self) -> io::Result<()>;
    /// Remove every recorded route. This method is idempotent.
    fn remove(&mut self) -> io::Result<()>;
    /// Return true while the controller holds a route record.
    fn has_routes(&self) -> bool;
}

/// The Windows device and route factories plus the source device check.
///
/// The production runtime uses Wintun and the native route boundary. A test
/// runtime returns in-memory objects, so the test creates no adapter and no
/// route.
#[cfg(any(windows, test))]
trait WindowsTunnelRuntime: Send + Sync {
    fn is_elevated(&self) -> bool;
    /// Load the Wintun exports without creating an adapter or a route.
    fn load_wintun(&self, wintun_dll: &std::path::Path) -> io::Result<()>;
    fn check_phone(&self, phone: &phone::PhoneProxy, cancel: &AtomicBool) -> io::Result<()>;
    fn open_device(
        &self,
        unit: u32,
        wintun_dll: &std::path::Path,
    ) -> io::Result<Box<dyn WindowsWintunDevice>>;
    fn open_routes(
        &self,
        identity: crate::windows_native_routes::AdapterIdentity,
    ) -> io::Result<Box<dyn WindowsRouteController>>;
}

pub struct Service {
    inner: Mutex<Inner>,
    failures: Arc<failures::FailureRecorder>,
}
impl Default for Service {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                active: None,
                mode: None,
                started: None,
                error: None,
                cleanup_blocked: false,
                icmp_enabled: false,
                #[cfg(any(target_os = "macos", target_os = "linux", windows))]
                workers: 0,
                pinned_iface: None,
                last_stop_reason: None,
                last_stop_at: None,
                logs: VecDeque::new(),
                next_log_seq: 0,
            }),
            failures: Arc::new(failures::FailureRecorder::new()),
        }
    }
}

impl Service {
    pub fn new() -> Self {
        Self::default()
    }

    fn reap_finished(inner: &mut Inner, failures: &failures::FailureRecorder) {
        #[cfg(unix)]
        if matches!(&inner.active, Some(Active::Socks { server, .. }) if !server.is_running()) {
            if let Some(Active::Socks { mut server, .. }) = inner.active.take() {
                server.stop();
                inner.error = Some("The SOCKS5 listener stopped unexpectedly.".into());
                inner.log("error", "The SOCKS5 listener stopped unexpectedly.");
                inner.mode = None;
                inner.started = None;
                inner.icmp_enabled = false;
                inner.pinned_iface = None;
                failures.clear();
            }
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            let finished =
                matches!(&inner.active, Some(Active::Tun { handle,.. }) if handle.is_finished());
            if finished {
                if let Some(Active::Tun {
                    handle,
                    fault,
                    auto_stop,
                    ..
                }) = inner.active.take()
                {
                    let panicked = handle.join().is_err();
                    let failure = fault.lock().unwrap().clone();
                    let reason = *auto_stop.lock().unwrap();
                    if let Some(reason) = reason {
                        inner.last_stop_reason = Some(reason);
                        inner.last_stop_at = Some(now());
                        if let Some(message) = crate::autostop::stop_message(reason) {
                            inner.log("info", message);
                        }
                    }
                    if let Some((message, cleanup_failed)) = failure {
                        inner.error = Some(message);
                        inner.cleanup_blocked |= cleanup_failed;
                        inner.log(
                            "error",
                            if cleanup_failed {
                                "Tunnel route cleanup failed."
                            } else {
                                "Tunnel stopped unexpectedly."
                            },
                        );
                    } else if panicked {
                        inner.error = Some("The tunnel worker failed.".into());
                        inner.cleanup_blocked = true;
                        inner.log("error", "Tunnel worker failed.");
                    }
                    inner.mode = None;
                    inner.started = None;
                    inner.icmp_enabled = false;
                    inner.pinned_iface = None;
                    failures.clear();
                }
            }
        }
    }

    fn resolve_interface(iface: Option<&str>) -> io::Result<(String, u32)> {
        let name = match iface {
            Some(value)
                if !value.is_empty()
                    && !value.starts_with("utun")
                    && value != "none"
                    && !value.starts_with("HotspotShade-Tunnel") =>
            {
                value.to_owned()
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a physical interface is required",
                ))
            }
            None => {
                #[cfg(unix)]
                {
                    environment::default_route()?.interface
                }
                #[cfg(windows)]
                {
                    let index = crate::platform::default_interface_index()?;
                    let name = normalization::interface_name(index)?;
                    if name.starts_with("HotspotShade-Tunnel") {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "the default interface is the tunnel adapter; select the physical hotspot interface",
                        ));
                    }
                    name
                }
            }
        };
        let index = normalization::interface_index(&name)?;
        Ok((name, index))
    }

    /// Refuse an outer interface proof whose index differs from the index that
    /// the start path recorded before the source device check.
    #[cfg(any(target_os = "linux", windows, test))]
    fn verify_outer_index(frozen: u32, proof: u32) -> io::Result<()> {
        if frozen == proof {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outer_interface_changed",
            ))
        }
    }

    #[cfg(unix)]
    pub fn start_socks(
        &self,
        address: SocketAddr,
        iface: Option<&str>,
        servers: Option<Vec<SocketAddr>>,
    ) -> io::Result<()> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listener must use loopback",
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_blocked {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before restarting",
            ));
        }
        if inner.active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service is running",
            ));
        }
        let (name, index) = Self::resolve_interface(iface)?;
        let servers = match servers {
            Some(v) if !v.is_empty() => v,
            _ => {
                let v = environment::system_dns()?;
                if v.is_empty() {
                    vec![SocketAddr::from(([8, 8, 8, 8], 53))]
                } else {
                    v
                }
            }
        };
        let audit = Arc::new(normalization::Audit::default());
        let resolver = Arc::new(dns::TinyResolver::new(
            servers,
            Some(index),
            Duration::from_secs(4),
        )?);
        let server = socks::SocksServer::start(address, resolver, Some(index), audit.clone())?;
        inner.active = Some(Active::Socks { server, audit });
        inner.mode = Some("socks5");
        inner.started = Some(now());
        inner.error = None;
        inner.last_stop_reason = None;
        inner.last_stop_at = None;
        inner.icmp_enabled = false;
        inner.pinned_iface = Some(name);
        inner.log("info", "SOCKS5 proxy started.");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn start_tun(
        &self,
        iface: Option<&str>,
        phone: Option<phone::PhoneProxy>,
        ipv6_forward: bool,
        workers: usize,
    ) -> io::Result<()> {
        let options = TunOptions {
            iface: iface.map(str::to_owned),
            ipv6: if ipv6_forward {
                Ipv6Policy::Forward
            } else {
                Ipv6Policy::Block
            },
            ..TunOptions::default()
        };
        self.start_tun_options(options, phone, workers)
    }

    #[cfg(target_os = "macos")]
    pub fn start_tun_options(
        &self,
        options: TunOptions,
        phone: Option<phone::PhoneProxy>,
        workers: usize,
    ) -> io::Result<()> {
        self.start_tun_options_cancellable(options, phone, workers, &AtomicBool::new(false))
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
    pub fn start_tun_options_cancellable(
        &self,
        _options: TunOptions,
        _phone: Option<phone::PhoneProxy>,
        _workers: usize,
        _cancel: &AtomicBool,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "The tunnel is not implemented on this platform.",
        ))
    }

    #[cfg(target_os = "macos")]
    pub fn start_tun_options_cancellable(
        &self,
        options: TunOptions,
        phone: Option<phone::PhoneProxy>,
        workers: usize,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        use crate::{
            ipv6::Ipv6Tunnel,
            platform::{configure_link, FrameBuffer, RouteManager, Utun},
            relay::{Relay, RelayConfig},
        };
        use std::os::fd::AsRawFd;
        let cancelled = || {
            if cancel.load(Ordering::Acquire) {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "start cancelled",
                ))
            } else {
                Ok(())
            }
        };
        options.validate(phone.is_some(), workers)?;
        cancelled()?;
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tunnel requires administrator privileges",
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_blocked {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before restarting",
            ));
        }
        if inner.active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service is running",
            ));
        }
        let pinned = if options.no_pin {
            None
        } else {
            Some(Self::resolve_interface(options.iface.as_deref())?)
        };
        let index = pinned.as_ref().map(|(_, index)| *index);
        let phone_mode = phone.is_some();
        let phone = if let Some(mut p) = phone {
            p.iface = index;
            if let Err(e) = p.check_cancellable(&normalization::Audit::default(), cancel) {
                if e.kind() == io::ErrorKind::Interrupted {
                    return Err(e);
                }
                let message = if crate::phone::auth_rejection(&e).is_some() {
                    "Source device authentication failed."
                } else {
                    "Source device connection check failed."
                };
                inner.log("error", message);
                // Only a rejected token is an authentication failure. A
                // timeout or a refused connection is a start failure.
                let code = auth_error_code(&e);
                return Err(io::Error::new(e.kind(), code));
            }
            Some(Arc::new(p))
        } else {
            None
        };
        cancelled()?;
        let tun = Utun::open(options.unit).map_err(|e| {
            inner.log("error", "Tunnel device creation failed.");
            io::Error::new(e.kind(), "tunnel_setup")
        })?;
        configure_link(tun.ifname(), options.addr, 1500).map_err(|e| {
            inner.log("error", "Tunnel device configuration failed.");
            io::Error::new(e.kind(), "tunnel_setup")
        })?;
        cancelled()?;
        let ipv6_forward = options.ipv6 == Ipv6Policy::Forward;
        self.failures.start();
        let relay = Relay::start(RelayConfig {
            iface: index,
            phone,
            dns_upstream: options.dns_upstream,
            workers,
            ipv6_forward,
            allow_unpinned: options.no_pin,
            icmp_phone: options.icmp_phone,
            icmp_persistent: options.icmp_persistent,
            failures: Some(self.failures.clone()),
        })?;
        cancelled()?;
        let mut routes = RouteManager::new(tun.ifname(), options.ipv6 == Ipv6Policy::Block)?;
        if let Err(error) = if options.no_routes {
            Ok(())
        } else {
            routes.install()
        } {
            inner.log("error", "Tunnel route setup failed.");
            if routes.has_installed_routes() {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        if let Err(error) = cancelled() {
            if routes.remove().is_err() || routes.has_installed_routes() {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        if !options.no_routes && options.ipv6 == Ipv6Policy::Block {
            if let Err(error) = crate::ipv6::verify_ipv6_route(None, Duration::from_secs(2)) {
                inner.log("error", "IPv6 block route verification failed.");
                if routes.remove().is_err() || routes.has_installed_routes() {
                    inner.cleanup_blocked = true;
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(io::Error::new(error.kind(), "route_setup"));
            }
        }
        let mut v6 = if ipv6_forward && !options.no_routes {
            let mut guard = match Ipv6Tunnel::new(tun.ifname()) {
                Ok(guard) => guard,
                Err(error) => {
                    if routes.remove().is_err() {
                        inner.cleanup_blocked = true;
                        inner.error =
                            Some("Route cleanup failed. Inspect routes before restarting.".into());
                    }
                    return Err(io::Error::new(error.kind(), "route_setup"));
                }
            };
            if let Err(error) = guard.install().and_then(|_| guard.verify()) {
                inner.log("error", "IPv6 tunnel route setup failed.");
                let v6_failed = guard.remove().is_err() || guard.has_changes();
                let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
                if v6_failed || v4_failed {
                    inner.cleanup_blocked = true;
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(io::Error::new(error.kind(), "route_setup"));
            }
            Some(guard)
        } else {
            None
        };
        if let Err(error) = cancelled() {
            let v6_failed = v6
                .as_mut()
                .map(|guard| guard.remove().is_err() || guard.has_changes())
                .unwrap_or(false);
            let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
            if v6_failed || v4_failed {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = stop.clone();
        let stats = Arc::new(Mutex::new(json!({})));
        let stats_worker = stats.clone();
        let diag = Arc::new(Mutex::new(diagnostics::empty()));
        let diag_worker = diag.clone();
        let fault = Arc::new(Mutex::new(None));
        let fault_worker = fault.clone();
        let auto_stop = Arc::new(Mutex::new(None));
        let verify_interface = if ipv6_forward {
            Some(tun.ifname().to_owned())
        } else {
            None
        };
        let verify_routes = !options.no_routes && options.ipv6 != Ipv6Policy::Inherit;
        let (resources, resource_rx) = std::sync::mpsc::sync_channel(1);
        let handle = match std::thread::Builder::new().name("hotspot-tun".into()).spawn(move || {
            let (tun, mut relay, mut routes, mut v6): (Utun, Relay, RouteManager, Option<Ipv6Tunnel>) = match resource_rx.recv() {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut device_errors = 0u64;
            let mut relay_failed = false;
            let monitor_stop = Arc::new(AtomicBool::new(false));
            let monitor_flag = monitor_stop.clone();
            let (monitor_tx,monitor_rx) = std::sync::mpsc::sync_channel::<String>(1);
            let mut monitor_reason: Option<String> = None;
            let monitor = if verify_routes { Some(std::thread::Builder::new().name("hotspot-route-check".into()).spawn(move || {
                // A route that does not match the policy stops the tunnel at once.
                // A check that cannot finish (timeout, spawn error) is not proof of
                // a leak. Stop only after several such checks in a row.
                let mut inconclusive = 0u32;
                while !monitor_flag.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_secs(5));
                    if monitor_flag.load(Ordering::Acquire) { break; }
                    match crate::ipv6::verify_ipv6_route(verify_interface.as_deref(),Duration::from_secs(2)) {
                        Ok(()) => inconclusive = 0,
                        Err(error) if error.kind() == io::ErrorKind::NotConnected => {
                            let _ = monitor_tx.try_send("The IPv6 route no longer matches the selected policy.".to_owned());
                            break;
                        }
                        Err(error) => {
                            inconclusive += 1;
                            if inconclusive >= ROUTE_CHECK_INCONCLUSIVE_LIMIT {
                                let _ = monitor_tx.try_send(format!("The IPv6 route check failed {} times in a row: {}.", inconclusive, error));
                                break;
                            }
                        }
                    }
                }
            })) } else { None };
            let monitor = match monitor { Some(Ok(handle)) => Some(handle), Some(Err(_)) => { relay_failed = true; None }, None=>None };
            let mut pending = std::collections::VecDeque::<Vec<u8>>::new();
            let mut frame = FrameBuffer::new();
            let mut next_stats = std::time::Instant::now();
            while !relay_failed && !stop_worker.load(Ordering::Acquire) && relay.is_running() {
                for _ in 0..256 {
                    match tun.read_packet(&mut frame) {
                        Ok(packet) => { if let Err(e) = relay.dispatch(packet) {
                            if e.kind() != io::ErrorKind::WouldBlock { relay_failed = true; break; }
                        }}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => { device_errors += 1; stop_worker.store(true,Ordering::Release); break; }
                    }
                }
                if relay_failed { break; }
                for _ in 0..256 {
                    if pending.len() >= 1024 { break; }
                    match relay.try_receive() { Some(packet) => pending.push_back(packet), None => break }
                }
                for _ in 0..256 {
                    let Some(packet) = pending.front() else { break };
                    match tun.write_packet(packet) {
                        Ok(_) => { pending.pop_front(); },
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => { device_errors += 1; relay_failed = true; break; }
                    }
                }
                if relay_failed { break; }
                if std::time::Instant::now() >= next_stats {
                    let s = relay.stats();
                    let mut stats = json!({"packets_in":s.packets_in,"packets_out":s.packets_out,
                    "bytes_in":s.bytes_in,"bytes_out":s.bytes_out,"tcp_flows":s.tcp_flows,"tcp_flows_closed":s.tcp_flows_closed,
                    "udp_flows_closed":s.udp_flows_closed,"udp_datagrams_in":s.udp_datagrams_in,"udp_datagrams_out":s.udp_datagrams_out,
                    "udp_errors":s.udp_errors,"udp_dropped":s.udp_dropped,"udp_reply_too_big":s.udp_reply_too_big,
                    "ttl_bad":s.ttl_bad,"ipv6_dropped":s.ipv6_dropped,"fragments_dropped":s.fragments_dropped,
                    "icmp_dropped":s.icmp_dropped,"icmp_requests":s.icmp_requests,"icmp_replies":s.icmp_replies,"icmp_errors":s.icmp_errors,
                    "send_dropped":s.send_dropped + device_errors,
                    "flow_errors":s.flow_errors,"queue_dropped":s.queue_dropped,
                    "tcp_setup_errors":s.tcp_setup_errors,"tcp_io_errors":s.tcp_io_errors,
                    "tcp_setup_refused":s.tcp_setup_refused,"tcp_setup_timed_out":s.tcp_setup_timed_out,
                    "tcp_setup_permission_denied":s.tcp_setup_permission_denied,"tcp_setup_other":s.tcp_setup_other,"tcp_setup_phone_unreachable":s.tcp_setup_phone_unreachable,
                    "dns_flows":s.dns_flows,"dns_setup_ok":s.dns_setup_ok,"dns_setup_failed":s.dns_setup_failed,
                    "input_queues":s.input_queues.iter().map(|q|json!({"packets_current":q.packets_current,"packets_peak":q.packets_peak,"max_age_us":q.max_age_us})).collect::<Vec<_>>(),
                    "output_queue":{"packets_current":s.output_queue.packets_current,"packets_peak":s.output_queue.packets_peak,"max_age_us":s.output_queue.max_age_us}});
                    if let Some(target)=stats.as_object_mut() {
                        let icmp=icmp_failure_stats(&s);
                        if let Some(values)=icmp.as_object(){target.extend(values.clone());}
                        let tcp=tcp_setup_timeout_stats(&s);
                        if let Some(values)=tcp.as_object(){target.extend(values.clone());}
                        let performance=tcp_performance_stats(&s);
                        if let Some(values)=performance.as_object(){target.extend(values.clone());}
                    }
                    *stats_worker.lock().unwrap() = stats;
                    *diag_worker.lock().unwrap() = relay.diagnostics();
                    next_stats = std::time::Instant::now() + Duration::from_millis(100);
                }
                if let Ok(reason) = monitor_rx.try_recv() { monitor_reason = Some(reason); relay_failed = true; break; }
                let mut pollfd = [
                    libc::pollfd { fd:tun.as_raw_fd(),events:libc::POLLIN | if pending.is_empty() {0} else {libc::POLLOUT},revents:0 },
                    libc::pollfd { fd:relay.output_fd(),events:libc::POLLIN,revents:0 },
                ];
                let result = unsafe { libc::poll(pollfd.as_mut_ptr(),pollfd.len() as libc::nfds_t,100) };
                if (result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
                    || pollfd.iter().any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0) { relay_failed = true; break; }
            }
            let unexpected = relay_failed || !stop_worker.load(Ordering::Acquire) || device_errors > 0;
            monitor_stop.store(true,Ordering::Release);
            if let Some(handle) = monitor { handle.thread().unpark(); let _ = handle.join(); }
            relay.stop();
            let v6_error = v6.as_mut().and_then(|guard| guard.remove().err());
            let route_error = routes.remove().err();
            if v6_error.is_some() || route_error.is_some() {
                *fault_worker.lock().unwrap() = Some(("Route cleanup failed. Inspect the routing table before restarting.".into(),true));
            } else if unexpected {
                let message = match monitor_reason {
                    Some(reason) => format!("The tunnel stopped. {}", reason),
                    None => "The tunnel device or relay stopped unexpectedly.".to_owned(),
                };
                *fault_worker.lock().unwrap() = Some((message,false));
            }
        }) {
            Ok(handle) => handle,
            Err(error) => {
                let v6_failed = v6.as_mut().map(|guard|guard.remove().is_err() || guard.has_changes()).unwrap_or(false);
                let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
                if v6_failed || v4_failed { inner.cleanup_blocked = true; inner.error = Some("Route cleanup failed. Inspect routes before restarting.".into()); }
                return Err(error);
            }
        };
        if let Err(error) = resources.send((tun, relay, routes, v6)) {
            let (tun, mut relay, mut routes, mut v6) = error.0;
            relay.stop();
            let v6_failed = v6
                .as_mut()
                .map(|guard| guard.remove().is_err() || guard.has_changes())
                .unwrap_or(false);
            let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
            drop(tun);
            let _ = handle.join();
            inner.cleanup_blocked = v6_failed || v4_failed;
            inner.error = Some("Tunnel startup failed. Inspect routes before restarting.".into());
            return Err(io::Error::other("tunnel worker failed to start"));
        }
        inner.active = Some(Active::Tun {
            stop,
            handle,
            stats,
            diag,
            fault,
            auto_stop,
        });
        inner.mode = Some(if phone_mode { "phone" } else { "tun" });
        inner.started = Some(now());
        inner.workers = workers;
        inner.error = None;
        inner.last_stop_reason = None;
        inner.last_stop_at = None;
        inner.icmp_enabled = phone_mode && options.icmp_phone;
        inner.pinned_iface = pinned.map(|(name, _)| name);
        inner.log(
            "info",
            if phone_mode {
                "Source device tunnel started."
            } else {
                "Tunnel started."
            },
        );
        if options.icmp_phone {
            inner.log("warning", "Experimental source device ICMP is enabled.");
        }
        if cancel.load(Ordering::Acquire) {
            self.stop_locked(&mut inner);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "start cancelled",
            ));
        }
        Ok(())
    }

    /// Start the Linux tunnel in direct mode or source device proxy mode.
    ///
    /// Direct mode has no source device. The method opens the TUN device,
    /// installs the dedicated table and the two policy rules, verifies the
    /// selected IPv4 routes and the selected IPv6 policy, starts the relay, and
    /// hands the resources to one worker thread. Source device proxy mode adds
    /// the source device check and always forwards IPv6.
    ///
    /// Every failure path removes the objects that this call created. A cleanup
    /// failure sets `cleanup_blocked` so a later start cannot overlap it. The
    /// worker stops on the normal stop flag, on a relay or device failure, or
    /// after 20 seconds without the physical hotspot link.
    #[cfg(target_os = "linux")]
    pub fn start_tun_options_cancellable(
        &self,
        options: TunOptions,
        phone: Option<phone::PhoneProxy>,
        workers: usize,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        use crate::platform_linux::{
            Ipv6Policy as LinuxIpv6Policy, LinkGuard, PacketBuffer, RouteManager, Tun,
        };
        use crate::relay::{Relay, RelayConfig};
        use std::os::fd::AsRawFd;
        let cancelled = || {
            if cancel.load(Ordering::Acquire) {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "start cancelled",
                ))
            } else {
                Ok(())
            }
        };
        options.validate(phone.is_some(), workers)?;
        let phone_mode = phone.is_some();
        if phone_mode && options.ipv6 != Ipv6Policy::Forward {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source device proxy mode requires IPv6 forwarding",
            ));
        }
        if !phone_mode {
            if options.no_pin {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the Linux tunnel requires outer interface pinning",
                ));
            }
            if options.no_routes {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the Linux tunnel requires managed routes",
                ));
            }
            if options.ipv6 == Ipv6Policy::Inherit {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the Linux tunnel supports IPv6 block and forward only",
                ));
            }
        }
        let policy = match options.ipv6 {
            Ipv6Policy::Block => LinuxIpv6Policy::Block,
            Ipv6Policy::Forward => LinuxIpv6Policy::Forward,
            Ipv6Policy::Inherit => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Linux inherit is an explicit leak and is not a start mode",
                ))
            }
        };
        cancelled()?;
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tunnel requires administrator privileges",
            ));
        }
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_blocked {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before restarting",
            ));
        }
        if inner.active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service is running",
            ));
        }
        let (outer_ifname, outer_ifindex) = Self::resolve_interface(options.iface.as_deref())?;
        let phone = if let Some(mut phone) = phone {
            phone.iface = Some(outer_ifindex);
            if let Err(error) = phone.check_cancellable(&normalization::Audit::default(), cancel) {
                if error.kind() == io::ErrorKind::Interrupted {
                    return Err(error);
                }
                let message = if crate::phone::auth_rejection(&error).is_some() {
                    "Source device authentication failed."
                } else {
                    "Source device connection check failed."
                };
                inner.log("error", message);
                let code = auth_error_code(&error);
                return Err(io::Error::new(error.kind(), code));
            }
            Some(Arc::new(phone))
        } else {
            None
        };
        cancelled()?;
        let ifname = format!("hs-tun{}", options.unit);
        let tun = match Tun::open(&ifname, 1500) {
            Ok(tun) => tun,
            Err(error) => {
                inner.log("error", "Tunnel device creation failed.");
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        let mut routes = match RouteManager::new(tun.ifname(), policy) {
            Ok(routes) => routes,
            Err(error) => return Err(io::Error::new(error.kind(), "route_setup")),
        };
        let interface = match routes.verify_interface(&tun) {
            Ok(proof) => proof,
            Err(error) => {
                inner.log("error", "Tunnel interface verification failed.");
                return Err(io::Error::other(error.to_string()));
            }
        };
        let outer = match routes.verify_outer_pin(&outer_ifname) {
            Ok(proof) => proof,
            Err(error) => {
                inner.log("error", "Outer interface verification failed.");
                return Err(io::Error::other(error.to_string()));
            }
        };
        if let Err(error) = Self::verify_outer_index(outer_ifindex, outer.ifindex()) {
            inner.log("error", "Outer interface changed during setup.");
            return Err(error);
        }
        let mut link = match LinkGuard::install(&interface, &tun, options.addr, 1500) {
            Ok(link) => link,
            Err(error) => {
                inner.log("error", "Tunnel device configuration failed.");
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        let prepared = routes
            .install_verified(&interface, &tun, &outer_ifname)
            .and_then(|()| {
                routes
                    .verify_start(&interface, &tun, &outer)
                    .map_err(|error| io::Error::other(error.to_string()))
            });
        if let Err(error) = prepared {
            inner.log("error", "Tunnel route setup failed.");
            let route_error = routes.remove().err();
            let link_error = link.remove().err();
            if route_error.is_some() || link_error.is_some() {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        if let Err(error) = cancelled() {
            let route_error = routes.remove().err();
            let link_error = link.remove().err();
            if route_error.is_some() || link_error.is_some() {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        self.failures.start();
        let relay = match Relay::start(RelayConfig {
            iface: Some(outer_ifindex),
            phone,
            dns_upstream: options.dns_upstream,
            workers,
            ipv6_forward: policy == LinuxIpv6Policy::Forward,
            allow_unpinned: false,
            icmp_phone: options.icmp_phone,
            icmp_persistent: options.icmp_persistent,
            failures: Some(self.failures.clone()),
        }) {
            Ok(relay) => relay,
            Err(error) => {
                inner.log("error", "Tunnel relay setup failed.");
                let route_error = routes.remove().err();
                let link_error = link.remove().err();
                if route_error.is_some() || link_error.is_some() {
                    inner.cleanup_blocked = true;
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(error);
            }
        };
        if let Err(error) = cancelled() {
            let mut relay = relay;
            relay.stop();
            let route_error = routes.remove().err();
            let link_error = link.remove().err();
            if route_error.is_some() || link_error.is_some() {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = stop.clone();
        let stats = Arc::new(Mutex::new(json!({})));
        let stats_worker = stats.clone();
        let diag = Arc::new(Mutex::new(diagnostics::empty()));
        let diag_worker = diag.clone();
        let fault = Arc::new(Mutex::new(None));
        let fault_worker = fault.clone();
        let auto_stop = Arc::new(Mutex::new(None));
        let auto_stop_worker = auto_stop.clone();
        let link_ifname = outer_ifname.clone();
        let (resources, resource_rx) = std::sync::mpsc::sync_channel(1);
        let handle = match std::thread::Builder::new()
            .name("hotspot-tun".into())
            .spawn(move || {
                let (tun, mut relay, mut routes, mut link): (Tun, Relay, RouteManager, LinkGuard) =
                    match resource_rx.recv() {
                        Ok(value) => value,
                        Err(_) => return,
                    };
                let mut device_errors = 0u64;
                let mut relay_failed = false;
                let mut buffer = match PacketBuffer::new(1500) {
                    Ok(buffer) => buffer,
                    Err(_) => {
                        relay.stop();
                        let route_error = routes.remove().err();
                        let link_error = link.remove().err();
                        if route_error.is_some() || link_error.is_some() {
                            *fault_worker.lock().unwrap() = Some((
                                "Route cleanup failed. Inspect the routing table before restarting."
                                    .into(),
                                true,
                            ));
                        }
                        return;
                    }
                };
                let link_monitor_stop = Arc::new(AtomicBool::new(false));
                let link_monitor_flag = link_monitor_stop.clone();
                let (link_tx, link_rx) = std::sync::mpsc::sync_channel::<&'static str>(1);
                let link_monitor = match std::thread::Builder::new()
                    .name("hotspot-link-check".into())
                    .spawn(move || {
                        let mut policy = crate::autostop::AutoStopPolicy::new();
                        while !link_monitor_flag.load(Ordering::Acquire) {
                            std::thread::park_timeout(Duration::from_secs(2));
                            if link_monitor_flag.load(Ordering::Acquire) {
                                break;
                            }
                            match crate::platform_linux::link_ready(&link_ifname) {
                                Ok(up) => {
                                    let sample = crate::autostop::sample_from(up, phone_mode, None);
                                    if let Some(reason) =
                                        policy.observe(std::time::Instant::now(), sample)
                                    {
                                        let _ = link_tx.try_send(reason);
                                        break;
                                    }
                                }
                                // An unknown link state is not link loss.
                                Err(_) => policy.reset(),
                            }
                        }
                    }) {
                    Ok(handle) => Some(handle),
                    Err(_) => {
                        relay_failed = true;
                        None
                    }
                };
                let mut pending = std::collections::VecDeque::<Vec<u8>>::new();
                let mut next_stats = std::time::Instant::now();
                while !relay_failed && !stop_worker.load(Ordering::Acquire) && relay.is_running() {
                    for _ in 0..256 {
                        match tun.read_packet(&mut buffer) {
                            Ok(packet) => {
                                if let Err(error) = relay.dispatch(packet.to_vec()) {
                                    if error.kind() != io::ErrorKind::WouldBlock {
                                        relay_failed = true;
                                        break;
                                    }
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => {
                                device_errors += 1;
                                relay_failed = true;
                                break;
                            }
                        }
                    }
                    if relay_failed {
                        break;
                    }
                    for _ in 0..256 {
                        if pending.len() >= 1024 {
                            break;
                        }
                        match relay.try_receive() {
                            Some(packet) => pending.push_back(packet),
                            None => break,
                        }
                    }
                    for _ in 0..256 {
                        let Some(packet) = pending.front() else {
                            break;
                        };
                        match tun.write_packet(packet) {
                            Ok(_) => {
                                pending.pop_front();
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => {
                                device_errors += 1;
                                relay_failed = true;
                                break;
                            }
                        }
                    }
                    if relay_failed {
                        break;
                    }
                    if std::time::Instant::now() >= next_stats {
                        *stats_worker.lock().unwrap() =
                            tunnel_relay_stats(&relay.stats(), device_errors);
                        *diag_worker.lock().unwrap() = relay.diagnostics();
                        next_stats = std::time::Instant::now() + Duration::from_millis(100);
                    }
                    if let Ok(reason) = link_rx.try_recv() {
                        *auto_stop_worker.lock().unwrap() = Some(reason);
                        break;
                    }
                    let mut pollfd = [
                        libc::pollfd {
                            fd: tun.as_raw_fd(),
                            events: libc::POLLIN
                                | if pending.is_empty() { 0 } else { libc::POLLOUT },
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: relay.output_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                    ];
                    let result = unsafe {
                        libc::poll(pollfd.as_mut_ptr(), pollfd.len() as libc::nfds_t, 100)
                    };
                    if (result < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
                        || pollfd.iter().any(|fd| {
                            fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                        })
                    {
                        relay_failed = true;
                        break;
                    }
                }
                let auto_reason = *auto_stop_worker.lock().unwrap();
                let unexpected = auto_reason.is_none()
                    && (relay_failed || !stop_worker.load(Ordering::Acquire) || device_errors > 0);
                link_monitor_stop.store(true, Ordering::Release);
                if let Some(handle) = link_monitor {
                    handle.thread().unpark();
                    let _ = handle.join();
                }
                relay.stop();
                let route_error = routes.remove().err();
                let link_error = link.remove().err();
                drop(tun);
                if route_error.is_some() || link_error.is_some() {
                    *fault_worker.lock().unwrap() = Some((
                        "Route cleanup failed. Inspect the routing table before restarting.".into(),
                        true,
                    ));
                } else if unexpected {
                    *fault_worker.lock().unwrap() = Some((
                        "The tunnel device or relay stopped unexpectedly.".into(),
                        false,
                    ));
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                let route_error = routes.remove().err();
                let link_error = link.remove().err();
                let mut relay = relay;
                relay.stop();
                if route_error.is_some() || link_error.is_some() {
                    inner.cleanup_blocked = true;
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(error);
            }
        };
        if let Err(error) = resources.send((tun, relay, routes, link)) {
            let (tun, mut relay, mut routes, mut link) = error.0;
            relay.stop();
            let route_error = routes.remove().err();
            let link_error = link.remove().err();
            drop(tun);
            let _ = handle.join();
            inner.cleanup_blocked = route_error.is_some() || link_error.is_some();
            inner.error = Some("Tunnel startup failed. Inspect routes before restarting.".into());
            return Err(io::Error::other("tunnel worker failed to start"));
        }
        inner.active = Some(Active::Tun {
            stop,
            handle,
            stats,
            diag,
            fault,
            auto_stop,
        });
        inner.mode = Some(if phone_mode { "phone" } else { "tun" });
        inner.started = Some(now());
        inner.workers = workers;
        inner.error = None;
        inner.last_stop_reason = None;
        inner.last_stop_at = None;
        inner.icmp_enabled = phone_mode && options.icmp_phone;
        inner.pinned_iface = Some(outer_ifname);
        inner.log(
            "info",
            if phone_mode {
                "Source device tunnel started."
            } else {
                "Tunnel started."
            },
        );
        if options.icmp_phone {
            inner.log("warning", "Experimental source device ICMP is enabled.");
        }
        if cancel.load(Ordering::Acquire) {
            self.stop_locked(&mut inner);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "start cancelled",
            ));
        }
        Ok(())
    }

    /// Start the Windows tunnel in source device proxy mode.
    ///
    /// The method mirrors the Linux start path. It checks the mode, the
    /// privileges, the outer interface, and the Wintun DLL before the source
    /// device check. It then opens the Wintun adapter, configures the adapter,
    /// installs the three native routes, starts the relay, and hands the
    /// resources to one worker thread.
    ///
    /// The Wintun DLL is never bundled. The path is explicit and absolute. The
    /// default is `wintun.dll` next to the executable. A missing file is a
    /// plain not-found error that names the path.
    ///
    /// Every failure path removes the routes that this call created and closes
    /// the adapter. A cleanup failure sets `cleanup_blocked`, so a later start
    /// cannot overlap the old resources.
    #[cfg(any(windows, test))]
    fn start_windows_tunnel_with(
        &self,
        options: TunOptions,
        phone: Option<phone::PhoneProxy>,
        workers: usize,
        cancel: &AtomicBool,
        runtime: &dyn WindowsTunnelRuntime,
    ) -> io::Result<()> {
        use crate::relay::{Relay, RelayConfig};

        let cancelled = || {
            if cancel.load(Ordering::Acquire) {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "start cancelled",
                ))
            } else {
                Ok(())
            }
        };
        options.validate(phone.is_some(), workers)?;
        let Some(mut phone) = phone else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "The Windows tunnel start supports source device proxy mode only.",
            ));
        };
        if options.ipv6 != Ipv6Policy::Forward {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source device proxy mode requires IPv6 forwarding",
            ));
        }
        if !runtime.is_elevated() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tunnel requires administrator privileges",
            ));
        }
        cancelled()?;
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_blocked {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before restarting",
            ));
        }
        if inner.active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service is running",
            ));
        }
        let (outer_ifname, outer_ifindex) = Self::resolve_interface(options.iface.as_deref())?;
        // Prove the physical interface again before any route change. A name
        // that no longer resolves to the frozen index stops the start.
        let proof = normalization::interface_index(&outer_ifname)?;
        Self::verify_outer_index(outer_ifindex, proof)?;
        // Report a missing or incompatible Wintun DLL before the source device
        // check. This creates no adapter and changes no route.
        let wintun = windows_wintun_path(&options)?;
        if let Err(error) = runtime.load_wintun(&wintun) {
            inner.log("error", "Wintun DLL load failed.");
            return Err(error);
        }
        phone.iface = Some(outer_ifindex);
        if let Err(error) = runtime.check_phone(&phone, cancel) {
            if error.kind() == io::ErrorKind::Interrupted {
                return Err(error);
            }
            let message = if crate::phone::auth_rejection(&error).is_some() {
                "Source device authentication failed."
            } else {
                "Source device connection check failed."
            };
            inner.log("error", message);
            let code = auth_error_code(&error);
            return Err(io::Error::new(error.kind(), code));
        }
        cancelled()?;
        let mut device = match runtime.open_device(options.unit, &wintun) {
            Ok(device) => device,
            Err(error) => {
                inner.log("error", "Wintun DLL or adapter setup failed.");
                return Err(error);
            }
        };
        if let Err(error) = device.configure_link(options.addr, 1500) {
            inner.log("error", "Tunnel device configuration failed.");
            return Err(io::Error::new(error.kind(), "tunnel_setup"));
        }
        // The adapter must have a name and a nonzero index before any route
        // can name it. A bad value stops the start before a route exists.
        if device.ifindex() == 0 || device.ifname().is_empty() {
            inner.log("error", "Tunnel device identity is invalid.");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tunnel_setup"));
        }
        cancelled()?;
        let identity = match device.route_identity() {
            Ok(identity) => identity,
            Err(error) => {
                inner.log("error", "Tunnel adapter identity check failed.");
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        let mut routes = match runtime.open_routes(identity) {
            Ok(routes) => routes,
            Err(error) => {
                inner.log("error", "Tunnel route boundary setup failed.");
                return Err(io::Error::new(error.kind(), "route_setup"));
            }
        };
        if let Err(error) = routes.install() {
            inner.log("error", "Tunnel route setup failed.");
            let cleanup_failed = clean_windows_start(&mut inner, None, Some(routes), Some(device));
            if cleanup_failed {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        if let Err(error) = cancelled() {
            let cleanup_failed = clean_windows_start(&mut inner, None, Some(routes), Some(device));
            if cleanup_failed {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        self.failures.start();
        let relay = match Relay::start(RelayConfig {
            iface: Some(outer_ifindex),
            phone: Some(Arc::new(phone)),
            dns_upstream: None,
            workers,
            ipv6_forward: true,
            allow_unpinned: false,
            icmp_phone: options.icmp_phone,
            icmp_persistent: options.icmp_persistent,
            failures: Some(self.failures.clone()),
        }) {
            Ok(relay) => relay,
            Err(error) => {
                inner.log("error", "Tunnel relay setup failed.");
                let cleanup_failed =
                    clean_windows_start(&mut inner, None, Some(routes), Some(device));
                if cleanup_failed {
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(error);
            }
        };
        if let Err(error) = cancelled() {
            let cleanup_failed =
                clean_windows_start(&mut inner, Some(relay), Some(routes), Some(device));
            if cleanup_failed {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = stop.clone();
        let stats = Arc::new(Mutex::new(json!({})));
        let stats_worker = stats.clone();
        let diag = Arc::new(Mutex::new(diagnostics::empty()));
        let diag_worker = diag.clone();
        let fault = Arc::new(Mutex::new(None));
        let fault_worker = fault.clone();
        let auto_stop = Arc::new(Mutex::new(None));
        let (resources, resource_rx) = std::sync::mpsc::sync_channel(1);
        let handle = match std::thread::Builder::new()
            .name("hotspot-tun".into())
            .spawn(move || {
                let (mut device, mut relay, mut routes): (
                    Box<dyn WindowsWintunDevice>,
                    Relay,
                    Box<dyn WindowsRouteController>,
                ) = match resource_rx.recv() {
                    Ok(value) => value,
                    Err(_) => return,
                };
                let mut device_errors = 0u64;
                let mut relay_failed = false;
                let mut pending = std::collections::VecDeque::<Vec<u8>>::new();
                let mut next_stats = std::time::Instant::now();
                while !relay_failed && !stop_worker.load(Ordering::Acquire) && relay.is_running() {
                    for _ in 0..256 {
                        match device.read_packet() {
                            Ok(packet) => {
                                if let Err(error) = relay.dispatch(packet) {
                                    if error.kind() != io::ErrorKind::WouldBlock {
                                        relay_failed = true;
                                        break;
                                    }
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => {
                                device_errors += 1;
                                relay_failed = true;
                                break;
                            }
                        }
                    }
                    if relay_failed {
                        break;
                    }
                    for _ in 0..256 {
                        if pending.len() >= 1024 {
                            break;
                        }
                        match relay.try_receive() {
                            Some(packet) => pending.push_back(packet),
                            None => break,
                        }
                    }
                    for _ in 0..256 {
                        let Some(packet) = pending.front() else {
                            break;
                        };
                        match device.write_packet(packet) {
                            Ok(_) => {
                                pending.pop_front();
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => {
                                device_errors += 1;
                                relay_failed = true;
                                break;
                            }
                        }
                    }
                    if relay_failed {
                        break;
                    }
                    if std::time::Instant::now() >= next_stats {
                        *stats_worker.lock().unwrap() =
                            tunnel_relay_stats(&relay.stats(), device_errors);
                        *diag_worker.lock().unwrap() = relay.diagnostics();
                        next_stats = std::time::Instant::now() + Duration::from_millis(100);
                    }
                    // The Wintun read event is a kernel event, not a socket.
                    // A short bounded wait keeps the relay output moving while
                    // the hotspot is idle.
                    match device.wait_readable(Duration::from_millis(10)) {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            device_errors += 1;
                            relay_failed = true;
                            break;
                        }
                    }
                }
                let unexpected =
                    relay_failed || !stop_worker.load(Ordering::Acquire) || device_errors > 0;
                relay.stop();
                let route_error = routes.remove().err();
                let routes_left = routes.has_routes();
                drop(routes);
                drop(device);
                if route_error.is_some() || routes_left {
                    *fault_worker.lock().unwrap() = Some((
                        "Route cleanup failed. Inspect the routing table before restarting.".into(),
                        true,
                    ));
                } else if unexpected {
                    *fault_worker.lock().unwrap() = Some((
                        "The tunnel device or relay stopped unexpectedly.".into(),
                        false,
                    ));
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                let cleanup_failed =
                    clean_windows_start(&mut inner, Some(relay), Some(routes), Some(device));
                if cleanup_failed {
                    inner.cleanup_blocked = true;
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(error);
            }
        };
        if let Err(error) = resources.send((device, relay, routes)) {
            let message = error.to_string();
            let (device, mut relay, mut routes) = error.0;
            relay.stop();
            let route_error = routes.remove().err();
            let routes_left = routes.has_routes();
            drop(routes);
            drop(device);
            let _ = handle.join();
            inner.cleanup_blocked = route_error.is_some() || routes_left;
            inner.error = Some("Tunnel startup failed. Inspect routes before restarting.".into());
            return Err(io::Error::other(format!(
                "tunnel worker failed to start: {message}"
            )));
        }
        inner.active = Some(Active::Tun {
            stop,
            handle,
            stats,
            diag,
            fault,
            auto_stop,
        });
        inner.mode = Some("phone");
        inner.started = Some(now());
        inner.workers = workers;
        inner.error = None;
        inner.last_stop_reason = None;
        inner.last_stop_at = None;
        inner.icmp_enabled = options.icmp_phone;
        inner.pinned_iface = Some(outer_ifname);
        inner.log("info", "Source device tunnel started.");
        if options.icmp_phone {
            inner.log("warning", "Experimental source device ICMP is enabled.");
        }
        if cancel.load(Ordering::Acquire) {
            self.stop_locked(&mut inner);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "start cancelled",
            ));
        }
        Ok(())
    }

    /// Stop the tunnel and remove the owned resources. Idempotent.
    fn stop_locked(&self, inner: &mut Inner) {
        inner.mode = None;
        inner.started = None;
        inner.icmp_enabled = false;
        inner.pinned_iface = None;
        let active = inner.active.take();
        let was_active = active.is_some();
        match active {
            #[cfg(unix)]
            Some(Active::Socks { mut server, .. }) => server.stop(),
            #[cfg(any(target_os = "macos", target_os = "linux", windows))]
            Some(Active::Tun {
                stop,
                handle,
                fault,
                auto_stop,
                ..
            }) => {
                stop.store(true, Ordering::Release);
                if handle.join().is_err() {
                    inner.error = Some("The tunnel worker failed.".into());
                    inner.cleanup_blocked = true;
                }
                let reason = *auto_stop
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(reason) = reason {
                    inner.last_stop_reason = Some(reason);
                    inner.last_stop_at = Some(now());
                    if let Some(message) = crate::autostop::stop_message(reason) {
                        inner.log("info", message);
                    }
                }
                if let Some((message, cleanup_failed)) = fault.lock().unwrap().clone() {
                    inner.error = Some(message);
                    inner.cleanup_blocked |= cleanup_failed;
                }
            }
            None => (),
        }
        if was_active {
            if inner.cleanup_blocked {
                inner.log("error", "Service stopped. Route cleanup failed.");
            } else {
                inner.log("info", "Service stopped.");
            }
        }
        self.failures.clear();
    }

    pub fn stop(&self) {
        // Keep the lifecycle lock until cleanup finishes. A new start must
        // not overlap the old tunnel's route removal.
        let mut inner = self.inner.lock().unwrap();
        self.stop_locked(&mut inner);
    }

    /// Check service liveness without querying the system routing table.
    pub fn is_running(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        // Report the state that reap_finished checked. If a worker exits after
        // that check, the next call records its error before reporting a stop.
        inner.active.is_some()
    }

    /// Failed source device setups for the current tunnel. The value is empty
    /// when no tunnel runs. The record stays in memory only.
    pub fn failures(&self) -> Value {
        let running = {
            let mut inner = self.inner.lock().unwrap();
            Self::reap_finished(&mut inner, &self.failures);
            tunnel_worker_running(&inner)
        };
        if running {
            self.failures.snapshot()
        } else {
            failures::empty_snapshot()
        }
    }

    /// The bounded relay counters and timing reservoirs. It holds no address,
    /// host name, token, or key.
    pub fn diagnostics(&self) -> Value {
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        let running = tunnel_worker_running(&inner);
        let (metrics, started, workers) = if running {
            match &inner.active {
                #[cfg(any(target_os = "macos", target_os = "linux", windows))]
                Some(Active::Tun { diag, .. }) => {
                    (diag.lock().unwrap().clone(), inner.started, inner.workers)
                }
                _ => (json!({}), None, 0),
            }
        } else {
            (json!({}), None, 0)
        };
        let mut value = diagnostics::empty();
        if running {
            value["running"] = json!(true);
            value["engine"]["uptime_s"] = json!(now().saturating_sub(started.unwrap_or_else(now)));
            value["engine"]["workers"] = json!(workers);
            if let Some(map) = value.as_object_mut() {
                for key in ["setup", "dns", "queues", "udp", "tcp"] {
                    if let Some(section) = metrics.get(key) {
                        map.insert(key.into(), section.clone());
                    }
                }
            }
        }
        let failures = if running {
            self.failures.snapshot()
        } else {
            failures::empty_snapshot()
        };
        value["failures"]["total"] = failures["total"].clone();
        value["failures"]["dropped"] = failures["dropped"].clone();
        value
    }

    pub fn status(&self) -> Value {
        let mut inner = self.inner.lock().unwrap();
        Self::reap_finished(&mut inner, &self.failures);
        let (running, stats) = match &inner.active {
            #[cfg(unix)]
            Some(Active::Socks { server, audit }) => {
                let (total, bad) = audit.snapshot();
                (
                    true,
                    json!({"active_clients":server.active_clients(),"outer_sockets":total,"ttl_bad":bad}),
                )
            }
            #[cfg(any(target_os = "macos", target_os = "linux", windows))]
            Some(Active::Tun { stats, .. }) => (true, stats.lock().unwrap().clone()),
            None => (false, json!({})),
        };
        // Prefer the interface that the running tunnel pinned. On Windows the
        // system default lookup can return the tunnel adapter after the /1
        // routes are installed.
        let route = if running {
            inner
                .pinned_iface
                .as_ref()
                .map(|interface| crate::environment::DefaultRoute {
                    interface: interface.clone(),
                    gateway: None,
                })
                .or_else(default_route_status)
        } else {
            default_route_status()
        };
        let icmp_enabled = running && inner.mode == Some("phone") && inner.icmp_enabled;
        json!({"running":running,"mode":if running { inner.mode } else { None },"started_at":inner.started,
            "icmp_enabled":icmp_enabled,
            "iface":inner.pinned_iface,
            "last_stop":{"reason":inner.last_stop_reason,"at":inner.last_stop_at},
            "stats":stats,"error":inner.error,"logs":inner.logs.iter().cloned().collect::<Vec<_>>(),"demo":false,
            "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
                "admin":is_administrator(),"default_iface":route.as_ref().map(|r|r.interface.clone()),
                "default_iface_name":route.as_ref().map(|r|r.interface.clone())}})
    }
}
/// Resolve the explicit Wintun path for a Windows start.
///
/// A test host that is not Windows only compiles this function. The test
/// runtime ignores the path, but the path must still be absolute.
#[cfg(any(windows, test))]
fn windows_wintun_path(options: &TunOptions) -> io::Result<PathBuf> {
    if let Some(path) = &options.wintun_dll {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the wintun.dll path must be absolute",
            ));
        }
        #[cfg(windows)]
        crate::platform::valid_wintun_path(path)?;
        return Ok(path.clone());
    }
    #[cfg(windows)]
    {
        crate::platform::default_wintun_path()
    }
    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an explicit absolute wintun.dll path is required",
        ))
    }
}

/// Remove the routes, stop the relay, and close the adapter in that order.
///
/// Return true when route cleanup failed or left a record. The caller records
/// the error and blocks a later start.
#[cfg(any(windows, test))]
fn clean_windows_start(
    inner: &mut Inner,
    relay: Option<crate::relay::Relay>,
    mut routes: Option<Box<dyn WindowsRouteController>>,
    device: Option<Box<dyn WindowsWintunDevice>>,
) -> bool {
    let mut failed = false;
    if let Some(mut relay) = relay {
        relay.stop();
    }
    if let Some(routes) = routes.as_mut() {
        if routes.remove().is_err() || routes.has_routes() {
            failed = true;
        }
    }
    drop(routes);
    drop(device);
    if failed {
        inner.cleanup_blocked = true;
    }
    failed
}

/// The production Windows runtime. It uses Wintun and the native route
/// boundary. The Wintun DLL is loaded from the explicit path.
#[cfg(windows)]
struct SystemWindowsTunnelRuntime;

#[cfg(windows)]
struct SystemWintunDevice {
    tun: crate::platform::Utun,
}

#[cfg(windows)]
impl WindowsWintunDevice for SystemWintunDevice {
    fn ifname(&self) -> &str {
        self.tun.ifname()
    }

    fn ifindex(&self) -> u32 {
        self.tun.ifindex()
    }

    fn configure_link(&mut self, addr: Ipv4Addr, mtu: u32) -> io::Result<()> {
        crate::platform::configure_link(&self.tun, addr, mtu)
    }

    fn route_identity(&mut self) -> io::Result<crate::windows_native_routes::AdapterIdentity> {
        self.tun.native_route_identity()
    }

    fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        self.tun.read_packet()
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.tun.write_packet(packet)
    }

    fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        self.tun.wait_readable(timeout)
    }
}

#[cfg(windows)]
struct SystemWindowsRoutes {
    boundary: crate::windows_native_routes::RouteBoundary,
}

#[cfg(windows)]
impl WindowsRouteController for SystemWindowsRoutes {
    fn install(&mut self) -> io::Result<()> {
        self.boundary
            .install()
            .map_err(|failure| io::Error::other(failure.to_string()))
    }

    fn remove(&mut self) -> io::Result<()> {
        let report = self.boundary.remove();
        if report.is_complete() {
            Ok(())
        } else {
            let reason = report
                .stopped
                .as_ref()
                .map(|error| format!(": {error}"))
                .unwrap_or_default();
            Err(io::Error::other(format!(
                "route cleanup failed: {} route records remain{}",
                report.retained.len(),
                reason
            )))
        }
    }

    fn has_routes(&self) -> bool {
        self.boundary.has_routes()
    }
}

#[cfg(windows)]
impl WindowsTunnelRuntime for SystemWindowsTunnelRuntime {
    fn is_elevated(&self) -> bool {
        crate::platform::is_elevated()
    }

    fn load_wintun(&self, wintun_dll: &std::path::Path) -> io::Result<()> {
        crate::platform::load_wintun(wintun_dll)
    }

    fn check_phone(&self, phone: &phone::PhoneProxy, cancel: &AtomicBool) -> io::Result<()> {
        phone.check_cancellable(&normalization::Audit::default(), cancel)
    }

    fn open_device(
        &self,
        unit: u32,
        wintun_dll: &std::path::Path,
    ) -> io::Result<Box<dyn WindowsWintunDevice>> {
        let tun = crate::platform::Utun::open_with_dll(unit, wintun_dll)?;
        Ok(Box::new(SystemWintunDevice { tun }))
    }

    fn open_routes(
        &self,
        identity: crate::windows_native_routes::AdapterIdentity,
    ) -> io::Result<Box<dyn WindowsRouteController>> {
        let boundary = crate::windows_native_routes::RouteBoundary::open(
            identity,
            crate::windows_route_verify::Ipv6RoutePolicy::Forward,
        );
        Ok(Box::new(SystemWindowsRoutes { boundary }))
    }
}

#[cfg(windows)]
impl Service {
    /// Start the Windows tunnel in source device proxy mode.
    pub fn start_tun_options_cancellable(
        &self,
        options: TunOptions,
        phone: Option<phone::PhoneProxy>,
        workers: usize,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        self.start_windows_tunnel_with(options, phone, workers, cancel, &SystemWindowsTunnelRuntime)
    }
}

/// Return the default IPv4 route for the status shape. Read-only.
fn default_route_status() -> Option<crate::environment::DefaultRoute> {
    #[cfg(unix)]
    {
        environment::default_route().ok()
    }
    #[cfg(windows)]
    {
        let index = crate::platform::default_interface_index().ok()?;
        let name = normalization::interface_name(index).ok()?;
        Some(crate::environment::DefaultRoute {
            interface: name,
            gateway: None,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Return true when the process has administrator or root rights.
fn is_administrator() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::platform::is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop();
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tun_option_tests {
    use super::*;
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
    #[test]
    fn unsupported_platform_rejects_tunnel_start() {
        let service = Service::new();
        let error = service
            .start_tun_options_cancellable(TunOptions::default(), None, 1, &AtomicBool::new(false))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(service.status()["running"], false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_direct_mode_requires_pinning_routes_and_a_supported_ipv6_policy() {
        let cancel = AtomicBool::new(false);
        let mut options = TunOptions {
            no_pin: true,
            ..TunOptions::default()
        };
        let service = Service::new();
        let error = service
            .start_tun_options_cancellable(options, None, 1, &cancel)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(service.status()["running"], false);

        options = TunOptions {
            no_routes: true,
            ..TunOptions::default()
        };
        let error = service
            .start_tun_options_cancellable(options, None, 1, &cancel)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        options = TunOptions {
            ipv6: Ipv6Policy::Inherit,
            ..TunOptions::default()
        };
        let error = service
            .start_tun_options_cancellable(options, None, 1, &cancel)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(service.status()["running"], false);
    }
    #[test]
    fn failure_record_is_empty_without_a_tunnel() {
        let service = Service::new();
        assert!(!service.is_running());
        assert_eq!(service.failures(), crate::failures::empty_snapshot());
    }
    #[cfg(unix)]
    #[test]
    fn diagnostics_are_the_empty_shape_without_a_tunnel() {
        let service = Service::new();
        let value = service.diagnostics();
        assert_eq!(value, crate::diagnostics::empty());
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some(iface),
                Some(vec!["127.0.0.1:53".parse().unwrap()]),
            )
            .unwrap();
        assert!(service.is_running());
        // A SOCKS5 listener is not a tunnel. The relay metrics stay empty.
        assert_eq!(service.diagnostics(), crate::diagnostics::empty());
        service.stop();
        assert!(!service.is_running());
    }
    #[cfg(unix)]
    #[test]
    fn stopped_socks_listener_is_reaped_as_an_error() {
        let service = Service::new();
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some(iface),
                Some(vec!["127.0.0.1:53".parse().unwrap()]),
            )
            .unwrap();
        {
            let inner = service.inner.lock().unwrap();
            if let Some(Active::Socks { server, .. }) = &inner.active {
                server.end_listener_for_test();
            } else {
                panic!("SOCKS listener did not start");
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while service.is_running() {
            assert!(
                std::time::Instant::now() < deadline,
                "listener did not stop"
            );
            std::thread::yield_now();
        }
        let status = service.status();
        assert_eq!(status["running"], false);
        assert!(status["mode"].is_null());
        assert_eq!(status["error"], "The SOCKS5 listener stopped unexpectedly.");
        assert_eq!(service.failures(), crate::failures::empty_snapshot());
    }
    #[test]
    fn only_a_rejected_token_is_an_auth_start_error() {
        assert_eq!(
            auth_error_code(&phone::rejected_credentials_error()),
            "phone_auth"
        );
        assert_eq!(
            auth_error_code(&io::Error::from(io::ErrorKind::TimedOut)),
            "service_start"
        );
        assert_eq!(
            auth_error_code(&io::Error::from(io::ErrorKind::PermissionDenied)),
            "service_start"
        );
        assert_eq!(
            auth_error_code(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            "service_start"
        );
    }
    #[test]
    fn tcp_setup_timeout_status_is_numeric() {
        let stats = crate::relay::RelayStats {
            tcp_setup_timeout_phone_connect: 1,
            tcp_setup_timeout_phone_auth: 2,
            tcp_setup_timeout_phone_destination: 3,
            tcp_setup_timeout_direct_connect: 4,
            ..Default::default()
        };
        let value = tcp_setup_timeout_stats(&stats);
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        assert!(object.values().all(|v| v.is_u64()));
        assert_eq!(value["tcp_setup_timeout_phone_auth"], 2);
        assert_eq!(value["tcp_setup_timeout_phone_destination"], 3);
    }
    #[test]
    fn icmp_failure_status_has_numeric_counters_only() {
        let stats = crate::relay::RelayStats {
            icmp_setup_errors: 1,
            icmp_timeouts: 2,
            icmp_phone_no_cellular: 3,
            icmp_phone_busy: 4,
            icmp_phone_timeout: 5,
            icmp_phone_failed: 6,
            icmp_malformed: 7,
            icmp_payload_mismatch: 8,
            icmp_io_errors: 9,
            icmp_output_errors: 10,
            icmp_phone_path_no_update: 11,
            icmp_phone_path_unsatisfied: 12,
            icmp_phone_path_not_cellular: 13,
            icmp_phone_path_no_interface: 14,
            icmp_phone_path_ambiguous: 15,
            ..Default::default()
        };
        let value = icmp_failure_stats(&stats);
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 15);
        assert!(object.values().all(|v| v.is_u64()));
        assert_eq!(value["icmp_phone_failed"], 6);
        assert_eq!(value["icmp_timeouts"], 2);
        assert_eq!(value["icmp_phone_path_no_interface"], 14);
        assert_eq!(value["icmp_phone_path_ambiguous"], 15);
    }
    #[test]
    fn direct_modes_and_phone_restrictions_are_checked_before_setup() {
        let mut options = TunOptions::default();
        assert!(options.validate(false, 2).is_ok());
        options.no_routes = true;
        options.no_pin = true;
        options.ipv6 = Ipv6Policy::Inherit;
        options.dns_upstream = Some("1.1.1.1:53".parse().unwrap());
        assert!(options.validate(false, 2).is_ok());
        assert!(options.validate(true, 2).is_err());
        options = TunOptions {
            ipv6: Ipv6Policy::Forward,
            ..TunOptions::default()
        };
        assert!(options.validate(true, 2).is_ok());
        options.no_routes = true;
        assert!(options.validate(true, 2).is_err());
        assert!(options.validate(false, 2).is_err());
    }
    #[test]
    fn invalid_values_fail_before_device_creation() {
        let mut options = TunOptions {
            unit: 256,
            ..TunOptions::default()
        };
        assert!(options.validate(false, 2).is_err());
        options.unit = 0;
        options.addr = "198.18.0.0".parse().unwrap();
        assert!(options.validate(false, 2).is_err());
        options.addr = "198.18.0.1".parse().unwrap();
        options.dns_upstream = Some("[::1]:53".parse().unwrap());
        assert!(options.validate(false, 2).is_err());
        assert!(TunOptions::default().validate(false, 0).is_err());
    }
    #[test]
    fn experimental_icmp_requires_explicit_phone_mode() {
        let mut options = TunOptions::default();
        assert!(!options.icmp_phone);
        assert!(!options.icmp_persistent);
        options.icmp_persistent = true;
        assert!(options.validate(true, 2).is_err());
        options.icmp_phone = true;
        assert!(options.validate(false, 2).is_err());
        options.ipv6 = Ipv6Policy::Forward;
        assert!(options.validate(true, 2).is_ok());
        options.no_pin = true;
        assert!(options.validate(true, 2).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn cancelled_start_returns_before_device_or_route_setup() {
        let service = Service::new();
        let cancelled = AtomicBool::new(true);
        let options = TunOptions {
            ipv6: Ipv6Policy::Forward,
            ..TunOptions::default()
        };
        let phone = phone::PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "hotspotshade".into(),
            token: "test".into(),
            iface: None,
            timeout: Duration::from_secs(1),
        };
        let error = service
            .start_tun_options_cancellable(options, Some(phone), 2, &cancelled)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(service.status()["running"], false);
    }
    #[test]
    fn outer_index_must_match_the_frozen_pin() {
        assert!(Service::verify_outer_index(9, 9).is_ok());
        let error = Service::verify_outer_index(9, 10).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "outer_interface_changed");
    }
    #[test]
    fn lifecycle_logs_are_bounded_and_keep_sequence() {
        let service = Service::new();
        let mut inner = service.inner.lock().unwrap();
        for _ in 0..300 {
            inner.log("info", "Service started.");
        }
        assert_eq!(inner.logs.len(), 256);
        assert_eq!(inner.logs.front().unwrap()["seq"], 45);
        assert_eq!(inner.logs.back().unwrap()["seq"], 300);
    }
    #[cfg(unix)]
    #[test]
    fn local_socks_start_and_stop_appear_in_status() {
        let service = Service::new();
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some(iface),
                Some(vec!["127.0.0.1:53".parse().unwrap()]),
            )
            .unwrap();
        let status = service.status();
        assert_eq!(status["logs"][0]["msg"], "SOCKS5 proxy started.");
        // The status names the interface that the service actually pinned.
        assert_eq!(status["iface"], iface);
        service.stop();
        let status = service.status();
        assert_eq!(status["logs"][1]["msg"], "Service stopped.");
        assert_eq!(status["iface"], Value::Null);
    }

    #[cfg(unix)]
    #[test]
    fn status_reports_ping_only_for_a_running_phone_tunnel() {
        let service = Service::new();
        assert_eq!(service.status()["icmp_enabled"], false);
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some(iface),
                Some(vec!["127.0.0.1:53".parse().unwrap()]),
            )
            .unwrap();
        // A direct mode never reports the phone echo relay.
        assert_eq!(service.status()["icmp_enabled"], false);
        {
            let mut inner = service.inner.lock().unwrap();
            inner.mode = Some("phone");
            inner.icmp_enabled = true;
        }
        assert_eq!(service.status()["icmp_enabled"], true);
        service.inner.lock().unwrap().icmp_enabled = false;
        assert_eq!(service.status()["icmp_enabled"], false);
        service.stop();
        assert_eq!(service.status()["icmp_enabled"], false);
    }

    /// The recorded side effects of the fake Windows runtime. It owns no
    /// adapter, route, or outer socket.
    #[cfg(any(windows, test))]
    #[derive(Default)]
    struct FakeWindowsState {
        events: Mutex<Vec<&'static str>>,
        route_records: Mutex<usize>,
        device_drops: std::sync::atomic::AtomicUsize,
        link_address: Mutex<Option<Ipv4Addr>>,
    }

    #[cfg(any(windows, test))]
    impl FakeWindowsState {
        fn record(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }

        fn count(&self, event: &'static str) -> usize {
            self.events()
                .iter()
                .filter(|value| **value == event)
                .count()
        }

        fn records(&self) -> usize {
            *self.route_records.lock().unwrap()
        }
    }

    #[cfg(any(windows, test))]
    fn fake_route_identity() -> crate::windows_native_routes::AdapterIdentity {
        crate::windows_native_routes::AdapterIdentity::new(
            0x0000_6000_0000_0007,
            crate::windows_native_routes::AdapterGuid::new(
                0x1122_3344,
                0x5566,
                0x7788,
                [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00],
            ),
        )
        .unwrap()
    }

    #[cfg(any(windows, test))]
    struct FakeWindowsDevice {
        state: Arc<FakeWindowsState>,
    }

    #[cfg(any(windows, test))]
    impl Drop for FakeWindowsDevice {
        fn drop(&mut self) {
            self.state.device_drops.fetch_add(1, Ordering::AcqRel);
            self.state.record("device_drop");
        }
    }

    #[cfg(any(windows, test))]
    impl WindowsWintunDevice for FakeWindowsDevice {
        fn ifname(&self) -> &str {
            "HotspotShade-Tunnel-7"
        }

        fn ifindex(&self) -> u32 {
            1
        }

        fn configure_link(&mut self, addr: Ipv4Addr, _mtu: u32) -> io::Result<()> {
            *self.state.link_address.lock().unwrap() = Some(addr);
            self.state.record("device_configure");
            Ok(())
        }

        fn route_identity(&mut self) -> io::Result<crate::windows_native_routes::AdapterIdentity> {
            self.state.record("device_identity");
            Ok(fake_route_identity())
        }

        fn read_packet(&mut self) -> io::Result<Vec<u8>> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
            Ok(packet.len())
        }

        fn wait_readable(&self, _timeout: Duration) -> io::Result<bool> {
            std::thread::sleep(Duration::from_millis(2));
            Ok(false)
        }
    }

    #[cfg(any(windows, test))]
    struct FakeWindowsRoutes {
        state: Arc<FakeWindowsState>,
        install_error_after: Option<usize>,
        remove_error: bool,
    }

    #[cfg(any(windows, test))]
    impl WindowsRouteController for FakeWindowsRoutes {
        fn install(&mut self) -> io::Result<()> {
            if let Some(after) = self.install_error_after {
                *self.state.route_records.lock().unwrap() = after;
                self.state.record("routes_install_partial");
                return Err(io::Error::other("route install failed"));
            }
            *self.state.route_records.lock().unwrap() = 3;
            self.state.record("routes_install");
            Ok(())
        }

        fn remove(&mut self) -> io::Result<()> {
            self.state.record("routes_remove");
            if self.remove_error {
                return Err(io::Error::other("route cleanup failed"));
            }
            *self.state.route_records.lock().unwrap() = 0;
            Ok(())
        }

        fn has_routes(&self) -> bool {
            self.state.records() > 0
        }
    }

    #[cfg(any(windows, test))]
    struct FakeWindowsRuntime {
        state: Arc<FakeWindowsState>,
        elevated: bool,
        device_error: Option<(io::ErrorKind, &'static str)>,
        install_error_after: Option<usize>,
        remove_error: bool,
    }

    #[cfg(any(windows, test))]
    impl FakeWindowsRuntime {
        fn new(state: Arc<FakeWindowsState>) -> Self {
            Self {
                state,
                elevated: true,
                device_error: None,
                install_error_after: None,
                remove_error: false,
            }
        }
    }

    #[cfg(any(windows, test))]
    impl WindowsTunnelRuntime for FakeWindowsRuntime {
        fn is_elevated(&self) -> bool {
            self.elevated
        }

        fn load_wintun(&self, _wintun_dll: &std::path::Path) -> io::Result<()> {
            self.state.record("wintun_load");
            if let Some((kind, message)) = self.device_error {
                return Err(io::Error::new(kind, message));
            }
            Ok(())
        }

        fn check_phone(&self, _phone: &phone::PhoneProxy, _cancel: &AtomicBool) -> io::Result<()> {
            self.state.record("phone_check");
            Ok(())
        }

        fn open_device(
            &self,
            _unit: u32,
            _wintun_dll: &std::path::Path,
        ) -> io::Result<Box<dyn WindowsWintunDevice>> {
            self.state.record("device_open");
            Ok(Box::new(FakeWindowsDevice {
                state: self.state.clone(),
            }))
        }

        fn open_routes(
            &self,
            _identity: crate::windows_native_routes::AdapterIdentity,
        ) -> io::Result<Box<dyn WindowsRouteController>> {
            self.state.record("routes_open");
            Ok(Box::new(FakeWindowsRoutes {
                state: self.state.clone(),
                install_error_after: self.install_error_after,
                remove_error: self.remove_error,
            }))
        }
    }

    #[cfg(any(windows, test))]
    fn fake_windows_options() -> TunOptions {
        TunOptions {
            unit: 7,
            iface: Some("1".into()),
            ipv6: Ipv6Policy::Forward,
            wintun_dll: Some(std::env::temp_dir().join("wintun.dll")),
            ..TunOptions::default()
        }
    }

    #[cfg(any(windows, test))]
    fn fake_phone() -> phone::PhoneProxy {
        phone::PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "hotspotshade".into(),
            token: "test-only".into(),
            iface: None,
            timeout: Duration::from_secs(1),
        }
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_start_and_stop_are_idempotent() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime::new(state.clone());
        let service = Service::new();
        service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap();
        let status = service.status();
        assert_eq!(status["running"], true);
        assert_eq!(status["mode"], "phone");
        assert_eq!(service.status()["iface"], "1");
        service.stop();
        assert!(!service.is_running());
        service.stop();
        assert!(!service.is_running());
        assert_eq!(state.count("routes_install"), 1);
        assert_eq!(state.count("routes_remove"), 1);
        assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
        assert_eq!(state.count("phone_check"), 1);
        assert_eq!(state.records(), 0);
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_failed_route_install_removes_the_partial_routes() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime {
            state: state.clone(),
            elevated: true,
            device_error: None,
            install_error_after: Some(2),
            remove_error: false,
        };
        let service = Service::new();
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "route_setup");
        assert_eq!(service.status()["running"], false);
        assert_eq!(state.count("routes_install_partial"), 1);
        assert_eq!(state.count("routes_remove"), 1);
        assert_eq!(state.records(), 0);
        assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
        // A complete rollback does not block a later start.
        assert_eq!(service.status()["error"], Value::Null);
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_drop_removes_routes_and_closes_the_device() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime::new(state.clone());
        let service = Service::new();
        service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap();
        drop(service);
        assert_eq!(state.count("routes_remove"), 1);
        assert_eq!(state.records(), 0);
        assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_missing_wintun_dll_is_a_plain_error() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime {
            state: state.clone(),
            elevated: true,
            device_error: Some((
                io::ErrorKind::NotFound,
                "cannot load C:\\tools\\wintun.dll: the file is missing",
            )),
            install_error_after: None,
            remove_error: false,
        };
        let service = Service::new();
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("wintun.dll"), "{error}");
        assert_eq!(state.count("wintun_load"), 1);
        assert_eq!(state.count("phone_check"), 0);
        assert_eq!(state.count("device_open"), 0);
        assert_eq!(state.count("routes_open"), 0);
        assert_eq!(state.count("routes_remove"), 0);
        assert_eq!(service.status()["running"], false);
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_direct_mode_is_refused_before_device_setup() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime::new(state.clone());
        let service = Service::new();
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                None,
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(state.count("device_open"), 0);
        assert!(!service.is_running());
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_requires_administrator_rights_before_device_setup() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime {
            state: state.clone(),
            elevated: false,
            device_error: None,
            install_error_after: None,
            remove_error: false,
        };
        let service = Service::new();
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(state.count("phone_check"), 0);
        assert_eq!(state.count("device_open"), 0);
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_tunnel_cleanup_failure_blocks_a_restart() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime {
            state: state.clone(),
            elevated: true,
            device_error: None,
            install_error_after: Some(1),
            remove_error: true,
        };
        let service = Service::new();
        let _ = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(service.status()["running"], false);
        assert!(service.status()["error"].as_str().is_some());
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "route cleanup failed; inspect routes before restarting"
        );
        assert_eq!(state.count("device_open"), 1);
    }
}
