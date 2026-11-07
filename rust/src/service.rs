//! Service lifecycle for the Rust backend.
use crate::{diagnostics, failures, normalization, phone};
#[cfg(unix)]
use crate::{dns, environment, socks};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io;
#[cfg(any(windows, test))]
use std::net::{IpAddr, Ipv6Addr};
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(any(windows, test))]
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Recheck retained outer-interface evidence on both sides of a startup step.
// The step may itself mutate state, so its caller still owns rollback on error.
#[cfg(any(target_os = "linux", test))]
fn linux_checked_step<T>(
    mut recheck: impl FnMut() -> io::Result<()>,
    step: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    recheck()?;
    let value = step()?;
    recheck()?;
    Ok(value)
}

#[cfg(any(target_os = "linux", test))]
fn linux_cleanup_start(
    remove_routes: impl FnOnce() -> bool,
    remove_link: impl FnOnce() -> bool,
) -> bool {
    // Always attempt both, even if route cleanup fails.
    let routes_failed = remove_routes();
    let link_failed = remove_link();
    routes_failed || link_failed
}

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

/// The diagnostics sections that a running relay replaces. Every other key
/// keeps the empty shape. The destination-privacy section carries its own mode
/// name, so the relay replaces the whole object and not only the counters.
const RELAY_DIAGNOSTIC_SECTIONS: [&str; 6] = [
    "setup",
    "dns",
    "queues",
    "udp",
    "tcp",
    "destination_privacy",
];

/// Copy the running relay metrics into the empty diagnostics shape.
fn merge_relay_diagnostics(value: &mut Value, metrics: &Value) {
    if let Some(map) = value.as_object_mut() {
        for key in RELAY_DIAGNOSTIC_SECTIONS {
            if let Some(section) = metrics.get(key) {
                map.insert(key.into(), section.clone());
            }
        }
    }
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
        if let Some(upstream) = self.dns_upstream {
            crate::dns::validate_upstream(upstream)?;
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
    /// Set when a direct start record was left behind by this service. A
    /// direct start writes the helper's `engine-session` record; if the start
    /// fails before it can remove the record, the exit path must report the
    /// same uncertainty as a route cleanup failure. The file itself blocks the
    /// next start. The flag is per service instance.
    direct_record_uncertain: Arc<AtomicBool>,
    /// True while a phone tunnel runs with the echo relay on.
    icmp_enabled: bool,
    /// The worker count of the running tunnel. macOS, Linux, and Windows run a
    /// tunnel.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    workers: usize,
    /// The physical interface name that the running tunnel pins to. None when
    /// no tunnel runs, or when the run is explicitly unpinned for diagnostics.
    pinned_iface: Option<String>,
    /// The token gate binding of the last Windows source device start: the
    /// tunnel adapter, the physical adapter that the start gate proved, the
    /// destination, and the pinned index. It is read only while that run is
    /// active, so a stale value after a stop is never used.
    #[cfg(any(windows, test))]
    windows_run: Option<WindowsPhoneRun>,
    /// The reason for the most recent automatic stop. It stays until the next
    /// successful start.
    last_stop_reason: Option<&'static str>,
    /// The time of the most recent automatic stop, in Unix seconds.
    last_stop_at: Option<u64>,
    logs: VecDeque<Value>,
    next_log_seq: u64,
}
impl Inner {
    /// True when the last cleanup could not be proved.
    ///
    /// A route, address, or device cleanup failure sets `cleanup_blocked`.
    /// A macOS direct start also sets `direct_record_uncertain` when its
    /// `engine-session` record could not be removed, including the case where
    /// the unlink succeeded but the directory sync failed. That flag is sticky
    /// for the life of the service, so every start gate must treat it like
    /// `cleanup_blocked` and refuse the next start.
    fn cleanup_uncertain(&self) -> bool {
        self.cleanup_blocked || self.direct_record_uncertain.load(Ordering::Acquire)
    }

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
    /// Run the token gate, then check the source device with the token.
    /// Return the physical adapter that the gate proved.
    fn check_phone(
        &self,
        phone: &phone::PhoneProxy,
        cancel: &AtomicBool,
    ) -> io::Result<crate::windows_route_verify::RetainedAdapterIdentity>;
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

/// The evidence that a Windows outer adapter is the physical hotspot link.
///
/// A direct start pins every outer socket to this adapter while the Wintun
/// routes send internet traffic to the tunnel adapter. The proof records the
/// adapter identity, its on-link IPv4 subnet, an optional set of on-link IPv6
/// subnets, and the outer-socket read-back that the start requires.
/// Construction rejects a value that does not meet the policy, so a caller
/// cannot pass a partial proof.
///
/// This type is a test seam and a contract for the future production reader.
/// The real Windows direct start stays behind
/// [`require_windows_direct_evidence`], so no live code builds this proof yet.
/// The direct link observer binds the exact retained index, LUID, and GUID from
/// this proof. It never resolves the alias again. The relay pins the index that
/// this proof records, so the direct worker stops when a later sample reports a
/// different live index. Detection is periodic and can miss a transient change.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WindowsOuterAdapterProof {
    ifname: String,
    ifindex: u32,
    adapter: crate::windows_route_verify::RetainedAdapterIdentity,
    local_subnet: crate::windows_route_verify::ProvenLocalSubnet,
    ipv6_local_subnets: Vec<crate::windows_route_verify::ProvenLocalSubnet>,
    hardware_interface: bool,
    tunnel_type_clear: bool,
    media_connected: bool,
    outer_ttl: i32,
    pinned_index: u32,
    observed_egress_index: u32,
    ttl_audit_bad: u64,
}

/// True for a Windows interface alias that is safe to pass to the retained
/// link observer.
///
/// A Windows alias can contain spaces, as in `Ethernet 2`. The check allows
/// the characters that `netsh` and the interface manager accept in this
/// program's own names, and it rejects control characters, path separators,
/// leading or trailing spaces, and the tunnel prefixes that
/// [`Service::check_physical_interface_name`] names. The check does not prove
/// that the adapter is physical.
#[cfg(any(windows, test))]
fn valid_windows_outer_alias(name: &str) -> bool {
    let length = name.chars().count();
    length > 0
        && length <= 127
        && name != "."
        && name != ".."
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
}

#[cfg(any(windows, test))]
impl WindowsOuterAdapterProof {
    /// Build a proof from one complete observation.
    ///
    /// Every field must agree. A TTL other than 65, a pin or observed egress
    /// index that differs from the adapter index, a nonzero TTL audit failure
    /// count, an unsafe or tunnel-shaped alias, or a local subnet on another
    /// adapter is an error. There is no partial success. The alias check keeps
    /// shell-shaped and tunnel names out of the link observer target; it is
    /// not evidence that the adapter is physical. The hardware and tunnel
    /// flags are the physical evidence.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ifname: &str,
        ifindex: u32,
        adapter: crate::windows_route_verify::RetainedAdapterIdentity,
        local_subnet: crate::windows_route_verify::ProvenLocalSubnet,
        hardware_interface: bool,
        tunnel_type_clear: bool,
        media_connected: bool,
        outer_ttl: i32,
        pinned_index: u32,
        observed_egress_index: u32,
        ttl_audit_bad: u64,
    ) -> io::Result<Self> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
        if ifindex == 0 || adapter.interface_index() != ifindex {
            return Err(invalid("outer_adapter_unverified"));
        }
        if !valid_windows_outer_alias(ifname)
            || Service::check_physical_interface_name(ifname).is_err()
        {
            return Err(invalid("outer_adapter_unverified"));
        }
        if !hardware_interface || !tunnel_type_clear || !media_connected {
            return Err(invalid("outer_adapter_unverified"));
        }
        if outer_ttl != normalization::OUTER_TTL
            || pinned_index != ifindex
            || observed_egress_index != ifindex
            || ttl_audit_bad != 0
        {
            return Err(invalid("outer_adapter_unverified"));
        }
        if local_subnet.adapter() != adapter
            || local_subnet.provenance()
                != crate::windows_route_verify::LocalSubnetProvenance::LocalInterface
            || !matches!(local_subnet.prefix().address, IpAddr::V4(_))
        {
            return Err(invalid("outer_adapter_unverified"));
        }
        Ok(Self {
            ifname: ifname.to_owned(),
            ifindex,
            adapter,
            local_subnet,
            ipv6_local_subnets: Vec::new(),
            hardware_interface,
            tunnel_type_clear,
            media_connected,
            outer_ttl,
            pinned_index,
            observed_egress_index,
            ttl_audit_bad,
        })
    }

    /// Add one proven on-link IPv6 subnet for the same physical adapter.
    ///
    /// The caller must read the prefix from the physical adapter and retain the
    /// same index, LUID, and GUID as this proof. The prefix must be inside
    /// `2000::/3` and at least as specific as `/64`. That is the only IPv6
    /// block that the direct route plan manages. A
    /// prefix outside that block cannot cover a managed route, so accepting it
    /// would only make the proof look stronger than it is. This value is an
    /// assertion about the adapter, not a measurement. The live route verifier
    /// confirms the retained adapter identity before and after the route reads.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_ipv6_local_subnet(
        mut self,
        subnet: crate::windows_route_verify::ProvenLocalSubnet,
    ) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "outer_adapter_unverified");
        if subnet.adapter() != self.adapter
            || subnet.provenance()
                != crate::windows_route_verify::LocalSubnetProvenance::LocalInterface
            || !matches!(subnet.prefix().address, IpAddr::V6(_))
            || subnet.prefix().length < crate::windows_route_verify::MIN_LOCAL_IPV6_LENGTH
            || !crate::windows_route_verify::IPV6_TUNNEL_ROUTE.contains(subnet.prefix().address)
        {
            return Err(invalid());
        }
        self.ipv6_local_subnets.push(subnet);
        Ok(self)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn ifindex(&self) -> u32 {
        self.ifindex
    }

    fn adapter(&self) -> crate::windows_route_verify::RetainedAdapterIdentity {
        self.adapter
    }

    fn local_subnet(&self) -> crate::windows_route_verify::ProvenLocalSubnet {
        self.local_subnet
    }

    fn ipv6_local_subnets(&self) -> &[crate::windows_route_verify::ProvenLocalSubnet] {
        &self.ipv6_local_subnets
    }
}

/// The route policy and retained identities that a direct route check proves.
///
/// The tunnel adapter and the outer physical adapter must not share an index,
/// a LUID, or a GUID. The context carries the proven local hotspot subnets so a
/// more-specific route on that physical adapter is expected, and it carries
/// the exact IPv6 policy that the route boundary installed.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WindowsDirectRouteContext {
    tunnel: crate::windows_route_verify::TunnelIdentity,
    tunnel_adapter: crate::windows_native_routes::AdapterIdentity,
    tunnel_retained: crate::windows_route_verify::RetainedAdapterIdentity,
    policy: crate::windows_route_verify::Ipv6RoutePolicy,
    outer: WindowsOuterAdapterProof,
}

#[cfg(any(windows, test))]
impl WindowsDirectRouteContext {
    fn new(
        tunnel_index: u32,
        tunnel_adapter: crate::windows_native_routes::AdapterIdentity,
        policy: crate::windows_route_verify::Ipv6RoutePolicy,
        outer: WindowsOuterAdapterProof,
    ) -> io::Result<Self> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
        if !policy.is_managed() {
            return Err(invalid("route_policy_unverified"));
        }
        let tunnel =
            crate::windows_route_verify::TunnelIdentity::new(tunnel_index, tunnel_adapter.luid())
                .map_err(|_| invalid("tunnel_identity_invalid"))?;
        let tunnel_retained = crate::windows_route_verify::RetainedAdapterIdentity::new(
            tunnel_index,
            tunnel_adapter.luid(),
            tunnel_adapter.guid().route_verify_guid(),
        )
        .map_err(|_| invalid("tunnel_identity_invalid"))?;
        let outer_adapter = outer.adapter();
        if outer_adapter.interface_index() == tunnel.interface_index
            || outer_adapter.interface_luid() == tunnel.interface_luid
            || outer_adapter.interface_guid() == tunnel_retained.interface_guid()
        {
            return Err(invalid("tunnel_identity_conflict"));
        }
        Ok(Self {
            tunnel,
            tunnel_adapter,
            tunnel_retained,
            policy,
            outer,
        })
    }

    fn tunnel(&self) -> crate::windows_route_verify::TunnelIdentity {
        self.tunnel
    }

    fn tunnel_adapter(&self) -> crate::windows_native_routes::AdapterIdentity {
        self.tunnel_adapter
    }

    fn tunnel_retained(&self) -> crate::windows_route_verify::RetainedAdapterIdentity {
        self.tunnel_retained
    }

    fn policy(&self) -> crate::windows_route_verify::Ipv6RoutePolicy {
        self.policy
    }

    fn outer(&self) -> &WindowsOuterAdapterProof {
        &self.outer
    }
}

/// One direct-mode outer link sample with the live index of the retained
/// adapter.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsDirectLinkSample {
    /// True for a conclusive up link and false for a conclusive down link.
    up: bool,
    /// The live index for the retained adapter, or `None` when it is gone.
    interface_index: Option<u32>,
}

/// What one direct link sample means for the start pin.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsDirectLinkDecision {
    /// The sample proves the pinned index still names the retained adapter.
    Link { up: bool },
    /// The pin no longer names the retained adapter. The relay is pinned to
    /// this index, so continuing could send outer traffic through another
    /// adapter. Stop on the first sample that proves the mismatch.
    StalePin,
}

/// Compare one link sample with the index that the relay pinned at start.
///
/// A retained observer follows the adapter LUID and GUID, so it can report an
/// up link after Windows moves that adapter to a new index. The relay did not
/// follow the move; its outer sockets still use the start index. Any sample
/// that does not prove the same index is a stale pin. This includes a removed
/// adapter, because Windows can reuse the old index for another adapter.
#[cfg(any(windows, test))]
fn classify_windows_direct_link(
    sample: WindowsDirectLinkSample,
    pinned_index: u32,
) -> WindowsDirectLinkDecision {
    match sample.interface_index {
        Some(index) if index == pinned_index => WindowsDirectLinkDecision::Link { up: sample.up },
        _ => WindowsDirectLinkDecision::StalePin,
    }
}

/// One direct-mode outer link observation behind a test seam.
#[cfg(any(windows, test))]
trait WindowsDirectLinkObserver: Send {
    /// Return the live index and link state. An inconclusive read is an error,
    /// which is unknown, not loss.
    fn observe(&self) -> io::Result<WindowsDirectLinkSample>;
}

/// One direct-mode route controller behind a test seam.
///
/// The controller installs and removes the same route plan as the phone path,
/// but it must also prove the installed plan before the relay starts. A fake
/// controller changes no route.
#[cfg(any(windows, test))]
trait WindowsDirectRouteController: Send {
    fn install(&mut self) -> io::Result<()>;
    /// Prove the exact IPv4 `/1` routes, the IPv6 policy, and the expected
    /// ownership. A failure or an unproven-route warning must stop the start
    /// before the relay exists.
    fn verify(&mut self, context: &WindowsDirectRouteContext) -> io::Result<()>;
    fn remove(&mut self) -> io::Result<()>;
    fn has_routes(&self) -> bool;
}

/// The relay surface that the direct worker uses.
///
/// The production adapter wraps [`crate::relay::Relay`]. A test adapter returns
/// fixed counters and creates no socket.
#[cfg(any(windows, test))]
trait WindowsDirectRelay: Send {
    fn is_running(&self) -> bool;
    fn dispatch(&self, packet: Vec<u8>) -> io::Result<()>;
    fn try_receive(&self) -> Option<Vec<u8>>;
    fn stop(&mut self);
    fn stats(&self) -> crate::relay::RelayStats;
    fn diagnostics(&self) -> Value;
}

/// The direct-mode factories. It has no source device check and no token
/// accessor by design, so a direct start cannot read a source token.
#[cfg(any(windows, test))]
trait WindowsDirectTunnelRuntime: Send + Sync {
    fn is_elevated(&self) -> bool;
    /// Load the Wintun exports without creating an adapter or a route.
    fn load_wintun(&self, wintun_dll: &std::path::Path) -> io::Result<()>;
    /// Prove the physical outer adapter before any route change.
    fn prove_outer_adapter(
        &self,
        ifname: &str,
        ifindex: u32,
    ) -> io::Result<WindowsOuterAdapterProof>;
    fn open_device(
        &self,
        unit: u32,
        wintun_dll: &std::path::Path,
    ) -> io::Result<Box<dyn WindowsWintunDevice>>;
    fn open_routes(
        &self,
        context: WindowsDirectRouteContext,
    ) -> io::Result<Box<dyn WindowsDirectRouteController>>;
    /// Bind one link observer to the exact retained index, LUID, and GUID in
    /// the proof. The binding rechecks the live identity once and fails closed
    /// on a mismatch. It must not resolve the alias again.
    fn bind_link_observer(
        &self,
        proof: &WindowsOuterAdapterProof,
    ) -> io::Result<Box<dyn WindowsDirectLinkObserver>>;
    fn start_relay(
        &self,
        config: &crate::relay::RelayConfig,
    ) -> io::Result<Box<dyn WindowsDirectRelay>>;
    /// The worker link-check period. Tests use a short value.
    fn link_poll_interval(&self) -> Duration {
        Duration::from_secs(2)
    }
    /// The continuous-loss limit. Tests use a short value.
    fn link_down_limit(&self) -> Duration {
        crate::autostop::LINK_DOWN_LIMIT
    }
}

/// The resources that one direct worker owns.
#[cfg(any(windows, test))]
struct WindowsDirectWorkerResources {
    device: Box<dyn WindowsWintunDevice>,
    relay: Box<dyn WindowsDirectRelay>,
    routes: Box<dyn WindowsDirectRouteController>,
    link: Box<dyn WindowsDirectLinkObserver>,
    /// The outer index that the relay pinned for every outer socket.
    pinned_index: u32,
    link_poll_interval: Duration,
    link_down_limit: Duration,
}

/// The fixed message for the Windows direct-mode evidence gate.
///
/// Direct mode changes the default route shape while the outer sockets stay
/// pinned to the physical hotspot adapter. Windows direct mode stays closed
/// until a Windows VM records that a physical adapter pin still egresses the
/// physical adapter while the Wintun `/1` and `2000::/3` routes are installed,
/// and an independent review accepts that evidence.
#[cfg(any(windows, test))]
pub(crate) const WINDOWS_DIRECT_EVIDENCE_REQUIRED: &str =
    "Windows direct mode is disabled: physical adapter pin and Wintun route evidence from a Windows VM and an independent review are required";

/// Refuse the real Windows direct start until the evidence gate opens.
///
/// The fake-backed lifecycle is a test seam. It creates no adapter and changes
/// no route. This function is the only entry to the production direct runtime.
#[cfg(any(windows, test))]
pub(crate) fn require_windows_direct_evidence() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        WINDOWS_DIRECT_EVIDENCE_REQUIRED,
    ))
}

/// IPv4 scopes that are local to the machine or link and cannot carry global
/// internet unicast.
///
/// A normal Windows host keeps loopback, link-local, multicast, and broadcast
/// routes. A route for one of these prefixes cannot carry internet traffic, so
/// it cannot bypass the tunnel for the traffic that the tunnel carries. The
/// route scan still records the warning. The direct gate accepts only this
/// narrow set; every other warning keeps the strict failure.
#[cfg(any(windows, test))]
const DIRECT_LOCAL_SCOPE_V4: [crate::windows_route_verify::RoutePrefix; 4] = [
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        length: 8,
    },
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        length: 16,
    },
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        length: 4,
    },
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        length: 32,
    },
];

/// IPv6 scopes that are local to the machine or link.
///
/// These are outside the managed `2000::/3` route, so the scan does not report
/// them today. The list stays explicit so a future scan change cannot turn a
/// loopback, link-local, or multicast route into a failure or a blanket
/// allowance.
#[cfg(any(windows, test))]
const DIRECT_LOCAL_SCOPE_V6: [crate::windows_route_verify::RoutePrefix; 3] = [
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::LOCALHOST),
        length: 128,
    },
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        length: 10,
    },
    crate::windows_route_verify::RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
        length: 8,
    },
];

#[cfg(any(windows, test))]
fn prefix_within(
    prefix: crate::windows_route_verify::RoutePrefix,
    block: crate::windows_route_verify::RoutePrefix,
) -> bool {
    match (prefix.address, block.address) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            prefix.length >= block.length && block.contains(prefix.address)
        }
        _ => false,
    }
}

/// True when a warning prefix is wholly inside one local-only scope.
///
/// A broader prefix that spans a local scope and a public range is not local.
/// The prefix-length check keeps it out.
#[cfg(any(windows, test))]
fn direct_local_scope(prefix: crate::windows_route_verify::RoutePrefix) -> bool {
    let blocks: &[crate::windows_route_verify::RoutePrefix] = match prefix.address {
        IpAddr::V4(_) => &DIRECT_LOCAL_SCOPE_V4,
        IpAddr::V6(_) => &DIRECT_LOCAL_SCOPE_V6,
    };
    blocks.iter().any(|block| prefix_within(prefix, *block))
}

/// True when a warning is an expected local-only route.
///
/// The reason check keeps a future warning kind from becoming an allowance
/// only because its prefix happens to be local.
#[cfg(any(windows, test))]
fn expected_direct_warning(warning: &crate::windows_route_verify::RouteWarning) -> bool {
    warning.reason == crate::windows_route_verify::RouteWarningReason::NonInternetRange
        && warning.prefix.is_valid()
        && direct_local_scope(warning.prefix)
}

/// Refuse a route proof with any warning that is not a local-only scope.
///
/// The Windows direct start uses this strict gate. A normal host has loopback,
/// link-local, multicast, and broadcast routes; those prefixes cannot carry
/// global internet unicast, so they do not bypass the tunnel for its traffic.
/// The proof still records them. Every other warning means the route scan did
/// not prove that route, so the start stops before the relay exists. The
/// message holds the unproven warning count, the first prefix, and its
/// interface index. This policy stays inside the closed direct gate.
#[cfg(any(windows, test))]
fn require_direct_route_proof(proof: &crate::windows_route_verify::RouteProof) -> io::Result<()> {
    let mut rejected = proof
        .warnings
        .iter()
        .filter(|warning| !expected_direct_warning(warning));
    let Some(first) = rejected.next() else {
        return Ok(());
    };
    let count = 1 + rejected.count();
    Err(io::Error::other(format!(
        "route verification failed: {count} unproven route warning(s), starting with {} on interface {}",
        first.prefix,
        first.interface_index
    )))
}

/// The token gate binding of one running Windows source device tunnel.
///
/// The start records it under the service lock when the run becomes active.
/// A later token gate during the run needs the same tunnel adapter, the same
/// physical adapter, and the same destination and pinned index.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsPhoneRun {
    pub run: crate::windows_physical_path::TokenRun,
    pub destination: SocketAddr,
    pub iface: u32,
}

/// Refuse a Windows start whose mode gate is still closed.
///
/// Direct mode stays behind the closed physical adapter evidence gate.
/// Source device proxy mode passes here: its gate needs the destination and
/// the pinned interface, so it runs at the token use itself, in the runtime
/// source device check right before the token leaves the process. The two
/// guards are separate, so a direct start never calls the token gate.
#[cfg(any(windows, test))]
fn require_windows_start_gate(phone_present: bool) -> io::Result<()> {
    if phone_present {
        Ok(())
    } else {
        require_windows_direct_evidence()
    }
}

/// The fixed message for a stop whose cleanup may have left routes or a
/// device behind. It holds no path, address, token, or key.
pub const CLEANUP_UNCERTAIN_MESSAGE: &str =
    "Tunnel cleanup did not finish. Inspect routes, devices, and the start record before restarting.";

/// The fixed refusal for a start after a panic poisoned the shared state.
///
/// A panic can interrupt a start or a cleanup while it holds the service
/// mutex. The partial state is not proof that a route, device, or start record
/// is absent, so the service refuses a new start instead of overlapping a
/// possibly live setup. The text holds no path, address, token, or key.
pub const SERVICE_STATE_UNAVAILABLE_MESSAGE: &str =
    "The service state is unavailable after an interrupted operation. Inspect routes, devices, and the start record before restarting.";

/// The fixed status for a service whose shared state a panic poisoned.
///
/// `running` stays true because the service cannot prove that the tunnel
/// stopped, and `cleanup_blocked` stays true because it cannot prove that
/// cleanup finished. `state` names the uncertainty for a reader that can show
/// it. No field holds a path, address, token, or key. This shape is a
/// conservative guard, not a measurement: the status contract has no honest
/// unknown value for `running`, so it never reports the idle shape.
fn unavailable_status() -> Value {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut value = json!({
        "running": true,
        "mode": Value::Null,
        "started_at": Value::Null,
        "icmp_enabled": false,
        "cleanup_blocked": true,
        "state": "unknown",
        "iface": Value::Null,
        "last_stop": {"reason": Value::Null, "at": Value::Null},
        "stats": {},
        "error": SERVICE_STATE_UNAVAILABLE_MESSAGE,
        "logs": [],
        "demo": false,
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "admin": is_administrator(),
            "default_iface": Value::Null,
            "default_iface_name": Value::Null,
            "destination_privacy": diagnostics::destination_privacy_capability(),
        },
    });
    #[cfg(target_os = "linux")]
    {
        // The crash-recovery claim cannot be read from a poisoned state. The
        // key stays present so a reader does not mistake the shape for a
        // complete answer.
        value["route_claim"] = Value::Null;
    }
    value
}

/// The fixed diagnostics shape for a poisoned service.
///
/// The counters cannot be read. `ok` is false and `running` stays true for the
/// same reason as [`unavailable_status`]: the service cannot prove a stop.
fn unavailable_diagnostics() -> Value {
    let mut value = diagnostics::empty();
    value["ok"] = json!(false);
    value["running"] = json!(true);
    value["state"] = json!("unknown");
    value["error"] = json!(SERVICE_STATE_UNAVAILABLE_MESSAGE);
    value
}

/// The fixed failure record for a poisoned service.
///
/// The record cannot be read. `ok` is false so a reader does not mistake the
/// empty shape for a healthy record with no failures.
fn unavailable_failures() -> Value {
    let mut value = failures::empty_snapshot();
    value["ok"] = json!(false);
    value["state"] = json!("unknown");
    value["error"] = json!(SERVICE_STATE_UNAVAILABLE_MESSAGE);
    value
}

#[cfg(target_os = "macos")]
const ROUTE_CLEANUP_FAILED_MESSAGE: &str =
    "Route cleanup failed. Inspect routes before restarting.";

/// One macOS start's shared exclusion lock and durable direct start record.
///
/// The start body owns both values after it creates the record and before it
/// hands the resources to the tunnel worker. The worker owns them until route
/// and device cleanup is proved. Drop is the panic path: it retains the shared
/// lock for the rest of the process and leaves the direct start record in
/// place. Only an explicit clean finish releases the lock, and only an
/// explicit record removal clears the record.
///
/// A panic during route install, device setup, a cleanup attempt, or record
/// removal therefore cannot release the lock while a route or device may
/// remain. The panic still propagates and can poison the service mutex. A
/// poisoned service refuses every start and reports the fixed uncertainty; it
/// never reports a clean stop.
/// This is exclusion against a cooperative install
/// coordinator for the life of this process. A process exit or abort releases
/// the lock, as the operating system does for any `flock`.
#[cfg(target_os = "macos")]
struct MacosStartLease {
    lock: Option<crate::macos_upgrade_lock::UpgradeLock>,
    intent: Option<crate::macos_upgrade_lock::DirectStartIntent>,
    state: MacosLeaseState,
}

/// The ownership state of [`MacosStartLease`].
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacosLeaseState {
    /// The start body owns route and device setup.
    StartBody,
    /// The value is in the handoff channel or in the worker before unpacking.
    WorkerHandoff,
    /// The tunnel worker owns route and device cleanup.
    WorkerOwned,
    /// Cleanup and record removal finished. Drop releases the lock.
    Finished,
    /// Cleanup is uncertain. The lock is already retained until exit.
    Retained,
}

#[cfg(target_os = "macos")]
impl MacosStartLease {
    fn new(lock: crate::macos_upgrade_lock::UpgradeLock) -> Self {
        Self {
            lock: Some(lock),
            intent: None,
            state: MacosLeaseState::StartBody,
        }
    }

    /// The lock that this start holds. The lease owns it until `finish` or
    /// `retain`, so a start-body call must succeed.
    fn lock(&self) -> &crate::macos_upgrade_lock::UpgradeLock {
        self.lock
            .as_ref()
            .expect("a start lease holds its lock until it settles")
    }

    fn helper_handoff(&self) -> bool {
        self.lock().helper_handoff()
    }

    fn set_intent(&mut self, intent: crate::macos_upgrade_lock::DirectStartIntent) {
        self.intent = Some(intent);
    }

    /// Remove the direct start record after a proved clean cleanup.
    ///
    /// A helper start owns no direct record, so this is a no-op there. A failed
    /// removal leaves the record in place and sets the sticky leftover flag
    /// when the intent drops.
    fn remove_intent(&mut self) -> io::Result<()> {
        match self.intent.as_mut() {
            Some(intent) => intent.remove_after_clean_cleanup(),
            None => Ok(()),
        }
    }

    /// Keep the shared lock for the rest of the process.
    ///
    /// The direct start record, when present, is left in place. The caller must
    /// report the cleanup uncertainty before it returns.
    fn retain(&mut self) {
        if matches!(
            self.state,
            MacosLeaseState::Finished | MacosLeaseState::Retained
        ) {
            return;
        }
        self.state = MacosLeaseState::Retained;
        if let Some(lock) = self.lock.take() {
            crate::macos_upgrade_lock::retain_until_exit(lock);
        }
    }

    /// Release the lock after route, device, and record cleanup is proved.
    fn finish(&mut self) {
        self.state = MacosLeaseState::Finished;
        self.intent.take();
        self.lock.take();
    }

    /// Arm the lease for the channel handoff to the tunnel worker.
    ///
    /// The value stays armed while it waits in the channel and while the worker
    /// unpacks it. A panic in either place retains the lock.
    fn into_worker_handoff(mut self) -> Self {
        debug_assert_eq!(self.state, MacosLeaseState::StartBody);
        self.state = MacosLeaseState::WorkerHandoff;
        self
    }

    /// Mark that the tunnel worker now owns route and device cleanup.
    fn into_worker_owned(mut self) -> Self {
        debug_assert_eq!(self.state, MacosLeaseState::WorkerHandoff);
        self.state = MacosLeaseState::WorkerOwned;
        self
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosStartLease {
    fn drop(&mut self) {
        match self.state {
            // A panic skipped the explicit settle. The route and device Drop
            // calls may have run during unwind, but they cannot prove success.
            // Keep the shared exclusion for the rest of the process and leave
            // the durable record for a person to inspect.
            MacosLeaseState::StartBody
            | MacosLeaseState::WorkerHandoff
            | MacosLeaseState::WorkerOwned => self.retain(),
            MacosLeaseState::Finished | MacosLeaseState::Retained => {}
        }
    }
}

/// Keep the shared install lock when a direct start cannot prove cleanup.
#[cfg(target_os = "macos")]
fn retain_macos_start(inner: &mut Inner, lease: &mut MacosStartLease) {
    inner.cleanup_blocked = true;
    inner.error = Some(ROUTE_CLEANUP_FAILED_MESSAGE.into());
    lease.retain();
}

/// Finish an early macOS start failure with no routes and no tunnel device.
///
/// The direct start record is removed only after the caller proved that no
/// route or device remains. A failed removal keeps the shared lock and blocks
/// later starts, because the next participant cannot tell whether this start
/// still owns an object.
#[cfg(target_os = "macos")]
fn settle_macos_start(
    inner: &mut Inner,
    lease: &mut MacosStartLease,
    error: io::Error,
) -> io::Error {
    if lease.remove_intent().is_err() {
        retain_macos_start(inner, lease);
        return io::Error::other(
            "The direct start record could not be removed. Inspect the state directory before restarting.",
        );
    }
    lease.finish();
    error
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
                direct_record_uncertain: Arc::new(AtomicBool::new(false)),
                icmp_enabled: false,
                #[cfg(any(target_os = "macos", target_os = "linux", windows))]
                workers: 0,
                pinned_iface: None,
                #[cfg(any(windows, test))]
                windows_run: None,
                last_stop_reason: None,
                last_stop_at: None,
                logs: VecDeque::new(),
                next_log_seq: 0,
            }),
            failures: Arc::new(failures::FailureRecorder::new()),
        }
    }
}

/// The kernel `rtm_type` value for a unicast route.
///
/// `platform_linux` keeps the same value private to its route parser. A route
/// observation must carry the type so this module can refuse a local route
/// before the token leaves the process.
#[cfg(any(target_os = "linux", test))]
const RTN_UNICAST: u8 = 1;

/// The kernel `rtm_type` value for a local route. A test uses it to prove that a
/// local address cannot carry the source device token.
#[cfg(test)]
const RTN_LOCAL: u8 = 2;

/// One kernel route to the source device, as observed by the start path.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhoneRoute {
    /// The output interface index.
    ifindex: u32,
    /// The next hop, or `None` for an on-link route.
    gateway: Option<Ipv4Addr>,
    /// True when the matched prefix contains the destination and the route
    /// has no next hop.
    on_link_prefix: bool,
    /// The `rtm_type` value. Only `RTN_UNICAST` may carry the token.
    route_type: u8,
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
                    // A poisoned worker mutex means the worker panicked while
                    // it held that value. The join error above already marks
                    // the cleanup uncertain, so recover the data instead of
                    // panicking the status path.
                    let failure = fault
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
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

    /// Take the shared state for a start or another exclusive change.
    ///
    /// A poisoned mutex means a panic interrupted an earlier service operation
    /// while it held this state. That panic may have happened between a route,
    /// device, or start-record change and its cleanup, so the partial data is
    /// not proof that anything is absent. The caller refuses with the fixed
    /// message instead of starting an overlapping setup. The mutex stays
    /// poisoned, so every later start refuses the same way.
    fn lock_checked(&self) -> io::Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other(SERVICE_STATE_UNAVAILABLE_MESSAGE))
    }

    /// Take the shared state for cleanup after a possible panic.
    ///
    /// The recovered data is used only to release what it still names. The
    /// cleanup flag is set before any work, so no later reader can mistake the
    /// recovered state for a clean stop. The mutex stays poisoned, so a start
    /// still refuses after this cleanup.
    fn lock_for_cleanup(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                inner.cleanup_blocked = true;
                inner
            }
        }
    }

    /// Return the interface name for one index. The Unix normalization module
    /// has no name helper, so this keeps the canonical check local.
    #[cfg(unix)]
    fn canonical_interface_name(index: u32) -> io::Result<String> {
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface index must be nonzero",
            ));
        }
        let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
        let result = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
        if result.is_null() {
            return Err(io::Error::last_os_error());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
        name.to_str()
            .map(str::to_owned)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "interface name is not UTF-8"))
    }

    #[cfg(windows)]
    fn canonical_interface_name(index: u32) -> io::Result<String> {
        normalization::interface_name(index)
    }

    /// Refuse a tunnel adapter name. The caller may pass a name or a numeric
    /// index, so the check must run again on the resolved canonical name.
    ///
    /// `utun`, `hs-tun`, and `HotspotShade-Tunnel` are the tunnel names that
    /// this project creates on macOS, Linux, and Windows. A numeric value is
    /// accepted here; the canonical name check after the lookup rejects a
    /// numeric tunnel index.
    fn check_physical_interface_name(name: &str) -> io::Result<()> {
        let tunnel = name.is_empty()
            || name == "none"
            || name.starts_with("utun")
            || name.starts_with("hs-tun")
            || name.starts_with("HotspotShade-Tunnel");
        if tunnel {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a physical interface is required",
            ));
        }
        Ok(())
    }

    /// Return the canonical name for a numeric interface value. A name that the
    /// person supplied is kept as written, so a Windows alias still reads the
    /// same in status. A numeric value becomes the resolved name because later
    /// callers pass the returned value to name-based checks.
    fn interface_name_for_result(requested: &str, canonical: &str) -> String {
        match requested.parse::<u32>() {
            Ok(index) if index != 0 => canonical.to_owned(),
            _ => requested.to_owned(),
        }
    }

    /// Resolve one physical interface name and index.
    ///
    /// A numeric value is resolved to its canonical name, because later checks
    /// use the returned name. The canonical name is checked again against the
    /// tunnel prefixes, so a numeric tunnel index cannot bypass the guard. A
    /// name that the caller supplied is returned as written, so a Windows alias
    /// still reads the same; its resolved index is still checked.
    fn resolve_interface(iface: Option<&str>) -> io::Result<(String, u32)> {
        let requested = match iface {
            Some(value) => {
                Self::check_physical_interface_name(value)?;
                value.to_owned()
            }
            None => {
                #[cfg(unix)]
                {
                    environment::default_route()?.interface
                }
                #[cfg(windows)]
                {
                    let index = crate::platform::default_interface_index()?;
                    Self::canonical_interface_name(index)?
                }
            }
        };
        let index = normalization::interface_index(&requested)?;
        let canonical = Self::canonical_interface_name(index)?;
        Self::check_physical_interface_name(&canonical)?;
        Ok((
            Self::interface_name_for_result(&requested, &canonical),
            index,
        ))
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

    /// Hold the interface index that the caller froze before the source device
    /// check. The service resolves the interface name again, so a name that now
    /// maps to another index must stop the start. The caller's index is the one
    /// that its gateway and route checks used.
    #[cfg(any(target_os = "linux", windows, test))]
    fn verify_expected_outer_index(expected: Option<u32>, resolved: u32) -> io::Result<()> {
        match expected {
            Some(index) if index != resolved => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outer_interface_changed",
            )),
            _ => Ok(()),
        }
    }

    /// Return the numeric IPv4 source device address, or refuse the start.
    ///
    /// The token is never sent to an IPv6 destination in this mode. A host name
    /// was already refused by the caller, which parses a numeric socket address.
    #[cfg(any(target_os = "linux", test))]
    fn phone_target_host(address: SocketAddr) -> io::Result<Ipv4Addr> {
        match address {
            SocketAddr::V4(address) => Ok(*address.ip()),
            SocketAddr::V6(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            )),
        }
    }

    /// Decide whether a source device destination is safe to contact.
    ///
    /// The selected interface is the interface that the tunnel pins its outer
    /// sockets to. Two cases are accepted:
    ///
    /// - The selected interface is the current default route. The destination
    ///   must be that route's IPv4 gateway.
    /// - The selected interface is not the default route, which is the explicit
    ///   `--iface` case. The kernel must send to the destination through that
    ///   interface, either on-link or with the destination as the next hop.
    ///
    /// The second case supports a hotspot that is not the system default. It
    /// cannot prove that an on-link address is the hotspot gateway, so a typo
    /// within the on-link subnet is still possible. The first case rejects that
    /// typo. This function never sends a token.
    ///
    /// A loopback, tunnel, VPN, container, or bridge name is refused here even
    /// when the caller supplied it explicitly. Both paths require an observed
    /// kernel route to the destination: a missing observation, a failed or
    /// unsupported lookup, a dead or link-down route, and a non-unicast route
    /// all fail closed. A local route (`RTN_LOCAL`) names an address on this
    /// host, so an oif and prefix match is not evidence that the source device
    /// is reachable through the hotspot. The observed route must leave through
    /// the selected interface and reach the destination as a next hop or an
    /// on-link address. The caller must still prove the live outer link before
    /// it uses the token.
    #[cfg(any(target_os = "linux", test))]
    fn verify_phone_destination(
        host: Ipv4Addr,
        outer_ifname: &str,
        outer_ifindex: u32,
        default_route: Option<(Option<Ipv4Addr>, &str, u32)>,
        observed: Option<PhoneRoute>,
    ) -> io::Result<()> {
        if !crate::environment::physical_interface_name(outer_ifname) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a physical interface is required",
            ));
        }
        let Some(route) = default_route else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            ));
        };
        // A lookup that failed, returned nothing, or marked the route dead or
        // link-down reaches this function as `None`. It is not evidence that
        // the source device is reachable, on either path.
        let Some(observed) = observed else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            ));
        };
        // A local or special route never carries the token, even when its oif
        // and prefix match the selected interface.
        if observed.route_type != RTN_UNICAST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            ));
        }
        if observed.ifindex != outer_ifindex {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outer_interface_changed",
            ));
        }
        // The observed route must send the destination to the selected
        // interface, either as its next hop or as an on-link address.
        if observed.gateway != Some(host)
            && !(observed.gateway.is_none() && observed.on_link_prefix)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            ));
        }
        if route.1 == outer_ifname && route.2 == outer_ifindex {
            return Self::verify_phone_route(host, outer_ifname, outer_ifindex, Some(route));
        }
        Ok(())
    }

    /// Recheck the source device host against the current physical default
    /// route immediately before the token leaves this process. A route change
    /// between the caller check and the service check must stop the start. The
    /// tuple holds the gateway, the interface name, and the interface index.
    #[cfg(any(target_os = "linux", test))]
    fn verify_phone_route(
        host: Ipv4Addr,
        iface: &str,
        index: u32,
        route: Option<(Option<Ipv4Addr>, &str, u32)>,
    ) -> io::Result<()> {
        let Some((gateway, route_iface, route_index)) = route else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            ));
        };
        if route_iface != iface || route_index != index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outer_interface_changed",
            ));
        }
        if gateway != Some(host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_device_moved",
            ));
        }
        Ok(())
    }

    /// Start the SOCKS5 proxy pinned to one physical interface.
    ///
    /// When the caller supplies no DNS servers, discovery is scoped to the
    /// pinned interface. On macOS that means an unambiguous `scutil` block for
    /// the interface. On Linux the system resolver files are one aggregate
    /// list and do not prove which link a server belongs to, so discovery
    /// fails closed and the caller must pass an explicit server. The service
    /// never substitutes a public resolver, so a name cannot be resolved
    /// through another network or a VPN resolver.
    ///
    /// An explicit list is bounded, deduplicated, and validated by
    /// [`dns::normalize_servers`]. It is still queried through a normalized
    /// socket pinned to the selected interface. A loopback server is a local
    /// stub, not a resolver on the hotspot link, so a production start rejects
    /// it. Only the test-only [`Self::start_socks_loopback`] entry allows the
    /// hermetic loopback seam; the GUI and CLI cannot reach that entry.
    #[cfg(unix)]
    pub fn start_socks(
        &self,
        address: SocketAddr,
        iface: Option<&str>,
        servers: Option<Vec<SocketAddr>>,
    ) -> io::Result<()> {
        self.start_socks_inner(address, iface, servers, false)
    }

    /// Start a loopback SOCKS5 listener for a hermetic unit test.
    ///
    /// This entry skips the physical-interface and loopback-resolver guards so
    /// a test can use a loopback interface and a local resolver. It is compiled
    /// only for unit tests. A production build has no such path, and neither
    /// the GUI nor the CLI can select it.
    #[cfg(all(unix, test))]
    pub(crate) fn start_socks_loopback(
        &self,
        address: SocketAddr,
        iface: Option<&str>,
        servers: Option<Vec<SocketAddr>>,
    ) -> io::Result<()> {
        self.start_socks_inner(address, iface, servers, true)
    }

    /// Validate the interface and resolver choice for a production SOCKS5
    /// start.
    ///
    /// A test seam skips both guards. A production start requires a physical
    /// interface name and rejects every loopback resolver, because a loopback
    /// stub does not prove which link a query would use. The loopback check is
    /// separate from the interface check, so neither can relax the other.
    #[cfg(unix)]
    fn validate_socks_selection(
        name: &str,
        servers: &[SocketAddr],
        allow_loopback_seam: bool,
    ) -> io::Result<()> {
        if allow_loopback_seam {
            return Ok(());
        }
        if !environment::physical_interface_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a physical interface is required",
            ));
        }
        if servers
            .iter()
            .any(|server| crate::dns::canonical_ip(server.ip()).is_loopback())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a loopback DNS server is not allowed",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn start_socks_inner(
        &self,
        address: SocketAddr,
        iface: Option<&str>,
        servers: Option<Vec<SocketAddr>>,
        allow_loopback_seam: bool,
    ) -> io::Result<()> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listener must use loopback",
            ));
        }
        let mut inner = self.lock_checked()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_uncertain() {
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
        Self::validate_socks_selection(&name, &[], allow_loopback_seam)?;
        #[cfg(target_os = "linux")]
        let physical = if allow_loopback_seam {
            None
        } else {
            Some(crate::platform_linux::capture_physical_outer(&name, index)?)
        };
        let servers = match servers {
            Some(v) => {
                // An explicit caller, including the CLI and the GUI, gets the
                // same bound, deduplication, and value checks. An empty list is
                // an error, not an invitation to fall back to system discovery.
                dns::normalize_servers(v)?
            }
            None => environment::system_dns_for_interface(&name)?,
        };
        Self::validate_socks_selection(&name, &servers, allow_loopback_seam)?;
        let audit = Arc::new(normalization::Audit::default());
        let resolver = Arc::new(dns::TinyResolver::new(
            servers,
            Some(index),
            Duration::from_secs(4),
        )?);
        #[cfg(target_os = "linux")]
        if let Some(physical) = &physical {
            physical.recheck()?;
        }
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

    /// Start the macOS tunnel in direct mode or source device proxy mode.
    ///
    /// The start takes the shared install lock before it opens a utun or
    /// changes a route. A direct start also creates the durable
    /// `engine-session` launch intent before the utun. A helper start already
    /// has that record, so the engine does not create or remove it. One lease
    /// owns the lock and the intent. It retains both after a panic in the start
    /// body, in the worker handoff, or in the worker until route and device
    /// cleanup is proved. The worker removes the intent only after route and
    /// device cleanup finished. A cleanup fault, record removal failure, or
    /// panic therefore keeps the lock so an install cannot replace files
    /// underneath a possibly live route.
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
        let mut inner = self.lock_checked()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_uncertain() {
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
        // Take the shared install exclusion before any utun or route change.
        // The lease owns the guard from here on and keeps it until cleanup is
        // proved. A panic in this start body retains the lock and leaves the
        // direct start record in place.
        let upgrade_lock = match crate::macos_upgrade_lock::acquire_for_tunnel_start() {
            Ok(guard) => guard,
            Err(error) => {
                inner.log("error", &format!("Tunnel start refused: {error}"));
                return Err(io::Error::other(
                    crate::macos_upgrade_lock::START_REFUSED_MESSAGE,
                ));
            }
        };
        let mut lease = MacosStartLease::new(upgrade_lock);
        // A direct start owns the write-ahead launch intent. A helper start
        // already has one that the helper owns. The O_EXCL create is the one
        // cooperative single-start slot for both participants, so a second
        // direct start or a helper start cannot create an overlapping record.
        if let Err(error) = cancelled() {
            // No route, device, or record exists yet. A cancellation here is
            // a clean early failure and releases the lock.
            return Err(settle_macos_start(&mut inner, &mut lease, error));
        }
        let direct_record_uncertain = Arc::clone(&inner.direct_record_uncertain);
        if !lease.helper_handoff() {
            match crate::macos_upgrade_lock::create_direct_start_intent(
                lease.lock(),
                direct_record_uncertain,
            ) {
                Ok(intent) => lease.set_intent(intent),
                Err(error) => {
                    inner.log("error", &format!("Tunnel start refused: {error}"));
                    // The create removes only the inode that it created. A
                    // failed removal leaves the record and sets the leftover
                    // flag, even when the unlink itself succeeded and the
                    // directory sync failed. That is this service's own sticky
                    // cleanup uncertainty: refuse every later start and keep
                    // the shared lock for the life of the process.
                    if inner.direct_record_uncertain.load(Ordering::Acquire) {
                        retain_macos_start(&mut inner, &mut lease);
                        inner.error = Some(
                            "The direct start record could not be removed. Inspect the state directory before restarting."
                                .into(),
                        );
                        return Err(io::Error::other(
                            "The direct start record could not be removed. Inspect the state directory before restarting.",
                        ));
                    }
                    // The create removed its own incomplete record. No route
                    // or device exists, so this is a clean early failure.
                    return Err(settle_macos_start(&mut inner, &mut lease, error));
                }
            }
        }
        if let Err(error) = cancelled() {
            return Err(settle_macos_start(&mut inner, &mut lease, error));
        }
        let tun = match Utun::open(options.unit) {
            Ok(tun) => tun,
            Err(error) => {
                inner.log("error", "Tunnel device creation failed.");
                return Err(settle_macos_start(
                    &mut inner,
                    &mut lease,
                    io::Error::new(error.kind(), "tunnel_setup"),
                ));
            }
        };
        if let Err(error) = configure_link(tun.ifname(), options.addr, 1500) {
            inner.log("error", "Tunnel device configuration failed.");
            drop(tun);
            return Err(settle_macos_start(
                &mut inner,
                &mut lease,
                io::Error::new(error.kind(), "tunnel_setup"),
            ));
        }
        if let Err(error) = cancelled() {
            drop(tun);
            return Err(settle_macos_start(&mut inner, &mut lease, error));
        }
        let ipv6_forward = options.ipv6 == Ipv6Policy::Forward;
        self.failures.start();
        let mut relay = match Relay::start(RelayConfig {
            iface: index,
            phone,
            dns_upstream: options.dns_upstream,
            workers,
            ipv6_forward,
            allow_unpinned: options.no_pin,
            icmp_phone: options.icmp_phone,
            icmp_persistent: options.icmp_persistent,
            failures: Some(self.failures.clone()),
        }) {
            Ok(relay) => relay,
            Err(error) => {
                drop(tun);
                return Err(settle_macos_start(&mut inner, &mut lease, error));
            }
        };
        if let Err(error) = cancelled() {
            relay.stop();
            drop(relay);
            drop(tun);
            return Err(settle_macos_start(&mut inner, &mut lease, error));
        }
        let mut routes = match RouteManager::new(tun.ifname(), options.ipv6 == Ipv6Policy::Block) {
            Ok(routes) => routes,
            Err(error) => {
                relay.stop();
                drop(relay);
                drop(tun);
                return Err(settle_macos_start(&mut inner, &mut lease, error));
            }
        };
        if let Err(error) = if options.no_routes {
            Ok(())
        } else {
            routes.install()
        } {
            inner.log("error", "Tunnel route setup failed.");
            // `install` already attempts its own rollback. A second attempt is
            // idempotent and is the only proof that no recorded route remains.
            let cleanup_failed = routes.remove().is_err() || routes.has_installed_routes();
            drop(routes);
            relay.stop();
            drop(relay);
            drop(tun);
            if cleanup_failed {
                retain_macos_start(&mut inner, &mut lease);
                return Err(io::Error::new(error.kind(), "route_setup"));
            }
            return Err(settle_macos_start(
                &mut inner,
                &mut lease,
                io::Error::new(error.kind(), "route_setup"),
            ));
        }
        if let Err(error) = cancelled() {
            let cleanup_failed = routes.remove().is_err() || routes.has_installed_routes();
            drop(routes);
            relay.stop();
            drop(relay);
            drop(tun);
            if cleanup_failed {
                retain_macos_start(&mut inner, &mut lease);
                return Err(error);
            }
            return Err(settle_macos_start(&mut inner, &mut lease, error));
        }
        if !options.no_routes && options.ipv6 == Ipv6Policy::Block {
            if let Err(error) = crate::ipv6::verify_ipv6_route(None, Duration::from_secs(2)) {
                inner.log("error", "IPv6 block route verification failed.");
                let cleanup_failed = routes.remove().is_err() || routes.has_installed_routes();
                drop(routes);
                relay.stop();
                drop(relay);
                drop(tun);
                if cleanup_failed {
                    retain_macos_start(&mut inner, &mut lease);
                    return Err(io::Error::new(error.kind(), "route_setup"));
                }
                return Err(settle_macos_start(
                    &mut inner,
                    &mut lease,
                    io::Error::new(error.kind(), "route_setup"),
                ));
            }
        }
        let mut v6 = if ipv6_forward && !options.no_routes {
            let mut guard = match Ipv6Tunnel::new(tun.ifname()) {
                Ok(guard) => guard,
                Err(error) => {
                    let cleanup_failed = routes.remove().is_err() || routes.has_installed_routes();
                    drop(routes);
                    relay.stop();
                    drop(relay);
                    drop(tun);
                    if cleanup_failed {
                        retain_macos_start(&mut inner, &mut lease);
                        return Err(io::Error::new(error.kind(), "route_setup"));
                    }
                    return Err(settle_macos_start(
                        &mut inner,
                        &mut lease,
                        io::Error::new(error.kind(), "route_setup"),
                    ));
                }
            };
            if let Err(error) = guard.install().and_then(|_| guard.verify()) {
                inner.log("error", "IPv6 tunnel route setup failed.");
                let v6_failed = guard.remove().is_err() || guard.has_changes();
                let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
                drop(guard);
                drop(routes);
                relay.stop();
                drop(relay);
                drop(tun);
                if v6_failed || v4_failed {
                    retain_macos_start(&mut inner, &mut lease);
                    return Err(io::Error::new(error.kind(), "route_setup"));
                }
                return Err(settle_macos_start(
                    &mut inner,
                    &mut lease,
                    io::Error::new(error.kind(), "route_setup"),
                ));
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
            drop(v6);
            drop(routes);
            relay.stop();
            drop(relay);
            drop(tun);
            if v6_failed || v4_failed {
                retain_macos_start(&mut inner, &mut lease);
                return Err(error);
            }
            return Err(settle_macos_start(&mut inner, &mut lease, error));
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
            let (tun, relay, routes, v6, lease): (
                Utun,
                Relay,
                RouteManager,
                Option<Ipv6Tunnel>,
                MacosStartLease,
            ) = match resource_rx.recv() {
                Ok(value) => value,
                Err(_) => return,
            };
            // The worker owns route and device cleanup from here. A panic in
            // the monitor setup below still retains the shared lock and the
            // direct start record.
            let mut lease = lease.into_worker_owned();
            // The monitor owns no route or device. Start it outside the
            // panic boundary so the boundary can still stop and join it.
            let monitor_stop = Arc::new(AtomicBool::new(false));
            let monitor_flag = monitor_stop.clone();
            let (monitor_tx, monitor_rx) = std::sync::mpsc::sync_channel::<String>(1);
            let monitor = if verify_routes {
                Some(std::thread::Builder::new().name("hotspot-route-check".into()).spawn(move || {
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
                }))
            } else {
                None
            };
            let monitor_failed = match &monitor {
                Some(Ok(_)) => false,
                Some(Err(_)) => true,
                None => verify_routes,
            };
            let mut resources = Some((tun, relay, routes, v6));
            // A panic after this point skips the explicit route removal. The
            // worker cannot prove that the route and device Drop calls
            // succeeded, so the handler retains the shared lock and leaves the
            // direct start record in place.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (tun, mut relay, mut routes, mut v6) = match resources.take() {
                    Some(value) => value,
                    None => return (true, true, None),
                };
                let mut device_errors = 0u64;
                let mut relay_failed = monitor_failed;
                let mut pending = std::collections::VecDeque::<Vec<u8>>::new();
                let mut frame = FrameBuffer::new();
                let mut next_stats = std::time::Instant::now();
                let mut monitor_reason: Option<String> = None;
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
                relay.stop();
                let v6_failed = v6
                    .as_mut()
                    .map(|guard| guard.remove().is_err() || guard.has_changes())
                    .unwrap_or(false);
                let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
                (v6_failed || v4_failed, unexpected, monitor_reason)
            }));
            monitor_stop.store(true, Ordering::Release);
            if let Some(Ok(handle)) = monitor {
                handle.thread().unpark();
                let _ = handle.join();
            }
            match outcome {
                Ok((cleanup_failed, unexpected, monitor_reason)) => {
                    if cleanup_failed {
                        *fault_worker.lock().unwrap() = Some((
                            "Route cleanup failed. Inspect the routing table before restarting.".into(),
                            true,
                        ));
                        // A route or address may remain. Keep the shared lock
                        // until this process exits so an install cannot replace
                        // files underneath it. The direct start record stays.
                        lease.retain();
                    } else {
                        let intent_failed = lease.remove_intent().is_err();
                        if intent_failed {
                            *fault_worker.lock().unwrap() = Some((
                                "The direct start record could not be removed. Inspect the state directory before restarting.".into(),
                                true,
                            ));
                            lease.retain();
                        } else {
                            // Route, device, and record cleanup are proved.
                            lease.finish();
                            if unexpected {
                                let message = match monitor_reason {
                                    Some(reason) => format!("The tunnel stopped. {}", reason),
                                    None => "The tunnel device or relay stopped unexpectedly.".to_owned(),
                                };
                                *fault_worker.lock().unwrap() = Some((message,false));
                            }
                        }
                    }
                }
                Err(_) => {
                    // A panic skipped the explicit cleanup. The route and
                    // device Drop calls may have run during the unwind, but the
                    // worker cannot prove that they succeeded.
                    *fault_worker.lock().unwrap() = Some((
                        "The tunnel worker failed. Inspect routes before restarting.".into(),
                        true,
                    ));
                    lease.retain();
                }
            }
        }) {
            Ok(handle) => handle,
            Err(error) => {
                let v6_failed = v6.as_mut().map(|guard|guard.remove().is_err() || guard.has_changes()).unwrap_or(false);
                let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
                drop(v6);
                drop(routes);
                relay.stop();
                drop(relay);
                drop(tun);
                if v6_failed || v4_failed {
                    retain_macos_start(&mut inner, &mut lease);
                    return Err(error);
                }
                return Err(settle_macos_start(&mut inner, &mut lease, error));
            }
        };
        if let Err(error) = resources.send((tun, relay, routes, v6, lease.into_worker_handoff())) {
            let (tun, mut relay, mut routes, mut v6, mut lease) = error.0;
            relay.stop();
            let v6_failed = v6
                .as_mut()
                .map(|guard| guard.remove().is_err() || guard.has_changes())
                .unwrap_or(false);
            let v4_failed = routes.remove().is_err() || routes.has_installed_routes();
            drop(v6);
            drop(routes);
            drop(tun);
            let _ = handle.join();
            if v6_failed || v4_failed {
                retain_macos_start(&mut inner, &mut lease);
            } else {
                let start_error = settle_macos_start(
                    &mut inner,
                    &mut lease,
                    io::Error::other("tunnel worker failed to start"),
                );
                if !inner.cleanup_blocked {
                    inner.error =
                        Some("Tunnel startup failed. Inspect routes before restarting.".into());
                }
                return Err(start_error);
            }
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
    /// The method takes the guarded route claim before it opens the TUN device
    /// or changes any link or route. It then opens the TUN device, installs the
    /// dedicated table and the two policy rules, verifies the selected IPv4
    /// routes and the selected IPv6 policy, starts the relay, and hands the
    /// resources to one worker thread. Source device proxy mode adds the source
    /// device check and always forwards IPv6.
    ///
    /// Every failure path removes the objects that this call created. A cleanup
    /// failure sets `cleanup_blocked` so a later start cannot overlap it, and
    /// the route manager keeps its claim lock until this process exits. The
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
        let mut inner = self.lock_checked()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_uncertain() {
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
        // The caller froze this index when it read the hotspot route. Keep it:
        // resolving the name again must not silently move the token to another
        // interface.
        let expected_index = phone.as_ref().and_then(|phone| phone.iface);
        let (outer_ifname, outer_ifindex) = Self::resolve_interface(options.iface.as_deref())?;
        Self::verify_expected_outer_index(expected_index, outer_ifindex)?;
        let physical = crate::platform_linux::capture_physical_outer(&outer_ifname, outer_ifindex)?;
        // Take the guarded route claim before the source device check or any
        // host mutation. A second start, or a start that cannot name the stale
        // objects, therefore creates no TUN device and changes no link address.
        // The claim manager is created from the name that the TUN device will
        // use, and the device is opened only after the claim is held.
        let ifname = format!("hs-tun{}", options.unit);
        let mut routes = match RouteManager::new(&ifname, policy) {
            Ok(routes) => routes,
            Err(error) => return Err(io::Error::new(error.kind(), "route_setup")),
        };
        if let Err(error) = linux_checked_step(
            || physical.recheck(),
            || routes.claim_start_with_outer(&physical),
        ) {
            inner.log("error", "Tunnel route claim check failed.");
            // The reason names the claim path, a namespace, a boot, or an
            // errno. It holds no token, key, address, or host.
            inner.log("error", &format!("Tunnel route claim reason: {error}"));
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        // Prove the live outer link before the source device token leaves this
        // process. This call is read-only: it opens no TUN device and installs
        // no route. It rejects loopback, tunnel, and VPN links even when the
        // caller named one explicitly, so the token cannot reach a local or
        // virtual listener first.
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
        // A stop request that arrives during the link proof must end the start
        // before the token is used.
        cancelled()?;
        let phone = if let Some(mut phone) = phone {
            // Validate the source device destination after the live outer link
            // proof and before the token leaves this process, for every caller.
            // The GUI freezes an index from the hotspot route. A CLI caller
            // leaves the index unset, so this check is the only guard against a
            // mistyped address. It runs before the phone check and before the
            // TUN device exists.
            let default_route = environment::default_route().ok().and_then(|route| {
                let index = normalization::interface_index(&route.interface).ok()?;
                Some((route.gateway, route.interface, index))
            });
            let host = Self::phone_target_host(phone.address)?;
            let observed = crate::platform_linux::route_to_ipv4(host)
                .ok()
                .and_then(|route| {
                    if route.multipath || route.via || route.encap || route.dead || route.link_down
                    {
                        return None;
                    }
                    let on_link_prefix = route.gateway.is_none() && route.prefix.contains(host);
                    route.ifindex.map(|ifindex| PhoneRoute {
                        ifindex,
                        gateway: route.gateway,
                        on_link_prefix,
                        route_type: route.route_type,
                    })
                });
            Self::verify_phone_destination(
                host,
                &outer_ifname,
                outer_ifindex,
                default_route
                    .as_ref()
                    .map(|(gateway, name, index)| (*gateway, name.as_str(), *index)),
                observed,
            )?;
            phone.iface = Some(outer_ifindex);
            if let Err(error) = linux_checked_step(
                || physical.recheck(),
                || phone.check_cancellable(&normalization::Audit::default(), cancel),
            ) {
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
        let tun = match linux_checked_step(|| physical.recheck(), || Tun::open(&ifname, 1500)) {
            Ok(tun) => tun,
            Err(error) => {
                inner.log("error", "Tunnel device creation failed.");
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        let interface = match routes.verify_interface(&tun) {
            Ok(proof) => proof,
            Err(error) => {
                inner.log("error", "Tunnel interface verification failed.");
                return Err(io::Error::other(error.to_string()));
            }
        };
        physical.recheck()?;
        let mut link = match LinkGuard::install(&interface, &tun, options.addr, 1500) {
            Ok(link) => link,
            Err(error) => {
                inner.log("error", "Tunnel device configuration failed.");
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        if let Err(error) = physical.recheck() {
            if link.remove().is_err() {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        let prepared = linux_checked_step(
            || physical.recheck(),
            || routes.install_verified(&interface, &tun, &outer_ifname),
        )
        .and_then(|()| {
            routes
                .verify_start(&interface, &tun, &outer)
                .map_err(|error| io::Error::other(error.to_string()))?;
            physical.recheck()
        });
        if let Err(error) = prepared {
            inner.log("error", "Tunnel route setup failed.");
            // The reason names a route prefix, a rule priority, an interface,
            // a claim path, or an errno. It holds no token, key, or address of
            // a person or a source device, so the service log can carry it.
            inner.log("error", &format!("Tunnel route setup reason: {error}"));
            if linux_cleanup_start(
                || routes.remove().is_err() || routes.has_installed_routes(),
                || link.remove().is_err(),
            ) {
                inner.cleanup_blocked = true;
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        if let Err(error) = cancelled().and_then(|()| physical.recheck()) {
            let route_error = routes.remove().err();
            let link_error = link.remove().err();
            if route_error.is_some() || routes.has_installed_routes() || link_error.is_some() {
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
                if route_error.is_some() || routes.has_installed_routes() || link_error.is_some() {
                    inner.cleanup_blocked = true;
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(error);
            }
        };
        if let Err(error) = cancelled().and_then(|()| physical.recheck()) {
            let mut relay = relay;
            relay.stop();
            let route_error = routes.remove().err();
            let link_error = link.remove().err();
            if route_error.is_some() || routes.has_installed_routes() || link_error.is_some() {
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
        let link_identity = physical.clone();
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
                        if route_error.is_some()
                            || routes.has_installed_routes()
                            || link_error.is_some()
                        {
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
                            match crate::platform_linux::link_ready_for(&link_identity) {
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
                if route_error.is_some() || routes.has_installed_routes() || link_error.is_some() {
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
                if route_error.is_some() || routes.has_installed_routes() || link_error.is_some() {
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
            inner.cleanup_blocked =
                route_error.is_some() || routes.has_installed_routes() || link_error.is_some();
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
        let mut inner = self.lock_checked()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_uncertain() {
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
        // Hold the index that the caller froze before the source device check.
        // The service resolves the interface name again, so a name that now
        // maps to another index must stop the start.
        let expected_index = phone.iface;
        let (outer_ifname, outer_ifindex) = Self::resolve_interface(options.iface.as_deref())?;
        Self::verify_expected_outer_index(expected_index, outer_ifindex)?;
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
        let destination = phone.address;
        let outer_adapter = match runtime.check_phone(&phone, cancel) {
            Ok(adapter) => adapter,
            Err(error) => {
                if error.kind() == io::ErrorKind::Interrupted {
                    return Err(error);
                }
                // The token gate refused the destination. No token byte left
                // the process. Keep the fixed code so the GUI can explain it.
                if error.to_string() == crate::windows_route_verify::TOKEN_DESTINATION_REFUSED {
                    inner.log(
                        "error",
                        "The source device is not the proven hotspot gateway.",
                    );
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
        };
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
        // The token gate accepts the unscoped /1 routes during the run only
        // when they belong to this exact tunnel index and LUID.
        let tunnel_run = match crate::windows_route_verify::TunnelIdentity::new(
            device.ifindex(),
            identity.luid(),
        ) {
            Ok(tunnel) => tunnel,
            Err(_) => {
                inner.log("error", "Tunnel adapter identity check failed.");
                return Err(io::Error::new(io::ErrorKind::InvalidData, "tunnel_setup"));
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
        inner.windows_run = Some(WindowsPhoneRun {
            run: crate::windows_physical_path::TokenRun {
                tunnel: tunnel_run,
                outer: outer_adapter,
            },
            destination,
            iface: outer_ifindex,
        });
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

    /// Start the Windows tunnel in direct mode.
    ///
    /// Direct mode has no source device. It never reads a source token and it
    /// never calls the source device check. It requires pinning, managed
    /// routes, and an explicit IPv6 block or forward policy.
    ///
    /// The start proves the physical outer adapter before it loads Wintun. It
    /// refuses a tunnel adapter that shares an index, LUID, or GUID with that
    /// outer adapter. It installs the route plan, proves the plan with a
    /// read-only route check that refuses every warning outside a local-only
    /// scope, binds one link observer to the proof's exact retained identity,
    /// and starts the relay only after those checks pass. The relay pins the
    /// proof's interface index, so the worker stops when a later sample finds
    /// the retained adapter at a different index. Sampling is periodic.
    ///
    /// A stop request is checked before every stage. Every failure path removes
    /// the routes that this call installed, then closes the device. A route
    /// cleanup failure sets `cleanup_blocked`.
    ///
    /// This entry is a test seam. The real Windows direct start stays behind
    /// [`require_windows_direct_evidence`], because no Windows VM evidence for
    /// a physical adapter pin under the Wintun routes exists yet.
    #[cfg(any(windows, test))]
    fn start_windows_direct_tunnel_with(
        &self,
        options: TunOptions,
        workers: usize,
        cancel: &AtomicBool,
        runtime: &dyn WindowsDirectTunnelRuntime,
    ) -> io::Result<()> {
        use crate::relay::RelayConfig;
        use crate::windows_route_verify::Ipv6RoutePolicy;

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
        options.validate(false, workers)?;
        if options.no_pin {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows direct mode requires outer interface pinning",
            ));
        }
        if options.no_routes {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows direct mode requires managed routes",
            ));
        }
        let policy = match options.ipv6 {
            Ipv6Policy::Block => Ipv6RoutePolicy::Block,
            Ipv6Policy::Forward => Ipv6RoutePolicy::Forward,
            Ipv6Policy::Inherit => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Windows direct mode supports IPv6 block and forward only",
                ))
            }
        };
        cancelled()?;
        if !runtime.is_elevated() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tunnel requires administrator privileges",
            ));
        }
        let mut inner = self.lock_checked()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.cleanup_uncertain() {
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
        // Prove the physical outer adapter before any adapter or route exists.
        // The proof carries the retained identity, the proven local subnet, and
        // the outer-socket TTL and pin read-back.
        let proof = match runtime.prove_outer_adapter(&outer_ifname, outer_ifindex) {
            Ok(proof) => proof,
            Err(error) => {
                inner.log("error", "Outer adapter proof failed.");
                return Err(error);
            }
        };
        if proof.ifindex() != outer_ifindex {
            inner.log(
                "error",
                "Outer adapter proof did not match the resolved index.",
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outer_adapter_unverified",
            ));
        }
        cancelled()?;
        let wintun = windows_wintun_path(&options)?;
        if let Err(error) = runtime.load_wintun(&wintun) {
            inner.log("error", "Wintun DLL load failed.");
            return Err(error);
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
        if device.ifindex() == 0 || device.ifname().is_empty() {
            inner.log("error", "Tunnel device identity is invalid.");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tunnel_setup"));
        }
        let identity = match device.route_identity() {
            Ok(identity) => identity,
            Err(error) => {
                inner.log("error", "Tunnel adapter identity check failed.");
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        // The route plan, the proof, and the tunnel identity are one value.
        // A tunnel adapter that shares any identity value with the physical
        // adapter is refused before a route exists.
        let context =
            match WindowsDirectRouteContext::new(device.ifindex(), identity, policy, proof) {
                Ok(context) => context,
                Err(error) => {
                    inner.log("error", "Tunnel and outer adapter identities conflict.");
                    return Err(error);
                }
            };
        cancelled()?;
        let mut routes = match runtime.open_routes(context.clone()) {
            Ok(routes) => routes,
            Err(error) => {
                inner.log("error", "Tunnel route boundary setup failed.");
                return Err(io::Error::new(error.kind(), "route_setup"));
            }
        };
        if let Err(error) = routes.install() {
            inner.log("error", "Tunnel route setup failed.");
            if clean_windows_direct_start(&mut inner, None, Some(routes), None, Some(device)) {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        // Prove the installed plan before the relay can carry a packet. The
        // controller refuses any unproven-route warning, so a warning is a
        // stop until the warning policy is reviewed.
        if let Err(error) = routes.verify(&context) {
            inner.log("error", "Tunnel route verification failed.");
            if clean_windows_direct_start(&mut inner, None, Some(routes), None, Some(device)) {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(io::Error::new(error.kind(), "route_setup"));
        }
        if let Err(error) = cancelled() {
            if clean_windows_direct_start(&mut inner, None, Some(routes), None, Some(device)) {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        // Bind one link observer for the tunnel lifetime. The binding uses the
        // exact retained index, LUID, and GUID from the proof, so a reused
        // alias cannot redirect a later sample.
        let link = match runtime.bind_link_observer(context.outer()) {
            Ok(link) => link,
            Err(error) => {
                inner.log("error", "Tunnel link observer setup failed.");
                if clean_windows_direct_start(&mut inner, None, Some(routes), None, Some(device)) {
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(io::Error::new(error.kind(), "tunnel_setup"));
            }
        };
        if let Err(error) = cancelled() {
            if clean_windows_direct_start(&mut inner, None, Some(routes), Some(link), Some(device))
            {
                inner.error =
                    Some("Route cleanup failed. Inspect routes before restarting.".into());
            }
            return Err(error);
        }
        self.failures.start();
        let relay_config = RelayConfig {
            iface: Some(outer_ifindex),
            phone: None,
            dns_upstream: options.dns_upstream,
            workers,
            ipv6_forward: policy == Ipv6RoutePolicy::Forward,
            allow_unpinned: false,
            icmp_phone: false,
            icmp_persistent: false,
            failures: Some(self.failures.clone()),
        };
        let relay = match runtime.start_relay(&relay_config) {
            Ok(relay) => relay,
            Err(error) => {
                inner.log("error", "Tunnel relay setup failed.");
                if clean_windows_direct_start(
                    &mut inner,
                    None,
                    Some(routes),
                    Some(link),
                    Some(device),
                ) {
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(io::Error::new(error.kind(), "direct_relay_setup"));
            }
        };
        if let Err(error) = cancelled() {
            if clean_windows_direct_start(
                &mut inner,
                Some(relay),
                Some(routes),
                Some(link),
                Some(device),
            ) {
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
        let link_poll_interval = runtime.link_poll_interval();
        let link_down_limit = runtime.link_down_limit();
        let (resources, resource_rx) = std::sync::mpsc::sync_channel(1);
        let handle = match std::thread::Builder::new()
            .name("hotspot-tun".into())
            .spawn(move || {
                let resources = match resource_rx.recv() {
                    Ok(value) => value,
                    Err(_) => return,
                };
                run_windows_direct_worker(
                    resources,
                    stop_worker,
                    stats_worker,
                    diag_worker,
                    fault_worker,
                    auto_stop_worker,
                );
            }) {
            Ok(handle) => handle,
            Err(error) => {
                if clean_windows_direct_start(
                    &mut inner,
                    Some(relay),
                    Some(routes),
                    Some(link),
                    Some(device),
                ) {
                    inner.error =
                        Some("Route cleanup failed. Inspect routes before restarting.".into());
                }
                return Err(error);
            }
        };
        if let Err(error) = resources.send(WindowsDirectWorkerResources {
            device,
            relay,
            routes,
            link,
            // The relay config above pins this same index. The start rejected a
            // proof whose adapter index differed from it.
            pinned_index: outer_ifindex,
            link_poll_interval,
            link_down_limit,
        }) {
            let WindowsDirectWorkerResources {
                device,
                relay,
                routes,
                link,
                ..
            } = error.0;
            let cleanup_failed = clean_windows_direct_start(
                &mut inner,
                Some(relay),
                Some(routes),
                Some(link),
                Some(device),
            );
            let _ = handle.join();
            inner.cleanup_blocked |= cleanup_failed;
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
        inner.mode = Some("tun");
        inner.started = Some(now());
        inner.workers = workers;
        inner.error = None;
        inner.last_stop_reason = None;
        inner.last_stop_at = None;
        inner.icmp_enabled = false;
        inner.pinned_iface = Some(outer_ifname);
        inner.log("info", "Tunnel started.");
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
                if let Some((message, cleanup_failed)) = fault
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                {
                    inner.error = Some(message);
                    inner.cleanup_blocked |= cleanup_failed;
                }
            }
            None => (),
        }
        if was_active {
            if inner.cleanup_uncertain() {
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
        let _ = self.stop_checked();
    }

    /// Stop the tunnel and report whether cleanup is provably complete.
    ///
    /// A clean stop returns `Ok`. A join fault or a route cleanup failure that
    /// leaves the service unable to prove that no route or device remains
    /// returns an error. The flag stays set for the rest of the process, so
    /// every later stop and every exit path reports the same uncertainty. The
    /// error text is fixed and holds no path or address.
    pub fn stop_checked(&self) -> io::Result<()> {
        // A panic may have skipped part of start or cleanup. Try to stop owned
        // resources, but never report that cleanup was proved merely because
        // the remaining state looks empty.
        let mut inner = self.lock_for_cleanup();
        self.stop_locked(&mut inner);
        if inner.cleanup_uncertain() {
            Err(io::Error::other(CLEANUP_UNCERTAIN_MESSAGE))
        } else {
            Ok(())
        }
    }

    /// Treat a panic in a tunnel start path as an uncertain cleanup.
    ///
    /// A panic can skip an explicit removal. The service cannot tell whether a
    /// route or device exists, so every later stop and the process exit must
    /// report a cleanup failure. A SOCKS start does not call this method: it
    /// owns no route or tunnel device.
    #[cfg(unix)]
    pub(crate) fn mark_start_panic(&self) {
        let mut inner = self.lock_for_cleanup();
        inner.cleanup_blocked = true;
        inner.error = Some("The tunnel start failed. Inspect routes before restarting.".into());
    }

    /// True when this process cannot prove that the last cleanup finished.
    ///
    /// A GUI exit path must treat this as a failed stop. The Swift helper sees
    /// the engine's exit status, not this value, so the engine must exit
    /// nonzero when this returns true.
    pub fn cleanup_uncertain(&self) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            // A poisoned lock cannot prove what work was interrupted. Do not
            // inspect a partial state and turn that uncertainty into success.
            Err(_) => return true,
        };
        Self::reap_finished(&mut inner, &self.failures);
        inner.cleanup_uncertain()
    }

    /// Inject one sticky cleanup fault for a hermetic reporting test.
    ///
    /// This does not create a route or a device. It exercises the stop and GUI
    /// exit contract when the service cannot prove cleanup.
    #[cfg(all(test, unix))]
    pub(crate) fn inject_cleanup_fault_for_test(&self) {
        let mut inner = self.lock_for_cleanup();
        inner.cleanup_blocked = true;
        inner.error = Some("Route cleanup failed. Inspect routes before restarting.".into());
    }

    #[cfg(all(test, unix))]
    pub(crate) fn poison_state_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.inner.lock().unwrap();
            panic!("simulated interrupted service operation");
        }));
    }

    /// Return the token gate binding of the running Windows source device
    /// tunnel, or None when no such run is active.
    ///
    /// A poisoned state returns None, so the token gate fails closed instead
    /// of accepting unknown `/1` routes.
    #[cfg(any(windows, test))]
    pub(crate) fn windows_phone_run(&self) -> Option<WindowsPhoneRun> {
        let mut inner = self.inner.lock().ok()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.active.is_some() && inner.mode == Some("phone") {
            inner.windows_run
        } else {
            None
        }
    }

    /// Run the Windows token gate for one token use.
    ///
    /// While a tunnel runs, the gate uses the binding that the start proved:
    /// the tunnel `/1` routes of this run and the same physical adapter. A
    /// running service without that binding fails closed. Without a tunnel,
    /// the unscoped default route must be the physical default route. The
    /// error is always the fixed `source_gateway_unproven` code.
    #[cfg(windows)]
    pub fn windows_token_gate(
        &self,
        destination: SocketAddr,
        iface: Option<u32>,
    ) -> io::Result<()> {
        let refused = || {
            io::Error::new(
                io::ErrorKind::NotConnected,
                crate::windows_route_verify::TOKEN_DESTINATION_REFUSED,
            )
        };
        let run = if self.is_running() {
            Some(self.windows_phone_run().ok_or_else(refused)?.run)
        } else {
            None
        };
        crate::windows_route_verify::require_token_destination_proof(destination, iface, run)
            .map(|_| ())
    }

    /// Run the Windows token gate for the running tunnel's own destination
    /// and pinned interface. The relay keeps using the token for new flows,
    /// so the CLI and the GUI call this while a run is live and stop the run
    /// on a refusal.
    #[cfg(windows)]
    pub fn windows_run_token_gate(&self) -> io::Result<()> {
        let current = self.windows_phone_run().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                crate::windows_route_verify::TOKEN_DESTINATION_REFUSED,
            )
        })?;
        crate::windows_route_verify::require_token_destination_proof(
            current.destination,
            Some(current.iface),
            Some(current.run),
        )
        .map(|_| ())
    }

    /// Check service liveness without querying the system routing table.
    pub fn is_running(&self) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            // A poisoned state cannot prove that the tunnel stopped. Report the
            // conservative answer so no caller records a clean stop or treats
            // the service as idle while a route or device may remain.
            Err(_) => return true,
        };
        Self::reap_finished(&mut inner, &self.failures);
        // Report the state that reap_finished checked. If a worker exits after
        // that check, the next call records its error before reporting a stop.
        inner.active.is_some()
    }

    /// Failed source device setups for the current tunnel. The value is empty
    /// when no tunnel runs. The record stays in memory only.
    pub fn failures(&self) -> Value {
        let running = {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                // The record cannot be read from a poisoned state. An empty
                // healthy record would hide the uncertainty.
                Err(_) => return unavailable_failures(),
            };
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
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            // The counters cannot be read from a poisoned state. The fixed
            // shape reports the uncertainty and never the idle shape.
            Err(_) => return unavailable_diagnostics(),
        };
        Self::reap_finished(&mut inner, &self.failures);
        let running = tunnel_worker_running(&inner);
        let (metrics, started, workers) = if running {
            match &inner.active {
                #[cfg(any(target_os = "macos", target_os = "linux", windows))]
                Some(Active::Tun { diag, .. }) => (
                    diag.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone(),
                    inner.started,
                    inner.workers,
                ),
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
            merge_relay_diagnostics(&mut value, &metrics);
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

    /// Remove a route claim file that cannot describe a live object.
    ///
    /// This is the safe operator path for a damaged or previous-boot claim. It
    /// removes only the claim file, never a route or a rule. It refuses while a
    /// tunnel runs, while cleanup is blocked, and while a valid current claim
    /// can still describe live objects. The next start handles those cases.
    #[cfg(target_os = "linux")]
    pub fn clear_route_claim(&self) -> io::Result<bool> {
        // A poisoned state cannot prove that no tunnel or owned claim exists.
        // Refuse instead of clearing a claim that may still describe an object.
        let mut inner = self.lock_checked()?;
        Self::reap_finished(&mut inner, &self.failures);
        if inner.active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the tunnel is running",
            ));
        }
        if inner.cleanup_blocked {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before clearing the claim",
            ));
        }
        crate::platform_linux::clear_corrupt_route_claim()
    }

    pub fn status(&self) -> Value {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            // A poisoned state cannot prove that the tunnel stopped. Report the
            // fixed uncertainty shape instead of an idle status.
            Err(_) => return unavailable_status(),
        };
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
            Some(Active::Tun { stats, .. }) => (
                true,
                stats
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
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
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut value = json!({"running":running,"mode":if running { inner.mode } else { None },"started_at":inner.started,
            "icmp_enabled":icmp_enabled,
            "cleanup_blocked":inner.cleanup_uncertain(),
            "iface":inner.pinned_iface,
            "last_stop":{"reason":inner.last_stop_reason,"at":inner.last_stop_at},
            "stats":stats,"error":inner.error,"logs":inner.logs.iter().cloned().collect::<Vec<_>>(),"demo":false,
            "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
                "admin":is_administrator(),"default_iface":route.as_ref().map(|r|r.interface.clone()),
                "default_iface_name":route.as_ref().map(|r|r.interface.clone()),
                "destination_privacy":diagnostics::destination_privacy_capability()}});
        #[cfg(target_os = "linux")]
        {
            // The crash-recovery claim is read-only here. It holds no address,
            // token, or key, and the inspection never deletes a route or rule.
            let claim = crate::platform_linux::inspect_route_claim();
            value["route_claim"] = json!({
                "present": claim.present,
                "locked": claim.locked,
                "private": claim.private,
                "usable": claim.usable,
                "same_boot": claim.same_boot,
                "same_namespace": claim.same_namespace,
                "stale_pid": claim.stale_pid,
                "problem": claim.problem,
            });
        }
        value
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

/// Remove direct-mode routes, stop the relay, drop the link observer, and close
/// the adapter in that order.
///
/// Return true when route cleanup failed or left a record. The caller records
/// the error and blocks a later start.
#[cfg(any(windows, test))]
fn clean_windows_direct_start(
    inner: &mut Inner,
    relay: Option<Box<dyn WindowsDirectRelay>>,
    mut routes: Option<Box<dyn WindowsDirectRouteController>>,
    link: Option<Box<dyn WindowsDirectLinkObserver>>,
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
    drop(link);
    drop(device);
    if failed {
        inner.cleanup_blocked = true;
    }
    failed
}

/// Run one direct worker until stop, relay failure, device failure, continuous
/// link loss, or a stale outer pin.
///
/// The cleanup order is fixed: stop the relay, remove the routes, drop the
/// retained link observer, then close the adapter. A route cleanup failure is
/// recorded as cleanup uncertainty. A link-loss or stale-pin stop is an
/// automatic stop, not an unexpected failure.
#[cfg(any(windows, test))]
fn run_windows_direct_worker(
    resources: WindowsDirectWorkerResources,
    stop_worker: Arc<AtomicBool>,
    stats_worker: Arc<Mutex<Value>>,
    diag_worker: Arc<Mutex<Value>>,
    fault_worker: Arc<Mutex<Option<(String, bool)>>>,
    auto_stop_worker: Arc<Mutex<Option<&'static str>>>,
) {
    let WindowsDirectWorkerResources {
        mut device,
        mut relay,
        mut routes,
        link,
        pinned_index,
        link_poll_interval,
        link_down_limit,
    } = resources;
    let mut device_errors = 0u64;
    let mut relay_failed = false;
    let mut pending = std::collections::VecDeque::<Vec<u8>>::new();
    let mut next_stats = std::time::Instant::now();
    let mut next_link = std::time::Instant::now();
    let mut link_policy = crate::autostop::AutoStopPolicy::with_limits(
        link_down_limit,
        crate::autostop::SOURCE_DEVICE_GONE_LIMIT,
    );
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
            *stats_worker.lock().unwrap() = tunnel_relay_stats(&relay.stats(), device_errors);
            *diag_worker.lock().unwrap() = relay.diagnostics();
            next_stats = std::time::Instant::now() + Duration::from_millis(100);
        }
        if std::time::Instant::now() >= next_link {
            next_link = std::time::Instant::now() + link_poll_interval;
            match link.observe() {
                Ok(sample) => match classify_windows_direct_link(sample, pinned_index) {
                    WindowsDirectLinkDecision::Link { up } => {
                        let sample = crate::autostop::sample_from(up, false, None);
                        let now = std::time::Instant::now();
                        if let Some(reason) = link_policy.observe(now, sample) {
                            *auto_stop_worker.lock().unwrap() = Some(reason);
                            break;
                        }
                    }
                    // The relay pins the start index. The retained observer
                    // follows the adapter to a new index, so the pin can name
                    // no adapter or a different adapter after index reuse.
                    // Do not wait for the link-down limit: the tunnel would
                    // otherwise keep sending outer traffic through the wrong
                    // adapter. `hotspot_lost` is the existing automatic-stop
                    // reason for a pinned hotspot that is no longer usable.
                    WindowsDirectLinkDecision::StalePin => {
                        *auto_stop_worker.lock().unwrap() = Some("hotspot_lost");
                        break;
                    }
                },
                // An unknown link state is not link loss. Reset the evidence
                // instead of starting or extending a loss interval.
                Err(_) => link_policy.reset(),
            }
        }
        // The Wintun read event is a kernel event, not a socket. A short
        // bounded wait keeps relay output moving while the hotspot is idle.
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
    let auto_reason = *auto_stop_worker.lock().unwrap();
    let unexpected = auto_reason.is_none()
        && (relay_failed || !stop_worker.load(Ordering::Acquire) || device_errors > 0);
    relay.stop();
    let route_error = routes.remove().err();
    let routes_left = routes.has_routes();
    drop(routes);
    drop(link);
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

    fn check_phone(
        &self,
        phone: &phone::PhoneProxy,
        cancel: &AtomicBool,
    ) -> io::Result<crate::windows_route_verify::RetainedAdapterIdentity> {
        // The token gate runs right before the token leaves the process. No
        // tunnel runs yet, so the unscoped probes must select the physical
        // default route. The proven adapter binds the later run checks.
        let adapter = crate::windows_route_verify::require_token_destination_proof(
            phone.address,
            phone.iface,
            None,
        )?;
        phone.check_cancellable(&normalization::Audit::default(), cancel)?;
        Ok(adapter)
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

/// The retained physical link observer for the production direct worker.
#[cfg(windows)]
struct SystemWindowsDirectLink {
    observer: crate::platform::RetainedPhysicalLinkObserver,
}

#[cfg(windows)]
impl WindowsDirectLinkObserver for SystemWindowsDirectLink {
    fn observe(&self) -> io::Result<WindowsDirectLinkSample> {
        let sample = self.observer.observe_sample()?;
        Ok(WindowsDirectLinkSample {
            up: sample.up,
            interface_index: sample.interface_index,
        })
    }
}

/// The production relay adapter for the direct worker.
#[cfg(windows)]
struct SystemWindowsDirectRelay {
    relay: crate::relay::Relay,
}

#[cfg(windows)]
impl WindowsDirectRelay for SystemWindowsDirectRelay {
    fn is_running(&self) -> bool {
        self.relay.is_running()
    }

    fn dispatch(&self, packet: Vec<u8>) -> io::Result<()> {
        self.relay.dispatch(packet)
    }

    fn try_receive(&self) -> Option<Vec<u8>> {
        self.relay.try_receive()
    }

    fn stop(&mut self) {
        self.relay.stop();
    }

    fn stats(&self) -> crate::relay::RelayStats {
        self.relay.stats()
    }

    fn diagnostics(&self) -> Value {
        self.relay.diagnostics()
    }
}

/// Build the route verification policy from one direct context.
///
/// The policy carries the proven IPv4 hotspot subnet. In forward mode it also
/// carries proven IPv6 subnets bound to the same adapter. Block mode does not
/// exempt global IPv6 local routes from the blackhole. The live check
/// confirms each retained adapter identity before and after the route reads, so
/// an IPv6 exemption cannot name another adapter. A missing IPv6 proof leaves
/// the policy unchanged: an unproven on-link IPv6 route stays a failure.
#[cfg(any(windows, test))]
fn windows_direct_verify_policy(
    context: &WindowsDirectRouteContext,
) -> crate::windows_route_verify::VerifyPolicy {
    let mut policy =
        crate::windows_route_verify::VerifyPolicy::new(context.tunnel(), context.policy())
            .with_local_subnet(context.outer().local_subnet());
    if context.policy() == crate::windows_route_verify::Ipv6RoutePolicy::Forward {
        for subnet in context.outer().ipv6_local_subnets() {
            policy = policy.with_local_subnet(*subnet);
        }
    }
    policy
}

/// The production direct route controller. It holds the native route boundary
/// and the exact context that the installer and verifier share.
#[cfg(windows)]
struct SystemWindowsDirectRoutes {
    boundary: crate::windows_native_routes::RouteBoundary,
    context: WindowsDirectRouteContext,
}

#[cfg(windows)]
impl WindowsDirectRouteController for SystemWindowsDirectRoutes {
    fn install(&mut self) -> io::Result<()> {
        self.boundary
            .install()
            .map_err(|failure| io::Error::other(failure.to_string()))
    }

    fn verify(&mut self, context: &WindowsDirectRouteContext) -> io::Result<()> {
        if context != &self.context {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "route_context_mismatch",
            ));
        }
        let policy = windows_direct_verify_policy(context);
        let proof =
            crate::windows_route_verify::verify_live_retained(&policy, &context.tunnel_retained())
                .map_err(|error| io::Error::other(format!("route verification failed: {error}")))?;
        // A warning outside a local-only scope is not proof. Reject it before
        // the relay exists.
        require_direct_route_proof(proof.proof())
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

/// The production direct runtime.
///
/// The real direct start is gated by [`require_windows_direct_evidence`]. The
/// outer adapter proof is deliberately unimplemented: a proof that a physical
/// adapter pin survives the Wintun routes needs a Windows VM measurement, not
/// another compile-time check.
#[cfg(windows)]
struct SystemWindowsDirectRuntime;

#[cfg(windows)]
impl WindowsDirectTunnelRuntime for SystemWindowsDirectRuntime {
    fn is_elevated(&self) -> bool {
        crate::platform::is_elevated()
    }

    fn load_wintun(&self, wintun_dll: &std::path::Path) -> io::Result<()> {
        crate::platform::load_wintun(wintun_dll)
    }

    fn prove_outer_adapter(
        &self,
        _ifname: &str,
        _ifindex: u32,
    ) -> io::Result<WindowsOuterAdapterProof> {
        require_windows_direct_evidence()?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the Windows physical outer adapter reader is not implemented",
        ))
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
        context: WindowsDirectRouteContext,
    ) -> io::Result<Box<dyn WindowsDirectRouteController>> {
        let boundary = crate::windows_native_routes::RouteBoundary::open(
            context.tunnel_adapter(),
            context.policy(),
        );
        Ok(Box::new(SystemWindowsDirectRoutes { boundary, context }))
    }

    fn bind_link_observer(
        &self,
        proof: &WindowsOuterAdapterProof,
    ) -> io::Result<Box<dyn WindowsDirectLinkObserver>> {
        // Bind the exact retained adapter identity from the proof. Do not
        // resolve the alias again: a reused alias can name another adapter, and
        // a rename must not look like link loss.
        let observer =
            crate::platform::RetainedPhysicalLinkObserver::bind_retained(proof.adapter())?;
        Ok(Box::new(SystemWindowsDirectLink { observer }))
    }

    fn start_relay(
        &self,
        config: &crate::relay::RelayConfig,
    ) -> io::Result<Box<dyn WindowsDirectRelay>> {
        let relay = crate::relay::Relay::start(config.clone())?;
        Ok(Box::new(SystemWindowsDirectRelay { relay }))
    }
}

#[cfg(windows)]
impl Service {
    /// Start the Windows tunnel in source device proxy mode or direct mode.
    ///
    /// Source device proxy mode runs the token gate in the source device check,
    /// right before the token leaves the process. Direct mode stays refused by
    /// the closed physical-adapter evidence gate. The two guards are separate,
    /// and direct mode never calls the token guard.
    pub fn start_tun_options_cancellable(
        &self,
        options: TunOptions,
        phone: Option<phone::PhoneProxy>,
        workers: usize,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        match phone {
            Some(phone) => {
                require_windows_start_gate(true)?;
                self.start_windows_tunnel_with(
                    options,
                    Some(phone),
                    workers,
                    cancel,
                    &SystemWindowsTunnelRuntime,
                )
            }
            None => {
                require_windows_start_gate(false)?;
                self.start_windows_direct_tunnel_with(
                    options,
                    workers,
                    cancel,
                    &SystemWindowsDirectRuntime,
                )
            }
        }
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
    #[test]
    fn linux_start_steps_recheck_around_recovery_credentials_and_mutations() {
        use std::cell::{Cell, RefCell};

        // A replacement observed at any boundary prevents subsequent work.
        // The fake claim represents claim_start, including stale-route recovery.
        let steps = [
            "claim_recovery",
            "credential_check",
            "open_tun",
            "install_routes",
        ];
        for failed_check in 0..steps.len() * 2 {
            let events = RefCell::new(Vec::new());
            let checks = Cell::new(0);
            for step in steps {
                let result = linux_checked_step(
                    || {
                        let n = checks.get();
                        checks.set(n + 1);
                        events.borrow_mut().push("identity");
                        if n == failed_check {
                            Err(io::Error::new(io::ErrorKind::NotConnected, "changed"))
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        events.borrow_mut().push(step);
                        Ok(())
                    },
                );
                if result.is_err() {
                    break;
                }
            }
            let events = events.into_inner();
            assert_eq!(checks.get(), failed_check + 1);
            assert_eq!(events.last(), Some(&"identity"));
            for (index, step) in steps.iter().enumerate() {
                assert_eq!(events.contains(step), failed_check > index * 2);
            }
        }
    }

    #[test]
    fn linux_start_cleanup_attempts_link_after_route_failure() {
        use std::cell::RefCell;
        for (route_failure, link_failure) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let events = RefCell::new(Vec::new());
            let failed = linux_cleanup_start(
                || {
                    events.borrow_mut().push("routes");
                    route_failure
                },
                || {
                    events.borrow_mut().push("link");
                    link_failure
                },
            );
            assert_eq!(*events.borrow(), ["routes", "link"]);
            assert_eq!(failed, route_failure || link_failure);
        }
    }

    #[test]
    fn linux_changed_identity_drops_new_tun_and_cleans_installed_routes() {
        use std::cell::{Cell, RefCell};
        struct FakeTun<'a>(&'a RefCell<Vec<&'static str>>);
        impl Drop for FakeTun<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("close_tun");
            }
        }
        let events = RefCell::new(Vec::new());
        let checks = Cell::new(0);
        let result = linux_checked_step(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(io::Error::new(io::ErrorKind::NotConnected, "changed"))
                } else {
                    Ok(())
                }
            },
            || {
                events.borrow_mut().push("open_tun");
                Ok(FakeTun(&events))
            },
        );
        assert!(result.is_err());
        assert_eq!(*events.borrow(), ["open_tun", "close_tun"]);

        events.borrow_mut().clear();
        checks.set(0);
        let result = linux_checked_step(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(io::Error::new(io::ErrorKind::NotConnected, "changed"))
                } else {
                    Ok(())
                }
            },
            || {
                events.borrow_mut().push("install_routes");
                Ok(())
            },
        );
        assert!(result.is_err());
        let blocked = linux_cleanup_start(
            || {
                events.borrow_mut().push("remove_routes");
                true
            },
            || {
                events.borrow_mut().push("remove_link");
                false
            },
        );
        assert!(blocked);
        assert_eq!(
            *events.borrow(),
            ["install_routes", "remove_routes", "remove_link"]
        );
    }
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
            .start_socks_loopback(
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
    #[test]
    fn status_reports_destination_privacy_as_off_and_unsupported() {
        let service = Service::new();
        let status = service.status();
        let privacy = &status["platform"]["destination_privacy"];
        assert_eq!(privacy["mode"], "off");
        assert_eq!(privacy["default_mode"], "off");
        assert_eq!(privacy["modes"]["off"], "supported");
        // No mode other than `off` has a code path. Do not report one as
        // supported, available, or active.
        for name in ["shape", "hide", "cover"] {
            assert_eq!(privacy["modes"][name], "unsupported", "{name}");
        }
        assert_eq!(privacy["sni_override"], "unsupported");
        assert_eq!(privacy["ech"], "unsupported");
        // The status carries no name, address, certificate, or ECH config.
        let text = privacy.to_string();
        for forbidden in ["token", "127.0.0.1", "example", "BEGIN"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
    #[test]
    fn a_running_relay_replaces_the_destination_privacy_counters() {
        let mut value = crate::diagnostics::empty();
        let mut counters = crate::diagnostics::zero_destination_privacy_counters();
        counters["ech_ok"] = json!(3);
        let metrics = json!({"destination_privacy":{"mode":"off","counters":counters}});
        merge_relay_diagnostics(&mut value, &metrics);
        assert_eq!(value["destination_privacy"]["mode"], "off");
        assert_eq!(value["destination_privacy"]["counters"]["ech_ok"], 3);
        // A section that the relay did not report keeps the empty shape.
        assert_eq!(value["setup"], crate::diagnostics::empty()["setup"].clone());
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
            .start_socks_loopback(
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
    fn tunnel_rejects_non_unicast_and_loopback_dns_upstreams() {
        for upstream in [
            "127.0.0.1:53",
            "0.0.0.0:53",
            "169.254.1.1:53",
            "224.0.0.1:53",
            "255.255.255.255:53",
            "[::ffff:192.0.2.53]:53",
        ] {
            let options = TunOptions {
                dns_upstream: Some(upstream.parse().unwrap()),
                ..TunOptions::default()
            };
            assert!(options.validate(false, 1).is_err(), "{upstream}");
        }
        let options = TunOptions {
            dns_upstream: Some("192.0.2.53:53".parse().unwrap()),
            ..TunOptions::default()
        };
        assert!(options.validate(false, 1).is_ok());
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
    /// Hermetic panic and cleanup tests for the macOS start lease.
    ///
    /// These use the production lock, durable intent, and `RouteManager` with a
    /// fake command runner. They create no utun, change no route, and need no
    /// root. They do not run the full start body, which requires a real device.
    #[cfg(target_os = "macos")]
    mod macos_start_lease_tests {
        use super::*;
        use crate::macos_upgrade_lock::{
            acquire_exclusive_for_test, acquire_shared_for_test, create_direct_start_intent,
            direct_intent_path_for_test, retained_lock_serial_for_test,
        };
        use crate::platform::{CommandRunner, RouteManager};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::AtomicU64;

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        /// A disposable state directory. It holds no real lock path.
        struct TestDirectory {
            root: PathBuf,
            state: PathBuf,
        }

        impl TestDirectory {
            fn new() -> Self {
                let unique = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "hotspotshade-start-lease-{}-{}",
                    std::process::id(),
                    unique
                ));
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(&root).unwrap();
                let state = root.join("state");
                Self { root, state }
            }

            fn state(&self) -> &Path {
                &self.state
            }

            fn intent_path(&self) -> PathBuf {
                direct_intent_path_for_test(&self.state)
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        /// A fake route command runner. It creates no route.
        #[derive(Default)]
        struct FakeRunner {
            install_panics: AtomicBool,
            cleanup_panics: AtomicBool,
            cleanup_fails: AtomicBool,
            deletes: AtomicU64,
        }

        impl CommandRunner for FakeRunner {
            fn run(&self, _program: &str, args: &[String]) -> io::Result<()> {
                if args.iter().any(|arg| arg == "add") {
                    if self.install_panics.swap(false, Ordering::AcqRel) {
                        // A panic inside install, not an error return.
                        std::panic::resume_unwind(Box::new("injected route install panic"));
                    }
                    return Ok(());
                }
                if args.iter().any(|arg| arg == "delete") {
                    self.deletes.fetch_add(1, Ordering::AcqRel);
                    if self.cleanup_panics.swap(false, Ordering::AcqRel) {
                        // A panic inside the explicit cleanup attempt.
                        std::panic::resume_unwind(Box::new("injected route cleanup panic"));
                    }
                    if self.cleanup_fails.load(Ordering::Acquire) {
                        return Err(io::Error::other("injected route cleanup failure"));
                    }
                }
                Ok(())
            }
        }

        /// Build the production lease and its durable direct start record.
        fn lease_with_intent(
            directory: &TestDirectory,
            leftover: &Arc<AtomicBool>,
        ) -> (MacosStartLease, Arc<AtomicBool>) {
            let lock = acquire_shared_for_test(directory.state()).unwrap();
            let mut lease = MacosStartLease::new(lock);
            let intent = create_direct_start_intent(lease.lock(), Arc::clone(leftover)).unwrap();
            lease.set_intent(intent);
            (lease, Arc::clone(leftover))
        }

        /// The clean early-failure helper removes the record and releases the
        /// lock without marking cleanup uncertainty.
        #[test]
        fn settle_clean_early_failure_removes_the_record_and_releases_the_lock() {
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let (mut lease, leftover) = lease_with_intent(&directory, &leftover);
            let service = Service::new();
            let mut inner = service.inner.lock().unwrap();
            let error = settle_macos_start(
                &mut inner,
                &mut lease,
                io::Error::other("injected early failure"),
            );
            assert_eq!(error.to_string(), "injected early failure");
            assert!(!inner.cleanup_blocked);
            assert!(!directory.intent_path().exists());
            assert!(!leftover.load(Ordering::Acquire));
            drop(inner);
            drop(acquire_exclusive_for_test(directory.state()).unwrap());
        }

        /// A record that cannot be removed is cleanup uncertainty. The helper
        /// marks the service and retains the shared lock.
        #[test]
        fn settle_retains_the_lock_when_record_removal_fails() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let (mut lease, leftover) = lease_with_intent(&directory, &leftover);
            let replacement = directory.root.join("replacement");
            std::fs::write(&replacement, b"replacement").unwrap();
            std::fs::rename(&replacement, directory.intent_path()).unwrap();
            let service = Service::new();
            let mut inner = service.inner.lock().unwrap();
            let error =
                settle_macos_start(&mut inner, &mut lease, io::Error::other("injected failure"));
            assert!(
                error.to_string().contains("could not be removed"),
                "{error}"
            );
            assert!(inner.cleanup_blocked);
            assert_eq!(
                std::fs::read(directory.intent_path()).unwrap(),
                b"replacement",
                "a replaced record must stay for recovery"
            );
            let lock_error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(lock_error.kind(), io::ErrorKind::WouldBlock);
            drop(inner);
            drop(lease);
            assert!(leftover.load(Ordering::Acquire));
        }

        /// A panicking start body must keep the shared lock and the record.
        #[test]
        fn a_start_panic_after_route_creation_retains_the_lock_and_record() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let runner = Arc::new(FakeRunner::default());
            let route_runner: Arc<dyn CommandRunner> = runner.clone();
            runner.cleanup_fails.store(true, Ordering::Release);
            let (lease, leftover) = lease_with_intent(&directory, &leftover);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // The lease and the routes share the panicking start-body
                // stack, as they do in production.
                let _lease = lease;
                let mut routes =
                    RouteManager::with_runner("utun7", true, Arc::clone(&route_runner)).unwrap();
                routes.install().unwrap();
                // The start body panics before it hands the resources to the
                // worker, and RouteManager::drop cannot remove the routes.
                std::panic::resume_unwind(Box::new("injected start-body panic"));
            }));
            assert!(outcome.is_err());
            assert!(
                runner.deletes.load(Ordering::Acquire) > 0,
                "the route manager must have attempted cleanup"
            );
            let error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(
                directory.intent_path().is_file(),
                "the durable start record must stay for recovery"
            );
            assert!(leftover.load(Ordering::Acquire));
        }

        /// A panic inside route install runs before any route is recorded, but
        /// the start still cannot prove cleanup. The lock and record stay.
        #[test]
        fn a_start_panic_during_route_install_retains_the_lock_and_record() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let runner = Arc::new(FakeRunner::default());
            let route_runner: Arc<dyn CommandRunner> = runner.clone();
            runner.install_panics.store(true, Ordering::Release);
            let (lease, leftover) = lease_with_intent(&directory, &leftover);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _lease = lease;
                let mut routes =
                    RouteManager::with_runner("utun8", true, Arc::clone(&route_runner)).unwrap();
                routes.install().unwrap();
            }));
            assert!(outcome.is_err());
            let error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(directory.intent_path().is_file());
            assert!(leftover.load(Ordering::Acquire));
        }

        /// A panic in the explicit cleanup attempt is still an unproved
        /// cleanup. The lease keeps the lock even when the later Drop cleanup
        /// happens to succeed.
        #[test]
        fn a_start_panic_during_route_cleanup_retains_the_lock_and_record() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let runner = Arc::new(FakeRunner::default());
            let route_runner: Arc<dyn CommandRunner> = runner.clone();
            let (lease, leftover) = lease_with_intent(&directory, &leftover);
            runner.cleanup_panics.store(true, Ordering::Release);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _lease = lease;
                let mut routes =
                    RouteManager::with_runner("utun9", true, Arc::clone(&route_runner)).unwrap();
                routes.install().unwrap();
                routes.remove().unwrap();
            }));
            assert!(outcome.is_err());
            assert!(
                runner.deletes.load(Ordering::Acquire) >= 1,
                "the cleanup attempt must have started"
            );
            let error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(directory.intent_path().is_file());
            assert!(leftover.load(Ordering::Acquire));
        }

        /// A clean early failure removes the record and releases the lock, so a
        /// later install can take the exclusive lock.
        #[test]
        fn a_clean_start_failure_releases_the_lock_and_removes_the_record() {
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let runner = Arc::new(FakeRunner::default());
            let route_runner: Arc<dyn CommandRunner> = runner.clone();
            let (mut lease, leftover) = lease_with_intent(&directory, &leftover);
            let mut routes =
                RouteManager::with_runner("utun9", true, Arc::clone(&route_runner)).unwrap();
            routes.install().unwrap();
            routes.remove().unwrap();
            assert!(!routes.has_installed_routes());
            drop(routes);
            lease.remove_intent().unwrap();
            lease.finish();
            assert!(!directory.intent_path().exists());
            assert!(!leftover.load(Ordering::Acquire));
            let exclusive = acquire_exclusive_for_test(directory.state()).unwrap();
            drop(exclusive);
        }

        /// A helper handoff owns no direct record, so a panic retains the
        /// shared lock without creating or removing `engine-session`.
        #[test]
        fn a_helper_start_panic_retains_the_lock_without_a_direct_record() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let lock = acquire_shared_for_test(directory.state()).unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _lease = MacosStartLease::new(lock);
                std::panic::resume_unwind(Box::new("injected helper start panic"));
            }));
            assert!(outcome.is_err());
            let error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(!directory.intent_path().exists());
        }

        /// A panic during the helper handoff poisons the service state and
        /// retains the shared lock. The helper owns the durable record, so no
        /// direct record appears here. The service must refuse a later start
        /// and never report a clean stop.
        #[test]
        fn a_helper_handoff_panic_poisons_the_service_and_keeps_the_lock() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let lock = acquire_shared_for_test(directory.state()).unwrap();
            let service = Service::new();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _inner = service.inner.lock().unwrap();
                let _lease = MacosStartLease::new(lock).into_worker_handoff();
                std::panic::resume_unwind(Box::new("injected helper handoff panic"));
            }));
            assert!(outcome.is_err());
            let error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(!directory.intent_path().exists());
            assert!(service.cleanup_uncertain());
            assert_eq!(service.status()["state"], "unknown");
            let error = service
                .start_socks_loopback("127.0.0.1:0".parse().unwrap(), None, None)
                .unwrap_err();
            assert_eq!(error.to_string(), SERVICE_STATE_UNAVAILABLE_MESSAGE);
            assert_eq!(
                service.stop_checked().unwrap_err().to_string(),
                CLEANUP_UNCERTAIN_MESSAGE
            );
        }

        /// A direct start panic keeps its durable record and poisons the
        /// service state. The lock and record stay, and the next start refuses.
        #[test]
        fn a_direct_start_panic_poisons_the_service_and_keeps_the_record() {
            let _serial = retained_lock_serial_for_test();
            let directory = TestDirectory::new();
            let leftover = Arc::new(AtomicBool::new(false));
            let (lease, leftover) = lease_with_intent(&directory, &leftover);
            let service = Service::new();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _inner = service.inner.lock().unwrap();
                let _lease = lease.into_worker_handoff();
                std::panic::resume_unwind(Box::new("injected direct start panic"));
            }));
            assert!(outcome.is_err());
            assert!(directory.intent_path().is_file());
            assert!(leftover.load(Ordering::Acquire));
            let error = acquire_exclusive_for_test(directory.state()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(service.cleanup_uncertain());
            let error = service
                .start_socks_loopback("127.0.0.1:0".parse().unwrap(), None, None)
                .unwrap_err();
            assert_eq!(error.to_string(), SERVICE_STATE_UNAVAILABLE_MESSAGE);
        }
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
    fn a_frozen_phone_index_must_match_the_resolved_index() {
        assert!(Service::verify_expected_outer_index(None, 7).is_ok());
        assert!(Service::verify_expected_outer_index(Some(7), 7).is_ok());
        let error = Service::verify_expected_outer_index(Some(7), 8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "outer_interface_changed");
    }
    #[test]
    fn the_physical_interface_guard_rejects_tunnel_names_and_keeps_names() {
        for name in [
            "",
            "none",
            "utun",
            "utun3",
            "hs-tun0",
            "hs-tun",
            "HotspotShade-Tunnel",
            "HotspotShade-Tunnel-7",
        ] {
            let error = Service::check_physical_interface_name(name).unwrap_err();
            assert_eq!(error.to_string(), "a physical interface is required");
        }
        for name in ["en0", "wlan0", "eth0", "Wi-Fi", "5"] {
            assert!(
                Service::check_physical_interface_name(name).is_ok(),
                "{name}"
            );
        }
    }
    #[test]
    fn a_numeric_interface_returns_the_resolved_name() {
        // A numeric caller value must not be used as a name later. A named
        // value is kept as written, so a Windows alias still reads the same.
        assert_eq!(Service::interface_name_for_result("7", "en0"), "en0");
        assert_eq!(Service::interface_name_for_result("07", "en0"), "en0");
        assert_eq!(Service::interface_name_for_result("0", "en0"), "0");
        assert_eq!(Service::interface_name_for_result("en0", "en0"), "en0");
        assert_eq!(
            Service::interface_name_for_result("Wi-Fi", "Intel Adapter"),
            "Wi-Fi"
        );
    }
    #[test]
    fn a_phone_route_change_stops_the_token_check() {
        let host: Ipv4Addr = "172.20.10.1".parse().unwrap();
        let gateway: Option<Ipv4Addr> = Some(host);
        assert!(
            Service::verify_phone_route(host, "hs-test5", 5, Some((gateway, "hs-test5", 5)))
                .is_ok()
        );
        // The interface name now maps to another index.
        let error =
            Service::verify_phone_route(host, "hs-test5", 5, Some((gateway, "hs-test6", 6)))
                .unwrap_err();
        assert_eq!(error.to_string(), "outer_interface_changed");
        // The default route now names another gateway.
        let other: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let error =
            Service::verify_phone_route(host, "hs-test5", 5, Some((Some(other), "hs-test5", 5)))
                .unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // A route with no gateway is not the source device.
        let error = Service::verify_phone_route(host, "hs-test5", 5, Some((None, "hs-test5", 5)))
            .unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // A missing route is not evidence that the source device is there.
        let error = Service::verify_phone_route(host, "hs-test5", 5, None).unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
    }
    #[test]
    fn a_cli_phone_without_a_frozen_index_is_checked_against_the_gateway_and_route() {
        // The CLI leaves `iface` unset. The route check must not depend on that
        // field. The default route proves the source device on the common path.
        // A selected non-default interface must route to the host directly.
        let host: Ipv4Addr = "172.20.10.1".parse().unwrap();
        let phone = phone::PhoneProxy {
            address: SocketAddr::from((host, 18080)),
            username: "hotspotshade".into(),
            token: "test".into(),
            iface: None,
            timeout: Duration::from_secs(1),
        };
        assert!(phone.iface.is_none());
        let host = Service::phone_target_host(phone.address).unwrap();
        let default = Some((Some(host), "en5", 5));
        let unicast = |ifindex, gateway, on_link_prefix| PhoneRoute {
            ifindex,
            gateway,
            on_link_prefix,
            route_type: RTN_UNICAST,
        };

        // The selected interface is the default and the host is its gateway.
        assert!(Service::verify_phone_destination(
            host,
            "en5",
            5,
            default,
            Some(unicast(5, None, true))
        )
        .is_ok());
        // A typo to another host on the same hotspot link is refused even when
        // the kernel would send to it on-link.
        let typed: Ipv4Addr = "172.20.10.11".parse().unwrap();
        let error = Service::verify_phone_destination(
            typed,
            "en5",
            5,
            default,
            Some(unicast(5, None, true)),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // The selected interface is not the system default. The documented
        // explicit-interface case accepts an on-link host on that interface.
        let wifi = Some((Some("192.168.1.1".parse().unwrap()), "wlan0", 6));
        assert!(Service::verify_phone_destination(
            host,
            "en5",
            5,
            wifi,
            Some(unicast(5, None, true))
        )
        .is_ok());
        // The host can also be the next hop through the selected interface.
        assert!(Service::verify_phone_destination(
            host,
            "en5",
            5,
            wifi,
            Some(unicast(5, Some(host), false))
        )
        .is_ok());
        // A route through another interface or another gateway is refused.
        let error =
            Service::verify_phone_destination(host, "en5", 5, wifi, Some(unicast(6, None, true)))
                .unwrap_err();
        assert_eq!(error.to_string(), "outer_interface_changed");
        let other: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let error = Service::verify_phone_destination(
            host,
            "en5",
            5,
            wifi,
            Some(unicast(5, Some(other), false)),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // A missing default route or no selected route is refused.
        let error = Service::verify_phone_destination(host, "en5", 5, None, None).unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        let error = Service::verify_phone_destination(host, "en5", 5, wifi, None).unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // The default-gateway path also requires an observed route. A failed,
        // unsupported, dead, or link-down lookup reaches this function as
        // `None`, so the matching default route alone is not enough.
        let error = Service::verify_phone_destination(host, "en5", 5, default, None).unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // A non-unicast route fails closed on the default path as well.
        let error = Service::verify_phone_destination(
            host,
            "en5",
            5,
            default,
            Some(PhoneRoute {
                ifindex: 5,
                gateway: Some(host),
                on_link_prefix: false,
                route_type: RTN_LOCAL,
            }),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        // An observed route through another interface fails even when the
        // default route matches the selected interface.
        let error = Service::verify_phone_destination(
            host,
            "en5",
            5,
            default,
            Some(unicast(6, None, true)),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "outer_interface_changed");
        // An IPv6 source device is refused before any token check.
        let error = Service::phone_target_host("[2001:db8::1]:18080".parse().unwrap()).unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
    }

    #[test]
    fn a_phone_check_is_not_reached_for_a_disallowed_interface_or_local_route() {
        // Hermetic regression for the token-order finding. The guard runs
        // before the closure that would use the token. A loopback or VPN name
        // and a local route must return an error without calling it.
        let host: Ipv4Addr = "172.20.10.1".parse().unwrap();
        let default = Some((Some(host), "en5", 5));
        let checked = std::cell::Cell::new(false);
        let guard = |interface: &str, route_type: u8| {
            // This closure stands in for `phone.check_cancellable`. It records
            // any token use, so the assertion proves that none happened.
            Service::verify_phone_destination(
                host,
                interface,
                5,
                default,
                Some(PhoneRoute {
                    ifindex: 5,
                    gateway: None,
                    on_link_prefix: true,
                    route_type,
                }),
            )
            .map(|()| checked.set(true))
        };
        for interface in ["lo", "lo0", "utun3", "tun0", "tap0", "wg0", "tailscale0"] {
            let error = guard(interface, RTN_UNICAST).unwrap_err();
            assert_eq!(error.to_string(), "a physical interface is required");
            assert!(!checked.get(), "{interface} reached the token check");
        }
        // A local route names an address on this host. An oif and prefix match
        // is not proof that the source device is reachable through the hotspot.
        let error = guard("en5", RTN_LOCAL).unwrap_err();
        assert_eq!(error.to_string(), "source_device_moved");
        assert!(!checked.get(), "a local route reached the token check");
    }
    #[cfg(any(windows, test))]
    #[test]
    fn a_windows_phone_index_change_is_refused_before_the_phone_check() {
        let state = Arc::new(FakeWindowsState::default());
        let mut runtime = FakeWindowsRuntime::new(state.clone());
        runtime.elevated = true;
        let service = Service::new();
        let mut phone = fake_phone();
        phone.iface = Some(999);
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(phone),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "outer_interface_changed");
        assert_eq!(state.count("phone_check"), 0);
        assert_eq!(state.count("wintun_load"), 0);
        assert_eq!(state.count("device_open"), 0);
    }
    #[cfg(unix)]
    #[test]
    fn explicit_dns_does_not_relax_the_socks_interface_guard() {
        let service = Service::new();
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        // A loopback listener with a public resolver is refused. The loopback
        // pair remains the hermetic test seam only when the resolver is also
        // loopback.
        let error = service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some(iface),
                Some(vec!["192.0.2.53:53".parse().unwrap()]),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "a physical interface is required");
        assert!(!service.is_running());
        // An empty explicit list is an error, not a silent discovery fallback.
        let error = service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some(iface),
                Some(Vec::new()),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!service.is_running());
        // A malformed or oversized list is rejected before a listener starts.
        let too_many = (0..=dns::MAX_EXPLICIT_SERVERS)
            .map(|index| format!("192.0.2.{index}:53").parse().unwrap())
            .collect::<Vec<SocketAddr>>();
        let error = service
            .start_socks("127.0.0.1:0".parse().unwrap(), Some(iface), Some(too_many))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!service.is_running());
        // A tunnel or VPN name is refused even with a loopback resolver. The
        // resolver must not relax the interface guard.
        let error = service
            .start_socks(
                "127.0.0.1:0".parse().unwrap(),
                Some("hs-tun0"),
                Some(vec!["127.0.0.1:53".parse().unwrap()]),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "a physical interface is required");
        assert!(!service.is_running());
        // The same pair through a VPN-shaped name is refused by the guard, not
        // accepted because every resolver is loopback.
        for name in ["utun4", "utun5"] {
            let error = service
                .start_socks(
                    "127.0.0.1:0".parse().unwrap(),
                    Some(name),
                    Some(vec!["127.0.0.1:53".parse().unwrap()]),
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name}");
            assert_eq!(
                error.to_string(),
                "a physical interface is required",
                "{name}"
            );
        }
        // A VPN name that is not on the early tunnel list is still refused by
        // the selection guard before any DNS query can run.
        for name in ["wg0", "tailscale0", "docker0"] {
            let error =
                Service::validate_socks_selection(name, &["127.0.0.1:53".parse().unwrap()], false)
                    .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name}");
            assert_eq!(
                error.to_string(),
                "a physical interface is required",
                "{name}"
            );
        }
        // A physical interface with a loopback resolver is still a local stub,
        // so a production start refuses it. This uses the value guard directly
        // so the test does not depend on a live interface name.
        let error =
            Service::validate_socks_selection("en5", &["127.0.0.1:53".parse().unwrap()], false)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "a loopback DNS server is not allowed");
        let mapped = "[::ffff:127.0.0.1]:53".parse().unwrap();
        assert_eq!(
            Service::validate_socks_selection("en5", &[mapped], false)
                .unwrap_err()
                .to_string(),
            "a loopback DNS server is not allowed"
        );
        // A mixed list that includes a loopback stub is refused as a whole.
        let error = Service::validate_socks_selection(
            "en5",
            &[
                "192.0.2.53:53".parse().unwrap(),
                "[::1]:5353".parse().unwrap(),
            ],
            false,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "a loopback DNS server is not allowed");
        // The test seam is the only place that may accept the pair.
        assert!(
            Service::validate_socks_selection("lo0", &["127.0.0.1:53".parse().unwrap()], true)
                .is_ok()
        );
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
            .start_socks_loopback(
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
            .start_socks_loopback(
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
        /// When set, the fake source device check returns the token gate
        /// refusal instead of contacting a source device.
        token_gate_refused: AtomicBool,
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

    /// The physical adapter that the fake token gate reports.
    #[cfg(any(windows, test))]
    fn fake_outer_adapter() -> crate::windows_route_verify::RetainedAdapterIdentity {
        crate::windows_route_verify::RetainedAdapterIdentity::new(
            9,
            0x0000_6000_0000_0009,
            crate::windows_route_verify::AdapterGuid::new(
                0x0909_0909,
                0x0909,
                0x0909,
                [9, 9, 9, 9, 9, 9, 9, 9],
            ),
        )
        .unwrap()
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

        fn check_phone(
            &self,
            _phone: &phone::PhoneProxy,
            _cancel: &AtomicBool,
        ) -> io::Result<crate::windows_route_verify::RetainedAdapterIdentity> {
            self.state.record("phone_check");
            if self.state.token_gate_refused.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    crate::windows_route_verify::TOKEN_DESTINATION_REFUSED,
                ));
            }
            Ok(fake_outer_adapter())
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
        assert_eq!(
            service.status()["iface"],
            Service::canonical_interface_name(1).unwrap()
        );
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
    fn windows_token_run_binding_is_reported_only_while_the_phone_run_is_live() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime::new(state.clone());
        let service = Service::new();
        assert_eq!(service.windows_phone_run(), None);
        service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap();
        let current = service.windows_phone_run().unwrap();
        assert_eq!(current.run.tunnel.interface_index, 1);
        assert_eq!(
            current.run.tunnel.interface_luid,
            fake_route_identity().luid()
        );
        // The physical adapter is the one that the start gate proved.
        assert_eq!(current.run.outer, fake_outer_adapter());
        assert_eq!(current.destination, fake_phone().address);
        assert_eq!(current.iface, normalization::interface_index("1").unwrap());
        service.stop();
        assert_eq!(service.windows_phone_run(), None);
    }

    #[cfg(any(windows, test))]
    #[test]
    fn windows_token_gate_refusal_stops_the_start_before_any_device() {
        let state = Arc::new(FakeWindowsState::default());
        state.token_gate_refused.store(true, Ordering::Release);
        let runtime = FakeWindowsRuntime::new(state.clone());
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
        assert_eq!(
            error.to_string(),
            crate::windows_route_verify::TOKEN_DESTINATION_REFUSED
        );
        assert_eq!(state.count("phone_check"), 1);
        assert_eq!(state.count("device_open"), 0);
        assert_eq!(state.count("routes_install"), 0);
        assert!(!service.is_running());
        assert_eq!(service.windows_phone_run(), None);
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

    /// A leftover direct start record is cleanup uncertainty even when no
    /// route cleanup failed. The file blocks the next start; the exit path must
    /// report the same failure.
    #[cfg(unix)]
    #[test]
    fn a_leftover_direct_start_record_blocks_a_stop_and_a_start() {
        let service = Service::new();
        service
            .inner
            .lock()
            .unwrap()
            .direct_record_uncertain
            .store(true, Ordering::Release);
        assert!(service.cleanup_uncertain());
        assert!(service.stop_checked().is_err());
        assert_eq!(service.status()["cleanup_blocked"], true);
        {
            let inner = service.inner.lock().unwrap();
            // The direct record flag alone is enough. The start gate must not
            // depend on a route cleanup failure also setting cleanup_blocked.
            assert!(!inner.cleanup_blocked);
            assert!(inner.cleanup_uncertain());
        }
        let error = service
            .start_socks_loopback("127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err();
        assert!(
            error.to_string().contains("route cleanup failed"),
            "{error}"
        );
    }

    #[test]
    fn poisoned_service_state_never_reports_a_clean_stop() {
        let service = Service::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = service.inner.lock().unwrap();
            panic!("simulated interrupted service operation");
        }));
        assert!(panic.is_err());
        assert!(service.cleanup_uncertain());
        assert_eq!(
            service.stop_checked().unwrap_err().to_string(),
            CLEANUP_UNCERTAIN_MESSAGE
        );
        assert!(service.cleanup_uncertain());
        assert!(service.stop_checked().is_err());
    }

    /// A poisoned state with no active tunnel is still not a stopped tunnel: a
    /// panic can happen after a route or device exists and before `active` is
    /// set. The read paths report the fixed uncertainty, and every start
    /// refuses with the fixed message.
    #[cfg(unix)]
    #[test]
    fn a_poisoned_service_reports_unknown_and_refuses_a_start() {
        let service = Service::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = service.inner.lock().unwrap();
            panic!("simulated interrupted service operation");
        }));
        assert!(panic.is_err());

        let status = service.status();
        assert_eq!(status["running"], true);
        assert_eq!(status["state"], "unknown");
        assert_eq!(status["cleanup_blocked"], true);
        assert_eq!(status["error"], SERVICE_STATE_UNAVAILABLE_MESSAGE);
        assert_eq!(status["logs"], json!([]));
        assert!(service.is_running());
        assert!(service.cleanup_uncertain());

        let diagnostics = service.diagnostics();
        assert_eq!(diagnostics["ok"], false);
        assert_eq!(diagnostics["running"], true);
        assert_eq!(diagnostics["state"], "unknown");
        assert_eq!(diagnostics["error"], SERVICE_STATE_UNAVAILABLE_MESSAGE);

        let failures = service.failures();
        assert_eq!(failures["ok"], false);
        assert_eq!(failures["state"], "unknown");

        let error = service
            .start_socks_loopback("127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err();
        assert_eq!(error.to_string(), SERVICE_STATE_UNAVAILABLE_MESSAGE);

        // Cleanup still runs, and it still reports uncertainty.
        assert_eq!(
            service.stop_checked().unwrap_err().to_string(),
            CLEANUP_UNCERTAIN_MESSAGE
        );
        // The GUI start-panic path recovers the state to mark the fault
        // instead of panicking on the poisoned mutex.
        service.mark_start_panic();
        assert!(service.cleanup_uncertain());
        // The mutex stays poisoned, so a later start refuses the same way.
        let error = service
            .start_socks_loopback("127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err();
        assert_eq!(error.to_string(), SERVICE_STATE_UNAVAILABLE_MESSAGE);
        assert_eq!(service.status()["state"], "unknown");
    }

    /// The Windows source device start reaches the shared state before any
    /// adapter or route. A poisoned state refuses there and creates nothing.
    #[cfg(any(windows, test))]
    #[test]
    fn a_poisoned_service_refuses_a_windows_start_before_any_device() {
        let state = Arc::new(FakeWindowsState::default());
        let runtime = FakeWindowsRuntime::new(state.clone());
        let service = Service::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = service.inner.lock().unwrap();
            panic!("simulated interrupted service operation");
        }));
        assert!(panic.is_err());
        let error = service
            .start_windows_tunnel_with(
                fake_windows_options(),
                Some(fake_phone()),
                1,
                &AtomicBool::new(false),
                &runtime,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), SERVICE_STATE_UNAVAILABLE_MESSAGE);
        assert!(state.events().is_empty(), "{:?}", state.events());
        assert_eq!(service.status()["cleanup_blocked"], true);
    }

    /// The poison handling does not change the clean path. A fresh service
    /// still reports idle and a proved clean stop.
    #[cfg(unix)]
    #[test]
    fn a_clean_service_still_reports_a_clean_stop() {
        let service = Service::new();
        assert!(!service.cleanup_uncertain());
        assert!(!service.is_running());
        let status = service.status();
        assert_eq!(status["running"], false);
        assert_eq!(status["cleanup_blocked"], false);
        assert_eq!(status.get("state"), None);
        assert_eq!(service.diagnostics(), crate::diagnostics::empty());
        assert_eq!(service.failures(), crate::failures::empty_snapshot());
        assert!(service.stop_checked().is_ok());
    }

    /// A worker join fault is a cleanup fault. The stop that joins it, every
    /// later stop, and the process exit must all report it. The fake worker
    /// panics with `resume_unwind`; no panic hook and no real worker exist.
    #[cfg(unix)]
    #[test]
    fn a_panicked_tunnel_worker_blocks_a_stop_and_a_restart() {
        let service = Service::new();
        let handle = std::thread::spawn(|| {
            std::panic::resume_unwind(Box::new("injected worker panic"));
        });
        while !handle.is_finished() {
            std::thread::yield_now();
        }
        {
            let mut inner = service.inner.lock().unwrap();
            inner.active = Some(Active::Tun {
                stop: Arc::new(AtomicBool::new(false)),
                handle,
                stats: Arc::new(Mutex::new(json!({}))),
                diag: Arc::new(Mutex::new(json!({}))),
                fault: Arc::new(Mutex::new(None)),
                auto_stop: Arc::new(Mutex::new(None)),
            });
        }
        assert!(service.cleanup_uncertain());
        let status = service.status();
        assert_eq!(status["running"], false);
        assert_eq!(status["cleanup_blocked"], true);
        assert!(service.stop_checked().is_err());
        assert!(service.cleanup_uncertain());
        let error = service
            .start_socks_loopback("127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err();
        assert!(error.to_string().contains("route cleanup failed"));
    }

    mod windows_direct_tests {
        use super::*;
        use crate::windows_native_routes::{AdapterGuid, AdapterIdentity};
        use crate::windows_route_verify::{
            Ipv6RoutePolicy, LocalSubnetProvenance, ProvenLocalSubnet, RetainedAdapterIdentity,
            RoutePrefix,
        };
        use std::net::IpAddr;
        use std::sync::atomic::AtomicUsize;

        const OUTER_LUID: u64 = 0x0000_6000_0000_0101;
        const OUTER_SUBNET: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 0);
        const TUNNEL_INDEX: u32 = 7000;

        fn outer_guid() -> AdapterGuid {
            AdapterGuid::new(
                0x0102_0304,
                0x0506,
                0x0708,
                [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10],
            )
        }

        fn outer_identity(index: u32) -> RetainedAdapterIdentity {
            RetainedAdapterIdentity::new(index, OUTER_LUID, outer_guid().route_verify_guid())
                .unwrap()
        }

        fn outer_subnet(index: u32) -> ProvenLocalSubnet {
            let prefix = RoutePrefix::new(IpAddr::V4(OUTER_SUBNET), 28).unwrap();
            ProvenLocalSubnet::new(
                prefix,
                outer_identity(index),
                LocalSubnetProvenance::LocalInterface,
            )
            .unwrap()
        }

        fn outer_ipv6_subnet(index: u32) -> ProvenLocalSubnet {
            let prefix = RoutePrefix::new(
                IpAddr::V6(std::net::Ipv6Addr::new(
                    0x2606, 0x4700, 0x1234, 0, 0, 0, 0, 0,
                )),
                64,
            )
            .unwrap();
            ProvenLocalSubnet::new(
                prefix,
                outer_identity(index),
                LocalSubnetProvenance::LocalInterface,
            )
            .unwrap()
        }

        fn outer_proof(index: u32) -> WindowsOuterAdapterProof {
            WindowsOuterAdapterProof::new(
                "Ethernet 2",
                index,
                outer_identity(index),
                outer_subnet(index),
                true,
                true,
                true,
                normalization::OUTER_TTL,
                index,
                index,
                0,
            )
            .unwrap()
        }

        fn direct_options(ipv6: Ipv6Policy) -> TunOptions {
            TunOptions {
                unit: 9,
                iface: Some("1".into()),
                ipv6,
                wintun_dll: Some(std::env::temp_dir().join("wintun.dll")),
                ..TunOptions::default()
            }
        }

        #[derive(Clone, Debug)]
        struct FakeDirectRelayConfig {
            iface: Option<u32>,
            phone_present: bool,
            dns_upstream: Option<SocketAddr>,
            workers: usize,
            ipv6_forward: bool,
            allow_unpinned: bool,
            icmp_phone: bool,
            icmp_persistent: bool,
            failures_present: bool,
        }

        #[derive(Default)]
        struct FakeDirectState {
            events: Mutex<Vec<&'static str>>,
            route_records: Mutex<usize>,
            device_drops: AtomicUsize,
            route_context: Mutex<Option<WindowsDirectRouteContext>>,
            relay_config: Mutex<Option<FakeDirectRelayConfig>>,
            relay_started: AtomicUsize,
            relay_stops: AtomicUsize,
            link_observations: AtomicUsize,
        }

        impl FakeDirectState {
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

            fn position(&self, event: &'static str) -> usize {
                self.events()
                    .iter()
                    .position(|value| *value == event)
                    .unwrap_or_else(|| panic!("missing event {event}: {:?}", self.events()))
            }
        }

        struct FakeDirectDevice {
            state: Arc<FakeDirectState>,
            ifindex: u32,
            identity: AdapterIdentity,
        }

        impl Drop for FakeDirectDevice {
            fn drop(&mut self) {
                self.state.device_drops.fetch_add(1, Ordering::AcqRel);
                self.state.record("device_drop");
            }
        }

        impl WindowsWintunDevice for FakeDirectDevice {
            fn ifname(&self) -> &str {
                "HotspotShade-Tunnel-Direct"
            }

            fn ifindex(&self) -> u32 {
                self.ifindex
            }

            fn configure_link(&mut self, _addr: Ipv4Addr, _mtu: u32) -> io::Result<()> {
                self.state.record("device_configure");
                Ok(())
            }

            fn route_identity(&mut self) -> io::Result<AdapterIdentity> {
                self.state.record("device_identity");
                Ok(self.identity)
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

        struct FakeDirectRoutes {
            state: Arc<FakeDirectState>,
            install_error_after: Option<usize>,
            remove_error: bool,
            verify_error: bool,
            cancel_on_verify: Option<Arc<AtomicBool>>,
        }

        impl WindowsDirectRouteController for FakeDirectRoutes {
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

            fn verify(&mut self, context: &WindowsDirectRouteContext) -> io::Result<()> {
                self.state.record("routes_verify");
                *self.state.route_context.lock().unwrap() = Some(context.clone());
                if let Some(cancel) = &self.cancel_on_verify {
                    cancel.store(true, Ordering::Release);
                }
                if self.verify_error {
                    return Err(io::Error::other("route verification failed"));
                }
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

        struct FakeDirectLink {
            state: Arc<FakeDirectState>,
            up: bool,
            error: bool,
            pinned_index: u32,
            index_after: Option<u32>,
            index_change_after: usize,
            removed_after: Option<usize>,
        }

        impl WindowsDirectLinkObserver for FakeDirectLink {
            fn observe(&self) -> io::Result<WindowsDirectLinkSample> {
                let seen = self.state.link_observations.fetch_add(1, Ordering::AcqRel) + 1;
                if seen == 1 {
                    self.state.record("link_observe");
                }
                if self.error {
                    return Err(io::Error::other("link observation unknown"));
                }
                let removed = self.removed_after.is_some_and(|after| seen >= after);
                let interface_index = if removed {
                    None
                } else if let Some(index) =
                    self.index_after.filter(|_| seen >= self.index_change_after)
                {
                    Some(index)
                } else {
                    Some(self.pinned_index)
                };
                Ok(WindowsDirectLinkSample {
                    up: self.up,
                    interface_index,
                })
            }
        }

        struct FakeDirectRelay {
            state: Arc<FakeDirectState>,
            running: AtomicBool,
        }

        impl WindowsDirectRelay for FakeDirectRelay {
            fn is_running(&self) -> bool {
                self.running.load(Ordering::Acquire)
            }

            fn dispatch(&self, _packet: Vec<u8>) -> io::Result<()> {
                Ok(())
            }

            fn try_receive(&self) -> Option<Vec<u8>> {
                None
            }

            fn stop(&mut self) {
                self.running.store(false, Ordering::Release);
                self.state.relay_stops.fetch_add(1, Ordering::AcqRel);
                self.state.record("relay_stop");
            }

            fn stats(&self) -> crate::relay::RelayStats {
                crate::relay::RelayStats::default()
            }

            fn diagnostics(&self) -> Value {
                json!({})
            }
        }

        struct FakeDirectRuntime {
            state: Arc<FakeDirectState>,
            elevated: bool,
            device_ifindex: u32,
            device_identity: AdapterIdentity,
            proof_index_offset: u32,
            install_error_after: Option<usize>,
            remove_error: bool,
            verify_error: bool,
            relay_error: bool,
            cancel_on_verify: Option<Arc<AtomicBool>>,
            cancel_on_link_bind: Option<Arc<AtomicBool>>,
            cancel_on_relay_start: Option<Arc<AtomicBool>>,
            link_up: bool,
            link_error: bool,
            link_index_after: Option<u32>,
            link_index_change_after: usize,
            link_removed_after: Option<usize>,
            link_poll_interval: Duration,
            link_down_limit: Duration,
        }

        impl FakeDirectRuntime {
            fn new(state: Arc<FakeDirectState>) -> Self {
                Self {
                    state,
                    elevated: true,
                    device_ifindex: TUNNEL_INDEX,
                    device_identity: fake_route_identity(),
                    proof_index_offset: 0,
                    install_error_after: None,
                    remove_error: false,
                    verify_error: false,
                    relay_error: false,
                    cancel_on_verify: None,
                    cancel_on_link_bind: None,
                    cancel_on_relay_start: None,
                    link_up: true,
                    link_error: false,
                    link_index_after: None,
                    link_index_change_after: 1,
                    link_removed_after: None,
                    link_poll_interval: Duration::from_millis(5),
                    link_down_limit: Duration::from_millis(15),
                }
            }
        }

        impl WindowsDirectTunnelRuntime for FakeDirectRuntime {
            fn is_elevated(&self) -> bool {
                self.elevated
            }

            fn load_wintun(&self, _wintun_dll: &std::path::Path) -> io::Result<()> {
                self.state.record("wintun_load");
                Ok(())
            }

            fn prove_outer_adapter(
                &self,
                _ifname: &str,
                ifindex: u32,
            ) -> io::Result<WindowsOuterAdapterProof> {
                self.state.record("outer_prove");
                let proof_index = ifindex.saturating_add(self.proof_index_offset);
                Ok(outer_proof(proof_index))
            }

            fn open_device(
                &self,
                _unit: u32,
                _wintun_dll: &std::path::Path,
            ) -> io::Result<Box<dyn WindowsWintunDevice>> {
                self.state.record("device_open");
                Ok(Box::new(FakeDirectDevice {
                    state: self.state.clone(),
                    ifindex: self.device_ifindex,
                    identity: self.device_identity,
                }))
            }

            fn open_routes(
                &self,
                context: WindowsDirectRouteContext,
            ) -> io::Result<Box<dyn WindowsDirectRouteController>> {
                self.state.record("routes_open");
                assert_eq!(context.tunnel_adapter().luid(), self.device_identity.luid());
                assert_eq!(context.tunnel_adapter().guid(), self.device_identity.guid());
                Ok(Box::new(FakeDirectRoutes {
                    state: self.state.clone(),
                    install_error_after: self.install_error_after,
                    remove_error: self.remove_error,
                    verify_error: self.verify_error,
                    cancel_on_verify: self.cancel_on_verify.clone(),
                }))
            }

            fn bind_link_observer(
                &self,
                proof: &WindowsOuterAdapterProof,
            ) -> io::Result<Box<dyn WindowsDirectLinkObserver>> {
                self.state.record("link_bind");
                assert_eq!(proof.ifname(), "Ethernet 2");
                // The binding must use the exact retained identity, not a
                // fresh alias lookup.
                assert_eq!(proof.adapter().interface_index(), proof.ifindex());
                assert_eq!(proof.adapter().interface_luid(), OUTER_LUID);
                assert_eq!(
                    proof.adapter().interface_guid(),
                    outer_guid().route_verify_guid()
                );
                if let Some(cancel) = &self.cancel_on_link_bind {
                    cancel.store(true, Ordering::Release);
                }
                Ok(Box::new(FakeDirectLink {
                    state: self.state.clone(),
                    up: self.link_up,
                    error: self.link_error,
                    pinned_index: proof.ifindex(),
                    index_after: self.link_index_after,
                    index_change_after: self.link_index_change_after,
                    removed_after: self.link_removed_after,
                }))
            }

            fn start_relay(
                &self,
                config: &crate::relay::RelayConfig,
            ) -> io::Result<Box<dyn WindowsDirectRelay>> {
                self.state.record("relay_start");
                self.state.relay_started.fetch_add(1, Ordering::AcqRel);
                if let Some(cancel) = &self.cancel_on_relay_start {
                    cancel.store(true, Ordering::Release);
                }
                *self.state.relay_config.lock().unwrap() = Some(FakeDirectRelayConfig {
                    iface: config.iface,
                    phone_present: config.phone.is_some(),
                    dns_upstream: config.dns_upstream,
                    workers: config.workers,
                    ipv6_forward: config.ipv6_forward,
                    allow_unpinned: config.allow_unpinned,
                    icmp_phone: config.icmp_phone,
                    icmp_persistent: config.icmp_persistent,
                    failures_present: config.failures.is_some(),
                });
                if self.relay_error {
                    return Err(io::Error::other("relay failed"));
                }
                Ok(Box::new(FakeDirectRelay {
                    state: self.state.clone(),
                    running: AtomicBool::new(true),
                }))
            }

            fn link_poll_interval(&self) -> Duration {
                self.link_poll_interval
            }

            fn link_down_limit(&self) -> Duration {
                self.link_down_limit
            }
        }

        fn relay_config(state: &FakeDirectState) -> FakeDirectRelayConfig {
            state
                .relay_config
                .lock()
                .unwrap()
                .clone()
                .expect("no relay was started")
        }

        fn route_context(state: &FakeDirectState) -> WindowsDirectRouteContext {
            state
                .route_context
                .lock()
                .unwrap()
                .clone()
                .expect("routes were not verified")
        }

        #[test]
        fn windows_direct_outer_proof_rejects_unsafe_evidence() {
            let valid = outer_proof(12);
            assert_eq!(valid.ifindex(), 12);
            assert_eq!(valid.ifname(), "Ethernet 2");
            assert_eq!(valid.local_subnet().prefix().length, 28);
            let invalid = |proof: io::Result<WindowsOuterAdapterProof>| {
                assert_eq!(proof.unwrap_err().to_string(), "outer_adapter_unverified");
            };
            let adapter = outer_identity(12);
            let subnet = outer_subnet(12);
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi", 12, adapter, subnet, true, true, true, 64, 12, 12, 0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                subnet,
                true,
                true,
                true,
                normalization::OUTER_TTL,
                11,
                12,
                0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                subnet,
                true,
                true,
                true,
                normalization::OUTER_TTL,
                12,
                13,
                0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                subnet,
                true,
                true,
                true,
                normalization::OUTER_TTL,
                12,
                12,
                1,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                subnet,
                false,
                true,
                true,
                normalization::OUTER_TTL,
                12,
                12,
                0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                subnet,
                true,
                false,
                true,
                normalization::OUTER_TTL,
                12,
                12,
                0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                subnet,
                true,
                true,
                false,
                normalization::OUTER_TTL,
                12,
                12,
                0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "utun4",
                12,
                adapter,
                subnet,
                true,
                true,
                true,
                normalization::OUTER_TTL,
                12,
                12,
                0,
            ));
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                outer_subnet(13),
                true,
                true,
                true,
                normalization::OUTER_TTL,
                12,
                12,
                0,
            ));
            // The required local subnet is IPv4. An IPv6 prefix belongs in the
            // separate optional list, which validates its own binding.
            invalid(WindowsOuterAdapterProof::new(
                "Wi-Fi",
                12,
                adapter,
                outer_ipv6_subnet(12),
                true,
                true,
                true,
                normalization::OUTER_TTL,
                12,
                12,
                0,
            ));
            assert_eq!(outer_proof(12).adapter().interface_luid(), OUTER_LUID);
        }

        #[test]
        fn windows_direct_outer_proof_binds_ipv6_subnets_to_the_outer_adapter() {
            let subnet = outer_ipv6_subnet(12);
            let proof = outer_proof(12).with_ipv6_local_subnet(subnet).unwrap();
            assert_eq!(proof.ipv6_local_subnets(), &[subnet]);
            assert_eq!(proof.ipv6_local_subnets()[0].adapter(), proof.adapter());

            let invalid = |proof: io::Result<WindowsOuterAdapterProof>| {
                assert_eq!(proof.unwrap_err().to_string(), "outer_adapter_unverified");
            };
            // Another adapter, or another proof source, is not this adapter's
            // local interface evidence.
            invalid(outer_proof(12).with_ipv6_local_subnet(outer_ipv6_subnet(13)));
            let authenticated = ProvenLocalSubnet::new(
                subnet.prefix(),
                outer_identity(12),
                LocalSubnetProvenance::AuthenticatedSourceDevice,
            )
            .unwrap();
            invalid(outer_proof(12).with_ipv6_local_subnet(authenticated));
            // The required local subnet is IPv4, and this field is IPv6 only.
            invalid(outer_proof(12).with_ipv6_local_subnet(outer_subnet(12)));
            // A prefix outside 2000::/3 cannot cover a managed route.
            let ula = ProvenLocalSubnet::new(
                RoutePrefix::new(
                    IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
                    64,
                )
                .unwrap(),
                outer_identity(12),
                LocalSubnetProvenance::LocalInterface,
            )
            .unwrap();
            invalid(outer_proof(12).with_ipv6_local_subnet(ula));
            assert!(ProvenLocalSubnet::new(
                RoutePrefix::new(IpAddr::V6("2606:4700:1234::".parse().unwrap()), 48).unwrap(),
                outer_identity(12),
                LocalSubnetProvenance::LocalInterface,
            )
            .is_err());

            let second = ProvenLocalSubnet::new(
                RoutePrefix::new(
                    IpAddr::V6(std::net::Ipv6Addr::new(
                        0x2606, 0x4700, 0x5678, 0, 0, 0, 0, 0,
                    )),
                    64,
                )
                .unwrap(),
                outer_identity(12),
                LocalSubnetProvenance::LocalInterface,
            )
            .unwrap();
            let proof = outer_proof(12)
                .with_ipv6_local_subnet(subnet)
                .unwrap()
                .with_ipv6_local_subnet(second)
                .unwrap();
            assert_eq!(proof.ipv6_local_subnets(), &[subnet, second]);
        }

        #[test]
        fn windows_direct_route_context_rejects_shared_identity_and_unmanaged_policy() {
            let tunnel = fake_route_identity();
            let conflict = WindowsDirectRouteContext::new(
                12,
                AdapterIdentity::new(OUTER_LUID, outer_guid()).unwrap(),
                Ipv6RoutePolicy::Block,
                outer_proof(12),
            )
            .unwrap_err();
            assert_eq!(conflict.to_string(), "tunnel_identity_conflict");
            let unmanaged = WindowsDirectRouteContext::new(
                7000,
                tunnel,
                Ipv6RoutePolicy::Inherit,
                outer_proof(12),
            )
            .unwrap_err();
            assert_eq!(unmanaged.to_string(), "route_policy_unverified");
            let ipv6 = outer_ipv6_subnet(12);
            let context = WindowsDirectRouteContext::new(
                7000,
                tunnel,
                Ipv6RoutePolicy::Forward,
                outer_proof(12).with_ipv6_local_subnet(ipv6).unwrap(),
            )
            .unwrap();
            assert_eq!(context.policy(), Ipv6RoutePolicy::Forward);
            assert_eq!(context.tunnel().interface_index, 7000);
            assert_eq!(context.tunnel_retained().interface_luid(), tunnel.luid());
            assert_eq!(context.tunnel_adapter(), tunnel);
            assert_eq!(context.outer().ifindex(), 12);
            assert_eq!(context.outer().ipv6_local_subnets(), &[ipv6]);
            // The verifier policy carries both family proofs on the same
            // physical adapter. A missing IPv6 proof adds nothing.
            let policy = windows_direct_verify_policy(&context);
            assert_eq!(policy.local_subnets.len(), 2);
            assert_eq!(policy.local_subnets[0], context.outer().local_subnet());
            assert_eq!(policy.local_subnets[1], ipv6);
            assert!(policy
                .local_subnets
                .iter()
                .all(|subnet| subnet.adapter() == context.outer().adapter()));
            let blocked = WindowsDirectRouteContext::new(
                7000,
                tunnel,
                Ipv6RoutePolicy::Block,
                outer_proof(12).with_ipv6_local_subnet(ipv6).unwrap(),
            )
            .unwrap();
            assert_eq!(
                windows_direct_verify_policy(&blocked).local_subnets,
                vec![blocked.outer().local_subnet()],
                "IPv6 block mode must not exempt an on-link global prefix"
            );
            let without_ipv6 = WindowsDirectRouteContext::new(
                7000,
                tunnel,
                Ipv6RoutePolicy::Forward,
                outer_proof(12),
            )
            .unwrap();
            assert_eq!(
                windows_direct_verify_policy(&without_ipv6)
                    .local_subnets
                    .len(),
                1
            );
        }

        #[test]
        fn windows_direct_real_start_stays_behind_a_closed_gate() {
            let error = require_windows_direct_evidence().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(error.to_string(), WINDOWS_DIRECT_EVIDENCE_REQUIRED);
            assert!(error.to_string().contains("Windows VM"));
            assert!(error.to_string().contains("independent review"));
        }

        #[test]
        fn windows_direct_gate_stays_closed_and_the_token_gate_is_per_use() {
            let direct = require_windows_start_gate(false).unwrap_err();
            assert_eq!(direct.kind(), io::ErrorKind::Unsupported);
            assert_eq!(direct.to_string(), WINDOWS_DIRECT_EVIDENCE_REQUIRED);
            assert!(!direct.to_string().contains("token"));

            // Source device proxy mode is gated at the token use, where the
            // destination and the pinned interface are known.
            assert!(require_windows_start_gate(true).is_ok());
        }

        #[cfg(windows)]
        #[test]
        fn windows_public_start_entry_keeps_direct_mode_closed() {
            let service = Service::new();
            let error = service
                .start_tun_options_cancellable(
                    TunOptions::default(),
                    None,
                    1,
                    &AtomicBool::new(false),
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(error.to_string(), WINDOWS_DIRECT_EVIDENCE_REQUIRED);
            assert!(!service.is_running());
        }

        #[cfg(windows)]
        #[test]
        fn windows_public_phone_entry_refuses_bad_options_before_any_device() {
            let service = Service::new();
            let proxy = crate::phone::PhoneProxy {
                address: "172.20.10.1:1234".parse().unwrap(),
                username: "hotspotshade".into(),
                token: "fixed-test-token".into(),
                iface: Some(1),
                timeout: Duration::from_secs(1),
            };
            let error = service
                .start_tun_options_cancellable(
                    TunOptions::default(),
                    Some(proxy),
                    1,
                    &AtomicBool::new(false),
                )
                .unwrap_err();
            // The default options block IPv6 forwarding, so the option check
            // refuses the start before Wintun, a device, the token gate, or a
            // token use.
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_safe_options_are_refused_before_device_setup() {
            let cases: [(TunOptions, io::ErrorKind, &str); 4] = [
                (
                    TunOptions {
                        no_pin: true,
                        ..direct_options(Ipv6Policy::Block)
                    },
                    io::ErrorKind::Unsupported,
                    "outer interface pinning",
                ),
                (
                    TunOptions {
                        no_routes: true,
                        ..direct_options(Ipv6Policy::Block)
                    },
                    io::ErrorKind::Unsupported,
                    "managed routes",
                ),
                (
                    direct_options(Ipv6Policy::Inherit),
                    io::ErrorKind::Unsupported,
                    "IPv6 block and forward",
                ),
                (
                    TunOptions {
                        icmp_phone: true,
                        ..direct_options(Ipv6Policy::Block)
                    },
                    io::ErrorKind::InvalidInput,
                    "experimental ICMP requires source device proxy mode",
                ),
            ];
            for (options, kind, message) in cases {
                let state = Arc::new(FakeDirectState::default());
                let runtime = FakeDirectRuntime::new(state.clone());
                let service = Service::new();
                let error = service
                    .start_windows_direct_tunnel_with(options, 1, &AtomicBool::new(false), &runtime)
                    .unwrap_err();
                assert_eq!(error.kind(), kind, "{message}");
                assert!(error.to_string().contains(message), "{error}");
                assert!(state.events().is_empty(), "{:?}", state.events());
                assert!(!service.is_running());
            }
        }

        #[test]
        fn windows_direct_non_elevated_is_refused_before_device_setup() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.elevated = false;
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(state.events().is_empty());
        }

        #[test]
        fn windows_direct_cancellation_before_setup_touches_nothing() {
            let state = Arc::new(FakeDirectState::default());
            let runtime = FakeDirectRuntime::new(state.clone());
            let service = Service::new();
            let cancel = AtomicBool::new(true);
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &cancel,
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(state.events().is_empty());
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_start_never_uses_a_source_token() {
            let state = Arc::new(FakeDirectState::default());
            let runtime = FakeDirectRuntime::new(state.clone());
            let service = Service::new();
            // The phone check is the only runtime path that runs the token
            // gate. The zero count below proves that direct mode skipped it.
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    2,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            let config = relay_config(&state);
            assert_eq!(
                config.iface,
                Some(normalization::interface_index("1").unwrap())
            );
            assert!(!config.phone_present);
            assert_eq!(config.dns_upstream, None);
            assert_eq!(config.workers, 2);
            assert!(!config.ipv6_forward);
            assert!(!config.allow_unpinned);
            assert!(!config.icmp_phone);
            assert!(!config.icmp_persistent);
            assert!(config.failures_present);
            assert_eq!(state.count("phone_check"), 0);
            let status = service.status();
            assert_eq!(status["running"], true);
            assert_eq!(status["mode"], "tun");
            assert_eq!(status["icmp_enabled"], false);
            service.stop();
            assert_eq!(state.count("relay_stop"), 1);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert_eq!(state.records(), 0);
        }

        fn fake_proven_route(prefix: RoutePrefix) -> crate::windows_route_verify::ProvenRoute {
            let next_hop = match prefix.address {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            crate::windows_route_verify::ProvenRoute {
                prefix,
                interface_index: TUNNEL_INDEX,
                interface_luid: fake_route_identity().luid(),
                next_hop,
                metric: 0,
                protocol: 0,
            }
        }

        fn fake_route_proof(
            warnings: Vec<crate::windows_route_verify::RouteWarning>,
        ) -> crate::windows_route_verify::RouteProof {
            crate::windows_route_verify::RouteProof {
                first_half: fake_proven_route(
                    RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 1).unwrap(),
                ),
                second_half: fake_proven_route(
                    RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)), 1).unwrap(),
                ),
                ipv6: fake_proven_route(
                    RoutePrefix::new(
                        IpAddr::V6(std::net::Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)),
                        3,
                    )
                    .unwrap(),
                ),
                ipv6_policy: Ipv6RoutePolicy::Block,
                probes_checked: 0,
                warnings,
            }
        }

        fn warning(
            prefix: RoutePrefix,
            interface_index: u32,
        ) -> crate::windows_route_verify::RouteWarning {
            crate::windows_route_verify::RouteWarning {
                prefix,
                interface_index,
                interface_luid: OUTER_LUID,
                reason: crate::windows_route_verify::RouteWarningReason::NonInternetRange,
            }
        }

        #[test]
        fn windows_direct_route_verification_rejects_unproven_warnings() {
            assert!(require_direct_route_proof(&fake_route_proof(Vec::new())).is_ok());
            let first =
                RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)), 32).unwrap();
            let second =
                RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)), 32).unwrap();
            let proof = fake_route_proof(vec![warning(first, 41), warning(second, 42)]);
            let error = require_direct_route_proof(&proof).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            let message = error.to_string();
            assert!(message.contains("2 unproven route warning"), "{message}");
            assert!(message.contains("203.0.113.9/32"), "{message}");
            assert!(message.contains("interface 41"), "{message}");
            assert!(
                !message.contains("198.51.100.7/32"),
                "the message names only the first warning: {message}"
            );
        }

        #[test]
        fn windows_direct_route_verification_accepts_local_scope_warnings() {
            let local = fake_route_proof(vec![
                warning(
                    RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 0)), 8).unwrap(),
                    41,
                ),
                warning(
                    RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 0, 0)), 16)
                        .unwrap(),
                    42,
                ),
                warning(
                    RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 0)), 4).unwrap(),
                    43,
                ),
                warning(
                    RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)), 32)
                        .unwrap(),
                    44,
                ),
            ]);
            assert!(require_direct_route_proof(&local).is_ok());

            // One documentation-range warning still fails, and the local
            // warnings do not inflate the unproven count.
            let mut mixed = local.warnings.clone();
            mixed.push(warning(
                RoutePrefix::new(
                    IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
                    32,
                )
                .unwrap(),
                45,
            ));
            let error = require_direct_route_proof(&fake_route_proof(mixed)).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("1 unproven route warning"), "{message}");
            assert!(message.contains("2001:db8::/32"), "{message}");
            assert!(!message.contains("127.0.0.0/8"), "{message}");

            // A malformed prefix with host bits set is not local proof.
            let malformed = crate::windows_route_verify::RouteWarning {
                prefix: RoutePrefix {
                    address: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    length: 8,
                },
                interface_index: 46,
                interface_luid: OUTER_LUID,
                reason: crate::windows_route_verify::RouteWarningReason::NonInternetRange,
            };
            assert!(!expected_direct_warning(&malformed));
        }

        #[test]
        fn windows_direct_local_scope_is_narrow() {
            let v4 = |address: [u8; 4], length: u8| {
                RoutePrefix::new(IpAddr::V4(std::net::Ipv4Addr::from(address)), length).unwrap()
            };
            let v6 = |address: std::net::Ipv6Addr, length: u8| {
                RoutePrefix::new(IpAddr::V6(address), length).unwrap()
            };
            for prefix in [
                v4([127, 0, 0, 0], 8),
                v4([127, 0, 0, 1], 32),
                v4([169, 254, 1, 2], 32),
                v4([224, 0, 0, 0], 4),
                v4([239, 255, 255, 250], 32),
                v4([255, 255, 255, 255], 32),
                v6(std::net::Ipv6Addr::LOCALHOST, 128),
                v6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
                v6(std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
            ] {
                assert!(direct_local_scope(prefix), "{prefix}");
            }
            for prefix in [
                v4([0, 0, 0, 0], 8),
                v4([10, 0, 0, 0], 8),
                v4([126, 0, 0, 0], 7),
                v4([192, 0, 2, 0], 24),
                v4([198, 18, 0, 0], 15),
                v4([198, 51, 100, 0], 24),
                v4([203, 0, 113, 0], 24),
                v4([240, 0, 0, 0], 4),
                v4([255, 255, 255, 0], 24),
                v6(
                    std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                    32,
                ),
                v6(
                    std::net::Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0),
                    32,
                ),
            ] {
                assert!(!direct_local_scope(prefix), "{prefix}");
            }
        }

        #[test]
        fn windows_direct_verifies_routes_before_the_relay() {
            let state = Arc::new(FakeDirectState::default());
            let runtime = FakeDirectRuntime::new(state.clone());
            let service = Service::new();
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            assert!(state.position("outer_prove") < state.position("wintun_load"));
            assert!(state.position("wintun_load") < state.position("device_open"));
            assert!(state.position("device_open") < state.position("routes_install"));
            assert!(state.position("routes_install") < state.position("routes_verify"));
            assert!(state.position("routes_verify") < state.position("link_bind"));
            assert!(state.position("link_bind") < state.position("relay_start"));
            let context = route_context(&state);
            assert_eq!(context.policy(), Ipv6RoutePolicy::Block);
            assert_eq!(context.tunnel().interface_index, TUNNEL_INDEX);
            assert_eq!(
                context.tunnel_retained().interface_luid(),
                fake_route_identity().luid()
            );
            assert_eq!(
                context.outer().ifindex(),
                context.outer().adapter().interface_index()
            );
            assert_eq!(context.outer().local_subnet().prefix().length, 28);
            service.stop();
            let events = state.events();
            let relay_stop = events
                .iter()
                .position(|event| *event == "relay_stop")
                .unwrap();
            let routes_remove = events
                .iter()
                .position(|event| *event == "routes_remove")
                .unwrap();
            let device_drop = events
                .iter()
                .position(|event| *event == "device_drop")
                .unwrap();
            assert!(relay_stop < routes_remove);
            assert!(routes_remove < device_drop);
        }

        #[test]
        fn windows_direct_ipv6_policy_reaches_routes_and_relay() {
            for policy in [Ipv6Policy::Block, Ipv6Policy::Forward] {
                let state = Arc::new(FakeDirectState::default());
                let runtime = FakeDirectRuntime::new(state.clone());
                let service = Service::new();
                service
                    .start_windows_direct_tunnel_with(
                        direct_options(policy),
                        1,
                        &AtomicBool::new(false),
                        &runtime,
                    )
                    .unwrap();
                let expected = match policy {
                    Ipv6Policy::Block => Ipv6RoutePolicy::Block,
                    Ipv6Policy::Forward => Ipv6RoutePolicy::Forward,
                    Ipv6Policy::Inherit => unreachable!(),
                };
                assert_eq!(route_context(&state).policy(), expected);
                assert_eq!(
                    relay_config(&state).ipv6_forward,
                    expected == Ipv6RoutePolicy::Forward
                );
                service.stop();
            }
        }

        #[test]
        fn windows_direct_proof_index_mismatch_is_refused() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.proof_index_offset = 1;
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "outer_adapter_unverified");
            assert_eq!(state.count("outer_prove"), 1);
            assert_eq!(state.count("wintun_load"), 0);
            assert_eq!(state.count("device_open"), 0);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_tunnel_identity_conflict_is_refused() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            let outer_index = normalization::interface_index("1").unwrap();
            runtime.device_ifindex = outer_index;
            runtime.device_identity = AdapterIdentity::new(OUTER_LUID, outer_guid()).unwrap();
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "tunnel_identity_conflict");
            assert_eq!(state.count("routes_open"), 0);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_route_verification_failure_stops_before_relay() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.verify_error = true;
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "route_setup");
            assert_eq!(state.count("routes_verify"), 1);
            assert_eq!(state.relay_started.load(Ordering::Acquire), 0);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert_eq!(state.records(), 0);
            assert_eq!(service.status()["error"], Value::Null);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_install_failure_rolls_back() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.install_error_after = Some(1);
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "route_setup");
            assert_eq!(state.count("routes_install_partial"), 1);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.records(), 0);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_relay_failure_cleans_routes_and_device() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.relay_error = true;
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "direct_relay_setup");
            assert_eq!(state.relay_started.load(Ordering::Acquire), 1);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.records(), 0);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_cancellation_after_route_verification_cleans_up() {
            let state = Arc::new(FakeDirectState::default());
            let cancel = Arc::new(AtomicBool::new(false));
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.cancel_on_verify = Some(cancel.clone());
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &cancel,
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(state.relay_started.load(Ordering::Acquire), 0);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.records(), 0);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_cancellation_after_link_bind_records_cleanup_failure() {
            for remove_error in [false, true] {
                let state = Arc::new(FakeDirectState::default());
                let cancel = Arc::new(AtomicBool::new(false));
                let mut runtime = FakeDirectRuntime::new(state.clone());
                runtime.cancel_on_link_bind = Some(cancel.clone());
                runtime.remove_error = remove_error;
                let service = Service::new();
                let error = service
                    .start_windows_direct_tunnel_with(
                        direct_options(Ipv6Policy::Block),
                        1,
                        &cancel,
                        &runtime,
                    )
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                assert_eq!(state.relay_started.load(Ordering::Acquire), 0);
                assert_eq!(state.count("routes_remove"), 1);
                assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
                assert_eq!(service.cleanup_uncertain(), remove_error);
                assert_eq!(service.stop_checked().is_err(), remove_error);
            }
        }

        #[test]
        fn windows_direct_cancellation_after_relay_start_cleans_up_in_order() {
            let state = Arc::new(FakeDirectState::default());
            let cancel = Arc::new(AtomicBool::new(false));
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.cancel_on_relay_start = Some(cancel.clone());
            let service = Service::new();
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &cancel,
                    &runtime,
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(state.relay_started.load(Ordering::Acquire), 1);
            assert_eq!(state.count("relay_stop"), 1);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.records(), 0);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            let events = state.events();
            let relay_stop = events
                .iter()
                .position(|event| *event == "relay_stop")
                .unwrap();
            let routes_remove = events
                .iter()
                .position(|event| *event == "routes_remove")
                .unwrap();
            let device_drop = events
                .iter()
                .position(|event| *event == "device_drop")
                .unwrap();
            assert!(relay_stop < routes_remove);
            assert!(routes_remove < device_drop);
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_link_sample_must_match_the_start_pin() {
            const PIN: u32 = 12;
            assert_eq!(
                classify_windows_direct_link(
                    WindowsDirectLinkSample {
                        up: true,
                        interface_index: Some(PIN),
                    },
                    PIN,
                ),
                WindowsDirectLinkDecision::Link { up: true }
            );
            assert_eq!(
                classify_windows_direct_link(
                    WindowsDirectLinkSample {
                        up: false,
                        interface_index: Some(PIN),
                    },
                    PIN,
                ),
                WindowsDirectLinkDecision::Link { up: false }
            );
            // A different index is stale even when the link is up: the
            // observer follows the adapter, but the relay does not.
            for up in [true, false] {
                assert_eq!(
                    classify_windows_direct_link(
                        WindowsDirectLinkSample {
                            up,
                            interface_index: Some(PIN + 1),
                        },
                        PIN,
                    ),
                    WindowsDirectLinkDecision::StalePin
                );
            }
            // A removed adapter has no live index. The old index can be
            // reused by another adapter, so the pin is stale.
            assert_eq!(
                classify_windows_direct_link(
                    WindowsDirectLinkSample {
                        up: false,
                        interface_index: None,
                    },
                    PIN,
                ),
                WindowsDirectLinkDecision::StalePin
            );
        }

        #[test]
        fn windows_direct_stale_pinned_index_stops_at_once() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            let pinned = normalization::interface_index("1").unwrap();
            runtime.link_index_after = Some(pinned + 1);
            runtime.link_index_change_after = 2;
            runtime.link_poll_interval = Duration::from_millis(5);
            // A 30 second down limit proves that the stop comes from the stale
            // pin, not from the continuous-loss policy.
            runtime.link_down_limit = Duration::from_secs(30);
            let service = Service::new();
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while service.is_running() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a stale pinned index did not stop the tunnel"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let status = service.status();
            assert_eq!(status["running"], false);
            assert_eq!(status["last_stop"]["reason"], "hotspot_lost");
            assert_eq!(status["error"], Value::Null);
            assert_eq!(status["cleanup_blocked"], false);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.count("relay_stop"), 1);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert!(state.link_observations.load(Ordering::Acquire) >= 2);
            service.stop();
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_removed_retained_identity_stops_at_once() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.link_removed_after = Some(2);
            runtime.link_poll_interval = Duration::from_millis(5);
            runtime.link_down_limit = Duration::from_secs(30);
            let service = Service::new();
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while service.is_running() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a removed retained identity did not stop the tunnel"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let status = service.status();
            assert_eq!(status["running"], false);
            assert_eq!(status["last_stop"]["reason"], "hotspot_lost");
            assert_eq!(status["error"], Value::Null);
            assert_eq!(status["cleanup_blocked"], false);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.count("relay_stop"), 1);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert!(state.link_observations.load(Ordering::Acquire) >= 2);
            service.stop();
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_unknown_link_observation_is_not_link_loss() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.link_error = true;
            runtime.link_poll_interval = Duration::from_millis(5);
            runtime.link_down_limit = Duration::from_millis(15);
            let service = Service::new();
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(100));
            assert!(service.is_running());
            assert!(state.link_observations.load(Ordering::Acquire) >= 2);
            let status = service.status();
            assert_eq!(status["last_stop"]["reason"], Value::Null);
            assert_eq!(status["error"], Value::Null);
            service.stop();
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
        }

        #[test]
        fn windows_direct_link_loss_stops_and_cleans_up() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.link_up = false;
            runtime.link_poll_interval = Duration::from_millis(5);
            runtime.link_down_limit = Duration::from_millis(15);
            let service = Service::new();
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while service.is_running() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "direct link loss did not stop the tunnel"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let status = service.status();
            assert_eq!(status["running"], false);
            assert_eq!(status["last_stop"]["reason"], "hotspot_lost");
            assert_eq!(status["error"], Value::Null);
            assert_eq!(status["cleanup_blocked"], false);
            assert_eq!(state.count("routes_remove"), 1);
            assert_eq!(state.count("relay_stop"), 1);
            assert_eq!(state.device_drops.load(Ordering::Acquire), 1);
            assert_eq!(state.records(), 0);
            assert!(state.link_observations.load(Ordering::Acquire) >= 2);
            service.stop();
            assert!(!service.is_running());
        }

        #[test]
        fn windows_direct_cleanup_failure_blocks_a_restart() {
            let state = Arc::new(FakeDirectState::default());
            let mut runtime = FakeDirectRuntime::new(state.clone());
            runtime.remove_error = true;
            let service = Service::new();
            service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
                    1,
                    &AtomicBool::new(false),
                    &runtime,
                )
                .unwrap();
            let error = service.stop_checked().unwrap_err();
            assert_eq!(error.to_string(), CLEANUP_UNCERTAIN_MESSAGE);
            let status = service.status();
            assert_eq!(status["running"], false);
            assert_eq!(status["cleanup_blocked"], true);
            assert!(status["error"]
                .as_str()
                .unwrap_or_default()
                .contains("Route cleanup failed"));
            assert_eq!(state.records(), 3);
            let error = service
                .start_windows_direct_tunnel_with(
                    direct_options(Ipv6Policy::Block),
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
}
