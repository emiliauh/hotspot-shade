//! Hotspot auto-off policy.
//!
//! A running tunnel stops itself when the hotspot link stays down for 20
//! seconds, or when fresh probes say that the source device app stays silent
//! for 90 seconds in source device proxy mode. Every good sample resets the
//! timer. One down sample never stops the tunnel. An unknown link observation
//! or a stale probe breaks the evidence of continuous loss in the GUI.
//!
//! The policy is pure and takes an injected clock. The link observer reads
//! interface flags and addresses through `getifaddrs`. It never starts a
//! process on the hot path.
use std::time::{Duration, Instant};

/// A hotspot link that stays down for this long stops the tunnel.
pub const LINK_DOWN_LIMIT: Duration = Duration::from_secs(20);
/// An answered link whose source device app stays silent for this long stops
/// the tunnel in source device proxy mode.
pub const SOURCE_DEVICE_GONE_LIMIT: Duration = Duration::from_secs(90);

/// One observation of the hotspot and the source device app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotspotSample {
    /// No tunnel runs, or it is starting or stopping. Clear the timers.
    Reset,
    /// The pinned interface is down, has no usable IPv4 address, or the
    /// presence probe reports `no_hotspot`.
    LinkDown,
    /// The link is up but the source device app does not answer.
    DeviceGone,
    /// The link is up and the source device app answered, or no probe is due.
    Good,
}

/// Map one probe result to one sample. Only source device proxy mode uses the
/// probe. Direct mode uses the interface check alone.
pub fn sample_from(link_up: bool, phone_mode: bool, probe: Option<&str>) -> HotspotSample {
    if !link_up || (phone_mode && probe == Some("no_hotspot")) {
        return HotspotSample::LinkDown;
    }
    if phone_mode && matches!(probe, Some("not_running" | "not_responding")) {
        return HotspotSample::DeviceGone;
    }
    HotspotSample::Good
}

/// The state machine for the two continuous timers.
pub struct AutoStopPolicy {
    link_down_limit: Duration,
    source_device_limit: Duration,
    link_down_since: Option<Instant>,
    source_device_since: Option<Instant>,
}
impl Default for AutoStopPolicy {
    fn default() -> Self {
        Self::new()
    }
}
impl AutoStopPolicy {
    pub fn new() -> Self {
        Self::with_limits(LINK_DOWN_LIMIT, SOURCE_DEVICE_GONE_LIMIT)
    }
    /// The limits are separate so that tests can use a short clock.
    pub fn with_limits(link_down_limit: Duration, source_device_limit: Duration) -> Self {
        Self {
            link_down_limit,
            source_device_limit,
            link_down_since: None,
            source_device_since: None,
        }
    }
    pub fn reset(&mut self) {
        self.link_down_since = None;
        self.source_device_since = None;
    }
    /// Record that the link recovered without changing the device timer.
    pub fn link_recovered(&mut self) {
        self.link_down_since = None;
    }
    /// Record that the source device answered without changing the link timer.
    pub fn source_device_answered(&mut self) {
        self.source_device_since = None;
    }
    /// Discard a silence interval when probe data is no longer current.
    pub fn source_device_unobserved(&mut self) {
        self.source_device_since = None;
    }
    /// Feed one sample. Return the stop reason at most once per continuous
    /// failure.
    pub fn observe(&mut self, now: Instant, sample: HotspotSample) -> Option<&'static str> {
        match sample {
            HotspotSample::Reset | HotspotSample::Good => {
                self.reset();
                None
            }
            HotspotSample::LinkDown => {
                self.source_device_since = None;
                let since = *self.link_down_since.get_or_insert(now);
                (now.saturating_duration_since(since) >= self.link_down_limit)
                    .then_some("hotspot_lost")
            }
            HotspotSample::DeviceGone => {
                self.link_down_since = None;
                let since = *self.source_device_since.get_or_insert(now);
                (now.saturating_duration_since(since) >= self.source_device_limit)
                    .then_some("source_device_gone")
            }
        }
    }
}

/// The fixed text for an automatic stop. It holds no secret and no address.
pub fn stop_message(reason: &str) -> Option<&'static str> {
    match reason {
        "hotspot_lost" => Some("The hotspot turned off, so HotspotShade turned the tunnel off."),
        "source_device_gone" => {
            Some("The source device stopped answering, so HotspotShade turned the tunnel off.")
        }
        _ => None,
    }
}

/// Return the fixed reason for a status value, or `None` for another value.
pub fn reason(value: &str) -> Option<&'static str> {
    match value {
        "hotspot_lost" => Some("hotspot_lost"),
        "source_device_gone" => Some("source_device_gone"),
        _ => None,
    }
}

/// True when the interface exists, is up, and has a usable IPv4 address.
#[cfg(unix)]
pub fn link_up(iface: &str) -> bool {
    link_observation(iface).unwrap_or(false)
}

/// Observe the link. An operating system error is not evidence of link loss.
#[cfg(unix)]
pub fn link_observation(iface: &str) -> std::io::Result<bool> {
    use std::ffi::CStr;
    if iface.is_empty() || iface.len() >= libc::IFNAMSIZ || iface.contains('\0') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut found = false;
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_bytes() != iface.as_bytes() {
            continue;
        }
        if entry.ifa_flags as i32 & libc::IFF_UP == 0 {
            continue;
        }
        if unsafe { (*entry.ifa_addr).sa_family as i32 } != libc::AF_INET {
            continue;
        }
        let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        let ip = std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
        if !ip.is_unspecified()
            && !ip.is_broadcast()
            && !ip.is_multicast()
            && !(ip.octets()[0] == 169 && ip.octets()[1] == 254)
        {
            found = true;
            break;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

/// Windows has no hotspot link observer. Report the link as up. The source
/// device probe still stops a tunnel after continuous silence.
#[cfg(not(unix))]
pub fn link_up(_iface: &str) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_down_stops_at_twenty_seconds_not_nineteen() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::new();
        assert_eq!(p.observe(t, HotspotSample::LinkDown), None);
        assert_eq!(
            p.observe(t + Duration::from_secs(19), HotspotSample::LinkDown),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(20), HotspotSample::LinkDown),
            Some("hotspot_lost")
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(22), HotspotSample::LinkDown),
            Some("hotspot_lost")
        );
        p.reset();
        assert_eq!(
            p.observe(t + Duration::from_secs(23), HotspotSample::LinkDown),
            None
        );
    }

    #[test]
    fn source_device_gone_stops_at_ninety_seconds() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::new();
        assert_eq!(p.observe(t, HotspotSample::DeviceGone), None);
        assert_eq!(
            p.observe(t + Duration::from_secs(89), HotspotSample::DeviceGone),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(90), HotspotSample::DeviceGone),
            Some("source_device_gone")
        );
    }

    #[test]
    fn a_good_sample_resets_a_timer() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::new();
        p.observe(t, HotspotSample::LinkDown);
        assert_eq!(
            p.observe(t + Duration::from_secs(15), HotspotSample::Good),
            None
        );
        // The timer starts again at 16 seconds. A single missed sample and the
        // good sample do not stop the tunnel.
        assert_eq!(
            p.observe(t + Duration::from_secs(16), HotspotSample::LinkDown),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(35), HotspotSample::LinkDown),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(36), HotspotSample::LinkDown),
            Some("hotspot_lost")
        );
    }

    #[test]
    fn starting_and_stopping_reset_the_timers() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::new();
        p.observe(t, HotspotSample::LinkDown);
        assert_eq!(
            p.observe(t + Duration::from_secs(19), HotspotSample::Reset),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(20), HotspotSample::LinkDown),
            None
        );
        p.observe(t + Duration::from_secs(30), HotspotSample::DeviceGone);
        p.observe(t + Duration::from_secs(40), HotspotSample::Reset);
        assert_eq!(
            p.observe(t + Duration::from_secs(100), HotspotSample::DeviceGone),
            None
        );
    }

    #[test]
    fn a_link_failure_and_a_source_failure_have_separate_timers() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::new();
        p.observe(t, HotspotSample::LinkDown);
        assert_eq!(
            p.observe(t + Duration::from_secs(10), HotspotSample::DeviceGone),
            None
        );
        // The link timer was cleared, so a new link failure needs 20 seconds.
        assert_eq!(
            p.observe(t + Duration::from_secs(11), HotspotSample::LinkDown),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(31), HotspotSample::LinkDown),
            Some("hotspot_lost")
        );
    }

    #[test]
    fn probe_states_map_to_samples() {
        assert_eq!(
            sample_from(false, true, Some("ready")),
            HotspotSample::LinkDown
        );
        assert_eq!(
            sample_from(true, true, Some("no_hotspot")),
            HotspotSample::LinkDown
        );
        assert_eq!(
            sample_from(true, true, Some("not_running")),
            HotspotSample::DeviceGone
        );
        assert_eq!(
            sample_from(true, true, Some("not_responding")),
            HotspotSample::DeviceGone
        );
        for answered in ["ready", "proxy_off", "connected", "unpaired", "not_trusted"] {
            assert_eq!(
                sample_from(true, true, Some(answered)),
                HotspotSample::Good,
                "{answered}"
            );
        }
        assert_eq!(sample_from(true, true, None), HotspotSample::Good);
        // Direct mode ignores the probe.
        assert_eq!(
            sample_from(true, false, Some("not_responding")),
            HotspotSample::Good
        );
        assert_eq!(sample_from(false, false, None), HotspotSample::LinkDown);
    }

    #[test]
    fn stop_messages_are_fixed_and_plain() {
        assert_eq!(
            stop_message("hotspot_lost"),
            Some("The hotspot turned off, so HotspotShade turned the tunnel off.")
        );
        assert_eq!(
            stop_message("source_device_gone"),
            Some("The source device stopped answering, so HotspotShade turned the tunnel off.")
        );
        assert_eq!(stop_message("user"), None);
        assert_eq!(stop_message("error"), None);
        assert_eq!(reason("hotspot_lost"), Some("hotspot_lost"));
        assert_eq!(reason("source_device_gone"), Some("source_device_gone"));
        assert_eq!(reason("user"), None);
    }

    #[cfg(unix)]
    #[test]
    fn link_observer_reads_a_real_interface_without_a_process() {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        assert!(link_up(name));
        assert!(!link_up("hs-no-such-interface"));
        assert!(!link_up(""));
        assert!(!link_up("lo0 with space"));
        assert_eq!(
            link_observation("").unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(!link_observation("hs-missing0").unwrap());
    }
}
