//! Hotspot auto-off policy.
//!
//! A running tunnel stops itself when the hotspot link stays down for 20
//! seconds, or when fresh probes say that the source device app stays silent
//! for 90 seconds in source device proxy mode. Every good sample resets the
//! timer. One down sample never stops the tunnel. An unknown link observation
//! or a stale probe breaks the evidence of continuous loss in the GUI.
//!
//! A plaintext status frame is not proof that the source device app is
//! present, and a timeout is not proof that it is absent. The policy keeps
//! those two apart. An unverified answer neither resets the silence timer nor
//! starts it immediately. A continuous run of unverified answers is bounded,
//! so a stuck or forged frame cannot hold the tunnel open for good.
//!
//! The policy is pure and takes an injected clock. The link observer reads
//! interface flags and IPv4 addresses through `getifaddrs` on Unix and through
//! the Windows interface and address tables on Windows. It never starts a
//! process on the hot path. A failed observation is unknown, not link loss.
use std::time::{Duration, Instant};

/// A hotspot link that stays down for this long stops the tunnel.
pub const LINK_DOWN_LIMIT: Duration = Duration::from_secs(20);
/// An answered link whose source device app stays silent for this long stops
/// the tunnel in source device proxy mode.
pub const SOURCE_DEVICE_GONE_LIMIT: Duration = Duration::from_secs(90);
/// A continuous run of plaintext answers is allowed this long before it
/// counts as source device silence. It matches the longest background pairing
/// prompt extension (120 seconds). A forged or stuck `Busy`, `Rejected`,
/// `NotActive`, or `LockedOut` answer cannot hold the tunnel open for good.
pub const UNVERIFIED_GRACE: Duration = Duration::from_secs(120);

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
    /// The link is up and the source device app gave a plaintext answer. The
    /// answer is not proof of presence and not proof of absence. It keeps an
    /// existing silence interval and starts one only after
    /// [`UNVERIFIED_GRACE`].
    Unverified,
    /// The probe could not run because the tunnel pin is unknown. This is a
    /// local failure, not an answer from the source device. It breaks the
    /// evidence of continuous loss instead of starting a timer.
    NoEvidence,
    /// The link is up and the source device app gave an authenticated answer,
    /// or no probe is due.
    Good,
}

/// True when a probe state is a plaintext answer from the pairing listener.
///
/// These states come from RESULT or CHALLENGE frames that the listener sends
/// before it authenticates anyone. Any host on the pairing port can send them.
/// None of them proves that the source device app is present, and none proves
/// that it is absent. Do not report trust or presence from them.
///
/// `pin_unknown` is not in this set. It is a local failure to pin the probe,
/// not an answer from the source device. It must not start a source device
/// timer either, so the GUI breaks the silence interval instead.
pub fn unverified_probe_state(state: &str) -> bool {
    matches!(state, "checking" | "unpaired" | "not_trusted")
}

/// Map one probe result to one sample. Only source device proxy mode uses the
/// probe. Direct mode uses the interface check alone.
pub fn sample_from(link_up: bool, phone_mode: bool, probe: Option<&str>) -> HotspotSample {
    if !link_up || (phone_mode && probe == Some("no_hotspot")) {
        return HotspotSample::LinkDown;
    }
    if phone_mode {
        match probe {
            Some("not_running" | "not_responding") => return HotspotSample::DeviceGone,
            Some("pin_unknown") => return HotspotSample::NoEvidence,
            Some(state) if unverified_probe_state(state) => return HotspotSample::Unverified,
            _ => {}
        }
    }
    HotspotSample::Good
}

/// The state machine for the continuous timers.
pub struct AutoStopPolicy {
    link_down_limit: Duration,
    source_device_limit: Duration,
    unverified_limit: Duration,
    link_down_since: Option<Instant>,
    source_device_since: Option<Instant>,
    /// When the current run of unverified answers began. A good answer, a
    /// silent answer, a link failure, or a reset clears it.
    unverified_since: Option<Instant>,
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
        Self::with_all_limits(link_down_limit, source_device_limit, UNVERIFIED_GRACE)
    }
    /// The full policy limits. Tests use this to keep simulated time short.
    pub fn with_all_limits(
        link_down_limit: Duration,
        source_device_limit: Duration,
        unverified_limit: Duration,
    ) -> Self {
        Self {
            link_down_limit,
            source_device_limit,
            unverified_limit,
            link_down_since: None,
            source_device_since: None,
            unverified_since: None,
        }
    }
    pub fn reset(&mut self) {
        self.link_down_since = None;
        self.source_device_since = None;
        self.unverified_since = None;
    }
    /// Record that the link recovered without changing the device timer.
    pub fn link_recovered(&mut self) {
        self.link_down_since = None;
    }
    /// Record that the source device answered without changing the link timer.
    pub fn source_device_answered(&mut self) {
        self.source_device_since = None;
        self.unverified_since = None;
    }
    /// Discard a silence interval when probe data is no longer current.
    pub fn source_device_unobserved(&mut self) {
        self.source_device_since = None;
        self.unverified_since = None;
    }
    /// Feed one sample. Return the stop reason at most once per continuous
    /// failure.
    pub fn observe(&mut self, now: Instant, sample: HotspotSample) -> Option<&'static str> {
        match sample {
            HotspotSample::Reset | HotspotSample::NoEvidence | HotspotSample::Good => {
                self.reset();
                None
            }
            HotspotSample::LinkDown => {
                self.source_device_since = None;
                self.unverified_since = None;
                let since = *self.link_down_since.get_or_insert(now);
                (now.saturating_duration_since(since) >= self.link_down_limit)
                    .then_some("hotspot_lost")
            }
            HotspotSample::DeviceGone => {
                self.link_down_since = None;
                self.unverified_since = None;
                let since = *self.source_device_since.get_or_insert(now);
                (now.saturating_duration_since(since) >= self.source_device_limit)
                    .then_some("source_device_gone")
            }
            HotspotSample::Unverified => {
                self.link_down_since = None;
                // Keep an existing silence interval. A timeout between two
                // plaintext answers is still continuous silence.
                let since = *self.unverified_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= self.unverified_limit {
                    self.source_device_since.get_or_insert(now);
                }
                let source_since = self.source_device_since?;
                (now.saturating_duration_since(source_since) >= self.source_device_limit)
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

/// Windows link observation is unavailable until the status mapping and
/// identity handling pass independent review and native Windows tests.
#[cfg(windows)]
pub fn link_observation(_iface: &str) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows link observation is not yet available",
    ))
}

/// Other targets have no link observer. An unsupported observation is unknown,
/// not link loss.
#[cfg(not(any(unix, windows)))]
pub fn link_observation(_iface: &str) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "link observation is not implemented on this platform",
    ))
}

/// Windows: a conclusive observation wins. An inconclusive observation
/// reports `true`, because this helper cannot express unknown and an API
/// failure must not look like link loss.
#[cfg(windows)]
pub fn link_up(iface: &str) -> bool {
    link_observation(iface).unwrap_or(true)
}

/// Other targets have no link observer. Report the link as up so the policy
/// never invents link loss on a platform that cannot observe it.
#[cfg(not(any(unix, windows)))]
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
    fn a_continuous_unverified_answer_is_bounded() {
        let t = Instant::now();
        // Use short limits so the test shows the two phases clearly.
        let mut p = AutoStopPolicy::with_all_limits(
            Duration::from_secs(20),
            Duration::from_secs(90),
            Duration::from_secs(30),
        );
        // The first 30 seconds only start the unverified run. No stop.
        assert_eq!(p.observe(t, HotspotSample::Unverified), None);
        assert_eq!(
            p.observe(t + Duration::from_secs(29), HotspotSample::Unverified),
            None
        );
        // At 30 seconds the unverified run counts as silence. The normal
        // source device limit still applies, so the stop comes at 120 seconds.
        assert_eq!(
            p.observe(t + Duration::from_secs(30), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(119), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(120), HotspotSample::Unverified),
            Some("source_device_gone")
        );
        // A good answer clears both the unverified run and the silence timer.
        assert_eq!(
            p.observe(t + Duration::from_secs(121), HotspotSample::Good),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(122), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(151), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(152), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(241), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(242), HotspotSample::Unverified),
            Some("source_device_gone")
        );
    }

    #[test]
    fn an_unverified_answer_does_not_reset_continuous_silence() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::new();
        // A timeout starts the silence timer.
        assert_eq!(p.observe(t, HotspotSample::DeviceGone), None);
        // Plaintext answers in between must not reset it. This is the
        // alternating Busy and timeout case.
        for second in (2..=88).step_by(2) {
            assert_eq!(
                p.observe(t + Duration::from_secs(second), HotspotSample::Unverified),
                None,
                "{second}"
            );
        }
        assert_eq!(
            p.observe(t + Duration::from_secs(90), HotspotSample::Unverified),
            Some("source_device_gone")
        );
    }

    #[test]
    fn a_link_failure_clears_the_unverified_run() {
        let t = Instant::now();
        let mut p = AutoStopPolicy::with_all_limits(
            Duration::from_secs(20),
            Duration::from_secs(90),
            Duration::from_secs(30),
        );
        assert_eq!(p.observe(t, HotspotSample::Unverified), None);
        assert_eq!(
            p.observe(t + Duration::from_secs(20), HotspotSample::LinkDown),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(40), HotspotSample::LinkDown),
            Some("hotspot_lost")
        );
        // The link recovers. The unverified run starts again from zero.
        assert_eq!(
            p.observe(t + Duration::from_secs(41), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(70), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(71), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(160), HotspotSample::Unverified),
            None
        );
        assert_eq!(
            p.observe(t + Duration::from_secs(161), HotspotSample::Unverified),
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
        for answered in ["ready", "proxy_off", "connected"] {
            assert_eq!(
                sample_from(true, true, Some(answered)),
                HotspotSample::Good,
                "{answered}"
            );
        }
        for unverified in ["checking", "unpaired", "not_trusted"] {
            assert_eq!(
                sample_from(true, true, Some(unverified)),
                HotspotSample::Unverified,
                "{unverified}"
            );
        }
        assert_eq!(
            sample_from(true, true, Some("pin_unknown")),
            HotspotSample::NoEvidence
        );
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

    #[cfg(windows)]
    #[test]
    fn the_windows_link_observer_is_unavailable_until_integrated() {
        // The gated observer reports unknown for every name. The helper that
        // cannot express unknown reports the link as up.
        assert_eq!(
            link_observation("").unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert!(link_up(""));
    }
}
