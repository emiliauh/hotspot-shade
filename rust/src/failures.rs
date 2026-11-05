//! Bounded in-memory record of failed source device connection setups.
//!
//! The data stays in target device memory. The relay never writes it to disk,
//! never sends it to the source device, and clears it when the tunnel stops.
//! The record holds no token and no credential.
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The data path queues at most this many events before it counts a drop.
const MAX_PENDING: usize = 10_000;

/// One event with the time that the data path saw it.
struct Queued {
    ts: u64,
    event: FailureEvent,
}

/// The maximum number of recent failures that the ring keeps.
pub const MAX_RECENT: usize = 200;
/// The maximum number of groups that the counters keep.
pub const MAX_GROUPS: usize = 100;
/// The maximum number of IP-to-name pairs that the hint map keeps.
pub const MAX_NAMES: usize = 2000;
/// The endpoint shows at most this many groups.
pub const SHOW_GROUPS: usize = 50;
/// The endpoint shows at most this many recent failures.
pub const SHOW_RECENT: usize = 100;
/// The DNS target that the relay sends to the source device.
const DNS_TARGET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Proto {
    Tcp,
    Udp,
    Dns,
}
impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Dns => "dns",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Family {
    Ipv4,
    Ipv6,
}
impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Reason {
    Unreachable,
    Refused,
    TimedOut,
    Denied,
    Other,
}
impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Unreachable => "unreachable",
            Reason::Refused => "refused",
            Reason::TimedOut => "timed_out",
            Reason::Denied => "denied",
            Reason::Other => "other",
        }
    }
    /// Map a SOCKS5 reply code to a reason class.
    ///
    /// Code 6 is an expired TTL, not a timeout. The reason classes have no TTL
    /// class, so code 6 maps to `Other`. Code 1 is a general failure, which can
    /// include a source device deadline, so it also maps to `Other`.
    pub fn from_code(code: u8) -> Self {
        match code {
            3 | 4 => Reason::Unreachable,
            5 => Reason::Refused,
            2 | 7 => Reason::Denied,
            _ => Reason::Other,
        }
    }
    /// Map a local socket error to a reason class.
    ///
    /// This function does not know where the error came from. Use
    /// `from_direct_setup_error` for a direct destination connect and
    /// `from_setup_error` for a source device setup.
    pub fn from_error(kind: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind;
        match kind {
            ErrorKind::ConnectionRefused => Reason::Refused,
            ErrorKind::TimedOut => Reason::TimedOut,
            ErrorKind::PermissionDenied => Reason::Denied,
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown => {
                Reason::Unreachable
            }
            _ => Reason::Other,
        }
    }
    /// Map one setup error and an optional source device reply code.
    ///
    /// A reply code is an answer about the destination, so it keeps its
    /// meaning. A local socket error without a reply code is not proof that the
    /// destination refused the flow, is unreachable, or timed out. A local
    /// refusal, a local unreachable error, a local permission error, and a
    /// local timeout become `Other`. A local timeout only proves that the
    /// target device stopped waiting for the source device.
    ///
    /// Code 6 is an expired TTL. It becomes `Other`, because the classes have
    /// no TTL class and a TTL expiry is not a timeout.
    pub fn from_setup_error(kind: std::io::ErrorKind, code: Option<u8>) -> Self {
        use std::io::ErrorKind;
        if let Some(code) = code {
            return Self::from_code(code);
        }
        match kind {
            ErrorKind::ConnectionRefused
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::PermissionDenied
            | ErrorKind::TimedOut => Self::Other,
            _ => Self::from_error(kind),
        }
    }
    /// Map one direct destination setup error.
    ///
    /// The target device connects to the destination itself, so a local
    /// timeout is a destination timeout. A refusal and an unreachable error
    /// keep their classes.
    pub fn from_direct_setup_error(kind: std::io::ErrorKind) -> Self {
        Self::from_error(kind)
    }
}

/// The setup stage of a source device connection. The endpoint exposes it as
/// one fixed word.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Phase {
    Connect,
    Greeting,
    Auth,
    Request,
}
impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Connect => "connect",
            Phase::Greeting => "greeting",
            Phase::Auth => "auth",
            Phase::Request => "request",
        }
    }
}

/// One failed setup. The recorder adds the wall time and the name hint.
#[derive(Clone, Copy, Debug)]
pub struct FailureEvent {
    pub proto: Proto,
    pub ip: IpAddr,
    pub port: u16,
    pub reason: Reason,
    pub code: Option<u8>,
    pub phase: Option<Phase>,
}
impl FailureEvent {
    /// A DNS lookup failure. The relay sends DNS to one fixed target.
    pub fn dns(reason: Reason, code: Option<u8>, phase: Option<Phase>) -> Self {
        Self {
            proto: Proto::Dns,
            ip: DNS_TARGET.into(),
            port: 53,
            reason,
            code,
            phase,
        }
    }
}

#[derive(Clone)]
struct Record {
    ts: u64,
    proto: Proto,
    ip: IpAddr,
    port: u16,
    reason: Reason,
    code: Option<u8>,
    phase: Option<Phase>,
    name: Option<String>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct GroupKey {
    proto: Proto,
    family: Family,
    port: u16,
    reason: Reason,
    phase: Option<Phase>,
}
#[derive(Clone)]
struct Group {
    count: u64,
    example_ip: IpAddr,
    code: Option<u8>,
    name: Option<String>,
}

struct Inner {
    recent: VecDeque<Record>,
    groups: HashMap<GroupKey, Group>,
    names: HashMap<IpAddr, String>,
    name_order: VecDeque<IpAddr>,
}
impl Inner {
    fn new() -> Self {
        Self {
            recent: VecDeque::new(),
            groups: HashMap::new(),
            names: HashMap::new(),
            name_order: VecDeque::new(),
        }
    }
    fn clear(&mut self) {
        self.recent.clear();
        self.groups.clear();
        self.names.clear();
        self.name_order.clear();
    }
    fn remember_name(&mut self, ip: IpAddr, name: String) {
        if ip.is_multicast() || ip.is_unspecified() || name.is_empty() || name.len() > 253 {
            return;
        }
        if let Some(stored) = self.names.get_mut(&ip) {
            *stored = name;
            return;
        }
        while self.names.len() >= MAX_NAMES {
            let Some(old) = self.name_order.pop_front() else {
                break;
            };
            self.names.remove(&old);
        }
        self.names.insert(ip, name);
        self.name_order.push_back(ip);
    }
}

/// The failure store. The data path only counts and sends the event on a
/// channel. It never waits for a lock that the endpoint holds. The endpoint
/// and the start and clear calls drain the channel into the store.
pub struct FailureRecorder {
    inner: Mutex<Inner>,
    queue: mpsc::Sender<Queued>,
    drain: Mutex<mpsc::Receiver<Queued>>,
    pending: AtomicUsize,
    total: AtomicU64,
    dropped: AtomicU64,
    since: AtomicU64,
}
impl Default for FailureRecorder {
    fn default() -> Self {
        Self::new()
    }
}
impl FailureRecorder {
    pub fn new() -> Self {
        let (queue, drain) = mpsc::channel();
        Self {
            inner: Mutex::new(Inner::new()),
            queue,
            drain: Mutex::new(drain),
            pending: AtomicUsize::new(0),
            total: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            since: AtomicU64::new(0),
        }
    }
    /// Clear the store and start a new session clock.
    pub fn start(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.discard_pending();
        inner.clear();
        self.total.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
        self.since.store(now().max(1), Ordering::Relaxed);
    }
    /// Clear the store when the tunnel stops.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.discard_pending();
        inner.clear();
        self.total.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
        self.since.store(0, Ordering::Relaxed);
    }
    /// Take the short lock without waiting. The endpoint holds the lock for a
    /// few microseconds, so a brief yield and a second try nearly always wins.
    /// The data path never sleeps or blocks on the lock.
    fn try_inner(&self) -> Option<std::sync::MutexGuard<'_, Inner>> {
        for _ in 0..4 {
            if let Ok(guard) = self.inner.try_lock() {
                return Some(guard);
            }
            std::thread::yield_now();
        }
        None
    }
    /// Record one failed setup. This call never waits for a lock.
    pub fn record(&self, event: FailureEvent) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if self.pending.load(Ordering::Relaxed) >= MAX_PENDING {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.pending.fetch_add(1, Ordering::Relaxed);
        let queued = Queued { ts: now(), event };
        if self.queue.send(queued).is_err() {
            self.pending.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Throw away queued events. The caller holds the store lock.
    fn discard_pending(&self) {
        let drain = self.drain.lock().unwrap_or_else(|e| e.into_inner());
        while drain.try_recv().is_ok() {
            self.pending.fetch_sub(1, Ordering::Relaxed);
        }
    }
    /// Move queued events into the store. The caller holds the store lock.
    fn drain_into(&self, inner: &mut Inner) {
        let drain = self.drain.lock().unwrap_or_else(|e| e.into_inner());
        while let Ok(queued) = drain.try_recv() {
            self.pending.fetch_sub(1, Ordering::Relaxed);
            self.apply(inner, queued);
        }
    }
    /// Add one event to the groups and to the ring.
    fn apply(&self, inner: &mut Inner, queued: Queued) {
        let Queued { ts, event } = queued;
        let name = inner.names.get(&event.ip).cloned();
        let key = GroupKey {
            proto: event.proto,
            family: Family::of(event.ip),
            port: event.port,
            reason: event.reason,
            phase: event.phase,
        };
        let full = inner.groups.len() >= MAX_GROUPS;
        match inner.groups.get_mut(&key) {
            Some(group) => {
                group.count += 1;
                if group.name.is_none() {
                    group.name = name.clone();
                }
                if group.code.is_none() {
                    group.code = event.code;
                }
            }
            None if !full => {
                inner.groups.insert(
                    key,
                    Group {
                        count: 1,
                        example_ip: event.ip,
                        code: event.code,
                        name: name.clone(),
                    },
                );
            }
            None => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        if inner.recent.len() >= MAX_RECENT {
            inner.recent.pop_front();
        }
        inner.recent.push_back(Record {
            ts,
            proto: event.proto,
            ip: event.ip,
            port: event.port,
            reason: event.reason,
            code: event.code,
            phase: event.phase,
            name,
        });
    }
    /// Remember the A and AAAA answers of one DNS reply that the relay forwards.
    /// The map is bounded and keeps no data on disk.
    pub fn remember_dns_response(&self, message: &[u8]) {
        let answers = dns_answers(message);
        if answers.is_empty() {
            return;
        }
        let Some(mut inner) = self.try_inner() else {
            return;
        };
        for (name, ip) in answers {
            inner.remember_name(ip, name);
        }
    }
    /// Return a remembered name. Test use only.
    #[cfg(test)]
    pub fn name_hint(&self, ip: IpAddr) -> Option<String> {
        let inner = self.inner.lock().ok()?;
        inner.names.get(&ip).cloned()
    }
    /// Return the endpoint value. The caller decides whether a tunnel runs.
    pub fn snapshot(&self) -> Value {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.drain_into(&mut inner);
        let since = match self.since.load(Ordering::Relaxed) {
            0 => Value::Null,
            value => json!(value),
        };
        let mut groups: Vec<(u64, GroupKey, Group)> = inner
            .groups
            .iter()
            .map(|(key, group)| (group.count, *key, group.clone()))
            .collect();
        groups.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.proto.cmp(&b.1.proto))
                .then_with(|| a.1.family.cmp(&b.1.family))
                .then_with(|| a.1.reason.cmp(&b.1.reason))
                .then_with(|| a.1.phase.cmp(&b.1.phase))
                .then_with(|| a.1.port.cmp(&b.1.port))
        });
        let groups: Vec<Value> = groups
            .into_iter()
            .take(SHOW_GROUPS)
            .map(|(count, key, group)| {
                json!({
                    "proto": key.proto.as_str(),
                    "family": key.family.as_str(),
                    "port": key.port,
                    "reason": key.reason.as_str(),
                    "phase": key.phase.map(Phase::as_str),
                    "count": count,
                    "name": group.name,
                    "example_ip": group.example_ip.to_string(),
                    "code": group.code,
                })
            })
            .collect();
        let recent: Vec<Value> = inner
            .recent
            .iter()
            .rev()
            .take(SHOW_RECENT)
            .map(|record| {
                json!({
                    "ts": record.ts,
                    "proto": record.proto.as_str(),
                    "family": Family::of(record.ip).as_str(),
                    "ip": record.ip.to_string(),
                    "port": record.port,
                    "reason": record.reason.as_str(),
                    "phase": record.phase.map(Phase::as_str),
                    "name": record.name,
                    "code": record.code,
                })
            })
            .collect();
        json!({
            "ok": true,
            "since": since,
            "total": self.total.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "groups": groups,
            "recent": recent,
        })
    }
}

/// The value that the endpoint returns when no tunnel runs.
pub fn empty_snapshot() -> Value {
    json!({
        "ok": true,
        "since": Value::Null,
        "total": 0,
        "dropped": 0,
        "groups": [],
        "recent": [],
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read one DNS name. Return the name and the offset after it. A compression
/// pointer must point backward or the hop limit stops the loop.
fn read_name(message: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut next = offset;
    let mut jumped = false;
    for _ in 0..32 {
        let length = *message.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let low = *message.get(offset + 1)? as usize;
            let pointer = (((length & 0x3f) as usize) << 8) | low;
            if !jumped {
                next = offset + 2;
                jumped = true;
            }
            if pointer >= message.len() {
                return None;
            }
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        if length == 0 {
            if !jumped {
                next = offset + 1;
            }
            break;
        }
        let start = offset + 1;
        let end = start.checked_add(length as usize)?;
        let label = message.get(start..end)?;
        if label.is_empty() || !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
            return None;
        }
        labels.push(String::from_utf8(label.to_vec()).ok()?.to_ascii_lowercase());
        offset = end;
    }
    if labels.is_empty() {
        return None;
    }
    let name = labels.join(".");
    if name.len() > 253 {
        return None;
    }
    Some((name, next))
}

/// Return the A and AAAA answers in one DNS message.
fn dns_answers(message: &[u8]) -> Vec<(String, IpAddr)> {
    if message.len() < 12 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    if answers == 0 || answers > 64 {
        return Vec::new();
    }
    let mut offset = 12;
    for _ in 0..questions {
        let Some((_, next)) = read_name(message, offset) else {
            return Vec::new();
        };
        offset = match next.checked_add(4) {
            Some(value) if value <= message.len() => value,
            _ => return Vec::new(),
        };
    }
    let mut result = Vec::new();
    for _ in 0..answers {
        let Some((name, next)) = read_name(message, offset) else {
            return Vec::new();
        };
        let Some(header) = message.get(next..next + 10) else {
            return Vec::new();
        };
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let start = match next.checked_add(10) {
            Some(value) => value,
            None => return Vec::new(),
        };
        let end = match start.checked_add(length) {
            Some(value) if value <= message.len() => value,
            _ => return Vec::new(),
        };
        if class == 1 {
            match (kind, length) {
                (1, 4) => {
                    let octets: [u8; 4] = message[start..end].try_into().unwrap();
                    result.push((name, IpAddr::from(octets)));
                }
                (28, 16) => {
                    let octets: [u8; 16] = message[start..end].try_into().unwrap();
                    result.push((name, IpAddr::from(octets)));
                }
                _ => {}
            }
        }
        offset = end;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(proto: Proto, ip: &str, port: u16, reason: Reason, code: Option<u8>) -> FailureEvent {
        FailureEvent {
            proto,
            ip: ip.parse().unwrap(),
            port,
            reason,
            code,
            phase: Some(Phase::Request),
        }
    }
    #[test]
    fn empty_snapshot_has_the_exact_shape() {
        assert_eq!(
            empty_snapshot(),
            json!({"ok":true,"since":null,"total":0,"dropped":0,"groups":[],"recent":[]})
        );
    }
    #[test]
    fn readers_never_make_the_data_path_drop_events() {
        use std::sync::Arc;
        let recorder = Arc::new(FailureRecorder::new());
        recorder.start();
        let reader = {
            let recorder = recorder.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    let _ = recorder.snapshot();
                    std::thread::yield_now();
                }
            })
        };
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let recorder = recorder.clone();
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        recorder.record(event(
                            Proto::Tcp,
                            "203.0.113.5",
                            443,
                            Reason::Unreachable,
                            Some(4),
                        ));
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        reader.join().unwrap();
        let value = recorder.snapshot();
        assert_eq!(value["total"], 2000);
        assert_eq!(value["dropped"], 0);
        assert_eq!(value["groups"][0]["count"], 2000);
    }
    #[test]
    fn snapshots_group_and_sort_newest_first() {
        let recorder = FailureRecorder::new();
        recorder.start();
        let now = recorder.snapshot()["since"].as_u64().unwrap();
        assert!(now > 0);
        for _ in 0..3 {
            recorder.record(event(
                Proto::Tcp,
                "203.0.113.5",
                443,
                Reason::Unreachable,
                Some(4),
            ));
        }
        recorder.record(event(
            Proto::Udp,
            "2001:db8::5",
            443,
            Reason::Refused,
            Some(5),
        ));
        let value = recorder.snapshot();
        assert_eq!(value["ok"], true);
        assert_eq!(value["total"], 4);
        assert_eq!(value["dropped"], 0);
        let groups = value["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["count"], 3);
        assert_eq!(groups[0]["proto"], "tcp");
        assert_eq!(groups[0]["family"], "ipv4");
        assert_eq!(groups[0]["port"], 443);
        assert_eq!(groups[0]["reason"], "unreachable");
        assert_eq!(groups[0]["example_ip"], "203.0.113.5");
        assert_eq!(groups[0]["code"], 4);
        assert_eq!(groups[0]["name"], Value::Null);
        assert_eq!(groups[1]["family"], "ipv6");
        let recent = value["recent"].as_array().unwrap();
        assert_eq!(recent.len(), 4);
        assert_eq!(recent[0]["proto"], "udp");
        assert_eq!(recent[3]["proto"], "tcp");
        recorder.clear();
        assert_eq!(recorder.snapshot(), empty_snapshot());
    }
    #[test]
    fn ring_and_group_limits_hold_and_overflow_is_counted() {
        let recorder = FailureRecorder::new();
        recorder.start();
        for index in 0..250u16 {
            recorder.record(event(
                Proto::Tcp,
                "203.0.113.5",
                1000 + index,
                Reason::Other,
                None,
            ));
        }
        let value = recorder.snapshot();
        assert_eq!(value["total"], 250);
        assert_eq!(value["dropped"], 150);
        assert_eq!(value["groups"].as_array().unwrap().len(), SHOW_GROUPS);
        assert_eq!(value["recent"].as_array().unwrap().len(), SHOW_RECENT);
    }
    #[test]
    fn snapshot_keys_match_the_endpoint_contract() {
        let recorder = FailureRecorder::new();
        recorder.start();
        recorder.record(event(
            Proto::Tcp,
            "203.0.113.5",
            443,
            Reason::Unreachable,
            Some(4),
        ));
        let value = recorder.snapshot();
        fn keys(value: &Value) -> Vec<&str> {
            let mut keys: Vec<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort();
            keys
        }
        assert_eq!(
            keys(&value),
            ["dropped", "groups", "ok", "recent", "since", "total"]
        );
        assert_eq!(
            keys(&value["groups"][0]),
            [
                "code",
                "count",
                "example_ip",
                "family",
                "name",
                "phase",
                "port",
                "proto",
                "reason"
            ]
        );
        assert_eq!(
            keys(&value["recent"][0]),
            ["code", "family", "ip", "name", "phase", "port", "proto", "reason", "ts"]
        );
    }
    #[test]
    fn phases_are_fixed_words_in_the_snapshot() {
        let recorder = FailureRecorder::new();
        recorder.start();
        for (phase, count) in [(Phase::Connect, 1), (Phase::Auth, 2), (Phase::Request, 3)] {
            for _ in 0..count {
                recorder.record(FailureEvent {
                    proto: Proto::Tcp,
                    ip: "203.0.113.5".parse().unwrap(),
                    port: 443,
                    reason: Reason::Other,
                    code: None,
                    phase: Some(phase),
                });
            }
        }
        recorder.record(FailureEvent {
            proto: Proto::Udp,
            ip: "2001:db8::5".parse().unwrap(),
            port: 443,
            reason: Reason::Other,
            code: None,
            phase: None,
        });
        let value = recorder.snapshot();
        let groups = value["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 4);
        assert_eq!(
            (groups[0]["phase"].as_str(), groups[0]["count"].as_u64()),
            (Some("request"), Some(3))
        );
        assert_eq!(
            (groups[1]["phase"].as_str(), groups[1]["count"].as_u64()),
            (Some("auth"), Some(2))
        );
        assert_eq!(
            (groups[2]["phase"].as_str(), groups[2]["count"].as_u64()),
            (Some("connect"), Some(1))
        );
        assert_eq!(groups[3]["phase"], Value::Null);
        let recent = value["recent"].as_array().unwrap();
        assert_eq!(recent[0]["phase"], Value::Null);
        assert_eq!(recent[1]["phase"], "request");
        assert_eq!(recent[4]["phase"], "auth");
        assert_eq!(recent[6]["phase"], "connect");
    }
    #[test]
    fn codes_and_phases_map_to_reasons() {
        assert_eq!(Reason::from_code(3), Reason::Unreachable);
        assert_eq!(Reason::from_code(4), Reason::Unreachable);
        assert_eq!(Reason::from_code(5), Reason::Refused);
        assert_eq!(Reason::from_code(2), Reason::Denied);
        assert_eq!(Reason::from_code(7), Reason::Denied);
        // Code 6 is an expired TTL, not a timeout.
        assert_eq!(Reason::from_code(6), Reason::Other);
        assert_eq!(Reason::from_code(1), Reason::Other);
        assert_eq!(
            Reason::from_error(std::io::ErrorKind::TimedOut),
            Reason::TimedOut
        );
        assert_eq!(
            Reason::from_error(std::io::ErrorKind::HostUnreachable),
            Reason::Unreachable
        );
        assert_eq!(Phase::Connect.as_str(), "connect");
        assert_eq!(Phase::Greeting.as_str(), "greeting");
        assert_eq!(Phase::Auth.as_str(), "auth");
        assert_eq!(Phase::Request.as_str(), "request");
    }
    #[test]
    fn setup_errors_do_not_blame_the_destination_without_a_source_reply() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::NetworkDown,
            ErrorKind::PermissionDenied,
            ErrorKind::TimedOut,
        ] {
            assert_eq!(
                Reason::from_setup_error(kind, None),
                Reason::Other,
                "{kind:?}"
            );
        }
        // A direct connect reaches the destination, so its local timeout is a
        // destination timeout.
        assert_eq!(
            Reason::from_direct_setup_error(ErrorKind::TimedOut),
            Reason::TimedOut
        );
        assert_eq!(
            Reason::from_direct_setup_error(ErrorKind::ConnectionRefused),
            Reason::Refused
        );
        assert_eq!(
            Reason::from_direct_setup_error(ErrorKind::HostUnreachable),
            Reason::Unreachable
        );
        // A source device reply code keeps its meaning even when the local
        // error kind has a different usual class.
        for (code, reason) in [
            (1, Reason::Other),
            (2, Reason::Denied),
            (3, Reason::Unreachable),
            (4, Reason::Unreachable),
            (5, Reason::Refused),
            (6, Reason::Other),
            (7, Reason::Denied),
            (8, Reason::Other),
        ] {
            assert_eq!(
                Reason::from_setup_error(ErrorKind::ConnectionRefused, Some(code)),
                reason,
                "code {code}"
            );
        }
    }
    #[test]
    fn dns_answers_keep_names_and_are_attached_to_records() {
        // A response for one question: example.com A 203.0.113.5,
        // www.example.com AAAA 2001:db8::5, and a CNAME that is ignored.
        let mut message = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut question = Vec::new();
        for label in ["example", "com"] {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.push(0);
        question.extend_from_slice(&[0, 1, 0, 1]);
        message.extend_from_slice(&question);
        // Answer 1: pointer to the question name, A 203.0.113.5.
        message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        message.extend_from_slice(&[203, 0, 113, 5]);
        // Answer 2: www.example.com AAAA 2001:db8::5.
        let name_start = message.len();
        for label in ["www", "example", "com"] {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        message.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        // Answer 3: a CNAME. The name uses a pointer to the second name.
        message.extend_from_slice(&[0xc0, name_start as u8, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2]);
        message.extend_from_slice(&[0xc0, 12]);
        let recorder = FailureRecorder::new();
        recorder.start();
        recorder.remember_dns_response(&message);
        recorder.record(event(
            Proto::Tcp,
            "203.0.113.5",
            443,
            Reason::Unreachable,
            Some(4),
        ));
        recorder.record(event(
            Proto::Tcp,
            "2001:db8::5",
            443,
            Reason::Unreachable,
            Some(4),
        ));
        let value = recorder.snapshot();
        assert_eq!(value["groups"][0]["name"], "example.com");
        assert_eq!(value["groups"][1]["name"], "www.example.com");
        assert_eq!(value["recent"][0]["name"], "www.example.com");
    }
    #[test]
    fn malformed_dns_replies_are_ignored() {
        assert!(dns_answers(&[]).is_empty());
        assert!(dns_answers(&[0xff; 12]).is_empty());
        let mut message = vec![0; 12];
        message[6] = 0;
        message[7] = 1;
        assert!(dns_answers(&message).is_empty());
    }
    #[test]
    fn name_map_is_bounded() {
        let recorder = FailureRecorder::new();
        recorder.start();
        for index in 0..MAX_NAMES + 50 {
            let ip = IpAddr::V4(Ipv4Addr::from((index as u32) + 1));
            let mut message = vec![
                0, 1, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            ];
            message.extend_from_slice(&[7]);
            message.extend_from_slice(b"example");
            message.extend_from_slice(&[3]);
            message.extend_from_slice(b"com");
            message.push(0);
            message.extend_from_slice(&[0, 1, 0, 1]);
            message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            message.extend_from_slice(&ip_octets(ip));
            recorder.remember_dns_response(&message);
        }
        let inner = recorder.inner.lock().unwrap();
        assert_eq!(inner.names.len(), MAX_NAMES);
        assert_eq!(inner.name_order.len(), MAX_NAMES);
    }
    fn ip_octets(ip: IpAddr) -> [u8; 4] {
        match ip {
            IpAddr::V4(value) => value.octets(),
            IpAddr::V6(_) => [0; 4],
        }
    }
}
