//! Scoped phone UDP diagnostic.
//!
//! The diagnostic sends sequenced STUN binding requests through the phone
//! proxy over UDP over TCP. It pins every outer socket
//! to one hotspot interface with the normalized socket factory. It creates no
//! route, no utun, and no listener. It does not change the default route, so
//! the primary network (for example Wi-Fi) stays in use for other traffic.
//!
//! Each run uses one inner flow and one outer socket. The phone token comes
//! from a terminal prompt with echo disabled or from a private file
//! descriptor. It never comes from arguments or the environment. The report
//! contains no token and no payload.
use crate::normalization::{self, Audit};
use crate::phone::{self, PhoneProxy, Target};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub const MAX_RATE: f64 = 500.0;
/// Rate limit with `--own-responder`. Use it only with a responder that the
/// user controls, for example `hotspotshade udp-responder`. Never use it with
/// a public STUN server.
pub const MAX_OWN_RATE: f64 = 5000.0;
pub const MAX_SECONDS: f64 = 120.0;
pub const MAX_PAD: usize = 1200;
pub const MAX_BURST: u32 = 64;
pub const MAX_WAIT: f64 = 10.0;
const STUN_MAGIC: u32 = 0x2112_A442;
const MAX_SECRET_INPUT: usize = 4096;

/// Phone credentials. Debug output is redacted. Drop clears the buffer.
pub struct Secrets {
    token: String,
}
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("token", &"[redacted]")
            .finish()
    }
}
impl Drop for Secrets {
    fn drop(&mut self) {
        // Best effort. Copies made by other code are not cleared.
        unsafe { self.token.as_bytes_mut() }.fill(0);
    }
}
impl Secrets {
    /// The phone token. Do not print or log it.
    pub fn token(&self) -> &str {
        &self.token
    }
}

fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 255 && !token.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn finish_secrets(token: String) -> Result<Secrets, &'static str> {
    if !valid_token(&token) {
        return Err("the source device token must contain 1 to 255 printable bytes");
    }
    Ok(Secrets { token })
}

/// Parse `{"token":"..."}`. Error text never contains input.
pub fn parse_secrets(text: &str) -> Result<Secrets, &'static str> {
    let value: Value =
        serde_json::from_str(text).map_err(|_| "the secret input must be one JSON object")?;
    let object = value
        .as_object()
        .ok_or("the secret input must be one JSON object")?;
    if object.keys().any(|key| key != "token") {
        return Err("the secret input accepts only token");
    }
    let token = object
        .get("token")
        .and_then(Value::as_str)
        .ok_or("the secret input needs a token string")?
        .to_owned();
    finish_secrets(token)
}

/// Read secrets from an inherited descriptor. Accept a pipe, a socket, or a
/// regular file that only the current user can read and write.
pub fn read_secrets_fd(fd: RawFd) -> Result<Secrets, String> {
    if fd < 0 {
        return Err("invalid secret descriptor".into());
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err("the secret descriptor is not open".into());
    }
    // Android's 32-bit stat stores the mode in a wider field than mode_t.
    // The file type and permission bits fit in mode_t.
    #[cfg(all(target_os = "android", target_pointer_width = "32"))]
    let mode = stat.st_mode as libc::mode_t;
    #[cfg(not(all(target_os = "android", target_pointer_width = "32")))]
    let mode = stat.st_mode;
    if !acceptable_secret_descriptor(mode, stat.st_uid, unsafe { libc::geteuid() }) {
        return Err(
            "the secret descriptor must be a pipe, a socket, or a file with mode 0600".into(),
        );
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut buffer = Vec::new();
    let read = file
        .take(MAX_SECRET_INPUT as u64 + 1)
        .read_to_end(&mut buffer);
    let result = match read {
        Ok(_) if buffer.len() > MAX_SECRET_INPUT => {
            Err("the secret input is too large".to_string())
        }
        Ok(_) => match std::str::from_utf8(&buffer) {
            Ok(text) => parse_secrets(text).map_err(str::to_owned),
            Err(_) => Err("the secret input must be UTF-8".into()),
        },
        Err(_) => Err("could not read the secret descriptor".into()),
    };
    buffer.fill(0);
    result
}

/// True when the descriptor mode is a pipe, a socket, or a regular file that
/// only its owner can read and write. `mode` is a `libc::mode_t`. On the
/// 32-bit Android targets that is 16 bits wide while `stat.st_mode` is 32 bits,
/// so the caller casts before the file type and permission bits are read.
fn acceptable_secret_descriptor(mode: libc::mode_t, owner: libc::uid_t, euid: libc::uid_t) -> bool {
    let kind = mode & libc::S_IFMT;
    kind == libc::S_IFIFO
        || kind == libc::S_IFSOCK
        || (kind == libc::S_IFREG && owner == euid && mode & 0o077 == 0)
}

struct EchoGuard {
    fd: RawFd,
    saved: libc::termios,
}
impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

fn read_hidden_line(tty: &mut File, prompt: &str, stop: &AtomicBool) -> io::Result<String> {
    let fd = tty.as_raw_fd();
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut quiet = saved;
    quiet.c_lflag &= !(libc::ECHO as libc::tcflag_t);
    quiet.c_lflag |= libc::ECHONL as libc::tcflag_t;
    let guard = EchoGuard { fd, saved };
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(io::Error::last_os_error());
    }
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // Poll so that a stop signal restores echo before the process exits.
        if stop.load(Ordering::Acquire) {
            line.fill(0);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "input cancelled",
            ));
        }
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut ready, 1, 100) } <= 0 {
            continue;
        }
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' || byte[0] == b'\r' => break,
            Ok(_) if line.len() < MAX_SECRET_INPUT => line.push(byte[0]),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                line.fill(0);
                return Err(e);
            }
        }
    }
    drop(guard);
    let text = String::from_utf8(line).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.fill(0);
        io::Error::new(io::ErrorKind::InvalidData, "input must be UTF-8")
    })?;
    Ok(text)
}

/// Prompt on the controlling terminal with echo disabled. Install the stop
/// signal handler first, so that Ctrl-C restores terminal echo.
pub fn prompt_secrets(stop: &AtomicBool) -> Result<Secrets, String> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "no terminal is available; use --secrets-fd".to_string())?;
    let token = read_hidden_line(&mut tty, "Source device token (input hidden): ", stop)
        .map_err(|_| "could not read the source device token".to_string())?;
    finish_secrets(token).map_err(str::to_owned)
}

/// Return the IPv4 address of `name` whose subnet contains `peer`.
/// Read-only. It uses getifaddrs and changes nothing.
pub fn on_link_address(name: &str, peer: Ipv4Addr) -> io::Result<Option<(Ipv4Addr, Ipv4Addr)>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        if unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() != name.as_bytes() {
            continue;
        }
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        let addr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        let mask = unsafe { &*(entry.ifa_netmask as *const libc::sockaddr_in) };
        let local = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let netmask = Ipv4Addr::from(u32::from_be(mask.sin_addr.s_addr));
        if same_subnet(local, peer, netmask) {
            found = Some((local, netmask));
            break;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

pub fn same_subnet(local: Ipv4Addr, peer: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let m = u32::from(mask);
    m != 0 && local != peer && (u32::from(local) & m) == (u32::from(peer) & m)
}

/// Interface counters from the kernel. They include all traffic on the interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IfCounters {
    pub ipackets: u32,
    pub opackets: u32,
    pub ierrors: u32,
    pub oerrors: u32,
    pub iqdrops: u32,
    pub ibytes: u32,
    pub obytes: u32,
}
impl IfCounters {
    /// The kernel counters are 32-bit. Use wrapping subtraction.
    pub fn delta(&self, before: &IfCounters) -> Value {
        json!({
            "ipackets": self.ipackets.wrapping_sub(before.ipackets),
            "opackets": self.opackets.wrapping_sub(before.opackets),
            "ierrors": self.ierrors.wrapping_sub(before.ierrors),
            "oerrors": self.oerrors.wrapping_sub(before.oerrors),
            "iqdrops": self.iqdrops.wrapping_sub(before.iqdrops),
            "ibytes": self.ibytes.wrapping_sub(before.ibytes),
            "obytes": self.obytes.wrapping_sub(before.obytes),
        })
    }
}

#[cfg(target_os = "macos")]
pub fn interface_counters(name: &str) -> Option<IfCounters> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_data.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != libc::AF_LINK
            || unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() != name.as_bytes()
        {
            continue;
        }
        let data = unsafe { &*(entry.ifa_data as *const libc::if_data) };
        found = Some(IfCounters {
            ipackets: data.ifi_ipackets,
            opackets: data.ifi_opackets,
            ierrors: data.ifi_ierrors,
            oerrors: data.ifi_oerrors,
            iqdrops: data.ifi_iqdrops,
            ibytes: data.ifi_ibytes,
            obytes: data.ifi_obytes,
        });
        break;
    }
    unsafe { libc::freeifaddrs(list) };
    found
}
#[cfg(not(target_os = "macos"))]
pub fn interface_counters(_name: &str) -> Option<IfCounters> {
    None
}

#[cfg(target_os = "macos")]
pub(crate) fn tcp_info(stream: &TcpStream) -> Option<Value> {
    let mut info: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            (&mut info as *mut libc::tcp_connection_info).cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(json!({
        "srtt_ms": info.tcpi_srtt,
        "rttvar_ms": info.tcpi_rttvar,
        "rto_ms": info.tcpi_rto,
        "snd_cwnd": info.tcpi_snd_cwnd,
        "snd_sbbytes": info.tcpi_snd_sbbytes,
        "tx_packets": info.tcpi_txpackets,
        "tx_bytes": info.tcpi_txbytes,
        "tx_retransmit_bytes": info.tcpi_txretransmitbytes,
        "rx_packets": info.tcpi_rxpackets,
        "rx_bytes": info.tcpi_rxbytes,
        "rx_out_of_order_bytes": info.tcpi_rxoutoforderbytes,
        "rx_retransmit_packets": info.tcpi_rxretransmitpackets,
    }))
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn tcp_info(_stream: &TcpStream) -> Option<Value> {
    None
}

/// Build a STUN binding request. The transaction ID is the run ID and the sequence.
pub fn stun_request(sequence: u64, run_id: &[u8; 4], pad: usize) -> Vec<u8> {
    let length = pad.div_ceil(4) * 4;
    let attributes = if pad > 0 { 4 + length } else { 0 };
    let mut packet = Vec::with_capacity(20 + attributes);
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    packet.extend_from_slice(&(attributes as u16).to_be_bytes());
    packet.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    packet.extend_from_slice(run_id);
    packet.extend_from_slice(&sequence.to_be_bytes());
    if pad > 0 {
        // 0xC0DE is comprehension-optional. A server ignores it.
        packet.extend_from_slice(&0xC0DEu16.to_be_bytes());
        packet.extend_from_slice(&(length as u16).to_be_bytes());
        packet.resize(20 + attributes, 0);
    }
    packet
}

/// Return the sequence of a STUN success or error response for this run.
pub fn parse_stun_response(data: &[u8], run_id: &[u8; 4]) -> Option<u64> {
    if data.len() < 20 {
        return None;
    }
    let kind = u16::from_be_bytes([data[0], data[1]]);
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC || !(kind == 0x0101 || kind == 0x0111) || data[8..12] != run_id[..] {
        return None;
    }
    Some(u64::from_be_bytes(data[12..20].try_into().ok()?))
}

/// Deterministic controlled loss. The same run ID and sequence give the same decision.
pub fn induced_drop(sequence: u64, run_id: &[u8; 4], basis_points: u32) -> bool {
    if basis_points == 0 {
        return false;
    }
    let mut z = sequence ^ (u64::from(u32::from_be_bytes(*run_id)) << 32);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z % 10_000) < u64::from(basis_points)
}

/// Settings for one diagnostic run. It contains no secret.
#[derive(Clone, Debug)]
pub struct ProbeConfig {
    /// Authenticated TCP proxy endpoint on the phone.
    pub phone: SocketAddr,
    /// Interface index of the hotspot link. Every outer socket uses it.
    pub iface: u32,
    pub target: SocketAddr,
    pub rate: f64,
    pub seconds: f64,
    pub burst: u32,
    pub pad: usize,
    pub wait: Duration,
    /// Controlled loss before the outer socket, in hundredths of a percent.
    pub drop_basis_points: u32,
    pub run_id: [u8; 4],
}
impl ProbeConfig {
    pub fn count(&self) -> u64 {
        (self.rate * self.seconds).round().max(1.0) as u64
    }
    fn due(&self, start: Instant, sequence: u64) -> Instant {
        let group = sequence / u64::from(self.burst.max(1));
        start + Duration::from_secs_f64(group as f64 * f64::from(self.burst.max(1)) / self.rate)
    }
}

/// Per-run sequence accounting.
#[derive(Default)]
pub struct Tally {
    pub sent_at: BTreeMap<u64, Instant>,
    pub received: HashMap<u64, Duration>,
    pub duplicates: u64,
    pub reordered: u64,
    pub unexpected: u64,
    highest: Option<u64>,
    pub induced: u64,
    pub would_block: u64,
    pub no_buffer: u64,
    pub send_errors: u64,
    pub not_sent: u64,
}
impl Tally {
    pub fn record_sent(&mut self, sequence: u64, at: Instant) {
        self.sent_at.insert(sequence, at);
    }
    pub fn record_reply(&mut self, data: &[u8], run_id: &[u8; 4], at: Instant) {
        let Some(sequence) = parse_stun_response(data, run_id) else {
            self.unexpected += 1;
            return;
        };
        let Some(sent) = self.sent_at.get(&sequence) else {
            self.unexpected += 1;
            return;
        };
        if self.received.contains_key(&sequence) {
            self.duplicates += 1;
            return;
        }
        self.received
            .insert(sequence, at.saturating_duration_since(*sent));
        if self.highest.is_some_and(|h| sequence < h) {
            self.reordered += 1;
        }
        self.highest = Some(self.highest.map_or(sequence, |h| h.max(sequence)));
    }
    pub fn all_answered(&self) -> bool {
        self.received.len() >= self.sent_at.len()
    }
    /// Summarize. Loss counts only requests that the outer socket accepted.
    pub fn summary(&self, count: u64, per_second: u64) -> Value {
        let lost: Vec<u64> = self
            .sent_at
            .keys()
            .copied()
            .filter(|s| !self.received.contains_key(s))
            .collect();
        let mut longest = 0u64;
        let mut run = 0u64;
        let mut previous: Option<u64> = None;
        let mut runs = 0u64;
        for &s in &lost {
            if previous.is_some_and(|p| s == p + 1) {
                run += 1;
            } else {
                run = 1;
                runs += 1;
            }
            longest = longest.max(run);
            previous = Some(s);
        }
        // A loss run that reaches the last sent request did not recover.
        let last_sent = self.sent_at.keys().next_back().copied();
        let unrecovered = match (lost.last(), last_sent) {
            (Some(&l), Some(s)) if l == s => run,
            _ => 0,
        };
        let per_second = per_second.max(1);
        let mut timeline = Vec::new();
        let mut first = 0;
        while first < count {
            let end = (first + per_second).min(count);
            let lost_here = (first..end)
                .filter(|s| self.sent_at.contains_key(s) && !self.received.contains_key(s))
                .count();
            timeline.push(lost_here);
            first = end;
        }
        let mut rtts: Vec<f64> = self
            .received
            .values()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pick = |fraction: f64| -> Value {
            if rtts.is_empty() {
                Value::Null
            } else {
                let index = ((fraction * rtts.len() as f64) as usize).min(rtts.len() - 1);
                json!((rtts[index] * 100.0).round() / 100.0)
            }
        };
        let sent = self.sent_at.len() as u64;
        json!({
            "scheduled": count,
            "induced_drops": self.induced,
            "sent": sent,
            "local_would_block": self.would_block,
            "local_no_buffer": self.no_buffer,
            "send_errors": self.send_errors,
            "not_sent_after_stop": self.not_sent,
            "received": self.received.len(),
            "lost": lost.len(),
            "loss_percent": if sent > 0 { json!(((lost.len() as f64) * 10000.0 / sent as f64).round() / 100.0) } else { Value::Null },
            "duplicates": self.duplicates,
            "reordered": self.reordered,
            "unexpected_replies": self.unexpected,
            "first_lost": lost.first(),
            "loss_runs": runs,
            "longest_loss_run": longest,
            "unrecovered_tail_run": unrecovered,
            "lost_per_second": timeline,
            "rtt_ms": {"min": pick(0.0), "p50": pick(0.5), "p90": pick(0.9), "p99": pick(0.99), "max": rtts.last()},
        })
    }
}

fn per_second(config: &ProbeConfig) -> u64 {
    config.rate.round().max(1.0) as u64
}

fn frame_reader(
    mut stream: TcpStream,
    done: Arc<AtomicBool>,
    tx: mpsc::Sender<(Vec<u8>, Instant)>,
) -> &'static str {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return "phone_closed",
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                let at = Instant::now();
                loop {
                    if buffer.len() < 2 {
                        break;
                    }
                    let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                    if len > 1472 {
                        return "framing_error";
                    }
                    if buffer.len() < 2 + len {
                        break;
                    }
                    let payload = buffer[2..2 + len].to_vec();
                    buffer.drain(..2 + len);
                    if tx.send((payload, at)).is_err() {
                        return "local";
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                if done.load(Ordering::Acquire) {
                    return "local";
                }
            }
            Err(_) => return "io_error",
        }
    }
}

/// Run one UDP-over-TCP flow. Use one authenticated TCP stream for the whole run.
pub fn run_tcp(
    config: &ProbeConfig,
    secrets: &Secrets,
    audit: &Audit,
    stop: &AtomicBool,
) -> io::Result<Value> {
    let proxy = PhoneProxy {
        address: config.phone,
        username: "hotspotshade".into(),
        token: secrets.token.clone(),
        iface: Some(config.iface),
        timeout: Duration::from_secs(5),
    };
    let opened = Instant::now();
    let opened_result = proxy.open_udp(Target::Ip(config.target.ip()), config.target.port(), audit);
    drop(proxy);
    let udp = opened_result?;
    let setup_ms = opened.elapsed().as_secs_f64() * 1000.0;
    let mut stream = udp.stream;
    // The relay sets TCP_NODELAY on phone-mode outer streams. Match it.
    stream.set_nodelay(true)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let reader_stream = stream.try_clone()?;
    let done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let reader_done = done.clone();
    let reader = std::thread::Builder::new()
        .name("udp-diag-tcp-reader".into())
        .spawn(move || frame_reader(reader_stream, reader_done, tx))?;
    let mut tally = Tally::default();
    let count = config.count();
    let start = Instant::now();
    let mut sequence = 0u64;
    let mut last_send = start;
    let mut stream_failed = false;
    let mut frame = Vec::with_capacity(2 + 20 + 4 + MAX_PAD + 4);
    loop {
        let now = Instant::now();
        if stop.load(Ordering::Acquire) && sequence < count {
            tally.not_sent += count - sequence;
            sequence = count;
        }
        while sequence < count && now >= config.due(start, sequence) && !stream_failed {
            if induced_drop(sequence, &config.run_id, config.drop_basis_points) {
                tally.induced += 1;
            } else {
                let request = stun_request(sequence, &config.run_id, config.pad);
                frame.clear();
                frame.extend_from_slice(&(request.len() as u16).to_be_bytes());
                frame.extend_from_slice(&request);
                let at = Instant::now();
                match stream.write_all(&frame) {
                    Ok(()) => tally.record_sent(sequence, at),
                    Err(_) => {
                        tally.send_errors += 1;
                        stream_failed = true;
                    }
                }
                last_send = at;
            }
            sequence += 1;
        }
        if stream_failed && sequence < count {
            tally.not_sent += count - sequence;
            sequence = count;
        }
        let done_sending = sequence >= count;
        if done_sending && (tally.all_answered() || now >= last_send + config.wait) {
            break;
        }
        let next = if done_sending {
            last_send + config.wait
        } else {
            config.due(start, sequence)
        };
        let timeout = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(50));
        match rx.recv_timeout(timeout) {
            Ok((reply, at)) => {
                tally.record_reply(&reply, &config.run_id, at);
                while let Ok((reply, at)) = rx.try_recv() {
                    tally.record_reply(&reply, &config.run_id, at);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // The reader stopped. Stop sending and report the rest as not sent.
                if sequence < count {
                    tally.not_sent += count - sequence;
                }
                stream_failed = true;
                break;
            }
        }
    }
    let info = tcp_info(&stream);
    done.store(true, Ordering::Release);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let reader_end = reader.join().unwrap_or("io_error");
    while let Ok((reply, at)) = rx.try_recv() {
        tally.record_reply(&reply, &config.run_id, at);
    }
    let mut report = tally.summary(count, per_second(config));
    let object = report.as_object_mut().unwrap();
    object.insert("mode".into(), json!("udp_over_tcp"));
    object.insert("ready".into(), json!(true));
    object.insert("setup_ms".into(), json!((setup_ms * 100.0).round() / 100.0));
    object.insert("stream_end".into(), json!(reader_end));
    object.insert("stream_failed".into(), json!(stream_failed));
    object.insert("tcp_info".into(), info.unwrap_or(Value::Null));
    Ok(report)
}

/// Run the UDP-over-TCP diagnostic. Record interface counter deltas. The result
/// is an array with one report.
pub fn run_diag(
    config: &ProbeConfig,
    secrets: &Secrets,
    iface_name: Option<&str>,
    stop: &AtomicBool,
) -> Value {
    let audit = Audit::default();
    let before = iface_name.and_then(interface_counters);
    let result = if stop.load(Ordering::Acquire) {
        Err(io::Error::new(io::ErrorKind::Interrupted, "stopped"))
    } else {
        run_tcp(config, secrets, &audit, stop)
    };
    let after = iface_name.and_then(interface_counters);
    let mut value = match result {
        Ok(value) => value,
        Err(error) => json!({"mode": "udp_over_tcp", "ready": false, "error": safe_error(&error)}),
    };
    let (outer, bad) = audit.snapshot();
    let object = value.as_object_mut().unwrap();
    add_goodput(object, config);
    object.insert("outer_sockets".into(), json!(outer));
    object.insert("ttl_bad".into(), json!(bad));
    if let (Some(b), Some(a)) = (before, after) {
        object.insert("interface_deltas".into(), a.delta(&b));
    }
    Value::Array(vec![value])
}

/// Add UDP payload rates. They count STUN payload bytes only, without UDP,
/// IP, framing, or encryption overhead. The time base is the scheduled send
/// time, so a run that stops early reports a lower rate.
fn add_goodput(object: &mut Map<String, Value>, config: &ProbeConfig) {
    let size = stun_request(0, &config.run_id, config.pad).len() as f64;
    object.insert("payload_bytes".into(), json!(size as u64));
    let rate = |key: &str| -> Value {
        match object.get(key).and_then(Value::as_u64) {
            Some(count) if config.seconds > 0.0 => {
                json!((count as f64 * size * 8.0 / config.seconds / 1e4).round() / 100.0)
            }
            _ => Value::Null,
        }
    };
    let up = rate("sent");
    let down = rate("received");
    object.insert("sent_payload_mbps".into(), up);
    object.insert("received_payload_mbps".into(), down);
}

/// Map an error to a fixed description. Error text never includes input.
pub fn safe_error(error: &io::Error) -> &'static str {
    if let Some(rejection) = phone::auth_rejection(error) {
        return match rejection {
            phone::AuthRejection::Method => "the source device rejected the authentication method",
            phone::AuthRejection::Credentials => "the source device rejected the credentials",
        };
    }
    match error.kind() {
        io::ErrorKind::PermissionDenied => "a local permission error blocked the hotspot socket",
        io::ErrorKind::ConnectionRefused => {
            "the source device refused the connection or the command"
        }
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            "the source device could not reach the destination"
        }
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            "the source device did not answer in time"
        }
        io::ErrorKind::InvalidInput => "invalid diagnostic configuration",
        io::ErrorKind::InvalidData => "the source device sent an invalid reply",
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
            "the source device closed the connection"
        }
        _ => match error.raw_os_error() {
            Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => "hotspot link is unreachable",
            Some(libc::EADDRNOTAVAIL) => "hotspot interface has no usable address",
            _ => "socket error on the hotspot link",
        },
    }
}

/// Command-line options. They contain no secret.
#[derive(Debug, Clone, PartialEq)]
pub struct DiagOptions {
    pub phone: SocketAddr,
    pub iface: String,
    pub target: SocketAddr,
    pub rate: f64,
    pub seconds: f64,
    pub burst: u32,
    pub pad: usize,
    pub wait: f64,
    pub drop_percent: f64,
    pub secrets_fd: Option<RawFd>,
    pub json: bool,
    /// The target is a responder that the user controls. It permits a higher rate.
    pub own_responder: bool,
}

fn option<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

pub const VALUE_FLAGS: &[&str] = &[
    "--phone",
    "--iface",
    "--target",
    "--rate",
    "--seconds",
    "--burst",
    "--pad",
    "--wait",
    "--drop-percent",
    "--secrets-fd",
];
pub const SWITCHES: &[&str] = &["--json", "--own-responder"];

/// Parse the source device proxy endpoint: a private unicast IPv4 address and a nonzero port.
pub fn parse_phone(text: &str) -> Result<SocketAddr, String> {
    let phone = text
        .parse::<SocketAddr>()
        .map_err(|_| "source device must be a numeric IPv4 address and port")?;
    let SocketAddr::V4(phone_v4) = phone else {
        return Err("source device must be a numeric IPv4 address and port".into());
    };
    if phone.port() == 0
        || !phone_v4.ip().is_private()
        || phone_v4.ip().is_unspecified()
        || phone_v4.ip().is_broadcast()
    {
        return Err("source device must be a private unicast IPv4 hotspot address".into());
    }
    Ok(phone)
}

/// Accept only a physical interface name. Reject tunnel, loopback, and bridge names.
pub fn check_iface(iface: &str) -> Result<(), String> {
    if iface.is_empty()
        || iface.len() >= libc::IF_NAMESIZE
        || iface.starts_with("utun")
        || iface.starts_with("lo")
        || iface.starts_with("bridge")
        || iface.parse::<u32>().is_ok()
        || !iface.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err("a physical hotspot interface name is required".into());
    }
    Ok(())
}

/// True for an address that can be a public test destination.
pub fn public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_private()
                || ip.is_link_local()
                || ip.octets()[0] == 0
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfec0
                || ip.to_ipv4_mapped().is_some())
        }
    }
}

fn finite_in(value: &str, low: f64, high: f64, inclusive_low: bool) -> Option<f64> {
    let v = value.parse::<f64>().ok().filter(|v| v.is_finite())?;
    let above = if inclusive_low { v >= low } else { v > low };
    (above && v <= high).then_some(v)
}

/// Parse options after `validate_options` has rejected unknown and repeated flags.
pub fn parse_options(args: &[String]) -> Result<DiagOptions, String> {
    let phone = parse_phone(option(args, "--phone").ok_or("source device address is required")?)?;
    let iface = option(args, "--iface")
        .ok_or("--iface is required; name the wired or wireless hotspot interface")?
        .to_owned();
    check_iface(&iface)?;
    let target = option(args, "--target")
        .ok_or("a numeric STUN --target ADDRESS:PORT is required")?
        .parse::<SocketAddr>()
        .map_err(|_| "target must be a numeric ADDRESS:PORT")?;
    if target.port() == 0 || !public_unicast(target.ip()) {
        return Err("target must be a public unicast address and a nonzero port".into());
    }
    let own_responder = args.iter().any(|a| a == "--own-responder");
    let rate_limit = if own_responder {
        MAX_OWN_RATE
    } else {
        MAX_RATE
    };
    let rate = finite_in(
        option(args, "--rate").unwrap_or("20"),
        0.0,
        rate_limit,
        false,
    )
    .ok_or(if own_responder {
        "rate must be above 0 and at most 5000 requests per second"
    } else {
        "rate must be above 0 and at most 500 requests per second; above 500 needs --own-responder"
    })?;
    let seconds = finite_in(
        option(args, "--seconds").unwrap_or("15"),
        0.0,
        MAX_SECONDS,
        false,
    )
    .ok_or("seconds must be above 0 and at most 120")?;
    let burst = option(args, "--burst")
        .unwrap_or("1")
        .parse::<u32>()
        .ok()
        .filter(|b| (1..=MAX_BURST).contains(b))
        .ok_or("burst must be 1 to 64")?;
    let pad = option(args, "--pad")
        .unwrap_or("0")
        .parse::<usize>()
        .ok()
        .filter(|p| *p <= MAX_PAD)
        .ok_or("pad must be 0 to 1200 bytes")?;
    let wait = finite_in(option(args, "--wait").unwrap_or("8"), 0.0, MAX_WAIT, true)
        .ok_or("wait must be 0 to 10 seconds")?;
    let drop_percent = finite_in(
        option(args, "--drop-percent").unwrap_or("0"),
        0.0,
        90.0,
        true,
    )
    .ok_or("drop percent must be 0 to 90")?;
    let secrets_fd = option(args, "--secrets-fd")
        .map(|v| v.parse::<RawFd>().ok().filter(|fd| *fd >= 0))
        .map(|v| v.ok_or("invalid secret descriptor"))
        .transpose()?;
    if (rate * seconds).round() < 1.0 {
        return Err("rate and seconds must schedule at least one request".into());
    }
    Ok(DiagOptions {
        phone,
        iface,
        target,
        rate,
        seconds,
        burst,
        pad,
        wait,
        drop_percent,
        secrets_fd,
        json: args.iter().any(|a| a == "--json"),
        own_responder,
    })
}

/// Collect read-only facts about the scoped link. Nothing is changed.
pub fn link_report(options: &DiagOptions) -> Result<(u32, Value), String> {
    link_facts(&options.iface, options.phone, &[options.target.ip()])
}

/// Read-only facts about the hotspot link and the default route. Nothing is changed.
pub fn link_facts(
    iface: &str,
    phone: SocketAddr,
    targets: &[IpAddr],
) -> Result<(u32, Value), String> {
    let IpAddr::V4(phone_ip) = phone.ip() else {
        return Err("the source device must be IPv4".into());
    };
    let index = normalization::interface_index(iface)
        .map_err(|_| "the hotspot interface does not exist".to_string())?;
    let (local, mask) = on_link_address(iface, phone_ip)
        .map_err(|_| "could not read interface addresses".to_string())?
        .ok_or_else(|| {
            "the source device address is not on the subnet of the hotspot interface".to_string()
        })?;
    let default = crate::environment::default_route().ok();
    let mut report = Map::new();
    report.insert("hotspot_interface".into(), json!(iface));
    report.insert("hotspot_local_address".into(), json!(local.to_string()));
    report.insert("hotspot_netmask".into(), json!(mask.to_string()));
    report.insert(
        "default_route_interface".into(),
        json!(default.as_ref().map(|r| r.interface.clone())),
    );
    report.insert(
        "default_route_gateway".into(),
        json!(default
            .as_ref()
            .and_then(|r| r.gateway)
            .map(|g| g.to_string())),
    );
    report.insert(
        "default_route_is_hotspot".into(),
        json!(default.as_ref().map(|r| r.interface == iface)),
    );
    report.insert("link_baudrate_bps".into(), json!(interface_baudrate(iface)));
    report.insert(
        "routes_before".into(),
        route_snapshot(iface, phone.ip(), targets),
    );
    Ok((index, Value::Object(report)))
}

/// Read the routes that matter to the scoped path. Read-only.
/// `primary_default` is the unscoped default. `hotspot_scoped_default` is the
/// default in the scope of the hotspot interface. The target lookups show the
/// unscoped route; the pinned outer sockets do not use it.
pub fn route_snapshot(iface: &str, phone: IpAddr, targets: &[IpAddr]) -> Value {
    use crate::environment::route_lookup;
    let show = |lookup: Option<crate::environment::RouteLookup>| -> Value {
        match lookup {
            Some(l) => json!({"interface": l.interface, "gateway": l.gateway}),
            None => Value::Null,
        }
    };
    let mut target_routes = Vec::new();
    for ip in targets {
        target_routes.push(json!({
            "family": if ip.is_ipv6() { "IPv6" } else { "IPv4" },
            "route": show(route_lookup(Some(*ip), None)),
        }));
    }
    json!({
        "primary_default": show(route_lookup(None, None)),
        "hotspot_scoped_default": show(route_lookup(None, Some(iface))),
        "phone": show(route_lookup(Some(phone), None)),
        "targets": target_routes,
    })
}

/// The interface link speed that the kernel reports, in bits per second.
/// A USB tether can report a nominal value. It is not a measured rate.
#[cfg(target_os = "macos")]
pub fn interface_baudrate(name: &str) -> Option<u64> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_data.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) == libc::AF_LINK
            && unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() == name.as_bytes()
        {
            let data = unsafe { &*(entry.ifa_data as *const libc::if_data) };
            found = Some(u64::from(data.ifi_baudrate));
            break;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    found
}
#[cfg(not(target_os = "macos"))]
pub fn interface_baudrate(_name: &str) -> Option<u64> {
    None
}

/// Add `routes_after`, `routes_unchanged`, and `default_route_unchanged` to
/// a link report. Read the same routes again and compare.
pub fn finish_link(link: &mut Value, iface: &str, phone: IpAddr, targets: &[IpAddr]) {
    let after = crate::environment::default_route().ok();
    let routes_after = route_snapshot(iface, phone, targets);
    if let Some(object) = link.as_object_mut() {
        let unchanged = after.as_ref().map(|r| {
            object.get("default_route_interface") == Some(&json!(r.interface))
                && object.get("default_route_gateway")
                    == Some(&json!(r.gateway.map(|g| g.to_string())))
        });
        object.insert("default_route_unchanged".into(), json!(unchanged));
        let same = object.get("routes_before") == Some(&routes_after);
        object.insert("routes_unchanged".into(), json!(same));
        object.insert("routes_after".into(), routes_after);
    }
}

pub fn random_run_id() -> io::Result<[u8; 4]> {
    let mut id = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    Ok(id)
}

pub fn config_from(options: &DiagOptions, iface: u32, run_id: [u8; 4]) -> ProbeConfig {
    ProbeConfig {
        phone: options.phone,
        iface,
        target: options.target,
        rate: options.rate,
        seconds: options.seconds,
        burst: options.burst,
        pad: options.pad,
        wait: Duration::from_secs_f64(options.wait),
        drop_basis_points: (options.drop_percent * 100.0).round() as u32,
        run_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The hotspot address of the phone. Only the tests use it.
    const HOTSPOT_PHONE: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 1);
    use std::net::TcpListener;
    use std::thread;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }
    fn loopback() -> (String, u32) {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        (name.into(), normalization::interface_index(name).unwrap())
    }
    fn secrets() -> Secrets {
        Secrets {
            token: "phone-token-value".into(),
        }
    }
    fn config(phone: SocketAddr, iface: u32) -> ProbeConfig {
        ProbeConfig {
            phone,
            iface,
            target: "203.0.113.9:3478".parse().unwrap(),
            rate: 200.0,
            seconds: 0.2,
            burst: 1,
            pad: 0,
            wait: Duration::from_millis(400),
            drop_basis_points: 0,
            run_id: [1, 2, 3, 4],
        }
    }
    fn stun_reply(request: &[u8]) -> Vec<u8> {
        let mut reply = request[..20].to_vec();
        reply[0] = 0x01;
        reply[1] = 0x01;
        reply[2] = 0;
        reply[3] = 0;
        reply
    }
    fn sequence_of(request: &[u8]) -> u64 {
        u64::from_be_bytes(request[12..20].try_into().unwrap())
    }

    #[test]
    fn stun_round_trip_and_padding() {
        let id = [9, 8, 7, 6];
        let request = stun_request(42, &id, 5);
        assert_eq!(request.len(), 20 + 4 + 8);
        assert_eq!(u16::from_be_bytes([request[2], request[3]]), 12);
        assert_eq!(
            parse_stun_response(&request, &id),
            None,
            "a request is not a reply"
        );
        assert_eq!(parse_stun_response(&stun_reply(&request), &id), Some(42));
        assert_eq!(parse_stun_response(&stun_reply(&request), &[0; 4]), None);
        assert_eq!(parse_stun_response(&request[..19], &id), None);
    }

    #[test]
    fn controlled_loss_is_deterministic_and_close_to_rate() {
        let id = [1, 2, 3, 4];
        let dropped = (0..20_000).filter(|s| induced_drop(*s, &id, 2_500)).count();
        assert!((4_500..5_500).contains(&dropped), "{dropped}");
        assert_eq!(
            (0..100)
                .map(|s| induced_drop(s, &id, 2_500))
                .collect::<Vec<_>>(),
            (0..100)
                .map(|s| induced_drop(s, &id, 2_500))
                .collect::<Vec<_>>()
        );
        assert!(!(0..1000).any(|s| induced_drop(s, &id, 0)));
    }

    #[test]
    fn tally_reports_runs_tail_reorder_and_duplicates() {
        let id = [0; 4];
        let mut tally = Tally::default();
        let start = Instant::now();
        for s in 0..10 {
            tally.record_sent(s, start);
        }
        let at = start + Duration::from_millis(5);
        for s in [0u64, 2, 1, 4, 5, 5] {
            tally.record_reply(&stun_reply(&stun_request(s, &id, 0)), &id, at);
        }
        tally.record_reply(b"short", &id, at);
        let summary = tally.summary(10, 5);
        assert_eq!(summary["sent"], 10);
        assert_eq!(summary["received"], 5);
        assert_eq!(summary["lost"], 5);
        assert_eq!(summary["loss_percent"], 50.0);
        assert_eq!(summary["duplicates"], 1);
        assert_eq!(summary["reordered"], 1);
        assert_eq!(summary["unexpected_replies"], 1);
        assert_eq!(summary["first_lost"], 3);
        assert_eq!(summary["loss_runs"], 2);
        assert_eq!(summary["longest_loss_run"], 4);
        assert_eq!(summary["unrecovered_tail_run"], 4);
        assert_eq!(summary["lost_per_second"], json!([1, 4]));
        assert_eq!(summary["rtt_ms"]["p50"], 5.0);
    }

    #[test]
    fn secrets_parse_strictly_and_never_echo_input() {
        let parsed = parse_secrets(r#"{"token":"tok-1"}"#).unwrap();
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("tok-1"));
        assert_eq!(parsed.token(), "tok-1");
        let leaky = "SECRET-CANARY";
        for input in [
            format!(r#"{{"token":"tok","udp_secret":"{leaky}"}}"#),
            format!(r#"{{"token":"{leaky}","extra":"x"}}"#),
            r#"{"token":""}"#.to_string(),
            format!("[\"{leaky}\"]"),
            format!("{{\"token\":\"{leaky}\""),
            format!(r#"{{"token":"a{}b"}}"#, "\\n"),
        ] {
            let error = parse_secrets(&input).unwrap_err();
            assert!(!error.contains(leaky));
        }
    }

    #[test]
    fn secrets_fd_accepts_pipe_and_private_file_only() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut writer = unsafe { File::from_raw_fd(fds[1]) };
        writer.write_all(br#"{"token":"pipe-token"}"#).unwrap();
        drop(writer);
        assert!(read_secrets_fd(fds[0]).is_ok());

        let dir = std::env::temp_dir().join(format!("hs-udp-diag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.json");
        std::fs::write(&path, br#"{"token":"file-token"}"#).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let open = File::open(&path).unwrap();
        let fd = std::os::fd::IntoRawFd::into_raw_fd(open);
        assert!(read_secrets_fd(fd).is_err());
        unsafe { libc::close(fd) };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fd = std::os::fd::IntoRawFd::into_raw_fd(File::open(&path).unwrap());
        assert!(read_secrets_fd(fd).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(read_secrets_fd(-1).is_err());
    }

    #[test]
    fn secret_descriptor_modes_are_classified_portably() {
        // 32-bit Android has a 16-bit mode_t and a 32-bit stat.st_mode. The
        // file type and permission bits must fit mode_t after the cast.
        let file = |perm: libc::mode_t| libc::S_IFREG | perm;
        assert!(acceptable_secret_descriptor(file(0o600), 1000, 1000));
        assert!(!acceptable_secret_descriptor(file(0o644), 1000, 1000));
        assert!(!acceptable_secret_descriptor(file(0o600), 1000, 1001));
        assert!(acceptable_secret_descriptor(libc::S_IFIFO, 1000, 0));
        assert!(acceptable_secret_descriptor(libc::S_IFSOCK, 1000, 0));
        assert!(!acceptable_secret_descriptor(
            libc::S_IFDIR | 0o700,
            1000,
            1000
        ));
        // Permission bits alone are not a file type.
        assert!(!acceptable_secret_descriptor(0o600, 1000, 1000));
        // Every file type constant fits the target mode_t. On the 32-bit
        // Android targets a 32-bit stat.st_mode would otherwise be truncated.
        for constant in [libc::S_IFMT, libc::S_IFREG, libc::S_IFIFO, libc::S_IFSOCK] {
            assert_eq!(constant & !libc::S_IFMT, 0);
        }
    }

    #[test]
    fn options_require_scope_and_reject_secret_flags() {
        let ok = parse_options(&args(&[
            "--phone",
            "172.20.10.1:18080",
            "--iface",
            "en6",
            "--target",
            "74.125.250.129:19302",
        ]))
        .unwrap();
        assert_eq!(ok.rate, 20.0);
        let v6 = parse_options(&args(&[
            "--phone",
            "172.20.10.1:18080",
            "--iface",
            "en6",
            "--target",
            "[2001:4860:4864:5:8000::1]:19302",
        ]))
        .unwrap();
        assert!(v6.target.is_ipv6());
        for input in [
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--target",
                "74.125.250.129:19302",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "utun4",
                "--target",
                "74.125.250.129:19302",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "lo0",
                "--target",
                "74.125.250.129:19302",
            ],
            vec![
                "--phone",
                "8.8.8.8:18080",
                "--iface",
                "en6",
                "--target",
                "74.125.250.129:19302",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "en6",
                "--target",
                "stun.example:19302",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "en6",
                "--target",
                "192.168.16.1:3478",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "en6",
                "--target",
                "74.125.250.129:19302",
                "--rate",
                "501",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "en6",
                "--target",
                "74.125.250.129:19302",
                "--rate",
                "NaN",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "en6",
                "--target",
                "74.125.250.129:19302",
                "--burst",
                "65",
            ],
            vec![
                "--phone",
                "172.20.10.1:18080",
                "--iface",
                "en6",
                "--target",
                "74.125.250.129:19302",
                "--drop-percent",
                "95",
            ],
        ] {
            assert!(parse_options(&args(&input)).is_err(), "accepted {input:?}");
        }
        assert!(!VALUE_FLAGS
            .iter()
            .any(|f| f.contains("token") || f.contains("secret=")));
    }

    #[test]
    fn subnet_check_requires_shared_prefix() {
        let mask: Ipv4Addr = "255.255.255.240".parse().unwrap();
        assert!(same_subnet(
            "172.20.10.3".parse().unwrap(),
            HOTSPOT_PHONE,
            mask
        ));
        assert!(!same_subnet(
            "192.168.16.5".parse().unwrap(),
            HOTSPOT_PHONE,
            "255.255.255.0".parse().unwrap()
        ));
        assert!(!same_subnet(HOTSPOT_PHONE, HOTSPOT_PHONE, mask));
        assert!(!same_subnet(
            "172.20.10.3".parse().unwrap(),
            HOTSPOT_PHONE,
            Ipv4Addr::UNSPECIFIED
        ));
        let (name, _) = loopback();
        let found = on_link_address(&name, "127.0.0.9".parse().unwrap()).unwrap();
        assert_eq!(found.map(|f| f.0), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(on_link_address(&name, HOTSPOT_PHONE).unwrap(), None);
        if cfg!(target_os = "macos") {
            assert!(interface_counters(&name).is_some());
        }
    }

    // Mock phone for UDP over TCP. It authenticates and drops every fifth request.
    fn tcp_phone(listener: TcpListener, token: &'static str) {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut hello = [0; 3];
        s.read_exact(&mut hello).unwrap();
        s.write_all(&[5, 2]).unwrap();
        let mut head = [0; 2];
        s.read_exact(&mut head).unwrap();
        let mut user = vec![0; head[1] as usize];
        s.read_exact(&mut user).unwrap();
        let mut plen = [0; 1];
        s.read_exact(&mut plen).unwrap();
        let mut pass = vec![0; plen[0] as usize];
        s.read_exact(&mut pass).unwrap();
        assert_eq!(user, b"hotspotshade");
        assert_eq!(pass, token.as_bytes());
        s.write_all(&[1, 0]).unwrap();
        let mut req = [0; 10];
        s.read_exact(&mut req).unwrap();
        assert_eq!(&req[..4], &[5, 0x80, 0, 1]);
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        loop {
            let mut len = [0; 2];
            if s.read_exact(&mut len).is_err() {
                return;
            }
            let mut request = vec![0; u16::from_be_bytes(len) as usize];
            if s.read_exact(&mut request).is_err() {
                return;
            }
            if sequence_of(&request) % 5 == 4 {
                continue;
            }
            let reply = stun_reply(&request);
            let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&reply);
            if s.write_all(&frame).is_err() {
                return;
            }
        }
    }

    #[test]
    fn tcp_mode_counts_loss_audits_ttl_and_hides_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || tcp_phone(listener, "phone-token-value"));
        let (_, index) = loopback();
        let audit = Audit::default();
        let report = run_tcp(
            &config(addr, index),
            &secrets(),
            &audit,
            &AtomicBool::new(false),
        )
        .unwrap();
        mock.join().unwrap();
        assert_eq!(report["sent"], 40);
        assert_eq!(report["lost"], 8);
        assert_eq!(report["loss_percent"], 20.0);
        assert_eq!(report["longest_loss_run"], 1);
        assert_eq!(audit.snapshot(), (1, 0));
        assert!(!report.to_string().contains("phone-token-value"));
    }

    #[test]
    fn tcp_mode_separates_induced_loss() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || tcp_phone(listener, "phone-token-value"));
        let (_, index) = loopback();
        let mut cfg = config(addr, index);
        cfg.drop_basis_points = 5_000;
        cfg.burst = 4;
        let report = run_tcp(&cfg, &secrets(), &Audit::default(), &AtomicBool::new(false)).unwrap();
        mock.join().unwrap();
        let induced = (0..40)
            .filter(|s| induced_drop(*s, &cfg.run_id, 5_000))
            .count() as u64;
        let mock_loss = (0..40)
            .filter(|s| !induced_drop(*s, &cfg.run_id, 5_000) && s % 5 == 4)
            .count() as u64;
        assert_eq!(report["induced_drops"], induced);
        assert_eq!(report["sent"], 40 - induced);
        assert_eq!(report["lost"], mock_loss);
    }

    #[test]
    fn safe_error_distinguishes_local_permission_from_auth_rejection() {
        for code in [libc::EACCES, libc::EPERM] {
            let local = io::Error::from_raw_os_error(code);
            assert_eq!(local.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                safe_error(&local),
                "a local permission error blocked the hotspot socket"
            );
        }
        assert_eq!(
            safe_error(&phone::rejected_credentials_error()),
            "the source device rejected the credentials"
        );
        assert_eq!(
            safe_error(&phone::rejected_method_error(
                io::ErrorKind::PermissionDenied
            )),
            "the source device rejected the authentication method"
        );
        // A source device SOCKS code 3 or 4 is not a refusal.
        assert_eq!(
            safe_error(&io::Error::from(io::ErrorKind::HostUnreachable)),
            "the source device could not reach the destination"
        );
        assert_eq!(
            safe_error(&io::Error::from(io::ErrorKind::NetworkUnreachable)),
            "the source device could not reach the destination"
        );
        assert_eq!(
            safe_error(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            "the source device refused the connection or the command"
        );
        for message in [
            safe_error(&phone::rejected_credentials_error()),
            safe_error(&phone::rejected_method_error(
                io::ErrorKind::PermissionDenied,
            )),
        ] {
            assert!(!message.contains("phone-token-value"));
        }
    }
    #[test]
    fn tcp_mode_reports_rejected_token_without_text() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut buf = [0; 64];
            let _ = s.read(&mut buf);
            s.write_all(&[1, 1]).unwrap();
        });
        let (name, index) = loopback();
        let value = run_diag(
            &config(addr, index),
            &secrets(),
            Some(&name),
            &AtomicBool::new(false),
        );
        mock.join().unwrap();
        assert_eq!(
            value[0]["error"],
            "the source device rejected the credentials"
        );
        assert_eq!(value[0]["ttl_bad"], 0);
        assert!(!value.to_string().contains("phone-token-value"));
    }

    #[test]
    fn own_responder_permits_bounded_bulk_rate_only() {
        let base = [
            "--phone",
            "172.20.10.1:18080",
            "--iface",
            "en6",
            "--target",
            "203.0.113.50:3479",
            "--rate",
        ];
        let with = |rate: &str, own: bool| {
            let mut all: Vec<&str> = base.to_vec();
            all.push(rate);
            if own {
                all.push("--own-responder");
            }
            parse_options(&args(&all))
        };
        assert!(with("2000", false).is_err());
        let ok = with("2000", true).unwrap();
        assert!(ok.own_responder);
        assert_eq!(ok.wait, 8.0, "wait covers the 5 second phone hold");
        assert!(with("5001", true).is_err());
        assert!(parse_options(&args(&[
            "--phone",
            "172.20.10.1:18080",
            "--iface",
            "en6",
            "--target",
            "100.64.1.1:3479",
        ]))
        .is_err());
    }
}
