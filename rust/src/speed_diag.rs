//! Scoped TCP throughput and latency-under-load diagnostic.
//!
//! The diagnostic measures TCP download and upload throughput through the
//! authenticated phone proxy. It measures latency with small probes on the
//! same path while the load runs, and with the same probes while the path is
//! idle. Optionally, it runs the same test on the target device direct path through
//! the hotspot, with the same address, for an apples-to-apples comparison.
//!
//! It pins every outer socket to one hotspot interface with the normalized
//! socket factory. It creates no route, no utun, and no listener. Each load
//! request and each probe uses its own outer socket and its own inner flow.
//! The target device never resolves a host name. On the source device path, the source device
//! resolves the name. The direct path needs a numeric address.
//!
//! The load uses plain HTTP/1.1. The tool has no TLS. Choose a test server
//! whose operator permits this use. The phone token comes from a hidden prompt
//! or a private descriptor. The report contains no token and no payload.
use crate::normalization::{self, Audit};
use crate::phone::{PhoneProxy, Target};
use crate::udp_diag::{self, ProbeConfig, Secrets};
use serde_json::{json, Map, Value};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MAX_STREAMS: usize = 16;
pub const MAX_PHASE_SECONDS: f64 = 30.0;
pub const MAX_IDLE_SECONDS: f64 = 30.0;
pub const MAX_REPEAT: u32 = 5;
pub const MAX_MB_PER_PHASE: u64 = 2000;
pub const MIN_PROBE_INTERVAL_MS: u64 = 200;
pub const MAX_PROBE_INTERVAL_MS: u64 = 5000;
const SAMPLE: Duration = Duration::from_millis(250);
const IO_TICK: Duration = Duration::from_millis(200);
const HEADER_LIMIT: usize = 16 * 1024;
const UPLOAD_REQUEST_BYTES: u64 = 25_000_000;
const MAX_CONSECUTIVE_FAILURES: u32 = 3;
const UDP_PROBE_RATE: f64 = 5.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// Each flow is one authenticated phone proxy connection.
    Phone,
    /// Each flow is one normalized target device socket through the hotspot NAT.
    Direct,
}
impl PathKind {
    pub fn name(self) -> &'static str {
        match self {
            PathKind::Phone => "phone_proxy",
            PathKind::Direct => "laptop_direct",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Load {
    Idle,
    Download,
    Upload,
}
impl Load {
    fn name(self) -> &'static str {
        match self {
            Load::Idle => "idle",
            Load::Download => "download",
            Load::Upload => "upload",
        }
    }
}

/// Settings for one run. It contains no secret.
#[derive(Clone, Debug)]
pub struct SpeedConfig {
    pub phone: SocketAddr,
    pub iface: u32,
    /// The HTTP Host header. On the phone path without `address`, the phone resolves it.
    pub host: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub download_path: Option<String>,
    pub upload_path: Option<String>,
    /// Optional small HTTP request for time to first byte. Without it, the probe measures connect time only.
    pub probe_path: Option<String>,
    pub streams: usize,
    pub seconds: f64,
    pub idle_seconds: f64,
    /// Probes and the steady throughput start after this time in a load phase.
    pub warmup: f64,
    pub probe_interval: Duration,
    pub max_bytes: u64,
    pub connect_timeout: Duration,
    /// Optional UDP latency probe through the phone, at a low fixed rate.
    pub udp_target: Option<SocketAddr>,
}

/// Open one outer flow on one path.
struct Opener<'a> {
    kind: PathKind,
    config: &'a SpeedConfig,
    proxy: Option<&'a PhoneProxy>,
    audit: &'a Audit,
}
impl Opener<'_> {
    fn open(&self) -> io::Result<TcpStream> {
        let stream = match self.kind {
            PathKind::Phone => {
                let proxy = self
                    .proxy
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no phone"))?;
                let target = match self.config.address {
                    Some(ip) => Target::Ip(ip),
                    None => Target::Domain(&self.config.host),
                };
                proxy.open_tcp(target, self.config.port, self.audit)?
            }
            PathKind::Direct => {
                let ip = self.config.address.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "direct path needs an address")
                })?;
                normalization::tcp_connect(
                    SocketAddr::new(ip, self.config.port),
                    Some(self.config.iface),
                    self.audit,
                    self.config.connect_timeout,
                )?
            }
        };
        stream.set_read_timeout(Some(IO_TICK))?;
        stream.set_write_timeout(Some(IO_TICK))?;
        Ok(stream)
    }
    /// Time to an authenticated phone session, without a destination.
    /// It measures the target device to source device hop and the source device app under the same load.
    fn auth(&self) -> Option<io::Result<()>> {
        self.proxy.map(|p| p.check(self.audit))
    }
}

pub fn request_head(
    method: &str,
    path: &str,
    host: &str,
    port: u16,
    length: Option<u64>,
) -> String {
    let host_header = if port == 80 {
        host.to_owned()
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: hotspotshade-speed-diag\r\nAccept: */*\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: close\r\n"
    );
    if let Some(length) = length {
        head.push_str(&format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {length}\r\n"
        ));
    }
    head.push_str("\r\n");
    head
}

/// Return the status code and the header length when the head is complete.
pub fn parse_status(buffer: &[u8]) -> Option<Result<(u16, usize), ()>> {
    let end = buffer.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let line_end = buffer.windows(2).position(|w| w == b"\r\n").unwrap_or(0);
    let line = std::str::from_utf8(&buffer[..line_end]).ok();
    let code = line.and_then(|l| {
        let mut parts = l.split(' ');
        let version = parts.next()?;
        if !version.starts_with("HTTP/1.") {
            return None;
        }
        parts.next()?.parse::<u16>().ok()
    });
    Some(code.map(|c| (c, end)).ok_or(()))
}

/// Read the response head until `deadline`. Return the status, the body bytes
/// already read, and the time of the first response byte.
fn read_head(
    stream: &mut TcpStream,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<(u16, usize, Instant)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let mut first = None;
    loop {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no response head"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => {
                first.get_or_insert_with(Instant::now);
                buffer.extend_from_slice(&chunk[..n]);
                match parse_status(&buffer) {
                    Some(Ok((code, head))) => {
                        return Ok((code, buffer.len() - head, first.unwrap()))
                    }
                    Some(Err(())) => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad status"))
                    }
                    None if buffer.len() > HEADER_LIMIT => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"))
                    }
                    None => {}
                }
            }
            Err(e) if is_tick(&e) => {}
            Err(e) => return Err(e),
        }
    }
}

fn is_tick(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    done: &AtomicBool,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if done.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "phase ended"));
        }
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "closed")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if is_tick(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Bytes in the send buffer that the peer has not acknowledged.
fn unsent_bytes(fd: RawFd) -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut value: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NWRITE,
                (&mut value as *mut libc::c_int).cast(),
                &mut size,
            )
        };
        if rc == 0 && value > 0 {
            return value as u64;
        }
    }
    let _ = fd;
    0
}

/// Shared counts for one load phase. Aggregate only.
#[derive(Default)]
struct LoadState {
    bytes: AtomicU64,
    unsent_at_end: AtomicU64,
    requests_started: AtomicU64,
    requests_completed: AtomicU64,
    open_errors: AtomicU64,
    http_errors: AtomicU64,
    io_errors: AtomicU64,
    active: AtomicUsize,
    tcp: Mutex<TcpAggregate>,
}

#[derive(Default)]
struct TcpAggregate {
    srtt_ms: Vec<f64>,
    retransmit_bytes: u64,
    rx_out_of_order_bytes: u64,
    rx_retransmit_packets: u64,
}
impl TcpAggregate {
    fn add(&mut self, stream: &TcpStream) {
        let Some(info) = udp_diag::tcp_info(stream) else {
            return;
        };
        if let Some(v) = info["srtt_ms"].as_f64() {
            self.srtt_ms.push(v);
        }
        self.retransmit_bytes += info["tx_retransmit_bytes"].as_u64().unwrap_or(0);
        self.rx_out_of_order_bytes += info["rx_out_of_order_bytes"].as_u64().unwrap_or(0);
        self.rx_retransmit_packets += info["rx_retransmit_packets"].as_u64().unwrap_or(0);
    }
    fn to_json(&self) -> Value {
        json!({
            "flows_sampled": self.srtt_ms.len(),
            "srtt_ms": percentiles(&self.srtt_ms),
            "tx_retransmit_bytes": self.retransmit_bytes,
            "rx_out_of_order_bytes": self.rx_out_of_order_bytes,
            "rx_retransmit_packets": self.rx_retransmit_packets,
        })
    }
}

fn fill_pattern() -> Vec<u8> {
    // Incompressible bytes. A fixed xorshift seed keeps runs comparable.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..64 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn load_worker(
    load: Load,
    opener: &Opener<'_>,
    config: &SpeedConfig,
    state: &LoadState,
    done: &AtomicBool,
    stop: &AtomicBool,
    pattern: &[u8],
) {
    let path = match load {
        Load::Download => config.download_path.as_deref(),
        Load::Upload => config.upload_path.as_deref(),
        Load::Idle => None,
    };
    let Some(path) = path else { return };
    let mut failures = 0u32;
    let mut chunk = vec![0u8; 64 * 1024];
    while !done.load(Ordering::Acquire)
        && !stop.load(Ordering::Acquire)
        && state.bytes.load(Ordering::Relaxed) < config.max_bytes
    {
        if failures >= MAX_CONSECUTIVE_FAILURES {
            break;
        }
        let mut stream = match opener.open() {
            Ok(s) => s,
            Err(_) => {
                state.open_errors.fetch_add(1, Ordering::Relaxed);
                failures += 1;
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        state.requests_started.fetch_add(1, Ordering::Relaxed);
        let ok = match load {
            Load::Download => {
                download_once(&mut stream, path, config, state, done, stop, &mut chunk)
            }
            Load::Upload => upload_once(&mut stream, path, config, state, done, stop, pattern),
            Load::Idle => Ok(true),
        };
        match ok {
            Ok(true) => {
                failures = 0;
                state.requests_completed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => {}
            Err(Failure::Http) => {
                failures += 1;
                state.http_errors.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(Failure::Io) => {
                failures += 1;
                state.io_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Ok(mut tcp) = state.tcp.lock() {
            tcp.add(&stream);
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

enum Failure {
    Http,
    Io,
}

/// Return Ok(true) for a complete response, Ok(false) when the phase ended first.
fn download_once(
    stream: &mut TcpStream,
    path: &str,
    config: &SpeedConfig,
    state: &LoadState,
    done: &AtomicBool,
    stop: &AtomicBool,
    chunk: &mut [u8],
) -> Result<bool, Failure> {
    let head = request_head("GET", path, &config.host, config.port, None);
    if write_all_until(stream, head.as_bytes(), done, stop).is_err() {
        return if done.load(Ordering::Acquire) {
            Ok(false)
        } else {
            Err(Failure::Io)
        };
    }
    let deadline = Instant::now() + config.connect_timeout;
    let (code, body, _) = match read_head(stream, deadline, done) {
        Ok(v) => v,
        Err(_) if done.load(Ordering::Acquire) || stop.load(Ordering::Acquire) => return Ok(false),
        Err(_) => return Err(Failure::Io),
    };
    if !(200..300).contains(&code) {
        return Err(Failure::Http);
    }
    state.bytes.fetch_add(body as u64, Ordering::Relaxed);
    loop {
        if done.load(Ordering::Acquire)
            || stop.load(Ordering::Acquire)
            || state.bytes.load(Ordering::Relaxed) >= config.max_bytes
        {
            return Ok(false);
        }
        match stream.read(chunk) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                state.bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) if is_tick(&e) => {}
            Err(_) => return Err(Failure::Io),
        }
    }
}

fn upload_once(
    stream: &mut TcpStream,
    path: &str,
    config: &SpeedConfig,
    state: &LoadState,
    done: &AtomicBool,
    stop: &AtomicBool,
    pattern: &[u8],
) -> Result<bool, Failure> {
    let remaining_cap = config
        .max_bytes
        .saturating_sub(state.bytes.load(Ordering::Relaxed));
    let length = UPLOAD_REQUEST_BYTES.min(remaining_cap).max(1);
    let head = request_head("POST", path, &config.host, config.port, Some(length));
    if write_all_until(stream, head.as_bytes(), done, stop).is_err() {
        return if done.load(Ordering::Acquire) {
            Ok(false)
        } else {
            Err(Failure::Io)
        };
    }
    let mut left = length;
    while left > 0 {
        if done.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
            state
                .unsent_at_end
                .fetch_add(unsent_bytes(stream.as_raw_fd()), Ordering::Relaxed);
            return Ok(false);
        }
        let size = (left as usize).min(pattern.len());
        match stream.write(&pattern[..size]) {
            Ok(0) => return Err(Failure::Io),
            Ok(n) => {
                left -= n as u64;
                state.bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) if is_tick(&e) => {}
            Err(_) => return Err(Failure::Io),
        }
    }
    // The body is complete. Wait for the status, but not past the phase end.
    let deadline = Instant::now() + config.connect_timeout;
    loop {
        match read_head(stream, deadline.min(Instant::now() + IO_TICK * 2), done) {
            Ok((code, _, _)) if (200..300).contains(&code) => return Ok(true),
            Ok(_) => return Err(Failure::Http),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                if done.load(Ordering::Acquire) || Instant::now() >= deadline {
                    state
                        .unsent_at_end
                        .fetch_add(unsent_bytes(stream.as_raw_fd()), Ordering::Relaxed);
                    return Ok(false);
                }
            }
            Err(_) => return Err(Failure::Io),
        }
    }
}

/// Latency samples from one phase. Aggregate only.
#[derive(Default)]
struct ProbeState {
    attempts: u64,
    failures: u64,
    connect_ms: Vec<f64>,
    ttfb_ms: Vec<f64>,
    http_errors: u64,
    auth_ms: Vec<f64>,
    auth_failures: u64,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn probe_once(
    opener: &Opener<'_>,
    config: &SpeedConfig,
    probe: &mut ProbeState,
    stop: &AtomicBool,
) {
    probe.attempts += 1;
    let started = Instant::now();
    match opener.open() {
        Ok(mut stream) => {
            probe.connect_ms.push(ms(started.elapsed()));
            if let Some(path) = config.probe_path.as_deref() {
                let head = request_head("GET", path, &config.host, config.port, None);
                let never = AtomicBool::new(false);
                let sent = Instant::now();
                let result = write_all_until(&mut stream, head.as_bytes(), &never, stop)
                    .and_then(|_| read_head(&mut stream, sent + config.connect_timeout, stop));
                match result {
                    Ok((code, _, first)) if (200..400).contains(&code) => {
                        probe
                            .ttfb_ms
                            .push(ms(first.saturating_duration_since(sent)));
                    }
                    Ok(_) => probe.http_errors += 1,
                    Err(_) => probe.failures += 1,
                }
            }
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Err(_) => probe.failures += 1,
    }
    let started = Instant::now();
    match opener.auth() {
        Some(Ok(())) => probe.auth_ms.push(ms(started.elapsed())),
        Some(Err(_)) => probe.auth_failures += 1,
        None => {}
    }
}

/// Nearest-rank percentiles. Null when there is no sample.
pub fn percentiles(values: &[f64]) -> Value {
    if values.is_empty() {
        return json!({"count": 0, "min": null, "p50": null, "p95": null, "p99": null, "max": null});
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pick = |q: f64| {
        let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
        (sorted[rank - 1] * 100.0).round() / 100.0
    };
    json!({
        "count": sorted.len(),
        "min": (sorted[0] * 100.0).round() / 100.0,
        "p50": pick(0.50),
        "p95": pick(0.95),
        "p99": pick(0.99),
        "max": (sorted[sorted.len() - 1] * 100.0).round() / 100.0,
    })
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0.0;
    }
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

fn mbps(bytes: u64, seconds: f64) -> Value {
    if seconds <= 0.0 {
        return Value::Null;
    }
    json!((bytes as f64 * 8.0 / seconds / 1e4).round() / 100.0)
}

/// Run one phase: optional load, latency probes, and an optional UDP probe.
fn run_phase(
    load: Load,
    opener: &Opener<'_>,
    config: &SpeedConfig,
    secrets: Option<&Secrets>,
    iface_name: Option<&str>,
    stop: &AtomicBool,
) -> Value {
    let seconds = if load == Load::Idle {
        config.idle_seconds
    } else {
        config.seconds
    };
    let probe_delay = if load == Load::Idle {
        0.0
    } else {
        config.warmup
    };
    let state = LoadState::default();
    let done = AtomicBool::new(false);
    let probe = Mutex::new(ProbeState::default());
    let udp_report: Mutex<Option<Value>> = Mutex::new(None);
    let pattern = fill_pattern();
    let counters_before = iface_name.and_then(udp_diag::interface_counters);
    let cpu_before = cpu_seconds();
    let start = Instant::now();
    let end = start + Duration::from_secs_f64(seconds);
    let mut series: Vec<u64> = Vec::new();
    let mut warm_bytes = None;
    std::thread::scope(|scope| {
        if load != Load::Idle {
            for _ in 0..config.streams {
                state.active.fetch_add(1, Ordering::AcqRel);
                scope.spawn(|| {
                    load_worker(load, opener, config, &state, &done, stop, &pattern);
                    state.active.fetch_sub(1, Ordering::AcqRel);
                });
            }
        }
        scope.spawn(|| {
            let first = start + Duration::from_secs_f64(probe_delay);
            let mut next = first;
            while !done.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
                let now = Instant::now();
                if now >= end {
                    break;
                }
                if now < next {
                    std::thread::sleep((next - now).min(Duration::from_millis(50)));
                    continue;
                }
                let mut sample = ProbeState::default();
                probe_once(opener, config, &mut sample, stop);
                if let Ok(mut total) = probe.lock() {
                    total.attempts += sample.attempts;
                    total.failures += sample.failures;
                    total.http_errors += sample.http_errors;
                    total.auth_failures += sample.auth_failures;
                    total.connect_ms.extend(sample.connect_ms);
                    total.ttfb_ms.extend(sample.ttfb_ms);
                    total.auth_ms.extend(sample.auth_ms);
                }
                next += config.probe_interval;
            }
        });
        if let (Some(target), Some(secrets), PathKind::Phone) =
            (config.udp_target, secrets, opener.kind)
        {
            let udp_seconds = (seconds - probe_delay).max(0.2);
            let slot = &udp_report;
            scope.spawn(move || {
                std::thread::sleep(Duration::from_secs_f64(probe_delay));
                let Ok(run_id) = udp_diag::random_run_id() else {
                    return;
                };
                let probe_config = ProbeConfig {
                    phone: config.phone,
                    iface: config.iface,
                    target,
                    rate: UDP_PROBE_RATE,
                    seconds: udp_seconds,
                    burst: 1,
                    pad: 0,
                    wait: Duration::from_secs(8),
                    drop_basis_points: 0,
                    run_id,
                };
                let result = udp_diag::run_tcp(&probe_config, secrets, opener.audit, stop);
                let value = match result {
                    Ok(mut v) => {
                        // Keep the latency and loss summary only.
                        let keep = [
                            "mode",
                            "ready",
                            "sent",
                            "received",
                            "lost",
                            "rtt_ms",
                            "close_reason",
                            "longest_loss_run",
                        ];
                        if let Some(object) = v.as_object_mut() {
                            object.retain(|k, _| keep.contains(&k.as_str()));
                        }
                        v
                    }
                    Err(error) => json!({"ready": false, "error": udp_diag::safe_error(&error)}),
                };
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(value);
                }
            });
        }
        // Sample the byte count. End early if every load worker stopped.
        let warm_at = start + Duration::from_secs_f64(probe_delay);
        let mut next = start + SAMPLE;
        loop {
            let now = Instant::now();
            if now >= end || stop.load(Ordering::Acquire) {
                break;
            }
            if load != Load::Idle && state.active.load(Ordering::Acquire) == 0 {
                break;
            }
            if now >= next {
                series.push(state.bytes.load(Ordering::Relaxed));
                next += SAMPLE;
            }
            if warm_bytes.is_none() && now >= warm_at {
                warm_bytes = Some((state.bytes.load(Ordering::Relaxed), now));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        done.store(true, Ordering::Release);
    });
    let elapsed = start.elapsed().as_secs_f64();
    let load_elapsed = Instant::now().min(end).duration_since(start).as_secs_f64();
    let cpu = cpu_seconds() - cpu_before;
    let counters_after = iface_name.and_then(udp_diag::interface_counters);
    let bytes = state.bytes.load(Ordering::Relaxed);
    let probe = probe.into_inner().unwrap_or_default();
    let mut report = Map::new();
    report.insert("phase".into(), json!(load.name()));
    report.insert("seconds".into(), json!((elapsed * 100.0).round() / 100.0));
    if load != Load::Idle {
        let unsent = state.unsent_at_end.load(Ordering::Relaxed);
        let delivered = bytes.saturating_sub(unsent);
        let steady = warm_bytes.map(|(b, at)| {
            let span = (start + Duration::from_secs_f64(load_elapsed))
                .saturating_duration_since(at)
                .as_secs_f64();
            mbps(delivered.saturating_sub(b), span)
        });
        let mut intervals: Vec<f64> = Vec::new();
        let warm_index = (probe_delay / SAMPLE.as_secs_f64()).ceil() as usize;
        for pair in series.windows(2).skip(warm_index.saturating_sub(1)) {
            intervals.push((pair[1] - pair[0]) as f64 * 8.0 / SAMPLE.as_secs_f64() / 1e6);
        }
        let tcp = state.tcp.lock().map(|t| t.to_json()).unwrap_or(Value::Null);
        report.insert(
            "throughput".into(),
            json!({
                "streams": config.streams,
                "bytes_counted": bytes,
                "bytes_unsent_at_end": unsent,
                "mbps_mean": mbps(delivered, load_elapsed),
                "mbps_after_warmup": steady.unwrap_or(Value::Null),
                "interval_mbps": percentiles(&intervals),
                "reached_byte_cap": bytes >= config.max_bytes,
                "ended_early": load_elapsed + 0.3 < seconds && !stop.load(Ordering::Acquire),
                "requests_started": state.requests_started.load(Ordering::Relaxed),
                "requests_completed": state.requests_completed.load(Ordering::Relaxed),
                "open_errors": state.open_errors.load(Ordering::Relaxed),
                "http_errors": state.http_errors.load(Ordering::Relaxed),
                "io_errors": state.io_errors.load(Ordering::Relaxed),
                "tcp": tcp,
            }),
        );
    }
    let success = if probe.attempts > 0 {
        json!(
            ((probe.attempts - probe.failures - probe.http_errors) as f64 * 10000.0
                / probe.attempts as f64)
                .round()
                / 100.0
        )
    } else {
        Value::Null
    };
    report.insert(
        "latency".into(),
        json!({
            "probes_from_second": probe_delay,
            "attempts": probe.attempts,
            "failures": probe.failures,
            "http_errors": probe.http_errors,
            "success_percent": success,
            "connect_ms": percentiles(&probe.connect_ms),
            "ttfb_ms": if config.probe_path.is_some() { percentiles(&probe.ttfb_ms) } else { Value::Null },
            "phone_auth_ms": if opener.kind == PathKind::Phone { percentiles(&probe.auth_ms) } else { Value::Null },
            "phone_auth_failures": probe.auth_failures,
        }),
    );
    if let Some(udp) = udp_report.into_inner().ok().flatten() {
        report.insert("udp_latency".into(), udp);
    }
    report.insert(
        "laptop_cpu".into(),
        json!({
            "process_cpu_seconds": (cpu * 1000.0).round() / 1000.0,
            "process_cpu_percent": if elapsed > 0.0 { json!((cpu / elapsed * 1000.0).round() / 10.0) } else { Value::Null },
        }),
    );
    if let (Some(b), Some(a)) = (counters_before, counters_after) {
        report.insert("interface_deltas".into(), a.delta(&b));
    }
    Value::Object(report)
}

/// Run one path: idle probes, then download, then upload.
pub fn run_path(
    kind: PathKind,
    config: &SpeedConfig,
    secrets: Option<&Secrets>,
    iface_name: Option<&str>,
    stop: &AtomicBool,
) -> Value {
    let audit = Audit::default();
    let proxy = match (kind, secrets) {
        (PathKind::Phone, Some(secrets)) => Some(PhoneProxy {
            address: config.phone,
            username: "hotspotshade".into(),
            token: secrets.token().to_owned(),
            iface: Some(config.iface),
            timeout: config.connect_timeout,
        }),
        _ => None,
    };
    let opener = Opener {
        kind,
        config,
        proxy: proxy.as_ref(),
        audit: &audit,
    };
    let mut phases = Vec::new();
    let mut loads = vec![Load::Idle];
    if config.download_path.is_some() {
        loads.push(Load::Download);
    }
    if config.upload_path.is_some() {
        loads.push(Load::Upload);
    }
    for (index, load) in loads.into_iter().enumerate() {
        if stop.load(Ordering::Acquire) {
            break;
        }
        if load == Load::Idle && config.idle_seconds <= 0.0 {
            continue;
        }
        if index > 0 {
            // Let queues drain so that one phase does not load the next.
            std::thread::sleep(Duration::from_secs(2));
        }
        phases.push(run_phase(load, &opener, config, secrets, iface_name, stop));
    }
    drop(proxy);
    let (outer, bad) = audit.snapshot();
    json!({
        "path": kind.name(),
        "outer_sockets": outer,
        "ttl_bad": bad,
        "phases": phases,
    })
}

fn median(values: &mut [f64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    let m = if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    };
    json!((m * 100.0).round() / 100.0)
}

/// Median over repetitions of measured values only. A missing value stays out.
pub fn summarize(runs: &[Value], kinds: &[PathKind]) -> Value {
    let mut out = Map::new();
    for kind in kinds {
        let collect = |phase: &str, pointer: &str| -> Vec<f64> {
            runs.iter()
                .filter(|r| r["path"] == kind.name())
                .flat_map(|r| r["phases"].as_array().cloned().unwrap_or_default())
                .filter(|p| p["phase"] == phase)
                .filter_map(|p| p.pointer(pointer).and_then(Value::as_f64))
                .collect()
        };
        let mut down = collect("download", "/throughput/mbps_after_warmup");
        let mut up = collect("upload", "/throughput/mbps_after_warmup");
        let mut idle_connect = collect("idle", "/latency/connect_ms/p50");
        let mut down_connect = collect("download", "/latency/connect_ms/p50");
        let mut up_connect = collect("upload", "/latency/connect_ms/p50");
        let mut idle_ttfb = collect("idle", "/latency/ttfb_ms/p50");
        let mut down_ttfb = collect("download", "/latency/ttfb_ms/p50");
        let mut up_ttfb = collect("upload", "/latency/ttfb_ms/p50");
        let repetitions = runs.iter().filter(|r| r["path"] == kind.name()).count();
        out.insert(
            kind.name().into(),
            json!({
                "repetitions": repetitions,
                "download_mbps_median": median(&mut down),
                "upload_mbps_median": median(&mut up),
                "connect_p50_ms_median": {
                    "idle": median(&mut idle_connect),
                    "download": median(&mut down_connect),
                    "upload": median(&mut up_connect),
                },
                "ttfb_p50_ms_median": {
                    "idle": median(&mut idle_ttfb),
                    "download": median(&mut down_ttfb),
                    "upload": median(&mut up_ttfb),
                },
            }),
        );
    }
    Value::Object(out)
}

/// Run every repetition. Alternate the path order on each repetition (A B, B A).
pub fn run_all(
    kinds: &[PathKind],
    repeat: u32,
    config: &SpeedConfig,
    secrets: Option<&Secrets>,
    iface_name: Option<&str>,
    stop: &AtomicBool,
) -> Vec<Value> {
    let mut runs = Vec::new();
    for repetition in 0..repeat {
        let mut order = kinds.to_vec();
        if repetition % 2 == 1 {
            order.reverse();
        }
        for kind in order {
            if stop.load(Ordering::Acquire) {
                return runs;
            }
            if !runs.is_empty() {
                std::thread::sleep(Duration::from_secs(3));
            }
            let mut value = run_path(kind, config, secrets, iface_name, stop);
            if let Some(object) = value.as_object_mut() {
                object.insert("repetition".into(), json!(repetition + 1));
            }
            runs.push(value);
        }
    }
    runs
}

/// Command-line options. They contain no secret.
#[derive(Clone, Debug, PartialEq)]
pub struct SpeedOptions {
    pub phone: SocketAddr,
    pub iface: String,
    pub host: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub download_path: Option<String>,
    pub upload_path: Option<String>,
    pub probe_path: Option<String>,
    pub paths: Vec<PathKind>,
    pub streams: usize,
    pub seconds: f64,
    pub idle_seconds: f64,
    pub warmup: f64,
    pub probe_interval_ms: u64,
    pub repeat: u32,
    pub max_mb: u64,
    pub udp_target: Option<SocketAddr>,
    pub secrets_fd: Option<RawFd>,
    pub json: bool,
}
impl SpeedOptions {
    pub fn needs_phone(&self) -> bool {
        self.paths.contains(&PathKind::Phone)
    }
    /// The largest number of load bytes that the run can transfer.
    pub fn planned_max_bytes(&self) -> u64 {
        let phases =
            u64::from(self.download_path.is_some()) + u64::from(self.upload_path.is_some());
        self.max_mb * 1_000_000 * phases * self.paths.len() as u64 * u64::from(self.repeat)
    }
}

pub const VALUE_FLAGS: &[&str] = &[
    "--phone",
    "--iface",
    "--host",
    "--address",
    "--port",
    "--download-path",
    "--upload-path",
    "--probe-path",
    "--paths",
    "--streams",
    "--seconds",
    "--idle-seconds",
    "--warmup",
    "--probe-interval-ms",
    "--repeat",
    "--max-mb",
    "--udp-target",
    "--secrets-fd",
];
pub const SWITCHES: &[&str] = &["--json"];

fn option<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 1024 && path.bytes().all(|b| (0x21..0x7f).contains(&b))
}

fn number<T: std::str::FromStr>(args: &[String], flag: &str, default: &str) -> Option<T> {
    option(args, flag).unwrap_or(default).parse::<T>().ok()
}

fn finite(args: &[String], flag: &str, default: &str, low: f64, high: f64) -> Option<f64> {
    number::<f64>(args, flag, default).filter(|v| v.is_finite() && *v >= low && *v <= high)
}

/// Parse options after `validate_options` rejected unknown and repeated flags.
pub fn parse_options(args: &[String]) -> Result<SpeedOptions, String> {
    let phone =
        udp_diag::parse_phone(option(args, "--phone").ok_or("source device address is required")?)?;
    let iface = option(args, "--iface")
        .ok_or("--iface is required; name the wired or wireless hotspot interface")?
        .to_owned();
    udp_diag::check_iface(&iface)?;
    let host_text = option(args, "--host").ok_or("--host is required")?;
    if host_text.contains("://") {
        return Err(
            "host must be a name or an address, not a URL; the tool uses plain HTTP".into(),
        );
    }
    let host_ip = host_text
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    if host_ip.is_none() && !valid_host(host_text) {
        return Err("host must be a DNS name or a numeric address".into());
    }
    let address = match option(args, "--address") {
        Some(text) => Some(
            text.parse::<IpAddr>()
                .map_err(|_| "address must be a numeric IP address")?,
        ),
        None => host_ip,
    };
    if let (Some(a), Some(h)) = (address, host_ip) {
        if a != h {
            return Err("address differs from the numeric host".into());
        }
    }
    if let Some(ip) = address {
        if !udp_diag::public_unicast(ip) {
            return Err("address must be a public unicast address".into());
        }
    }
    let host = host_ip.map_or_else(|| host_text.to_ascii_lowercase(), |ip| ip.to_string());
    let port = number::<u16>(args, "--port", "80")
        .filter(|p| *p != 0)
        .ok_or("port must be 1 to 65535")?;
    if port == 443 {
        return Err("port 443 needs TLS; the tool uses plain HTTP".into());
    }
    let path = |flag: &str| -> Result<Option<String>, String> {
        match option(args, flag) {
            None => Ok(None),
            Some(p) if valid_path(p) => Ok(Some(p.to_owned())),
            Some(_) => Err(format!(
                "{flag} must start with / and contain printable ASCII"
            )),
        }
    };
    let download_path = path("--download-path")?;
    let upload_path = path("--upload-path")?;
    let probe_path = path("--probe-path")?;
    if download_path.is_none() && upload_path.is_none() {
        return Err("give --download-path, --upload-path, or both".into());
    }
    let paths = match option(args, "--paths").unwrap_or("phone") {
        "phone" => vec![PathKind::Phone],
        "direct" => vec![PathKind::Direct],
        "phone,direct" => vec![PathKind::Phone, PathKind::Direct],
        "direct,phone" => vec![PathKind::Direct, PathKind::Phone],
        _ => return Err("paths must be phone, direct, phone,direct, or direct,phone".into()),
    };
    if paths.contains(&PathKind::Direct) && address.is_none() {
        return Err(
            "the direct path needs a numeric --address; the target device does not resolve names"
                .into(),
        );
    }
    let streams = number::<usize>(args, "--streams", "4")
        .filter(|s| (1..=MAX_STREAMS).contains(s))
        .ok_or("streams must be 1 to 16")?;
    let seconds =
        finite(args, "--seconds", "20", 2.0, MAX_PHASE_SECONDS).ok_or("seconds must be 2 to 30")?;
    let idle_seconds = finite(args, "--idle-seconds", "10", 0.0, MAX_IDLE_SECONDS)
        .ok_or("idle seconds must be 0 to 30")?;
    let warmup = finite(args, "--warmup", "3", 0.0, MAX_PHASE_SECONDS)
        .filter(|w| *w + 1.0 <= seconds)
        .ok_or("warmup must be at least 0 and at least 1 second shorter than seconds")?;
    let probe_interval_ms = number::<u64>(args, "--probe-interval-ms", "1000")
        .filter(|v| (MIN_PROBE_INTERVAL_MS..=MAX_PROBE_INTERVAL_MS).contains(v))
        .ok_or("probe interval must be 200 to 5000 ms")?;
    let repeat = number::<u32>(args, "--repeat", "1")
        .filter(|v| (1..=MAX_REPEAT).contains(v))
        .ok_or("repeat must be 1 to 5")?;
    let max_mb = number::<u64>(args, "--max-mb", "200")
        .filter(|v| (1..=MAX_MB_PER_PHASE).contains(v))
        .ok_or("max-mb must be 1 to 2000 per phase")?;
    let udp_target = option(args, "--udp-target")
        .map(|t| {
            t.parse::<SocketAddr>()
                .map_err(|_| "udp target must be a numeric ADDRESS:PORT")
        })
        .transpose()?;
    if let Some(t) = udp_target {
        if t.port() == 0 || !udp_diag::public_unicast(t.ip()) {
            return Err("udp target must be a public unicast address and a nonzero port".into());
        }
    }
    if udp_target.is_some() && !paths.contains(&PathKind::Phone) {
        return Err("the UDP latency probe needs the source device path".into());
    }
    let secrets_fd = option(args, "--secrets-fd")
        .map(|v| {
            v.parse::<RawFd>()
                .ok()
                .filter(|fd| *fd >= 0)
                .ok_or("invalid secret descriptor")
        })
        .transpose()?;
    Ok(SpeedOptions {
        phone,
        iface,
        host,
        address,
        port,
        download_path,
        upload_path,
        probe_path,
        paths,
        streams,
        seconds,
        idle_seconds,
        warmup,
        probe_interval_ms,
        repeat,
        max_mb,
        udp_target,
        secrets_fd,
        json: args.iter().any(|a| a == "--json"),
    })
}

pub fn config_from(options: &SpeedOptions, iface: u32) -> SpeedConfig {
    SpeedConfig {
        phone: options.phone,
        iface,
        host: options.host.clone(),
        address: options.address,
        port: options.port,
        download_path: options.download_path.clone(),
        upload_path: options.upload_path.clone(),
        probe_path: options.probe_path.clone(),
        streams: options.streams,
        seconds: options.seconds,
        idle_seconds: options.idle_seconds,
        warmup: options.warmup,
        probe_interval: Duration::from_millis(options.probe_interval_ms),
        max_bytes: options.max_mb * 1_000_000,
        connect_timeout: Duration::from_secs(5),
        udp_target: options.udp_target,
    }
}

#[cfg(test)]
mod tests;
