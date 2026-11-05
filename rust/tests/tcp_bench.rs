//! Hermetic throughput benchmark for the inner TCP endpoint.
//!
//! The benchmark calls the public engine API only. It opens no socket, creates
//! no route, and needs no privilege. It drives one large download and one large
//! upload with partial outer writes and an inner receive window of 65535 bytes.
//!
//! Run it with:
//!
//! ```text
//! cargo test --release --locked --manifest-path rust/Cargo.toml \
//!     --test tcp_bench -- --ignored --nocapture
//! ```
//!
//! One verified pass checks the byte stream against a reference digest. The
//! timed passes keep the digest out of the measurement.
use hotspotshade::packet::{self, TcpSegment};
use hotspotshade::tcp::{Action, TcpFlow, MSS_INNER, RCV_WINDOW};
use std::time::{Duration, Instant};

const REPS: usize = 3;
const DOWNLOAD_TOTAL: usize = 256 * 1024 * 1024;
const UPLOAD_TOTAL: usize = 64 * 1024 * 1024;
/// The relay reads the outer socket into a 64 KiB buffer.
const OUTER_READ: usize = 64 * 1024;
/// A realistic outer write accepts less than the inner sender offered.
const OUTER_WRITE: usize = 16 * 1024;

/// An order-sensitive digest of the delivered byte stream. It works on one
/// byte at a time, so it does not depend on how the stream is split.
struct Digest(u64);
impl Digest {
    fn new() -> Self {
        Digest(0xcbf2_9ce4_8422_2325)
    }
    fn feed(&mut self, data: &[u8]) {
        for byte in data {
            self.0 = (self.0 ^ *byte as u64).wrapping_mul(0x100_0000_01b3);
        }
    }
}

fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    let mut state = seed | 1;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn inner_ack(ack: u32, window: u16) -> TcpSegment<'static> {
    TcpSegment {
        sport: 40000,
        dport: 443,
        seq: 1001,
        ack,
        flags: packet::ACK,
        window,
        options: &[],
        data: &[],
    }
}

fn digest_of(chunk: &[u8], bytes: usize) -> u64 {
    let mut digest = Digest::new();
    let mut fed = 0;
    while fed < bytes {
        let n = chunk.len().min(bytes - fed);
        digest.feed(&chunk[..n]);
        fed += n;
    }
    digest.0
}

/// Download: the outer socket delivers data, the inner client acknowledges it.
/// The engine must turn the outer stream into MSS-sized inner segments and keep
/// inflight data bounded by the inner receive window.
fn download(bytes: usize, ack_every: usize, verify: bool) -> (Duration, u64) {
    let now = Instant::now();
    let source = payload(bytes, 0x1234_5678);
    let mut flow = TcpFlow::new(1000, 2000, &[2, 4, 5, 180], RCV_WINDOW, now);
    flow.outer_connected();
    flow.actions();
    let mut digest = Digest::new();
    let mut delivered = 0usize;
    let mut acked = 0usize;
    let mut unacked = 0usize;
    let mut segments = 0usize;
    let mut total_segments = 0usize;
    let mut ack_events = 0usize;
    let start = Instant::now();
    while delivered < bytes {
        let end = delivered + OUTER_READ.min(bytes - delivered);
        let chunk = &source[delivered..end];
        flow.outer_data(chunk, now);
        delivered += chunk.len();
        loop {
            let mut emitted = false;
            for action in flow.actions() {
                if let Action::Send { data, .. } = action {
                    if data.is_empty() {
                        continue;
                    }
                    if verify {
                        digest.feed(&data);
                    }
                    unacked += data.len();
                    emitted = true;
                    segments += 1;
                    total_segments += 1;
                    if segments >= ack_every {
                        segments = 0;
                        acked += unacked;
                        unacked = 0;
                        ack_events += 1;
                        flow.on_inner(
                            &inner_ack(2001u32.wrapping_add(acked as u32), RCV_WINDOW),
                            now,
                        );
                    }
                }
            }
            if !emitted && unacked != 0 {
                segments = 0;
                acked += unacked;
                unacked = 0;
                ack_events += 1;
                flow.on_inner(
                    &inner_ack(2001u32.wrapping_add(acked as u32), RCV_WINDOW),
                    now,
                );
            } else if !emitted {
                break;
            }
        }
    }
    assert_eq!(acked + unacked, delivered, "download lost bytes");
    assert_eq!(flow.inflight(), 0, "download left data inflight");
    if verify {
        if ack_every == 1 {
            assert_eq!(ack_events, total_segments);
        } else {
            assert!(ack_events < total_segments);
        }
        println!("  {total_segments} segments, {ack_events} ACK events");
        assert_eq!(
            digest.0,
            digest_of(&source, bytes),
            "download changed the byte stream"
        );
    }
    (start.elapsed(), digest.0)
}

/// Upload: the inner client sends MSS-sized segments, the outer socket accepts
/// part of the queued data. The engine must preserve byte order and keep the
/// pending buffer bounded by the advertised receive window.
fn upload(bytes: usize, outer_write: usize, verify: bool) -> (Duration, u64) {
    let now = Instant::now();
    let source = payload(bytes, 0xdead_beef);
    let mut flow = TcpFlow::new(500, 900, &[2, 4, 5, 180], RCV_WINDOW, now);
    flow.outer_connected();
    flow.actions();
    let mut digest = Digest::new();
    let mut sent = 0usize;
    let mut written = 0usize;
    let mut window = RCV_WINDOW as usize;
    let mut sequence = 501u32;
    let start = Instant::now();
    while written < bytes {
        if sent < bytes && window > 0 {
            let n = MSS_INNER.min(bytes - sent).min(window);
            flow.on_inner(
                &TcpSegment {
                    sport: 40000,
                    dport: 443,
                    seq: sequence,
                    ack: 901,
                    flags: packet::ACK,
                    window: RCV_WINDOW,
                    options: &[],
                    data: &source[sent..sent + n],
                },
                now,
            );
            sequence = sequence.wrapping_add(n as u32);
            sent += n;
        } else {
            let pending = flow.pending_bytes();
            assert!(!pending.is_empty(), "no pending bytes and no credit");
            let n = pending.len().min(outer_write).min(bytes - written);
            if verify {
                digest.feed(&pending[..n]);
            }
            flow.outer_written(n);
            written += n;
        }
        for action in flow.actions() {
            if let Action::Send { window: next, .. } = action {
                window = next as usize;
            }
        }
        assert!(flow.pending_bytes().len() <= hotspotshade::tcp::MAX_PENDING_CLIENT);
    }
    assert_eq!(sent, bytes);
    if verify {
        assert_eq!(
            digest.0,
            digest_of(&source, bytes),
            "upload changed the byte stream"
        );
    }
    (start.elapsed(), digest.0)
}

fn report(name: &str, bytes: usize, mut run: impl FnMut(bool) -> (Duration, u64)) -> Duration {
    // One verified pass proves the stream. The timed passes leave the digest
    // out, so the numbers describe the engine only.
    run(true);
    let mut best = Duration::MAX;
    for rep in 0..REPS {
        let (elapsed, _) = run(false);
        println!(
            "{name:<34} rep {}: {:7.2} ms  {:6.3} ns/byte  {:8.1} MiB/s",
            rep + 1,
            elapsed.as_secs_f64() * 1e3,
            elapsed.as_secs_f64() * 1e9 / bytes as f64,
            bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0)
        );
        best = best.min(elapsed);
    }
    println!(
        "{name:<34} best: {:7.2} ms  {:6.3} ns/byte  {:8.1} MiB/s",
        best.as_secs_f64() * 1e3,
        best.as_secs_f64() * 1e9 / bytes as f64,
        bytes as f64 / best.as_secs_f64() / (1024.0 * 1024.0)
    );
    best
}

#[test]
#[ignore = "performance measurement, run in release mode"]
fn tcp_endpoint_throughput() {
    println!("inner TCP endpoint throughput");
    println!(
        "download {} MiB, outer read {} KiB, inner window {} bytes",
        DOWNLOAD_TOTAL / (1024 * 1024),
        OUTER_READ / 1024,
        RCV_WINDOW
    );
    report("download, ack every segment", DOWNLOAD_TOTAL, |verify| {
        download(DOWNLOAD_TOTAL, 1, verify)
    });
    report("download, ack every 2 segments", DOWNLOAD_TOTAL, |verify| {
        download(DOWNLOAD_TOTAL, 2, verify)
    });
    println!(
        "upload {} MiB, outer write {} KiB",
        UPLOAD_TOTAL / (1024 * 1024),
        OUTER_WRITE / 1024
    );
    report("upload, 16 KiB outer writes", UPLOAD_TOTAL, |verify| {
        upload(UPLOAD_TOTAL, OUTER_WRITE, verify)
    });
    report("upload, 64 KiB outer writes", UPLOAD_TOTAL, |verify| {
        upload(UPLOAD_TOTAL, OUTER_READ, verify)
    });
}
