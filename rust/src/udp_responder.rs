//! Bounded UDP responder for `phone-udp-diag --own-responder`.
//!
//! Run this program on a host that the user controls. It is a test
//! destination, not a relay. It does not forward traffic. It answers each
//! valid sequenced STUN binding request from `phone-udp-diag` with a reply of
//! the same size, so it does not amplify traffic. It locks to the first peer
//! IP address unless `--peer` names one. It stops after `--seconds`. It
//! limits replies to `--max-pps`. It stores no payload and logs no address.
//!
//! This socket is a listener on the destination host. It is not an outer
//! socket on the target device data path, so it does not use the normalized factory.
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const STUN_MAGIC: u32 = 0x2112_A442;
const PAD_ATTRIBUTE: u16 = 0xC0DE;
pub const MAX_SECONDS: f64 = 3600.0;
pub const MAX_PPS: u32 = 20_000;
/// The largest request that `phone-udp-diag` sends: 20 + 4 + 1200 bytes.
pub const MAX_REQUEST: usize = 1224;

/// Return a same-size binding success reply for a valid diagnostic request.
/// Accept only a binding request with the STUN magic and either no attribute
/// or one 0xC0DE padding attribute that fills the message.
pub fn reply_for(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 20 || request.len() > MAX_REQUEST {
        return None;
    }
    let kind = u16::from_be_bytes([request[0], request[1]]);
    let length = u16::from_be_bytes([request[2], request[3]]) as usize;
    let magic = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);
    if kind != 0x0001
        || magic != STUN_MAGIC
        || length + 20 != request.len()
        || !length.is_multiple_of(4)
    {
        return None;
    }
    if length > 0 {
        if length < 4 {
            return None;
        }
        let attribute = u16::from_be_bytes([request[20], request[21]]);
        let value = u16::from_be_bytes([request[22], request[23]]) as usize;
        if attribute != PAD_ATTRIBUTE || value + 4 != length {
            return None;
        }
    }
    let mut reply = vec![0u8; request.len()];
    reply[0] = 0x01;
    reply[1] = 0x01;
    reply[2..20].copy_from_slice(&request[2..20]);
    if length > 0 {
        reply[20..24].copy_from_slice(&request[20..24]);
    }
    Some(reply)
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResponderOptions {
    pub listen: SocketAddr,
    pub seconds: f64,
    pub max_pps: u32,
    pub peer: Option<IpAddr>,
    pub json: bool,
}

pub const VALUE_FLAGS: &[&str] = &["--listen", "--seconds", "--max-pps", "--peer"];
pub const SWITCHES: &[&str] = &["--json"];

fn option<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

pub fn parse_options(args: &[String]) -> Result<ResponderOptions, String> {
    let listen = option(args, "--listen")
        .ok_or("--listen ADDRESS:PORT is required")?
        .parse::<SocketAddr>()
        .map_err(|_| "listen must be a numeric ADDRESS:PORT")?;
    if listen.port() == 0 || listen.ip().is_multicast() {
        return Err("listen must be a unicast or unspecified address and a nonzero port".into());
    }
    let seconds = option(args, "--seconds")
        .unwrap_or("300")
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= MAX_SECONDS)
        .ok_or("seconds must be above 0 and at most 3600")?;
    let max_pps = option(args, "--max-pps")
        .unwrap_or("5000")
        .parse::<u32>()
        .ok()
        .filter(|v| (1..=MAX_PPS).contains(v))
        .ok_or("max-pps must be 1 to 20000")?;
    let peer = option(args, "--peer")
        .map(|v| {
            v.parse::<IpAddr>()
                .map_err(|_| "peer must be a numeric IP address")
        })
        .transpose()?;
    Ok(ResponderOptions {
        listen,
        seconds,
        max_pps,
        peer,
        json: args.iter().any(|a| a == "--json"),
    })
}

#[derive(Default, Debug)]
pub struct ResponderStats {
    pub received: u64,
    pub replied: u64,
    pub rejected_format: u64,
    pub rejected_peer: u64,
    pub rate_limited: u64,
    pub send_errors: u64,
    pub received_bytes: u64,
    pub replied_bytes: u64,
}
impl ResponderStats {
    pub fn to_json(&self, elapsed: Duration, peer_locked: bool) -> Value {
        let seconds = elapsed.as_secs_f64().max(1e-9);
        json!({
            "received": self.received,
            "replied": self.replied,
            "rejected_format": self.rejected_format,
            "rejected_peer": self.rejected_peer,
            "rate_limited": self.rate_limited,
            "send_errors": self.send_errors,
            "received_bytes": self.received_bytes,
            "replied_bytes": self.replied_bytes,
            "elapsed_seconds": (seconds * 100.0).round() / 100.0,
            "peer_locked": peer_locked,
        })
    }
}

/// Serve until `stop`, the time limit, or a socket error. Return aggregate counts.
pub fn serve(
    socket: &UdpSocket,
    options: &ResponderOptions,
    stop: &AtomicBool,
) -> io::Result<(ResponderStats, Duration, bool)> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let start = Instant::now();
    let limit = Duration::from_secs_f64(options.seconds);
    let mut stats = ResponderStats::default();
    let mut peer = options.peer;
    let mut tokens = f64::from(options.max_pps);
    let mut refilled = start;
    let mut buffer = [0u8; 2048];
    while !stop.load(Ordering::Acquire) && start.elapsed() < limit {
        let (n, from) = match socket.recv_from(&mut buffer) {
            Ok(value) => value,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        stats.received += 1;
        stats.received_bytes += n as u64;
        let Some(reply) = reply_for(&buffer[..n]) else {
            stats.rejected_format += 1;
            continue;
        };
        match peer {
            Some(ip) if ip != from.ip() => {
                stats.rejected_peer += 1;
                continue;
            }
            Some(_) => {}
            None => peer = Some(from.ip()),
        }
        let now = Instant::now();
        let max = f64::from(options.max_pps);
        tokens = (tokens + now.duration_since(refilled).as_secs_f64() * max).min(max);
        refilled = now;
        if tokens < 1.0 {
            stats.rate_limited += 1;
            continue;
        }
        tokens -= 1.0;
        match socket.send_to(&reply, from) {
            Ok(sent) => {
                stats.replied += 1;
                stats.replied_bytes += sent as u64;
            }
            Err(_) => stats.send_errors += 1,
        }
    }
    Ok((stats, start.elapsed(), peer.is_some()))
}

// These tests use the UDP diagnostic helpers. The diagnostic is unix only.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::udp_diag::{parse_stun_response, stun_request};
    use std::sync::Arc;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn reply_has_same_size_and_matches_request() {
        let id = [1, 2, 3, 4];
        for pad in [0usize, 1, 5, 1200] {
            let request = stun_request(77, &id, pad);
            let reply = reply_for(&request).unwrap();
            assert_eq!(reply.len(), request.len(), "no amplification");
            assert_eq!(parse_stun_response(&reply, &id), Some(77));
        }
    }

    #[test]
    fn reply_rejects_other_messages() {
        let id = [1, 2, 3, 4];
        let good = stun_request(1, &id, 8);
        let mut wrong_kind = good.clone();
        wrong_kind[1] = 0x11;
        let mut wrong_magic = good.clone();
        wrong_magic[4] ^= 1;
        let mut wrong_attribute = good.clone();
        wrong_attribute[21] = 0x06;
        let mut wrong_length = good.clone();
        wrong_length[3] += 4;
        let reply = reply_for(&good).unwrap();
        for bad in [
            &wrong_kind[..],
            &wrong_magic[..],
            &wrong_attribute[..],
            &wrong_length[..],
            &good[..19],
            &reply[..],
            &vec![0u8; MAX_REQUEST + 4][..],
        ] {
            assert!(reply_for(bad).is_none());
        }
    }

    #[test]
    fn options_are_bounded() {
        let ok = parse_options(&args(&["--listen", "0.0.0.0:3479"])).unwrap();
        assert_eq!(ok.max_pps, 5000);
        assert_eq!(ok.seconds, 300.0);
        for bad in [
            vec!["--listen", "host:1"],
            vec!["--listen", "0.0.0.0:0"],
            vec!["--listen", "0.0.0.0:1", "--seconds", "3601"],
            vec!["--listen", "0.0.0.0:1", "--max-pps", "20001"],
            vec!["--listen", "0.0.0.0:1", "--max-pps", "0"],
            vec!["--listen", "0.0.0.0:1", "--peer", "example.test"],
        ] {
            assert!(parse_options(&args(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn serve_locks_peer_limits_rate_and_stops() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let options = ResponderOptions {
            listen: address,
            seconds: 5.0,
            max_pps: 50,
            peer: None,
            json: true,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || serve(&server, &options, &flag).unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let id = [9, 9, 9, 9];
        for sequence in 0..200u64 {
            client
                .send_to(&stun_request(sequence, &id, 100), address)
                .unwrap();
        }
        client.send_to(b"not a request", address).unwrap();
        let mut replies = 0;
        let mut buffer = [0u8; 2048];
        while let Ok((n, _)) = client.recv_from(&mut buffer) {
            assert_eq!(n, 124);
            assert!(parse_stun_response(&buffer[..n], &id).is_some());
            replies += 1;
        }
        stop.store(true, Ordering::Release);
        let (stats, _, locked) = handle.join().unwrap();
        assert!(locked);
        assert_eq!(stats.received, 201);
        assert_eq!(stats.rejected_format, 1);
        assert_eq!(stats.replied, replies);
        assert!(
            (50..=60).contains(&replies),
            "rate limit holds near the bucket size: {replies}"
        );
        assert_eq!(stats.replied + stats.rate_limited, 200);
    }

    #[test]
    fn serve_rejects_other_peers() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let options = ResponderOptions {
            listen: address,
            seconds: 0.5,
            max_pps: 100,
            peer: Some("127.0.0.2".parse().unwrap()),
            json: true,
        };
        let stop = AtomicBool::new(false);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&stun_request(0, &[1; 4], 0), address)
            .unwrap();
        let (stats, _, _) = serve(&server, &options, &stop).unwrap();
        assert_eq!(stats.rejected_peer, 1);
        assert_eq!(stats.replied, 0);
    }
}
