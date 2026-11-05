//! A DNS resolver that sends queries through normalized sockets.
use crate::normalization::{self, Audit};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
const QTYPE_CNAME: u16 = 5;
/// Keep the cache bounded. Clear it when it reaches this many entries.
const CACHE_MAX_ENTRIES: usize = 512;
/// Shorten a long server TTL to this many seconds.
const CACHE_MAX_TTL: u32 = 3600;
/// Follow at most this many CNAME links from the queried name.
const MAX_CNAME_HOPS: usize = 8;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
fn word(data: &[u8], offset: usize) -> io::Result<u16> {
    if offset + 2 > data.len() {
        return Err(bad("truncated DNS message"));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}
fn dword(data: &[u8], offset: usize) -> io::Result<u32> {
    if offset + 4 > data.len() {
        return Err(bad("truncated DNS message"));
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Require a numeric IP literal, with an optional port.
pub fn parse_server(text: &str) -> io::Result<SocketAddr> {
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        if addr.port() == 0 {
            return Err(invalid("DNS port must be nonzero"));
        }
        return Ok(addr);
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(invalid("DNS server must be a numeric IP address"))
}

fn query(name: &str, typ: u16, id: u16) -> io::Result<Vec<u8>> {
    if typ != QTYPE_A && typ != QTYPE_AAAA {
        return Err(invalid("unsupported DNS query type"));
    }
    let mut out = vec![0; 12];
    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2] = 1;
    out[5] = 1;
    let name = name.trim_end_matches('.');
    if name.is_empty() || !name.is_ascii() || name.len() > 253 {
        return Err(invalid("DNS name must be ASCII"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid("invalid DNS label"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

// Read labels and compression pointers. Bound every jump and reject loops.
fn read_name(data: &[u8], start: usize) -> io::Result<(String, usize)> {
    let mut pos = start;
    let mut end = None;
    let mut labels = Vec::new();
    let mut jumps = 0usize;
    let mut expanded = 0usize;
    loop {
        if pos >= data.len() {
            return Err(bad("truncated DNS name"));
        }
        let n = data[pos];
        if n & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return Err(bad("truncated DNS pointer"));
            }
            let to = (((n & 0x3f) as usize) << 8) | data[pos + 1] as usize;
            if to >= data.len() || jumps >= 32 {
                return Err(bad("invalid DNS pointer"));
            }
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = to;
            jumps += 1;
            continue;
        }
        if n & 0xc0 != 0 {
            return Err(bad("invalid DNS label"));
        }
        pos += 1;
        if n == 0 {
            return Ok((labels.join("."), end.unwrap_or(pos)));
        }
        let len = n as usize;
        if len > 63 || pos + len > data.len() {
            return Err(bad("truncated DNS label"));
        }
        expanded += len + 1;
        if expanded > 255 {
            return Err(bad("DNS name too long"));
        }
        let label =
            std::str::from_utf8(&data[pos..pos + len]).map_err(|_| bad("invalid DNS label"))?;
        if !label.is_ascii() || label.contains('.') {
            return Err(bad("invalid DNS label"));
        }
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }
}

// Return the accepted addresses and the smallest TTL that belongs to them.
// Accept an address only when its owner is the queried name or a name on the
// CNAME chain that starts at the queried name and has no CNAME itself. The caller caches one address,
// so the smallest TTL that covers the chain and the address records is the safe
// lifetime.
fn answers(data: &[u8], name: &str, typ: u16, id: u16) -> io::Result<(Vec<IpAddr>, u32)> {
    if data.len() < 12 || word(data, 0)? != id {
        return Err(bad("unexpected DNS transaction"));
    }
    let flags = word(data, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7a4f != 0 || word(data, 4)? != 1 {
        return Err(bad("invalid DNS response"));
    }
    let count = word(data, 6)? as usize;
    if count > 64 {
        return Err(bad("too many DNS answers"));
    }
    let (question, mut offset) = read_name(data, 12)?;
    if !question.eq_ignore_ascii_case(name.trim_end_matches('.'))
        || word(data, offset)? != typ
        || word(data, offset + 2)? != 1
    {
        return Err(bad("DNS question mismatch"));
    }
    offset += 4;
    // A CNAME chain can be longer than the CNAME count, so bound the walk.
    let mut cnames: HashMap<String, (String, u32)> = HashMap::new();
    let mut addresses: Vec<(String, IpAddr, u32)> = Vec::new();
    for _ in 0..count {
        let (owner, next) = read_name(data, offset)?;
        offset = next;
        let rtype = word(data, offset)?;
        let class = word(data, offset + 2)?;
        let record_ttl = dword(data, offset + 4)?;
        let len = word(data, offset + 8)? as usize;
        offset += 10;
        if offset + len > data.len() {
            return Err(bad("truncated DNS answer"));
        }
        // RFC 2181: a TTL with the top bit set is not a valid lifetime.
        let record_ttl = if record_ttl & 0x8000_0000 != 0 {
            0
        } else {
            record_ttl
        };
        if class == 1 && rtype == QTYPE_CNAME {
            let (target, after) = read_name(data, offset)?;
            if target.is_empty() || after != offset + len {
                return Err(bad("invalid DNS CNAME"));
            }
            match cnames.entry(owner) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((target, record_ttl));
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if entry.get().0 != target {
                        return Err(bad("conflicting DNS CNAMEs"));
                    }
                    entry.get_mut().1 = entry.get().1.min(record_ttl);
                }
            }
        } else if class == 1 && rtype == typ {
            let addr = if typ == QTYPE_A && len == 4 {
                Some(IpAddr::from([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]))
            } else if typ == QTYPE_AAAA && len == 16 {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[offset..offset + 16]);
                Some(IpAddr::from(bytes))
            } else {
                None
            };
            if let Some(addr) = addr {
                addresses.push((owner, addr, record_ttl));
            }
        }
        offset += len;
    }
    // Walk the chain from the verified question name. Reject a loop or a chain
    // that is too long. Both cases cannot name a real owner.
    let mut chain = vec![question];
    let mut chain_ttl: Option<u32> = None;
    while let Some((target, ttl)) = cnames.get(chain.last().unwrap()) {
        if chain.contains(target) {
            return Err(bad("DNS CNAME loop"));
        }
        if chain.len() > MAX_CNAME_HOPS {
            return Err(bad("DNS CNAME chain too long"));
        }
        chain_ttl = Some(chain_ttl.map_or(*ttl, |old| old.min(*ttl)));
        chain.push(target.clone());
    }
    let mut result = Vec::new();
    let mut ttl = chain_ttl;
    for (owner, addr, record_ttl) in addresses {
        if chain.contains(&owner) && !cnames.contains_key(&owner) {
            result.push(addr);
            ttl = Some(ttl.map_or(record_ttl, |old| old.min(record_ttl)));
        }
    }
    Ok((result, ttl.unwrap_or(0)))
}

type Clock = dyn Fn() -> Instant + Send + Sync;

/// A small DNS client for the tunnel.
///
/// The cache holds one address for each name and query type. It honors the
/// smallest TTL in the answer. An answer with TTL 0 is not cached. The cache
/// holds at most 512 entries and shortens a TTL above 3600 seconds.
pub struct TinyResolver {
    servers: Vec<SocketAddr>,
    iface: Option<u32>,
    timeout: Duration,
    cache: Mutex<HashMap<(String, u16), (IpAddr, Instant)>>,
    clock: Box<Clock>,
}
impl TinyResolver {
    pub fn new(
        servers: Vec<SocketAddr>,
        iface: Option<u32>,
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::with_clock(servers, iface, timeout, Box::new(Instant::now))
    }
    fn with_clock(
        servers: Vec<SocketAddr>,
        iface: Option<u32>,
        timeout: Duration,
        clock: Box<Clock>,
    ) -> io::Result<Self> {
        if servers.is_empty() || servers.iter().any(|s| s.port() == 0) || timeout.is_zero() {
            return Err(invalid("DNS server and timeout are required"));
        }
        Ok(Self {
            servers,
            iface,
            timeout,
            cache: Mutex::new(HashMap::new()),
            clock,
        })
    }
    fn now(&self) -> Instant {
        (self.clock)()
    }
    pub fn resolve(&self, name: &str, typ: u16, audit: &Audit) -> io::Result<IpAddr> {
        self.resolve_cancellable(name, typ, audit, None)
    }
    /// Resolve a name and check for cancellation while waiting for DNS replies.
    pub fn resolve_cancellable(
        &self,
        name: &str,
        typ: u16,
        audit: &Audit,
        stopped: Option<&AtomicBool>,
    ) -> io::Result<IpAddr> {
        if stopped.is_some_and(|s| s.load(Ordering::Acquire)) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "DNS lookup cancelled",
            ));
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let key = (name.clone(), typ);
        {
            let mut cache = self.cache.lock().unwrap();
            let now = self.now();
            if let Some((addr, expires)) = cache.get(&key) {
                if *expires > now {
                    return Ok(*addr);
                }
            }
            cache.retain(|_, (_, expires)| *expires > now);
        }
        let mut id_bytes = [0u8; 2];
        File::open("/dev/urandom")?.read_exact(&mut id_bytes)?;
        let id = u16::from_ne_bytes(id_bytes);
        let message = query(&name, typ, id)?;
        let servers = &self.servers[..self.servers.len().min(3)];
        let per_server = (self.timeout / servers.len() as u32).max(Duration::from_millis(500));
        let mut buf = [0u8; 65535];
        for server in servers {
            if stopped.is_some_and(|s| s.load(Ordering::Acquire)) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "DNS lookup cancelled",
                ));
            }
            let sock = normalization::udp_socket(server.ip(), self.iface, audit)?;
            if sock.connect(server).is_err() || sock.send(&message).is_err() {
                continue;
            }
            let deadline = Instant::now() + per_server;
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                if stopped.is_some_and(|s| s.load(Ordering::Acquire)) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "DNS lookup cancelled",
                    ));
                }
                let interval = if stopped.is_some() {
                    left.min(Duration::from_millis(200))
                } else {
                    left
                };
                sock.set_read_timeout(Some(interval.max(Duration::from_millis(1))))?;
                match sock.recv(&mut buf) {
                    Ok(n) => {
                        if let Ok((addrs, ttl)) = answers(&buf[..n], &name, typ, id) {
                            if let Some(addr) = addrs.first().copied() {
                                let ttl = ttl.min(CACHE_MAX_TTL);
                                if ttl > 0 {
                                    let expires = self.now() + Duration::from_secs(u64::from(ttl));
                                    let mut cache = self.cache.lock().unwrap();
                                    let now = self.now();
                                    if cache.len() >= CACHE_MAX_ENTRIES {
                                        cache.retain(|_, (_, expires)| *expires > now);
                                        if cache.len() >= CACHE_MAX_ENTRIES {
                                            cache.clear();
                                        }
                                    }
                                    cache.insert(key.clone(), (addr, expires));
                                }
                                return Ok(addr);
                            }
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue
                    }
                    Err(_) => break,
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "DNS lookup failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::net::UdpSocket;
    #[cfg(unix)]
    use std::thread;
    #[test]
    fn literal_only() {
        assert!(parse_server("example.com:53").is_err());
        assert_eq!(parse_server("1.1.1.1").unwrap().port(), 53);
        assert_eq!(parse_server("[::1]:5353").unwrap().port(), 5353);
    }
    // Build a response for a query with one A or AAAA record.
    fn reply(query: &[u8], addr: IpAddr, ttl: u32) -> Vec<u8> {
        let mut out = query.to_vec();
        out[2] = 0x81;
        out[3] = 0x80;
        out[7] = 1;
        out.extend_from_slice(&[0xc0, 0x0c]);
        let (rtype, rdata) = match addr {
            IpAddr::V4(v) => (QTYPE_A, v.octets().to_vec()),
            IpAddr::V6(v) => (QTYPE_AAAA, v.octets().to_vec()),
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
        out
    }
    #[test]
    fn reads_the_smallest_answer_ttl() {
        let request = query("example.test", QTYPE_A, 0x1234).unwrap();
        let mut message = reply(&request, "1.2.3.4".parse().unwrap(), 300);
        message[7] = 2;
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        message.extend_from_slice(&120u32.to_be_bytes());
        message.extend_from_slice(&[0, 4, 5, 6, 7, 8]);
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x1234).unwrap();
        assert_eq!(
            addrs,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(ttl, 120);
    }
    #[test]
    fn treats_a_top_bit_ttl_as_zero() {
        let request = query("example.test", QTYPE_A, 0x1234).unwrap();
        let message = reply(&request, "1.2.3.4".parse().unwrap(), 0x8000_002a);
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x1234).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(ttl, 0);
    }
    // Encode a name without compression for a record owner or a CNAME target.
    fn encoded_name(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in text.trim_end_matches('.').split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }
    fn record(owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }
    fn answer_message(request: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = request.to_vec();
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            out.extend_from_slice(record);
        }
        out
    }
    #[test]
    fn rejects_conflicting_and_malformed_alias_records() {
        let request = query("example.test", QTYPE_A, 0x2222).unwrap();
        let alias = record(
            &[0xc0, 0x0c],
            QTYPE_CNAME,
            300,
            &encoded_name("target.test"),
        );
        let duplicate = record(&[0xc0, 0x0c], QTYPE_CNAME, 10, &encoded_name("target.test"));
        let address = record(&encoded_name("target.test"), QTYPE_A, 60, &[1, 2, 3, 4]);
        let wrong = record(&[0xc0, 0x0c], QTYPE_A, 60, &[9, 9, 9, 9]);
        let message = answer_message(&request, &[wrong, alias.clone(), duplicate, address]);
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x2222).unwrap();
        assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 10);
        let conflict = record(&[0xc0, 0x0c], QTYPE_CNAME, 10, &encoded_name("other.test"));
        assert!(answers(
            &answer_message(&request, &[alias, conflict]),
            "example.test",
            QTYPE_A,
            0x2222
        )
        .is_err());
        let mut trailing = encoded_name("target.test");
        trailing.push(0);
        let message = answer_message(
            &request,
            &[record(&[0xc0, 0x0c], QTYPE_CNAME, 60, &trailing)],
        );
        assert!(answers(&message, "example.test", QTYPE_A, 0x2222).is_err());
        assert!(read_name(&[3, b'a', b'.', b'b', 0], 0).is_err());
        let mut bad_opcode = answer_message(&request, &[]);
        bad_opcode[2] |= 0x08;
        assert!(answers(&bad_opcode, "example.test", QTYPE_A, 0x2222).is_err());
    }
    #[test]
    fn rejects_an_unrelated_owner() {
        let request = query("example.test", QTYPE_A, 0x2222).unwrap();
        // The address belongs to a name that the question does not reach.
        let message = answer_message(
            &request,
            &[record(
                &encoded_name("other.test"),
                QTYPE_A,
                3600,
                &[5, 6, 7, 8],
            )],
        );
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x2222).unwrap();
        assert!(addrs.is_empty());
        assert_eq!(ttl, 0);
        // A chain that starts at another name does not make its target reachable.
        let message = answer_message(
            &request,
            &[
                record(
                    &encoded_name("other.test"),
                    QTYPE_CNAME,
                    3600,
                    &encoded_name("target.test"),
                ),
                record(&encoded_name("target.test"), QTYPE_A, 3600, &[9, 9, 9, 9]),
            ],
        );
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x2222).unwrap();
        assert!(addrs.is_empty());
        assert_eq!(ttl, 0);
    }
    #[test]
    fn uses_the_minimum_cname_ttl() {
        let request = query("example.test", QTYPE_A, 0x3333).unwrap();
        let message = answer_message(
            &request,
            &[
                record(&[0xc0, 0x0c], QTYPE_CNAME, 60, &encoded_name("target.test")),
                record(&encoded_name("target.test"), QTYPE_A, 300, &[1, 2, 3, 4]),
            ],
        );
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x3333).unwrap();
        assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 60);
    }
    #[test]
    fn follows_a_valid_cname_chain() {
        let request = query("Example.Test", QTYPE_A, 0x4444).unwrap();
        let message = answer_message(
            &request,
            &[
                record(&[0xc0, 0x0c], QTYPE_CNAME, 120, &encoded_name("first.test")),
                record(
                    &encoded_name("FIRST.TEST"),
                    QTYPE_CNAME,
                    30,
                    &encoded_name("second.test"),
                ),
                record(&encoded_name("second.test"), QTYPE_A, 300, &[9, 9, 9, 9]),
                record(&encoded_name("unrelated.test"), QTYPE_A, 1, &[7, 7, 7, 7]),
            ],
        );
        let (addrs, ttl) = answers(&message, "example.test", QTYPE_A, 0x4444).unwrap();
        assert_eq!(addrs, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 30);
    }
    #[test]
    fn rejects_a_cname_loop() {
        let request = query("example.test", QTYPE_A, 0x5555).unwrap();
        let message = answer_message(
            &request,
            &[
                record(&[0xc0, 0x0c], QTYPE_CNAME, 60, &encoded_name("first.test")),
                record(
                    &encoded_name("first.test"),
                    QTYPE_CNAME,
                    60,
                    &encoded_name("example.test"),
                ),
                record(&encoded_name("example.test"), QTYPE_A, 60, &[1, 2, 3, 4]),
            ],
        );
        assert!(answers(&message, "example.test", QTYPE_A, 0x5555).is_err());
    }
    #[test]
    fn rejects_a_cname_chain_that_is_too_long() {
        let request = query("example.test", QTYPE_A, 0x6666).unwrap();
        let mut records = vec![record(
            &[0xc0, 0x0c],
            QTYPE_CNAME,
            60,
            &encoded_name("hop0.test"),
        )];
        for hop in 0..=MAX_CNAME_HOPS {
            records.push(record(
                &encoded_name(&format!("hop{hop}.test")),
                QTYPE_CNAME,
                60,
                &encoded_name(&format!("hop{}.test", hop + 1)),
            ));
        }
        let message = answer_message(&request, &records);
        assert!(answers(&message, "example.test", QTYPE_A, 0x6666).is_err());
    }
    #[test]
    fn rejects_malformed_cname_records() {
        let request = query("example.test", QTYPE_A, 0x7777).unwrap();
        // The name in the record data runs past the record length.
        let message = answer_message(
            &request,
            &[record(
                &[0xc0, 0x0c],
                QTYPE_CNAME,
                60,
                &encoded_name("target.test"),
            )],
        );
        let mut short = message.clone();
        let pos = short.len() - 15;
        short[pos..pos + 2].copy_from_slice(&4u16.to_be_bytes());
        assert!(answers(&short, "example.test", QTYPE_A, 0x7777).is_err());
        // The CNAME target is empty.
        let message = answer_message(&request, &[record(&[0xc0, 0x0c], QTYPE_CNAME, 60, &[0])]);
        assert!(answers(&message, "example.test", QTYPE_A, 0x7777).is_err());
        // The CNAME record data is cut off.
        let message = answer_message(
            &request,
            &[record(
                &[0xc0, 0x0c],
                QTYPE_CNAME,
                60,
                &encoded_name("target.test"),
            )],
        );
        assert!(answers(
            &message[..message.len() - 4],
            "example.test",
            QTYPE_A,
            0x7777
        )
        .is_err());
    }
    #[test]
    fn rejects_malformed_answers() {
        let request = query("example.test", QTYPE_A, 0x1234).unwrap();
        let message = reply(&request, "1.2.3.4".parse().unwrap(), 60);
        // The answer length runs past the packet.
        assert!(answers(
            &message[..message.len() - 2],
            "example.test",
            QTYPE_A,
            0x1234
        )
        .is_err());
        // The answer length field is missing.
        assert!(answers(
            &message[..message.len() - 6],
            "example.test",
            QTYPE_A,
            0x1234
        )
        .is_err());
        // The TTL field is missing.
        assert!(answers(
            &message[..message.len() - 10],
            "example.test",
            QTYPE_A,
            0x1234
        )
        .is_err());
        // The transaction id does not match.
        assert!(answers(&message, "example.test", QTYPE_A, 0x1235).is_err());
    }
    #[cfg(unix)]
    #[derive(Clone)]
    struct ManualClock {
        base: Instant,
        offset_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }
    #[cfg(unix)]
    impl ManualClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            }
        }
        fn advance(&self, by: Duration) {
            self.offset_ms
                .fetch_add(by.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        fn now(&self) -> Instant {
            self.base
                + Duration::from_millis(self.offset_ms.load(std::sync::atomic::Ordering::Relaxed))
        }
    }
    #[cfg(unix)]
    fn clocked_resolver(addr: SocketAddr, clock: ManualClock) -> TinyResolver {
        TinyResolver::with_clock(
            vec![addr],
            None,
            Duration::from_secs(2),
            Box::new(move || clock.now()),
        )
        .unwrap()
    }
    #[cfg(unix)]
    #[test]
    fn caches_until_the_server_ttl_expires() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let first = reply(&b[..n], "1.2.3.4".parse().unwrap(), 30);
            server.send_to(&first, src).unwrap();
            let (n, src) = server.recv_from(&mut b).unwrap();
            let second = reply(&b[..n], "5.6.7.8".parse().unwrap(), 30);
            server.send_to(&second, src).unwrap();
        });
        let clock = ManualClock::new();
        let resolver = clocked_resolver(addr, clock.clone());
        let audit = Audit::default();
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        clock.advance(Duration::from_secs(29));
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (2, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn does_not_cache_zero_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let first = reply(&b[..n], "1.2.3.4".parse().unwrap(), 0);
            server.send_to(&first, src).unwrap();
            let (n, src) = server.recv_from(&mut b).unwrap();
            let second = reply(&b[..n], "5.6.7.8".parse().unwrap(), 0);
            server.send_to(&second, src).unwrap();
        });
        let resolver = clocked_resolver(addr, ManualClock::new());
        let audit = Audit::default();
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (2, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn shortens_a_long_server_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let first = reply(&b[..n], "1.2.3.4".parse().unwrap(), 86_400);
            server.send_to(&first, src).unwrap();
            let (n, src) = server.recv_from(&mut b).unwrap();
            let second = reply(&b[..n], "5.6.7.8".parse().unwrap(), 86_400);
            server.send_to(&second, src).unwrap();
        });
        let clock = ManualClock::new();
        let resolver = clocked_resolver(addr, clock.clone());
        let audit = Audit::default();
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        clock.advance(Duration::from_secs(u64::from(CACHE_MAX_TTL) - 1));
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (2, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn expires_at_the_cname_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let first = answer_message(
                &b[..n],
                &[
                    record(&[0xc0, 0x0c], QTYPE_CNAME, 10, &encoded_name("target.test")),
                    record(&encoded_name("target.test"), QTYPE_A, 300, &[1, 2, 3, 4]),
                ],
            );
            server.send_to(&first, src).unwrap();
            let (n, src) = server.recv_from(&mut b).unwrap();
            let second = answer_message(
                &b[..n],
                &[
                    record(&[0xc0, 0x0c], QTYPE_CNAME, 10, &encoded_name("target.test")),
                    record(&encoded_name("target.test"), QTYPE_A, 300, &[5, 6, 7, 8]),
                ],
            );
            server.send_to(&second, src).unwrap();
        });
        let clock = ManualClock::new();
        let resolver = clocked_resolver(addr, clock.clone());
        let audit = Audit::default();
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        clock.advance(Duration::from_secs(9));
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        // The chain TTL is 10 seconds. The entry expires at exactly 10 seconds.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (2, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn validates_dns_question_and_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let mut response = b[..n].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
            let mut forged = response.clone();
            forged[0] ^= 1;
            server.send_to(&forged, src).unwrap();
            server.send_to(&response, src).unwrap();
        });
        let audit = Audit::default();
        let resolver = TinyResolver::new(vec![addr], None, Duration::from_secs(2)).unwrap();
        assert_eq!(
            resolver.resolve("example.com", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolver.resolve("example.com", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn resolves_aaaa_over_normalized_ipv4_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            assert_eq!(&b[n - 4..n], &[0, 28, 0, 1]);
            let mut response = b[..n].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16]);
            response.extend_from_slice(
                &"2001:db8::1234"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            server.send_to(&response, src).unwrap();
        });
        let audit = Audit::default();
        let resolver = TinyResolver::new(vec![addr], None, Duration::from_secs(2)).unwrap();
        assert_eq!(
            resolver
                .resolve("example.test", QTYPE_AAAA, &audit)
                .unwrap(),
            "2001:db8::1234".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn cancellation_interrupts_silent_server() {
        use std::sync::Arc;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resolver = TinyResolver::new(
            vec![server.local_addr().unwrap()],
            None,
            Duration::from_secs(10),
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut data = [0; 512];
            let _ = server.recv_from(&mut data).unwrap();
            signal.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let e = resolver
            .resolve_cancellable("example.test", QTYPE_A, &Audit::default(), Some(&stop))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }
}
