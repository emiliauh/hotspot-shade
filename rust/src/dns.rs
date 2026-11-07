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
/// The most explicit upstream servers that one configuration may name.
///
/// The bound keeps a hand-written or generated list from turning a lookup into
/// an unbounded walk. It is larger than the usual one or two servers and small
/// enough to validate by hand.
pub const MAX_EXPLICIT_SERVERS: usize = 8;
/// Give one attempt at least this long, unless less time is left in the
/// overall budget.
const MIN_SERVER_BUDGET: Duration = Duration::from_millis(500);
/// Poll interval while a stop flag lets a lookup end early.
const STOP_POLL: Duration = Duration::from_millis(200);

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

/// Return the address that validation and socket creation must use.
///
/// An IPv4-mapped IPv6 literal such as `::ffff:127.0.0.1` names an IPv4
/// destination, but it is still an `IpAddr::V6` value. Left alone, it skips
/// every IPv4 unicast check and `normalization::udp_socket` opens an IPv6
/// socket with `IPV6_UNICAST_HOPS` instead of an IPv4 socket with `IP_TTL`.
/// Canonicalize it once, before dedupe, validation, or socket creation, so
/// every consumer sees the same address and the same family.
///
/// The deprecated IPv4-compatible form (`::127.0.0.1`) is not mapped here.
/// Modern stacks do not route it as IPv4, so it stays an ordinary IPv6
/// literal.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

fn canonical_server(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(canonical_ip(server.ip()), server.port())
        }
        _ => server,
    }
}

/// Parse one numeric DNS server literal, with an optional port.
///
/// An IPv4-mapped IPv6 literal is returned as the IPv4 address it names, so a
/// caller gets the socket family that the destination needs. The normal IPv4
/// and IPv6 literal grammar is unchanged. A loopback address is allowed at this
/// layer for a hermetic test resolver. An unspecified, link-local, multicast,
/// or broadcast address is not a unicast upstream and is rejected, whatever
/// spelling it uses.
pub fn parse_server(text: &str) -> io::Result<SocketAddr> {
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        check_server(addr)?;
        let addr = canonical_server(addr);
        check_server(addr)?;
        return Ok(addr);
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        let addr = canonical_server(SocketAddr::new(ip, 53));
        check_server(addr)?;
        return Ok(addr);
    }
    Err(invalid("DNS server must be a numeric IP address"))
}

/// Return true for an address that cannot be one explicit upstream server.
///
/// A loopback address is allowed at this layer so the hermetic resolver tests
/// and a local diagnostic can use one. The service start path rejects a
/// loopback upstream for a production SOCKS5 tunnel, because it is a local stub
/// rather than a resolver on the hotspot link. An unspecified, link-local,
/// multicast, or broadcast address is not a unicast upstream and is rejected.
///
/// An IPv4-mapped IPv6 address is checked as the IPv4 address it names. Without
/// that step, `::ffff:0.0.0.0`, `::ffff:169.254.1.1`, `::ffff:224.0.0.1`, and
/// `::ffff:255.255.255.255` pass the IPv6 checks and reach the code that opens
/// an outer socket.
fn unusable_explicit_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(ip) => {
            ip.octets()[0] == 0 || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            let link_local = ip.segments()[0] & 0xffc0 == 0xfe80;
            ip.is_unspecified() || link_local || ip.is_multicast()
        }
    }
}

/// Apply the value checks that every parsed server must pass.
fn check_server(server: SocketAddr) -> io::Result<()> {
    if let SocketAddr::V6(v6) = server {
        if v6.scope_id() != 0 || v6.flowinfo() != 0 {
            return Err(invalid(
                "DNS server must not have IPv6 scope or flow information",
            ));
        }
    }
    if server.port() == 0 {
        return Err(invalid("DNS port must be nonzero"));
    }
    if unusable_explicit_ip(server.ip()) {
        return Err(invalid("DNS server must be a unicast address"));
    }
    Ok(())
}

/// Validate a production upstream without changing its address family.
pub(crate) fn validate_upstream(server: SocketAddr) -> io::Result<()> {
    check_server(server)?;
    if server.ip().is_loopback() || canonical_ip(server.ip()).is_loopback() {
        return Err(invalid("DNS upstream must not be loopback"));
    }
    if canonical_server(server) != server {
        return Err(invalid("DNS upstream must use a canonical address"));
    }
    Ok(())
}

/// Validate an explicit upstream server list.
///
/// The list must not be empty, must hold at most [`MAX_EXPLICIT_SERVERS`]
/// entries, and every entry must be a numeric unicast address with a nonzero
/// port. A caller passes only parsed socket addresses here, so this function
/// checks the value, not its original text. An IPv4-mapped IPv6 entry is
/// checked as the IPv4 address it names; use [`normalize_servers`] when the
/// returned list must also carry that canonical address. It does not resolve a
/// name and it does not read a resolver file. The caller must still pin the
/// query socket to the physical interface.
pub fn validate_servers(servers: &[SocketAddr]) -> io::Result<()> {
    if servers.is_empty() {
        return Err(invalid("at least one DNS server is required"));
    }
    if servers.len() > MAX_EXPLICIT_SERVERS {
        return Err(invalid("too many DNS servers"));
    }
    for server in servers {
        check_server(*server)?;
    }
    Ok(())
}

/// Normalize an explicit upstream server list.
///
/// The function canonicalizes every entry, drops a duplicate in the order it
/// first appears, then applies [`validate_servers`]. An IPv4-mapped IPv6 entry
/// therefore becomes the IPv4 address it names, and `1.1.1.1` and
/// `::ffff:1.1.1.1` are one server. Every caller gets the same bound, the same
/// deduplication, the same value checks, and the same socket family. It never
/// resolves a name.
pub fn normalize_servers(servers: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    let mut unique = Vec::with_capacity(servers.len());
    for server in servers {
        check_server(server)?;
        let server = canonical_server(server);
        if !unique.contains(&server) {
            unique.push(server);
        }
    }
    validate_servers(&unique)?;
    Ok(unique)
}

/// Parse a bounded explicit server list from one command-line value.
///
/// Entries are separated by a comma or ASCII whitespace. Each entry is a
/// numeric unicast IP literal with an optional port, as [`parse_server`]
/// accepts. Duplicates are dropped in the order that they appear, and an
/// IPv4-mapped IPv6 entry is canonicalized to the IPv4 address it names before
/// that check. A malformed entry, a non-unicast address, an empty list, or a
/// list above [`MAX_EXPLICIT_SERVERS`] is an error. The function never resolves
/// a name.
pub fn parse_server_list(text: &str) -> io::Result<Vec<SocketAddr>> {
    if text.trim().is_empty() {
        return Err(invalid("at least one DNS server is required"));
    }
    let mut servers = Vec::new();
    for item in text.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let server = parse_server(item)?;
        if !servers.contains(&server) {
            servers.push(server);
        }
        if servers.len() > MAX_EXPLICIT_SERVERS {
            return Err(invalid("too many DNS servers"));
        }
    }
    normalize_servers(servers)
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

/// Validate the fields that identify which query a reply belongs to before
/// the reply's RCODE is trusted. A wrong transaction, a query opcode, the
/// truncated bit, the reserved Z bit, or a question that does not match the
/// query makes the reply unusable for this lookup. The return value is the
/// flags word, the question name, and the offset after its type and class.
fn checked_question(
    data: &[u8],
    name: &str,
    typ: u16,
    id: u16,
) -> io::Result<(u16, String, usize)> {
    if data.len() < 12 {
        return Err(bad("truncated DNS message"));
    }
    if word(data, 0)? != id {
        return Err(bad("unexpected DNS transaction"));
    }
    let flags = word(data, 2)?;
    if flags & 0x8000 == 0 {
        return Err(bad("DNS message is not a response"));
    }
    if flags & 0x7800 != 0 {
        return Err(bad("unexpected DNS opcode"));
    }
    if flags & 0x0200 != 0 {
        return Err(bad("truncated DNS response"));
    }
    if flags & 0x0040 != 0 {
        return Err(bad("reserved DNS flag set"));
    }
    if word(data, 4)? != 1 {
        return Err(bad("unexpected DNS question count"));
    }
    let (question, offset) = read_name(data, 12)?;
    if !question.eq_ignore_ascii_case(name.trim_end_matches('.'))
        || word(data, offset)? != typ
        || word(data, offset + 2)? != 1
    {
        return Err(bad("DNS question mismatch"));
    }
    Ok((flags, question, offset + 4))
}

// Return the accepted addresses and the smallest TTL that belongs to them.
// Accept an address only when its owner is the queried name or a name on the
// CNAME chain that starts at the queried name and has no CNAME itself. The caller caches one address,
// so the smallest TTL that covers the chain and the address records is the safe
// lifetime.
fn answers(data: &[u8], name: &str, typ: u16, id: u16) -> io::Result<(Vec<IpAddr>, u32)> {
    let (flags, question, mut offset) = checked_question(data, name, typ, id)?;
    // The caller classifies an error RCODE before it asks for addresses.
    if flags & 0x000f != 0 {
        return Err(bad("DNS response carries an error code"));
    }
    let count = word(data, 6)? as usize;
    if count > 64 {
        return Err(bad("too many DNS answers"));
    }
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

/// What one DNS reply means for this lookup. The variants keep a dead
/// resolver, a malformed reply, and a name that does not exist apart.
enum Reply {
    Answer(Vec<IpAddr>, u32),
    NoSuchName,
    NoAddress,
    ServerFailure,
    /// The reply does not identify this query, is truncated, or is malformed.
    Invalid,
}

/// Classify one reply before the full answer parser runs.
///
/// The question name, the question type and class, the opcode, the truncated
/// bit, and the reserved Z bit are checked before the RCODE is read. A reply
/// that fails one of those checks is `Invalid`: it cannot say that a name does
/// not exist, and it cannot report a server failure. A reply that carries no
/// address is not a failure. The caller needs to tell it apart from a
/// malformed reply and from a missing server.
fn classify_reply(data: &[u8], name: &str, typ: u16, id: u16) -> Reply {
    let Ok((flags, _, _)) = checked_question(data, name, typ, id) else {
        return Reply::Invalid;
    };
    match flags & 0x000f {
        0 => match answers(data, name, typ, id) {
            Ok((addrs, ttl)) if !addrs.is_empty() => Reply::Answer(addrs, ttl),
            Ok(_) => Reply::NoAddress,
            Err(_) => Reply::Invalid,
        },
        3 => Reply::NoSuchName,
        // FORMERR, SERVFAIL, NOTIMP, and REFUSED are server-side failures.
        _ => Reply::ServerFailure,
    }
}

/// Build an error that says why the lookup failed. The text holds a server
/// count and an operating-system socket message at most. It never holds a
/// name, an address, or a token.
fn lookup_error(
    tried: usize,
    no_name: usize,
    no_address: usize,
    server_failure: usize,
    bad_reply: bool,
    transport_failure: Option<&str>,
) -> io::Error {
    let count = if tried == 1 {
        "1 server tried".to_owned()
    } else {
        format!("{tried} servers tried")
    };
    if tried == 0 {
        return io::Error::new(
            io::ErrorKind::TimedOut,
            "DNS timeout expired before a lookup",
        );
    }
    if no_name == tried {
        return io::Error::new(io::ErrorKind::NotFound, "DNS name does not exist");
    }
    if no_address == tried {
        return io::Error::new(
            io::ErrorKind::NotFound,
            "DNS name has no address of this type",
        );
    }
    if server_failure == tried {
        return io::Error::other(format!("DNS server rejected the query ({count})"));
    }
    if bad_reply {
        return io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DNS reply was not usable ({count})"),
        );
    }
    if let Some(detail) = transport_failure {
        return io::Error::other(format!(
            "DNS socket failed before a reply ({count}): {detail}"
        ));
    }
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("DNS servers did not answer ({count})"),
    )
}

/// A small DNS client for the tunnel.
///
/// The cache holds one address for each name and query type. It honors the
/// smallest TTL in the answer. An answer with TTL 0 is not cached. The cache
/// holds at most 512 entries and shortens a TTL above 3600 seconds.
///
/// Pinning is part of the contract. A resolver built with an interface index
/// pins every query socket to that interface. `None` is a loopback-only test
/// and local-diagnostic mode: construction fails when a server is not a
/// loopback address, because an unpinned query would leave the machine on the
/// ordinary network path. SOCKS5 mode has no `--no-pin` option and always
/// passes the physical hotspot index. The server list is bounded and every
/// server must be a numeric unicast address with a nonzero port; see
/// [`validate_servers`]. An IPv4-mapped IPv6 server is canonicalized to IPv4
/// before the loopback check and before a query socket is opened.
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
        if servers.is_empty() || timeout.is_zero() {
            return Err(invalid("DNS server and timeout are required"));
        }
        // Drop a duplicate so one server is not tried twice, then apply the
        // same bound and value checks as every other explicit list.
        let unique = normalize_servers(servers)?;
        if iface.is_none() && unique.iter().any(|s| !s.ip().is_loopback()) {
            return Err(invalid(
                "an unpinned DNS resolver may use only loopback servers",
            ));
        }
        Ok(Self {
            servers: unique,
            iface,
            timeout,
            cache: Mutex::new(HashMap::new()),
            clock,
        })
    }
    /// The configured servers, in the order the resolver tries them.
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }
    /// The interface used for every DNS query socket, if pinned.
    pub fn interface(&self) -> Option<u32> {
        self.iface
    }
    fn now(&self) -> Instant {
        (self.clock)()
    }
    pub fn resolve(&self, name: &str, typ: u16, audit: &Audit) -> io::Result<IpAddr> {
        self.resolve_cancellable(name, typ, audit, None)
    }
    /// Resolve a name and check for cancellation while waiting for DNS replies.
    ///
    /// All servers share one overall `timeout`. Each attempt gets an equal
    /// share of the time that is left, with a floor of [`MIN_SERVER_BUDGET`]
    /// when that much time is left, capped by the time that is left. The wait
    /// therefore ends at `timeout` apart from socket setup and scheduling. A
    /// server that uses its whole share can leave later servers no time; those
    /// servers are not tried, and the error still names the count that were
    /// tried.
    ///
    /// A reply that is truncated, has a wrong transaction, a wrong opcode, a
    /// reserved flag, or a question that does not match this lookup is
    /// unusable. It is not a name error and not a server failure. The resolver
    /// keeps waiting for another reply until the attempt deadline. If no
    /// server returns a usable reply and no server said that the name is
    /// missing, has no address of this type, or rejected the query, the error
    /// is [`io::ErrorKind::InvalidData`] when at least one reply was unusable.
    /// Otherwise a silent budget expiry is [`io::ErrorKind::TimedOut`].
    /// Cancellation returns [`io::ErrorKind::Interrupted`] at once.
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
        let overall = Instant::now();
        let mut tried = 0usize;
        let mut no_name = 0usize;
        let mut no_address = 0usize;
        let mut server_failure = 0usize;
        let mut bad_reply = false;
        let mut transport_failure: Option<String> = None;
        let mut buf = [0u8; 65535];
        for (index, server) in self.servers.iter().enumerate() {
            if stopped.is_some_and(|s| s.load(Ordering::Acquire)) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "DNS lookup cancelled",
                ));
            }
            // Each attempt gets an equal share of the time that is left, with
            // a floor and a cap. The cap keeps the overall timeout, so a
            // server that uses its whole share can leave no time for the ones
            // after it.
            let remaining = self.timeout.saturating_sub(overall.elapsed());
            if remaining.is_zero() {
                break;
            }
            tried += 1;
            let left = (self.servers.len() - index) as u32;
            let per_server = (remaining / left).max(MIN_SERVER_BUDGET).min(remaining);
            let sock = match normalization::udp_socket(server.ip(), self.iface, audit) {
                Ok(sock) => sock,
                Err(error) => {
                    transport_failure = Some(error.to_string());
                    continue;
                }
            };
            if let Err(error) = sock.connect(*server) {
                transport_failure = Some(error.to_string());
                continue;
            }
            if let Err(error) = sock.send(&message) {
                transport_failure = Some(error.to_string());
                continue;
            }
            let deadline = Instant::now() + per_server;
            while let Some(wait) = deadline.checked_duration_since(Instant::now()) {
                if stopped.is_some_and(|s| s.load(Ordering::Acquire)) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "DNS lookup cancelled",
                    ));
                }
                let interval = if stopped.is_some() {
                    wait.min(STOP_POLL)
                } else {
                    wait
                };
                sock.set_read_timeout(Some(interval.max(Duration::from_millis(1))))?;
                match sock.recv(&mut buf) {
                    Ok(n) => match classify_reply(&buf[..n], &name, typ, id) {
                        Reply::Answer(addrs, ttl) => {
                            let addr = addrs[0];
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
                        Reply::NoSuchName => {
                            no_name += 1;
                            break;
                        }
                        Reply::NoAddress => {
                            no_address += 1;
                            break;
                        }
                        Reply::ServerFailure => {
                            server_failure += 1;
                            break;
                        }
                        // A wrong transaction or a malformed reply might be a
                        // stale packet. Keep waiting for the real answer.
                        Reply::Invalid => bad_reply = true,
                    },
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
                    Err(error) => {
                        transport_failure = Some(error.to_string());
                        break;
                    }
                }
            }
        }
        Err(lookup_error(
            tried,
            no_name,
            no_address,
            server_failure,
            bad_reply,
            transport_failure.as_deref(),
        ))
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
    #[test]
    fn scoped_or_flow_labeled_servers_are_rejected_without_silent_loss() {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let ip: Ipv6Addr = "2001:db8::53".parse().unwrap();
        for (flow, scope) in [(1, 0), (0, 2)] {
            let addr = SocketAddr::V6(SocketAddrV6::new(ip, 53, flow, scope));
            assert!(validate_servers(&[addr]).is_err());
            assert!(normalize_servers(vec![addr]).is_err());
        }
        let normal = SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 0));
        assert_eq!(normalize_servers(vec![normal]).unwrap(), vec![normal]);
    }
    #[test]
    fn explicit_server_lists_are_bounded_and_validated() {
        assert_eq!(
            parse_server_list("1.1.1.1, 9.9.9.9:5353").unwrap(),
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:5353".parse::<SocketAddr>().unwrap(),
            ]
        );
        // Whitespace works too, and a duplicate is dropped in place.
        assert_eq!(
            parse_server_list("1.1.1.1\t1.1.1.1 9.9.9.9").unwrap(),
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:53".parse::<SocketAddr>().unwrap(),
            ]
        );
        // A malformed entry, an empty entry list, a zero port, and a
        // non-unicast address are errors. No name is resolved.
        for text in [
            "dns.example",
            "1.1.1.1,dns.example",
            "",
            " , ",
            "1.1.1.1:0",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "169.254.1.1",
            "[fe80::1]",
            "[ff02::1]",
        ] {
            assert!(parse_server_list(text).is_err(), "accepted {text:?}");
        }
        // The count bound applies after deduplication.
        let mut many = String::new();
        for index in 0..=MAX_EXPLICIT_SERVERS {
            many.push_str(&format!("192.0.2.{index},"));
        }
        assert!(parse_server_list(&many).is_err());
        let mut at_limit = String::new();
        for index in 0..MAX_EXPLICIT_SERVERS {
            at_limit.push_str(&format!("192.0.2.{index},"));
        }
        assert_eq!(
            parse_server_list(&at_limit).unwrap().len(),
            MAX_EXPLICIT_SERVERS
        );
    }
    #[test]
    fn normalize_servers_deduplicates_both_address_families() {
        let v4: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::53]:5353".parse().unwrap();
        assert_eq!(
            normalize_servers(vec![v4, v6, v4, v6]).unwrap(),
            vec![v4, v6]
        );
        assert!(normalize_servers(Vec::new()).is_err());
        assert!(normalize_servers(vec![v4; MAX_EXPLICIT_SERVERS + 1]).is_ok());
        let unique: Vec<SocketAddr> = (0..=MAX_EXPLICIT_SERVERS)
            .map(|index| format!("192.0.2.{index}:53").parse().unwrap())
            .collect();
        assert!(normalize_servers(unique).is_err());
    }
    #[test]
    fn explicit_server_validation_allows_a_loopback_test_resolver() {
        assert!(validate_servers(&["127.0.0.1:53".parse().unwrap()]).is_ok());
        let error = validate_servers(&[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(validate_servers(&["0.0.0.0:53".parse().unwrap()]).is_err());
    }
    #[test]
    fn unpinned_resolver_requires_loopback_servers() {
        let relay = "192.0.2.1:53".parse().unwrap();
        let error = match TinyResolver::new(vec![relay], None, Duration::from_secs(1)) {
            Ok(_) => panic!("an unpinned resolver must reject a non-loopback server"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let loopback = "127.0.0.1:53".parse().unwrap();
        assert!(TinyResolver::new(vec![loopback], None, Duration::from_secs(1)).is_ok());
        assert!(TinyResolver::new(
            vec!["192.0.2.1:53".parse().unwrap()],
            Some(4),
            Duration::from_secs(1)
        )
        .is_ok());
    }
    #[test]
    fn mapped_server_literals_are_canonicalized() {
        // A mapped literal names an IPv4 destination. The parsed value must
        // carry the IPv4 family so validation and socket creation see IPv4.
        assert_eq!(
            parse_server("[::ffff:127.0.0.1]:5353").unwrap(),
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_server("::ffff:1.1.1.1").unwrap(),
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        // The hex spelling of the same mapped address canonicalizes too.
        assert_eq!(
            parse_server("[::ffff:c000:22b]:5353").unwrap(),
            "192.0.2.43:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_server_list("[::ffff:1.1.1.1]:5353").unwrap(),
            vec!["1.1.1.1:5353".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            normalize_servers(vec!["[::ffff:1.1.1.1]:5353".parse().unwrap()]).unwrap(),
            vec!["1.1.1.1:5353".parse::<SocketAddr>().unwrap()]
        );
        // Normal IPv4 and IPv6 grammar keeps its family and value.
        assert_eq!(
            parse_server("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_server("[2001:db8::53]:5353").unwrap(),
            "[2001:db8::53]:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_server("[::1]:5353").unwrap(),
            "[::1]:5353".parse::<SocketAddr>().unwrap()
        );
        assert!(parse_server("[2001:db8::53]:5353").unwrap().is_ipv6());
        assert!(parse_server("2001:db8::53").unwrap().is_ipv6());
    }
    #[test]
    fn mapped_non_unicast_servers_get_the_ipv4_checks() {
        // Each mapped value must fail exactly where its IPv4 spelling fails,
        // including the single-literal parser that the DNS upstream uses.
        let cases = [
            ("[::ffff:0.0.0.0]:53", "0.0.0.0:53"),
            ("[::ffff:0.1.2.3]:53", "0.1.2.3:53"),
            ("[::ffff:169.254.1.1]:53", "169.254.1.1:53"),
            ("[::ffff:224.0.0.1]:53", "224.0.0.1:53"),
            ("[::ffff:255.255.255.255]:53", "255.255.255.255:53"),
        ];
        for (mapped, plain) in cases {
            let mapped: SocketAddr = mapped.parse().unwrap();
            let plain: SocketAddr = plain.parse().unwrap();
            for server in [mapped, plain] {
                let error = parse_server(&server.to_string()).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    parse_server_list(&server.to_string()).is_err(),
                    "accepted {server}"
                );
                let error = validate_servers(&[server]).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    normalize_servers(vec![server]).is_err(),
                    "accepted {server}"
                );
            }
        }
    }
    #[test]
    fn mapped_loopback_is_checked_as_loopback() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:53".parse().unwrap();
        assert!(validate_servers(&[mapped]).is_ok());
        assert_eq!(
            normalize_servers(vec![mapped]).unwrap(),
            vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()]
        );
        // An unpinned resolver allows only loopback servers. The canonical
        // value is what makes this mapped literal pass that check.
        assert!(TinyResolver::new(vec![mapped], None, Duration::from_secs(1)).is_ok());
        // A mapped non-loopback server is still rejected while unpinned.
        assert!(TinyResolver::new(
            vec!["[::ffff:192.0.2.1]:53".parse().unwrap()],
            None,
            Duration::from_secs(1)
        )
        .is_err());
    }
    #[test]
    fn normalize_servers_deduplicates_mapped_aliases() {
        let v4: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let other: SocketAddr = "1.1.1.1:5353".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:1.1.1.1]:53".parse().unwrap();
        let mapped_other: SocketAddr = "[::ffff:1.1.1.1]:5353".parse().unwrap();
        assert_eq!(
            normalize_servers(vec![v4, mapped, mapped_other, other, v4]).unwrap(),
            vec![v4, other]
        );
        // The CLI list parser applies the same canonical dedupe in order.
        assert_eq!(
            parse_server_list("::ffff:1.1.1.1, 1.1.1.1:53, 1.1.1.1:5353").unwrap(),
            vec![v4, other]
        );
        // The count bound applies after canonical dedupe, so a mapped alias of
        // an earlier entry does not consume a slot.
        let mut text = String::new();
        for index in 0..MAX_EXPLICIT_SERVERS {
            text.push_str(&format!("192.0.2.{index},"));
        }
        text.push_str("::ffff:192.0.2.0");
        assert_eq!(
            parse_server_list(&text).unwrap().len(),
            MAX_EXPLICIT_SERVERS
        );
    }
    #[cfg(unix)]
    #[test]
    fn mapped_public_server_opens_an_ipv4_socket() {
        let mapped: SocketAddr = "[::ffff:192.0.2.53]:5353".parse().unwrap();
        let normalized = normalize_servers(vec![mapped]).unwrap();
        assert_eq!(
            normalized,
            vec!["192.0.2.53:5353".parse::<SocketAddr>().unwrap()]
        );
        // udp_socket selects the family from the IpAddr variant. The
        // canonical value is what keeps the outer socket on IP_TTL.
        let audit = Audit::default();
        let socket = normalization::udp_socket(normalized[0].ip(), None, &audit).unwrap();
        assert!(socket.local_addr().unwrap().is_ipv4());
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[cfg(unix)]
    #[test]
    fn resolves_through_a_mapped_loopback_server() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let message = reply(&b[..n], "192.0.2.7".parse().unwrap(), 60);
            server.send_to(&message, src).unwrap();
        });
        let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{port}").parse().unwrap();
        let resolver = TinyResolver::new(vec![mapped], None, Duration::from_secs(2)).unwrap();
        let expected = SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), port);
        assert_eq!(resolver.servers(), &[expected]);
        let audit = Audit::default();
        assert_eq!(
            resolver.resolve("mapped.test", QTYPE_A, &audit).unwrap(),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn tries_every_configured_server() {
        // The first server never answers. The lookup must still reach the
        // second one inside the overall timeout. No server is dropped from the
        // tail of the list.
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let answer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let answer_addr = answer.local_addr().unwrap();
        answer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = answer.recv_from(&mut b).unwrap();
            let message = reply(&b[..n], "1.2.3.4".parse().unwrap(), 60);
            answer.send_to(&message, src).unwrap();
        });
        let resolver = TinyResolver::new(
            vec![silent.local_addr().unwrap(), answer_addr],
            None,
            Duration::from_secs(2),
        )
        .unwrap();
        let audit = Audit::default();
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (2, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn reports_a_missing_name() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let mut message = b[..n].to_vec();
            // A response with RCODE 3, the name does not exist.
            message[2] = 0x81;
            message[3] = 0x83;
            server.send_to(&message, src).unwrap();
        });
        let resolver = TinyResolver::new(vec![server_addr], None, Duration::from_secs(1)).unwrap();
        let error = resolver
            .resolve("missing.test", QTYPE_A, &Audit::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("does not exist"));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn reports_a_missing_address_type() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let mut message = b[..n].to_vec();
            // A valid response with no answer record: NODATA, not a failure.
            message[2] = 0x81;
            message[3] = 0x80;
            message[7] = 0;
            server.send_to(&message, src).unwrap();
        });
        let resolver = TinyResolver::new(vec![server_addr], None, Duration::from_secs(1)).unwrap();
        let error = resolver
            .resolve("empty.test", QTYPE_AAAA, &Audit::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("no address of this type"));
        worker.join().unwrap();
    }
    #[test]
    fn rejects_error_replies_that_do_not_match_the_question() {
        let request = query("example.test", QTYPE_A, 0x4242).unwrap();
        let mut message = request.clone();
        message[2] = 0x81;
        message[3] = 0x83;
        // A matching reply with RCODE 3 is the only NXDOMAIN case.
        assert!(matches!(
            classify_reply(&message, "example.test", QTYPE_A, 0x4242),
            Reply::NoSuchName
        ));
        // A different name, type, or transaction is not NXDOMAIN.
        assert!(matches!(
            classify_reply(&message, "other.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        assert!(matches!(
            classify_reply(&message, "example.test", QTYPE_AAAA, 0x4242),
            Reply::Invalid
        ));
        assert!(matches!(
            classify_reply(&message, "example.test", QTYPE_A, 0x4243),
            Reply::Invalid
        ));
        let mut wrong_class = message.clone();
        let last = wrong_class.len() - 1;
        wrong_class[last] = 2;
        assert!(matches!(
            classify_reply(&wrong_class, "example.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        // A query opcode, the truncated bit, and the reserved Z bit are
        // checked before the RCODE.
        let mut opcode = message.clone();
        opcode[2] |= 0x08;
        assert!(matches!(
            classify_reply(&opcode, "example.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        let mut truncated = message.clone();
        truncated[2] |= 0x02;
        assert!(matches!(
            classify_reply(&truncated, "example.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        let mut reserved = message.clone();
        reserved[3] |= 0x40;
        assert!(matches!(
            classify_reply(&reserved, "example.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        let mut two_questions = message.clone();
        two_questions[5] = 2;
        assert!(matches!(
            classify_reply(&two_questions, "example.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        // A query is not a response.
        assert!(matches!(
            classify_reply(&request, "example.test", QTYPE_A, 0x4242),
            Reply::Invalid
        ));
        // A matching server failure is still classified as one.
        let mut failure = request.clone();
        failure[2] = 0x81;
        failure[3] = 0x82;
        assert!(matches!(
            classify_reply(&failure, "example.test", QTYPE_A, 0x4242),
            Reply::ServerFailure
        ));
    }
    #[cfg(unix)]
    #[test]
    fn ignores_a_mismatched_error_reply_and_waits_for_the_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = server.recv_from(&mut b).unwrap();
            let mut bogus = b[..n].to_vec();
            bogus[2] = 0x81;
            bogus[3] = 0x83;
            // Break the question class. The RCODE must not be trusted.
            let last = bogus.len() - 1;
            bogus[last] = 2;
            server.send_to(&bogus, src).unwrap();
            let good = reply(&b[..n], "192.0.2.7".parse().unwrap(), 60);
            server.send_to(&good, src).unwrap();
        });
        let audit = Audit::default();
        let resolver = TinyResolver::new(vec![addr], None, Duration::from_secs(2)).unwrap();
        assert_eq!(
            resolver.resolve("example.test", QTYPE_A, &audit).unwrap(),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn reports_a_malformed_reply_as_invalid_data() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let worker_socket = server.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, src) = worker_socket.recv_from(&mut b).unwrap();
            let mut forged = b[..n].to_vec();
            forged[0] ^= 1;
            worker_socket.send_to(&forged, src).unwrap();
            // Keep the socket open until the resolver gives up, so the test
            // measures the reply budget and not a refused port.
            thread::sleep(Duration::from_millis(500));
        });
        let resolver = TinyResolver::new(vec![addr], None, Duration::from_millis(250)).unwrap();
        let error = resolver
            .resolve("example.test", QTYPE_A, &Audit::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not usable"));
        worker.join().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn reports_a_timeout_when_no_server_answers() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let audit = Audit::default();
        let resolver = TinyResolver::new(
            vec![server.local_addr().unwrap()],
            None,
            Duration::from_millis(250),
        )
        .unwrap();
        let start = Instant::now();
        let error = resolver
            .resolve("example.test", QTYPE_A, &audit)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("did not answer"));
        assert!(start.elapsed() >= Duration::from_millis(200));
        assert_eq!(audit.snapshot(), (1, 0));
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
