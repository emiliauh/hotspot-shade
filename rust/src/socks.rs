//! A loopback SOCKS5 server with normalized outer sockets.
use crate::dns::{TinyResolver, QTYPE_A, QTYPE_AAAA};
use crate::normalization::{self, Audit};
use crate::tls_shape::{ClientHelloShaper, ShapeLimits, ShapeState};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const LIMIT_CLIENTS: usize = 128;
const LIMIT_UDP_FLOWS: usize = 128;
const LIMIT_TOTAL_UDP_FLOWS: usize = 512;
const UDP_BATCH: usize = 64;
const IDLE: Duration = Duration::from_secs(300);
const TIMEOUT: Duration = Duration::from_secs(10);

struct Shared {
    stopped: AtomicBool,
    active: AtomicUsize,
    next: AtomicU64,
    clients: Mutex<HashMap<u64, TcpStream>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    resolver: Arc<TinyResolver>,
    iface: Option<u32>,
    audit: Arc<Audit>,
    udp_active: Arc<AtomicUsize>,
    /// Explicit ClientHello reframing. `None` keeps every relay byte unchanged.
    shape: Option<ShapeLimits>,
}

/// Owns the loopback listener and all active handlers.
pub struct SocksServer {
    pub address: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl SocksServer {
    /// Start a loopback SOCKS5 listener.
    ///
    /// `iface` is the interface index for every outer socket. `None` cannot
    /// pin a socket, so that mode reaches only loopback destinations and is
    /// for hermetic tests and local diagnostics. The product path always
    /// passes the physical hotspot index.
    pub fn start(
        address: SocketAddr,
        resolver: Arc<TinyResolver>,
        iface: Option<u32>,
        audit: Arc<Audit>,
    ) -> io::Result<Self> {
        Self::start_with_shape(address, resolver, iface, audit, None)
    }
    /// Start with an explicit ClientHello reframing policy.
    ///
    /// `None` is the default: the relay copies every byte. `Some(limits)` is an
    /// explicit opt-in. The shaper changes only the record framing of the
    /// first ClientHello on a TCP flow. It does not hide SNI, DNS names, or
    /// the destination, and it does not control TCP segmentation. See
    /// [`crate::tls_shape`].
    pub fn start_with_shape(
        address: SocketAddr,
        resolver: Arc<TinyResolver>,
        iface: Option<u32>,
        audit: Arc<Audit>,
        shape: Option<ShapeLimits>,
    ) -> io::Result<Self> {
        if resolver.interface() != iface {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS and DNS resolver interfaces must match",
            ));
        }
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS listener must use loopback",
            ));
        }
        if let Some(limits) = shape {
            // Fail at start, not on the first flow with a bad configuration.
            ClientHelloShaper::new(limits)?;
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let shared = Arc::new(Shared {
            stopped: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            next: AtomicU64::new(0),
            clients: Mutex::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
            resolver,
            iface,
            audit,
            udp_active: Arc::new(AtomicUsize::new(0)),
            shape,
        });
        let s = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("socks-accept".into())
            .spawn(move || {
                while !s.stopped.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((client, peer)) => {
                            if client.set_nonblocking(false).is_err() {
                                continue;
                            }
                            if s.stopped.load(Ordering::Acquire) {
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            if s.active.fetch_add(1, Ordering::AcqRel) >= LIMIT_CLIENTS {
                                s.active.fetch_sub(1, Ordering::AcqRel);
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            let id = s.next.fetch_add(1, Ordering::Relaxed);
                            match client.try_clone() {
                                Ok(copy) => {
                                    s.clients.lock().unwrap().insert(id, copy);
                                }
                                Err(_) => {
                                    s.active.fetch_sub(1, Ordering::AcqRel);
                                    continue;
                                }
                            }
                            let worker = Arc::clone(&s);
                            match thread::Builder::new().name("socks-flow".into()).spawn(
                                move || {
                                    let _ = handle_client(client, peer, &worker);
                                    worker.clients.lock().unwrap().remove(&id);
                                    worker.active.fetch_sub(1, Ordering::AcqRel);
                                },
                            ) {
                                Ok(handle) => {
                                    let mut threads = s.threads.lock().unwrap();
                                    // Reap finished handlers during operation.
                                    let mut i = 0;
                                    while i < threads.len() {
                                        if threads[i].is_finished() {
                                            let _ = threads.swap_remove(i).join();
                                        } else {
                                            i += 1;
                                        }
                                    }
                                    threads.push(handle);
                                }
                                Err(_) => {
                                    s.clients.lock().unwrap().remove(&id);
                                    s.active.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20))
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            address,
            shared,
            thread: Some(thread),
        })
    }
    pub fn stop(&mut self) {
        self.shared.stopped.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        for stream in self.shared.clients.lock().unwrap().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let handles = std::mem::take(&mut *self.shared.threads.lock().unwrap());
        for handle in handles {
            let _ = handle.join();
        }
    }
    pub fn active_clients(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }
    /// Return false when the listener thread has ended.
    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }
    #[cfg(test)]
    pub(crate) fn end_listener_for_test(&self) {
        self.shared.stopped.store(true, Ordering::Release);
    }
}
impl Drop for SocksServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Decide whether an outer socket may reach this destination.
///
/// A server with an interface index pins every outer socket to that
/// interface. That is the product path. A server without one cannot pin a
/// socket, so it may reach only a loopback destination, which cannot leave
/// the machine. SOCKS5 mode has no `--no-pin` option; `None` exists for
/// hermetic tests and local diagnostics only.
fn outer_egress_allowed(iface: Option<u32>, target: IpAddr) -> bool {
    iface.is_some() || target.is_loopback()
}

fn reply(stream: &mut TcpStream, rep: u8, addr: SocketAddr) -> io::Result<()> {
    let mut out = vec![5, rep, 0];
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&out)
}
fn zero_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn read_target(stream: &mut TcpStream, atyp: u8, s: &Shared) -> io::Result<SocketAddr> {
    let ip = match atyp {
        1 => {
            let mut x = [0; 4];
            stream.read_exact(&mut x)?;
            IpAddr::from(x)
        }
        4 => {
            let mut x = [0; 16];
            stream.read_exact(&mut x)?;
            IpAddr::from(x)
        }
        3 => {
            let mut n = [0];
            stream.read_exact(&mut n)?;
            if n[0] == 0 {
                return Err(invalid("empty hostname"));
            }
            let mut name = vec![0; n[0] as usize];
            stream.read_exact(&mut name)?;
            let name = std::str::from_utf8(&name).map_err(|_| invalid("invalid hostname"))?;
            if !name.is_ascii() {
                return Err(invalid("hostname must be ASCII"));
            }
            s.resolver
                .resolve_cancellable(name, QTYPE_A, &s.audit, Some(&s.stopped))
                .or_else(|_| {
                    s.resolver
                        .resolve_cancellable(name, QTYPE_AAAA, &s.audit, Some(&s.stopped))
                })?
        }
        _ => return Err(invalid("unsupported address type")),
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port)?;
    Ok(SocketAddr::new(
        crate::dns::canonical_ip(ip),
        u16::from_be_bytes(port),
    ))
}
fn handle_client(mut client: TcpStream, peer: SocketAddr, s: &Arc<Shared>) -> io::Result<()> {
    client.set_read_timeout(Some(TIMEOUT))?;
    client.set_write_timeout(Some(TIMEOUT))?;
    let mut header = [0; 2];
    client.read_exact(&mut header)?;
    if header[0] != 5 || header[1] == 0 {
        return Err(invalid("invalid SOCKS greeting"));
    }
    let mut methods = vec![0; header[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 255])?;
        return Err(invalid("no supported authentication method"));
    }
    client.write_all(&[5, 0])?;
    let mut req = [0; 4];
    client.read_exact(&mut req)?;
    if req[0] != 5 || req[2] != 0 {
        return Err(invalid("invalid SOCKS request"));
    }
    let target = match read_target(&mut client, req[3], s) {
        Ok(t) => t,
        Err(e) => {
            let _ = reply(&mut client, 8, zero_addr());
            return Err(e);
        }
    };
    match req[1] {
        1 => {
            if target.port() == 0 {
                reply(&mut client, 1, zero_addr())?;
                return Err(invalid("invalid target port"));
            }
            if !outer_egress_allowed(s.iface, target.ip()) {
                // Connection not allowed by ruleset. No socket is opened.
                reply(&mut client, 2, zero_addr())?;
                return Err(invalid(
                    "unpinned outer socket requires a loopback destination",
                ));
            }
            let outer = match normalization::tcp_connect_cancellable(
                target,
                s.iface,
                &s.audit,
                TIMEOUT,
                Some(&s.stopped),
            ) {
                Ok(t) => t,
                Err(e) => {
                    let _ = reply(&mut client, 5, zero_addr());
                    return Err(e);
                }
            };
            // Keep the flow usable if the local kernel rejects this option.
            let _ = normalization::set_tcp_keepalive(
                &outer,
                normalization::TcpKeepalive::SOURCE_DEVICE,
            );
            let bound = outer.local_addr().unwrap_or_else(|_| zero_addr());
            reply(&mut client, 0, bound)?;
            relay(client, outer, s)
        }
        3 => {
            let local = SocketAddr::new(
                if peer.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                },
                0,
            );
            let udp = UdpSocket::bind(local)?;
            udp.set_nonblocking(true)?;
            reply(&mut client, 0, udp.local_addr()?)?;
            udp_associate(client, peer, udp, s)
        }
        _ => {
            reply(&mut client, 7, zero_addr())?;
            Err(invalid("unsupported SOCKS command"))
        }
    }
}

fn pump(
    mut src: TcpStream,
    mut dst: TcpStream,
    s: Arc<Shared>,
    last: Arc<Mutex<Instant>>,
    mut shaper: Option<ClientHelloShaper>,
) {
    let _ = src.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = dst.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 32768];
    loop {
        if s.stopped.load(Ordering::Acquire) || last.lock().unwrap().elapsed() > IDLE {
            break;
        }
        match src.read(&mut buf) {
            Ok(0) => {
                // A client that ends before the ClientHello is complete must
                // still deliver the bytes it sent. finish releases them once,
                // unchanged, before the half-close.
                if let Some(shaping) = shaper.as_mut() {
                    if shaping.finish(&mut |chunk| dst.write_all(chunk)).is_err() {
                        break;
                    }
                }
                let _ = dst.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                let written = match shaper.as_mut() {
                    None => dst.write_all(&buf[..n]),
                    Some(shaping) => shaping.feed(&buf[..n], &mut |chunk| dst.write_all(chunk)),
                };
                if written.is_err() {
                    break;
                }
                // Once the flow stops buffering, write it directly. The
                // reframed or passed-through bytes already left in order.
                if shaper
                    .as_ref()
                    .is_some_and(|shaping| shaping.state() != ShapeState::Buffering)
                {
                    shaper = None;
                }
                *last.lock().unwrap() = Instant::now();
            }
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
            Err(_) => break,
        }
    }
    let _ = src.shutdown(Shutdown::Both);
    let _ = dst.shutdown(Shutdown::Both);
}
fn relay(client: TcpStream, outer: TcpStream, s: &Arc<Shared>) -> io::Result<()> {
    let a = client.try_clone()?;
    let b = outer.try_clone()?;
    let _ = client.set_nodelay(true);
    let _ = outer.set_nodelay(true);
    let state = Arc::clone(s);
    let last = Arc::new(Mutex::new(Instant::now()));
    let l = Arc::clone(&last);
    let t = thread::Builder::new()
        .name("socks-return".into())
        .spawn(move || pump(b, a, state, l, None))?;
    // Shape only the client to destination direction. The returned bytes are
    // never rewritten.
    let shaper = s
        .shape
        .map(|limits| ClientHelloShaper::new(limits).expect("shape limits were checked at start"));
    pump(client, outer, Arc::clone(s), last, shaper);
    let _ = t.join();
    Ok(())
}

struct UdpPermit(Arc<AtomicUsize>);
impl Drop for UdpPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn reserve_udp(active: &Arc<AtomicUsize>) -> Option<UdpPermit> {
    let mut count = active.load(Ordering::Acquire);
    loop {
        if count >= LIMIT_TOTAL_UDP_FLOWS {
            return None;
        }
        match active.compare_exchange_weak(count, count + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(UdpPermit(Arc::clone(active))),
            Err(actual) => count = actual,
        }
    }
}
struct Flow {
    socket: normalization::NormalizedUdpSocket,
    last: Instant,
    _permit: UdpPermit,
}
fn udp_target(packet: &[u8], s: &Shared) -> io::Result<(SocketAddr, SocketAddr, usize)> {
    if packet.len() < 4 || packet[0..3] != [0, 0, 0] {
        return Err(invalid("invalid or fragmented UDP request"));
    }
    let (ip, mut offset) = match packet[3] {
        1 if packet.len() >= 10 => (
            IpAddr::from([packet[4], packet[5], packet[6], packet[7]]),
            8,
        ),
        4 if packet.len() >= 22 => {
            let mut b = [0; 16];
            b.copy_from_slice(&packet[4..20]);
            (IpAddr::from(b), 20)
        }
        3 if packet.len() >= 5 => {
            let n = packet[4] as usize;
            if n == 0 || packet.len() < 7 + n {
                return Err(invalid("invalid UDP domain"));
            }
            let name = std::str::from_utf8(&packet[5..5 + n])
                .map_err(|_| invalid("invalid UDP domain"))?;
            if !name.is_ascii() {
                return Err(invalid("invalid UDP domain"));
            }
            (
                s.resolver
                    .resolve_cancellable(name, QTYPE_A, &s.audit, Some(&s.stopped))
                    .or_else(|_| {
                        s.resolver
                            .resolve_cancellable(name, QTYPE_AAAA, &s.audit, Some(&s.stopped))
                    })?,
                5 + n,
            )
        }
        _ => return Err(invalid("invalid UDP address")),
    };
    if packet.len() < offset + 2 {
        return Err(invalid("truncated UDP port"));
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;
    if port == 0 {
        return Err(invalid("invalid UDP port"));
    }
    let original = SocketAddr::new(ip, port);
    let target = SocketAddr::new(crate::dns::canonical_ip(ip), port);
    if !outer_egress_allowed(s.iface, target.ip()) {
        return Err(invalid(
            "unpinned outer socket requires a loopback destination",
        ));
    }
    Ok((original, target, offset))
}
fn udp_associate(
    mut control: TcpStream,
    peer: SocketAddr,
    local: UdpSocket,
    s: &Arc<Shared>,
) -> io::Result<()> {
    control.set_nonblocking(true)?;
    let mut source = None;
    let mut flows: HashMap<(SocketAddr, SocketAddr), Flow> = HashMap::new();
    let mut data = [0u8; 65535];
    let mut ctl = [0u8; 64];
    while !s.stopped.load(Ordering::Acquire) {
        match control.read(&mut ctl) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
        for _ in 0..UDP_BATCH {
            match local.recv_from(&mut data) {
                Ok((n, from)) if from.ip() == peer.ip() => {
                    if source.is_some() && source != Some(from) {
                        continue;
                    }
                    let (original, target, off) = match udp_target(&data[..n], s) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if source.is_none() {
                        source = Some(from);
                    }
                    let key = (from, original);
                    if !flows.contains_key(&key) {
                        if flows.len() >= LIMIT_UDP_FLOWS {
                            continue;
                        }
                        let permit = match reserve_udp(&s.udp_active) {
                            Some(v) => v,
                            None => continue,
                        };
                        let socket = match normalization::udp_socket(target.ip(), s.iface, &s.audit)
                        {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        if socket.connect(target).is_err() || socket.set_nonblocking(true).is_err()
                        {
                            continue;
                        }
                        flows.insert(
                            key,
                            Flow {
                                socket,
                                last: Instant::now(),
                                _permit: permit,
                            },
                        );
                    }
                    if let Some(flow) = flows.get_mut(&key) {
                        if flow.socket.send(&data[off..n]).is_ok() {
                            flow.last = Instant::now();
                        }
                    }
                }
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        flows.retain(|(from, target), flow| {
            for _ in 0..UDP_BATCH {
                match flow.socket.recv(&mut data) {
                    Ok(n) => {
                        let mut packet = vec![0, 0, 0];
                        match crate::dns::canonical_ip(target.ip()) {
                            IpAddr::V4(ip) => {
                                packet.push(1);
                                packet.extend_from_slice(&ip.octets());
                            }
                            IpAddr::V6(ip) => {
                                packet.push(4);
                                packet.extend_from_slice(&ip.octets());
                            }
                        }
                        packet.extend_from_slice(&target.port().to_be_bytes());
                        packet.extend_from_slice(&data[..n]);
                        let _ = local.send_to(&packet, from);
                        flow.last = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return false,
                }
            }
            flow.last.elapsed() < IDLE
        });
        let mut pollfds = Vec::with_capacity(flows.len() + 2);
        pollfds.push(libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        pollfds.push(libc::pollfd {
            fd: local.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        for flow in flows.values() {
            pollfds.push(libc::pollfd {
                fd: flow.socket.raw_handle(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 1000) };
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_and_socks_interfaces_must_match_before_listening() {
        for (resolver_iface, socks_iface) in [(Some(1), Some(2)), (None, Some(1)), (Some(1), None)]
        {
            let resolver = Arc::new(
                TinyResolver::new(
                    vec!["127.0.0.1:9".parse().unwrap()],
                    resolver_iface,
                    Duration::from_secs(1),
                )
                .unwrap(),
            );
            for shape in [None, Some(ShapeLimits::default())] {
                let error = match SocksServer::start_with_shape(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::clone(&resolver),
                    socks_iface,
                    Arc::new(Audit::default()),
                    shape,
                ) {
                    Ok(_) => panic!("mismatched interfaces accepted"),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(error.to_string().contains("interfaces must match"));
            }
            assert!(SocksServer::start(
                "127.0.0.1:0".parse().unwrap(),
                resolver,
                socks_iface,
                Arc::new(Audit::default())
            )
            .is_err());
        }
    }
    fn start() -> (SocksServer, Arc<Audit>) {
        let audit = Arc::new(Audit::default());
        let resolver = Arc::new(
            TinyResolver::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                None,
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        let server = SocksServer::start(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            None,
            Arc::clone(&audit),
        )
        .unwrap();
        (server, audit)
    }
    #[test]
    fn listener_liveness_changes_when_stopped() {
        let (mut server, _) = start();
        assert!(server.is_running());
        server.stop();
        assert!(!server.is_running());
    }
    fn handshake(address: SocketAddr, command: u8, target: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut s = TcpStream::connect(address).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        s.read_exact(&mut method).unwrap();
        assert_eq!(method, [5, 0]);
        let mut req = vec![5, command, 0, 1];
        match target.ip() {
            IpAddr::V4(v) => req.extend_from_slice(&v.octets()),
            _ => panic!("IPv4 target required"),
        };
        req.extend_from_slice(&target.port().to_be_bytes());
        s.write_all(&req).unwrap();
        let mut rep = [0; 10];
        s.read_exact(&mut rep).unwrap();
        assert_eq!(&rep[..4], &[5, 0, 0, 1]);
        let bound = SocketAddr::new(
            IpAddr::from([rep[4], rep[5], rep[6], rep[7]]),
            u16::from_be_bytes([rep[8], rep[9]]),
        );
        (s, bound)
    }
    #[test]
    fn connect_preserves_half_close_and_ttl() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let echo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = Vec::new();
            s.read_to_end(&mut b).unwrap();
            assert_eq!(b, b"request");
            s.write_all(b"response").unwrap();
        });
        let (mut server, audit) = start();
        let (mut client, _) = handshake(server.address, 1, dest);
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        server.stop();
        echo.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.active_clients(), 0);
    }
    fn start_shaped() -> (SocksServer, Arc<Audit>) {
        let audit = Arc::new(Audit::default());
        let resolver = Arc::new(
            TinyResolver::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                None,
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        let server = SocksServer::start_with_shape(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            None,
            Arc::clone(&audit),
            Some(ShapeLimits::default()),
        )
        .unwrap();
        (server, audit)
    }
    fn client_hello(body_len: usize) -> Vec<u8> {
        let mut message = Vec::with_capacity(4 + body_len);
        message.push(1);
        message.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        for i in 0..body_len {
            message.push((i % 251) as u8);
        }
        message
    }
    fn handshake_record(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![22, 3, 1];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }
    /// Split shaped bytes back into record payloads until `message_len` bytes
    /// are collected. Return the payload, the record count, and the largest
    /// payload. The bytes after the records are the unshaped tail.
    fn reassemble(bytes: &[u8], message_len: usize) -> (Vec<u8>, usize, usize, usize) {
        let mut offset = 0;
        let mut payload = Vec::new();
        let mut records = 0;
        let mut largest = 0;
        while payload.len() < message_len {
            assert!(bytes.len() - offset >= 5, "a record header is present");
            let header = &bytes[offset..offset + 5];
            assert_eq!(header[0], 22, "a shaped record is a handshake record");
            assert_eq!(header[1], 3);
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            assert!(bytes.len() - offset - 5 >= len);
            payload.extend_from_slice(&bytes[offset + 5..offset + 5 + len]);
            largest = largest.max(len);
            offset += 5 + len;
            records += 1;
        }
        (payload, records, largest, offset)
    }
    #[test]
    fn shape_mode_reframes_the_first_client_hello_and_keeps_every_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let message = client_hello(300);
        let expected = message.clone();
        let tail = b"later bytes".to_vec();
        let expected_tail = tail.clone();
        let echo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            s.read_to_end(&mut bytes).unwrap();
            let (payload, records, largest, offset) = reassemble(&bytes, expected.len());
            assert_eq!(payload, expected, "handshake bytes are identical");
            assert!(records > 1, "the ClientHello spans many records");
            assert!(largest <= 8, "no shaped record payload is larger than 8");
            assert_eq!(
                &bytes[offset..],
                &expected_tail[..],
                "later bytes are unchanged"
            );
            s.write_all(b"response").unwrap();
        });
        let (mut server, audit) = start_shaped();
        let (mut client, _) = handshake(server.address, 1, dest);
        let mut input = handshake_record(&message);
        input.extend_from_slice(&tail);
        client.write_all(&input).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        server.stop();
        echo.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.active_clients(), 0);
    }
    #[test]
    fn an_incomplete_client_hello_is_flushed_unchanged_on_half_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let message = client_hello(300);
        let input = handshake_record(&message);
        let partial = input[..40].to_vec();
        let expected = partial.clone();
        let echo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            s.read_to_end(&mut bytes).unwrap();
            assert_eq!(
                bytes, expected,
                "a ClientHello cut short by EOF arrives once, unchanged"
            );
            s.write_all(b"response").unwrap();
        });
        let (mut server, audit) = start_shaped();
        let (mut client, _) = handshake(server.address, 1, dest);
        client.write_all(&partial).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        server.stop();
        echo.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.active_clients(), 0);
    }

    /// Force a reset on close, so the peer sees a sink error rather than a
    /// quiet FIN.
    fn abort_stream(stream: &TcpStream) {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt SO_LINGER");
    }

    #[test]
    fn shape_mode_forwards_short_requests_before_a_half_close() {
        // A one to four byte request that waits for a reply must not be held.
        let (mut server, audit) = start_shaped();
        for len in 1..=4 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let dest = listener.local_addr().unwrap();
            let request = b"PING"[..len].to_vec();
            let expected = request.clone();
            let reply = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut got = vec![0u8; expected.len()];
                s.read_exact(&mut got).unwrap();
                assert_eq!(got, expected);
                s.write_all(&got).unwrap();
            });
            let (mut client, _) = handshake(server.address, 1, dest);
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            client.write_all(&request).unwrap();
            let mut response = vec![0u8; request.len()];
            client.read_exact(&mut response).unwrap();
            assert_eq!(response, request, "a {len} byte request is not held");
            let _ = client.shutdown(Shutdown::Both);
            reply.join().unwrap();
        }
        server.stop();
        assert_eq!(audit.snapshot(), (4, 0));
        assert_eq!(server.active_clients(), 0);
    }

    #[test]
    fn shape_mode_reassembles_a_header_split_across_writes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let message = client_hello(300);
        let expected = message.clone();
        let tail = b"after the hello".to_vec();
        let expected_tail = tail.clone();
        let echo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut bytes = Vec::new();
            s.read_to_end(&mut bytes).unwrap();
            let (payload, _, _, offset) = reassemble(&bytes, expected.len());
            assert_eq!(payload, expected);
            assert_eq!(&bytes[offset..], &expected_tail[..]);
            s.write_all(b"response").unwrap();
        });
        let (mut server, audit) = start_shaped();
        let (mut client, _) = handshake(server.address, 1, dest);
        let mut input = handshake_record(&message);
        input.extend_from_slice(&tail);
        client.set_nodelay(true).unwrap();
        for part in [
            &input[..1],
            &input[1..2],
            &input[2..3],
            &input[3..5],
            &input[5..6],
            &input[6..],
        ] {
            client.write_all(part).unwrap();
            thread::sleep(Duration::from_millis(10));
        }
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        server.stop();
        echo.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.active_clients(), 0);
    }

    #[test]
    fn shape_mode_closes_cleanly_on_an_immediate_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let echo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut bytes = Vec::new();
            s.read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty(), "no byte is invented at EOF");
            s.write_all(b"ok").unwrap();
        });
        let (mut server, audit) = start_shaped();
        let (mut client, _) = handshake(server.address, 1, dest);
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"ok");
        server.stop();
        echo.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.active_clients(), 0);
    }

    #[test]
    fn shape_mode_closes_when_the_destination_write_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let closer = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut first = [0u8; 1];
            let _ = s.read(&mut first);
            abort_stream(&s);
            drop(s);
        });
        let (mut server, audit) = start_shaped();
        let (mut client, _) = handshake(server.address, 1, dest);
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let message = client_hello(16_380);
        let input = handshake_record(&message);
        let _ = client.write_all(&input);
        let mut buffer = [0u8; 32];
        match client.read(&mut buffer) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) => {}
            other => panic!("the shaped flow must close after a sink failure: {other:?}"),
        }
        let _ = client.shutdown(Shutdown::Both);
        server.stop();
        closer.join().unwrap();
        assert_eq!(server.active_clients(), 0);
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn shape_off_keeps_a_client_hello_byte_for_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        let message = client_hello(120);
        let mut input = handshake_record(&message);
        input.extend_from_slice(b"tail");
        let expected = input.clone();
        let echo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = Vec::new();
            s.read_to_end(&mut b).unwrap();
            assert_eq!(b, expected);
            s.write_all(b"ok").unwrap();
        });
        let (mut server, audit) = start();
        let (mut client, _) = handshake(server.address, 1, dest);
        client.write_all(&input).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"ok");
        server.stop();
        echo.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[test]
    fn shape_start_rejects_invalid_limits() {
        let resolver = Arc::new(
            TinyResolver::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                None,
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        let limits = ShapeLimits {
            max_chunk: 0,
            ..ShapeLimits::default()
        };
        assert!(SocksServer::start_with_shape(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            None,
            Arc::new(Audit::default()),
            Some(limits),
        )
        .is_err());
    }
    #[test]
    fn udp_associate_uses_one_audited_socket_per_target() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = echo.local_addr().unwrap();
        let task = thread::spawn(move || {
            let mut b = [0; 20];
            for _ in 0..2 {
                let (n, peer) = echo.recv_from(&mut b).unwrap();
                echo.send_to(&b[..n], peer).unwrap();
            }
        });
        let (mut server, audit) = start();
        let (control, bound) = handshake(server.address, 3, "0.0.0.0:0".parse().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let rogue = UdpSocket::bind("127.0.0.1:0").unwrap();
        rogue.send_to(b"invalid", bound).unwrap();
        let mut req = vec![0, 0, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&dest.port().to_be_bytes());
        req.extend_from_slice(b"hello");
        for _ in 0..2 {
            udp.send_to(&req, bound).unwrap();
            let mut b = [0; 100];
            let (n, _) = udp.recv_from(&mut b).unwrap();
            assert_eq!(&b[n - 5..n], b"hello");
        }
        assert_eq!(server.shared.udp_active.load(Ordering::Acquire), 1);
        drop(control);
        server.stop();
        task.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.shared.udp_active.load(Ordering::Acquire), 0);
    }
    #[test]
    fn mapped_tcp_and_udp_use_audited_ipv4_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let tcp = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            stream.write_all(&byte).unwrap();
        });
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = echo.local_addr().unwrap().port();
        let task = thread::spawn(move || {
            let mut data = [0; 8];
            for _ in 0..2 {
                let (n, peer) = echo.recv_from(&mut data).unwrap();
                echo.send_to(&data[..n], peer).unwrap();
            }
        });
        let (mut server, audit) = start();
        let mut client = TcpStream::connect(server.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).unwrap();
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(&mapped.octets());
        request.extend_from_slice(&tcp_port.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response[..4], &[5, 0, 0, 1]);
        client.write_all(b"x").unwrap();
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        drop(client);
        tcp.join().unwrap();
        let (control, bound) = handshake(server.address, 3, "0.0.0.0:0".parse().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut request = vec![0, 0, 0, 4];
        request.extend_from_slice(&mapped.octets());
        request.extend_from_slice(&udp_port.to_be_bytes());
        request.extend_from_slice(b"hello");
        udp.send_to(&request, bound).unwrap();
        let mut response = [0; 100];
        let (n, _) = udp.recv_from(&mut response).unwrap();
        assert_eq!(&response[..4], &[0, 0, 0, 1]);
        assert_eq!(&response[n - 5..n], b"hello");
        let mut ipv4_request = vec![0, 0, 0, 1, 127, 0, 0, 1];
        ipv4_request.extend_from_slice(&udp_port.to_be_bytes());
        ipv4_request.extend_from_slice(b"hello");
        udp.send_to(&ipv4_request, bound).unwrap();
        udp.recv_from(&mut response).unwrap();
        assert_eq!(server.shared.udp_active.load(Ordering::Acquire), 2);
        drop(control);
        task.join().unwrap();
        server.stop();
        assert_eq!(audit.snapshot(), (3, 0));
    }
    #[test]
    fn mapped_aaaa_domain_targets_use_ipv4_for_tcp_and_udp() {
        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let dns_addr = dns.local_addr().unwrap();
        let dns_task = thread::spawn(move || {
            for _ in 0..3 {
                let mut buf = [0; 512];
                let (n, peer) = dns.recv_from(&mut buf).unwrap();
                let mut reply = buf[..n].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                if u16::from_be_bytes([buf[n - 4], buf[n - 3]]) == QTYPE_AAAA {
                    reply[7] = 1;
                    reply.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                    reply.extend_from_slice(&Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
                }
                dns.send_to(&reply, peer).unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let tcp = thread::spawn(move || {
            drop(listener.accept().unwrap());
        });
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = echo.local_addr().unwrap().port();
        let task = thread::spawn(move || {
            let mut b = [0; 8];
            let (n, peer) = echo.recv_from(&mut b).unwrap();
            echo.send_to(&b[..n], peer).unwrap();
        });
        let audit = Arc::new(Audit::default());
        let resolver =
            Arc::new(TinyResolver::new(vec![dns_addr], None, Duration::from_secs(1)).unwrap());
        let mut server = SocksServer::start(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            None,
            Arc::clone(&audit),
        )
        .unwrap();
        let mut client = TcpStream::connect(server.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).unwrap();
        let mut request = vec![5, 1, 0, 3, 6];
        request.extend_from_slice(b"x.test");
        request.extend_from_slice(&tcp_port.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response[..4], &[5, 0, 0, 1]);
        drop(client);
        tcp.join().unwrap();
        let (control, bound) = handshake(server.address, 3, "0.0.0.0:0".parse().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut request = vec![0, 0, 0, 3, 6];
        request.extend_from_slice(b"x.test");
        request.extend_from_slice(&udp_port.to_be_bytes());
        request.extend_from_slice(b"hello");
        udp.send_to(&request, bound).unwrap();
        let mut response = [0; 100];
        let (n, _) = udp.recv_from(&mut response).unwrap();
        assert_eq!(&response[..4], &[0, 0, 0, 1]);
        assert_eq!(&response[n - 5..n], b"hello");
        drop(control);
        task.join().unwrap();
        dns_task.join().unwrap();
        server.stop();
        assert_eq!(audit.snapshot(), (5, 0));
    }
    #[test]
    fn refuses_non_loopback_listener() {
        let resolver = Arc::new(
            TinyResolver::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                None,
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        assert!(SocksServer::start(
            "0.0.0.0:0".parse().unwrap(),
            resolver,
            None,
            Arc::new(Audit::default())
        )
        .is_err());
    }
    #[test]
    fn unpinned_egress_is_loopback_only() {
        assert!(outer_egress_allowed(Some(4), "192.0.2.1".parse().unwrap()));
        assert!(outer_egress_allowed(None, IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(outer_egress_allowed(None, IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!outer_egress_allowed(None, "192.0.2.1".parse().unwrap()));
    }
    #[test]
    fn unpinned_connect_to_a_non_loopback_target_opens_no_socket() {
        let (mut server, audit) = start();
        let mut client = TcpStream::connect(server.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [5, 0]);
        // TEST-NET-1 is never a local destination. The guard runs before any
        // socket call, so the connection attempt cannot leave the machine.
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&[192, 0, 2, 1]);
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 2, 0, 1]);
        assert_eq!(audit.snapshot(), (0, 0));
        server.stop();
    }
    #[test]
    fn global_udp_limit_releases_permits() {
        let active = Arc::new(AtomicUsize::new(LIMIT_TOTAL_UDP_FLOWS - 1));
        let permit = reserve_udp(&active).unwrap();
        assert!(reserve_udp(&active).is_none());
        drop(permit);
        assert_eq!(active.load(Ordering::Acquire), LIMIT_TOTAL_UDP_FLOWS - 1);
    }
    #[test]
    fn stop_cancels_dns_lookup() {
        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let resolver = Arc::new(
            TinyResolver::new(
                vec![dns.local_addr().unwrap()],
                None,
                Duration::from_secs(10),
            )
            .unwrap(),
        );
        let mut server = SocksServer::start(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            None,
            Arc::new(Audit::default()),
        )
        .unwrap();
        let mut client = TcpStream::connect(server.address).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).unwrap();
        let mut req = vec![5, 1, 0, 3, 10];
        req.extend_from_slice(b"never.test");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).unwrap();
        let mut data = [0; 512];
        let _ = dns.recv_from(&mut data).unwrap();
        let start = Instant::now();
        server.stop();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(server.active_clients(), 0);
    }
    #[test]
    fn ipv6_connect_and_udp_work_from_ipv4_local_client() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let tcp = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut b = [0; 1];
            stream.read_exact(&mut b).unwrap();
            stream.write_all(&b).unwrap();
        });
        let echo = UdpSocket::bind("[::1]:0").unwrap();
        let udp_port = echo.local_addr().unwrap().port();
        let task = thread::spawn(move || {
            let mut b = [0; 10];
            let (n, peer) = echo.recv_from(&mut b).unwrap();
            echo.send_to(&b[..n], peer).unwrap();
        });
        let (mut server, audit) = start();
        let mut client = TcpStream::connect(server.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).unwrap();
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&tcp_port.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0; 22];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response[..4], &[5, 0, 0, 4]);
        client.write_all(b"x").unwrap();
        let mut result = [0; 1];
        client.read_exact(&mut result).unwrap();
        assert_eq!(&result, b"x");
        drop(client);
        tcp.join().unwrap();
        let (control, bound) = handshake(server.address, 3, "0.0.0.0:0".parse().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut request = vec![0, 0, 0, 4];
        request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&udp_port.to_be_bytes());
        request.extend_from_slice(b"hello");
        udp.send_to(&request, bound).unwrap();
        let mut reply = [0; 100];
        let (n, _) = udp.recv_from(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[0, 0, 0, 4]);
        assert_eq!(&reply[n - 5..n], b"hello");
        drop(control);
        task.join().unwrap();
        server.stop();
        assert_eq!(audit.snapshot(), (2, 0));
    }
}
