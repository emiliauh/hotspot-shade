//! A loopback SOCKS5 server with normalized outer sockets.
use crate::dns::{TinyResolver, QTYPE_A, QTYPE_AAAA};
use crate::normalization::{self, Audit};
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
}

/// Owns the loopback listener and all active handlers.
pub struct SocksServer {
    pub address: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl SocksServer {
    pub fn start(
        address: SocketAddr,
        resolver: Arc<TinyResolver>,
        iface: Option<u32>,
        audit: Arc<Audit>,
    ) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS listener must use loopback",
            ));
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
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
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

fn pump(mut src: TcpStream, mut dst: TcpStream, s: Arc<Shared>, last: Arc<Mutex<Instant>>) {
    let _ = src.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = dst.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 32768];
    loop {
        if s.stopped.load(Ordering::Acquire) || last.lock().unwrap().elapsed() > IDLE {
            break;
        }
        match src.read(&mut buf) {
            Ok(0) => {
                let _ = dst.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
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
        .spawn(move || pump(b, a, state, l))?;
    pump(client, outer, Arc::clone(s), last);
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
    socket: UdpSocket,
    last: Instant,
    _permit: UdpPermit,
}
fn udp_target(packet: &[u8], s: &Shared) -> io::Result<(SocketAddr, usize)> {
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
    Ok((SocketAddr::new(ip, port), offset))
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
                    let (target, off) = match udp_target(&data[..n], s) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if source.is_none() {
                        source = Some(from);
                    }
                    let key = (from, target);
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
                        match target.ip() {
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
                fd: flow.socket.as_raw_fd(),
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
