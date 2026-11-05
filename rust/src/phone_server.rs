//! Loopback SOCKS5 adapter for the authenticated phone proxy.
use crate::{
    normalization::{self, Audit},
    phone::{self, PhoneProxy},
};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_CLIENTS: usize = 128;
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest time one write may make no progress before the flow closes.
const WRITE_STALL: Duration = Duration::from_secs(30);

struct Shared {
    stopped: AtomicBool,
    active: AtomicUsize,
    next: AtomicU64,
    clients: Mutex<HashMap<u64, TcpStream>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    phone: Arc<PhoneProxy>,
    audit: Arc<Audit>,
}

/// A loopback listener. Stop joins all client handlers.
pub struct PhoneServer {
    pub address: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl PhoneServer {
    pub fn start(
        address: SocketAddr,
        phone: Arc<PhoneProxy>,
        audit: Arc<Audit>,
    ) -> io::Result<Self> {
        Self::start_with_options(address, phone, audit, false)
    }
    /// Permit an unpinned outer socket only for diagnostics and loopback tests.
    pub fn start_with_options(
        address: SocketAddr,
        phone: Arc<PhoneProxy>,
        audit: Arc<Audit>,
        allow_unpinned: bool,
    ) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "phone listener must use loopback",
            ));
        }
        if phone.iface.is_none() && !allow_unpinned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "phone interface is required",
            ));
        }
        if phone.address.port() == 0
            || phone.timeout.is_zero()
            || phone.username.is_empty()
            || phone.username.len() > 255
            || phone.token.is_empty()
            || phone.token.len() > 255
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid phone configuration",
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
            phone,
            audit,
        });
        let state = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("phone-accept".into())
            .spawn(move || {
                while !state.stopped.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            if state.stopped.load(Ordering::Acquire) {
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            if state.active.fetch_add(1, Ordering::AcqRel) >= MAX_CLIENTS {
                                state.active.fetch_sub(1, Ordering::AcqRel);
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            if client.set_nonblocking(true).is_err() {
                                state.active.fetch_sub(1, Ordering::AcqRel);
                                continue;
                            }
                            let id = state.next.fetch_add(1, Ordering::Relaxed);
                            let copy = match client.try_clone() {
                                Ok(v) => v,
                                Err(_) => {
                                    state.active.fetch_sub(1, Ordering::AcqRel);
                                    continue;
                                }
                            };
                            state.clients.lock().unwrap().insert(id, copy);
                            let worker = Arc::clone(&state);
                            match thread::Builder::new().name("phone-flow".into()).spawn(
                                move || {
                                    let _ = serve_client(client, &worker);
                                    worker.clients.lock().unwrap().remove(&id);
                                    worker.active.fetch_sub(1, Ordering::AcqRel);
                                },
                            ) {
                                Ok(handle) => {
                                    let mut threads = state.threads.lock().unwrap();
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
                                    state.clients.lock().unwrap().remove(&id);
                                    state.active.fetch_sub(1, Ordering::AcqRel);
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
    pub fn active_clients(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }
    /// Return false when the listener thread has ended.
    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }
    pub fn stop(&mut self) {
        self.shared.stopped.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        for stream in self.shared.clients.lock().unwrap().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let handles = std::mem::take(&mut *self.shared.threads.lock().unwrap());
        for handle in handles {
            let _ = handle.join();
        }
    }
}
impl Drop for PhoneServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
/// Turn on TCP keepalive for the source device socket.
///
/// Keepalive is not application traffic. It lets the kernel detect a peer that
/// is gone while a flow is silent. The relay does not depend on it for
/// correctness: a socket error or a stop still ends the flow.
fn set_keepalive(stream: &TcpStream) -> io::Result<()> {
    normalization::set_tcp_keepalive(stream, normalization::TcpKeepalive::SOURCE_DEVICE)
}
fn wait(stream: &TcpStream, events: i16, deadline: Instant, state: &Shared) -> io::Result<()> {
    loop {
        if state.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "phone adapter stopped",
            ));
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "phone adapter setup timed out")
            })?;
        let ms = left.min(Duration::from_millis(100)).as_millis().max(1) as i32;
        let mut p = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut p, 1, ms) };
        if result < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if result > 0 {
            if p.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"));
            }
            // Read/write obtains the precise error, and can consume remaining data on HUP.
            return Ok(());
        }
    }
}
fn read_exact(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    state: &Shared,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        if state.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "phone adapter stopped",
            ));
        }
        match stream.read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream, libc::POLLIN, deadline, state)?
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn write_all(
    stream: &mut TcpStream,
    buf: &[u8],
    deadline: Instant,
    state: &Shared,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        if state.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "phone adapter stopped",
            ));
        }
        match stream.write(&buf[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "connection closed",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream, libc::POLLOUT, deadline, state)?
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn reply(client: &mut TcpStream, code: u8, deadline: Instant, state: &Shared) -> io::Result<()> {
    write_all(client, &[5, code, 0, 1, 0, 0, 0, 0, 0, 0], deadline, state)
}
/// Map one local setup error to a SOCKS5 reply code.
///
/// Only a source device authentication rejection is code 2 (not allowed).
/// Every other local setup error is code 1 (general failure). A local socket
/// error is not an answer about the destination. The caller forwards a source
/// device reply code unchanged. The reply holds no credential.
fn setup_reply_code(error: &io::Error) -> u8 {
    if phone::auth_rejection(error).is_some() {
        2
    } else {
        1
    }
}
fn serve_client(mut client: TcpStream, state: &Arc<Shared>) -> io::Result<()> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let mut greeting = [0; 2];
    read_exact(&mut client, &mut greeting, deadline, state)?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(invalid("invalid SOCKS greeting"));
    }
    let mut methods = vec![0; greeting[1] as usize];
    read_exact(&mut client, &mut methods, deadline, state)?;
    if !methods.contains(&0) {
        write_all(&mut client, &[5, 255], deadline, state)?;
        return Err(invalid("no supported method"));
    }
    write_all(&mut client, &[5, 0], deadline, state)?;
    let mut head = [0; 4];
    read_exact(&mut client, &mut head, deadline, state)?;
    if head[0] != 5 || head[2] != 0 {
        return Err(invalid("invalid SOCKS request"));
    }
    let mut target = vec![5, 1, 0, head[3]];
    let len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0; 1];
            read_exact(&mut client, &mut n, deadline, state)?;
            if n[0] == 0 {
                reply(&mut client, 8, deadline, state)?;
                return Err(invalid("empty domain"));
            }
            target.push(n[0]);
            n[0] as usize
        }
        _ => {
            reply(&mut client, 8, deadline, state)?;
            return Err(invalid("unsupported address type"));
        }
    };
    let offset = target.len();
    target.resize(offset + len + 2, 0);
    read_exact(&mut client, &mut target[offset..], deadline, state)?;
    if head[1] != 1 {
        reply(&mut client, 7, deadline, state)?;
        return Err(invalid("unsupported SOCKS command"));
    }
    if head[3] == 3
        && (!target[offset..offset + len].is_ascii() || target[offset..offset + len].contains(&0))
    {
        reply(&mut client, 8, deadline, state)?;
        return Err(invalid("invalid domain"));
    }
    if target[target.len() - 2..] == [0, 0] {
        reply(&mut client, 1, deadline, state)?;
        return Err(invalid("invalid destination port"));
    }
    let phone_deadline = Instant::now() + state.phone.timeout;
    let mut outer =
        match normalization::tcp_start(state.phone.address, state.phone.iface, &state.audit) {
            Ok(socket) => socket,
            Err(e) => {
                let _ = reply(&mut client, setup_reply_code(&e), deadline, state);
                return Err(e);
            }
        };
    // Keep the source device reply code, so the local client sees the same
    // result. A deadline must not become a local refusal.
    let mut source_code = None;
    let setup = (|| -> io::Result<()> {
        wait(&outer, libc::POLLOUT, phone_deadline, state)?;
        if let Some(e) = outer.take_error()? {
            return Err(e);
        }
        write_all(&mut outer, &[5, 1, 2], phone_deadline, state)?;
        let mut response = [0; 2];
        read_exact(&mut outer, &mut response, phone_deadline, state)?;
        if response != [5, 2] {
            return Err(phone::rejected_method_error(
                io::ErrorKind::PermissionDenied,
            ));
        }
        let user = state.phone.username.as_bytes();
        let pass = state.phone.token.as_bytes();
        let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
        auth.extend_from_slice(&[1, user.len() as u8]);
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        write_all(&mut outer, &auth, phone_deadline, state)?;
        read_exact(&mut outer, &mut response, phone_deadline, state)?;
        if response != [1, 0] {
            return Err(phone::rejected_credentials_error());
        }
        write_all(&mut outer, &target, phone_deadline, state)?;
        let mut header = [0; 4];
        read_exact(&mut outer, &mut header, phone_deadline, state)?;
        if header[0] != 5 || header[2] != 0 {
            return Err(invalid("invalid phone reply"));
        }
        if header[1] != 0 {
            source_code = Some(header[1]);
            return Err(phone::reply_error(header[1]));
        }
        let len = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut n = [0; 1];
                read_exact(&mut outer, &mut n, phone_deadline, state)?;
                if n[0] == 0 {
                    return Err(invalid("invalid phone reply"));
                }
                n[0] as usize
            }
            _ => return Err(invalid("invalid phone reply")),
        };
        let mut tail = vec![0; len + 2];
        read_exact(&mut outer, &mut tail, phone_deadline, state)
    })();
    if let Err(e) = setup {
        let code = source_code.unwrap_or_else(|| setup_reply_code(&e));
        let _ = reply(&mut client, code, deadline, state);
        return Err(e);
    }
    reply(&mut client, 0, deadline, state)?;
    // A silent established flow is healthy. This adapter has no application
    // idle timer. Keepalive on the source device socket lets the kernel report
    // a peer that is gone. It does not count as application traffic.
    let _ = set_keepalive(&outer);
    client.set_nonblocking(false)?;
    outer.set_nonblocking(false)?;
    let _ = client.set_nodelay(true);
    let _ = outer.set_nodelay(true);
    relay(client, outer, state)
}
/// Write all bytes and keep the flow open through a busy hotspot.
///
/// A blocking socket with a write timeout can report `WouldBlock` or `TimedOut`
/// with no bytes written. Retry from the same offset. Abort only after
/// `WRITE_STALL` without progress, or when the caller stops. The old
/// `write_all` call closed an established flow after one 2 second timeout.
fn write_all_retry<W: Write>(
    dst: &mut W,
    buf: &[u8],
    progress: &mut Instant,
    mut should_stop: impl FnMut() -> bool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        if should_stop() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "phone adapter stopped",
            ));
        }
        if progress.elapsed() > WRITE_STALL {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "phone adapter write stalled",
            ));
        }
        match dst.write(&buf[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "connection closed",
                ))
            }
            Ok(n) => {
                offset += n;
                *progress = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
/// Copy one direction of an established relay.
///
/// A read timeout is not an idle flow. Wait for the next read, and stop only
/// when the adapter stops, the source ends, or an I/O error arrives.
fn copy_direction(
    src: &mut impl Read,
    dst: &mut impl Write,
    mut should_stop: impl FnMut() -> bool,
) -> io::Result<()> {
    let mut buffer = [0u8; 32768];
    loop {
        if should_stop() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "phone adapter stopped",
            ));
        }
        match src.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                let mut progress = Instant::now();
                write_all_retry(dst, &buffer[..n], &mut progress, &mut should_stop)?;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}
fn pump(mut src: TcpStream, mut dst: TcpStream, state: Arc<Shared>) {
    let _ = src.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = dst.set_write_timeout(Some(Duration::from_secs(2)));
    let result = copy_direction(&mut src, &mut dst, || state.stopped.load(Ordering::Acquire));
    if result.is_ok() {
        // The source ended. Half-close the other side and let the return pump
        // carry the rest of the other direction.
        let _ = dst.shutdown(Shutdown::Write);
        return;
    }
    let _ = src.shutdown(Shutdown::Both);
    let _ = dst.shutdown(Shutdown::Both);
}
fn relay(client: TcpStream, outer: TcpStream, state: &Arc<Shared>) -> io::Result<()> {
    let a = client.try_clone()?;
    let b = outer.try_clone()?;
    let shared = Arc::clone(state);
    let worker = thread::Builder::new()
        .name("phone-return".into())
        .spawn(move || pump(b, a, shared))?;
    pump(client, outer, Arc::clone(state));
    let _ = worker.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    fn start(phone_address: SocketAddr) -> (PhoneServer, Arc<Audit>) {
        let phone = Arc::new(PhoneProxy {
            address: phone_address,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(5),
        });
        let audit = Arc::new(Audit::default());
        let server = PhoneServer::start_with_options(
            "127.0.0.1:0".parse().unwrap(),
            phone,
            Arc::clone(&audit),
            true,
        )
        .unwrap();
        (server, audit)
    }
    fn negotiate(address: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 0]);
        stream
    }
    #[test]
    fn socks_replies_distinguish_local_errors_from_auth_rejection() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Unsupported,
            io::ErrorKind::Other,
        ] {
            let error = io::Error::new(kind, "local detail");
            assert_eq!(
                setup_reply_code(&error),
                1,
                "a local error is not a destination answer: {kind:?}"
            );
        }
        assert_eq!(
            setup_reply_code(&phone::rejected_method_error(
                io::ErrorKind::PermissionDenied
            )),
            2
        );
        assert_eq!(setup_reply_code(&phone::rejected_credentials_error()), 2);
    }
    #[test]
    fn adapter_reports_local_source_failure_as_general_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (mut server, _audit) = start(addr);
        let mut client = negotiate(server.address);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(
            reply[1], 1,
            "a local source device error must not look like a destination refusal"
        );
        server.stop();
        assert_eq!(server.active_clients(), 0);
    }
    #[test]
    fn adapter_reports_source_device_token_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut greet = [0; 3];
            s.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [5, 1, 2]);
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            s.write_all(&[1, 1]).unwrap();
            let mut extra = [0; 1];
            assert_eq!(s.read(&mut extra).unwrap(), 0);
        });
        let (mut server, audit) = start(addr);
        let mut client = negotiate(server.address);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 2);
        server.stop();
        mock.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[test]
    fn adapter_reports_authentication_method_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut greet = [0; 3];
            s.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [5, 1, 2]);
            s.write_all(&[5, 255]).unwrap();
            let mut extra = [0; 1];
            assert_eq!(s.read(&mut extra).unwrap(), 0);
        });
        let (mut server, audit) = start(addr);
        let mut client = negotiate(server.address);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 2);
        server.stop();
        mock.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[test]
    fn remote_domain_auth_and_half_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut greet = [0; 3];
            s.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [5, 1, 2]);
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            s.write_all(&[1, 0]).unwrap();
            let mut head = [0; 5];
            s.read_exact(&mut head).unwrap();
            assert_eq!(head, [5, 1, 0, 3, 15]);
            let mut target = [0; 17];
            s.read_exact(&mut target).unwrap();
            assert_eq!(&target[..15], b"example.invalid");
            assert_eq!(&target[15..], &443u16.to_be_bytes());
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut bytes = Vec::new();
            s.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"request");
            s.write_all(b"response").unwrap();
        });
        let (mut server, audit) = start(addr);
        let mut client = negotiate(server.address);
        let mut req = vec![5, 1, 0, 3, 15];
        req.extend_from_slice(b"example.invalid");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        server.stop();
        mock.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        assert_eq!(server.active_clients(), 0);
    }
    #[test]
    fn rejects_unsupported_command_without_phone_socket() {
        let (mut server, audit) = start("127.0.0.1:9".parse().unwrap());
        let mut client = negotiate(server.address);
        client.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 7);
        server.stop();
        assert_eq!(audit.snapshot(), (0, 0));
    }
    #[test]
    fn refuses_wildcard_or_unpinned_by_default() {
        let phone = Arc::new(PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(1),
        });
        assert!(PhoneServer::start(
            "0.0.0.0:0".parse().unwrap(),
            phone.clone(),
            Arc::new(Audit::default())
        )
        .is_err());
        assert!(PhoneServer::start(
            "127.0.0.1:0".parse().unwrap(),
            phone,
            Arc::new(Audit::default())
        )
        .is_err());
    }
    #[test]
    fn stop_cancels_stalled_phone_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            tx.send(()).unwrap();
            let mut b = [0; 1];
            assert_eq!(s.read(&mut b).unwrap(), 0);
        });
        let (mut server, audit) = start(addr);
        let mut client = negotiate(server.address);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        server.stop();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(server.active_clients(), 0);
        assert_eq!(audit.snapshot(), (1, 0));
        mock.join().unwrap();
    }
    #[test]
    fn source_reply_codes_are_forwarded_unchanged() {
        // Code 6 is an expired TTL. The adapter forwards every source reply
        // code without changing it into a local refusal or timeout.
        for code in [1u8, 2, 3, 4, 5, 6, 7, 8] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let mock = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut greet = [0; 3];
                s.read_exact(&mut greet).unwrap();
                s.write_all(&[5, 2]).unwrap();
                let mut auth = [0; 6];
                s.read_exact(&mut auth).unwrap();
                s.write_all(&[1, 0]).unwrap();
                let mut req = [0; 10];
                s.read_exact(&mut req).unwrap();
                s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let mut extra = [0; 1];
                let _ = s.read(&mut extra);
            });
            let (mut server, _audit) = start(addr);
            let mut client = negotiate(server.address);
            client
                .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(reply[1], code, "source code {code} must not change");
            server.stop();
            mock.join().unwrap();
            assert_eq!(server.active_clients(), 0);
        }
    }
    #[derive(Default)]
    struct FlakyWriter {
        calls: usize,
        written: Vec<u8>,
    }
    impl Write for FlakyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls <= 2 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn write_retry_keeps_bytes_after_a_timeout() {
        let mut writer = FlakyWriter::default();
        let mut progress = Instant::now();
        write_all_retry(&mut writer, b"hello", &mut progress, || false).unwrap();
        assert_eq!(writer.written, b"hello");
        assert!(writer.calls >= 3);
    }
    struct PartialWriter {
        calls: usize,
        written: Vec<u8>,
    }
    impl Write for PartialWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            match self.calls {
                1 => {
                    let n = 2.min(buf.len());
                    self.written.extend_from_slice(&buf[..n]);
                    Ok(n)
                }
                2 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                _ => {
                    self.written.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn write_retry_resumes_after_a_partial_write() {
        let mut writer = PartialWriter {
            calls: 0,
            written: Vec::new(),
        };
        let mut progress = Instant::now();
        write_all_retry(&mut writer, b"hello", &mut progress, || false).unwrap();
        assert_eq!(writer.written, b"hello");
    }
    #[test]
    fn write_retry_aborts_after_a_long_stall() {
        let mut writer = FlakyWriter::default();
        let mut progress = Instant::now()
            .checked_sub(WRITE_STALL + Duration::from_secs(1))
            .unwrap();
        let error = write_all_retry(&mut writer, b"hello", &mut progress, || false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(writer.calls, 0);
    }
    #[test]
    fn write_retry_stops_when_the_adapter_stops() {
        let mut writer = FlakyWriter::default();
        let mut progress = Instant::now();
        let error = write_all_retry(&mut writer, b"hello", &mut progress, || true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(writer.calls, 0);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn get_socket_int(fd: std::os::fd::RawFd, level: i32, option: i32) -> io::Result<i32> {
        let mut value: i32 = 0;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                option,
                &mut value as *mut _ as *mut libc::c_void,
                &mut size,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value)
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn keepalive_is_enabled_on_the_source_device_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        set_keepalive(&client).unwrap();
        // macOS returns the option bit for SO_KEEPALIVE. Linux returns 1.
        assert_ne!(
            get_socket_int(client.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            0
        );
    }
    struct SilentThenData {
        silence: usize,
        data: &'static [u8],
        offset: usize,
    }
    impl Read for SilentThenData {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.silence > 0 {
                self.silence -= 1;
                // A blocking socket reports a read timeout as WouldBlock.
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            if self.offset < self.data.len() {
                let n = buf.len().min(self.data.len() - self.offset);
                buf[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
                self.offset += n;
                return Ok(n);
            }
            Ok(0)
        }
    }
    #[test]
    fn silent_relay_survives_many_read_timeouts() {
        // 600 empty reads stand for 10 minutes of 1 second read timeouts. The
        // old 300 second application idle timer ended this relay.
        let mut src = SilentThenData {
            silence: 600,
            data: b"late",
            offset: 0,
        };
        let mut dst = Vec::new();
        copy_direction(&mut src, &mut dst, || false).unwrap();
        assert_eq!(dst, b"late");
    }
    #[test]
    fn silent_relay_stops_when_the_adapter_stops() {
        let mut src = SilentThenData {
            silence: usize::MAX,
            data: b"",
            offset: 0,
        };
        let mut dst = Vec::new();
        let error = copy_direction(&mut src, &mut dst, || true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(dst.is_empty());
    }
    #[test]
    fn stop_ends_an_established_silent_relay() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut greet = [0; 3];
            s.read_exact(&mut greet).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            s.write_all(&[1, 0]).unwrap();
            let mut req = [0; 10];
            s.read_exact(&mut req).unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            tx.send(()).unwrap();
            // Hold the connection open with no data. The read ends when the
            // adapter stops and closes the socket.
            let mut b = [0; 1];
            let _ = s.read(&mut b);
        });
        let (mut server, _audit) = start(addr);
        let mut client = negotiate(server.address);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Wait past one read timeout. The silent relay stays open.
        thread::sleep(Duration::from_millis(1200));
        let started = Instant::now();
        server.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(server.active_clients(), 0);
        mock.join().unwrap();
    }
}
