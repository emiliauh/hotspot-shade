//! Authenticated connections to the optional phone proxy.
//!
//! The readiness wait uses `poll` on Unix and `select` on Windows. Both waits
//! use short slices. They check the stop flag between slices and keep one
//! deadline for the whole check. A Windows connect follows the `tcp_start`
//! contract: wait for writable or error, then read `SO_ERROR`.
use crate::normalization::{self, Audit};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const UDP_COMMAND: u8 = 0x80;
const MAX_DATAGRAM: usize = 1472;

/// Ask the readiness wait for readable data.
const READABLE: u8 = 1;
/// Ask the readiness wait for writable space.
const WRITABLE: u8 = 2;
/// Report an error, hangup, or failed connect on the socket.
const FAILED: u8 = 4;

/// A target IP address or an ASCII domain name. Domain names are sent to the phone.
pub enum Target<'a> {
    Ip(IpAddr),
    Domain(&'a str),
}

/// The phone address is numeric. The token is never used in process arguments.
pub struct PhoneProxy {
    pub address: SocketAddr,
    pub username: String,
    pub token: String,
    pub iface: Option<u32>,
    pub timeout: Duration,
}
impl Drop for PhoneProxy {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn protocol(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Map one SOCKS5 reply code from the source device to an I/O error.
///
/// The code keeps the source device answer. A caller can then report an
/// unreachable destination as unreachable, not as a refusal. Code 1 is a
/// general failure, such as a deadline that did not prove the destination
/// unreachable. Code 3 is a network unreachable. Code 4 is a host unreachable.
/// Code 5 is a refusal. Code 6 is an expired TTL. Codes 2, 7, and 8 are policy,
/// command, or address denials.
pub(crate) fn reply_error(code: u8) -> io::Error {
    let (kind, message) = match code {
        2 => (
            io::ErrorKind::PermissionDenied,
            "phone proxy denied the connection",
        ),
        3 => (
            io::ErrorKind::NetworkUnreachable,
            "phone proxy reported network unreachable",
        ),
        4 => (
            io::ErrorKind::HostUnreachable,
            "phone proxy reported host unreachable",
        ),
        5 => (
            io::ErrorKind::ConnectionRefused,
            "phone proxy refused the connection",
        ),
        6 => (io::ErrorKind::Other, "phone proxy reported an expired TTL"),
        7 => (
            io::ErrorKind::Unsupported,
            "phone proxy does not support the command",
        ),
        8 => (
            io::ErrorKind::Unsupported,
            "phone proxy does not support the address type",
        ),
        _ => (io::ErrorKind::Other, "phone proxy rejected the command"),
    };
    io::Error::new(kind, message)
}

#[derive(Debug)]
struct CredentialsRejected;

impl std::fmt::Display for CredentialsRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source device rejected credentials")
    }
}

impl std::error::Error for CredentialsRejected {}

#[derive(Debug)]
struct AuthenticationMethodRejected;

impl std::fmt::Display for AuthenticationMethodRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source device rejected the authentication method")
    }
}

impl std::error::Error for AuthenticationMethodRejected {}

/// The kind of authentication rejection from the source device.
///
/// A method mismatch is not an incorrect token. A local OS permission error is
/// neither, and it has no marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthRejection {
    Method,
    Credentials,
}

pub(crate) fn rejected_credentials_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, CredentialsRejected)
}

/// Build a method mismatch error. The caller keeps the kind that its path used
/// before, so counters and callers see no change.
pub(crate) fn rejected_method_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, AuthenticationMethodRejected)
}

/// Identify an authentication rejection without confusing it with an OS error.
pub(crate) fn auth_rejection(error: &io::Error) -> Option<AuthRejection> {
    let cause = error.get_ref()?;
    if cause.is::<AuthenticationMethodRejected>() {
        Some(AuthRejection::Method)
    } else if cause.is::<CredentialsRejected>() {
        Some(AuthRejection::Credentials)
    } else {
        None
    }
}

/// True when the source device rejects the method or token. Local socket
/// errors return false.
pub fn authentication_rejected(error: &io::Error) -> bool {
    auth_rejection(error).is_some()
}

/// True only for an incorrect source device token. A local OS permission error
/// and a method mismatch return false.
pub fn credentials_rejected(error: &io::Error) -> bool {
    auth_rejection(error) == Some(AuthRejection::Credentials)
}

fn check_deadline(deadline: Instant, cancelled: &AtomicBool) -> io::Result<Duration> {
    if cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "phone check cancelled",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "phone check timed out"))
}
#[cfg(unix)]
fn wait_socket(
    stream: &TcpStream,
    events: u8,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<u8> {
    let mut poll_events: i16 = 0;
    if events & READABLE != 0 {
        poll_events |= libc::POLLIN;
    }
    if events & WRITABLE != 0 {
        poll_events |= libc::POLLOUT;
    }
    loop {
        let remaining = check_deadline(deadline, cancelled)?;
        let millis = remaining.min(Duration::from_millis(100)).as_millis().max(1) as i32;
        let mut fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: poll_events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut fd, 1, millis) };
        if result > 0 {
            check_deadline(deadline, cancelled)?;
            if fd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "phone socket closed",
                ));
            }
            let mut ready = 0;
            if fd.revents & libc::POLLIN != 0 {
                ready |= READABLE;
            }
            if fd.revents & libc::POLLOUT != 0 {
                ready |= WRITABLE;
            }
            if fd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                ready |= FAILED;
            }
            return Ok(ready);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

/// The Winsock calls and structures that the Windows readiness wait uses.
///
/// `fd_set` holds `u_int fd_count` and 64 `SOCKET` values. `SOCKET` is
/// `UINT_PTR`, so the set is 260 bytes on x86 and 520 bytes on x64 and ARM64.
/// `timeval` uses two 32-bit `long` values on every Windows target. The static
/// assertions below reject a wrong layout at compile time.
#[cfg(windows)]
mod winsock {
    use super::{FAILED, READABLE, WRITABLE};
    use std::io;
    use std::mem;
    use std::os::windows::io::RawSocket;
    use std::ptr;

    const FD_SETSIZE: usize = 64;
    const INVALID_SOCKET: RawSocket = RawSocket::MAX;
    const SOCKET_ERROR: i32 = -1;
    /// The wait was interrupted by a signal or a console event.
    const WSAEINTR: i32 = 10004;
    /// The descriptor is not a socket. This matches the Unix `POLLNVAL` case.
    const WSAENOTSOCK: i32 = 10038;

    #[repr(C)]
    struct FdSet {
        count: u32,
        sockets: [RawSocket; FD_SETSIZE],
    }

    #[repr(C)]
    struct Timeval {
        seconds: i32,
        microseconds: i32,
    }

    const _: () = {
        if cfg!(target_arch = "x86") {
            assert!(mem::size_of::<FdSet>() == 260);
            assert!(mem::align_of::<FdSet>() == 4);
        } else {
            assert!(mem::size_of::<FdSet>() == 520);
            assert!(mem::align_of::<FdSet>() == 8);
        }
        assert!(mem::size_of::<Timeval>() == 8);
        assert!(mem::align_of::<Timeval>() == 4);
    };

    // The normalization module declares the same Winsock symbol with private,
    // layout-identical structures. The static assertions above prove both
    // layouts. The linker resolves both declarations to the same function.
    #[allow(clashing_extern_declarations)]
    #[link(name = "ws2_32")]
    extern "system" {
        fn select(
            ignored: i32,
            read: *mut FdSet,
            write: *mut FdSet,
            except: *mut FdSet,
            timeout: *const Timeval,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    impl FdSet {
        fn one(raw: RawSocket) -> Self {
            let mut set = Self {
                count: 1,
                sockets: [INVALID_SOCKET; FD_SETSIZE],
            };
            set.sockets[0] = raw;
            set
        }
    }

    /// Wait once for the requested socket state.
    ///
    /// A failed connect appears in the exception set. The caller reads
    /// `SO_ERROR` after a writable or failed result. A zero result is a slice
    /// timeout, so the caller can check the stop flag and the deadline.
    pub(super) fn wait(raw: RawSocket, events: u8, millis: u32) -> io::Result<u8> {
        {
            let mut read = FdSet::one(raw);
            let mut write = FdSet::one(raw);
            let mut except = FdSet::one(raw);
            let read_ptr = if events & READABLE != 0 {
                &mut read
            } else {
                ptr::null_mut()
            };
            let write_ptr = if events & WRITABLE != 0 {
                &mut write
            } else {
                ptr::null_mut()
            };
            // Winsock reports a failed nonblocking connect in the exception
            // set. Monitor it for every writable wait.
            let except_ptr = if events & WRITABLE != 0 {
                &mut except
            } else {
                ptr::null_mut()
            };
            let timeout = Timeval {
                seconds: (millis / 1000) as i32,
                microseconds: ((millis % 1000) * 1000) as i32,
            };
            let result = unsafe { select(0, read_ptr, write_ptr, except_ptr, &timeout) };
            if result == SOCKET_ERROR {
                let code = unsafe { WSAGetLastError() };
                if code == WSAEINTR {
                    // Let the caller recheck cancellation and the deadline.
                    return Ok(0);
                }
                if code == WSAENOTSOCK {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "phone socket closed",
                    ));
                }
                return Err(io::Error::from_raw_os_error(code));
            }
            if result == 0 {
                return Ok(0);
            }
            let mut ready = 0;
            if events & READABLE != 0 && read.count != 0 {
                ready |= READABLE;
            }
            if events & WRITABLE != 0 && write.count != 0 {
                ready |= WRITABLE;
            }
            if events & WRITABLE != 0 && except.count != 0 {
                ready |= FAILED;
            }
            Ok(ready)
        }
    }
}

#[cfg(windows)]
fn wait_socket(
    stream: &TcpStream,
    events: u8,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<u8> {
    loop {
        let remaining = check_deadline(deadline, cancelled)?;
        let millis = remaining.min(Duration::from_millis(100)).as_millis().max(1) as u32;
        let ready = winsock::wait(stream.as_raw_socket(), events, millis)?;
        if ready != 0 {
            check_deadline(deadline, cancelled)?;
            return Ok(ready);
        }
    }
}
fn write_cancel(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        check_deadline(deadline, cancelled)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "phone closed during authentication",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_socket(stream, WRITABLE, deadline, cancelled)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn read_cancel(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        check_deadline(deadline, cancelled)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "phone closed during authentication",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_socket(stream, READABLE, deadline, cancelled)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl PhoneProxy {
    fn authenticate(&self, audit: &Audit) -> io::Result<TcpStream> {
        let u = self.username.as_bytes();
        let p = self.token.as_bytes();
        if u.is_empty() || u.len() > 255 || p.is_empty() || p.len() > 255 {
            return Err(invalid("phone credentials must contain 1 to 255 bytes"));
        }
        let mut stream = normalization::tcp_connect(self.address, self.iface, audit, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(&[5, 1, 2])?;
        let mut answer = [0; 2];
        stream.read_exact(&mut answer)?;
        if answer != [5, 2] {
            return Err(rejected_method_error(io::ErrorKind::InvalidData));
        }
        let mut auth = Zeroizing::new(Vec::with_capacity(3 + u.len() + p.len()));
        auth.extend_from_slice(&[1, u.len() as u8]);
        auth.extend_from_slice(u);
        auth.push(p.len() as u8);
        auth.extend_from_slice(p);
        stream.write_all(&auth)?;
        drop(auth);
        stream.read_exact(&mut answer)?;
        if answer != [1, 0] {
            return Err(rejected_credentials_error());
        }
        Ok(stream)
    }

    pub fn check(&self, audit: &Audit) -> io::Result<()> {
        self.authenticate(audit).map(|_| ())
    }

    /// Check phone authentication with one deadline and prompt cancellation.
    pub fn check_cancellable(&self, audit: &Audit, cancelled: &AtomicBool) -> io::Result<()> {
        let u = self.username.as_bytes();
        let p = self.token.as_bytes();
        if u.is_empty() || u.len() > 255 || p.is_empty() || p.len() > 255 {
            return Err(invalid("phone credentials must contain 1 to 255 bytes"));
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| invalid("phone timeout is too large"))?;
        check_deadline(deadline, cancelled)?;
        let mut stream = normalization::tcp_start(self.address, self.iface, audit)?;
        let ready = wait_socket(&stream, WRITABLE, deadline, cancelled)?;
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        if ready & FAILED != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "phone connection failed",
            ));
        }
        write_cancel(&mut stream, &[5, 1, 2], deadline, cancelled)?;
        let mut reply = [0; 2];
        read_cancel(&mut stream, &mut reply, deadline, cancelled)?;
        if reply != [5, 2] {
            return Err(rejected_method_error(io::ErrorKind::InvalidData));
        }
        let mut auth = Zeroizing::new(Vec::with_capacity(3 + u.len() + p.len()));
        auth.extend_from_slice(&[1, u.len() as u8]);
        auth.extend_from_slice(u);
        auth.push(p.len() as u8);
        auth.extend_from_slice(p);
        write_cancel(&mut stream, &auth, deadline, cancelled)?;
        drop(auth);
        read_cancel(&mut stream, &mut reply, deadline, cancelled)?;
        if reply != [1, 0] {
            return Err(rejected_credentials_error());
        }
        check_deadline(deadline, cancelled)?;
        Ok(())
    }

    fn open(
        &self,
        target: Target<'_>,
        port: u16,
        command: u8,
        audit: &Audit,
    ) -> io::Result<TcpStream> {
        if port == 0 {
            return Err(invalid("destination port must be nonzero"));
        }
        let mut request = vec![5, command, 0];
        match target {
            Target::Ip(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Target::Ip(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            Target::Domain(name) => {
                let b = name.as_bytes();
                if b.is_empty() || b.len() > 255 || !name.is_ascii() || b.contains(&0) {
                    return Err(invalid(
                        "destination domain must be ASCII and contain 1 to 255 bytes",
                    ));
                }
                request.extend_from_slice(&[3, b.len() as u8]);
                request.extend_from_slice(b);
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        let mut stream = self.authenticate(audit)?;
        stream.write_all(&request)?;
        let mut header = [0; 4];
        stream.read_exact(&mut header)?;
        if header[0] != 5 || header[2] != 0 {
            return Err(protocol("invalid phone reply"));
        }
        if header[1] != 0 {
            return Err(reply_error(header[1]));
        }
        let size = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut len = [0];
                stream.read_exact(&mut len)?;
                if len[0] == 0 {
                    return Err(protocol("empty bound domain"));
                }
                len[0] as usize
            }
            _ => return Err(protocol("invalid phone bound address")),
        };
        let mut tail = vec![0u8; size + 2];
        stream.read_exact(&mut tail)?;
        Ok(stream)
    }

    pub fn open_tcp(&self, target: Target<'_>, port: u16, audit: &Audit) -> io::Result<TcpStream> {
        self.open(target, port, 1, audit)
    }

    /// The phone UDP extension uses a private command and one stream per flow.
    pub fn open_udp(&self, target: Target<'_>, port: u16, audit: &Audit) -> io::Result<PhoneUdp> {
        Ok(PhoneUdp {
            stream: self.open(target, port, UDP_COMMAND, audit)?,
        })
    }
}

pub struct PhoneUdp {
    pub stream: TcpStream,
}
impl PhoneUdp {
    pub fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(invalid("UDP datagram exceeds phone limit"));
        }
        self.stream
            .write_all(&(datagram.len() as u16).to_be_bytes())?;
        self.stream.write_all(datagram)
    }
    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut header = [0; 2];
        self.stream.read_exact(&mut header)?;
        let len = u16::from_be_bytes(header) as usize;
        if len > MAX_DATAGRAM {
            return Err(protocol("phone sent an oversized UDP datagram"));
        }
        let mut payload = vec![0; len];
        self.stream.read_exact(&mut payload)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn local_permission_errors_are_not_credential_rejections() {
        #[cfg(unix)]
        let codes = [libc::EACCES, libc::EPERM];
        // WSAEACCES and ERROR_ACCESS_DENIED both map to PermissionDenied.
        #[cfg(windows)]
        let codes = [10013, 5];
        for code in codes {
            let local = io::Error::from_raw_os_error(code);
            assert_eq!(local.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(auth_rejection(&local), None);
            assert!(!credentials_rejected(&local));
        }
        let rejected = rejected_credentials_error();
        assert_eq!(auth_rejection(&rejected), Some(AuthRejection::Credentials));
        assert!(credentials_rejected(&rejected));
    }

    #[test]
    fn method_rejection_is_distinct_from_incorrect_credentials() {
        let method = rejected_method_error(io::ErrorKind::PermissionDenied);
        assert_eq!(method.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(auth_rejection(&method), Some(AuthRejection::Method));
        assert!(!credentials_rejected(&method));
        let credentials = rejected_credentials_error();
        assert_eq!(credentials.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            auth_rejection(&credentials),
            Some(AuthRejection::Credentials)
        );
        assert!(credentials_rejected(&credentials));
    }

    #[test]
    fn cancellable_check_authenticates_and_audits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            stream.write_all(&[1, 0]).unwrap();
        });
        let audit = Audit::default();
        let cancelled = AtomicBool::new(false);
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        phone.check_cancellable(&audit, &cancelled).unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[test]
    fn cancellable_check_stops_a_stalled_phone() {
        use std::sync::{mpsc, Arc};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            tx.send(()).unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let audit = Arc::new(Audit::default());
        let socket_audit = audit.clone();
        let worker = thread::spawn(move || {
            let phone = PhoneProxy {
                address: addr,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(10),
            };
            phone.check_cancellable(&socket_audit, &flag)
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        cancelled.store(true, Ordering::Release);
        assert_eq!(
            worker.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(audit.snapshot(), (1, 0));
        mock.join().unwrap();
    }
    #[test]
    fn cancellable_check_with_initial_stop_does_not_open_socket() {
        let phone = PhoneProxy {
            address: "127.0.0.1:9".parse().unwrap(),
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(1),
        };
        let audit = Audit::default();
        assert_eq!(
            phone
                .check_cancellable(&audit, &AtomicBool::new(true))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(audit.snapshot(), (0, 0));
    }
    // The margins are wide on purpose. A busy CI runner can delay a thread by
    // more than 100 ms. The mock replies after 250 ms. The shared budget is 600 ms.
    #[test]
    fn cancellable_check_uses_one_timeout_for_all_steps() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            thread::sleep(Duration::from_millis(250));
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            stream.read_exact(&mut auth).unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_millis(600),
        };
        let start = Instant::now();
        let error = phone
            .check_cancellable(&Audit::default(), &AtomicBool::new(false))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
        mock.join().unwrap();
    }
    #[test]
    fn cancellable_check_rejects_a_source_device_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            stream.read_exact(&mut auth).unwrap();
            stream.write_all(&[1, 1]).unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        let audit = Audit::default();
        let error = phone
            .check_cancellable(&audit, &AtomicBool::new(false))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(credentials_rejected(&error));
        assert_eq!(auth_rejection(&error), Some(AuthRejection::Credentials));
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[test]
    fn cancellable_check_rejects_the_authentication_method() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&[5, 0xff]).unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        let audit = Audit::default();
        let error = phone
            .check_cancellable(&audit, &AtomicBool::new(false))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(auth_rejection(&error), Some(AuthRejection::Method));
        assert!(!credentials_rejected(&error));
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[test]
    fn cancellable_check_accepts_a_byte_at_a_time_mock_source() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            for byte in [5, 2] {
                stream.write_all(&[byte]).unwrap();
                thread::sleep(Duration::from_millis(20));
            }
            let mut auth = [0; 6];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            for byte in [1, 0] {
                stream.write_all(&[byte]).unwrap();
                thread::sleep(Duration::from_millis(20));
            }
        });
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        let audit = Audit::default();
        phone
            .check_cancellable(&audit, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[test]
    fn open_tcp_round_trip_sends_a_domain_without_dns_lookup() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            stream.write_all(&[1, 0]).unwrap();
            // The request holds the ASCII name. The target device must not
            // resolve it before it sends the request.
            let mut request = [0; 19];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            assert_eq!(request[4], 12);
            assert_eq!(&request[5..17], b"example.test");
            assert_eq!(&request[17..], &443u16.to_be_bytes());
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let audit = Audit::default();
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        let mut stream = phone
            .open_tcp(Target::Domain("example.test"), 443, &audit)
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
        drop(stream);
        worker.join().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[test]
    fn authenticated_udp_frames_and_audit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            s.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x01u\x02pw");
            s.write_all(&[1, 0]).unwrap();
            let mut req = [0; 10];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req[1], UDP_COMMAND);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut payload = [0; 5];
            s.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"\x00\x03abc");
            s.write_all(&[0, 0]).unwrap();
        });
        let audit = Audit::default();
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        let mut udp = phone
            .open_udp(Target::Ip("1.1.1.1".parse().unwrap()), 123, &audit)
            .unwrap();
        udp.send(b"abc").unwrap();
        assert_eq!(udp.recv().unwrap(), b"");
        assert!(udp.send(&vec![0; 1473]).is_err());
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[test]
    fn rejects_bad_token_without_sending_target() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut greeting = [0; 3];
            s.read_exact(&mut greeting).unwrap();
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 6];
            s.read_exact(&mut auth).unwrap();
            s.write_all(&[1, 1]).unwrap();
            let mut extra = [0; 1];
            assert_eq!(s.read(&mut extra).unwrap(), 0);
        });
        let audit = Audit::default();
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        let result = phone.open_tcp(Target::Domain("example.test"), 443, &audit);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(credentials_rejected(&error));
        assert_eq!(audit.snapshot(), (1, 0));
        worker.join().unwrap();
    }
    #[test]
    fn socks_reply_codes_keep_their_meaning() {
        fn kind_for(code: u8) -> io::ErrorKind {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let worker = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut greeting = [0; 3];
                s.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 2]);
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
            let phone = PhoneProxy {
                address: addr,
                username: "u".into(),
                token: "pw".into(),
                iface: None,
                timeout: Duration::from_secs(2),
            };
            let error = phone
                .open_tcp(
                    Target::Ip("1.1.1.1".parse().unwrap()),
                    443,
                    &Audit::default(),
                )
                .unwrap_err();
            worker.join().unwrap();
            error.kind()
        }
        // Unreachable, refusal, and expired TTL replies keep distinct meanings.
        assert_eq!(kind_for(2), io::ErrorKind::PermissionDenied);
        assert_eq!(kind_for(3), io::ErrorKind::NetworkUnreachable);
        assert_eq!(kind_for(4), io::ErrorKind::HostUnreachable);
        assert_eq!(kind_for(5), io::ErrorKind::ConnectionRefused);
        assert_eq!(kind_for(6), io::ErrorKind::Other);
        assert_eq!(kind_for(7), io::ErrorKind::Unsupported);
        assert_eq!(kind_for(8), io::ErrorKind::Unsupported);
        assert_eq!(kind_for(1), io::ErrorKind::Other);
    }

    #[cfg(windows)]
    #[test]
    fn windows_readiness_wait_completes_a_loopback_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let audit = Audit::default();
        let stream = normalization::tcp_start(addr, None, &audit).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let ready = wait_socket(&stream, WRITABLE, deadline, &AtomicBool::new(false)).unwrap();
        assert!(ready & WRITABLE != 0);
        assert!(stream.take_error().unwrap().is_none());
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[cfg(windows)]
    #[test]
    fn windows_readable_wait_reports_only_requested_state() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.write_all(b"x").unwrap();
        let ready = wait_socket(
            &stream,
            READABLE,
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(ready, READABLE);
    }

    #[test]
    fn ipv6_destinations_work_for_tcp_and_framed_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let ip = "2001:db8::1234".parse::<std::net::Ipv6Addr>().unwrap();
        let worker = thread::spawn(move || {
            for command in [1, UDP_COMMAND] {
                let (mut s, _) = listener.accept().unwrap();
                let mut greeting = [0; 3];
                s.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 2]);
                s.write_all(&[5, 2]).unwrap();
                let mut auth = [0; 6];
                s.read_exact(&mut auth).unwrap();
                s.write_all(&[1, 0]).unwrap();
                let mut req = [0; 22];
                s.read_exact(&mut req).unwrap();
                assert_eq!(&req[..4], &[5, command, 0, 4]);
                assert_eq!(&req[4..20], &ip.octets());
                assert_eq!(&req[20..], &443u16.to_be_bytes());
                let mut reply = vec![5, 0, 0, 4];
                reply.extend_from_slice(&ip.octets());
                reply.extend_from_slice(&0u16.to_be_bytes());
                s.write_all(&reply).unwrap();
                if command == UDP_COMMAND {
                    let mut frame = [0; 3];
                    s.read_exact(&mut frame).unwrap();
                    assert_eq!(&frame, b"\0\x01x");
                    s.write_all(&frame).unwrap();
                }
            }
        });
        let audit = Audit::default();
        let phone = PhoneProxy {
            address: addr,
            username: "u".into(),
            token: "pw".into(),
            iface: None,
            timeout: Duration::from_secs(2),
        };
        drop(
            phone
                .open_tcp(Target::Ip(IpAddr::V6(ip)), 443, &audit)
                .unwrap(),
        );
        let mut udp = phone
            .open_udp(Target::Ip(IpAddr::V6(ip)), 443, &audit)
            .unwrap();
        udp.send(b"x").unwrap();
        assert_eq!(udp.recv().unwrap(), b"x");
        worker.join().unwrap();
        assert_eq!(audit.snapshot(), (2, 0));
    }
}
