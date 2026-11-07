//! Create every outer socket with a TTL audit and interface binding.
pub use crate::normalized_udp::NormalizedUdpSocket;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const OUTER_TTL: i32 = 65;

fn reject_mapped(ip: IpAddr) -> io::Result<()> {
    if matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4-mapped IPv6 addresses must be passed as IPv4",
        ));
    }
    Ok(())
}

#[derive(Default)]
pub struct Audit {
    pub outer_sockets: AtomicU64,
    pub ttl_bad: AtomicU64,
}

impl Audit {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.outer_sockets.load(Ordering::Relaxed),
            self.ttl_bad.load(Ordering::Relaxed),
        )
    }
}

pub fn interface_index(name: &str) -> io::Result<u32> {
    if let Ok(index) = name.parse::<u32>() {
        if index != 0 {
            return Ok(index);
        }
    }
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

fn set_int(fd: RawFd, level: i32, option: i32, value: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &value as *const _ as *const libc::c_void,
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn new_socket(v6: bool, kind: i32, iface: Option<u32>, audit: &Audit) -> io::Result<OwnedFd> {
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    #[cfg(target_os = "linux")]
    let socket_kind = kind | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let socket_kind = kind;
    let raw = unsafe { libc::socket(family, socket_kind, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Darwin has no atomic SOCK_CLOEXEC. Set the flag before publishing the
    // descriptor; a concurrent process spawn can still race this operation.
    #[cfg(not(target_os = "linux"))]
    {
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TTL)
    };
    set_int(raw, level, opt, OUTER_TTL)?;
    if let Some(index) = iface {
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface index must be nonzero",
            ));
        }
        #[cfg(target_os = "macos")]
        set_int(raw, level, if v6 { 125 } else { 25 }, index as i32)?;
        #[cfg(target_os = "linux")]
        {
            let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
            if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
                return Err(io::Error::last_os_error());
            }
            let len = unsafe { libc::strlen(name.as_ptr()) + 1 };
            if unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name.as_ptr().cast(),
                    len as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "interface pinning is unavailable",
        ));
    }
    let mut ttl: i32 = 0;
    let mut size = mem::size_of::<i32>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            raw,
            level,
            opt,
            &mut ttl as *mut _ as *mut libc::c_void,
            &mut size,
        )
    };
    audit.outer_sockets.fetch_add(1, Ordering::Relaxed);
    if rc != 0 || ttl != OUTER_TTL {
        audit.ttl_bad.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::other("outer socket TTL audit failed"));
    }
    Ok(fd)
}

// Return true for an immediate connection and false when it is in progress.
fn connect_raw(raw: RawFd, addr: SocketAddr) -> io::Result<bool> {
    let rc = match addr {
        SocketAddr::V4(a) => {
            let mut s: libc::sockaddr_in = unsafe { mem::zeroed() };
            s.sin_family = libc::AF_INET as _;
            #[cfg(target_os = "macos")]
            {
                s.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            }
            s.sin_port = a.port().to_be();
            s.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(a.ip().octets()),
            };
            unsafe {
                libc::connect(
                    raw,
                    (&s as *const libc::sockaddr_in).cast(),
                    mem::size_of_val(&s) as _,
                )
            }
        }
        SocketAddr::V6(a) => {
            let mut s: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            s.sin6_family = libc::AF_INET6 as _;
            #[cfg(target_os = "macos")]
            {
                s.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            s.sin6_port = a.port().to_be();
            s.sin6_flowinfo = a.flowinfo();
            s.sin6_scope_id = a.scope_id();
            s.sin6_addr = libc::in6_addr {
                s6_addr: a.ip().octets(),
            };
            unsafe {
                libc::connect(
                    raw,
                    (&s as *const libc::sockaddr_in6).cast(),
                    mem::size_of_val(&s) as _,
                )
            }
        }
    };
    if rc == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EINPROGRESS) || e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Start a nonblocking connection to a numeric address. Check SO_ERROR after
/// the socket becomes writable. An in-progress connection is not an error.
/// IPv4-mapped IPv6 addresses are rejected; pass the IPv4 address instead.
pub fn tcp_start(addr: SocketAddr, iface: Option<u32>, audit: &Audit) -> io::Result<TcpStream> {
    crate::normalized_udp::validate_destination(addr)?;
    let fd = new_socket(addr.is_ipv6(), libc::SOCK_STREAM, iface, audit)?;
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    connect_raw(raw, addr)?;
    Ok(TcpStream::from(fd))
}

/// Connect to a numeric address. Hostname resolution is never used.
/// IPv4-mapped IPv6 addresses are rejected; pass the IPv4 address instead.
pub fn tcp_connect(
    addr: SocketAddr,
    iface: Option<u32>,
    audit: &Audit,
    timeout: Duration,
) -> io::Result<TcpStream> {
    tcp_connect_cancellable(addr, iface, audit, timeout, None)
}

/// Connect with a deadline and an optional cancellation flag.
/// Check both again before returning a connected stream.
pub fn tcp_connect_cancellable(
    addr: SocketAddr,
    iface: Option<u32>,
    audit: &Audit,
    timeout: Duration,
    stopped: Option<&AtomicBool>,
) -> io::Result<TcpStream> {
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "timeout must be positive",
        ));
    }
    if stopped.is_some_and(|s| s.load(Ordering::Acquire)) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "connection cancelled",
        ));
    }
    crate::normalized_udp::validate_destination(addr)?;
    let started = Instant::now();
    let fd = new_socket(addr.is_ipv6(), libc::SOCK_STREAM, iface, audit)?;
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if !connect_raw(raw, addr)? {
        let mut poll = libc::pollfd {
            fd: raw,
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            let left = crate::connect_deadline::remaining(started, timeout, stopped)?;
            let interval = if stopped.is_some() {
                left.min(Duration::from_millis(200))
            } else {
                left
            };
            let millis = interval.as_millis().min(i32::MAX as u128).max(1) as i32;
            let n = unsafe { libc::poll(&mut poll, 1, millis) };
            if n > 0 {
                crate::connect_deadline::remaining(started, timeout, stopped)?;
                break;
            }
            if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
        let mut error: i32 = 0;
        let mut len = mem::size_of_val(&error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
    }
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    crate::connect_deadline::remaining(started, timeout, stopped)?;
    Ok(TcpStream::from(fd))
}

/// Create an unconnected normalized datagram socket for a numeric address family.
/// IPv4-mapped IPv6 addresses are rejected; pass the IPv4 address instead.
pub fn udp_socket(
    ip: IpAddr,
    iface: Option<u32>,
    audit: &Audit,
) -> io::Result<NormalizedUdpSocket> {
    reject_mapped(ip)?;
    let fd = new_socket(ip.is_ipv6(), libc::SOCK_DGRAM, iface, audit)?;
    Ok(NormalizedUdpSocket::new(UdpSocket::from(fd), ip.is_ipv6()))
}

/// Bounded TCP keepalive values for a normalized outer socket.
///
/// The kernel sends the first probe after `idle` seconds. It sends one probe
/// every `interval` seconds. It closes the connection after `count` probes
/// with no answer. Values are whole seconds.
///
/// The Linux kernel accepts idle and interval in 1..=32767 seconds and count
/// in 1..=127. This type rejects values outside those ranges. It also rejects
/// a configured dead-peer age above five minutes. A smaller age can detect a
/// dead peer sooner. It also sends more probe traffic. Kernel scheduling and
/// network behavior can change the actual detection time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpKeepalive {
    idle_secs: u16,
    interval_secs: u16,
    count: u8,
}

/// The largest idle or interval value that the Linux kernel accepts.
const MAX_KEEPALIVE_SECS: u64 = 32767;
/// The largest probe count that the Linux kernel accepts.
const MAX_KEEPALIVE_COUNT: u32 = 127;

impl TcpKeepalive {
    /// Match the source device app: 60 seconds idle, 10 seconds interval, and
    /// 3 probes. A dead peer is normally detected in about 90 seconds.
    pub const SOURCE_DEVICE: Self = Self {
        idle_secs: 60,
        interval_secs: 10,
        count: 3,
    };

    /// A dead peer must be detected within five minutes.
    pub const MAX_DEAD_PEER_AGE: Duration = Duration::from_secs(300);

    /// Create a bounded keepalive setting.
    ///
    /// Returns `io::ErrorKind::InvalidInput` for a zero value, a value with
    /// sub-second precision, a value above the kernel limit, or a dead-peer
    /// age above [`Self::MAX_DEAD_PEER_AGE`].
    pub fn new(idle: Duration, interval: Duration, count: u32) -> io::Result<Self> {
        let idle_secs = keepalive_secs(idle, "idle")?;
        let interval_secs = keepalive_secs(interval, "interval")?;
        if !(1..=MAX_KEEPALIVE_COUNT).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tcp keepalive count must be in 1..={MAX_KEEPALIVE_COUNT}"),
            ));
        }
        let age = u64::from(idle_secs) + u64::from(interval_secs) * u64::from(count);
        if age > Self::MAX_DEAD_PEER_AGE.as_secs() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tcp keepalive dead-peer age must not exceed {} seconds",
                    Self::MAX_DEAD_PEER_AGE.as_secs()
                ),
            ));
        }
        Ok(Self {
            idle_secs,
            interval_secs,
            count: count as u8,
        })
    }

    /// The time without data before the first probe.
    pub fn idle(&self) -> Duration {
        Duration::from_secs(u64::from(self.idle_secs))
    }

    /// The time between probes.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.interval_secs))
    }

    /// The number of unanswered probes before the kernel closes the socket.
    pub fn count(&self) -> u32 {
        u32::from(self.count)
    }

    /// The longest time from the last data to a closed connection.
    pub fn dead_peer_age(&self) -> Duration {
        Duration::from_secs(
            u64::from(self.idle_secs) + u64::from(self.interval_secs) * u64::from(self.count),
        )
    }
}

fn keepalive_secs(value: Duration, name: &str) -> io::Result<u16> {
    let secs = value.as_secs();
    if value.subsec_nanos() != 0 || !(1..=MAX_KEEPALIVE_SECS).contains(&secs) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tcp keepalive {name} must be whole seconds in 1..={MAX_KEEPALIVE_SECS}"),
        ));
    }
    Ok(secs as u16)
}

#[cfg(target_os = "macos")]
const KEEPALIVE_IDLE_OPTION: i32 = libc::TCP_KEEPALIVE;
#[cfg(target_os = "linux")]
const KEEPALIVE_IDLE_OPTION: i32 = libc::TCP_KEEPIDLE;

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_int(fd: RawFd, level: i32, option: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut size = mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut size,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

/// Enable TCP keepalive on an existing TCP outer socket and verify the kernel
/// values.
///
/// Call this after `tcp_start` or `tcp_connect` returns a stream. This helper
/// does not create a socket. It does not change the TTL, the interface pin, or
/// the audit counters. The socket helpers do not call it. An uncalled helper
/// does not change a live flow.
///
/// This helper supports macOS and Linux. It returns the kernel error when a
/// socket option fails. If the read-back values differ, it disables
/// `SO_KEEPALIVE` and returns `io::ErrorKind::Other`. A failed option set can
/// leave earlier keepalive values on the socket.
///
/// The platform options are `IPPROTO_TCP`/`TCP_KEEPALIVE` on macOS and
/// `IPPROTO_TCP`/`TCP_KEEPIDLE` on Linux. Both platforms use `TCP_KEEPINTVL`
/// and `TCP_KEEPCNT` for the interval and count. Each value is a C `int` in
/// seconds, except the probe count. Darwin returns the nonzero
/// `SO_KEEPALIVE` option bit (8) on read-back. Linux returns 1.
///
/// Keepalive probes are kernel traffic. They do not count as application
/// data. They do not extend an application idle timeout.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn set_tcp_keepalive(stream: &TcpStream, keepalive: TcpKeepalive) -> io::Result<()> {
    set_tcp_keepalive_fd(stream.as_raw_fd(), keepalive)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn set_tcp_keepalive_fd(fd: RawFd, keepalive: TcpKeepalive) -> io::Result<()> {
    let idle = i32::from(keepalive.idle_secs);
    let interval = i32::from(keepalive.interval_secs);
    let count = i32::from(keepalive.count);
    // Set the tunables before the enable. If a tunable fails, keepalive stays
    // off unless the caller enabled it before this call.
    set_int(fd, libc::IPPROTO_TCP, KEEPALIVE_IDLE_OPTION, idle)?;
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, interval)?;
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, count)?;
    set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    let verified = (|| {
        // Darwin returns the SO_KEEPALIVE option bit (8) when it is set.
        // Linux returns 1. Treat any nonzero value as enabled.
        let on = get_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE)?;
        let got_idle = get_int(fd, libc::IPPROTO_TCP, KEEPALIVE_IDLE_OPTION)?;
        let got_interval = get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL)?;
        let got_count = get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT)?;
        if on != 0 && got_idle == idle && got_interval == interval && got_count == count {
            Ok(())
        } else {
            Err(io::Error::other("tcp keepalive verification failed"))
        }
    })();
    if verified.is_err() {
        let _ = set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 0);
    }
    verified
}

/// Enable TCP keepalive on an existing TCP outer socket.
///
/// This platform does not support this helper. The project supports the
/// helper on macOS and Linux only.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn set_tcp_keepalive(_stream: &TcpStream, _keepalive: TcpKeepalive) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tcp keepalive is supported on macOS and Linux only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ttl_is_audited() {
        let audit = Audit::default();
        let socket = udp_socket("127.0.0.1".parse().unwrap(), None, &audit).unwrap();
        assert_eq!(socket.ttl().unwrap(), 65);
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[test]
    fn udp_socket_is_close_on_exec() {
        let socket = udp_socket("127.0.0.1".parse().unwrap(), None, &Audit::default()).unwrap();
        let flags = unsafe { libc::fcntl(socket.raw_handle(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    #[test]
    fn invalid_interface_fails_closed() {
        let audit = Audit::default();
        assert!(udp_socket("127.0.0.1".parse().unwrap(), Some(u32::MAX), &audit).is_err());
    }
    #[test]
    fn tcp_connection_is_normalized_before_connect() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let audit = Audit::default();
        let client = tcp_connect(
            server.local_addr().unwrap(),
            None,
            &audit,
            Duration::from_secs(2),
        )
        .unwrap();
        let (_accepted, _) = server.accept().unwrap();
        assert_eq!(client.ttl().unwrap(), 65);
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[test]
    fn cancelled_connection_does_not_create_socket() {
        let audit = Audit::default();
        let stopped = AtomicBool::new(true);
        let e = tcp_connect_cancellable(
            "127.0.0.1:9".parse().unwrap(),
            None,
            &audit,
            Duration::from_secs(1),
            Some(&stopped),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        assert_eq!(audit.snapshot(), (0, 0));
    }
    #[test]
    fn ipv6_sockets_are_audited() {
        let server = std::net::TcpListener::bind("[::1]:0").unwrap();
        let audit = Audit::default();
        let client = tcp_connect(
            server.local_addr().unwrap(),
            None,
            &audit,
            Duration::from_secs(2),
        )
        .unwrap();
        let (_accepted, _) = server.accept().unwrap();
        let udp = udp_socket("::1".parse().unwrap(), None, &audit).unwrap();
        for fd in [client.as_raw_fd(), udp.raw_handle()] {
            let mut hops: i32 = 0;
            let mut size = mem::size_of::<i32>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_UNICAST_HOPS,
                    (&mut hops as *mut i32).cast(),
                    &mut size,
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(hops, 65);
        }
        assert_eq!(audit.snapshot(), (2, 0));
    }
    #[test]
    fn tcp_start_is_nonblocking_and_audited_for_both_families() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let server = std::net::TcpListener::bind(address).unwrap();
            let audit = Audit::default();
            let mut client = tcp_start(server.local_addr().unwrap(), None, &audit).unwrap();
            let flags = unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFL) };
            assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
            let mut event = libc::pollfd {
                fd: client.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            assert!(unsafe { libc::poll(&mut event, 1, 2000) } > 0);
            assert!(client.take_error().unwrap().is_none());
            let (mut peer, _) = server.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            use std::io::{Read, Write};
            client.write_all(b"ok").unwrap();
            let mut b = [0; 2];
            peer.read_exact(&mut b).unwrap();
            assert_eq!(&b, b"ok");
            assert_eq!(audit.snapshot(), (1, 0));
        }
    }
    #[test]
    fn keepalive_defaults_match_the_source_device() {
        let keepalive = TcpKeepalive::SOURCE_DEVICE;
        assert_eq!(keepalive.idle(), Duration::from_secs(60));
        assert_eq!(keepalive.interval(), Duration::from_secs(10));
        assert_eq!(keepalive.count(), 3);
        assert_eq!(keepalive.dead_peer_age(), Duration::from_secs(90));
        let boundary =
            TcpKeepalive::new(Duration::from_secs(299), Duration::from_secs(1), 1).unwrap();
        assert_eq!(boundary.dead_peer_age(), TcpKeepalive::MAX_DEAD_PEER_AGE);
    }
    #[test]
    fn keepalive_rejects_unbounded_or_invalid_values() {
        let cases = [
            (Duration::ZERO, Duration::from_secs(10), 3),
            (Duration::from_secs(60), Duration::ZERO, 3),
            (Duration::from_millis(60_500), Duration::from_secs(10), 3),
            (Duration::from_secs(32_768), Duration::from_secs(10), 3),
            (Duration::from_secs(60), Duration::from_secs(32_768), 3),
            (Duration::from_secs(60), Duration::from_secs(10), 0),
            (Duration::from_secs(60), Duration::from_secs(10), 128),
            (Duration::from_secs(300), Duration::from_secs(1), 1),
        ];
        for (idle, interval, count) in cases {
            let error = TcpKeepalive::new(idle, interval, count).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn keepalive_is_set_and_verified_on_normalized_loopback_sockets() {
        let custom = TcpKeepalive::new(Duration::from_secs(5), Duration::from_secs(2), 4).unwrap();
        for (address, keepalive) in [
            ("127.0.0.1:0", custom),
            ("[::1]:0", TcpKeepalive::SOURCE_DEVICE),
        ] {
            let server = std::net::TcpListener::bind(address).unwrap();
            let audit = Audit::default();
            let client = tcp_connect(
                server.local_addr().unwrap(),
                None,
                &audit,
                Duration::from_secs(2),
            )
            .unwrap();
            let (_accepted, _) = server.accept().unwrap();
            set_tcp_keepalive(&client, keepalive).unwrap();
            let fd = client.as_raw_fd();
            let idle = i32::try_from(keepalive.idle().as_secs()).unwrap();
            let interval = i32::try_from(keepalive.interval().as_secs()).unwrap();
            let count = i32::try_from(keepalive.count()).unwrap();
            assert_ne!(
                get_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
                0
            );
            assert_eq!(
                get_int(fd, libc::IPPROTO_TCP, KEEPALIVE_IDLE_OPTION).unwrap(),
                idle
            );
            assert_eq!(
                get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL).unwrap(),
                interval
            );
            assert_eq!(
                get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT).unwrap(),
                count
            );
            let ttl = if server.local_addr().unwrap().is_ipv4() {
                i32::try_from(client.ttl().unwrap()).unwrap()
            } else {
                get_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS).unwrap()
            };
            assert_eq!(ttl, OUTER_TTL);
            assert_eq!(audit.snapshot(), (1, 0));
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn keepalive_is_set_before_a_started_connection_completes() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let audit = Audit::default();
        let client = tcp_start(server.local_addr().unwrap(), None, &audit).unwrap();
        set_tcp_keepalive(&client, TcpKeepalive::SOURCE_DEVICE).unwrap();
        let fd = client.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
        assert_ne!(
            get_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            0
        );
        assert_eq!(
            get_int(fd, libc::IPPROTO_TCP, KEEPALIVE_IDLE_OPTION).unwrap(),
            60
        );
        assert_eq!(
            get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL).unwrap(),
            10
        );
        assert_eq!(
            get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT).unwrap(),
            3
        );
        let (_peer, _) = server.accept().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn keepalive_reports_a_non_tcp_socket_error() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = set_tcp_keepalive_fd(udp.as_raw_fd(), TcpKeepalive::SOURCE_DEVICE).unwrap_err();
        assert!(
            error.raw_os_error().is_some(),
            "expected an OS socket error, got {error}"
        );
    }
}
