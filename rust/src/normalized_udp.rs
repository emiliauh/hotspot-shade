use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub(crate) fn validate_destination(addr: SocketAddr) -> io::Result<()> {
    if let SocketAddr::V6(v6) = addr {
        if v6.ip().to_ipv4_mapped().is_some() || v6.scope_id() != 0 || v6.flowinfo() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 destination must not contain a mapped address, scope, or flow information",
            ));
        }
    }
    Ok(())
}

/// An audited outer UDP socket with a fixed address family.
///
/// Destination methods accept numeric addresses only and reject IPv4-mapped
/// IPv6 addresses. This type deliberately exposes neither the socket nor a raw
/// descriptor. Changing `udp_socket` to return this type breaks callers that
/// explicitly require `UdpSocket` or use its raw descriptor traits.
///
/// ```compile_fail
/// use hotspotshade::normalization::{udp_socket, Audit};
/// use std::os::fd::AsRawFd;
/// let socket = udp_socket("::1".parse().unwrap(), None, &Audit::default()).unwrap();
/// let _ = socket.as_raw_fd();
/// ```
///
/// Windows callers cannot borrow or take ownership of the raw socket either.
///
/// ```compile_fail
/// # #[cfg(not(windows))] compile_error!("Windows-only trait check");
/// # #[cfg(windows)] {
/// use hotspotshade::normalization::NormalizedUdpSocket;
/// use std::os::windows::io::AsRawSocket;
/// fn require_trait<T: AsRawSocket>() {}
/// require_trait::<NormalizedUdpSocket>();
/// # }
/// ```
/// ```compile_fail
/// # #[cfg(not(windows))] compile_error!("Windows-only trait check");
/// # #[cfg(windows)] {
/// use hotspotshade::normalization::NormalizedUdpSocket;
/// use std::os::windows::io::IntoRawSocket;
/// fn require_trait<T: IntoRawSocket>() {}
/// require_trait::<NormalizedUdpSocket>();
/// # }
/// ```
/// ```compile_fail
/// # #[cfg(not(windows))] compile_error!("Windows-only trait check");
/// # #[cfg(windows)] {
/// use hotspotshade::normalization::NormalizedUdpSocket;
/// use std::os::windows::io::AsSocket;
/// fn require_trait<T: AsSocket>() {}
/// require_trait::<NormalizedUdpSocket>();
/// # }
/// ```
/// ```compile_fail
/// # #[cfg(not(windows))] compile_error!("Windows-only trait check");
/// # #[cfg(windows)] {
/// use hotspotshade::normalization::NormalizedUdpSocket;
/// use std::os::windows::io::OwnedSocket;
/// fn require_trait<T: From<OwnedSocket>>() {}
/// require_trait::<NormalizedUdpSocket>();
/// # }
/// ```
/// ```compile_fail
/// # #[cfg(not(windows))] compile_error!("Windows-only trait check");
/// # #[cfg(windows)] {
/// use hotspotshade::normalization::NormalizedUdpSocket;
/// use std::os::windows::io::OwnedSocket;
/// fn require_trait<T: Into<OwnedSocket>>() {}
/// require_trait::<NormalizedUdpSocket>();
/// # }
/// ```
/// ```compile_fail
/// # #[cfg(not(windows))] compile_error!("Windows-only trait check");
/// # #[cfg(windows)] {
/// use hotspotshade::normalization::NormalizedUdpSocket;
/// use std::os::windows::io::FromRawSocket;
/// fn require_trait<T: FromRawSocket>() {}
/// require_trait::<NormalizedUdpSocket>();
/// # }
/// ```
pub struct NormalizedUdpSocket {
    socket: UdpSocket,
    ipv6: bool,
}

impl std::fmt::Debug for NormalizedUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NormalizedUdpSocket")
            .field("ipv6", &self.ipv6)
            .finish_non_exhaustive()
    }
}

impl NormalizedUdpSocket {
    pub(crate) fn new(socket: UdpSocket, ipv6: bool) -> Self {
        Self { socket, ipv6 }
    }

    fn validate(&self, addr: SocketAddr) -> io::Result<()> {
        validate_destination(addr)?;
        if addr.is_ipv6() != self.ipv6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP destination does not match the normalized socket family",
            ));
        }
        Ok(())
    }

    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.validate(addr)?;
        self.socket.connect(addr)
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.validate(addr)?;
        self.socket.send_to(buf, addr)
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn ttl(&self) -> io::Result<u32> {
        self.socket.ttl()
    }
    pub fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        self.socket.set_nonblocking(value)
    }
    pub fn set_read_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(value)
    }
    pub fn set_write_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(value)
    }

    #[cfg(unix)]
    pub(crate) fn raw_handle(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }
    #[cfg(windows)]
    pub(crate) fn raw_handle(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.socket.as_raw_socket()
    }
}
