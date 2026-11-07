//! Create every outer socket with a TTL audit and interface binding on Windows.
//!
//! The helpers use Winsock directly. Each outer socket sets TTL 65 and, when an
//! interface index is given, pins the socket with `IP_UNICAST_IF` or
//! `IPV6_UNICAST_IF`. The IPv4 option takes the index in network byte order.
//! The IPv6 option takes the index in host byte order. A read-back audit closes
//! the socket when the TTL value is wrong.
//!
//! A nonblocking connect registers `FD_CONNECT` before the connect call and
//! waits on the Winsock event object. `WSAEnumNetworkEvents` then holds the
//! connect result for that event. This is the documented completion check, and
//! it does not depend on which `select` descriptor set reports the socket.
//!
//! The tunnel relay uses these helpers in source device proxy mode. A live
//! Windows tunnel test is still needed. The Windows CI job tests the helpers
//! on loopback.
pub use crate::normalized_udp::NormalizedUdpSocket;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, OwnedSocket, RawSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const OUTER_TTL: i32 = 65;

/// The longest slice a cancellable wait uses before it checks the stop flag.
const CANCEL_SLICE: Duration = Duration::from_millis(200);

/// The largest timeout that `WSAWaitForMultipleEvents` does not read as
/// `WSA_INFINITE`. `u32::MAX` means an infinite wait, so stay below it.
const MAX_WAIT_MILLIS: u128 = (u32::MAX - 1) as u128;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const WSA_FLAG_OVERLAPPED: u32 = 0x01;
const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
const IPPROTO_IP: i32 = 0;
const IPPROTO_IPV6: i32 = 41;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
const IP_TTL: i32 = 4;
// Windows defines IPV6_UNICAST_HOPS as 4. The Linux value is 16.
const IPV6_UNICAST_HOPS: i32 = 4;
const IP_UNICAST_IF: i32 = 31;
const IPV6_UNICAST_IF: i32 = 31;
const SOL_SOCKET: i32 = 0xffff;
const SO_ERROR: i32 = 0x1007;
const SO_KEEPALIVE: i32 = 0x0008;
/// `SIO_KEEPALIVE_VALS` is `_WSAIOW(IOC_VENDOR, 4)`.
const SIO_KEEPALIVE_VALS: u32 = 0x9800_0004;
const FIONBIO: u32 = 0x8004_667e;
// The `FD_XXX` network event bits and their `iErrorCode` array indexes.
const FD_CONNECT: i32 = 0x0010;
const FD_CONNECT_BIT: usize = 4;
const FD_MAX_EVENTS: usize = 10;
const WSA_WAIT_EVENT_0: u32 = 0;
const WSA_WAIT_TIMEOUT: u32 = 258;
const WSAEWOULDBLOCK: i32 = 10035;
const WSAEINPROGRESS: i32 = 10036;
const WSAEALREADY: i32 = 10037;
const WSAEINTR: i32 = 10004;
const INVALID_SOCKET: RawSocket = RawSocket::MAX;
const SOCKET_ERROR: i32 = -1;
const IF_NAMESIZE: usize = 256;
/// Windows interface indices are 24-bit numbers.
const MAX_INTERFACE_INDEX: u32 = 0x00ff_ffff;

// `WSADATA` has two layouts. The 64-bit layout places the socket limits and
// the vendor pointer before the text buffers. The 32-bit layout places them
// after the text buffers. The Windows header selects the layout with
// `_WIN64`. Both layouts use the default packing.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the Windows socket helper supports x86, x86_64, and aarch64 only");

#[cfg(not(target_arch = "x86"))]
#[repr(C)]
struct WsaData {
    version: u16,
    high_version: u16,
    max_sockets: u16,
    max_udp_datagram: u16,
    vendor_info: *mut std::ffi::c_char,
    description: [std::ffi::c_char; 257],
    system_status: [std::ffi::c_char; 129],
}

#[cfg(target_arch = "x86")]
#[repr(C)]
struct WsaData {
    version: u16,
    high_version: u16,
    description: [std::ffi::c_char; 257],
    system_status: [std::ffi::c_char; 129],
    max_sockets: u16,
    max_udp_datagram: u16,
    vendor_info: *mut std::ffi::c_char,
}

// The field order is not enough. Check the total size and the alignment
// against the Windows header so a wrong layout cannot compile.
const _: () = {
    if cfg!(target_arch = "x86") {
        assert!(mem::size_of::<WsaData>() == 400);
        assert!(mem::align_of::<WsaData>() == 4);
    } else {
        assert!(mem::size_of::<WsaData>() == 408);
        assert!(mem::align_of::<WsaData>() == 8);
    }
};

#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
struct FdSet {
    count: u32,
    sockets: [RawSocket; 64],
}

#[repr(C)]
struct Timeval {
    seconds: i32,
    microseconds: i32,
}

/// The record that `WSAEnumNetworkEvents` fills for one socket.
///
/// `network_events` holds the `FD_XXX` bits. `error_code` holds one code for
/// each bit, at the index of that bit.
#[repr(C)]
struct WsaNetworkEvents {
    network_events: i32,
    error_code: [i32; FD_MAX_EVENTS],
}

// `select` reads these structures at their exact Windows sizes.
const _: () = {
    if cfg!(target_arch = "x86") {
        assert!(mem::size_of::<FdSet>() == 260);
        assert!(mem::align_of::<FdSet>() == 4);
    } else {
        assert!(mem::size_of::<FdSet>() == 520);
        assert!(mem::align_of::<FdSet>() == 8);
    }
    assert!(mem::size_of::<Timeval>() == 8);
};

// `WSANETWORKEVENTS` holds one `long` and a fixed array of `int`. Both layouts
// are 4-byte aligned and 44 bytes long.
const _: () = {
    assert!(mem::size_of::<WsaNetworkEvents>() == 44);
    assert!(mem::align_of::<WsaNetworkEvents>() == 4);
    assert!(FD_CONNECT_BIT < FD_MAX_EVENTS);
    // `FD_CONNECT` is bit 4, and the record indexes the code by that bit.
    assert!(FD_CONNECT == 1 << FD_CONNECT_BIT);
    assert!(FD_CONNECT == 0x0010 && FD_CONNECT_BIT == 4);
};

// Build a `fd_set` that holds one socket. `select` rewrites the count, so
// build a new set for each wait.
//
// The connect helper below uses event notification. The layout stays for a
// caller that waits on a `tcp_start` socket, and the tests cover it.
#[allow(dead_code)]
fn fd_set(raw: RawSocket) -> FdSet {
    let mut set = FdSet {
        count: 1,
        sockets: [INVALID_SOCKET; 64],
    };
    set.sockets[0] = raw;
    set
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
    fn WSAGetLastError() -> i32;
    fn WSASocketW(
        family: i32,
        kind: i32,
        protocol: i32,
        protocol_info: *mut std::ffi::c_void,
        group: u32,
        flags: u32,
    ) -> RawSocket;
    fn connect(socket: RawSocket, name: *const u8, name_len: i32) -> i32;
    fn bind(socket: RawSocket, name: *const u8, name_len: i32) -> i32;
    fn listen(socket: RawSocket, backlog: i32) -> i32;
    fn setsockopt(socket: RawSocket, level: i32, option: i32, value: *const u8, length: i32)
        -> i32;
    fn getsockopt(
        socket: RawSocket,
        level: i32,
        option: i32,
        value: *mut u8,
        length: *mut i32,
    ) -> i32;
    fn WSAIoctl(
        socket: RawSocket,
        control: u32,
        input: *const u8,
        input_length: u32,
        output: *mut u8,
        output_length: u32,
        returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
        completion: *mut std::ffi::c_void,
    ) -> i32;
    fn ioctlsocket(socket: RawSocket, command: u32, argument: *mut u32) -> i32;
    // The phone module declares the same ABI with private, equivalent types.
    // Both modules assert the Winsock layouts at compile time.
    #[allow(dead_code, clashing_extern_declarations)]
    fn select(
        ignored: i32,
        read: *mut FdSet,
        write: *mut FdSet,
        except: *mut FdSet,
        timeout: *const Timeval,
    ) -> i32;
    fn WSACreateEvent() -> *mut std::ffi::c_void;
    fn WSACloseEvent(event: *mut std::ffi::c_void) -> i32;
    fn WSAEventSelect(socket: RawSocket, event: *mut std::ffi::c_void, events: i32) -> i32;
    fn WSAEnumNetworkEvents(
        socket: RawSocket,
        event: *mut std::ffi::c_void,
        out: *mut WsaNetworkEvents,
    ) -> i32;
    fn WSAWaitForMultipleEvents(
        count: u32,
        events: *const *mut std::ffi::c_void,
        wait_all: i32,
        timeout_ms: u32,
        alertable: i32,
    ) -> u32;
}

#[link(name = "iphlpapi")]
extern "system" {
    fn ConvertInterfaceAliasToLuid(alias: *const u16, luid: *mut u64) -> u32;
    fn ConvertInterfaceLuidToIndex(luid: *const u64, index: *mut u32) -> u32;
    fn if_nametoindex(name: *const u8) -> u32;
    fn if_indextoname(index: u32, name: *mut u8) -> *mut u8;
}

/// Counts outer sockets and TTL audit failures.
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

static WINSOCK: OnceLock<i32> = OnceLock::new();

fn ensure_winsock() -> io::Result<()> {
    let code = *WINSOCK.get_or_init(|| unsafe {
        let mut data: WsaData = mem::zeroed();
        WSAStartup(0x0202, &mut data)
    });
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

fn last_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// Resolve an interface name or a numeric index to a Windows interface index.
///
/// The name may be the adapter name from `if_indextoname` or the friendly
/// adapter alias. The lookup never changes network configuration.
pub fn interface_index(name: &str) -> io::Result<u32> {
    if let Ok(index) = name.parse::<u32>() {
        if index != 0 && index <= MAX_INTERFACE_INDEX {
            return Ok(index);
        }
    }
    if name.is_empty() || name.bytes().any(|b| b == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface",
        ));
    }
    ensure_winsock()?;
    let c_name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
    let index = unsafe { if_nametoindex(c_name.as_ptr().cast()) };
    if index != 0 {
        return Ok(index);
    }
    interface_alias_index(name)
}

fn interface_alias_index(alias: &str) -> io::Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = std::ffi::OsStr::new(alias)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut luid: u64 = 0;
    let status = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut index: u32 = 0;
    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if index == 0 {
        return Err(io::Error::other("interface index is zero"));
    }
    Ok(index)
}

/// Return the adapter name for an interface index. The lookup changes nothing.
pub fn interface_name(index: u32) -> io::Result<String> {
    if index == 0 || index > MAX_INTERFACE_INDEX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be a nonzero 24-bit number",
        ));
    }
    ensure_winsock()?;
    let mut buffer = [0u8; IF_NAMESIZE];
    let result = unsafe { if_indextoname(index, buffer.as_mut_ptr()) };
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "interface index not found",
        ));
    }
    let len = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8(buffer[..len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "interface name is not UTF-8"))
}

fn set_bytes(socket: RawSocket, level: i32, option: i32, value: &[u8]) -> io::Result<()> {
    let rc = unsafe { setsockopt(socket, level, option, value.as_ptr(), value.len() as i32) };
    if rc == SOCKET_ERROR {
        Err(last_wsa_error())
    } else {
        Ok(())
    }
}

fn set_int(socket: RawSocket, level: i32, option: i32, value: i32) -> io::Result<()> {
    set_bytes(socket, level, option, &value.to_ne_bytes())
}

fn get_int(socket: RawSocket, level: i32, option: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut length = mem::size_of::<i32>() as i32;
    let rc = unsafe {
        getsockopt(
            socket,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if rc == SOCKET_ERROR {
        Err(last_wsa_error())
    } else {
        checked_int_option(value, length)
    }
}

// The options read by get_int are documented as four-byte integers. This
// guards against an unexpected successful short or oversized provider result.
fn checked_int_option(value: i32, length: i32) -> io::Result<i32> {
    if length != mem::size_of::<i32>() as i32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket option returned an invalid length",
        ));
    }
    Ok(value)
}

fn set_nonblocking(socket: RawSocket, enabled: bool) -> io::Result<()> {
    let mut mode: u32 = u32::from(enabled);
    if unsafe { ioctlsocket(socket, FIONBIO, &mut mode) } == SOCKET_ERROR {
        Err(last_wsa_error())
    } else {
        Ok(())
    }
}

/// Return the `IP_UNICAST_IF` or `IPV6_UNICAST_IF` option value.
///
/// Microsoft documents a network byte order index when setting the IPv4
/// option and a host byte order index when setting the IPv6 option. A read
/// of either option returns the index in host byte order. Do not decode an
/// IPv4 read with the byte order used for the write.
fn unicast_if_value(v6: bool, index: u32) -> [u8; 4] {
    if v6 {
        index.to_ne_bytes()
    } else {
        index.to_be_bytes()
    }
}

fn new_socket(v6: bool, kind: i32, iface: Option<u32>, audit: &Audit) -> io::Result<OwnedSocket> {
    if kind != SOCK_STREAM && kind != SOCK_DGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported socket type",
        ));
    }
    ensure_winsock()?;
    let family = if v6 { AF_INET6 } else { AF_INET };
    let protocol = if kind == SOCK_STREAM {
        IPPROTO_TCP
    } else {
        IPPROTO_UDP
    };
    // Set non-inheritance at creation so another thread cannot inherit the
    // outer socket between creation and a separate handle-flag update.
    let raw = unsafe {
        WSASocketW(
            family,
            kind,
            protocol,
            std::ptr::null_mut(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if raw == INVALID_SOCKET {
        return Err(last_wsa_error());
    }
    // Own the socket before any operation that can fail.
    let owned = unsafe { OwnedSocket::from_raw_socket(raw) };
    let (level, ttl_option) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_HOPS)
    } else {
        (IPPROTO_IP, IP_TTL)
    };
    set_int(raw, level, ttl_option, OUTER_TTL)?;
    if let Some(index) = iface {
        if index == 0 || index > MAX_INTERFACE_INDEX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface index must be a nonzero 24-bit number",
            ));
        }
        // Windows expects a network byte order index for IPv4 and a host byte
        // order index for IPv6. The two options differ on purpose.
        let option = if v6 {
            (IPPROTO_IPV6, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP, IP_UNICAST_IF)
        };
        set_bytes(raw, option.0, option.1, &unicast_if_value(v6, index))?;
    }
    let ttl = match get_int(raw, level, ttl_option) {
        Ok(value) => value,
        Err(error) => {
            audit.outer_sockets.fetch_add(1, Ordering::Relaxed);
            audit.ttl_bad.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
    };
    audit.outer_sockets.fetch_add(1, Ordering::Relaxed);
    if ttl != OUTER_TTL {
        audit.ttl_bad.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::other("outer socket TTL audit failed"));
    }
    Ok(owned)
}

// Return true for an immediate connection and false when it is in progress.
fn connect_raw(raw: RawSocket, addr: SocketAddr) -> io::Result<bool> {
    let rc = match addr {
        SocketAddr::V4(a) => {
            let name = SockaddrIn {
                family: AF_INET as u16,
                port: a.port().to_be(),
                addr: u32::from_ne_bytes(a.ip().octets()),
                zero: [0; 8],
            };
            unsafe {
                connect(
                    raw,
                    (&name as *const SockaddrIn).cast(),
                    mem::size_of_val(&name) as i32,
                )
            }
        }
        SocketAddr::V6(a) => {
            let name = SockaddrIn6 {
                family: AF_INET6 as u16,
                port: a.port().to_be(),
                flowinfo: a.flowinfo(),
                addr: a.ip().octets(),
                scope_id: a.scope_id(),
            };
            unsafe {
                connect(
                    raw,
                    (&name as *const SockaddrIn6).cast(),
                    mem::size_of_val(&name) as i32,
                )
            }
        }
    };
    if rc == 0 {
        return Ok(true);
    }
    let error = last_wsa_error();
    match error.raw_os_error() {
        Some(WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY) => Ok(false),
        _ => Err(error),
    }
}

/// The state of one connect attempt after a wait.
#[derive(Debug, PartialEq, Eq)]
enum ConnectState {
    Connected,
    Failed(i32),
    Pending,
}

/// Classify one `WSAEnumNetworkEvents` record for a connect wait.
///
/// Winsock sets `FD_CONNECT` when the attempt completes or fails, and records
/// the reason in the error code for that bit. A set bit with a zero code means
/// the connection completed. A set bit with a nonzero code means the attempt
/// failed. A clear bit means the wait must continue.
///
/// `so_error` is a fallback for a signaled event with an empty record. It never
/// proves success, because a zero `SO_ERROR` also describes a connect that is
/// still in progress.
fn classify_connect(network_events: i32, connect_error: i32, so_error: i32) -> ConnectState {
    if network_events & FD_CONNECT != 0 {
        return if connect_error != 0 {
            ConnectState::Failed(connect_error)
        } else {
            ConnectState::Connected
        };
    }
    if so_error != 0 {
        return ConnectState::Failed(so_error);
    }
    ConnectState::Pending
}

/// Resolve one signaled event record to a connect state.
///
/// The `FD_CONNECT` bit holds the result, so the `SO_ERROR` read is skipped in
/// that case. A signaled event with an empty record reads `SO_ERROR` once. A
/// failed read is an error. An empty record with a zero `SO_ERROR` is
/// `Pending`. Both cases fail closed.
fn resolve_connect(
    network_events: i32,
    connect_error: i32,
    read_so_error: impl FnOnce() -> io::Result<i32>,
) -> io::Result<ConnectState> {
    if network_events & FD_CONNECT != 0 {
        return Ok(classify_connect(network_events, connect_error, 0));
    }
    let so_error = read_so_error()?;
    Ok(classify_connect(network_events, connect_error, so_error))
}

/// Turn a classified state into the wait result.
///
/// A pending attempt is not a success. The wait fails closed with
/// `InvalidData`.
fn connect_result(state: ConnectState) -> io::Result<()> {
    match state {
        ConnectState::Connected => Ok(()),
        ConnectState::Failed(code) => Err(io::Error::from_raw_os_error(code)),
        ConnectState::Pending => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "connect event has no completion result",
        )),
    }
}

/// The Winsock calls that manage one connect event.
///
/// This trait is the test seam. A test uses a fake to record the cleanup order
/// and to inject a failure. Production uses `WinsockEvents`.
trait EventApi {
    fn create_event(&self) -> io::Result<*mut std::ffi::c_void>;
    fn select_event(
        &self,
        socket: RawSocket,
        event: *mut std::ffi::c_void,
        events: i32,
    ) -> io::Result<()>;
    fn close_event(&self, event: *mut std::ffi::c_void);
    fn close_socket(&self, socket: OwnedSocket);
}

struct WinsockEvents;

static WINSOCK_EVENTS: WinsockEvents = WinsockEvents;

impl EventApi for WinsockEvents {
    fn create_event(&self) -> io::Result<*mut std::ffi::c_void> {
        let event = unsafe { WSACreateEvent() };
        if event.is_null() {
            Err(last_wsa_error())
        } else {
            Ok(event)
        }
    }

    fn select_event(
        &self,
        socket: RawSocket,
        event: *mut std::ffi::c_void,
        events: i32,
    ) -> io::Result<()> {
        if unsafe { WSAEventSelect(socket, event, events) } == SOCKET_ERROR {
            Err(last_wsa_error())
        } else {
            Ok(())
        }
    }

    fn close_event(&self, event: *mut std::ffi::c_void) {
        // A failed close leaves a stale handle. No retry can help.
        let _ = unsafe { WSACloseEvent(event) };
    }

    fn close_socket(&self, socket: OwnedSocket) {
        // The owned handle closes exactly once, here.
        drop(socket);
    }
}

/// Owns the `FD_CONNECT` event handle and, until it is handed over, the socket.
///
/// The guard cancels the event association before it closes the event handle.
/// When the cancellation fails, it closes the socket first. Closing the socket
/// removes every association. The guard never touches the raw handle after that
/// close, so a reused socket handle cannot be disassociated by mistake.
///
/// Winsock keeps the socket nonblocking after it removes the association, so
/// the caller restores the blocking mode after `disarm` succeeds.
struct ConnectEvent<'a> {
    socket: Option<OwnedSocket>,
    event: Option<*mut std::ffi::c_void>,
    api: &'a dyn EventApi,
}

impl<'a> ConnectEvent<'a> {
    /// Create the event and register `FD_CONNECT` on the socket.
    ///
    /// Register before the connect call. An association that starts after the
    /// connect can miss `FD_CONNECT`, but the result stays in `SO_ERROR`.
    fn register(socket: OwnedSocket, api: &'a dyn EventApi) -> io::Result<Self> {
        let raw = socket.as_raw_socket();
        let event = match api.create_event() {
            Ok(event) => event,
            Err(error) => {
                api.close_socket(socket);
                return Err(error);
            }
        };
        // The guard owns both handles from here.
        let guard = Self {
            socket: Some(socket),
            event: Some(event),
            api,
        };
        if let Err(error) = api.select_event(raw, event, FD_CONNECT) {
            // Drop cancels a partial association and closes both handles.
            drop(guard);
            return Err(error);
        }
        Ok(guard)
    }

    /// Return the raw socket while this guard owns it.
    fn raw_socket(&self) -> io::Result<RawSocket> {
        self.socket
            .as_ref()
            .map(OwnedSocket::as_raw_socket)
            .ok_or_else(|| io::Error::other("connect socket is already closed"))
    }

    /// Return the event handle while the association is active.
    fn event_handle(&self) -> io::Result<*mut std::ffi::c_void> {
        self.event
            .ok_or_else(|| io::Error::other("connect event is already closed"))
    }

    /// Cancel the event association and close the event handle.
    ///
    /// On failure the socket can still hold the association. The method closes
    /// the socket first, so the event is never closed under a live association.
    /// The guard then owns no handle, and this method reports the failure.
    ///
    /// A second call does nothing. The socket stays owned unless the
    /// cancellation fails.
    fn disarm(&mut self) -> io::Result<()> {
        let Some(event) = self.event else {
            return Ok(());
        };
        let Ok(raw) = self.raw_socket() else {
            // No socket is left to disassociate. A closed socket holds no
            // association, so the event can close alone.
            self.event = None;
            self.api.close_event(event);
            return Ok(());
        };
        self.event = None;
        match self.api.select_event(raw, std::ptr::null_mut(), 0) {
            Ok(()) => {
                self.api.close_event(event);
                Ok(())
            }
            Err(error) => {
                // Close the socket before the event. The raw handle is dead
                // after this call, so no later path can reuse it.
                self.close_socket();
                self.api.close_event(event);
                Err(error)
            }
        }
    }

    /// Close the owned socket once. Later calls do nothing.
    fn close_socket(&mut self) {
        if let Some(socket) = self.socket.take() {
            self.api.close_socket(socket);
        }
    }

    /// Hand the connected socket to a `TcpStream`.
    ///
    /// Call this only after `disarm` succeeds and the blocking mode is
    /// restored. The guard refuses to hand over a socket that still holds the
    /// event association.
    fn into_stream(mut self) -> io::Result<TcpStream> {
        if self.event.is_some() {
            return Err(io::Error::other(
                "connect event is still associated with the socket",
            ));
        }
        let socket = self
            .socket
            .take()
            .ok_or_else(|| io::Error::other("connect socket is already closed"))?;
        Ok(TcpStream::from(socket))
    }
}

impl Drop for ConnectEvent<'_> {
    fn drop(&mut self) {
        let _ = self.disarm();
        self.close_socket();
    }
}

/// Wait for the `FD_CONNECT` record and return the connect result.
///
/// The wait checks the stop flag between slices. The deadline covers the whole
/// wait, and an expired deadline is always `TimedOut`.
fn wait_for_connect(
    raw: RawSocket,
    event: *mut std::ffi::c_void,
    started: Instant,
    timeout: Duration,
    stopped: Option<&AtomicBool>,
) -> io::Result<()> {
    loop {
        let left = crate::connect_deadline::remaining(started, timeout, stopped)?;
        let slice = if stopped.is_some() {
            left.min(CANCEL_SLICE)
        } else {
            left
        };
        let millis = slice.as_millis().clamp(1, MAX_WAIT_MILLIS) as u32;
        let wait = unsafe { WSAWaitForMultipleEvents(1, &event, 1, millis, 0) };
        #[cfg(test)]
        eprintln!(
            "connect event wait result={wait} elapsed_ms={}",
            started.elapsed().as_millis()
        );
        if wait == WSA_WAIT_TIMEOUT {
            continue;
        }
        if wait != WSA_WAIT_EVENT_0 {
            let error = last_wsa_error();
            if error.raw_os_error() == Some(WSAEINTR) {
                continue;
            }
            return Err(error);
        }
        crate::connect_deadline::remaining(started, timeout, stopped)?;
        let mut record: WsaNetworkEvents = unsafe { mem::zeroed() };
        if unsafe { WSAEnumNetworkEvents(raw, event, &mut record) } == SOCKET_ERROR {
            return Err(last_wsa_error());
        }
        #[cfg(test)]
        eprintln!(
            "connect event mask={:#x} error={}",
            record.network_events, record.error_code[FD_CONNECT_BIT]
        );
        // Read `SO_ERROR` only after the record. A read of `SO_ERROR` clears
        // the status, and the record holds the result of this connect.
        let state = resolve_connect(
            record.network_events,
            record.error_code[FD_CONNECT_BIT],
            || get_int(raw, SOL_SOCKET, SO_ERROR),
        )?;
        // The event record is one-shot and was cleared by enumeration. An
        // empty record cannot prove a connection or promise another signal.
        // Return an error instead of waiting on a possibly lost completion.
        return connect_result(state);
    }
}

fn reject_mapped(ip: IpAddr) -> io::Result<()> {
    if matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4-mapped IPv6 addresses must be passed as IPv4",
        ));
    }
    Ok(())
}

/// Start a nonblocking connection to a numeric address.
/// IPv4-mapped IPv6 addresses are rejected; pass the IPv4 address instead.
///
/// The returned stream is nonblocking in every case. An in-progress connection
/// is not an error, so the stream can be pending. The caller must wait until
/// the socket reports writable or failed, and then read `SO_ERROR` before it
/// uses the stream. A zero `SO_ERROR` from a still pending attempt does not
/// prove success. Do not register `FD_CONNECT` after this call. The attempt can
/// finish before the registration and the event can be missed.
///
/// Use `tcp_connect` or `tcp_connect_cancellable` when the caller needs a
/// blocking stream or a deadline.
pub fn tcp_start(addr: SocketAddr, iface: Option<u32>, audit: &Audit) -> io::Result<TcpStream> {
    crate::normalized_udp::validate_destination(addr)?;
    let owned = new_socket(addr.is_ipv6(), SOCK_STREAM, iface, audit)?;
    let raw = owned.as_raw_socket();
    set_nonblocking(raw, true)?;
    connect_raw(raw, addr)?;
    let raw = owned.into_raw_socket();
    Ok(unsafe { TcpStream::from_raw_socket(raw) })
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
    let owned = new_socket(addr.is_ipv6(), SOCK_STREAM, iface, audit)?;
    // The guard owns the socket for the whole attempt. Every early return
    // closes the event and the socket in a safe order.
    let mut event = ConnectEvent::register(owned, &WINSOCK_EVENTS)?;
    let raw = event.raw_socket()?;
    set_nonblocking(raw, true)?;
    // Registration happened before the connect call. A late association can
    // miss the event, so the order matters.
    if !connect_raw(raw, addr)? {
        wait_for_connect(raw, event.event_handle()?, started, timeout, stopped)?;
    }
    // Remove the association before the blocking-mode change. Winsock keeps the
    // socket nonblocking while the event is associated.
    event.disarm()?;
    set_nonblocking(raw, false)?;
    crate::connect_deadline::remaining(started, timeout, stopped)?;
    event.into_stream()
}

/// Create an unconnected normalized datagram socket for a numeric address family.
/// IPv4-mapped IPv6 addresses are rejected; pass the IPv4 address instead.
pub fn udp_socket(
    ip: IpAddr,
    iface: Option<u32>,
    audit: &Audit,
) -> io::Result<NormalizedUdpSocket> {
    reject_mapped(ip)?;
    let owned = new_socket(ip.is_ipv6(), SOCK_DGRAM, iface, audit)?;
    let raw = owned.into_raw_socket();
    Ok(NormalizedUdpSocket::new(
        unsafe { UdpSocket::from_raw_socket(raw) },
        ip.is_ipv6(),
    ))
}

/// Enable TCP keepalive on an existing TCP outer socket and verify the kernel
/// value.
///
/// The Windows values are whole milliseconds. `SIO_KEEPALIVE_VALS` sets the
/// enable flag, the idle time, and the interval. Windows fixes the probe count.
/// The count is 10 on Windows 10 and later. The API cannot change it and
/// `getsockopt` cannot read it back. This helper therefore checks
/// `SO_KEEPALIVE` only. It does not create a socket and does not change the
/// outer socket TTL, the interface pin, or the audit counters.
///
/// Call this after `tcp_start` or `tcp_connect` returns a stream. The socket
/// helpers do not call it. If `WSAIoctl` fails, the helper returns the Winsock
/// error. If the read-back value is not enabled, it disables `SO_KEEPALIVE` and
/// returns `io::ErrorKind::Other`.
///
/// Keepalive probes are kernel traffic. They do not count as application data.
/// They do not extend an application idle timeout.
pub fn set_tcp_keepalive(stream: &TcpStream, keepalive: TcpKeepalive) -> io::Result<()> {
    set_tcp_keepalive_socket(stream.as_raw_socket(), keepalive)
}

/// The `tcp_keepalive` structure that `SIO_KEEPALIVE_VALS` expects. All three
/// fields are `DWORD` values. The time values are milliseconds.
#[repr(C)]
struct TcpKeepaliveVals {
    onoff: u32,
    keepalive_time_ms: u32,
    keepalive_interval_ms: u32,
}

const _: () = {
    assert!(mem::size_of::<TcpKeepaliveVals>() == 12);
    assert!(mem::align_of::<TcpKeepaliveVals>() == 4);
};

fn set_tcp_keepalive_socket(socket: RawSocket, keepalive: TcpKeepalive) -> io::Result<()> {
    ensure_winsock()?;
    let values = TcpKeepaliveVals {
        onoff: 1,
        keepalive_time_ms: keepalive.idle_ms,
        keepalive_interval_ms: keepalive.interval_ms,
    };
    let mut returned: u32 = 0;
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_KEEPALIVE_VALS,
            (&values as *const TcpKeepaliveVals).cast(),
            mem::size_of_val(&values) as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == SOCKET_ERROR {
        return Err(last_wsa_error());
    }
    let verified = get_int(socket, SOL_SOCKET, SO_KEEPALIVE).and_then(|enabled| {
        if enabled == 0 {
            Err(io::Error::other("tcp keepalive verification failed"))
        } else {
            Ok(())
        }
    });
    if verified.is_err() {
        let _ = set_int(socket, SOL_SOCKET, SO_KEEPALIVE, 0);
    }
    verified
}

/// Bounded TCP keepalive values for a normalized outer socket.
///
/// The helper sends the first probe after `idle`. It sends one probe every
/// `interval` while no answer arrives. Windows fixes the number of unanswered
/// probes. [`TcpKeepalive::FIXED_PROBE_COUNT`] is that count. The API cannot
/// change it, and a read-back cannot read it.
///
/// The constructor keeps the same shape as the macOS and Linux helper, so one
/// call site works on every platform. Windows ignores the requested `count`.
/// The constructor still checks it, and it uses the fixed probe count for the
/// dead-peer age limit. This type accepts whole milliseconds and rejects a
/// value outside 1 millisecond to 1 hour. It also rejects a computed dead-peer
/// age above five minutes.
///
/// A smaller age can detect a dead peer sooner. It also sends more probe
/// traffic. Kernel scheduling and network behavior can change the actual
/// detection time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpKeepalive {
    idle_ms: u32,
    interval_ms: u32,
    count: u8,
}

/// The largest idle or interval value that this helper accepts: one hour.
const MAX_KEEPALIVE_MS: u64 = 3_600_000;
/// The largest probe count that the shared value type accepts.
const MAX_KEEPALIVE_COUNT: u32 = 127;

impl TcpKeepalive {
    /// Match the source device app: 60 seconds idle and 10 seconds interval.
    /// The requested count is 3. Windows uses its fixed count of 10 probes.
    pub const SOURCE_DEVICE: Self = Self {
        idle_ms: 60_000,
        interval_ms: 10_000,
        count: 3,
    };

    /// A dead peer must be detected within five minutes.
    pub const MAX_DEAD_PEER_AGE: Duration = Duration::from_secs(300);

    /// The fixed number of unanswered probes on Windows 10 and later.
    pub const FIXED_PROBE_COUNT: u32 = 10;

    /// Create a bounded keepalive setting.
    ///
    /// Returns `io::ErrorKind::InvalidInput` for a zero value, a value with
    /// sub-millisecond precision, a value above the one hour limit, an invalid
    /// count, or a dead-peer age above [`Self::MAX_DEAD_PEER_AGE`]. The age uses
    /// the fixed Windows probe count.
    pub fn new(idle: Duration, interval: Duration, count: u32) -> io::Result<Self> {
        let idle_ms = keepalive_ms(idle, "idle")?;
        let interval_ms = keepalive_ms(interval, "interval")?;
        if !(1..=MAX_KEEPALIVE_COUNT).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tcp keepalive count must be in 1..={MAX_KEEPALIVE_COUNT}"),
            ));
        }
        let age_ms =
            u64::from(idle_ms) + u64::from(interval_ms) * u64::from(Self::FIXED_PROBE_COUNT);
        if age_ms > Self::MAX_DEAD_PEER_AGE.as_millis() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tcp keepalive dead-peer age must not exceed {} seconds",
                    Self::MAX_DEAD_PEER_AGE.as_secs()
                ),
            ));
        }
        Ok(Self {
            idle_ms,
            interval_ms,
            count: count as u8,
        })
    }

    /// The time without data before the first probe.
    pub fn idle(&self) -> Duration {
        Duration::from_millis(u64::from(self.idle_ms))
    }

    /// The time between probes.
    pub fn interval(&self) -> Duration {
        Duration::from_millis(u64::from(self.interval_ms))
    }

    /// The requested number of unanswered probes. Windows ignores this value.
    pub fn count(&self) -> u32 {
        u32::from(self.count)
    }

    /// The number of unanswered probes that Windows uses.
    pub fn fixed_probe_count(&self) -> u32 {
        Self::FIXED_PROBE_COUNT
    }

    /// The longest time from the last data to a closed connection on Windows.
    pub fn dead_peer_age(&self) -> Duration {
        Duration::from_millis(
            u64::from(self.idle_ms)
                + u64::from(self.interval_ms) * u64::from(Self::FIXED_PROBE_COUNT),
        )
    }
}

fn keepalive_ms(value: Duration, name: &str) -> io::Result<u32> {
    let millis = value.as_millis();
    if !value.subsec_nanos().is_multiple_of(1_000_000)
        || millis == 0
        || millis > u128::from(MAX_KEEPALIVE_MS)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tcp keepalive {name} must be whole milliseconds in 1..={MAX_KEEPALIVE_MS}"),
        ));
    }
    Ok(millis as u32)
}

/// `SO_EXCLUSIVEADDRUSE` is `~SO_REUSEADDR` in winsock2.h.
const SO_EXCLUSIVEADDRUSE: i32 = !0x0004;
const SOMAXCONN: i32 = 0x7fff_ffff;

/// Bind the local control listener on `127.0.0.1` with `SO_EXCLUSIVEADDRUSE`.
///
/// This is not an outer socket. It sets no TTL and no interface pin, and it
/// carries no tethered traffic. Without the option, another socket of the same
/// user can bind the same address and port with `SO_REUSEADDR` and receive new
/// loopback connections, including a request that carries the per-launch
/// bearer secret. The socket is created non-inheritable, so a child process
/// cannot keep the port open.
pub fn exclusive_loopback_listener(
    address: std::net::SocketAddrV4,
) -> io::Result<std::net::TcpListener> {
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the control listener must use a loopback address",
        ));
    }
    ensure_winsock()?;
    let raw = unsafe {
        WSASocketW(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            std::ptr::null_mut(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if raw == INVALID_SOCKET {
        return Err(last_wsa_error());
    }
    // Own the socket before any operation that can fail.
    let owned = unsafe { OwnedSocket::from_raw_socket(raw) };
    set_int(raw, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)?;
    let name = SockaddrIn {
        family: AF_INET as u16,
        port: address.port().to_be(),
        addr: u32::from_ne_bytes(address.ip().octets()),
        zero: [0; 8],
    };
    let rc = unsafe {
        bind(
            raw,
            (&name as *const SockaddrIn).cast(),
            mem::size_of_val(&name) as i32,
        )
    };
    if rc != 0 {
        return Err(last_wsa_error());
    }
    if unsafe { listen(raw, SOMAXCONN) } != 0 {
        return Err(last_wsa_error());
    }
    Ok(unsafe { std::net::TcpListener::from_raw_socket(owned.into_raw_socket()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_option_read_rejects_incomplete_or_invalid_lengths() {
        assert_eq!(checked_int_option(65, 4).unwrap(), 65);
        for length in [-1, 0, 1, 2, 3, 5, 8] {
            let error = checked_int_option(0, length).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetHandleInformation(handle: *mut std::ffi::c_void, flags: *mut u32) -> i32;
    }

    fn assert_not_inheritable(socket: RawSocket) {
        let mut flags = 0;
        let result = unsafe { GetHandleInformation(socket as *mut std::ffi::c_void, &mut flags) };
        assert_ne!(result, 0, "{}", io::Error::last_os_error());
        assert_eq!(flags & 1, 0, "socket handle is inheritable");
    }

    #[test]
    fn normalized_tcp_and_udp_handles_are_not_inheritable() {
        let audit = Audit::default();
        for v6 in [false, true] {
            for kind in [SOCK_STREAM, SOCK_DGRAM] {
                let socket = new_socket(v6, kind, None, &audit).unwrap();
                assert_not_inheritable(socket.as_raw_socket());
            }
            let ip = if v6 { "::1" } else { "127.0.0.1" };
            let udp = udp_socket(ip.parse().unwrap(), None, &audit).unwrap();
            assert_not_inheritable(udp.raw_handle());
        }
        assert_eq!(audit.snapshot(), (6, 0));
    }

    const WSAECONNREFUSED: i32 = 10061;
    const WSAETIMEDOUT: i32 = 10060;
    const WSAENETUNREACH: i32 = 10051;
    const WSAEINVAL: i32 = 10022;
    const FD_WRITE: i32 = 0x0002;

    /// One cleanup step that a connect event performs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum EventOp {
        Create,
        Associate { socket: RawSocket, events: i32 },
        Disassociate { socket: RawSocket },
        CloseEvent,
        CloseSocket { socket: RawSocket },
    }

    /// A fake event seam. It records each call and can inject a failure.
    #[derive(Default)]
    struct FakeEvents {
        log: std::cell::RefCell<Vec<EventOp>>,
        fail_create: bool,
        fail_associate: bool,
        fail_disassociate: bool,
    }

    impl FakeEvents {
        fn log(&self) -> Vec<EventOp> {
            self.log.borrow().clone()
        }
    }

    impl EventApi for FakeEvents {
        fn create_event(&self) -> io::Result<*mut std::ffi::c_void> {
            self.log.borrow_mut().push(EventOp::Create);
            if self.fail_create {
                return Err(io::Error::other("event create failed"));
            }
            Ok(std::ptr::NonNull::<u8>::dangling().as_ptr().cast())
        }

        fn select_event(
            &self,
            socket: RawSocket,
            _event: *mut std::ffi::c_void,
            events: i32,
        ) -> io::Result<()> {
            if events == 0 {
                self.log.borrow_mut().push(EventOp::Disassociate { socket });
                if self.fail_disassociate {
                    return Err(io::Error::other("association cancel failed"));
                }
            } else {
                self.log
                    .borrow_mut()
                    .push(EventOp::Associate { socket, events });
                if self.fail_associate {
                    return Err(io::Error::other("association failed"));
                }
            }
            Ok(())
        }

        fn close_event(&self, _event: *mut std::ffi::c_void) {
            self.log.borrow_mut().push(EventOp::CloseEvent);
        }

        fn close_socket(&self, socket: OwnedSocket) {
            let raw = socket.as_raw_socket();
            self.log
                .borrow_mut()
                .push(EventOp::CloseSocket { socket: raw });
            drop(socket);
        }
    }

    fn test_socket(audit: &Audit) -> OwnedSocket {
        new_socket(false, SOCK_DGRAM, None, audit).unwrap()
    }

    #[test]
    fn ttl_is_audited() {
        let audit = Audit::default();
        let socket = udp_socket("127.0.0.1".parse().unwrap(), None, &audit).unwrap();
        assert_eq!(socket.ttl().unwrap(), 65);
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn invalid_interface_fails_closed() {
        let audit = Audit::default();
        assert!(udp_socket("127.0.0.1".parse().unwrap(), Some(0), &audit).is_err());
        assert!(udp_socket("127.0.0.1".parse().unwrap(), Some(u32::MAX), &audit).is_err());
    }

    #[test]
    fn unicast_interface_values_use_the_documented_byte_order() {
        let index: u32 = 0x0102_0304;
        assert_eq!(unicast_if_value(false, index), index.to_be_bytes());
        assert_eq!(unicast_if_value(true, index), index.to_ne_bytes());
        // The two options must not share one byte order.
        assert_ne!(
            unicast_if_value(false, index),
            unicast_if_value(true, index)
        );
    }

    #[test]
    fn pinning_reads_back_the_interface_index() {
        // Index 1 is the loopback interface on a normal Windows host. Skip the
        // check when the test host does not expose it.
        if interface_name(1).is_err() {
            return;
        }
        let audit = Audit::default();
        let v4 = udp_socket("127.0.0.1".parse().unwrap(), Some(1), &audit).unwrap();
        assert_eq!(
            get_int(v4.raw_handle(), IPPROTO_IP, IP_UNICAST_IF).unwrap(),
            1
        );
        let v6 = udp_socket("::1".parse().unwrap(), Some(1), &audit).unwrap();
        assert_eq!(
            get_int(v6.raw_handle(), IPPROTO_IPV6, IPV6_UNICAST_IF).unwrap(),
            1
        );
        assert_eq!(audit.snapshot(), (2, 0));
    }

    #[test]
    fn interface_index_accepts_numeric_and_rejects_zero() {
        assert_eq!(interface_index("1").unwrap(), 1);
        assert!(interface_index("0").is_err());
        assert!(interface_index("16777216").is_err());
        assert!(interface_index("").is_err());
    }

    #[test]
    fn interface_name_round_trips_when_the_index_exists() {
        let Ok(name) = interface_name(1) else {
            return;
        };
        assert_eq!(interface_index(&name).unwrap(), 1);
    }

    #[test]
    fn connect_event_classifies_the_documented_results() {
        // A set `FD_CONNECT` bit with a zero code is a completed connection.
        assert_eq!(classify_connect(FD_CONNECT, 0, 0), ConnectState::Connected);
        // A set bit with a code is a failed attempt. This is the refused
        // loopback case that the connect wait must report before the deadline.
        assert_eq!(
            classify_connect(FD_CONNECT, WSAECONNREFUSED, 0),
            ConnectState::Failed(WSAECONNREFUSED)
        );
        assert_eq!(
            io::Error::from_raw_os_error(WSAECONNREFUSED).kind(),
            io::ErrorKind::ConnectionRefused
        );
        // A clear bit never proves success.
        assert_eq!(classify_connect(0, 0, 0), ConnectState::Pending);
        assert_eq!(
            classify_connect(0, 0, WSAECONNREFUSED),
            ConnectState::Failed(WSAECONNREFUSED)
        );
        // A write bit is not connect evidence. Only `FD_CONNECT` is.
        assert_eq!(classify_connect(FD_WRITE, 0, 0), ConnectState::Pending);
        // `FD_READ` is bit 0, not the connect event.
        assert_eq!(classify_connect(0x0001, 0, 0), ConnectState::Pending);
    }

    #[test]
    fn connect_failure_codes_map_to_socket_error_kinds() {
        // `WSAEnumNetworkEvents` reports these codes for `FD_CONNECT`.
        assert_eq!(
            io::Error::from_raw_os_error(WSAETIMEDOUT).kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            io::Error::from_raw_os_error(WSAENETUNREACH).kind(),
            io::ErrorKind::NetworkUnreachable
        );
        // A failed connect is not reported as a timeout.
        assert_ne!(
            io::Error::from_raw_os_error(WSAECONNREFUSED).kind(),
            io::Error::from_raw_os_error(WSAETIMEDOUT).kind()
        );
    }

    #[test]
    fn empty_signaled_record_fails_closed() {
        // A signaled wait with an empty record and a zero `SO_ERROR` does not
        // prove success. The wait must report `InvalidData`.
        let state = resolve_connect(0, 0, || Ok(0)).unwrap();
        assert_eq!(state, ConnectState::Pending);
        assert_eq!(
            connect_result(state).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn so_error_read_failure_fails_closed() {
        // A failed `SO_ERROR` read must stop the wait. It never becomes a
        // success or a timeout.
        let error =
            resolve_connect(0, 0, || Err(io::Error::from_raw_os_error(WSAEINVAL))).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(WSAEINVAL));
    }

    #[test]
    fn the_connect_bit_is_the_only_success_evidence() {
        // A set `FD_CONNECT` bit with a zero code is enough. The helper must
        // not read `SO_ERROR`, which would clear the result.
        let state = resolve_connect(FD_CONNECT, 0, || {
            panic!("a connect bit must not read SO_ERROR")
        })
        .unwrap();
        assert_eq!(state, ConnectState::Connected);
        assert!(connect_result(state).is_ok());
    }

    #[test]
    fn connect_event_cancels_the_association_before_it_closes_the_event() {
        let audit = Audit::default();
        let api = FakeEvents::default();
        let socket = test_socket(&audit);
        let raw = socket.as_raw_socket();
        let mut guard = ConnectEvent::register(socket, &api).unwrap();
        guard.disarm().unwrap();
        assert_eq!(
            api.log(),
            vec![
                EventOp::Create,
                EventOp::Associate {
                    socket: raw,
                    events: FD_CONNECT,
                },
                EventOp::Disassociate { socket: raw },
                EventOp::CloseEvent,
            ]
        );
        // A successful cancel keeps the socket for the caller.
        drop(guard);
        let log = api.log();
        assert_eq!(log.last(), Some(&EventOp::CloseSocket { socket: raw }));
        assert_eq!(
            log.iter()
                .filter(|op| matches!(op, EventOp::CloseSocket { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn disassociation_failure_closes_the_socket_before_the_event() {
        let audit = Audit::default();
        let api = FakeEvents {
            fail_disassociate: true,
            ..FakeEvents::default()
        };
        let socket = test_socket(&audit);
        let raw = socket.as_raw_socket();
        let mut guard = ConnectEvent::register(socket, &api).unwrap();
        let error = guard.disarm().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            api.log(),
            vec![
                EventOp::Create,
                EventOp::Associate {
                    socket: raw,
                    events: FD_CONNECT,
                },
                EventOp::Disassociate { socket: raw },
                EventOp::CloseSocket { socket: raw },
                EventOp::CloseEvent,
            ]
        );
        // Drop must not close either handle a second time.
        drop(guard);
        assert_eq!(api.log().len(), 5);
    }

    #[test]
    fn association_failure_closes_both_handles_once() {
        let audit = Audit::default();
        let api = FakeEvents {
            fail_associate: true,
            ..FakeEvents::default()
        };
        let socket = test_socket(&audit);
        let raw = socket.as_raw_socket();
        assert!(ConnectEvent::register(socket, &api).is_err());
        assert_eq!(
            api.log(),
            vec![
                EventOp::Create,
                EventOp::Associate {
                    socket: raw,
                    events: FD_CONNECT,
                },
                EventOp::Disassociate { socket: raw },
                EventOp::CloseEvent,
                EventOp::CloseSocket { socket: raw },
            ]
        );
    }

    #[test]
    fn association_and_cancel_failure_closes_the_socket_before_the_event() {
        let audit = Audit::default();
        let api = FakeEvents {
            fail_associate: true,
            fail_disassociate: true,
            ..FakeEvents::default()
        };
        let socket = test_socket(&audit);
        let raw = socket.as_raw_socket();
        assert!(ConnectEvent::register(socket, &api).is_err());
        assert_eq!(
            api.log(),
            vec![
                EventOp::Create,
                EventOp::Associate {
                    socket: raw,
                    events: FD_CONNECT,
                },
                EventOp::Disassociate { socket: raw },
                EventOp::CloseSocket { socket: raw },
                EventOp::CloseEvent,
            ]
        );
    }

    #[test]
    fn event_create_failure_closes_the_socket_once() {
        let audit = Audit::default();
        let api = FakeEvents {
            fail_create: true,
            ..FakeEvents::default()
        };
        let socket = test_socket(&audit);
        let raw = socket.as_raw_socket();
        assert!(ConnectEvent::register(socket, &api).is_err());
        assert_eq!(
            api.log(),
            vec![EventOp::Create, EventOp::CloseSocket { socket: raw }]
        );
    }

    #[test]
    fn disarm_is_idempotent() {
        let audit = Audit::default();
        let api = FakeEvents::default();
        let socket = test_socket(&audit);
        let mut guard = ConnectEvent::register(socket, &api).unwrap();
        guard.disarm().unwrap();
        guard.disarm().unwrap();
        let log = api.log();
        assert_eq!(
            log.iter()
                .filter(|op| matches!(op, EventOp::Disassociate { .. }))
                .count(),
            1
        );
        assert_eq!(
            log.iter()
                .filter(|op| matches!(op, EventOp::CloseEvent))
                .count(),
            1
        );
        drop(guard);
        assert_eq!(
            api.log()
                .iter()
                .filter(|op| matches!(op, EventOp::CloseSocket { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn into_stream_refuses_an_associated_socket() {
        let audit = Audit::default();
        let api = FakeEvents::default();
        let socket = test_socket(&audit);
        let raw = socket.as_raw_socket();
        let guard = ConnectEvent::register(socket, &api).unwrap();
        let error = guard.into_stream().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        // The guard cancels the association before it closes the event and the
        // socket. No `TcpStream` takes over an associated handle.
        assert_eq!(
            api.log(),
            vec![
                EventOp::Create,
                EventOp::Associate {
                    socket: raw,
                    events: FD_CONNECT,
                },
                EventOp::Disassociate { socket: raw },
                EventOp::CloseEvent,
                EventOp::CloseSocket { socket: raw },
            ]
        );
    }

    #[test]
    fn zero_timeout_is_rejected_before_a_socket_exists() {
        let audit = Audit::default();
        let error =
            tcp_connect("127.0.0.1:9".parse().unwrap(), None, &audit, Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(audit.snapshot(), (0, 0));
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
    fn connected_stream_waits_for_delayed_data() {
        use std::io::{Read, Write};

        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let audit = Audit::default();
        let mut client = tcp_connect(
            server.local_addr().unwrap(),
            None,
            &audit,
            Duration::from_secs(5),
        )
        .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut peer, _) = server.accept().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            peer.write_all(&[42]).unwrap();
        });
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        writer.join().unwrap();
        assert_eq!(byte, [42]);
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn refused_loopback_connection_fails_before_the_deadline() {
        // Bind a loopback port, then close the listener. Nothing listens on
        // that port, so the connect must fail before the deadline. Windows can
        // need more than two seconds to report a refusal after SYN retries.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let audit = Audit::default();
        let started = Instant::now();
        let timeout = Duration::from_secs(10);
        let error = tcp_connect(addr, None, &audit, timeout).unwrap_err();
        if error.kind() != io::ErrorKind::ConnectionRefused {
            let baseline = TcpStream::connect_timeout(&addr, timeout);
            eprintln!("Standard library closed-port result: {baseline:?}");
        }
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused, "{error}");
        assert!(started.elapsed() < timeout);
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn cancelled_connection_does_not_create_socket() {
        let audit = Audit::default();
        let stopped = AtomicBool::new(true);
        let error = tcp_connect_cancellable(
            "127.0.0.1:9".parse().unwrap(),
            None,
            &audit,
            Duration::from_secs(1),
            Some(&stopped),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
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
        assert_eq!(
            get_int(client.as_raw_socket(), IPPROTO_IPV6, IPV6_UNICAST_HOPS).unwrap(),
            65
        );
        assert_eq!(
            get_int(udp.raw_handle(), IPPROTO_IPV6, IPV6_UNICAST_HOPS).unwrap(),
            65
        );
        assert_eq!(audit.snapshot(), (2, 0));
    }

    #[test]
    fn tcp_start_is_nonblocking_and_audited() {
        use std::io::{Read, Write};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let audit = Audit::default();
        let mut client = tcp_start(server.local_addr().unwrap(), None, &audit).unwrap();
        let raw = client.as_raw_socket();
        let mut write = fd_set(raw);
        let mut except = fd_set(raw);
        let timeout = Timeval {
            seconds: 2,
            microseconds: 0,
        };
        let n = unsafe { select(0, std::ptr::null_mut(), &mut write, &mut except, &timeout) };
        assert!(n > 0);
        assert!(client.take_error().unwrap().is_none());
        let (mut peer, _) = server.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.write_all(b"ok").unwrap();
        let mut buffer = [0; 2];
        peer.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ok");
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn keepalive_defaults_match_the_source_device() {
        let keepalive = TcpKeepalive::SOURCE_DEVICE;
        assert_eq!(keepalive.idle(), Duration::from_secs(60));
        assert_eq!(keepalive.interval(), Duration::from_secs(10));
        assert_eq!(keepalive.count(), 3);
        assert_eq!(keepalive.fixed_probe_count(), 10);
        assert_eq!(keepalive.dead_peer_age(), Duration::from_secs(160));
        let boundary =
            TcpKeepalive::new(Duration::from_secs(290), Duration::from_secs(1), 1).unwrap();
        assert_eq!(boundary.dead_peer_age(), TcpKeepalive::MAX_DEAD_PEER_AGE);
    }

    #[test]
    fn keepalive_rejects_unbounded_or_invalid_values() {
        let cases = [
            (Duration::ZERO, Duration::from_secs(10), 3),
            (Duration::from_secs(60), Duration::ZERO, 3),
            (Duration::from_micros(60_500), Duration::from_secs(10), 3),
            (Duration::from_secs(3_601), Duration::from_secs(10), 3),
            (Duration::from_secs(60), Duration::from_secs(3_601), 3),
            (Duration::from_secs(60), Duration::from_secs(10), 0),
            (Duration::from_secs(60), Duration::from_secs(10), 128),
            // Windows always uses 10 probes, so a requested count of 1 does
            // not make 299 seconds of idle time safe.
            (Duration::from_secs(299), Duration::from_secs(1), 1),
        ];
        for (idle, interval, count) in cases {
            let error = TcpKeepalive::new(idle, interval, count).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn keepalive_accepts_whole_millisecond_values() {
        let keepalive =
            TcpKeepalive::new(Duration::from_millis(1_500), Duration::from_millis(250), 3).unwrap();
        assert_eq!(keepalive.idle(), Duration::from_millis(1_500));
        assert_eq!(keepalive.interval(), Duration::from_millis(250));
        assert!(TcpKeepalive::new(
            Duration::from_micros(1_500_500),
            Duration::from_millis(250),
            3
        )
        .is_err());
    }

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
            assert_ne!(
                get_int(client.as_raw_socket(), SOL_SOCKET, SO_KEEPALIVE).unwrap(),
                0
            );
            let ttl = if server.local_addr().unwrap().is_ipv4() {
                i32::try_from(client.ttl().unwrap()).unwrap()
            } else {
                get_int(client.as_raw_socket(), IPPROTO_IPV6, IPV6_UNICAST_HOPS).unwrap()
            };
            assert_eq!(ttl, OUTER_TTL);
            assert_eq!(audit.snapshot(), (1, 0));
        }
    }

    #[test]
    fn keepalive_is_set_before_a_started_connection_completes() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let audit = Audit::default();
        let client = tcp_start(server.local_addr().unwrap(), None, &audit).unwrap();
        set_tcp_keepalive(&client, TcpKeepalive::SOURCE_DEVICE).unwrap();
        assert_ne!(
            get_int(client.as_raw_socket(), SOL_SOCKET, SO_KEEPALIVE).unwrap(),
            0
        );
        let (_peer, _) = server.accept().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn keepalive_reports_a_non_tcp_socket_error() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let raw = udp.as_raw_socket();
        // `SIO_KEEPALIVE_VALS` is documented for TCP sockets. A UDP socket
        // must not report a successful keepalive setting.
        assert!(set_tcp_keepalive_socket(raw, TcpKeepalive::SOURCE_DEVICE).is_err());
    }

    #[test]
    fn exclusive_loopback_listener_refuses_a_shared_bind() {
        let listener = exclusive_loopback_listener(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::LOCALHOST,
            0,
        ))
        .unwrap();
        let local = listener.local_addr().unwrap();
        assert_eq!(local.ip(), IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_ne!(local.port(), 0);
        assert_not_inheritable(listener.as_raw_socket());

        // A second socket that asks for SO_REUSEADDR must not share the port.
        const SO_REUSEADDR: i32 = 0x0004;
        let raw = unsafe {
            WSASocketW(
                AF_INET,
                SOCK_STREAM,
                IPPROTO_TCP,
                std::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        assert_ne!(raw, INVALID_SOCKET);
        let second = unsafe { OwnedSocket::from_raw_socket(raw) };
        set_int(second.as_raw_socket(), SOL_SOCKET, SO_REUSEADDR, 1).unwrap();
        let name = SockaddrIn {
            family: AF_INET as u16,
            port: local.port().to_be(),
            addr: u32::from_ne_bytes(std::net::Ipv4Addr::LOCALHOST.octets()),
            zero: [0; 8],
        };
        let rc = unsafe {
            bind(
                second.as_raw_socket(),
                (&name as *const SockaddrIn).cast(),
                mem::size_of_val(&name) as i32,
            )
        };
        assert_ne!(
            rc, 0,
            "a SO_REUSEADDR bind must not share the listener port"
        );

        // The listener still accepts a plain loopback connection.
        let client = std::net::TcpStream::connect(local).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
        drop(accepted);
    }

    #[test]
    fn exclusive_loopback_listener_refuses_a_non_loopback_address() {
        let error = exclusive_loopback_listener(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
