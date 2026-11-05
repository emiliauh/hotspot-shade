//! Windows relay readiness and wake foundation.
//!
//! The source device proxy tunnel uses this module on Windows. A live Windows
//! tunnel test is still needed. Do not read this module, its tests, or the
//! Windows CI compile result as proof that a live Windows tunnel works.
//!
//! # Readiness is advisory
//!
//! [`WaitSet`] uses `WSAPoll` on Windows. It has no 64-socket limit. A ready bit
//! does not prove that the next read or write completes:
//!
//! - A read can report ready while `recv` returns `WouldBlock`.
//! - A graceful close can appear as readable. A `recv` that returns 0 is the
//!   only reliable end-of-file signal.
//! - A failed nonblocking connect can appear as writable. Read `SO_ERROR`
//!   before you use the stream. [`check_connect`] does this. Do not rely on
//!   `WSAPoll` to detect failed connects on Windows before version 2004. Use
//!   a connect-specific `select` wait with write and exception sets.
//! - This relay does not use out-of-band data. The module reports it as
//!   readable. The caller must not enable out-of-band reads.
//!
//! Call [`read_result`] and [`write_result`] after a ready bit. They keep
//! `Ok(0)` apart from `WouldBlock`.
//!
//! # Cancellation
//!
//! [`WaitSet::wait`] checks the stop flag before each slice and after a wait.
//! A slice is at most [`CANCEL_SLICE`]. A stop request therefore ends the wait
//! within that bound. The wait checks the deadline between slices.
//!
//! # Wake channel
//!
//! Windows has no `UnixStream::pair`. [`WakePair`] uses two UDP sockets that are
//! bound and connected on `127.0.0.1` only. It is a local control channel. It is
//! not an outer socket and it carries no tunnel data.
//!
//! UDP delivery is not guaranteed. A successful send does not prove that the
//! receiver has a datagram. A sender signals after it adds work. The receiver
//! must recheck the work queue after every wait, including timeouts. A bounded
//! timeout is required. A [`WakeSignal::Retry`] means no signal was sent. The
//! producer must retry or rely on that bounded queue check. Use these orders:
//!
//! 1. Drain the channel, then check the work queue, then wait.
//! 2. Wait, then drain the channel, then check the work queue.
//!
//! Do not drain the channel and then block without a queue check. Neither
//! ordering turns UDP into a reliable wake channel.
//!
//! # Socket lifetime and cleanup
//!
//! A closed socket in the set can make `WSAPoll` fail with `WSAENOTSOCK` or
//! `WSAEINVAL`. The wait returns `BrokenPipe` or `InvalidInput`. Drop the set
//! and build it again from the live sockets. Do not reuse an entry after its
//! socket closes. Windows can reuse a socket handle value for a new socket.
//!
//! The types in this module own no tunnel device and no route. Dropping a
//! [`WaitSet`], [`WakePair`], or [`WakeReceiver`] closes only the sockets that
//! the value owns.
//!
//! # Windows ABI
//!
//! The module declares `WSAPoll` and `WSAGetLastError` from `ws2_32.dll`. It
//! does not copy a private Winsock type from another module.
//! `normalization_windows` and `phone` keep their Winsock definitions private.
//! The local `WSAPOLLFD` definition matches `winsock2.h`:
//!
//! ```c
//! typedef struct pollfd {
//!   SOCKET fd;
//!   SHORT  events;
//!   SHORT  revents;
//! } WSAPOLLFD;
//! ```
//!
//! `SOCKET` is `UINT_PTR` and `SHORT` is 16 bits. Compile-time assertions check
//! the size, the alignment, and the field offsets for x86 and the 64-bit
//! targets.
//!
//! # Tests
//!
//! The pure tests run on every platform. The native tests run only on Windows.
//! Every loopback test binds to `127.0.0.1`. A test creates no route, device,
//! driver, or tunnel. The Windows native tests need a Windows host.
//!
//! Microsoft references:
//!
//! - `WSAPoll`:
//!   <https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsapoll>
//! - `WSAPOLLFD`:
//!   <https://learn.microsoft.com/windows/win32/api/winsock2/ns-winsock2-wsapollfd>

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[cfg(windows)]
use std::net::TcpStream;
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::time::Instant;

/// The longest wait slice when a stop flag can change.
pub const CANCEL_SLICE: Duration = Duration::from_millis(100);

// The values come from winsock2.h. `POLLIN` and `POLLOUT` are combinations.
const POLLRDNORM: i16 = 0x0100;
const POLLRDBAND: i16 = 0x0200;
const POLLPRI: i16 = 0x0400;
const POLLWRNORM: i16 = 0x0010;
const POLLWRBAND: i16 = 0x0020;
const POLLERR: i16 = 0x0001;
const POLLHUP: i16 = 0x0002;
const POLLNVAL: i16 = 0x0004;

const KNOWN_REVENTS: i16 =
    POLLRDNORM | POLLRDBAND | POLLPRI | POLLWRNORM | POLLWRBAND | POLLERR | POLLHUP | POLLNVAL;

const WSAEINTR: i32 = 10004;
const WSAEINVAL: i32 = 10022;
const WSAENOTSOCK: i32 = 10038;

/// The state that a caller asks `WSAPoll` to watch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interest(u16);

impl Interest {
    /// No state. A wait set rejects an empty interest.
    pub const NONE: Self = Self(0);
    /// Normal data can be read.
    pub const READABLE: Self = Self(1 << 0);
    /// Normal data can be written.
    pub const WRITABLE: Self = Self(1 << 1);
    /// Both readable and writable.
    pub const READ_WRITE: Self = Self(Self::READABLE.0 | Self::WRITABLE.0);

    /// Return true when every bit of `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Return true when any bit of `other` is present.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Return true when no state is requested.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return the union of two interests.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for Interest {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// The state that one wait reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ready(u16);

impl Ready {
    /// Normal data can be read.
    pub const READABLE: Self = Self(1 << 0);
    /// Normal data can be written.
    pub const WRITABLE: Self = Self(1 << 1);
    /// The socket reported an error.
    pub const ERROR: Self = Self(1 << 2);
    /// The peer disconnected or aborted the stream. This bit can arrive with
    /// `READABLE`. Read the pending data before you close the flow.
    pub const HANGUP: Self = Self(1 << 3);
    /// The socket value is not a live socket.
    pub const INVALID: Self = Self(1 << 4);

    /// Return true when every bit of `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Return true when any bit of `other` is present.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Return true when no state is reported.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return true for an error, a hangup, or an invalid socket.
    pub const fn is_failure(self) -> bool {
        self.intersects(Self::ERROR.union(Self::HANGUP).union(Self::INVALID))
    }

    /// Return the union of two states.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for Ready {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// One socket value for a wait set.
///
/// The value is the Windows `SOCKET` handle. On a test host it is an opaque
/// number. [`SocketId::INVALID`] and the Windows `INVALID_SOCKET` value are the
/// same value on every supported target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SocketId(usize);

impl SocketId {
    /// The invalid socket value.
    pub const INVALID: Self = Self(usize::MAX);

    /// Build an opaque socket value.
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    /// Return the opaque socket value.
    pub const fn value(self) -> usize {
        self.0
    }

    /// Return true for the invalid socket value.
    pub const fn is_invalid(self) -> bool {
        self.0 == usize::MAX
    }

    /// Build an identifier from a Windows socket handle.
    #[cfg(windows)]
    pub fn from_raw_socket(raw: RawSocket) -> Self {
        Self(raw as usize)
    }

    /// Return the Windows socket handle.
    #[cfg(windows)]
    pub fn as_raw_socket(self) -> RawSocket {
        self.0 as RawSocket
    }
}

/// One socket that a wait reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyEvent {
    /// The socket that reported state.
    pub socket: SocketId,
    /// The state that the socket reported.
    pub ready: Ready,
}

/// The result of one wait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// At least one socket reported state.
    Ready(Vec<ReadyEvent>),
    /// The timeout elapsed.
    TimedOut,
    /// The stop flag was set.
    Cancelled,
}

#[derive(Clone, Copy, Debug)]
struct WaitEntry {
    socket: SocketId,
    interest: Interest,
}

/// A bounded, rebuildable set of sockets for one wait.
///
/// Insert each live socket with its interest. Call [`WaitSet::clear`] and add
/// the sockets again after a flow changes. The set has no 64-socket limit.
#[derive(Clone, Debug, Default)]
pub struct WaitSet {
    entries: Vec<WaitEntry>,
}

impl WaitSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty set with room for `capacity` sockets.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Return the number of sockets in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true when the set has no socket.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Add one socket and its interest.
    ///
    /// The call rejects the invalid socket value, an empty interest, and a
    /// socket that is already in the set. This keeps one socket to one result.
    pub fn insert(&mut self, socket: SocketId, interest: Interest) -> io::Result<()> {
        if socket.is_invalid() {
            return Err(invalid_input("socket id is invalid"));
        }
        if interest.is_empty() {
            return Err(invalid_input("socket interest is empty"));
        }
        if self.entries.iter().any(|entry| entry.socket == socket) {
            return Err(invalid_input("socket is already in the wait set"));
        }
        self.entries.push(WaitEntry { socket, interest });
        Ok(())
    }

    /// Wait for one socket state, a timeout, or a stop request.
    ///
    /// The call checks the stop flag before each slice and after a wait. A
    /// slice is at most [`CANCEL_SLICE`]. A zero timeout performs one
    /// nonblocking check. An empty set sleeps in bounded slices.
    #[cfg(windows)]
    pub fn wait(&self, timeout: Duration, stopped: &AtomicBool) -> io::Result<WaitOutcome> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid_input("timeout is too large"))?;
        let mut first = true;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let slice = match next_wait_slice(
                remaining,
                first,
                stopped.load(Ordering::Acquire),
                CANCEL_SLICE,
            ) {
                WaitSlice::Wait(slice) => slice,
                WaitSlice::TimedOut => return Ok(WaitOutcome::TimedOut),
                WaitSlice::Cancelled => return Ok(WaitOutcome::Cancelled),
            };
            first = false;
            if self.entries.is_empty() {
                if slice.is_zero() {
                    return Ok(WaitOutcome::TimedOut);
                }
                std::thread::sleep(slice);
                continue;
            }
            match winsock::poll(&self.entries, poll_millis(slice))? {
                winsock::PollResult::Events(events) => {
                    if stopped.load(Ordering::Acquire) {
                        return Ok(WaitOutcome::Cancelled);
                    }
                    return Ok(WaitOutcome::Ready(events));
                }
                winsock::PollResult::TimedOut | winsock::PollResult::Interrupted => {
                    if slice.is_zero() {
                        return Ok(WaitOutcome::TimedOut);
                    }
                }
            }
        }
    }
}

/// One bounded wait slice, or a terminal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitSlice {
    Wait(Duration),
    TimedOut,
    Cancelled,
}

/// Select the next wait slice.
///
/// A stop request wins. The first slice may be zero so that a zero timeout
/// performs one nonblocking check. The cap is at least 1 ms so that a zero cap
/// cannot create a busy loop.
fn next_wait_slice(
    remaining: Duration,
    first: bool,
    stopped: bool,
    max_slice: Duration,
) -> WaitSlice {
    if stopped {
        return WaitSlice::Cancelled;
    }
    if remaining.is_zero() && !first {
        return WaitSlice::TimedOut;
    }
    let cap = max_slice.max(Duration::from_millis(1));
    WaitSlice::Wait(remaining.min(cap))
}

/// Convert a wait slice to the `WSAPoll` timeout in milliseconds.
///
/// A positive value rounds up to 1 ms. A zero value stays zero.
fn poll_millis(slice: Duration) -> i32 {
    if slice.is_zero() {
        0
    } else {
        (slice.as_nanos().saturating_add(999_999) / 1_000_000).min(i32::MAX as u128) as i32
    }
}

/// The reason that `WSAPoll` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitFailure {
    Interrupted,
    InvalidSocket,
    InvalidInput,
    Other(i32),
}

/// Classify one `WSAGetLastError` value from `WSAPoll`.
fn classify_wait_error(code: i32) -> WaitFailure {
    match code {
        WSAEINTR => WaitFailure::Interrupted,
        WSAENOTSOCK => WaitFailure::InvalidSocket,
        WSAEINVAL => WaitFailure::InvalidInput,
        other => WaitFailure::Other(other),
    }
}

/// Convert one `WSAPoll` interest to the normal-data event bits.
///
/// Do not request priority data. The Microsoft Winsock provider rejects
/// `POLLPRI`.
fn backend_events(interest: Interest) -> i16 {
    let mut events = 0;
    if interest.contains(Interest::READABLE) {
        events |= POLLRDNORM;
    }
    if interest.contains(Interest::WRITABLE) {
        events |= POLLWRNORM;
    }
    events
}

/// Convert one `revents` value to the state that the caller requested.
///
/// Error conditions are always reported. A normal-data bit is reported only
/// when the caller asked for that direction. An unexpected or unknown bit fails
/// closed as an error. The relay must not continue on a state that it does not
/// understand.
fn classify_revents(raw: i16, interest: Interest) -> Ready {
    let mut ready = Ready::default();
    if raw & !KNOWN_REVENTS != 0 {
        ready = ready.union(Ready::ERROR);
    }
    if raw & POLLNVAL != 0 {
        ready = ready.union(Ready::INVALID);
    }
    if raw & POLLERR != 0 {
        ready = ready.union(Ready::ERROR);
    }
    if raw & POLLHUP != 0 {
        ready = ready.union(Ready::HANGUP);
    }
    if interest.contains(Interest::READABLE) && raw & (POLLRDNORM | POLLRDBAND) != 0 {
        ready = ready.union(Ready::READABLE);
    }
    if interest.contains(Interest::WRITABLE) && raw & (POLLWRNORM | POLLWRBAND) != 0 {
        ready = ready.union(Ready::WRITABLE);
    }
    if raw & POLLPRI != 0 {
        // The Microsoft provider does not return this bit. Do not use it.
        ready = ready.union(Ready::ERROR);
    }
    if raw != 0 && ready.is_empty() {
        ready = Ready::ERROR;
    }
    ready
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The result of one read attempt.
#[derive(Debug)]
pub enum ReadResult {
    /// The read returned this many bytes.
    Data(usize),
    /// The peer closed the stream. Do not read again.
    EndOfFile,
    /// The socket is not ready, or the call was interrupted. Try again.
    Retry,
    /// The read failed. Close the flow.
    Error(io::Error),
}

/// Classify one read attempt after a readable bit.
///
/// A zero-byte read is end of file. It is not a retry. A Windows graceful close
/// can arrive as readable, so the read attempt is the proof.
pub fn read_result(result: io::Result<usize>) -> ReadResult {
    match result {
        Ok(0) => ReadResult::EndOfFile,
        Ok(count) => ReadResult::Data(count),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            ReadResult::Retry
        }
        Err(error) => ReadResult::Error(error),
    }
}

/// The result of one write attempt.
#[derive(Debug)]
pub enum WriteResult {
    /// The write accepted this many bytes.
    Wrote(usize),
    /// The socket is not ready, or the call was interrupted. Try again.
    Retry,
    /// The write accepted no byte from a nonempty slice. Close the flow.
    Zero,
    /// The write failed. Close the flow.
    Error(io::Error),
}

/// Classify one write attempt after a writable bit.
///
/// A zero-byte write from a nonempty slice is a failure. Do not retry it.
pub fn write_result(result: io::Result<usize>) -> WriteResult {
    match result {
        Ok(0) => WriteResult::Zero,
        Ok(count) => WriteResult::Wrote(count),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            WriteResult::Retry
        }
        Err(error) => WriteResult::Error(error),
    }
}

/// The next step after a connect readiness result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectAction {
    Pending,
    VerifySuccess,
    VerifyFailure,
}

/// Select the `SO_ERROR` check for one connect readiness result.
///
/// A failure bit wins over a writable bit. Windows reports a failed connect as
/// writable on some versions, so a writable bit alone is not proof of success.
fn connect_action(ready: Ready) -> ConnectAction {
    if ready.is_failure() {
        ConnectAction::VerifyFailure
    } else if ready.contains(Ready::WRITABLE) {
        ConnectAction::VerifySuccess
    } else {
        ConnectAction::Pending
    }
}

/// The result of one nonblocking connect check.
#[derive(Debug)]
pub enum ConnectCheck {
    /// The connect is still in progress.
    Pending,
    /// The connect completed.
    Connected,
    /// The connect failed. The error comes from `SO_ERROR`.
    Failed(io::Error),
}

/// Read `SO_ERROR` for one nonblocking connect.
///
/// The caller must pass the readiness result for a connecting stream. Do not
/// call this before the stream reports writable or failed. A read of
/// `SO_ERROR` clears the status, so one check is enough.
///
/// A writable result with a nonzero `SO_ERROR` is a failure. A failure result
/// with a zero `SO_ERROR` is a closed connection. Neither case is a success.
#[cfg(windows)]
pub fn check_connect(stream: &TcpStream, ready: Ready) -> io::Result<ConnectCheck> {
    match connect_action(ready) {
        ConnectAction::Pending => Ok(ConnectCheck::Pending),
        ConnectAction::VerifySuccess => match stream.take_error()? {
            Some(error) => Ok(ConnectCheck::Failed(error)),
            None => Ok(ConnectCheck::Connected),
        },
        ConnectAction::VerifyFailure => match stream.take_error()? {
            Some(error) => Ok(ConnectCheck::Failed(error)),
            None => Ok(ConnectCheck::Failed(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed before it completed",
            ))),
        },
    }
}

/// The result of one wake signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeSignal {
    /// The socket accepted the datagram. Delivery is not guaranteed.
    Sent,
    /// The socket did not send a datagram. Retry or use a bounded queue check.
    Retry,
    /// The receiver is gone. The caller is stopping.
    Closed,
}

/// Classify one wake datagram send.
///
/// A blocked or interrupted send needs a retry. It does not prove that the
/// receiver has a pending datagram. A refused, reset, or disconnected peer
/// means that the receiver is gone.
pub fn classify_wake_send(result: io::Result<usize>) -> io::Result<WakeSignal> {
    match result {
        Ok(1) => Ok(WakeSignal::Sent),
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "wake datagram was not sent",
        )),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wake datagram length is invalid",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) || error.raw_os_error() == Some(WSAEINTR) =>
        {
            Ok(WakeSignal::Retry)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(WakeSignal::Closed)
        }
        Err(error) => Err(error),
    }
}

/// The sending half of a local wake channel.
///
/// The type is thread safe. Any number of producers can signal the same
/// receiver. Each producer handles a failed or blocked signal.
pub struct WakeSender {
    socket: UdpSocket,
}

impl WakeSender {
    /// Signal the receiver.
    ///
    /// Call this after the work queue push. Even [`WakeSignal::Sent`] does not
    /// guarantee delivery. The receiver must use a bounded wait and recheck
    /// the work queue after it wakes or times out.
    pub fn signal(&self) -> io::Result<WakeSignal> {
        classify_wake_send(self.socket.send(&[1]))
    }
}

/// The receiving half of a local wake channel.
pub struct WakeReceiver {
    socket: UdpSocket,
}

impl WakeReceiver {
    /// Remove every pending wake datagram. Return the datagram count.
    ///
    /// An empty channel returns zero. A zero-length datagram counts as one
    /// wake. Call this after the wait and before the next queue check.
    pub fn drain(&self) -> io::Result<usize> {
        let mut buffer = [0u8; 64];
        let mut count = 0;
        loop {
            match self.socket.recv(&mut buffer) {
                Ok(_) => count += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /// Return the socket value for a [`WaitSet`].
    #[cfg(windows)]
    pub fn socket_id(&self) -> SocketId {
        SocketId::from_raw_socket(self.socket.as_raw_socket())
    }
}

/// A local loopback wake channel.
///
/// Both sockets bind to `127.0.0.1:0` and connect to each other. The bind and
/// connect calls take numeric addresses. They do not call `getaddrinfo`. The
/// pair uses no route change and no external address. It is not an outer socket.
pub struct WakePair {
    sender: WakeSender,
    receiver: WakeReceiver,
}

impl WakePair {
    /// Create one loopback wake pair.
    pub fn new() -> io::Result<Self> {
        let receiver = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        receiver.connect(sender.local_addr()?)?;
        sender.connect(receiver.local_addr()?)?;
        receiver.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        Ok(Self {
            sender: WakeSender { socket: sender },
            receiver: WakeReceiver { socket: receiver },
        })
    }

    /// Split the pair into one sender and one receiver.
    pub fn split(self) -> (WakeSender, WakeReceiver) {
        (self.sender, self.receiver)
    }
}

#[cfg(windows)]
mod winsock {
    use super::{
        backend_events, classify_revents, classify_wait_error, invalid_input, ReadyEvent,
        WaitEntry, WaitFailure,
    };
    use std::io;
    use std::mem::{align_of, offset_of, size_of};
    use std::os::windows::io::RawSocket;

    const SOCKET_ERROR: i32 = -1;

    /// The Windows `WSAPOLLFD` structure.
    ///
    /// `SOCKET` is pointer sized. `SHORT` is 16 bits. The structure has padding
    /// before the two `SHORT` fields on a 64-bit target.
    #[repr(C)]
    struct WsaPollFd {
        fd: RawSocket,
        events: i16,
        revents: i16,
    }

    const _: () = {
        if cfg!(target_arch = "x86") {
            assert!(size_of::<WsaPollFd>() == 8);
            assert!(align_of::<WsaPollFd>() == 4);
            assert!(offset_of!(WsaPollFd, fd) == 0);
            assert!(offset_of!(WsaPollFd, events) == 4);
            assert!(offset_of!(WsaPollFd, revents) == 6);
        } else {
            assert!(size_of::<WsaPollFd>() == 16);
            assert!(align_of::<WsaPollFd>() == 8);
            assert!(offset_of!(WsaPollFd, fd) == 0);
            assert!(offset_of!(WsaPollFd, events) == 8);
            assert!(offset_of!(WsaPollFd, revents) == 10);
        }
    };

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAPoll(fds: *mut WsaPollFd, count: u32, timeout: i32) -> i32;
        // The phone and normalization modules declare the same symbol with
        // private types.
        #[allow(clashing_extern_declarations)]
        fn WSAGetLastError() -> i32;
    }

    /// The result of one native wait.
    pub(super) enum PollResult {
        Events(Vec<ReadyEvent>),
        TimedOut,
        Interrupted,
    }

    /// Wait once for the sockets in `entries`.
    ///
    /// The caller must pass at least one entry. The count is the array length,
    /// not the socket count. `WSAPoll` has no 64-socket limit.
    pub(super) fn poll(entries: &[WaitEntry], timeout_ms: i32) -> io::Result<PollResult> {
        let count = u32::try_from(entries.len())
            .map_err(|_| invalid_input("wait set has too many sockets"))?;
        let mut fds = Vec::with_capacity(entries.len());
        for entry in entries {
            fds.push(WsaPollFd {
                fd: entry.socket.as_raw_socket(),
                events: backend_events(entry.interest),
                revents: 0,
            });
        }
        let result = unsafe { WSAPoll(fds.as_mut_ptr(), count, timeout_ms) };
        if result == SOCKET_ERROR {
            let code = unsafe { WSAGetLastError() };
            return match classify_wait_error(code) {
                WaitFailure::Interrupted => Ok(PollResult::Interrupted),
                WaitFailure::InvalidSocket => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "a socket in the wait set is closed",
                )),
                WaitFailure::InvalidInput => Err(invalid_input("WSAPoll rejected the wait set")),
                WaitFailure::Other(code) => Err(io::Error::from_raw_os_error(code)),
            };
        }
        if result == 0 {
            return Ok(PollResult::TimedOut);
        }
        if result as usize > fds.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WSAPoll returned more results than sockets",
            ));
        }
        let mut events = Vec::with_capacity(result as usize);
        let mut nonzero = 0;
        for (entry, fd) in entries.iter().zip(fds.iter()) {
            if fd.revents == 0 {
                continue;
            }
            nonzero += 1;
            events.push(ReadyEvent {
                socket: entry.socket,
                ready: classify_revents(fd.revents, entry.interest),
            });
        }
        if nonzero != result as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WSAPoll count does not match its results",
            ));
        }
        Ok(PollResult::Events(events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::time::{Duration, Instant};

    #[test]
    fn interest_maps_to_normal_winsock_events() {
        assert_eq!(backend_events(Interest::NONE), 0);
        assert_eq!(backend_events(Interest::READABLE), POLLRDNORM);
        assert_eq!(backend_events(Interest::WRITABLE), POLLWRNORM);
        assert_eq!(
            backend_events(Interest::READABLE | Interest::WRITABLE),
            POLLRDNORM | POLLWRNORM
        );
        // The Microsoft provider rejects a priority-data request.
        assert_eq!(
            backend_events(Interest::READABLE | Interest::WRITABLE) & POLLPRI,
            0
        );
    }

    #[test]
    fn readiness_classification_keeps_error_states_apart() {
        let both = Interest::READABLE | Interest::WRITABLE;
        assert_eq!(classify_revents(POLLRDNORM, both), Ready::READABLE);
        assert_eq!(classify_revents(POLLWRNORM, both), Ready::WRITABLE);
        assert_eq!(
            classify_revents(POLLRDNORM | POLLWRNORM, both),
            Ready::READABLE | Ready::WRITABLE
        );
        assert_eq!(
            classify_revents(POLLRDBAND | POLLWRBAND, both),
            Ready::READABLE | Ready::WRITABLE
        );
        assert_eq!(classify_revents(POLLERR, both), Ready::ERROR);
        assert_eq!(classify_revents(POLLHUP, both), Ready::HANGUP);
        assert_eq!(classify_revents(POLLNVAL, both), Ready::INVALID);
        assert_eq!(classify_revents(0, both), Ready::default());
        // An unrequested state or an unknown bit fails closed.
        assert_eq!(
            classify_revents(POLLRDNORM, Interest::WRITABLE),
            Ready::ERROR
        );
        assert_eq!(classify_revents(POLLPRI, both), Ready::ERROR);
        assert_eq!(classify_revents(0x4000, both), Ready::ERROR);
        assert_eq!(
            classify_revents(POLLRDNORM | 0x4000, both),
            Ready::READABLE | Ready::ERROR
        );
    }

    #[test]
    fn wait_set_has_no_sixty_four_socket_limit() {
        let mut set = WaitSet::new();
        for value in 1..=100 {
            set.insert(SocketId::new(value), Interest::READABLE)
                .unwrap();
        }
        assert_eq!(set.len(), 100);
        assert_eq!(set.entries[0].interest, Interest::READABLE);
        assert!(!set.is_empty());
        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn wait_set_rejects_invalid_duplicate_and_empty_entries() {
        let mut set = WaitSet::new();
        assert_eq!(
            set.insert(SocketId::INVALID, Interest::READABLE)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        set.insert(SocketId::new(7), Interest::READABLE).unwrap();
        assert_eq!(
            set.insert(SocketId::new(7), Interest::WRITABLE)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            set.insert(SocketId::new(8), Interest::NONE)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn wait_slices_are_bounded_and_stop_wins() {
        assert_eq!(
            next_wait_slice(Duration::from_secs(5), false, false, CANCEL_SLICE),
            WaitSlice::Wait(CANCEL_SLICE)
        );
        assert_eq!(
            next_wait_slice(Duration::from_millis(10), false, false, CANCEL_SLICE),
            WaitSlice::Wait(Duration::from_millis(10))
        );
        assert_eq!(
            next_wait_slice(Duration::ZERO, true, false, CANCEL_SLICE),
            WaitSlice::Wait(Duration::ZERO)
        );
        assert_eq!(
            next_wait_slice(Duration::ZERO, false, false, CANCEL_SLICE),
            WaitSlice::TimedOut
        );
        assert_eq!(
            next_wait_slice(Duration::from_secs(5), false, true, CANCEL_SLICE),
            WaitSlice::Cancelled
        );
        assert_eq!(
            next_wait_slice(Duration::from_secs(5), false, false, Duration::ZERO),
            WaitSlice::Wait(Duration::from_millis(1))
        );
    }

    #[test]
    fn poll_timeouts_round_up_and_stay_in_range() {
        assert_eq!(poll_millis(Duration::ZERO), 0);
        assert_eq!(poll_millis(Duration::from_nanos(1)), 1);
        assert_eq!(poll_millis(Duration::from_micros(1500)), 2);
        assert_eq!(poll_millis(Duration::from_millis(100)), 100);
        assert_eq!(
            poll_millis(Duration::from_millis(i32::MAX as u64 + 1)),
            i32::MAX
        );
    }

    #[test]
    fn wait_errors_distinguish_a_closed_socket_from_a_bad_set() {
        assert_eq!(classify_wait_error(WSAEINTR), WaitFailure::Interrupted);
        assert_eq!(classify_wait_error(WSAENOTSOCK), WaitFailure::InvalidSocket);
        assert_eq!(classify_wait_error(WSAEINVAL), WaitFailure::InvalidInput);
        assert_eq!(classify_wait_error(10055), WaitFailure::Other(10055));
    }

    #[test]
    fn read_eof_is_not_retry() {
        assert!(matches!(read_result(Ok(0)), ReadResult::EndOfFile));
        assert!(matches!(read_result(Ok(5)), ReadResult::Data(5)));
        assert!(matches!(
            read_result(Err(io::Error::from(ErrorKind::WouldBlock))),
            ReadResult::Retry
        ));
        assert!(matches!(
            read_result(Err(io::Error::from(ErrorKind::Interrupted))),
            ReadResult::Retry
        ));
        assert!(matches!(
            read_result(Err(io::Error::from(ErrorKind::ConnectionReset))),
            ReadResult::Error(_)
        ));
    }

    #[test]
    fn a_zero_write_is_not_retry() {
        assert!(matches!(write_result(Ok(0)), WriteResult::Zero));
        assert!(matches!(write_result(Ok(3)), WriteResult::Wrote(3)));
        assert!(matches!(
            write_result(Err(io::Error::from(ErrorKind::WouldBlock))),
            WriteResult::Retry
        ));
        assert!(matches!(
            write_result(Err(io::Error::from(ErrorKind::BrokenPipe))),
            WriteResult::Error(_)
        ));
    }

    #[test]
    fn a_writable_connect_still_needs_so_error() {
        assert_eq!(connect_action(Ready::default()), ConnectAction::Pending);
        assert_eq!(connect_action(Ready::READABLE), ConnectAction::Pending);
        assert_eq!(
            connect_action(Ready::WRITABLE),
            ConnectAction::VerifySuccess
        );
        assert_eq!(
            connect_action(Ready::ERROR | Ready::WRITABLE),
            ConnectAction::VerifyFailure
        );
        assert_eq!(
            connect_action(Ready::HANGUP | Ready::WRITABLE),
            ConnectAction::VerifyFailure
        );
        assert_eq!(connect_action(Ready::INVALID), ConnectAction::VerifyFailure);
    }

    #[test]
    fn wake_send_classification_keeps_saturation_and_close_apart() {
        assert_eq!(classify_wake_send(Ok(1)).unwrap(), WakeSignal::Sent);
        assert_eq!(
            classify_wake_send(Ok(0)).unwrap_err().kind(),
            ErrorKind::WriteZero
        );
        assert_eq!(
            classify_wake_send(Ok(2)).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            classify_wake_send(Err(io::Error::from(ErrorKind::WouldBlock))).unwrap(),
            WakeSignal::Retry
        );
        assert_eq!(
            classify_wake_send(Err(io::Error::from_raw_os_error(WSAEINTR))).unwrap(),
            WakeSignal::Retry
        );
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::NotConnected,
            ErrorKind::BrokenPipe,
        ] {
            assert_eq!(
                classify_wake_send(Err(io::Error::from(kind))).unwrap(),
                WakeSignal::Closed
            );
        }
        assert_eq!(
            classify_wake_send(Err(io::Error::from(ErrorKind::PermissionDenied)))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    /// Drain a wake channel until it delivers one datagram or the deadline
    /// passes. A loopback datagram can arrive shortly after `send` returns.
    fn drain_until(receiver: &WakeReceiver, minimum: usize) -> usize {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let count = receiver.drain().unwrap();
            if count >= minimum || Instant::now() >= deadline {
                return count;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn wake_pair_sends_and_drains_saturated_datagrams() {
        let (sender, receiver) = WakePair::new().unwrap().split();
        assert_eq!(sender.signal().unwrap(), WakeSignal::Sent);
        assert!(drain_until(&receiver, 1) >= 1);
        assert_eq!(receiver.drain().unwrap(), 0);
        for _ in 0..10_000 {
            match sender.signal().unwrap() {
                WakeSignal::Sent => {}
                WakeSignal::Retry => break,
                WakeSignal::Closed => panic!("wake receiver closed while it is open"),
            }
        }
        assert!(drain_until(&receiver, 1) >= 1);
        assert_eq!(sender.signal().unwrap(), WakeSignal::Sent);
        assert!(drain_until(&receiver, 1) >= 1);
    }

    #[test]
    fn wake_types_are_thread_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WakeSender>();
        assert_send_sync::<WakeReceiver>();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::windows::io::{AsRawSocket, RawSocket};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    fn socket_id(raw: RawSocket) -> SocketId {
        SocketId::from_raw_socket(raw)
    }

    #[test]
    fn loopback_tcp_wait_reports_readable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.write_all(b"x").unwrap();
        let mut set = WaitSet::new();
        set.insert(socket_id(client.as_raw_socket()), Interest::READABLE)
            .unwrap();
        let outcome = set
            .wait(Duration::from_secs(2), &AtomicBool::new(false))
            .unwrap();
        let WaitOutcome::Ready(events) = outcome else {
            panic!("readable socket did not report ready: {outcome:?}");
        };
        assert_eq!(events.len(), 1);
        assert!(events[0].ready.contains(Ready::READABLE));
        let mut byte = [0u8; 1];
        client.take_error().unwrap();
        let mut client = client;
        client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
    }

    #[test]
    fn nonblocking_connect_completes_with_so_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let audit = crate::normalization::Audit::default();
        let stream =
            crate::normalization::tcp_start(listener.local_addr().unwrap(), None, &audit).unwrap();
        let mut set = WaitSet::new();
        set.insert(socket_id(stream.as_raw_socket()), Interest::WRITABLE)
            .unwrap();
        let outcome = set
            .wait(Duration::from_secs(2), &AtomicBool::new(false))
            .unwrap();
        let WaitOutcome::Ready(events) = outcome else {
            panic!("connect did not report ready: {outcome:?}");
        };
        assert_eq!(events.len(), 1);
        match check_connect(&stream, events[0].ready).unwrap() {
            ConnectCheck::Connected => {}
            ConnectCheck::Failed(error) => panic!("loopback connect failed: {error}"),
            ConnectCheck::Pending => panic!("loopback connect is still pending"),
        }
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(audit.snapshot(), (1, 0));
    }

    #[test]
    fn refused_connect_reports_the_socket_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let audit = crate::normalization::Audit::default();
        let stream = crate::normalization::tcp_start(address, None, &audit).unwrap();
        let mut set = WaitSet::new();
        set.insert(socket_id(stream.as_raw_socket()), Interest::WRITABLE)
            .unwrap();
        let started = Instant::now();
        let outcome = set
            .wait(Duration::from_secs(10), &AtomicBool::new(false))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        let WaitOutcome::Ready(events) = outcome else {
            panic!("refused connect did not report ready: {outcome:?}");
        };
        let check = check_connect(&stream, events[0].ready).unwrap();
        match check {
            ConnectCheck::Failed(error) => {
                assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
            }
            ConnectCheck::Connected => panic!("closed loopback port reported a connection"),
            ConnectCheck::Pending => panic!("closed loopback port left the connect pending"),
        }
    }

    #[test]
    fn wait_set_handles_more_than_sixty_four_sockets() {
        let sockets = (0..70)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let mut set = WaitSet::new();
        for socket in &sockets {
            set.insert(socket_id(socket.as_raw_socket()), Interest::WRITABLE)
                .unwrap();
        }
        let outcome = set
            .wait(Duration::from_secs(2), &AtomicBool::new(false))
            .unwrap();
        let WaitOutcome::Ready(events) = outcome else {
            panic!("writable sockets did not report ready: {outcome:?}");
        };
        assert_eq!(events.len(), sockets.len());
        assert!(events
            .iter()
            .all(|event| event.ready.contains(Ready::WRITABLE)));
    }

    #[test]
    fn wake_interrupts_a_blocked_wait() {
        let (sender, receiver) = WakePair::new().unwrap().split();
        let wake_id = receiver.socket_id();
        let mut set = WaitSet::new();
        set.insert(wake_id, Interest::READABLE).unwrap();
        let started = Instant::now();
        let producer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            sender.signal().unwrap();
        });
        let outcome = set
            .wait(Duration::from_secs(2), &AtomicBool::new(false))
            .unwrap();
        producer.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        let WaitOutcome::Ready(events) = outcome else {
            panic!("wake did not interrupt the wait: {outcome:?}");
        };
        assert!(events
            .iter()
            .any(|event| event.socket == wake_id && event.ready.contains(Ready::READABLE)));
        assert!(receiver.drain().unwrap() >= 1);
    }

    #[test]
    fn a_wake_is_not_lost_when_it_arrives_before_the_wait() {
        let (sender, receiver) = WakePair::new().unwrap().split();
        let wake_id = receiver.socket_id();
        let mut set = WaitSet::new();
        set.insert(wake_id, Interest::READABLE).unwrap();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let done = Arc::new(AtomicBool::new(false));
        let producer = {
            let queue = queue.clone();
            let done = done.clone();
            thread::spawn(move || {
                for value in 0..500u64 {
                    queue.lock().unwrap().push_back(value);
                    sender.signal().unwrap();
                }
                done.store(true, Ordering::Release);
                sender.signal().unwrap();
            })
        };
        let stop = AtomicBool::new(false);
        let mut seen = Vec::new();
        while !done.load(Ordering::Acquire) || !queue.lock().unwrap().is_empty() {
            match set.wait(Duration::from_secs(2), &stop).unwrap() {
                WaitOutcome::Ready(events) => {
                    assert!(events.iter().any(|event| event.socket == wake_id));
                    let _ = receiver.drain().unwrap();
                }
                WaitOutcome::TimedOut => panic!("wake was lost"),
                WaitOutcome::Cancelled => panic!("unexpected cancellation"),
            }
            let mut queue = queue.lock().unwrap();
            while let Some(value) = queue.pop_front() {
                seen.push(value);
            }
        }
        producer.join().unwrap();
        assert_eq!(seen, (0..500u64).collect::<Vec<_>>());
    }

    #[test]
    fn stop_cancels_a_wait_within_the_slice() {
        let stopped = Arc::new(AtomicBool::new(false));
        let setter = {
            let stopped = stopped.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                stopped.store(true, Ordering::Release);
            })
        };
        let set = WaitSet::new();
        let started = Instant::now();
        let outcome = set.wait(Duration::from_secs(5), &stopped).unwrap();
        setter.join().unwrap();
        assert_eq!(outcome, WaitOutcome::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn empty_wait_set_times_out() {
        let set = WaitSet::new();
        let outcome = set
            .wait(Duration::from_millis(30), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(outcome, WaitOutcome::TimedOut);
    }

    #[test]
    fn a_native_wait_times_out() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut set = WaitSet::new();
        set.insert(socket_id(socket.as_raw_socket()), Interest::READABLE)
            .unwrap();
        let outcome = set
            .wait(Duration::from_millis(30), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(outcome, WaitOutcome::TimedOut);
    }

    #[test]
    fn stop_cancels_a_native_wait_within_the_slice() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut set = WaitSet::new();
        set.insert(socket_id(socket.as_raw_socket()), Interest::READABLE)
            .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let setter = {
            let stopped = stopped.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                stopped.store(true, Ordering::Release);
            })
        };
        let started = Instant::now();
        let outcome = set.wait(Duration::from_secs(5), &stopped).unwrap();
        setter.join().unwrap();
        assert_eq!(outcome, WaitOutcome::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_bad_socket_handle_fails_closed() {
        assert!(SocketId::from_raw_socket(RawSocket::MAX).is_invalid());
        let mut set = WaitSet::new();
        assert!(set.insert(SocketId::INVALID, Interest::READABLE).is_err());
        set.insert(socket_id(1), Interest::READABLE).unwrap();
        let error = set
            .wait(Duration::from_secs(1), &AtomicBool::new(false))
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::BrokenPipe | ErrorKind::InvalidInput
        ));
    }
}
