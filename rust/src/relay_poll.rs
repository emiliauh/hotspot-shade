//! Portable readiness waits and wake channels for the relay.
//!
//! The relay waits on a set of sockets and wakes a waiting worker. This module
//! holds those two operations. It holds no tunnel code.
//!
//! # Platforms
//!
//! On Unix, [`PollSet`] wraps `libc::poll`. It keeps the behavior of the relay
//! code that it replaces.
//!
//! On Windows, [`PollSet`] wraps [`crate::windows_relay_wait::WaitSet`], which
//! uses `WSAPoll`. The set has no 64-socket limit.
//!
//! # Readiness is advisory
//!
//! A ready bit does not prove that the next read or write completes. Read the
//! socket result and handle `WouldBlock` and end of file. A failed nonblocking
//! connect can appear as writable. Read `SO_ERROR` before you use the stream.
//!
//! # Wake channel
//!
//! [`WakePair`] is a local control channel. It is not an outer socket and it
//! carries no tunnel data. On Unix it is a `UnixStream` pair. Windows has no
//! `UnixStream::pair`, so that platform uses a connected UDP pair on
//! `127.0.0.1`.
//!
//! A successful signal does not prove delivery on the Windows channel. The
//! caller must recheck its work queue after every wait, including a timeout.
//! The relay uses a bounded wait for this reason.
//!
//! # Socket lifetime
//!
//! Build the set from live sockets. Do not keep an entry after its socket
//! closes. A Windows wait can fail with `BrokenPipe` or `InvalidInput` when a
//! socket in the set closes. Drop the set and build it again.

use std::io;
use std::time::Duration;

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
#[cfg(windows)]
use std::sync::atomic::AtomicBool;

#[cfg(unix)]
mod platform {
    use super::{AsRawFd, RawFd};

    /// The native socket value for one wait.
    pub type RawHandle = RawFd;

    /// A socket value that a [`super::PollSet`] can wait on.
    pub trait AsSocketHandle {
        /// Return the native socket value.
        fn socket_handle(&self) -> RawHandle;
    }

    impl<T: AsRawFd + ?Sized> AsSocketHandle for T {
        fn socket_handle(&self) -> RawHandle {
            self.as_raw_fd()
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{AsRawSocket, RawSocket};

    /// The native socket value for one wait.
    pub type RawHandle = RawSocket;

    /// A socket value that a [`super::PollSet`] can wait on.
    pub trait AsSocketHandle {
        /// Return the native socket value.
        fn socket_handle(&self) -> RawHandle;
    }

    impl<T: AsRawSocket + ?Sized> AsSocketHandle for T {
        fn socket_handle(&self) -> RawHandle {
            self.as_raw_socket()
        }
    }
}

pub use platform::{AsSocketHandle, RawHandle};

/// Return the native socket value for one socket.
pub fn handle<T: AsSocketHandle + ?Sized>(socket: &T) -> RawHandle {
    socket.socket_handle()
}

/// The state that a caller asks one wait to report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interest(u8);

impl Interest {
    /// No state. A wait skips an empty interest.
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

impl std::ops::BitOrAssign for Interest {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.union(other);
    }
}

/// The state that one wait reports for one socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ready(u8);

impl Ready {
    /// No state.
    pub const NONE: Self = Self(0);
    /// Normal data can be read.
    pub const READABLE: Self = Self(1 << 0);
    /// Normal data can be written.
    pub const WRITABLE: Self = Self(1 << 1);
    /// The socket reported an error.
    pub const ERROR: Self = Self(1 << 2);
    /// The peer disconnected or aborted the stream. This bit can arrive with
    /// `READABLE`. Read the pending data before you close the stream.
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

impl std::ops::BitOrAssign for Ready {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.union(other);
    }
}

/// Convert a timeout to the millisecond value of one wait.
///
/// A positive value rounds down. A value above `i32::MAX` is capped.
#[cfg(unix)]
fn timeout_millis(timeout: Duration) -> i32 {
    timeout.as_millis().min(i32::MAX as u128) as i32
}

/// A set of sockets for one readiness wait.
///
/// Call [`PollSet::clear`] and add the live sockets again after a flow changes.
/// One socket can appear once in a Windows set.
pub struct PollSet {
    #[cfg(unix)]
    fds: Vec<libc::pollfd>,
    #[cfg(windows)]
    set: crate::windows_relay_wait::WaitSet,
    #[cfg(windows)]
    handles: Vec<crate::windows_relay_wait::SocketId>,
    #[cfg(windows)]
    ready: Vec<Ready>,
}

impl Default for PollSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl PollSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create an empty set with room for `capacity` sockets.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            fds: Vec::with_capacity(capacity),
        }
    }

    /// Return the number of sockets in the set.
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Return true when the set has no socket.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// Remove every entry.
    pub fn clear(&mut self) {
        self.fds.clear();
    }

    /// Add one native socket value and its interest. Return its index.
    pub fn push_handle(&mut self, handle: RawHandle, interest: Interest) -> io::Result<usize> {
        let index = self.fds.len();
        self.fds.push(libc::pollfd {
            fd: handle,
            events: interest.poll_events(),
            revents: 0,
        });
        Ok(index)
    }

    /// Add one socket and its interest. Return its index.
    pub fn push<T: AsSocketHandle + ?Sized>(
        &mut self,
        socket: &T,
        interest: Interest,
    ) -> io::Result<usize> {
        self.push_handle(handle(socket), interest)
    }

    /// Wait for one socket state or a timeout.
    ///
    /// A zero timeout performs one nonblocking check. The call reports an
    /// interrupted wait as `io::ErrorKind::Interrupted`.
    pub fn wait(&mut self, timeout: Duration) -> io::Result<usize> {
        let count = unsafe {
            libc::poll(
                self.fds.as_mut_ptr(),
                self.fds.len() as libc::nfds_t,
                timeout_millis(timeout),
            )
        };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    /// Return the state that the last wait reported for one index.
    pub fn ready(&self, index: usize) -> Ready {
        self.fds
            .get(index)
            .map(|fd| Ready::from_revents(fd.revents))
            .unwrap_or_default()
    }
}

#[cfg(unix)]
impl Interest {
    /// Convert the interest to the `poll` event bits.
    fn poll_events(self) -> i16 {
        let mut events = 0;
        if self.contains(Self::READABLE) {
            events |= libc::POLLIN;
        }
        if self.contains(Self::WRITABLE) {
            events |= libc::POLLOUT;
        }
        events
    }
}

#[cfg(unix)]
impl Ready {
    /// Convert the `poll` result bits to a ready state.
    fn from_revents(revents: i16) -> Self {
        let mut ready = Self::NONE;
        if revents & libc::POLLIN != 0 {
            ready |= Self::READABLE;
        }
        if revents & libc::POLLOUT != 0 {
            ready |= Self::WRITABLE;
        }
        if revents & libc::POLLERR != 0 {
            ready |= Self::ERROR;
        }
        if revents & libc::POLLHUP != 0 {
            ready |= Self::HANGUP;
        }
        if revents & libc::POLLNVAL != 0 {
            ready |= Self::INVALID;
        }
        ready
    }
}

// The Windows wait has no stop flag in this use. The relay uses a bounded
// timeout, so a stop request ends the wait at the next timeout.
#[cfg(windows)]
static NEVER_STOP: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
impl PollSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create an empty set with room for `capacity` sockets.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            set: crate::windows_relay_wait::WaitSet::with_capacity(capacity),
            handles: Vec::with_capacity(capacity),
            ready: Vec::new(),
        }
    }

    /// Return the number of sockets in the set.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Return true when the set has no socket.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Remove every entry.
    pub fn clear(&mut self) {
        self.set.clear();
        self.handles.clear();
        self.ready.clear();
    }

    /// Add one socket value and its interest. Return its index.
    ///
    /// The call rejects an invalid socket value, an empty interest, and a
    /// socket that is already in the set.
    pub fn push_handle(&mut self, handle: RawHandle, interest: Interest) -> io::Result<usize> {
        let socket = crate::windows_relay_wait::SocketId::from_raw_socket(handle);
        self.set.insert(socket, interest.backend())?;
        let index = self.handles.len();
        self.handles.push(socket);
        Ok(index)
    }

    /// Add one socket and its interest. Return its index.
    pub fn push<T: AsSocketHandle + ?Sized>(
        &mut self,
        socket: &T,
        interest: Interest,
    ) -> io::Result<usize> {
        self.push_handle(handle(socket), interest)
    }

    /// Wait for one socket state or a timeout.
    ///
    /// A zero timeout performs one nonblocking check. The call reports a
    /// closed socket in the set as `io::ErrorKind::BrokenPipe` or
    /// `io::ErrorKind::InvalidInput`.
    pub fn wait(&mut self, timeout: Duration) -> io::Result<usize> {
        self.ready.clear();
        let outcome = self.set.wait(timeout, &NEVER_STOP)?;
        let crate::windows_relay_wait::WaitOutcome::Ready(events) = outcome else {
            return Ok(0);
        };
        self.ready.resize(self.handles.len(), Ready::default());
        for event in events {
            if let Some(index) = self.handles.iter().position(|id| *id == event.socket) {
                self.ready[index] = Ready::from_backend(event.ready);
            }
        }
        Ok(self.ready.iter().filter(|ready| !ready.is_empty()).count())
    }

    /// Return the state that the last wait reported for one index.
    pub fn ready(&self, index: usize) -> Ready {
        self.ready.get(index).copied().unwrap_or_default()
    }
}

#[cfg(windows)]
impl Interest {
    /// Convert the interest to the wait set interest.
    fn backend(self) -> crate::windows_relay_wait::Interest {
        use crate::windows_relay_wait::Interest as Backend;
        let mut interest = Backend::NONE;
        if self.contains(Self::READABLE) {
            interest = interest | Backend::READABLE;
        }
        if self.contains(Self::WRITABLE) {
            interest = interest | Backend::WRITABLE;
        }
        interest
    }
}

#[cfg(windows)]
impl Ready {
    /// Convert a wait set state to a ready state.
    fn from_backend(ready: crate::windows_relay_wait::Ready) -> Self {
        use crate::windows_relay_wait::Ready as Backend;
        let mut result = Self::NONE;
        if ready.contains(Backend::READABLE) {
            result |= Self::READABLE;
        }
        if ready.contains(Backend::WRITABLE) {
            result |= Self::WRITABLE;
        }
        if ready.contains(Backend::ERROR) {
            result |= Self::ERROR;
        }
        if ready.contains(Backend::HANGUP) {
            result |= Self::HANGUP;
        }
        if ready.contains(Backend::INVALID) {
            result |= Self::INVALID;
        }
        result
    }
}

/// A local wake channel.
///
/// Both halves bind or connect to the loopback address only. The channel makes
/// no route change and uses no external address. It is not an outer socket.
pub struct WakePair {
    sender: WakeSender,
    receiver: WakeReceiver,
}

impl WakePair {
    /// Create one wake pair.
    pub fn new() -> io::Result<Self> {
        Self::create()
    }

    /// Split the pair into one sender and one receiver.
    pub fn split(self) -> (WakeSender, WakeReceiver) {
        (self.sender, self.receiver)
    }
}

/// The sending half of a local wake channel.
///
/// The type is thread safe. Any number of producers can signal the same
/// receiver.
#[cfg(unix)]
pub struct WakeSender {
    stream: UnixStream,
}

/// The receiving half of a local wake channel.
#[cfg(unix)]
pub struct WakeReceiver {
    stream: UnixStream,
}

#[cfg(unix)]
impl WakePair {
    fn create() -> io::Result<Self> {
        let (receiver, sender) = UnixStream::pair()?;
        receiver.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        Ok(Self {
            sender: WakeSender { stream: sender },
            receiver: WakeReceiver { stream: receiver },
        })
    }
}

#[cfg(unix)]
impl WakeSender {
    /// Signal the receiver.
    ///
    /// The call ignores a full or closed channel. The receiver rechecks its
    /// work queue after every bounded wait.
    pub fn signal(&self) {
        let _ = (&self.stream).write(&[1]);
    }

    /// Release the channel. A wait on the receiver ends.
    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(unix)]
impl WakeReceiver {
    /// Remove every pending signal.
    pub fn drain(&self) {
        let mut buffer = [0u8; 256];
        while (&self.stream)
            .read(&mut buffer)
            .is_ok_and(|count| count > 0)
        {}
    }

    /// Return the native socket value for a [`PollSet`].
    pub fn handle(&self) -> RawHandle {
        self.stream.as_raw_fd()
    }
}

/// The sending half of a local wake channel.
#[cfg(windows)]
pub struct WakeSender {
    inner: crate::windows_relay_wait::WakeSender,
}

/// The receiving half of a local wake channel.
#[cfg(windows)]
pub struct WakeReceiver {
    inner: crate::windows_relay_wait::WakeReceiver,
}

#[cfg(windows)]
impl WakePair {
    fn create() -> io::Result<Self> {
        let (sender, receiver) = crate::windows_relay_wait::WakePair::new()?.split();
        Ok(Self {
            sender: WakeSender { inner: sender },
            receiver: WakeReceiver { inner: receiver },
        })
    }
}

#[cfg(windows)]
impl WakeSender {
    /// Signal the receiver.
    ///
    /// Delivery is not guaranteed. The call ignores a retry request and a
    /// closed receiver. The receiver rechecks its work queue after every
    /// bounded wait.
    pub fn signal(&self) {
        let _ = self.inner.signal();
    }

    /// Wake the receiver so that a wait ends at its next loop check.
    pub fn shutdown(&self) {
        let _ = self.inner.signal();
    }
}

#[cfg(windows)]
impl WakeReceiver {
    /// Remove every pending signal.
    pub fn drain(&self) {
        let _ = self.inner.drain();
    }

    /// Return the native socket value for a [`PollSet`].
    pub fn handle(&self) -> RawHandle {
        self.inner.socket_id().as_raw_socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::time::Instant;

    #[test]
    fn interest_bits_combine() {
        let both = Interest::READABLE | Interest::WRITABLE;
        assert!(both.contains(Interest::READABLE));
        assert!(both.contains(Interest::WRITABLE));
        assert!(both.contains(both));
        assert!(both.contains(Interest::NONE));
        assert!(Interest::NONE.is_empty());
        assert!(!Interest::READABLE.is_empty());
        let mut value = Interest::NONE;
        value |= Interest::WRITABLE;
        assert_eq!(value, Interest::WRITABLE);
    }

    #[test]
    fn ready_failure_covers_error_hangup_and_invalid() {
        assert!(!Ready::READABLE.is_failure());
        assert!(!Ready::WRITABLE.is_failure());
        assert!(!Ready::default().is_failure());
        for ready in [Ready::ERROR, Ready::HANGUP, Ready::INVALID] {
            assert!(ready.is_failure(), "{ready:?}");
        }
        assert!((Ready::READABLE | Ready::ERROR).is_failure());
        assert!((Ready::READABLE | Ready::WRITABLE).contains(Ready::READABLE));
        let mut value = Ready::NONE;
        value |= Ready::HANGUP;
        assert_eq!(value, Ready::HANGUP);
    }

    #[test]
    fn a_wait_times_out_without_a_ready_socket() {
        let mut set = PollSet::with_capacity(1);
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        set.push(&socket, Interest::READABLE).unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        assert_eq!(set.wait(Duration::from_millis(20)).unwrap(), 0);
        assert!(set.ready(0).is_empty());
        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn a_wait_reports_a_readable_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut set = PollSet::with_capacity(1);
        set.push(&client, Interest::READABLE).unwrap();
        assert_eq!(set.wait(Duration::from_millis(20)).unwrap(), 0);
        peer.set_nonblocking(true).unwrap();
        use std::io::Write;
        peer.write_all(b"x").unwrap();
        assert_eq!(set.wait(Duration::from_secs(2)).unwrap(), 1);
        assert!(set.ready(0).contains(Ready::READABLE));
        drop(peer);
    }

    /// Wait for one wake signal. A loopback datagram can arrive after `send`
    /// returns, so the test retries with a deadline.
    fn wait_for_wake(receiver: &WakeReceiver) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut set = PollSet::with_capacity(1);
        set.push_handle(receiver.handle(), Interest::READABLE)
            .unwrap();
        while Instant::now() < deadline {
            if set.wait(Duration::from_millis(20)).unwrap() > 0 {
                return true;
            }
        }
        false
    }

    #[test]
    fn a_wake_signal_interrupts_a_wait_and_drains() {
        let (sender, receiver) = WakePair::new().unwrap().split();
        sender.signal();
        assert!(wait_for_wake(&receiver), "wake signal did not arrive");
        // Keep the sender open. A closed sender makes the receiver readable
        // with end of file, which is not a pending signal.
        receiver.drain();
        assert_eq!(
            {
                let mut set = PollSet::with_capacity(1);
                set.push_handle(receiver.handle(), Interest::READABLE)
                    .unwrap();
                set.wait(Duration::from_millis(30)).unwrap()
            },
            0
        );
        drop(sender);
    }
}
