//! Engine-side control transport for a future desktop shell.
//!
//! This module is a foundation. It is not wired into the service, the web GUI,
//! or the desktop demo. It opens no listener, changes no route, and touches no
//! device.
//!
//! # Security model
//!
//! The desktop shell gives the engine three private operating-system channels:
//!
//! - One duplex byte channel for control frames.
//! - One read-only channel for parent liveness. The shell holds the write end
//!   for its whole life and writes no bytes.
//! - One private descriptor for a per-launch session key.
//!
//! The key never crosses the control channel. The engine sends a challenge. The
//! shell proves that it holds the key with one HMAC answer. The engine answers
//! with its own proof. Every request then travels on the same continuous
//! channel. There is no second listener, no port, no port file, and no HTTP
//! bearer request. A process that reuses a port cannot join a session.
//!
//! The channels are the authentication boundary. The shell must create them
//! with no access for an unrelated process. The shell must close its copies on
//! quit. Do not pass a channel to another child process. A leaked write handle
//! keeps a channel open after the shell exits. The engine then cannot see
//! end-of-file.
//!
//! The protocol authenticates the peer. It does not encrypt frames. The private
//! operating-system channels protect the bytes.
//!
//! The engine watches the liveness channel on its own thread. A clean
//! end-of-file means the parent is gone. The engine must then run its normal
//! stop path and remove its routes and devices. The control frames and the
//! liveness check never share a read. See "Parent liveness" below.
//!
//! # Wire format
//!
//! Each frame has one fixed 16-byte header and a bounded payload:
//!
//! ```text
//! [magic 4][version 1][kind 1][flags 1][reserved 1][id 4][length 4][payload]
//! ```
//!
//! `magic` is `HSDC`. The version is 1. `flags` and `reserved` must be zero.
//! `id` and `length` are big-endian. The length is the payload length. The
//! server reads at most 64 payload bytes for a request. It writes at most 64
//! KiB for a response. It rejects a bad magic, a bad version, an unknown kind,
//! a nonzero flag, a hostile length, and a partial frame. It sends one fixed
//! error code and closes the channel.
//!
//! Frame kinds:
//!
//! | Kind | Direction | Payload |
//! |---|---|---|
//! | 1 `Challenge` | engine to shell | 32-byte server nonce |
//! | 2 `Hello` | shell to engine | 32-byte client nonce, 32-byte HMAC |
//! | 3 `Ready` | engine to shell | 32-byte HMAC |
//! | 4 `Request` | shell to engine | command byte and fixed fields |
//! | 5 `Response` | engine to shell | status byte, then JSON or an error code |
//! | 6 `Fatal` | engine to shell | one error code |
//!
//! A request identifier is never zero. It must increase for each request in one
//! session. A repeated identifier is a protocol fault.
//!
//! The command payload is binary and strictly sized. The allowlist is
//! [`ControlCommand`]. It has no host, port, token, path, or process field.
//! A request cannot name a destination. A future handler uses the stored
//! pairing state only.
//!
//! Manual source device token entry is not in this foundation. That fallback
//! needs a separate design that keeps the token out of responses, errors, and
//! logs. Do not add a free-form token field to this transport without it.
//! Direct mode and its explicit IPv6 policy are also not represented yet. Add
//! them before using this protocol for a full target app.
//!
//! A successful response carries status byte 0 and one JSON object. The engine
//! redacts fields named like a credential. It never returns a handler error
//! string. An error response carries status byte 1 and one fixed error code.
//!
//! # Integration contract
//!
//! The shell must do this work before the engine can use the transport:
//!
//! 1. Create one private duplex channel for control frames and one private
//!    read-only channel for parent liveness. Give no access to an unrelated
//!    process. On Unix, use `O_CLOEXEC`, or set `FD_CLOEXEC`. On Windows, use
//!    non-inheritable handles.
//! 2. Generate a 32-byte session key with an operating-system random source.
//! 3. Pass the key on a separate private descriptor as 64 lowercase hex bytes
//!    and one newline. Do not use a command line or an environment variable.
//!    The key is not the HTTP bearer secret. See "Key separation" below.
//! 4. Keep the write end of the liveness channel open for the life of the
//!    shell. Write no bytes. Close it when the shell quits.
//! 5. Read the key with [`read_session_key`]. Start
//!    [`ControlServer::supervise`] on a dedicated thread with the control
//!    channel, the liveness channel, the key, one [`CancelToken`], and a grace
//!    period. Use [`SUPERVISOR_GRACE`] in the service.
//! 6. Read [`SupervisedOutcome`]. Exit the engine process after every return.
//!    A clean stop reports cleanup success. It does not mean the session can
//!    continue or that helper threads have exited.
//! 7. Close the control channel when the shell quits. Never give a channel or
//!    the key to the webview.
//!
//! Keep one set of channels for the life of the shell process. Do not close
//! them when one window closes. A menu bar app can outlive its main window.
//!
//! The shell must map fixed UI actions to fixed [`ControlCommand`] values. It
//! must not accept a command name, URL, host, or free-form body from the page.
//! Do not add a generic bridge.
//!
//! The handler `shutdown` method covers a closed channel and a protocol fault.
//! It does not replace the signal path. The engine must still stop the service
//! on SIGINT and SIGTERM and remove its routes.
//!
//! # Parent liveness
//!
//! The shell gives the engine a second private channel for liveness. The engine
//! watches that channel on a dedicated thread. End-of-file and a read error
//! count as parent loss. A read error counts as loss because the engine cannot
//! prove that the parent is alive. Bytes on the liveness channel are ignored.
//!
//! [`ControlServer::supervise`] runs the session on a worker thread. A second
//! thread reads control frames. A partial frame blocks only that thread, so the
//! session loop can observe a cancel request. The supervisor waits for one of
//! three events:
//!
//! - The worker stops and reports a [`ServeOutcome`].
//! - The liveness channel reports parent loss.
//! - The engine requests [`CancelReason::LocalStop`].
//!
//! A cancel request sets one [`CancelToken`]. The token holds the first reason.
//! The worker checks the token between frame reads, before each handler call,
//! and before each response write. The supervisor waits a bounded grace period
//! for the worker to stop. [`SESSION_POLL_INTERVAL`] is the fixed poll interval.
//!
//! The supervisor returns no later than one poll interval plus the grace period
//! after the liveness channel closes, unless the scheduler delays a thread. That
//! bound is a report deadline. It is not a cleanup guarantee.
//!
//! The supervisor returns one [`SupervisedOutcome`]. Its state is one of:
//!
//! - [`SupervisionState::Stopped`]: the worker stopped and reported its cleanup
//!   result.
//! - [`SupervisionState::Parked`]: the worker did not stop inside the grace
//!   period. Cleanup did not complete. [`SupervisedOutcome::cleanup`] is
//!   [`CleanupOutcome::Unfinished`]. The engine must exit the process.
//! - [`SupervisionState::Lost`]: the worker thread ended with no result. The
//!   engine cannot know whether cleanup ran. It must exit the process.
//! - [`SupervisionState::NotStarted`]: the supervisor could not start a
//!   thread. No session ran. The engine must run its stop path and exit.
//!
//! The supervisor does not cancel a blocked handler call. Rust has no portable
//! way to stop a thread that does not return. A handler can observe the token
//! with [`ControlHandler::handle_with_cancel`]. A blocked handler is reported,
//! not forced. The supervisor does not run cleanup on a second thread while a
//! handler is in flight. A late handler return could change service state after
//! cleanup. The supervisor never restarts a session. Do not add a restart loop.
//!
//! The supervisor adds no keepalive deadline. Only parent loss and a local stop
//! request end a session. A caller that needs a deadline must run its own
//! watchdog and request [`CancelReason::LocalStop`].
//!
//! [`PARENT_LIVENESS_ENFORCED`] is false. The transport observes parent loss
//! independently and always reports inside a bound. It cannot guarantee that a
//! blocked handler call returns or that cleanup ran.
//! [`CLEANUP_GUARANTEED`] is false. [`SERVICE_REQUIREMENTS`] lists the work that
//! the service integration must finish. [`ControlServer::new_for_service`]
//! fails closed.
//!
//! On Unix, the engine must ignore `SIGPIPE`. A write to a closed control pipe
//! must return an error so the cleanup path can run. A `SIGPIPE` default action
//! stops the process and skips cleanup. The panic guard needs a build with
//! unwinding. A `panic = "abort"` build stops the process and runs no cleanup.
//!
//! # Descriptor rules
//!
//! On Unix, create the control channel, the liveness channel, and the key
//! descriptor with `O_CLOEXEC`, or set `FD_CLOEXEC` before another thread
//! starts. On Windows, create non-inheritable handles and keep an explicit
//! handle list. Pass only those handles to the engine. A descriptor inherited
//! by an unrelated child can keep a channel open after the shell exits. A child
//! can also read the key descriptor. The shell must close its copies on quit.
//! The engine must not give a descriptor to a helper, a tunnel worker, or the
//! webview.
//!
//! # Key separation
//!
//! The session key is not the HTTP bearer secret and not the source device
//! token. Do not derive one from another. Do not store the session key in the
//! GUI, an environment variable, a command line, or an HTTP header. The key
//! descriptor carries the key from the shell to the engine only.
//!
//! # Redaction limits
//!
//! Redaction matches field names. It does not inspect values. A secret with an
//! unknown field name, inside a string value, or in a log text passes through.
//! Redaction is a final guard. It is not data-loss prevention. A handler must
//! not put a credential in a response at all. Do not depend on redaction for
//! the source device token, the identity key, or the session key.
//!
//! This module does not create the pipes, read the descriptor, start the
//! engine, stop the tunnel, or remove routes. The desktop shell does not use
//! this transport today. Its README states that the real service is not
//! connected. Do not wire this transport to the real service while
//! [`PARENT_LIVENESS_ENFORCED`] is false.
//!
//! [`serve`]: ControlServer::serve

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::{self, Debug};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: [u8; 4] = *b"HSDC";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16;
const NONCE_LEN: usize = 32;
const PROOF_LEN: usize = 32;
const HELLO_LEN: usize = NONCE_LEN + PROOF_LEN;

/// The length of one session key in bytes.
pub const SESSION_KEY_LEN: usize = 32;
/// The length of the session key text form, without the newline.
pub const SESSION_KEY_TEXT_LEN: usize = SESSION_KEY_LEN * 2;
/// The largest request payload that the server accepts.
pub const MAX_REQUEST_PAYLOAD: usize = 64;
/// The largest response payload that the server writes.
pub const MAX_RESPONSE_PAYLOAD: usize = 64 * 1024;

const HANDSHAKE_MAX_PAYLOAD: usize = HELLO_LEN;
const HELLO_LABEL: &[u8] = b"hotspotshade-desktop-control-v1/hello";
const READY_LABEL: &[u8] = b"hotspotshade-desktop-control-v1/ready";

/// The largest payload that any inbound frame may carry.
const INBOUND_MAX_PAYLOAD: usize = if MAX_REQUEST_PAYLOAD > HANDSHAKE_MAX_PAYLOAD {
    MAX_REQUEST_PAYLOAD
} else {
    HANDSHAKE_MAX_PAYLOAD
};

/// The interval between cancellation checks on one session.
///
/// This interval bounds the delay between a cancel request and the session
/// loop that observes it.
pub const SESSION_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The default grace period for a worker to stop and report cleanup.
///
/// The supervisor returns after this period even when the worker is parked.
/// Use this value in the service. A test may pass a shorter value.
pub const SUPERVISOR_GRACE: Duration = Duration::from_secs(5);

/// A fixed control error. It carries no backend text and no input value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// The shell does not hold the session key.
    Unauthorized,
    /// The frame or command is not valid.
    Protocol,
    /// The service is not ready.
    Unavailable,
    /// Another operation is in progress.
    Busy,
    /// The service refused the operation.
    Refused,
    /// The command is not supported.
    Unsupported,
    /// The service failed in an unspecified way.
    Internal,
    /// The answer is larger than the protocol limit.
    TooLarge,
    /// The channel is closed.
    Disconnected,
    /// The session key text is not valid.
    InvalidKey,
}

impl ControlError {
    /// A stable machine code. It contains no secret.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Protocol => "protocol",
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::Refused => "refused",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
            Self::TooLarge => "too_large",
            Self::Disconnected => "disconnected",
            Self::InvalidKey => "invalid_key",
        }
    }

    /// Fixed text for a person. It contains no backend text.
    pub fn message(self) -> &'static str {
        match self {
            Self::Unauthorized => "The control session is not authorized.",
            Self::Protocol => "The control protocol failed.",
            Self::Unavailable => "The service is not ready.",
            Self::Busy => "Another operation is in progress.",
            Self::Refused => "The service refused the operation.",
            Self::Unsupported => "The operation is not supported.",
            Self::Internal => "The service could not complete the operation.",
            Self::TooLarge => "The answer is too large.",
            Self::Disconnected => "The control channel is closed.",
            Self::InvalidKey => "The session key is not valid.",
        }
    }

    fn wire_error(self) -> WireError {
        match self {
            Self::Unauthorized | Self::InvalidKey => WireError::Unauthorized,
            Self::Protocol => WireError::Protocol,
            Self::Unavailable => WireError::Unavailable,
            Self::Busy => WireError::Busy,
            Self::Refused => WireError::Refused,
            Self::Unsupported => WireError::Unsupported,
            Self::Internal | Self::Disconnected => WireError::Internal,
            Self::TooLarge => WireError::TooLarge,
        }
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ControlError {}

/// A fixed fault in the control transport. It carries no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFault {
    /// The frame does not start with `HSDC`.
    BadMagic,
    /// The frame version is not 1.
    BadVersion,
    /// The frame kind is not known.
    UnknownFrameKind,
    /// A flag or the reserved byte is not zero.
    BadFlags,
    /// The payload length is above the protocol limit.
    OversizedFrame,
    /// The channel ended inside a frame.
    TruncatedFrame,
    /// The frame kind is not allowed in this state.
    UnexpectedFrame,
    /// A request identifier is zero, repeated, or lower than the last one.
    BadRequestId,
    /// The command byte or the command length is not allowed.
    BadCommand,
    /// The handshake proof does not match the session key.
    Unauthenticated,
    /// A handler panicked. The session stopped.
    HandlerPanicked,
    /// The server caught a panic outside one handler call.
    Panicked,
    /// The channel failed.
    Io,
}

impl ControlFault {
    fn wire_error(self) -> Option<WireError> {
        match self {
            Self::Unauthenticated => Some(WireError::Unauthorized),
            Self::HandlerPanicked | Self::Panicked => Some(WireError::Internal),
            Self::Io => None,
            Self::BadMagic
            | Self::BadVersion
            | Self::UnknownFrameKind
            | Self::BadFlags
            | Self::OversizedFrame
            | Self::TruncatedFrame
            | Self::UnexpectedFrame
            | Self::BadRequestId
            | Self::BadCommand => Some(WireError::Protocol),
        }
    }

    /// Fixed text for a developer. It contains no input bytes.
    pub fn message(self) -> &'static str {
        match self {
            Self::BadMagic => "The control frame header is not valid.",
            Self::BadVersion => "The control protocol version is not supported.",
            Self::UnknownFrameKind => "The control frame kind is not supported.",
            Self::BadFlags => "The control frame flags are not valid.",
            Self::OversizedFrame => "The control frame is too large.",
            Self::TruncatedFrame => "The control frame is incomplete.",
            Self::UnexpectedFrame => "The control frame is not expected now.",
            Self::BadRequestId => "The control request identifier is not valid.",
            Self::BadCommand => "The control command is not allowed.",
            Self::Unauthenticated => "The control session is not authorized.",
            Self::HandlerPanicked => "The control handler stopped on a panic.",
            Self::Panicked => "An unexpected panic stopped the control session.",
            Self::Io => "The control channel failed.",
        }
    }
}

impl fmt::Display for ControlFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ControlFault {}

/// The result of the engine cleanup path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// The handler ran cleanup and reported success.
    Complete,
    /// The handler ran cleanup and reported a fixed failure.
    Failed(ControlError),
    /// The handler panicked during cleanup. The transport discards the panic
    /// payload.
    Panicked,
    /// Cleanup did not return inside the supervisor grace period.
    ///
    /// The service state is unknown. Do not claim that routes and devices are
    /// removed. The engine must exit the process.
    Unfinished,
}

impl CleanupOutcome {
    /// True only when cleanup ran and reported success.
    pub fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// The observed progress of the handler cleanup call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupPhase {
    /// Cleanup has not started.
    Idle,
    /// Cleanup started and has not returned.
    Running,
    /// Cleanup returned, failed, or panicked.
    Finished,
}

/// Why a control session received a cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    /// The independent liveness channel ended or failed.
    ParentLost,
    /// The engine or a signal path requested a process stop.
    ///
    /// This is not the Stop command. The Stop command stops the tunnel and
    /// keeps the session. A local stop ends the session and needs the process
    /// exit path.
    LocalStop,
}

struct CancelState {
    reason: Mutex<Option<CancelReason>>,
    signal: Condvar,
}

/// One shared cancel request for a control session.
///
/// The token holds the first reason. A later request does not replace it. The
/// token holds no key, address, or backend text. `Debug` prints only the
/// reason.
#[derive(Clone)]
pub struct CancelToken(Arc<CancelState>);

impl CancelToken {
    /// Build a token with no cancel request.
    pub fn new() -> Self {
        Self(Arc::new(CancelState {
            reason: Mutex::new(None),
            signal: Condvar::new(),
        }))
    }

    /// Set the first cancel reason. Return true when this call set it.
    pub fn request(&self, reason: CancelReason) -> bool {
        let mut slot = lock(&self.0.reason);
        if slot.is_some() {
            return false;
        }
        *slot = Some(reason);
        drop(slot);
        self.0.signal.notify_all();
        true
    }

    /// Return the first cancel reason.
    pub fn reason(&self) -> Option<CancelReason> {
        *lock(&self.0.reason)
    }

    /// True when a cancel request arrived.
    pub fn is_requested(&self) -> bool {
        self.reason().is_some()
    }

    /// Wait for a cancel request.
    ///
    /// The method returns at once when a request already arrived. It returns
    /// `None` when the timeout ends or the wait wakes without a request. A
    /// caller that must not stop early can call it in a loop.
    pub fn wait(&self, timeout: Duration) -> Option<CancelReason> {
        let state = lock(&self.0.reason);
        if state.is_some() {
            return *state;
        }
        let (state, _) = self
            .0
            .signal
            .wait_timeout(state, timeout)
            .unwrap_or_else(|poison| poison.into_inner());
        *state
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for CancelToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancelToken")
            .field("reason", &self.reason())
            .finish()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Why one server run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeStop {
    /// The parent closed the control channel.
    ParentClosed,
    /// The session received a cancel request on the independent liveness
    /// channel or from the engine.
    Cancelled(CancelReason),
    /// The handler accepted the shutdown command and the reply was written.
    ShutdownRequested,
    /// The handler refused the shutdown command or did not complete it. The
    /// reply was written and the session ended.
    ShutdownRefused(ControlError),
    /// The channel failed or a peer broke the protocol.
    Fault(ControlFault),
}

/// The result of one server run.
///
/// The stop reason and the cleanup result are separate. A parent close, a
/// cancel, or an accepted shutdown is not a clean stop when cleanup fails or
/// panics.
#[must_use = "the engine must run its stop and cleanup path when the control server stops"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeOutcome {
    stop: ServeStop,
    cleanup: CleanupOutcome,
}

impl ServeOutcome {
    fn new(stop: ServeStop, cleanup: CleanupOutcome) -> Self {
        Self { stop, cleanup }
    }

    /// Why the server stopped.
    pub fn stop(self) -> ServeStop {
        self.stop
    }

    /// The result of the handler cleanup path.
    pub fn cleanup(self) -> CleanupOutcome {
        self.cleanup
    }

    /// True only when the session ended by a channel close, a cancel, or an
    /// accepted shutdown, and cleanup completed without an error or a panic.
    pub fn stopped_cleanly(self) -> bool {
        matches!(
            self.stop,
            ServeStop::ParentClosed | ServeStop::Cancelled(_) | ServeStop::ShutdownRequested
        ) && self.cleanup.is_complete()
    }

    /// True when cleanup ran and reported success.
    pub fn cleanup_complete(self) -> bool {
        self.cleanup.is_complete()
    }
}

/// How one supervised control session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionState {
    /// The worker stopped and reported its result.
    Stopped,
    /// The worker did not stop inside the grace period after a cancel request.
    ///
    /// The worker can be inside a handler call, a channel write, or cleanup.
    /// [`SupervisedOutcome::cleanup_phase`] tells whether cleanup started.
    Parked,
    /// The worker thread ended with no result.
    Lost,
    /// The supervisor could not start a thread. No session ran.
    NotStarted,
}

/// The result of [`ControlServer::supervise`].
///
/// The state and the cleanup result are separate. Only
/// [`SupervisionState::Stopped`] carries a cleanup result from the worker. A
/// parked, lost, or unstarted session reports
/// [`CleanupOutcome::Unfinished`], because the engine did not observe a
/// completed cleanup. Do not claim that routes and devices are removed in that
/// case.
#[must_use = "the engine must read the supervision state and exit after every return"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisedOutcome {
    state: SupervisionState,
    stop: Option<ServeOutcome>,
    cancel: Option<CancelReason>,
    cleanup_phase: CleanupPhase,
    waited: Duration,
}

impl SupervisedOutcome {
    fn stopped(
        stop: ServeOutcome,
        cancel: Option<CancelReason>,
        cleanup_phase: CleanupPhase,
        waited: Duration,
    ) -> Self {
        Self {
            state: SupervisionState::Stopped,
            stop: Some(stop),
            cancel,
            cleanup_phase,
            waited,
        }
    }

    fn halted(
        state: SupervisionState,
        cancel: Option<CancelReason>,
        cleanup_phase: CleanupPhase,
        waited: Duration,
    ) -> Self {
        debug_assert_ne!(state, SupervisionState::Stopped);
        Self {
            state,
            stop: None,
            cancel,
            cleanup_phase,
            waited,
        }
    }

    /// How the supervised session ended.
    pub fn state(self) -> SupervisionState {
        self.state
    }

    /// The worker result. It is `None` when the worker did not stop.
    pub fn stop(self) -> Option<ServeOutcome> {
        self.stop
    }

    /// The first cancel reason that the supervisor observed.
    pub fn cancel(self) -> Option<CancelReason> {
        self.cancel
    }

    /// The cleanup progress observed when the supervisor returned.
    ///
    /// A parked worker can report [`CleanupPhase::Running`] when the grace
    /// period ended during cleanup.
    pub fn cleanup_phase(self) -> CleanupPhase {
        self.cleanup_phase
    }

    /// The cleanup result. A parked, lost, or unstarted session reports
    /// [`CleanupOutcome::Unfinished`].
    pub fn cleanup(self) -> CleanupOutcome {
        match self.stop {
            Some(stop) => stop.cleanup(),
            None => CleanupOutcome::Unfinished,
        }
    }

    /// True when cleanup ran and reported success.
    pub fn cleanup_complete(self) -> bool {
        self.cleanup().is_complete()
    }

    /// True only when the worker stopped, the session ended by a close, a
    /// cancel, or an accepted shutdown, and cleanup completed.
    pub fn stopped_cleanly(self) -> bool {
        match self.stop {
            Some(stop) => stop.stopped_cleanly(),
            None => false,
        }
    }

    /// Every supervised session is final, including a clean shutdown.
    pub fn requires_process_exit(self) -> bool {
        true
    }

    /// True when the worker stopped and reported a result.
    pub fn worker_stopped(self) -> bool {
        self.stop.is_some()
    }

    /// The time from supervisor start to the return.
    pub fn waited(self) -> Duration {
        self.waited
    }
}

/// A 32-byte per-launch session key.
///
/// The key never crosses the control channel. `Debug` never prints it. The key
/// is wiped when it drops. Use [`SessionKey::matches`] for a constant-time
/// compare. Do not add `PartialEq`.
pub struct SessionKey([u8; SESSION_KEY_LEN]);

impl SessionKey {
    /// Build a key from exactly 32 bytes. The caller must supply 32 random
    /// bytes from an operating-system source. This method does not measure
    /// entropy.
    pub fn from_bytes(bytes: [u8; SESSION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Parse 64 hex bytes. Upper and lower case are accepted.
    pub fn from_hex(text: &str) -> Result<Self, ControlError> {
        Self::from_hex_bytes(text.as_bytes())
    }

    fn from_hex_bytes(text: &[u8]) -> Result<Self, ControlError> {
        if text.len() != SESSION_KEY_TEXT_LEN {
            return Err(ControlError::InvalidKey);
        }
        // Build the key in its final type, so an early error wipes the partial
        // key through `Drop`.
        let mut key = Self([0u8; SESSION_KEY_LEN]);
        for (index, slot) in key.0.iter_mut().enumerate() {
            let high = hex_value(text[index * 2]).ok_or(ControlError::InvalidKey)?;
            let low = hex_value(text[index * 2 + 1]).ok_or(ControlError::InvalidKey)?;
            *slot = (high << 4) | low;
        }
        Ok(key)
    }

    /// Compare two keys without an early return.
    pub fn matches(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }

    fn bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }
}

impl Clone for SessionKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Debug for SessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey([redacted])")
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Read a session key from a private descriptor.
///
/// The function reads exactly 64 hex bytes and one newline. It returns an error
/// for a short line, a missing newline, or a non-hex byte. It wipes its buffer
/// on every path. Use a blocking descriptor. The caller owns the descriptor and
/// must close it. Extra bytes after the newline are not read.
pub fn read_session_key<R: Read>(reader: &mut R) -> Result<SessionKey, ControlError> {
    let mut buffer = [0u8; SESSION_KEY_TEXT_LEN + 1];
    let result = read_session_key_line(reader, &mut buffer);
    wipe(&mut buffer);
    result
}

fn read_session_key_line<R: Read>(
    reader: &mut R,
    buffer: &mut [u8; SESSION_KEY_TEXT_LEN + 1],
) -> Result<SessionKey, ControlError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ControlError::InvalidKey),
        }
    }
    if filled != buffer.len() || buffer[SESSION_KEY_TEXT_LEN] != b'\n' {
        return Err(ControlError::InvalidKey);
    }
    SessionKey::from_hex_bytes(&buffer[..SESSION_KEY_TEXT_LEN])
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The fixed command allowlist.
///
/// The list has no host, port, token, path, or process field. A request cannot
/// name a destination. A future handler uses the stored pairing state only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCommand {
    /// Read the service status.
    Status,
    /// Read the bounded relay counters.
    Diagnostics,
    /// Read the bounded recent failures.
    Failures,
    /// Read the activity log after one sequence number. The handler must trim
    /// the answer to the response limit. The shell advances `since` after each
    /// answer.
    Logs {
        /// The last sequence number that the shell received.
        since: u64,
    },
    /// Read the pairing state.
    PairStatus,
    /// Start one pairing with the discovered source device.
    Pair,
    /// Cancel a pairing.
    PairCancel,
    /// Forget the stored pairing.
    Forget,
    /// Run one source device presence probe now.
    ProbeSourceDevice,
    /// Start the tunnel from the stored pairing.
    Start {
        /// The tunnel mode.
        mode: StartMode,
        /// The echo setting for this start.
        ping: PingOption,
    },
    /// Stop the tunnel. Stop is idempotent.
    Stop,
    /// Stop the tunnel and end the control session. The transport ends the
    /// session after the reply. A refusal is reported as
    /// [`ServeStop::ShutdownRefused`].
    Shutdown,
}

/// The allowed start mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// The source device proxy mode.
    Phone,
}

impl StartMode {
    fn code(self) -> u8 {
        match self {
            Self::Phone => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Phone),
            _ => None,
        }
    }
}

/// The echo setting for one start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingOption {
    /// Use the default for the mode.
    Default,
    /// Turn the echo relay on.
    Enabled,
    /// Turn the echo relay off.
    Disabled,
}

impl PingOption {
    fn code(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::Enabled => 1,
            Self::Disabled => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Default),
            1 => Some(Self::Enabled),
            2 => Some(Self::Disabled),
            _ => None,
        }
    }
}

const CMD_STATUS: u8 = 1;
const CMD_DIAGNOSTICS: u8 = 2;
const CMD_FAILURES: u8 = 3;
const CMD_LOGS: u8 = 4;
const CMD_PAIR_STATUS: u8 = 5;
const CMD_PAIR: u8 = 6;
const CMD_PAIR_CANCEL: u8 = 7;
const CMD_FORGET: u8 = 8;
const CMD_PROBE_SOURCE_DEVICE: u8 = 9;
const CMD_START: u8 = 10;
const CMD_STOP: u8 = 11;
const CMD_SHUTDOWN: u8 = 12;

impl ControlCommand {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Status => vec![CMD_STATUS],
            Self::Diagnostics => vec![CMD_DIAGNOSTICS],
            Self::Failures => vec![CMD_FAILURES],
            Self::Logs { since } => {
                let mut payload = Vec::with_capacity(9);
                payload.push(CMD_LOGS);
                payload.extend_from_slice(&since.to_be_bytes());
                payload
            }
            Self::PairStatus => vec![CMD_PAIR_STATUS],
            Self::Pair => vec![CMD_PAIR],
            Self::PairCancel => vec![CMD_PAIR_CANCEL],
            Self::Forget => vec![CMD_FORGET],
            Self::ProbeSourceDevice => vec![CMD_PROBE_SOURCE_DEVICE],
            Self::Start { mode, ping } => vec![CMD_START, mode.code(), ping.code()],
            Self::Stop => vec![CMD_STOP],
            Self::Shutdown => vec![CMD_SHUTDOWN],
        }
    }

    fn decode(payload: &[u8]) -> Option<Self> {
        let (command, rest) = payload.split_first()?;
        match *command {
            CMD_STATUS if rest.is_empty() => Some(Self::Status),
            CMD_DIAGNOSTICS if rest.is_empty() => Some(Self::Diagnostics),
            CMD_FAILURES if rest.is_empty() => Some(Self::Failures),
            CMD_LOGS if rest.len() == 8 => {
                let mut since = [0u8; 8];
                since.copy_from_slice(rest);
                Some(Self::Logs {
                    since: u64::from_be_bytes(since),
                })
            }
            CMD_PAIR_STATUS if rest.is_empty() => Some(Self::PairStatus),
            CMD_PAIR if rest.is_empty() => Some(Self::Pair),
            CMD_PAIR_CANCEL if rest.is_empty() => Some(Self::PairCancel),
            CMD_FORGET if rest.is_empty() => Some(Self::Forget),
            CMD_PROBE_SOURCE_DEVICE if rest.is_empty() => Some(Self::ProbeSourceDevice),
            CMD_START if rest.len() == 2 => Some(Self::Start {
                mode: StartMode::from_code(rest[0])?,
                ping: PingOption::from_code(rest[1])?,
            }),
            CMD_STOP if rest.is_empty() => Some(Self::Stop),
            CMD_SHUTDOWN if rest.is_empty() => Some(Self::Shutdown),
            _ => None,
        }
    }
}

/// True only when the transport can stop a blocked handler call or a blocked
/// channel read after the parent closes its channel.
///
/// It is false. [`ControlServer::supervise`] stops a blocked channel read and
/// always returns inside a bound. It cannot stop a blocked handler call. A
/// blocked handler call is reported as [`SupervisionState::Parked`].
pub const PARENT_LIVENESS_ENFORCED: bool = false;

/// True when the transport watches parent liveness on a channel that is
/// separate from the control frames.
pub const PARENT_LOSS_OBSERVED_INDEPENDENTLY: bool = true;

/// True when the transport can make a blocked handler call return after a
/// cancel request.
pub const HANDLER_STALL_CANCELLABLE: bool = false;

/// True when the transport can guarantee that cleanup ran after parent loss.
///
/// It is false. A handler that blocks in `handle` or `shutdown` keeps cleanup
/// incomplete. The supervisor reports [`CleanupOutcome::Unfinished`]. The
/// engine must then exit the process. Process exit closes the tunnel device,
/// but it does not remove device-independent routes.
pub const CLEANUP_GUARANTEED: bool = false;

/// Work that must finish before the transport can protect the real service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRequirement {
    /// Every handler call must return inside the supervisor grace period, or
    /// it must observe the [`CancelToken`].
    BoundedHandler,
    /// Every cleanup call must return inside the supervisor grace period.
    BoundedCleanup,
    /// The engine must exit after every supervisor return. On Unix it must
    /// ignore `SIGPIPE`. The shell must close both private channels.
    ProcessExit,
    /// Control output must not block cleanup indefinitely.
    BoundedOutput,
    /// Device-independent routes need a cleanup path outside a parked worker.
    IndependentRouteCleanup,
}

/// The work that is not done yet. Do not enable the production constructor
/// while this list is not empty.
pub const SERVICE_REQUIREMENTS: [ServiceRequirement; 5] = [
    ServiceRequirement::BoundedHandler,
    ServiceRequirement::BoundedCleanup,
    ServiceRequirement::ProcessExit,
    ServiceRequirement::BoundedOutput,
    ServiceRequirement::IndependentRouteCleanup,
];

/// Watches one private parent liveness channel.
///
/// The watcher runs on its own thread and blocks in `read` on a channel that is
/// separate from the control frames. End-of-file and a read error request
/// [`CancelReason::ParentLost`]. Bytes are ignored. The thread is detached. It
/// ends at end-of-file or on a read error. It can outlive a session that
/// stopped for another reason, because a blocked read has no portable cancel.
/// The process exit reclaims it.
pub struct ParentWatch {
    _token: CancelToken,
}

impl ParentWatch {
    /// Start one liveness watcher. The caller keeps the write end alive for the
    /// life of the parent.
    pub fn start<R: Read + Send + 'static>(mut reader: R, cancel: CancelToken) -> io::Result<Self> {
        let thread_cancel = cancel.clone();
        let _handle = thread::Builder::new()
            .name("hotspotshade-parent-watch".into())
            .spawn(move || watch_parent(&mut reader, &thread_cancel))?;
        Ok(Self { _token: cancel })
    }
}

fn watch_parent<R: Read>(reader: &mut R, cancel: &CancelToken) {
    struct ParentLossGuard<'a>(&'a CancelToken);
    impl Drop for ParentLossGuard<'_> {
        fn drop(&mut self) {
            self.0.request(CancelReason::ParentLost);
        }
    }
    // An unwinding reader must not leave the engine believing its parent is
    // alive. An abort still requires the process-level cleanup strategy.
    let _guard = ParentLossGuard(cancel);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// The engine side of the control transport.
///
/// The handler `shutdown` method runs once when the session loop returns. It
/// runs on a parent close, a cancel, a protocol fault, a refused shutdown, and
/// a panic in `handle`. A parked worker did not return, so its cleanup result
/// is not known. Keep `shutdown` idempotent. It must report the cleanup result.
///
/// The server has no production constructor. [`ControlServer::new_for_service`]
/// fails closed because a blocked handler call still prevents a guaranteed
/// stop. Tests use a private constructor.
pub struct ControlServer<H> {
    handler: H,
    key: SessionKey,
    nonce: [u8; NONCE_LEN],
}

impl<H: ControlHandler> ControlServer<H> {
    /// Build a server for one hermetic test session. The server nonce is unique
    /// for this process. The nonce is not a secret.
    #[cfg(test)]
    fn new(handler: H, key: SessionKey) -> Self {
        Self {
            handler,
            key,
            nonce: unique_nonce(b"server"),
        }
    }

    /// Build a server for the real service.
    ///
    /// This method fails closed with [`ControlError::Unsupported`].
    /// [`SERVICE_REQUIREMENTS`] lists the work that must finish first. The
    /// main requirement is a handler and a cleanup call that both return inside
    /// the supervisor grace period. Do not add a production constructor until
    /// every requirement is met.
    pub fn new_for_service(_handler: H, _key: SessionKey) -> Result<Self, ControlError> {
        Err(ControlError::Unsupported)
    }

    #[cfg(test)]
    fn with_nonce(handler: H, key: SessionKey, nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            handler,
            key,
            nonce,
        }
    }

    /// Serve one private channel until the parent closes it or asks to stop.
    ///
    /// The server handles one request at a time. It writes at most one bounded
    /// answer for each request. It closes the channel after a protocol fault.
    /// The method takes ownership of the channel. Do not keep another copy of a
    /// handle. The server cannot close a channel that another copy keeps open.
    ///
    /// The method is single-threaded. It observes a closed channel only in a
    /// read. A blocked handler delays parent-loss cleanup without a bound. Use
    /// [`supervise`](Self::supervise) for the parent-liveness boundary. The
    /// cleanup result is part of the returned [`ServeOutcome`].
    pub fn serve<R: Read, W: Write>(self, mut input: R, mut output: W) -> ServeOutcome {
        let cancel = CancelToken::new();
        let phase = SessionPhase::new();
        let mut frames = DirectFrames { input: &mut input };
        self.run(&mut frames, &mut output, &cancel, &phase)
    }

    /// Serve one private channel with one cancel token.
    ///
    /// A second thread reads the control frames. The session loop polls the
    /// frame channel and checks the token, so a partial frame does not block a
    /// cancel request. This method does not watch parent liveness. Use
    /// [`supervise`](Self::supervise) for that.
    ///
    /// The frame reader owns the input handle. A blocked read can keep that
    /// thread alive after the session ends. The process exit reclaims it. If
    /// the reader thread cannot start, the session fails closed and runs
    /// cleanup.
    pub fn serve_cancellable<R, W>(self, input: R, output: W, cancel: CancelToken) -> ServeOutcome
    where
        R: Read + Send + 'static,
        W: Write,
    {
        let phase = SessionPhase::new();
        self.serve_with_reader(input, output, cancel, &phase)
    }

    /// Serve one private control channel under the parent-liveness boundary.
    ///
    /// The method starts one liveness watcher and one worker thread. It waits
    /// for the worker to stop, for parent loss, or for a local cancel request.
    /// After a cancel request it waits at most `grace` for the worker. It then
    /// returns a [`SupervisedOutcome`] that reports the truth, even when the
    /// worker is still parked.
    ///
    /// The method never restarts a session. The caller must exit the process
    /// after every outcome, including a clean stop. Use [`SUPERVISOR_GRACE`]
    /// as the grace period.
    pub fn supervise<R, W, L>(
        self,
        input: R,
        output: W,
        parent: L,
        cancel: CancelToken,
        grace: Duration,
    ) -> SupervisedOutcome
    where
        H: 'static,
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        L: Read + Send + 'static,
    {
        if ParentWatch::start(parent, cancel.clone()).is_err() {
            return SupervisedOutcome::halted(
                SupervisionState::NotStarted,
                cancel.reason(),
                CleanupPhase::Idle,
                Duration::ZERO,
            );
        }
        let phase = Arc::new(SessionPhase::new());
        let worker_phase = Arc::clone(&phase);
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::channel::<ServeOutcome>();
        let spawned = thread::Builder::new()
            .name("hotspotshade-desktop-control".into())
            .spawn(move || {
                let stop = self.serve_with_reader(input, output, worker_cancel, &worker_phase);
                let _ = sender.send(stop);
            });
        if spawned.is_err() {
            return SupervisedOutcome::halted(
                SupervisionState::NotStarted,
                cancel.reason(),
                CleanupPhase::Idle,
                Duration::ZERO,
            );
        }

        let start = Instant::now();
        let mut cancel_seen = None;
        loop {
            if let Some(reason) = cancel.reason() {
                let observed = *cancel_seen.get_or_insert_with(Instant::now);
                let deadline = observed + grace;
                let now = Instant::now();
                if now >= deadline {
                    return SupervisedOutcome::halted(
                        SupervisionState::Parked,
                        Some(reason),
                        phase.get(),
                        start.elapsed(),
                    );
                }
                match receiver.recv_timeout((deadline - now).min(SESSION_POLL_INTERVAL)) {
                    Ok(stop) => {
                        return SupervisedOutcome::stopped(
                            stop,
                            cancel.reason(),
                            phase.get(),
                            start.elapsed(),
                        )
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => {
                        return SupervisedOutcome::halted(
                            SupervisionState::Lost,
                            cancel.reason(),
                            phase.get(),
                            start.elapsed(),
                        )
                    }
                }
            }
            match receiver.recv_timeout(SESSION_POLL_INTERVAL) {
                Ok(stop) => {
                    return SupervisedOutcome::stopped(
                        stop,
                        cancel.reason(),
                        phase.get(),
                        start.elapsed(),
                    )
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return SupervisedOutcome::halted(
                        SupervisionState::Lost,
                        cancel.reason(),
                        phase.get(),
                        start.elapsed(),
                    )
                }
            }
        }
    }

    fn serve_with_reader<R, W>(
        self,
        input: R,
        mut output: W,
        cancel: CancelToken,
        phase: &SessionPhase,
    ) -> ServeOutcome
    where
        R: Read + Send + 'static,
        W: Write,
    {
        match spawn_frame_reader(input) {
            Ok(reader) => {
                let mut frames = ChannelFrames { frames: reader };
                self.run(&mut frames, &mut output, &cancel, phase)
            }
            Err(_) => {
                let mut cleanup = None;
                let stop = {
                    let _guard = ShutdownGuard {
                        handler: &self.handler,
                        result: &mut cleanup,
                        phase,
                    };
                    ServeStop::Fault(ControlFault::Io)
                };
                ServeOutcome::new(stop, cleanup.unwrap_or(CleanupOutcome::Panicked))
            }
        }
    }

    fn run<F: FrameSource, W: Write>(
        self,
        frames: &mut F,
        output: &mut W,
        cancel: &CancelToken,
        phase: &SessionPhase,
    ) -> ServeOutcome {
        let Self {
            handler,
            key,
            nonce,
        } = self;
        let mut cleanup = None;
        let stop = {
            let _guard = ShutdownGuard {
                handler: &handler,
                result: &mut cleanup,
                phase,
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serve_loop(&handler, &key, &nonce, frames, output, cancel)
            })) {
                Ok(stop) => stop,
                Err(_) => {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if cancel.reason().is_none() {
                            write_fatal(output, WireError::Internal);
                        }
                    }));
                    ServeStop::Fault(ControlFault::Panicked)
                }
            }
        };
        ServeOutcome::new(stop, cleanup.unwrap_or(CleanupOutcome::Panicked))
    }
}

/// The engine work behind the control transport. Implement this trait to map
/// the fixed command allowlist to the service.
///
/// `handle` returns one JSON object for a successful command. The transport
/// redacts fields that look like a credential, then applies the response
/// limit. Trim large lists to fit [`MAX_RESPONSE_PAYLOAD`]. A larger answer
/// becomes a `TooLarge` error and no partial data is sent. An error must be a
/// [`ControlError`]. Do not return backend text. Return an error for a refusal.
/// Do not encode a refusal as an `Ok` object.
pub trait ControlHandler: Send + Sync {
    /// Run one allowed command.
    fn handle(&self, command: ControlCommand) -> Result<Value, ControlError>;

    /// Run one allowed command with the session cancel token.
    ///
    /// The default calls [`handle`](Self::handle) and ignores the token.
    /// Override this method to stop long work when the session cancels. The
    /// token holds no secret. The token is set by parent loss or by a local
    /// stop request. A handler that returns a refusal must return a fixed
    /// [`ControlError`].
    fn handle_with_cancel(
        &self,
        command: ControlCommand,
        cancel: &CancelToken,
    ) -> Result<Value, ControlError> {
        let _ = cancel;
        self.handle(command)
    }

    /// Run the normal stop path and report the result.
    ///
    /// The transport calls this exactly once when the session loop returns. The
    /// paths include a parent close, a cancel, a protocol fault, a refused
    /// shutdown, and a panic in `handle`. The method must be idempotent and
    /// must remove every route and device. Return an error when cleanup is
    /// incomplete. Do not return a fixed success without a cleanup check. The
    /// method must return inside the supervisor grace period. A blocked cleanup
    /// is reported as [`CleanupOutcome::Unfinished`] and is not a clean stop.
    fn shutdown(&self) -> Result<(), ControlError>;
}

impl<T: ControlHandler + ?Sized> ControlHandler for std::sync::Arc<T> {
    fn handle(&self, command: ControlCommand) -> Result<Value, ControlError> {
        (**self).handle(command)
    }

    fn handle_with_cancel(
        &self,
        command: ControlCommand,
        cancel: &CancelToken,
    ) -> Result<Value, ControlError> {
        (**self).handle_with_cancel(command, cancel)
    }

    fn shutdown(&self) -> Result<(), ControlError> {
        (**self).shutdown()
    }
}

/// The shell side of the control transport.
///
/// The client takes one reader and one writer, so the shell can pass two
/// inherited pipes or two handles. The client applies no deadline. A shell with
/// a visible window must run the client on a worker thread and apply its own
/// deadline. A closed channel returns [`ControlError::Disconnected`].
pub struct ControlClient<R, W> {
    input: R,
    output: W,
    next_id: u32,
}

impl<R: Read, W: Write> ControlClient<R, W> {
    /// Prove the session key on one channel.
    ///
    /// The method reads the engine challenge, sends the HMAC answer, and
    /// checks the engine proof. It returns no key material.
    pub fn connect(input: R, output: W, key: SessionKey) -> Result<Self, ControlError> {
        let mut input = input;
        let mut output = output;
        let challenge = match read_frame(&mut input, HANDSHAKE_MAX_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            FrameRead::Closed => return Err(ControlError::Disconnected),
            FrameRead::Fault(ControlFault::Io) => return Err(ControlError::Disconnected),
            FrameRead::Fault(_) => return Err(ControlError::Protocol),
        };
        if challenge.kind != FrameKind::Challenge
            || challenge.id != 0
            || challenge.payload.len() != NONCE_LEN
        {
            return Err(ControlError::Protocol);
        }
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&challenge.payload);

        let client_nonce = unique_nonce(b"client");
        let mut hello_proof = session_proof(&key, HELLO_LABEL, &server_nonce, &client_nonce);
        let mut hello = [0u8; HELLO_LEN];
        hello[..NONCE_LEN].copy_from_slice(&client_nonce);
        hello[NONCE_LEN..].copy_from_slice(&hello_proof);
        wipe(&mut hello_proof);
        let sent = write_frame(&mut output, FrameKind::Hello, 0, &hello);
        wipe(&mut hello);
        if sent.is_err() {
            return Err(ControlError::Disconnected);
        }

        let ready = match read_frame(&mut input, HANDSHAKE_MAX_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            FrameRead::Closed => return Err(ControlError::Disconnected),
            FrameRead::Fault(ControlFault::Io) => return Err(ControlError::Disconnected),
            FrameRead::Fault(_) => return Err(ControlError::Protocol),
        };
        if ready.kind == FrameKind::Fatal {
            return Err(fatal_error(&ready.payload));
        }
        if ready.kind != FrameKind::Ready || ready.id != 0 || ready.payload.len() != PROOF_LEN {
            return Err(ControlError::Protocol);
        }
        let mut expected = session_proof(&key, READY_LABEL, &server_nonce, &client_nonce);
        let matches = constant_time_eq(&expected, &ready.payload);
        wipe(&mut expected);
        if !matches {
            return Err(ControlError::Unauthorized);
        }
        Ok(Self {
            input,
            output,
            next_id: 1,
        })
    }

    /// Send one allowed command and read one bounded answer.
    pub fn request(&mut self, command: ControlCommand) -> Result<Value, ControlError> {
        if self.next_id == 0 {
            return Err(ControlError::Protocol);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let payload = command.encode();
        if write_frame(&mut self.output, FrameKind::Request, id, &payload).is_err() {
            return Err(ControlError::Disconnected);
        }
        let frame = match read_frame(&mut self.input, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            FrameRead::Closed => return Err(ControlError::Disconnected),
            FrameRead::Fault(ControlFault::Io) => return Err(ControlError::Disconnected),
            FrameRead::Fault(_) => return Err(ControlError::Protocol),
        };
        if frame.kind == FrameKind::Fatal {
            return Err(fatal_error(&frame.payload));
        }
        if frame.kind != FrameKind::Response || frame.id != id {
            return Err(ControlError::Protocol);
        }
        let status = frame
            .payload
            .first()
            .copied()
            .ok_or(ControlError::Protocol)?;
        match status {
            0 => {
                let value: Value = serde_json::from_slice(&frame.payload[1..])
                    .map_err(|_| ControlError::Protocol)?;
                if value.is_object() {
                    Ok(value)
                } else {
                    Err(ControlError::Protocol)
                }
            }
            1 if frame.payload.len() == 2 => {
                let error = WireError::from_byte(frame.payload[1])
                    .map(ControlError::from)
                    .unwrap_or(ControlError::Protocol);
                Err(error)
            }
            _ => Err(ControlError::Protocol),
        }
    }

    /// Request that the engine stop and end the session.
    ///
    /// A refused shutdown returns the handler error code. The session ends
    /// after the answer. Success means the request was accepted. Cleanup runs
    /// afterward and can fail or stall. The shell must wait for process exit
    /// and inspect the final cleanup result.
    pub fn request_shutdown(&mut self) -> Result<(), ControlError> {
        self.request(ControlCommand::Shutdown).map(|_| ())
    }
}

struct SessionPhase(AtomicU8);

impl SessionPhase {
    fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    fn set(&self, phase: CleanupPhase) {
        let code = match phase {
            CleanupPhase::Idle => 0,
            CleanupPhase::Running => 1,
            CleanupPhase::Finished => 2,
        };
        self.0.store(code, Ordering::SeqCst);
    }

    fn get(&self) -> CleanupPhase {
        match self.0.load(Ordering::SeqCst) {
            1 => CleanupPhase::Running,
            2 => CleanupPhase::Finished,
            _ => CleanupPhase::Idle,
        }
    }
}

struct ShutdownGuard<'a, H: ControlHandler + ?Sized> {
    handler: &'a H,
    result: &'a mut Option<CleanupOutcome>,
    phase: &'a SessionPhase,
}

impl<H: ControlHandler + ?Sized> Drop for ShutdownGuard<'_, H> {
    fn drop(&mut self) {
        self.phase.set(CleanupPhase::Running);
        *self.result = Some(run_cleanup(self.handler));
        self.phase.set(CleanupPhase::Finished);
    }
}

fn run_cleanup<H: ControlHandler + ?Sized>(handler: &H) -> CleanupOutcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.shutdown())) {
        Ok(Ok(())) => CleanupOutcome::Complete,
        Ok(Err(error)) => CleanupOutcome::Failed(error),
        Err(_) => CleanupOutcome::Panicked,
    }
}

trait FrameSource {
    /// Return one read result. `None` means that the wait ended with no frame.
    fn next(&mut self, wait: Duration) -> Option<FrameRead>;
}

struct DirectFrames<'a, R: Read> {
    input: &'a mut R,
}

impl<R: Read> FrameSource for DirectFrames<'_, R> {
    fn next(&mut self, _wait: Duration) -> Option<FrameRead> {
        Some(read_frame(self.input, INBOUND_MAX_PAYLOAD))
    }
}

struct ChannelFrames {
    frames: mpsc::Receiver<FrameRead>,
}

impl FrameSource for ChannelFrames {
    fn next(&mut self, wait: Duration) -> Option<FrameRead> {
        match self.frames.recv_timeout(wait) {
            Ok(read) => Some(read),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => Some(FrameRead::Fault(ControlFault::Io)),
        }
    }
}

fn spawn_frame_reader<R: Read + Send + 'static>(
    mut input: R,
) -> io::Result<mpsc::Receiver<FrameRead>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let _handle = thread::Builder::new()
        .name("hotspotshade-control-frames".into())
        .spawn(move || loop {
            let read = read_frame(&mut input, INBOUND_MAX_PAYLOAD);
            let terminal = !matches!(read, FrameRead::Frame(_));
            if sender.send(read).is_err() {
                break;
            }
            if terminal {
                break;
            }
        })?;
    Ok(receiver)
}

fn next_frame<F: FrameSource>(frames: &mut F, cancel: &CancelToken) -> Result<Frame, ServeStop> {
    loop {
        if let Some(reason) = cancel.reason() {
            return Err(ServeStop::Cancelled(reason));
        }
        match frames.next(SESSION_POLL_INTERVAL) {
            Some(FrameRead::Frame(frame)) => return Ok(frame),
            Some(FrameRead::Closed) => return Err(ServeStop::ParentClosed),
            Some(FrameRead::Fault(fault)) => return Err(ServeStop::Fault(fault)),
            None => continue,
        }
    }
}

fn report_fault<W: Write>(stop: ServeStop, output: &mut W, cancel: &CancelToken) -> ServeStop {
    if let ServeStop::Fault(fault) = stop {
        if cancel.reason().is_none() {
            write_fault(output, fault);
        }
        ServeStop::Fault(fault)
    } else {
        stop
    }
}

fn serve_loop<H: ControlHandler + ?Sized, F: FrameSource, W: Write>(
    handler: &H,
    key: &SessionKey,
    nonce: &[u8; NONCE_LEN],
    frames: &mut F,
    output: &mut W,
    cancel: &CancelToken,
) -> ServeStop {
    if let Err(stop) = establish(key, nonce, frames, output, cancel) {
        return stop;
    }
    let mut last_id = 0u32;
    loop {
        let frame = match next_frame(frames, cancel) {
            Ok(frame) => frame,
            Err(stop) => return report_fault(stop, output, cancel),
        };
        if frame.kind != FrameKind::Request {
            if cancel.reason().is_none() {
                write_fatal(output, WireError::Protocol);
            }
            return ServeStop::Fault(ControlFault::UnexpectedFrame);
        }
        if frame.id == 0 || frame.id <= last_id {
            if cancel.reason().is_none() {
                write_fatal(output, WireError::Protocol);
            }
            return ServeStop::Fault(ControlFault::BadRequestId);
        }
        last_id = frame.id;
        let Some(command) = ControlCommand::decode(&frame.payload) else {
            if cancel.reason().is_none() {
                write_fatal(output, WireError::Protocol);
            }
            return ServeStop::Fault(ControlFault::BadCommand);
        };
        let is_shutdown = command == ControlCommand::Shutdown;
        if let Some(reason) = cancel.reason() {
            return ServeStop::Cancelled(reason);
        }
        let answer = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.handle_with_cancel(command, cancel)
        })) {
            Ok(answer) => answer,
            Err(_) => {
                if cancel.reason().is_none() {
                    write_fatal(output, WireError::Internal);
                }
                return ServeStop::Fault(ControlFault::HandlerPanicked);
            }
        };
        // A cancel request during a handler call ends the session. Do not
        // write an answer to a parent that may be gone.
        if let Some(reason) = cancel.reason() {
            return ServeStop::Cancelled(reason);
        }
        match answer {
            Ok(mut value) if value.is_object() => {
                redact(&mut value);
                match write_value(output, frame.id, &value) {
                    Answer::Sent => {
                        if is_shutdown {
                            return ServeStop::ShutdownRequested;
                        }
                    }
                    Answer::Refused(error) => {
                        if is_shutdown {
                            return ServeStop::ShutdownRefused(error);
                        }
                    }
                    Answer::Io => return ServeStop::Fault(ControlFault::Io),
                }
            }
            Ok(_) => {
                let error = ControlError::Internal;
                if write_error(output, frame.id, error).is_err() {
                    return ServeStop::Fault(ControlFault::Io);
                }
                if is_shutdown {
                    return ServeStop::ShutdownRefused(error);
                }
            }
            Err(error) => {
                if write_error(output, frame.id, error).is_err() {
                    return ServeStop::Fault(ControlFault::Io);
                }
                if is_shutdown {
                    return ServeStop::ShutdownRefused(error);
                }
            }
        }
    }
}

fn establish<F: FrameSource, W: Write>(
    key: &SessionKey,
    nonce: &[u8; NONCE_LEN],
    frames: &mut F,
    output: &mut W,
    cancel: &CancelToken,
) -> Result<(), ServeStop> {
    if let Some(reason) = cancel.reason() {
        return Err(ServeStop::Cancelled(reason));
    }
    if write_frame(output, FrameKind::Challenge, 0, nonce).is_err() {
        return Err(ServeStop::Fault(ControlFault::Io));
    }
    let frame = match next_frame(frames, cancel) {
        Ok(frame) => frame,
        Err(stop) => return Err(report_fault(stop, output, cancel)),
    };
    if frame.kind != FrameKind::Hello || frame.id != 0 || frame.payload.len() != HELLO_LEN {
        if cancel.reason().is_none() {
            write_fatal(output, WireError::Protocol);
        }
        return Err(ServeStop::Fault(ControlFault::UnexpectedFrame));
    }
    let mut client_nonce = [0u8; NONCE_LEN];
    client_nonce.copy_from_slice(&frame.payload[..NONCE_LEN]);
    let mut expected = session_proof(key, HELLO_LABEL, nonce, &client_nonce);
    let matches = constant_time_eq(&expected, &frame.payload[NONCE_LEN..]);
    wipe(&mut expected);
    if !matches {
        if cancel.reason().is_none() {
            write_fatal(output, WireError::Unauthorized);
        }
        return Err(ServeStop::Fault(ControlFault::Unauthenticated));
    }
    let mut ready = session_proof(key, READY_LABEL, nonce, &client_nonce);
    if let Some(reason) = cancel.reason() {
        wipe(&mut ready);
        return Err(ServeStop::Cancelled(reason));
    }
    let sent = write_frame(output, FrameKind::Ready, 0, &ready);
    wipe(&mut ready);
    if sent.is_err() {
        return Err(ServeStop::Fault(ControlFault::Io));
    }
    Ok(())
}

fn session_proof(
    key: &SessionKey,
    label: &[u8],
    server_nonce: &[u8; NONCE_LEN],
    client_nonce: &[u8; NONCE_LEN],
) -> [u8; PROOF_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.bytes()).expect("HMAC accepts a 32-byte key");
    mac.update(label);
    mac.update(server_nonce);
    mac.update(client_nonce);
    let tag = mac.finalize().into_bytes();
    let mut proof = [0u8; PROOF_LEN];
    proof.copy_from_slice(&tag);
    proof
}

fn unique_nonce(label: &[u8]) -> [u8; NONCE_LEN] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"hotspotshade-desktop-control-nonce-v1");
    hasher.update(label);
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(now.to_be_bytes());
    hasher.update(counter.to_be_bytes());
    // Mix the standard library's OS-seeded hasher keys. The counter already
    // makes the value unique for this process. This step adds uncertainty.
    for marker in [0u8, 1u8] {
        let state = std::collections::hash_map::RandomState::new();
        let mut hasher2 = state.build_hasher();
        hasher2.write_u8(marker);
        hasher.update(hasher2.finish().to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest);
    nonce
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FrameKind {
    Challenge = 1,
    Hello = 2,
    Ready = 3,
    Request = 4,
    Response = 5,
    Fatal = 6,
}

impl FrameKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Challenge),
            2 => Some(Self::Hello),
            3 => Some(Self::Ready),
            4 => Some(Self::Request),
            5 => Some(Self::Response),
            6 => Some(Self::Fatal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum WireError {
    Unauthorized = 1,
    Protocol = 2,
    Unavailable = 3,
    Busy = 4,
    Refused = 5,
    Unsupported = 6,
    Internal = 7,
    TooLarge = 8,
}

impl WireError {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Unauthorized),
            2 => Some(Self::Protocol),
            3 => Some(Self::Unavailable),
            4 => Some(Self::Busy),
            5 => Some(Self::Refused),
            6 => Some(Self::Unsupported),
            7 => Some(Self::Internal),
            8 => Some(Self::TooLarge),
            _ => None,
        }
    }
}

impl From<WireError> for ControlError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::Unauthorized => Self::Unauthorized,
            WireError::Protocol => Self::Protocol,
            WireError::Unavailable => Self::Unavailable,
            WireError::Busy => Self::Busy,
            WireError::Refused => Self::Refused,
            WireError::Unsupported => Self::Unsupported,
            WireError::Internal => Self::Internal,
            WireError::TooLarge => Self::TooLarge,
        }
    }
}

struct Frame {
    kind: FrameKind,
    id: u32,
    payload: Vec<u8>,
}

impl Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        wipe(&mut self.payload);
    }
}

#[derive(Debug)]
enum FrameRead {
    Frame(Frame),
    Closed,
    Fault(ControlFault),
}

fn read_frame<R: Read>(input: &mut R, max_payload: usize) -> FrameRead {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        match input.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return FrameRead::Closed,
            Ok(0) => return FrameRead::Fault(ControlFault::TruncatedFrame),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return FrameRead::Fault(ControlFault::Io),
        }
    }
    if header[..4] != MAGIC {
        return FrameRead::Fault(ControlFault::BadMagic);
    }
    if header[4] != VERSION {
        return FrameRead::Fault(ControlFault::BadVersion);
    }
    let Some(kind) = FrameKind::from_byte(header[5]) else {
        return FrameRead::Fault(ControlFault::UnknownFrameKind);
    };
    if header[6] != 0 || header[7] != 0 {
        return FrameRead::Fault(ControlFault::BadFlags);
    }
    let id = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let length = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
    let length = match usize::try_from(length) {
        Ok(length) => length,
        Err(_) => return FrameRead::Fault(ControlFault::OversizedFrame),
    };
    if length > max_payload {
        return FrameRead::Fault(ControlFault::OversizedFrame);
    }
    let mut payload = vec![0u8; length];
    let mut filled = 0;
    while filled < length {
        match input.read(&mut payload[filled..]) {
            Ok(0) => return FrameRead::Fault(ControlFault::TruncatedFrame),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return FrameRead::Fault(ControlFault::Io),
        }
    }
    FrameRead::Frame(Frame { kind, id, payload })
}

fn write_frame<W: Write>(
    output: &mut W,
    kind: FrameKind,
    id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = kind as u8;
    header[6] = 0;
    header[7] = 0;
    header[8..12].copy_from_slice(&id.to_be_bytes());
    header[12..16].copy_from_slice(&length.to_be_bytes());
    output.write_all(&header)?;
    output.write_all(payload)?;
    output.flush()
}

fn write_fatal<W: Write>(output: &mut W, error: WireError) {
    let _ = write_frame(output, FrameKind::Fatal, 0, &[error as u8]);
}

fn write_fault<W: Write>(output: &mut W, fault: ControlFault) {
    if let Some(error) = fault.wire_error() {
        write_fatal(output, error);
    }
}

fn write_error<W: Write>(output: &mut W, id: u32, error: ControlError) -> io::Result<()> {
    write_frame(
        output,
        FrameKind::Response,
        id,
        &[1u8, error.wire_error() as u8],
    )
}

enum Answer {
    Sent,
    Refused(ControlError),
    Io,
}

fn write_value<W: Write>(output: &mut W, id: u32, value: &Value) -> Answer {
    let mut writer = BoundedWriter {
        buffer: Vec::new(),
        limit: MAX_RESPONSE_PAYLOAD - 1,
        overflowed: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        let error = if writer.overflowed {
            ControlError::TooLarge
        } else {
            ControlError::Internal
        };
        wipe(&mut writer.buffer);
        return match write_error(output, id, error) {
            Ok(()) => Answer::Refused(error),
            Err(_) => Answer::Io,
        };
    }
    let mut payload = Vec::with_capacity(writer.buffer.len() + 1);
    payload.push(0u8);
    payload.extend_from_slice(&writer.buffer);
    let sent = write_frame(output, FrameKind::Response, id, &payload);
    wipe(&mut payload);
    wipe(&mut writer.buffer);
    match sent {
        Ok(()) => Answer::Sent,
        Err(_) => Answer::Io,
    }
}

struct BoundedWriter {
    buffer: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.buffer.len()) {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "response too large",
            ));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fatal_error(payload: &[u8]) -> ControlError {
    if payload.len() != 1 {
        return ControlError::Protocol;
    }
    WireError::from_byte(payload[0])
        .map(ControlError::from)
        .unwrap_or(ControlError::Protocol)
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if sensitive_field(key) {
                    *value = Value::String("[redacted]".into());
                } else {
                    redact(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item);
            }
        }
        _ => (),
    }
}

fn sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("authorization")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower == "auth"
        || lower == "key"
        || lower.ends_with("key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn test_key() -> SessionKey {
        SessionKey::from_hex(TEST_KEY_HEX).unwrap()
    }

    fn other_key() -> SessionKey {
        SessionKey::from_hex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
            .unwrap()
    }

    struct QueueState {
        data: VecDeque<u8>,
        closed: bool,
    }

    struct Queue {
        state: Mutex<QueueState>,
        ready: Condvar,
    }

    struct Sender(Arc<Queue>);

    struct Receiver(Arc<Queue>);

    fn queue() -> (Sender, Receiver) {
        let queue = Arc::new(Queue {
            state: Mutex::new(QueueState {
                data: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
        });
        (Sender(Arc::clone(&queue)), Receiver(queue))
    }

    impl Write for Sender {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| io::Error::other("queue lock"))?;
            if state.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            state.data.extend(bytes.iter().copied());
            drop(state);
            self.0.ready.notify_all();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Sender {
        fn drop(&mut self) {
            if let Ok(mut state) = self.0.state.lock() {
                state.closed = true;
            }
            self.0.ready.notify_all();
        }
    }

    impl Read for Receiver {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| io::Error::other("queue lock"))?;
            loop {
                if !state.data.is_empty() {
                    let count = buffer.len().min(state.data.len());
                    for slot in buffer.iter_mut().take(count) {
                        if let Some(byte) = state.data.pop_front() {
                            *slot = byte;
                        }
                    }
                    return Ok(count);
                }
                if state.closed {
                    return Ok(0);
                }
                state = self
                    .0
                    .ready
                    .wait(state)
                    .map_err(|_| io::Error::other("queue wait"))?;
            }
        }
    }

    struct Duplex {
        reader: Receiver,
        writer: Sender,
    }

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reader.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writer.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }
    }

    struct Recorder {
        commands: Mutex<Vec<ControlCommand>>,
        shutdowns: AtomicUsize,
        reply: Mutex<Option<Result<Value, ControlError>>>,
        cleanup: Mutex<Result<(), ControlError>>,
        panic_handle: AtomicBool,
        panic_cleanup: AtomicBool,
    }

    impl Default for Recorder {
        fn default() -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                shutdowns: AtomicUsize::new(0),
                reply: Mutex::new(None),
                cleanup: Mutex::new(Ok(())),
                panic_handle: AtomicBool::new(false),
                panic_cleanup: AtomicBool::new(false),
            }
        }
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn set_ok(&self, value: Value) {
            *self.reply.lock().unwrap() = Some(Ok(value));
        }

        fn set_error(&self, error: ControlError) {
            *self.reply.lock().unwrap() = Some(Err(error));
        }

        fn set_cleanup(&self, result: Result<(), ControlError>) {
            *self.cleanup.lock().unwrap() = result;
        }

        fn panic_on_handle(&self) {
            self.panic_handle.store(true, AtomicOrdering::SeqCst);
        }

        fn panic_on_cleanup(&self) {
            self.panic_cleanup.store(true, AtomicOrdering::SeqCst);
        }

        fn commands(&self) -> Vec<ControlCommand> {
            self.commands.lock().unwrap().clone()
        }

        fn shutdowns(&self) -> usize {
            self.shutdowns.load(AtomicOrdering::SeqCst)
        }
    }

    impl ControlHandler for Recorder {
        fn handle(&self, command: ControlCommand) -> Result<Value, ControlError> {
            self.commands.lock().unwrap().push(command);
            if self.panic_handle.load(AtomicOrdering::SeqCst) {
                panic!("test handler panic");
            }
            self.reply
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| Ok(json!({"ok": true})))
        }

        fn shutdown(&self) -> Result<(), ControlError> {
            self.shutdowns.fetch_add(1, AtomicOrdering::SeqCst);
            if self.panic_cleanup.load(AtomicOrdering::SeqCst) {
                panic!("test cleanup panic");
            }
            *self.cleanup.lock().unwrap()
        }
    }

    fn complete(stop: ServeStop) -> ServeOutcome {
        ServeOutcome::new(stop, CleanupOutcome::Complete)
    }

    fn channel_pair() -> (Duplex, Receiver, Sender) {
        let (client_writer, server_reader) = queue();
        let (server_writer, client_reader) = queue();
        (
            Duplex {
                reader: client_reader,
                writer: client_writer,
            },
            server_reader,
            server_writer,
        )
    }

    fn start_server<H: ControlHandler + 'static>(
        server: ControlServer<H>,
    ) -> (Duplex, mpsc::Receiver<ServeOutcome>) {
        let (client, server_reader, server_writer) = channel_pair();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let outcome = server.serve(server_reader, server_writer);
            let _ = sender.send(outcome);
        });
        (client, receiver)
    }

    fn wait_outcome(receiver: &mpsc::Receiver<ServeOutcome>) -> ServeOutcome {
        receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("the control server did not stop")
    }

    fn connect(
        duplex: Duplex,
        key: SessionKey,
    ) -> Result<ControlClient<Receiver, Sender>, ControlError> {
        ControlClient::connect(duplex.reader, duplex.writer, key)
    }

    fn raw_serve(bytes: &[u8]) -> (ServeOutcome, Arc<Recorder>, Receiver) {
        let handler = Recorder::new();
        let (client_writer, server_reader) = queue();
        let (server_writer, client_reader) = queue();
        {
            let mut writer = client_writer;
            writer.write_all(bytes).unwrap();
        }
        let outcome = ControlServer::new(Arc::clone(&handler), test_key())
            .serve(server_reader, server_writer);
        (outcome, handler, client_reader)
    }

    fn raw_header(
        magic: [u8; 4],
        version: u8,
        kind: u8,
        flags: u8,
        reserved: u8,
        id: u32,
        length: u32,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&magic);
        header.push(version);
        header.push(kind);
        header.push(flags);
        header.push(reserved);
        header.extend_from_slice(&id.to_be_bytes());
        header.extend_from_slice(&length.to_be_bytes());
        header
    }

    fn read_raw(receiver: &mut Receiver) -> Option<Frame> {
        match read_frame(receiver, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => Some(frame),
            FrameRead::Closed | FrameRead::Fault(_) => None,
        }
    }

    #[test]
    fn framed_round_trip_uses_the_fixed_command_allowlist() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        assert_eq!(
            client
                .request(ControlCommand::Start {
                    mode: StartMode::Phone,
                    ping: PingOption::Enabled,
                })
                .unwrap(),
            json!({"ok": true})
        );
        assert_eq!(
            client.request(ControlCommand::Logs { since: 7 }).unwrap(),
            json!({"ok": true})
        );
        drop(client);
        assert_eq!(wait_outcome(&outcome), complete(ServeStop::ParentClosed));
        assert_eq!(
            handler.commands(),
            vec![
                ControlCommand::Status,
                ControlCommand::Start {
                    mode: StartMode::Phone,
                    ping: PingOption::Enabled,
                },
                ControlCommand::Logs { since: 7 },
            ]
        );
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn parent_loss_before_and_after_the_handshake_stops_the_server() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let client = connect(duplex, key).unwrap();
        assert_eq!(handler.shutdowns(), 0);
        drop(client);
        assert_eq!(wait_outcome(&outcome), complete(ServeStop::ParentClosed));
        assert_eq!(handler.shutdowns(), 1);

        // The channel closes before the engine writes a challenge.
        let handler = Recorder::new();
        let (writer, reader) = queue();
        drop(writer);
        let (server_writer, client_reader) = queue();
        let outcome =
            ControlServer::new(Arc::clone(&handler), test_key()).serve(reader, server_writer);
        assert_eq!(outcome, complete(ServeStop::ParentClosed));
        assert_eq!(handler.shutdowns(), 1);
        drop(client_reader);
    }

    #[test]
    fn truncated_and_hostile_frames_fail_closed() {
        let key = test_key();

        // An incomplete header.
        let (outcome, handler, mut output) = raw_serve(b"HSDC\x01");
        assert_eq!(
            outcome,
            complete(ServeStop::Fault(ControlFault::TruncatedFrame))
        );
        assert_eq!(handler.shutdowns(), 1);
        assert!(handler.commands().is_empty());
        let challenge = read_raw(&mut output).expect("challenge");
        assert_eq!(challenge.kind, FrameKind::Challenge);
        let fatal = read_raw(&mut output).expect("fatal");
        assert_eq!(fatal.kind, FrameKind::Fatal);
        assert_eq!(fatal.payload, vec![WireError::Protocol as u8]);

        // A hostile length is rejected before any payload allocation.
        let mut hostile = raw_header(MAGIC, VERSION, FrameKind::Hello as u8, 0, 0, 0, u32::MAX);
        hostile.truncate(HEADER_LEN);
        let (outcome, handler, _output) = raw_serve(&hostile);
        assert_eq!(
            outcome,
            complete(ServeStop::Fault(ControlFault::OversizedFrame))
        );
        assert_eq!(handler.shutdowns(), 1);
        assert!(handler.commands().is_empty());

        // A request length above the request limit is rejected after the
        // handshake. This checks the request bound, not only the header.
        let handler = Recorder::new();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        let mut oversized = raw_header(
            MAGIC,
            VERSION,
            FrameKind::Request as u8,
            0,
            0,
            1,
            (MAX_REQUEST_PAYLOAD + 1) as u32,
        );
        oversized.truncate(HEADER_LEN);
        client.output.write_all(&oversized).unwrap();
        let fatal = match read_frame(&mut client.input, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(fatal.kind, FrameKind::Fatal);
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::OversizedFrame))
        );
        assert!(handler.commands().is_empty());
        assert_eq!(handler.shutdowns(), 1);

        // Bad magic, bad version, unknown kind, and nonzero flags are rejected.
        for header in [
            raw_header(*b"XXXX", VERSION, FrameKind::Hello as u8, 0, 0, 0, 0),
            raw_header(MAGIC, 2, FrameKind::Hello as u8, 0, 0, 0, 0),
            raw_header(MAGIC, VERSION, 99, 0, 0, 0, 0),
            raw_header(MAGIC, VERSION, FrameKind::Hello as u8, 1, 0, 0, 0),
            raw_header(MAGIC, VERSION, FrameKind::Hello as u8, 0, 1, 0, 0),
        ] {
            let (outcome, handler, _output) = raw_serve(&header);
            assert!(matches!(outcome.stop(), ServeStop::Fault(_)));
            assert_eq!(handler.shutdowns(), 1);
            assert!(handler.commands().is_empty());
        }

        // A payload that claims more bytes than the channel carries.
        let mut short = raw_header(MAGIC, VERSION, FrameKind::Hello as u8, 0, 0, 0, 3);
        short.extend_from_slice(&[1u8, 2u8]);
        let (outcome, handler, _output) = raw_serve(&short);
        assert_eq!(
            outcome,
            complete(ServeStop::Fault(ControlFault::TruncatedFrame))
        );
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn a_partial_request_after_the_handshake_fails_closed() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        let mut partial = raw_header(MAGIC, VERSION, FrameKind::Request as u8, 0, 0, 1, 2);
        partial.push(CMD_STATUS);
        client.output.write_all(&partial).unwrap();
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::TruncatedFrame))
        );
        assert!(handler.commands().is_empty());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn a_response_frame_from_the_shell_is_rejected() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        write_frame(&mut client.output, FrameKind::Response, 1, &[0u8]).unwrap();
        let fatal = match read_frame(&mut client.input, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(fatal.kind, FrameKind::Fatal);
        assert_eq!(fatal.payload, vec![WireError::Protocol as u8]);
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::UnexpectedFrame))
        );
        assert!(handler.commands().is_empty());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn handshake_rejects_a_wrong_key_and_a_replayed_nonce() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let error = match connect(duplex, other_key()) {
            Ok(_) => panic!("the wrong key was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, ControlError::Unauthorized);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::Unauthenticated))
        );
        assert_eq!(handler.shutdowns(), 1);

        // The proof binds the server nonce. A Hello from another session does
        // not pass.
        let handler = Recorder::new();
        let nonce = [0x5au8; NONCE_LEN];
        let server = ControlServer::with_nonce(Arc::clone(&handler), key.clone(), nonce);
        let (mut client, outcome) = start_server(server);
        let challenge = match read_frame(&mut client, HANDSHAKE_MAX_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(challenge.kind, FrameKind::Challenge);
        assert_eq!(challenge.payload.as_slice(), nonce.as_slice());
        let client_nonce = [0x11u8; NONCE_LEN];
        let wrong = session_proof(&key, HELLO_LABEL, &[0x5bu8; NONCE_LEN], &client_nonce);
        let mut hello = Vec::with_capacity(HELLO_LEN);
        hello.extend_from_slice(&client_nonce);
        hello.extend_from_slice(&wrong);
        write_frame(&mut client, FrameKind::Hello, 0, &hello).unwrap();
        let fatal = match read_frame(&mut client, HANDSHAKE_MAX_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(fatal.kind, FrameKind::Fatal);
        assert_eq!(fatal.payload, vec![WireError::Unauthorized as u8]);
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::Unauthenticated))
        );
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn only_the_fixed_commands_and_exact_fields_are_accepted() {
        let allowed = [
            (ControlCommand::Status, CMD_STATUS),
            (ControlCommand::Diagnostics, CMD_DIAGNOSTICS),
            (ControlCommand::Failures, CMD_FAILURES),
            (ControlCommand::PairStatus, CMD_PAIR_STATUS),
            (ControlCommand::Pair, CMD_PAIR),
            (ControlCommand::PairCancel, CMD_PAIR_CANCEL),
            (ControlCommand::Forget, CMD_FORGET),
            (ControlCommand::ProbeSourceDevice, CMD_PROBE_SOURCE_DEVICE),
            (ControlCommand::Stop, CMD_STOP),
            (ControlCommand::Shutdown, CMD_SHUTDOWN),
        ];
        for (command, id) in allowed {
            assert_eq!(ControlCommand::decode(&command.encode()), Some(command));
            assert_eq!(ControlCommand::decode(&[id]), Some(command));
        }
        assert_eq!(
            ControlCommand::decode(&ControlCommand::Logs { since: 9 }.encode()),
            Some(ControlCommand::Logs { since: 9 })
        );
        assert_eq!(
            ControlCommand::decode(
                &ControlCommand::Start {
                    mode: StartMode::Phone,
                    ping: PingOption::Disabled,
                }
                .encode()
            ),
            Some(ControlCommand::Start {
                mode: StartMode::Phone,
                ping: PingOption::Disabled,
            })
        );

        // No command identifier exists outside the fixed set.
        for id in 13..=255u8 {
            assert_eq!(ControlCommand::decode(&[id]), None, "{id}");
        }
        assert_eq!(ControlCommand::decode(&[0u8]), None);

        // A known command with extra bytes is not a request for a host, a
        // process, or any other free-form value.
        for id in [
            CMD_STATUS,
            CMD_DIAGNOSTICS,
            CMD_FAILURES,
            CMD_PAIR_STATUS,
            CMD_PAIR,
            CMD_PAIR_CANCEL,
            CMD_FORGET,
            CMD_PROBE_SOURCE_DEVICE,
            CMD_STOP,
            CMD_SHUTDOWN,
        ] {
            assert!(ControlCommand::decode(&[id, b'x']).is_none(), "{id}");
        }
        for suffix in [
            b"example.com".as_slice(),
            b"/bin/sh".as_slice(),
            b"192.0.2.1:22".as_slice(),
            b"powershell".as_slice(),
        ] {
            let mut status = vec![CMD_STATUS];
            status.extend_from_slice(suffix);
            assert!(ControlCommand::decode(&status).is_none());
            let mut start = vec![
                CMD_START,
                StartMode::Phone.code(),
                PingOption::Default.code(),
            ];
            start.extend_from_slice(suffix);
            assert!(ControlCommand::decode(&start).is_none());
        }
        assert!(ControlCommand::decode(&[CMD_START, 9, 0]).is_none());
        assert!(ControlCommand::decode(&[CMD_START, 1, 9]).is_none());
        assert!(ControlCommand::decode(&[CMD_LOGS, 0, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(ControlCommand::decode(&[CMD_LOGS, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_free_form_request_never_reaches_the_handler() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        let mut payload = vec![
            CMD_START,
            StartMode::Phone.code(),
            PingOption::Default.code(),
        ];
        payload.extend_from_slice(b"example.com");
        write_frame(&mut client.output, FrameKind::Request, 1, &payload).unwrap();
        let fatal = match read_frame(&mut client.input, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(fatal.kind, FrameKind::Fatal);
        assert_eq!(fatal.payload, vec![WireError::Protocol as u8]);
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::BadCommand))
        );
        assert!(handler.commands().is_empty());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn repeated_and_zero_request_ids_are_rejected() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        write_frame(
            &mut client.output,
            FrameKind::Request,
            1,
            &ControlCommand::Status.encode(),
        )
        .unwrap();
        let fatal = match read_frame(&mut client.input, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(fatal.kind, FrameKind::Fatal);
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::BadRequestId))
        );
        assert_eq!(handler.commands(), vec![ControlCommand::Status]);
        assert_eq!(handler.shutdowns(), 1);

        // Identifier zero is never a request.
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        write_frame(
            &mut client.output,
            FrameKind::Request,
            0,
            &ControlCommand::Status.encode(),
        )
        .unwrap();
        let fatal = match read_frame(&mut client.input, MAX_RESPONSE_PAYLOAD) {
            FrameRead::Frame(frame) => frame,
            other => panic!("unexpected read: {other:?}"),
        };
        assert_eq!(fatal.kind, FrameKind::Fatal);
        drop(client);
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::Fault(ControlFault::BadRequestId))
        );
        assert!(handler.commands().is_empty());
    }

    #[test]
    fn secrets_are_redacted_and_errors_are_fixed_text() {
        let handler = Recorder::new();
        handler.set_ok(json!({
            "ok": true,
            "token": "secret-token-value",
            "nested": {
                "password": "secret-password",
                "passphrase": "secret-passphrase",
                "api_key": "secret-key",
                "authorization": "Bearer secret-authorization",
                "identity.key": "secret-identity",
                "auth": "secret-auth",
                "note": "visible"
            }
        }));
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key.clone()).unwrap();
        let value = client.request(ControlCommand::Status).unwrap();
        assert_eq!(value["token"], "[redacted]");
        assert_eq!(value["nested"]["password"], "[redacted]");
        assert_eq!(value["nested"]["passphrase"], "[redacted]");
        assert_eq!(value["nested"]["api_key"], "[redacted]");
        assert_eq!(value["nested"]["authorization"], "[redacted]");
        assert_eq!(value["nested"]["identity.key"], "[redacted]");
        assert_eq!(value["nested"]["auth"], "[redacted]");
        assert_eq!(value["nested"]["note"], "visible");
        let text = value.to_string();
        for secret in [
            "secret-token-value",
            "secret-password",
            "secret-passphrase",
            "secret-key",
            "secret-authorization",
            "secret-identity",
            "secret-auth",
            TEST_KEY_HEX,
        ] {
            assert!(!text.contains(secret), "{secret}");
        }

        handler.set_error(ControlError::Internal);
        let error = match client.request(ControlCommand::Diagnostics) {
            Ok(_) => panic!("the error was reported as success"),
            Err(error) => error,
        };
        assert_eq!(error, ControlError::Internal);
        assert_eq!(
            error.message(),
            "The service could not complete the operation."
        );
        assert!(!error.to_string().contains(TEST_KEY_HEX));

        let debug = format!("{key:?}");
        assert_eq!(debug, "SessionKey([redacted])");
        assert!(!debug.contains(TEST_KEY_HEX));
        drop(client);
        assert_eq!(wait_outcome(&outcome), complete(ServeStop::ParentClosed));
    }

    #[test]
    fn the_session_key_never_crosses_the_control_channel() {
        struct TapWriter<W> {
            inner: W,
            written: Arc<Mutex<Vec<u8>>>,
        }

        impl<W: Write> Write for TapWriter<W> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.written.lock().unwrap().extend_from_slice(bytes);
                self.inner.write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.inner.flush()
            }
        }

        let handler = Recorder::new();
        let key = test_key();
        let (client, server_reader, server_writer) = channel_pair();
        let Duplex { reader, writer } = client;
        let client_log = Arc::new(Mutex::new(Vec::new()));
        let server_log = Arc::new(Mutex::new(Vec::new()));
        let tap_client = TapWriter {
            inner: writer,
            written: Arc::clone(&client_log),
        };
        let tap_server = TapWriter {
            inner: server_writer,
            written: Arc::clone(&server_log),
        };
        let (sender, receiver) = mpsc::channel();
        let server_key = key.clone();
        thread::spawn(move || {
            let outcome = ControlServer::new(Arc::clone(&handler), server_key)
                .serve(server_reader, tap_server);
            let _ = sender.send(outcome);
        });
        let mut client = ControlClient::connect(reader, tap_client, key).unwrap();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        drop(client);
        assert_eq!(wait_outcome(&receiver), complete(ServeStop::ParentClosed));

        let key_bytes = test_key();
        let key_bytes = key_bytes.bytes();
        for log in [&client_log, &server_log] {
            let bytes = log.lock().unwrap();
            assert!(!bytes
                .windows(SESSION_KEY_LEN)
                .any(|window| window == key_bytes.as_slice()));
            assert!(!bytes
                .windows(SESSION_KEY_TEXT_LEN)
                .any(|window| window == TEST_KEY_HEX.as_bytes()));
        }
    }

    #[test]
    fn oversized_and_malformed_handler_answers_stay_bounded() {
        let handler = Recorder::new();
        handler.set_ok(json!({"text": "a".repeat(MAX_RESPONSE_PAYLOAD)}));
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        match client.request(ControlCommand::Status) {
            Err(ControlError::TooLarge) => (),
            other => panic!("unexpected answer: {other:?}"),
        }

        handler.set_ok(json!([1, 2, 3]));
        match client.request(ControlCommand::Diagnostics) {
            Err(ControlError::Internal) => (),
            other => panic!("unexpected answer: {other:?}"),
        }

        handler.set_ok(json!({"ok": true}));
        assert_eq!(
            client.request(ControlCommand::Failures).unwrap(),
            json!({"ok": true})
        );
        drop(client);
        assert_eq!(wait_outcome(&outcome), complete(ServeStop::ParentClosed));
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn shutdown_replies_then_stops_the_server() {
        let handler = Recorder::new();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        client.request_shutdown().unwrap();
        assert_eq!(
            wait_outcome(&outcome),
            complete(ServeStop::ShutdownRequested)
        );
        assert_eq!(handler.shutdowns(), 1);
        match client.request(ControlCommand::Status) {
            Err(ControlError::Disconnected) => (),
            other => panic!("unexpected answer: {other:?}"),
        }
        assert_eq!(handler.commands(), vec![ControlCommand::Shutdown]);
    }

    #[test]
    fn a_refused_shutdown_is_not_a_clean_stop() {
        let handler = Recorder::new();
        handler.set_error(ControlError::Refused);
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        match client.request_shutdown() {
            Err(ControlError::Refused) => (),
            other => panic!("unexpected answer: {other:?}"),
        }
        let outcome = wait_outcome(&outcome);
        assert_eq!(
            outcome.stop(),
            ServeStop::ShutdownRefused(ControlError::Refused)
        );
        assert_eq!(outcome.cleanup(), CleanupOutcome::Complete);
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.shutdowns(), 1);
        assert_eq!(handler.commands(), vec![ControlCommand::Shutdown]);
        match client.request(ControlCommand::Status) {
            Err(ControlError::Disconnected) => (),
            other => panic!("unexpected answer: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_shutdown_answer_is_not_a_clean_stop() {
        let handler = Recorder::new();
        handler.set_ok(json!([1, 2, 3]));
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        match client.request_shutdown() {
            Err(ControlError::Internal) => (),
            other => panic!("unexpected answer: {other:?}"),
        }
        let outcome = wait_outcome(&outcome);
        assert_eq!(
            outcome.stop(),
            ServeStop::ShutdownRefused(ControlError::Internal)
        );
        assert_eq!(outcome.cleanup(), CleanupOutcome::Complete);
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn an_oversized_shutdown_answer_is_not_a_clean_stop() {
        let handler = Recorder::new();
        handler.set_ok(json!({"text": "a".repeat(MAX_RESPONSE_PAYLOAD)}));
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        match client.request_shutdown() {
            Err(ControlError::TooLarge) => (),
            other => panic!("unexpected answer: {other:?}"),
        }
        let outcome = wait_outcome(&outcome);
        assert_eq!(
            outcome.stop(),
            ServeStop::ShutdownRefused(ControlError::TooLarge)
        );
        assert_eq!(outcome.cleanup(), CleanupOutcome::Complete);
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn a_handler_panic_fails_closed_and_cleanup_still_runs() {
        let handler = Recorder::new();
        handler.panic_on_handle();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let mut client = connect(duplex, key).unwrap();
        match client.request(ControlCommand::Status) {
            Err(ControlError::Internal) => (),
            other => panic!("unexpected answer: {other:?}"),
        }
        let outcome = wait_outcome(&outcome);
        assert_eq!(
            outcome.stop(),
            ServeStop::Fault(ControlFault::HandlerPanicked)
        );
        assert_eq!(outcome.cleanup(), CleanupOutcome::Complete);
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.shutdowns(), 1);
        assert_eq!(handler.commands(), vec![ControlCommand::Status]);
    }

    #[test]
    fn parent_loss_reports_a_cleanup_failure() {
        let handler = Recorder::new();
        handler.set_cleanup(Err(ControlError::Busy));
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let client = connect(duplex, key).unwrap();
        drop(client);
        let outcome = wait_outcome(&outcome);
        assert_eq!(outcome.stop(), ServeStop::ParentClosed);
        assert_eq!(
            outcome.cleanup(),
            CleanupOutcome::Failed(ControlError::Busy)
        );
        assert!(!outcome.stopped_cleanly());
        assert!(!outcome.cleanup_complete());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn a_cleanup_panic_is_reported_and_not_clean() {
        let handler = Recorder::new();
        handler.panic_on_cleanup();
        let key = test_key();
        let (duplex, outcome) = start_server(ControlServer::new(Arc::clone(&handler), key.clone()));
        let client = connect(duplex, key).unwrap();
        drop(client);
        let outcome = wait_outcome(&outcome);
        assert_eq!(outcome.stop(), ServeStop::ParentClosed);
        assert_eq!(outcome.cleanup(), CleanupOutcome::Panicked);
        assert!(!outcome.stopped_cleanly());
        assert!(!outcome.cleanup_complete());
        assert_eq!(handler.shutdowns(), 1);
    }

    #[test]
    fn service_integration_fails_closed_without_parent_liveness() {
        let enforced = PARENT_LIVENESS_ENFORCED;
        let independent = PARENT_LOSS_OBSERVED_INDEPENDENTLY;
        let cancellable = HANDLER_STALL_CANCELLABLE;
        let guaranteed = CLEANUP_GUARANTEED;
        assert!(!enforced);
        assert!(independent);
        assert!(!cancellable);
        assert!(!guaranteed);
        assert!(!SERVICE_REQUIREMENTS.is_empty());
        assert!(SERVICE_REQUIREMENTS.contains(&ServiceRequirement::BoundedHandler));
        assert!(SERVICE_REQUIREMENTS.contains(&ServiceRequirement::BoundedCleanup));
        assert!(SERVICE_REQUIREMENTS.contains(&ServiceRequirement::ProcessExit));
        assert!(SERVICE_REQUIREMENTS.contains(&ServiceRequirement::BoundedOutput));
        assert!(SERVICE_REQUIREMENTS.contains(&ServiceRequirement::IndependentRouteCleanup));
        let result = ControlServer::new_for_service(Recorder::new(), test_key());
        assert!(matches!(result, Err(ControlError::Unsupported)));
    }

    #[test]
    fn session_key_reader_accepts_only_one_exact_line() {
        let mut input = io::Cursor::new(format!("{TEST_KEY_HEX}\n").into_bytes());
        let key = read_session_key(&mut input).unwrap();
        assert!(key.matches(&test_key()));

        let upper = TEST_KEY_HEX.to_ascii_uppercase();
        let mut input = io::Cursor::new(format!("{upper}\n").into_bytes());
        assert!(read_session_key(&mut input).unwrap().matches(&test_key()));

        for text in [
            String::new(),
            "abc".to_owned(),
            format!("{TEST_KEY_HEX}\r\n"),
            TEST_KEY_HEX.to_owned(),
            format!("{}g\n", &TEST_KEY_HEX[..SESSION_KEY_TEXT_LEN - 1]),
        ] {
            let mut input = io::Cursor::new(text.into_bytes());
            assert_eq!(
                read_session_key(&mut input).unwrap_err(),
                ControlError::InvalidKey
            );
        }
        assert_eq!(
            ControlError::InvalidKey.message(),
            "The session key is not valid."
        );
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn test_key() -> SessionKey {
        SessionKey::from_hex(KEY_HEX).unwrap()
    }

    struct PipeState {
        data: VecDeque<u8>,
        closed: bool,
    }

    struct Pipe {
        state: Mutex<PipeState>,
        ready: Condvar,
    }

    struct PipeWriter(Arc<Pipe>);

    struct PipeReader(Arc<Pipe>);

    fn pipe() -> (PipeWriter, PipeReader) {
        let pipe = Arc::new(Pipe {
            state: Mutex::new(PipeState {
                data: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
        });
        (PipeWriter(Arc::clone(&pipe)), PipeReader(pipe))
    }

    impl Write for PipeWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            state.data.extend(bytes.iter().copied());
            drop(state);
            self.0.ready.notify_all();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for PipeWriter {
        fn drop(&mut self) {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.closed = true;
            drop(state);
            self.0.ready.notify_all();
        }
    }

    impl Read for PipeReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            loop {
                if !state.data.is_empty() {
                    let count = buffer.len().min(state.data.len());
                    for slot in buffer.iter_mut().take(count) {
                        if let Some(byte) = state.data.pop_front() {
                            *slot = byte;
                        }
                    }
                    return Ok(count);
                }
                if state.closed {
                    return Ok(0);
                }
                state = self
                    .0
                    .ready
                    .wait(state)
                    .unwrap_or_else(|poison| poison.into_inner());
            }
        }
    }

    struct Gate {
        open: Mutex<bool>,
        ready: Condvar,
    }

    impl Gate {
        fn new() -> Self {
            Self {
                open: Mutex::new(false),
                ready: Condvar::new(),
            }
        }

        fn open(&self) {
            *self
                .open
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = true;
            self.ready.notify_all();
        }

        fn wait(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            let mut open = self
                .open
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            loop {
                if *open {
                    return true;
                }
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                let (guard, _) = self
                    .ready
                    .wait_timeout(open, deadline - now)
                    .unwrap_or_else(|poison| poison.into_inner());
                open = guard;
            }
        }
    }

    struct LifecycleHandler {
        handles: AtomicUsize,
        commands: Mutex<Vec<ControlCommand>>,
        cleanups: AtomicUsize,
        cleanup_done: AtomicUsize,
        cleanup_result: Mutex<Result<(), ControlError>>,
        reply: Mutex<Result<Value, ControlError>>,
        entered: Gate,
        release: Gate,
        cleanup_entered: Gate,
        cleanup_release: Gate,
        stall_handle: AtomicBool,
        honor_cancel: AtomicBool,
        stall_cleanup: AtomicBool,
        panic_cleanup: AtomicBool,
    }

    impl LifecycleHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                handles: AtomicUsize::new(0),
                commands: Mutex::new(Vec::new()),
                cleanups: AtomicUsize::new(0),
                cleanup_done: AtomicUsize::new(0),
                cleanup_result: Mutex::new(Ok(())),
                reply: Mutex::new(Ok(json!({"ok": true}))),
                entered: Gate::new(),
                release: Gate::new(),
                cleanup_entered: Gate::new(),
                cleanup_release: Gate::new(),
                stall_handle: AtomicBool::new(false),
                honor_cancel: AtomicBool::new(false),
                stall_cleanup: AtomicBool::new(false),
                panic_cleanup: AtomicBool::new(false),
            })
        }

        fn stall_handle(&self, honor_cancel: bool) {
            self.stall_handle.store(true, AtomicOrdering::SeqCst);
            self.honor_cancel
                .store(honor_cancel, AtomicOrdering::SeqCst);
        }

        fn set_cleanup(&self, result: Result<(), ControlError>) {
            *self
                .cleanup_result
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = result;
        }

        fn stall_cleanup(&self) {
            self.stall_cleanup.store(true, AtomicOrdering::SeqCst);
        }

        fn panic_cleanup(&self) {
            self.panic_cleanup.store(true, AtomicOrdering::SeqCst);
        }

        fn release_handle(&self) {
            self.release.open();
        }

        fn release_cleanup(&self) {
            self.cleanup_release.open();
        }

        fn handles(&self) -> usize {
            self.handles.load(AtomicOrdering::SeqCst)
        }

        fn cleanups(&self) -> usize {
            self.cleanups.load(AtomicOrdering::SeqCst)
        }

        fn cleanup_done(&self) -> usize {
            self.cleanup_done.load(AtomicOrdering::SeqCst)
        }

        fn run(
            &self,
            command: ControlCommand,
            cancel: Option<&CancelToken>,
        ) -> Result<Value, ControlError> {
            self.handles.fetch_add(1, AtomicOrdering::SeqCst);
            self.commands
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(command);
            self.entered.open();
            if self.stall_handle.load(AtomicOrdering::SeqCst) {
                if self.honor_cancel.load(AtomicOrdering::SeqCst) {
                    if let Some(cancel) = cancel {
                        let _ = cancel.wait(Duration::from_secs(30));
                    }
                } else {
                    let _ = self.release.wait(Duration::from_secs(30));
                }
            }
            self.reply
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
        }
    }

    impl ControlHandler for LifecycleHandler {
        fn handle(&self, command: ControlCommand) -> Result<Value, ControlError> {
            self.run(command, None)
        }

        fn handle_with_cancel(
            &self,
            command: ControlCommand,
            cancel: &CancelToken,
        ) -> Result<Value, ControlError> {
            self.run(command, Some(cancel))
        }

        fn shutdown(&self) -> Result<(), ControlError> {
            self.cleanups.fetch_add(1, AtomicOrdering::SeqCst);
            self.cleanup_entered.open();
            if self.stall_cleanup.load(AtomicOrdering::SeqCst) {
                let _ = self.cleanup_release.wait(Duration::from_secs(30));
            }
            if self.panic_cleanup.load(AtomicOrdering::SeqCst) {
                panic!("lifecycle cleanup panic");
            }
            let result = *self
                .cleanup_result
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            self.cleanup_done.fetch_add(1, AtomicOrdering::SeqCst);
            result
        }
    }

    struct Session {
        outcome: mpsc::Receiver<SupervisedOutcome>,
        cancel: CancelToken,
        parent: Option<PipeWriter>,
        input: Option<PipeReader>,
        output: Option<PipeWriter>,
    }

    fn start_session(handler: Arc<LifecycleHandler>, grace: Duration) -> Session {
        let (client_output, server_input) = pipe();
        let (server_output, client_input) = pipe();
        let (parent_output, parent_input) = pipe();
        let cancel = CancelToken::new();
        let server = ControlServer::new(handler, test_key());
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let outcome = server.supervise(
                server_input,
                server_output,
                parent_input,
                worker_cancel,
                grace,
            );
            let _ = sender.send(outcome);
        });
        Session {
            outcome: receiver,
            cancel,
            parent: Some(parent_output),
            input: Some(client_input),
            output: Some(client_output),
        }
    }

    impl Session {
        fn connect(&mut self) -> ControlClient<PipeReader, PipeWriter> {
            let input = self.input.take().expect("client input");
            let output = self.output.take().expect("client output");
            ControlClient::connect(input, output, test_key()).expect("handshake")
        }

        fn lose_parent(&mut self) {
            drop(self.parent.take());
        }

        fn wait(&mut self) -> SupervisedOutcome {
            self.outcome
                .recv_timeout(Duration::from_secs(10))
                .expect("the supervisor did not return")
        }
    }

    fn wait_until(mut condition: impl FnMut() -> bool, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        condition()
    }

    fn request_status_frame(client: &mut ControlClient<PipeReader, PipeWriter>, id: u32) {
        write_frame(
            &mut client.output,
            FrameKind::Request,
            id,
            &ControlCommand::Status.encode(),
        )
        .unwrap();
    }

    fn request_shutdown_frame(client: &mut ControlClient<PipeReader, PipeWriter>, id: u32) {
        write_frame(
            &mut client.output,
            FrameKind::Request,
            id,
            &ControlCommand::Shutdown.encode(),
        )
        .unwrap();
    }

    #[test]
    fn independent_parent_loss_stops_an_open_channel() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        assert_eq!(handler.handles(), 1);

        // The control channel stays open. Only the independent liveness channel
        // reports the parent loss.
        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(outcome.cancel(), Some(CancelReason::ParentLost));
        assert_eq!(
            outcome.stop().unwrap().stop(),
            ServeStop::Cancelled(CancelReason::ParentLost)
        );
        assert_eq!(outcome.cleanup(), CleanupOutcome::Complete);
        assert_eq!(outcome.cleanup_phase(), CleanupPhase::Finished);
        assert!(outcome.stopped_cleanly());
        assert!(outcome.worker_stopped());
        assert!(outcome.waited() < Duration::from_secs(3));
        assert_eq!(handler.cleanups(), 1);

        // No implicit restart. The engine does not serve another request.
        assert_eq!(
            client.request(ControlCommand::Diagnostics).unwrap_err(),
            ControlError::Disconnected
        );
        thread::sleep(Duration::from_millis(50));
        assert_eq!(handler.handles(), 1);
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn a_partial_frame_does_not_delay_parent_loss() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        let mut partial = Vec::new();
        partial.extend_from_slice(&MAGIC);
        partial.extend_from_slice(&[VERSION, FrameKind::Request as u8, 0, 0]);
        partial.extend_from_slice(&1u32.to_be_bytes());
        partial.extend_from_slice(&4u32.to_be_bytes());
        partial.push(CMD_STATUS);
        client.output.write_all(&partial).unwrap();
        thread::sleep(Duration::from_millis(50));

        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(
            outcome.stop().unwrap().stop(),
            ServeStop::Cancelled(CancelReason::ParentLost)
        );
        assert!(outcome.stopped_cleanly());
        assert!(outcome.waited() < Duration::from_secs(3));
        assert_eq!(handler.handles(), 0);
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn local_stop_ends_a_stalled_input() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        let mut partial = Vec::new();
        partial.extend_from_slice(&MAGIC);
        partial.extend_from_slice(&[VERSION, FrameKind::Request as u8, 0, 0]);
        partial.extend_from_slice(&1u32.to_be_bytes());
        partial.extend_from_slice(&4u32.to_be_bytes());
        partial.push(CMD_STATUS);
        client.output.write_all(&partial).unwrap();
        thread::sleep(Duration::from_millis(50));

        // The control input is stalled inside a partial frame. The local stop
        // still reaches the session loop and cleanup runs.
        assert!(session.cancel.request(CancelReason::LocalStop));
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(
            outcome.stop().unwrap().stop(),
            ServeStop::Cancelled(CancelReason::LocalStop)
        );
        assert!(outcome.stopped_cleanly());
        assert!(outcome.waited() < Duration::from_secs(3));
        assert_eq!(handler.handles(), 0);
    }

    #[test]
    fn parent_loss_before_the_handshake_stops_cleanly() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let started = Instant::now();
        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(
            outcome.stop().unwrap().stop(),
            ServeStop::Cancelled(CancelReason::ParentLost)
        );
        assert!(outcome.stopped_cleanly());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(handler.handles(), 0);
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn local_stop_ends_the_session_without_parent_loss() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        assert!(session.cancel.request(CancelReason::LocalStop));
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(outcome.cancel(), Some(CancelReason::LocalStop));
        assert_eq!(
            outcome.stop().unwrap().stop(),
            ServeStop::Cancelled(CancelReason::LocalStop)
        );
        assert!(outcome.stopped_cleanly());
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn a_cancel_request_stops_a_cooperative_handler() {
        let handler = LifecycleHandler::new();
        handler.stall_handle(true);
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        request_status_frame(&mut client, 1);
        assert!(handler.entered.wait(Duration::from_secs(2)));

        let started = Instant::now();
        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(
            outcome.stop().unwrap().stop(),
            ServeStop::Cancelled(CancelReason::ParentLost)
        );
        assert!(outcome.stopped_cleanly());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(handler.handles(), 1);
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn a_stalled_handler_is_reported_as_parked_and_not_clean() {
        let handler = LifecycleHandler::new();
        handler.stall_handle(false);
        let grace = Duration::from_millis(150);
        let mut session = start_session(Arc::clone(&handler), grace);
        let mut client = session.connect();
        request_status_frame(&mut client, 1);
        assert!(handler.entered.wait(Duration::from_secs(2)));

        let started = Instant::now();
        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Parked);
        assert_eq!(outcome.cancel(), Some(CancelReason::ParentLost));
        assert_eq!(outcome.cleanup(), CleanupOutcome::Unfinished);
        assert_eq!(outcome.cleanup_phase(), CleanupPhase::Idle);
        assert!(!outcome.cleanup_complete());
        assert!(!outcome.stopped_cleanly());
        assert!(!outcome.worker_stopped());
        assert!(outcome.waited() >= grace);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(handler.cleanups(), 0);

        // Release the handler. The worker finishes the session and runs cleanup
        // exactly once. No second worker exists.
        handler.release_handle();
        assert!(wait_until(
            || handler.cleanup_done() == 1,
            Duration::from_secs(3)
        ));
        assert_eq!(handler.cleanups(), 1);
        assert_eq!(handler.handles(), 1);
    }

    #[test]
    fn a_cleanup_failure_is_reported_and_is_not_clean() {
        let handler = LifecycleHandler::new();
        handler.set_cleanup(Err(ControlError::Busy));
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(
            outcome.cleanup(),
            CleanupOutcome::Failed(ControlError::Busy)
        );
        assert!(!outcome.cleanup_complete());
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn a_cleanup_panic_is_reported_and_is_not_clean() {
        let handler = LifecycleHandler::new();
        handler.panic_cleanup();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        assert_eq!(
            client.request(ControlCommand::Status).unwrap(),
            json!({"ok": true})
        );
        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(outcome.cleanup(), CleanupOutcome::Panicked);
        assert_eq!(outcome.cleanup_phase(), CleanupPhase::Finished);
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn a_cleanup_stall_is_reported_as_parked_during_cleanup() {
        let handler = LifecycleHandler::new();
        handler.stall_cleanup();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(150));
        let mut client = session.connect();
        // The shutdown command returns a reply, ends the session loop, and
        // enters cleanup. Cleanup then stalls. Parent loss arrives while
        // cleanup is already running.
        request_shutdown_frame(&mut client, 1);
        assert!(handler.cleanup_entered.wait(Duration::from_secs(2)));

        session.lose_parent();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Parked);
        assert_eq!(outcome.cancel(), Some(CancelReason::ParentLost));
        assert_eq!(outcome.cleanup(), CleanupOutcome::Unfinished);
        assert_eq!(outcome.cleanup_phase(), CleanupPhase::Running);
        assert!(!outcome.stopped_cleanly());
        assert_eq!(handler.cleanups(), 1);

        handler.release_cleanup();
        assert!(wait_until(
            || handler.cleanup_done() == 1,
            Duration::from_secs(3)
        ));
    }

    #[test]
    fn the_parent_watcher_ignores_bytes_and_reports_loss() {
        let (mut writer, reader) = pipe();
        let cancel = CancelToken::new();
        let _watch = ParentWatch::start(reader, cancel.clone()).unwrap();
        writer.write_all(b"noise").unwrap();
        assert_eq!(cancel.wait(Duration::from_millis(100)), None);
        assert!(!cancel.is_requested());

        drop(writer);
        assert_eq!(
            cancel.wait(Duration::from_secs(2)),
            Some(CancelReason::ParentLost)
        );
    }

    #[test]
    fn a_parent_watch_read_error_counts_as_loss() {
        struct FailReader;

        impl Read for FailReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("gone"))
            }
        }

        let cancel = CancelToken::new();
        let _watch = ParentWatch::start(FailReader, cancel.clone()).unwrap();
        assert_eq!(
            cancel.wait(Duration::from_secs(2)),
            Some(CancelReason::ParentLost)
        );
    }

    #[test]
    fn a_parent_watch_reader_panic_counts_as_loss() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                panic!("reader failed");
            }
        }
        let cancel = CancelToken::new();
        let _watch = ParentWatch::start(PanicReader, cancel.clone()).unwrap();
        assert_eq!(
            cancel.wait(Duration::from_secs(2)),
            Some(CancelReason::ParentLost)
        );
    }

    #[test]
    fn a_shutdown_acknowledgement_does_not_claim_cleanup_succeeded() {
        let handler = LifecycleHandler::new();
        handler.set_cleanup(Err(ControlError::Busy));
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        client.request_shutdown().unwrap();
        let outcome = session.wait();
        assert_eq!(outcome.stop().unwrap().stop(), ServeStop::ShutdownRequested);
        assert_eq!(
            outcome.cleanup(),
            CleanupOutcome::Failed(ControlError::Busy)
        );
        assert!(!outcome.stopped_cleanly());
        assert!(outcome.requires_process_exit());
    }

    #[test]
    fn every_supervisor_outcome_requires_process_exit() {
        for reason in [
            ServeStop::ParentClosed,
            ServeStop::Cancelled(CancelReason::ParentLost),
            ServeStop::Cancelled(CancelReason::LocalStop),
            ServeStop::ShutdownRequested,
        ] {
            let stop = ServeOutcome::new(reason, CleanupOutcome::Complete);
            let outcome =
                SupervisedOutcome::stopped(stop, None, CleanupPhase::Finished, Duration::ZERO);
            assert!(outcome.stopped_cleanly());
            assert!(outcome.requires_process_exit());
        }
        for state in [
            SupervisionState::Parked,
            SupervisionState::Lost,
            SupervisionState::NotStarted,
        ] {
            let outcome =
                SupervisedOutcome::halted(state, None, CleanupPhase::Idle, Duration::ZERO);
            assert!(outcome.requires_process_exit());
            assert!(!outcome.stopped_cleanly());
        }
    }

    #[test]
    fn the_first_cancel_reason_wins() {
        let cancel = CancelToken::new();
        assert!(cancel.request(CancelReason::LocalStop));
        assert!(!cancel.request(CancelReason::ParentLost));
        assert_eq!(cancel.reason(), Some(CancelReason::LocalStop));
        assert_eq!(
            cancel.wait(Duration::from_millis(10)),
            Some(CancelReason::LocalStop)
        );
        let debug = format!("{cancel:?}");
        assert!(debug.contains("LocalStop"));
        assert!(!debug.contains(KEY_HEX));
    }

    #[test]
    fn the_shutdown_command_ends_the_supervised_session() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        let mut client = session.connect();
        client.request_shutdown().unwrap();
        let outcome = session.wait();
        assert_eq!(outcome.state(), SupervisionState::Stopped);
        assert_eq!(outcome.stop().unwrap().stop(), ServeStop::ShutdownRequested);
        assert_eq!(outcome.cancel(), None);
        assert!(outcome.stopped_cleanly());
        assert!(outcome.requires_process_exit());
        assert_eq!(handler.cleanups(), 1);
    }

    #[test]
    fn lifecycle_types_hold_no_secret_text() {
        let handler = LifecycleHandler::new();
        let mut session = start_session(Arc::clone(&handler), Duration::from_millis(500));
        session.lose_parent();
        let outcome = session.wait();
        let debug = format!("{outcome:?}");
        assert!(!debug.contains(KEY_HEX));
        let key = test_key();
        let key_bytes = key.bytes();
        assert!(!debug
            .as_bytes()
            .windows(SESSION_KEY_LEN)
            .any(|window| window == key_bytes.as_slice()));
    }
}
