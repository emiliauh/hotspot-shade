//! Source-device pairing responder foundation, protocol v1.
//!
//! This module holds the source-device side of the pairing protocol. It is a
//! transport-agnostic state machine. It opens no socket, writes no file, and
//! calls no Android or iOS API. The host app owns the listener, the frames,
//! the clock, the trust store, and the user prompt.
//!
//! The target device side is [`crate::pairing`]. The Swift source device app
//! implements the same behaviour in `ios/HotspotProxy/Pairing.swift`. The
//! protocol and the fixed vectors are shared. Change all three together.
//!
//! # Limits
//!
//! This is a foundation, not a finished Android source device app. The host
//! still needs a hotspot-only listener, a persistent trust store, a protected
//! token store, foreground and background lifecycle handling, and live device
//! tests. This module does not claim that Android pairing works.
//!
//! # Secrets
//!
//! The module never logs or formats the proxy token, a private key, or a
//! stored identity key. It returns no token. [`PairingCredentials`] redacts its
//! token in `Debug` output and erases it on drop. [`SessionKeys`] already
//! redacts and erases its key material. [`Output`] shows only a frame count and
//! a status, not bytes.
//!
//! # Protocol notes
//!
//! Protocol v1 has no source-device long-term identity on the wire. The only
//! long-term identity is the target device static public key `L_s` in the
//! injected trust store. [`PairingIdentity`] supplies the per-session source
//! ephemeral key and the AEAD nonces. Do not add a source-device key to the
//! wire format without a protocol change and new parity vectors.
//!
//! The source device fails closed:
//!
//! - An unknown target device gets no prompt for a status-only or forget
//!   HELLO. It gets RESULT status Rejected.
//! - A status or forget command requires a trusted key after the proof.
//! - An invalid frame, an unknown flag, or a bad proof gets RESULT Rejected.
//! - A trust-store or random-source failure returns an error. The host must
//!   close the connection and must not send the pending frame.
//! - An unknown source address gets at most MAX_PEER_CHALLENGES challenges in
//!   CHALLENGE_WINDOW_SECONDS. All unknown source addresses together get at
//!   most MAX_UNKNOWN_CHALLENGES challenges in the same window. The state
//!   machine charges both budgets before it creates the ephemeral secret. It
//!   charges no budget when the source device has no pairing credentials. It
//!   answers NotActive in that case. A trusted key skips both budgets: that
//!   path is intentionally unbudgeted. The budgets are an availability limit,
//!   not an authentication limit.
//! - An approval must name the connection, the prompt ID, and the displayed
//!   code. A stale connection, a stale prompt, a wrong code, or an expired
//!   deadline does not approve a prompt.
//! - The state table and the rate-limit maps have fixed bounds.

use crate::pairing::frame as wire_frame;
use crate::pairing::{
    agree, commitment, decode_hello, decode_reveal, derive_keys, encode_challenge,
    encode_result_ok, encode_result_status, format_code, sas_code, transcript_hash, verify_proof,
    PhoneCredentials, SessionKeys, MAX_FRAME,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

/// The source device listens for pairings on this port, on the hotspot address
/// only. The module does not open the listener.
pub const PAIRING_PORT: u16 = crate::pairing::PAIRING_PORT;

/// The STATUS_REQ message type.
pub const MSG_STATUS_REQ: u8 = 0x05;
/// The STATUS message type.
pub const MSG_STATUS: u8 = 0x06;
/// The FORGET message type.
pub const MSG_FORGET: u8 = 0x07;

/// The largest number of active pairing sessions. The Swift source device app
/// also allows four pairing connections. A new connection over the cap gets a
/// busy result and a close.
pub const MAX_SESSIONS: usize = 4;

/// The largest buffered byte count for [`FrameReader`]. A caller can hold four
/// maximum-size frames before it must drain the reader.
pub const MAX_BUFFERED: usize = 4 * (2 + MAX_FRAME);

/// The largest peer identifier that the state machine accepts. A source
/// address text is shorter than this limit.
pub const MAX_PEER_LEN: usize = 64;

const MAX_TRACKED_PEERS: usize = 256;
const MAX_UNKNOWN_ATTEMPTS: usize = 3;
const MAX_INVALID_FAILURES: usize = 10;
const FAILURES_FOR_LOCKOUT: usize = 3;
const MAX_BACKOFF_LEVEL: u8 = 2;
const REVEAL_SECONDS: u64 = 5;
const DECISION_SECONDS: u64 = 60;
const INACTIVE_DECISION_SECONDS: u64 = 120;
const LOCKOUT_SECONDS: u64 = 30;
const UNKNOWN_WINDOW_SECONDS: u64 = 600;
const FAILURE_WINDOW_SECONDS: u64 = 60;
const INVALID_WINDOW_SECONDS: u64 = 60;
const MAX_SESSION_NONCES: usize = 4;
/// The largest number of unknown challenges across all source addresses in
/// CHALLENGE_WINDOW_SECONDS.
const MAX_UNKNOWN_CHALLENGES: usize = 8;
/// The largest number of unknown challenges from one source address in
/// CHALLENGE_WINDOW_SECONDS. One source address cannot use the whole global
/// budget.
const MAX_PEER_CHALLENGES: usize = 4;
const CHALLENGE_WINDOW_SECONDS: u64 = 60;
static NEXT_PROMPT_ID: AtomicUsize = AtomicUsize::new(1);

fn next_prompt_id() -> Result<PromptId, SourcePairingError> {
    let mut current = NEXT_PROMPT_ID.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).ok_or(SourcePairingError::Protocol)?;
        match NEXT_PROMPT_ID.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(PromptId(current)),
            Err(actual) => current = actual,
        }
    }
}

/// A pairing status byte from RESULT. Re-exported from the target side so both
/// sides use one definition.
pub use crate::pairing::PhoneStatus as PairingStatus;

/// A host connection identifier. The host chooses the value and keeps it
/// stable for one pairing connection.
pub type ConnectionId = u64;

/// Identifies one displayed decision, even if a connection ID is reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromptId(usize);

/// One atomic snapshot for the host to display and later approve or deny.
///
/// The `Debug` output redacts the displayed code. A log line must not hold a
/// value that a person reads from the screen.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingPrompt {
    pub id: PromptId,
    pub connection: ConnectionId,
    pub code: String,
}

impl fmt::Debug for PairingPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingPrompt")
            .field("id", &self.id)
            .field("connection", &self.connection)
            .field("code", &"[redacted]")
            .finish()
    }
}

/// A pairing failure that the host must handle. The text of each variant is
/// fixed and holds no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourcePairingError {
    /// A frame or message has a bad shape.
    Protocol,
    /// A byte-stream buffer passed the fixed bound.
    FrameTooLarge,
    /// The random source failed.
    Identity,
    /// The injected trust store failed.
    TrustStore,
    /// The injected clock moved backwards.
    Clock,
    /// The peer identifier is not usable.
    Peer,
    /// The injected credentials or status are not usable.
    Configuration,
}

impl SourcePairingError {
    /// A fixed message that is safe to show to a person.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Protocol => "The pairing message is invalid.",
            Self::FrameTooLarge => "The pairing message is too large.",
            Self::Identity => "The source device random source failed.",
            Self::TrustStore => "The source device trust store failed.",
            Self::Clock => "The source device clock moved backwards.",
            Self::Peer => "The pairing peer identifier is not usable.",
            Self::Configuration => "The source device pairing settings are invalid.",
        }
    }
}

impl fmt::Display for SourcePairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SourcePairingError {}

/// A monotonic clock. The host injects it. The state machine rejects a value
/// below the last value, so a wall-clock jump cannot extend a deadline.
pub trait Clock {
    fn now(&self) -> Duration;
}

/// The per-session identity material for the source device.
///
/// Protocol v1 has no source-device long-term wire key. `ephemeral_secret`
/// returns a fresh X25519 secret for `P_e` for every session. `nonce` returns a fresh 12-byte AEAD
/// nonce for every sealed message. A nonce must never repeat under one
/// `k_enc`. Use [`OsRandomIdentity`] in production.
pub trait PairingIdentity {
    fn ephemeral_secret(&mut self) -> Result<[u8; 32], SourcePairingError>;
    fn nonce(&mut self) -> Result<[u8; 12], SourcePairingError>;
}

/// The trust store for target-device static public keys. The host saves the
/// keys across app launches. [`MemoryTrustStore`] is for tests and previews.
pub trait PairingTrustStore {
    fn contains(&self, public_key: &[u8; 32]) -> bool;
    fn add(&mut self, public_key: &[u8; 32]) -> Result<(), SourcePairingError>;
    fn remove(&mut self, public_key: &[u8; 32]) -> Result<(), SourcePairingError>;
}

/// The proxy credentials that the source device sends after a successful
/// pairing. The token is private and is erased on drop.
pub struct PairingCredentials {
    host: Ipv4Addr,
    port: u16,
    token: String,
}

impl PairingCredentials {
    /// Create credentials for the pairing result.
    ///
    /// The port must be 1024 to 65535 and must not be [`PAIRING_PORT`]. The
    /// host must be a usable IPv4 hotspot address. The token must be 1 to 255
    /// printable ASCII bytes. A refused value returns
    /// [`SourcePairingError::Configuration`] and erases the token.
    pub fn new(
        host: Ipv4Addr,
        port: u16,
        token: impl Into<String>,
    ) -> Result<Self, SourcePairingError> {
        let mut token = token.into();
        if !is_usable_host(host)
            || !is_usable_proxy_port(port)
            || token.is_empty()
            || token.len() > 255
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            zeroize::Zeroize::zeroize(&mut token);
            return Err(SourcePairingError::Configuration);
        }
        Ok(Self { host, port, token })
    }

    pub fn host(&self) -> Ipv4Addr {
        self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn as_phone_credentials(&self) -> PhoneCredentials {
        PhoneCredentials {
            host: self.host,
            port: self.port,
            token: self.token.clone(),
        }
    }
}

impl Drop for PairingCredentials {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

impl fmt::Debug for PairingCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCredentials")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("token", &"[redacted]")
            .finish()
    }
}

/// The live status that the source device sends on the authenticated pairing
/// channel. It holds no token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyStatus {
    pub proxy_running: bool,
    pub foreground: bool,
    pub connections: u16,
    pub port: u16,
    pub host: Ipv4Addr,
    /// The app sends 0. The field stays in the wire format for parity.
    pub sequence: u32,
}

/// The proxy credentials and live status. The host injects one implementation.
/// A missing value makes the state machine answer NotActive or Rejected.
pub trait PairingContext {
    fn credentials(&self) -> Option<&PairingCredentials>;
    fn status(&self) -> Option<&ProxyStatus>;
}

/// A host action after one frame, one timer expiry, or one user decision.
///
/// `frames` holds complete wire frames. Each frame already has its u16 length
/// prefix. Write the frames in order. If `close` is true, close the connection
/// after the last frame. `status` is for host logging only and holds no secret.
/// Bytes in `frames` stay private: they can hold encrypted credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct Output {
    pub connection: ConnectionId,
    pub frames: Vec<Vec<u8>>,
    pub close: bool,
    pub status: Option<PairingStatus>,
}

impl Output {
    fn empty(connection: ConnectionId) -> Self {
        Self {
            connection,
            frames: Vec::new(),
            close: false,
            status: None,
        }
    }

    fn frames(
        connection: ConnectionId,
        frames: Vec<Vec<u8>>,
        close: bool,
        status: Option<PairingStatus>,
    ) -> Self {
        Self {
            connection,
            frames,
            close,
            status,
        }
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("connection", &self.connection)
            .field("frame_count", &self.frames.len())
            .field("close", &self.close)
            .field("status", &self.status)
            .finish()
    }
}

/// A bounded frame reader for a byte stream.
///
/// The reader holds at most [`MAX_BUFFERED`] bytes. It rejects an empty frame
/// and a frame payload above [`MAX_FRAME`]. A caller must drain complete frames
/// with [`FrameReader::next_frame`] before it pushes again. A parser error
/// means that the caller must close the connection and call
/// [`PairingResponder::receive_invalid`].
#[derive(Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    /// Add bytes. A value that would pass [`MAX_BUFFERED`] is refused.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SourcePairingError> {
        if bytes.len() > MAX_BUFFERED.saturating_sub(self.buffer.len()) {
            return Err(SourcePairingError::FrameTooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Return the next complete frame payload. The length prefix is removed.
    /// `None` means that more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, SourcePairingError> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(SourcePairingError::Protocol);
        }
        if self.buffer.len() < 2 + length {
            return Ok(None);
        }
        let payload = self.buffer[2..2 + length].to_vec();
        self.buffer.drain(..2 + length);
        Ok(Some(payload))
    }

    /// The byte count that the reader holds now.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

/// The random identity source for a real host. It uses the existing operating
/// system random helper from [`crate::pairing`].
///
/// The shared helper uses `getentropy` on macOS and Linux. Bionic exports
/// `getentropy` only from API 28, so the helper reads `/dev/urandom` on
/// Android. The Linux kernel CSPRNG backs that device. The Android minimum is
/// API 26. A failed source returns [`SourcePairingError::Identity`]. The host
/// must close the connection and must not send the pending frame. This module
/// does not add a JNI random path.
#[derive(Default)]
pub struct OsRandomIdentity;

impl PairingIdentity for OsRandomIdentity {
    fn ephemeral_secret(&mut self) -> Result<[u8; 32], SourcePairingError> {
        let mut bytes = [0u8; 32];
        crate::pairing::random_bytes(&mut bytes).map_err(|_| SourcePairingError::Identity)?;
        Ok(bytes)
    }

    fn nonce(&mut self) -> Result<[u8; 12], SourcePairingError> {
        let mut bytes = [0u8; 12];
        crate::pairing::random_bytes(&mut bytes).map_err(|_| SourcePairingError::Identity)?;
        Ok(bytes)
    }
}

/// A trust store in process memory. It is for tests, previews, and a host that
/// loads and saves the key list itself. It is not persistent.
#[derive(Default, Debug)]
pub struct MemoryTrustStore {
    keys: BTreeSet<[u8; 32]>,
}

impl MemoryTrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn clear(&mut self) {
        self.keys.clear();
    }
}

impl PairingTrustStore for MemoryTrustStore {
    fn contains(&self, public_key: &[u8; 32]) -> bool {
        self.keys.contains(public_key)
    }

    fn add(&mut self, public_key: &[u8; 32]) -> Result<(), SourcePairingError> {
        self.keys.insert(*public_key);
        Ok(())
    }

    fn remove(&mut self, public_key: &[u8; 32]) -> Result<(), SourcePairingError> {
        self.keys.remove(public_key);
        Ok(())
    }
}

/// The host-supplied dependencies. The state machine owns no global state.
pub struct PairingResponderDependencies {
    pub identity: Box<dyn PairingIdentity>,
    pub trust: Box<dyn PairingTrustStore>,
    pub context: Box<dyn PairingContext>,
    pub clock: Box<dyn Clock>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitingReveal,
    AwaitingDecision,
    Authenticated,
}

enum Stage {
    AwaitingReveal {
        ephemeral: StaticSecret,
        commit: [u8; 32],
    },
    AwaitingDecision(SessionKeys, PromptId),
    Authenticated(SessionKeys),
}

struct Session {
    connection: ConnectionId,
    l_s: [u8; 32],
    known: bool,
    flags: u8,
    shown_active: bool,
    deadline: Duration,
    first_deactivate: Option<Duration>,
    peer: String,
    nonces: Vec<[u8; 12]>,
    stage: Stage,
}

impl Session {
    fn phase(&self) -> Phase {
        match self.stage {
            Stage::AwaitingReveal { .. } => Phase::AwaitingReveal,
            Stage::AwaitingDecision(..) => Phase::AwaitingDecision,
            Stage::Authenticated(_) => Phase::Authenticated,
        }
    }
}

#[derive(Default)]
struct InvalidBudget {
    failures: Vec<Duration>,
    until: Duration,
    level: u8,
}

/// The source-device pairing responder state machine.
///
/// One pairing decision runs at a time. The host calls every method on one
/// thread or with its own lock. Do not call one responder from two threads.
pub struct PairingResponder {
    identity: Box<dyn PairingIdentity>,
    trust: Box<dyn PairingTrustStore>,
    context: Box<dyn PairingContext>,
    clock: Box<dyn Clock>,
    sessions: BTreeMap<ConnectionId, Session>,
    unknown_budget: BTreeMap<String, Vec<Duration>>,
    /// The times of the unknown challenges, for each source address. The sum of
    /// the lists is at most MAX_UNKNOWN_CHALLENGES, so the map stays small.
    unknown_challenges: BTreeMap<String, Vec<Duration>>,
    invalid_budget: BTreeMap<String, InvalidBudget>,
    failures: BTreeMap<String, Vec<Duration>>,
    lockouts: BTreeMap<String, Duration>,
    decision: Option<ConnectionId>,
    app_active: bool,
    last_now: Duration,
}

impl PairingResponder {
    pub fn new(dependencies: PairingResponderDependencies) -> Self {
        Self {
            identity: dependencies.identity,
            trust: dependencies.trust,
            context: dependencies.context,
            clock: dependencies.clock,
            sessions: BTreeMap::new(),
            unknown_budget: BTreeMap::new(),
            unknown_challenges: BTreeMap::new(),
            invalid_budget: BTreeMap::new(),
            failures: BTreeMap::new(),
            lockouts: BTreeMap::new(),
            decision: None,
            app_active: false,
            last_now: Duration::ZERO,
        }
    }

    /// Return the current unexpired prompt as one snapshot. The host must
    /// return this connection, this ID, and this code with the user's decision.
    /// `None` means that no prompt waits or that its deadline passed.
    pub fn pending_prompt(&self) -> Option<PairingPrompt> {
        let connection = self.decision?;
        let session = self.sessions.get(&connection)?;
        let now = self.clock.now();
        if now < self.last_now || now >= session.deadline {
            return None;
        }
        match &session.stage {
            Stage::AwaitingDecision(keys, id) => Some(PairingPrompt {
                id: *id,
                connection,
                code: format_code(&sas_code(&keys.sas)),
            }),
            _ => None,
        }
    }

    /// The earliest session deadline. The host calls [`Self::tick`] at or after
    /// this value.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.sessions.values().map(|session| session.deadline).min()
    }

    /// The active session count.
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Handle one complete frame payload. The length prefix is not part of
    /// `frame`.
    ///
    /// `peer` is the source address text for rate limits. Give the source
    /// address without a port or a zone. An IP address is canonicalized, so
    /// alternate spellings share one budget. `app_active` is the current
    /// foreground state. A prompt timeout counts toward a lockout only when
    /// the prompt was visible before its deadline and the app is active.
    pub fn receive(
        &mut self,
        connection: ConnectionId,
        frame: &[u8],
        peer: &str,
        app_active: bool,
    ) -> Result<Output, SourcePairingError> {
        let peer = canonical_peer(peer)?;
        let now = self.now()?;
        self.app_active = app_active;
        if app_active {
            if let Some(connection) = self.decision {
                if let Some(session) = self.sessions.get_mut(&connection) {
                    // A prompt that already passed its deadline was not
                    // visible. Do not count it as a visible timeout.
                    if matches!(&session.stage, Stage::AwaitingDecision(..))
                        && now < session.deadline
                    {
                        session.shown_active = true;
                    }
                }
            }
        }

        if frame.is_empty() || frame.len() > MAX_FRAME {
            let session_peer = self
                .sessions
                .remove(&connection)
                .map(|session| session.peer)
                .unwrap_or_else(|| peer.clone());
            self.clear_decision(connection);
            return Ok(self.bad(connection, &session_peer, now));
        }

        if let Some(session) = self.sessions.remove(&connection) {
            if now >= session.deadline {
                return Ok(self.expire(session, now));
            }
            return match session.phase() {
                Phase::AwaitingReveal => self.receive_reveal(session, frame, now),
                Phase::AwaitingDecision => {
                    let session_peer = session.peer;
                    self.clear_decision(connection);
                    if frame.first() == Some(&MSG_STATUS_REQ) {
                        Ok(self.reply(connection, PairingStatus::Rejected, true))
                    } else {
                        Ok(self.bad(connection, &session_peer, now))
                    }
                }
                Phase::Authenticated => self.receive_authenticated(session, frame),
            };
        }

        if self.sessions.len() >= MAX_SESSIONS {
            return Ok(self.reply(connection, PairingStatus::Busy, false));
        }

        let Ok((l_s, commit)) = decode_hello(frame) else {
            return Ok(self.bad(connection, &peer, now));
        };
        let flags = if frame.len() == 67 { frame[66] } else { 0 };
        let known = self.trust.contains(&l_s);

        // Flags 3 would mean status-only and forget at the same time. Protocol
        // v1 defines bit 0 and bit 1 only. Fail closed on the combination.
        if flags > 2 {
            return Ok(self.reply(connection, PairingStatus::Rejected, false));
        }
        // An unknown target device must never cause a prompt for a status or
        // forget exchange.
        if !known && flags != 0 {
            return Ok(self.reply(connection, PairingStatus::Rejected, false));
        }
        if !known && self.is_locked(&peer, now) {
            return Ok(self.reply(connection, PairingStatus::LockedOut, true));
        }
        if !known && self.invalid_backoff_active(&peer, now) {
            return Ok(self.reply(connection, PairingStatus::Rejected, false));
        }
        // A trusted key skips both challenge budgets. That path is
        // intentionally unbudgeted. The budgets are an availability limit for
        // unknown peers, not an authentication limit.
        if !known {
            // A source device with pairing off answers NotActive. It must not
            // charge the challenge budget, or the peer is locked out later.
            if self.context.credentials().is_none() {
                return Ok(self.reply(connection, PairingStatus::NotActive, true));
            }
            self.prune_challenges(now);
            // Charge both challenge budgets before the ephemeral secret
            // exists. An active attacker must not get a fresh handshake for
            // each connection attempt.
            if self.challenge_budget_used(&peer) {
                return Ok(self.reply(connection, PairingStatus::Busy, false));
            }
            self.charge_challenge(&peer, now);
        }

        let mut secret = self.identity.ephemeral_secret()?;
        let ephemeral = StaticSecret::from(secret);
        wipe_array(&mut secret);
        let p_e = PublicKey::from(&ephemeral).to_bytes();
        let challenge = encode_challenge(&p_e, known);
        let wire = wire_frame(&challenge).map_err(|_| SourcePairingError::Protocol)?;
        let deadline = now.saturating_add(Duration::from_secs(REVEAL_SECONDS));
        self.sessions.insert(
            connection,
            Session {
                connection,
                l_s,
                known,
                flags,
                shown_active: false,
                deadline,
                first_deactivate: None,
                peer,
                nonces: Vec::new(),
                stage: Stage::AwaitingReveal { ephemeral, commit },
            },
        );
        Ok(Output::frames(connection, vec![wire], false, None))
    }

    /// Handle a frame parser error for a connection. This method removes the
    /// session and the decision before it checks the peer text. A failed check
    /// must not leak a session slot or leave a prompt unanswerable.
    pub fn receive_invalid(
        &mut self,
        connection: ConnectionId,
        peer: &str,
    ) -> Result<Output, SourcePairingError> {
        let session_peer = self
            .sessions
            .remove(&connection)
            .map(|session| session.peer);
        self.clear_decision(connection);
        let peer = canonical_peer(peer)?;
        let now = self.now()?;
        let session_peer = session_peer.unwrap_or(peer);
        Ok(self.bad(connection, &session_peer, now))
    }

    /// Apply the user decision to the pending prompt.
    ///
    /// `connection`, `prompt_id`, and `code` must name the prompt that the
    /// person saw. `code` is the exact string from [`PairingPrompt::code`].
    /// A stale connection, a stale prompt ID, a different code, or an expired
    /// deadline does not approve a prompt. `None` means that no prompt waits
    /// for this decision. An expired prompt returns a timeout output for the
    /// host to send and close.
    pub fn decide(
        &mut self,
        connection: ConnectionId,
        prompt_id: PromptId,
        code: &str,
        allow: bool,
    ) -> Result<Option<Output>, SourcePairingError> {
        let now = self.now()?;
        if self.decision != Some(connection) {
            return Ok(None);
        }
        let Some(current) = self.sessions.get(&connection) else {
            return Ok(None);
        };
        let Stage::AwaitingDecision(keys, id) = &current.stage else {
            return Ok(None);
        };
        if *id != prompt_id || format_code(&sas_code(&keys.sas)) != code {
            return Ok(None);
        }
        if now >= current.deadline {
            let Some(session) = self.sessions.remove(&connection) else {
                return Ok(None);
            };
            return Ok(Some(self.expire(session, now)));
        }
        self.decision = None;
        let Some(session) = self.sessions.remove(&connection) else {
            return Ok(None);
        };
        if !allow {
            return Ok(Some(self.finish(
                connection,
                &session.peer,
                PairingStatus::Denied,
                now,
            )));
        }
        self.success(session, now, true).map(Some)
    }

    /// Expire the earliest session whose deadline passed. The host calls this
    /// when [`Self::next_deadline`] passes. Call it again while the next
    /// deadline is still due.
    pub fn tick(&mut self) -> Result<Option<Output>, SourcePairingError> {
        let now = self.now()?;
        let connection = self
            .sessions
            .iter()
            .filter(|(_, session)| now >= session.deadline)
            .min_by_key(|(_, session)| session.deadline)
            .map(|(connection, _)| *connection);
        let Some(connection) = connection else {
            return Ok(None);
        };
        let Some(session) = self.sessions.remove(&connection) else {
            return Ok(None);
        };
        Ok(Some(self.expire(session, now)))
    }

    /// Mark the app as active. A pending prompt becomes visible only when its
    /// deadline has not passed. A prompt that was never visible before its
    /// deadline is not a visible timeout.
    pub fn activate(&mut self) {
        self.app_active = true;
        let now = self.clock.now();
        if now < self.last_now {
            // A backwards clock is rejected by `now` on the next protocol
            // call. Do not mark a prompt visible with an unusable time.
            return;
        }
        self.last_now = now;
        let Some(connection) = self.decision else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&connection) else {
            return;
        };
        if matches!(&session.stage, Stage::AwaitingDecision(..)) && now < session.deadline {
            session.shown_active = true;
        }
    }

    /// Mark the app as inactive. A live prompt gets at most 120 seconds after
    /// the first inactive notice. Repeated calls cannot extend it past that
    /// limit. An expired prompt returns a timeout for the host to send and
    /// close.
    pub fn deactivate(&mut self) -> Result<Option<Output>, SourcePairingError> {
        let now = self.now()?;
        self.app_active = false;
        let Some(connection) = self.decision else {
            return Ok(None);
        };
        let Some(session) = self.sessions.get(&connection) else {
            return Ok(None);
        };
        // Only a live decision prompt can be extended.
        if !matches!(&session.stage, Stage::AwaitingDecision(..)) {
            return Ok(None);
        }
        if now >= session.deadline {
            if let Some(session) = self.sessions.remove(&connection) {
                return Ok(Some(self.expire(session, now)));
            }
            return Ok(None);
        }
        if let Some(session) = self.sessions.get_mut(&connection) {
            let first = *session.first_deactivate.get_or_insert(now);
            let cap = first.saturating_add(Duration::from_secs(INACTIVE_DECISION_SECONDS));
            let extended = now
                .saturating_add(Duration::from_secs(INACTIVE_DECISION_SECONDS))
                .min(cap);
            if extended > session.deadline {
                session.deadline = extended;
            }
        }
        Ok(None)
    }

    /// Drop all state for one closed connection. The host calls this when the
    /// socket closes.
    pub fn connection_closed(&mut self, connection: ConnectionId) {
        self.sessions.remove(&connection);
        self.clear_decision(connection);
        self.prune_all();
    }

    fn now(&mut self) -> Result<Duration, SourcePairingError> {
        let now = self.clock.now();
        if now < self.last_now {
            return Err(SourcePairingError::Clock);
        }
        self.last_now = now;
        Ok(now)
    }

    fn receive_reveal(
        &mut self,
        mut session: Session,
        frame: &[u8],
        now: Duration,
    ) -> Result<Output, SourcePairingError> {
        let Stage::AwaitingReveal { ephemeral, commit } = session.stage else {
            return Err(SourcePairingError::Protocol);
        };
        let Ok((l_e, proof)) = decode_reveal(frame) else {
            return Ok(self.bad(session.connection, &session.peer, now));
        };
        if commitment(&l_e, &session.l_s) != commit {
            return Ok(self.bad(session.connection, &session.peer, now));
        }
        let Ok(ee) = agree(&ephemeral, &l_e).map(zeroize::Zeroizing::new) else {
            return Ok(self.bad(session.connection, &session.peer, now));
        };
        let Ok(es) = agree(&ephemeral, &session.l_s).map(zeroize::Zeroizing::new) else {
            return Ok(self.bad(session.connection, &session.peer, now));
        };
        let p_e = PublicKey::from(&ephemeral).to_bytes();
        let keys = derive_keys(&ee, &es, transcript_hash(&session.l_s, &l_e, &p_e));
        if !verify_proof(&keys, &proof) {
            return Ok(self.bad(session.connection, &session.peer, now));
        }

        if session.known {
            // The trust list can change while the handshake runs. Recheck it
            // before the source device sends credentials or accepts a command.
            if !self.trust.contains(&session.l_s) {
                return Ok(self.reply(session.connection, PairingStatus::Rejected, true));
            }
            if session.flags == 0 {
                // A known target needs no user prompt. Zero is never issued
                // as a prompt ID.
                session.stage = Stage::AwaitingDecision(keys, PromptId(0));
                return self.success(session, now, false);
            }
            session.stage = Stage::Authenticated(keys);
            session.deadline = now.saturating_add(Duration::from_secs(REVEAL_SECONDS));
            let connection = session.connection;
            self.sessions.insert(connection, session);
            return Ok(Output::empty(connection));
        }

        if let Some(connection) = self.decision {
            if !self.sessions.contains_key(&connection) {
                self.decision = None;
            }
        }
        if self.decision.is_some() {
            return Ok(self.reply(session.connection, PairingStatus::Busy, true));
        }

        // Check the credentials before the attempt budget. A source device
        // with pairing off answers NotActive. It must not charge the budget,
        // or the peer is locked out for the whole attempt window.
        let Some(_) = self.context.credentials() else {
            return Ok(self.reply(session.connection, PairingStatus::NotActive, true));
        };

        self.prune_unknown(now);
        if !self.unknown_budget.contains_key(&session.peer)
            && self.unknown_budget.len() >= MAX_TRACKED_PEERS
        {
            return Ok(self.reply(session.connection, PairingStatus::LockedOut, true));
        }
        let attempts = self.unknown_budget.entry(session.peer.clone()).or_default();
        if attempts.len() >= MAX_UNKNOWN_ATTEMPTS {
            return Ok(self.reply(session.connection, PairingStatus::LockedOut, true));
        }
        attempts.push(now);

        session.deadline = now.saturating_add(Duration::from_secs(if self.app_active {
            DECISION_SECONDS
        } else {
            INACTIVE_DECISION_SECONDS
        }));
        session.shown_active = self.app_active;
        session.stage = Stage::AwaitingDecision(keys, next_prompt_id()?);
        let connection = session.connection;
        self.sessions.insert(connection, session);
        self.decision = Some(connection);
        Ok(Output::empty(connection))
    }

    fn success(
        &mut self,
        mut session: Session,
        now: Duration,
        add_trust: bool,
    ) -> Result<Output, SourcePairingError> {
        let keys = match &session.stage {
            Stage::AwaitingDecision(keys, _) => keys,
            _ => return Err(SourcePairingError::Protocol),
        };
        let Some(credentials) = self
            .context
            .credentials()
            .map(PairingCredentials::as_phone_credentials)
        else {
            return Ok(self.reply(session.connection, PairingStatus::NotActive, true));
        };
        let nonce = self.identity.nonce()?;
        if session.nonces.contains(&nonce) || session.nonces.len() >= MAX_SESSION_NONCES {
            return Err(SourcePairingError::Identity);
        }
        let ciphertext = crate::pairing::seal_credentials(keys, &nonce, &credentials)
            .map_err(|_| SourcePairingError::Protocol)?;
        drop(credentials);
        let message = encode_result_ok(&nonce, &ciphertext);
        let wire = wire_frame(&message).map_err(|_| SourcePairingError::Protocol)?;

        // Add the target device to the trust store only after the result is
        // ready. A failed store must not leave a trusted key behind.
        if add_trust {
            self.trust.add(&session.l_s)?;
        }

        let Stage::AwaitingDecision(keys, _) = session.stage else {
            return Err(SourcePairingError::Protocol);
        };
        session.nonces.push(nonce);
        session.stage = Stage::Authenticated(keys);
        session.deadline = now.saturating_add(Duration::from_secs(REVEAL_SECONDS));
        let connection = session.connection;
        self.sessions.insert(connection, session);
        Ok(Output::frames(
            connection,
            vec![wire],
            false,
            Some(PairingStatus::Ok),
        ))
    }

    fn receive_authenticated(
        &mut self,
        session: Session,
        frame: &[u8],
    ) -> Result<Output, SourcePairingError> {
        let Session {
            connection,
            l_s,
            flags,
            nonces,
            stage,
            ..
        } = session;
        let Stage::Authenticated(keys) = stage else {
            return Err(SourcePairingError::Protocol);
        };

        if frame.len() < 29 || !self.trust.contains(&l_s) {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        }

        if flags == 2 {
            if frame[0] != MSG_FORGET {
                return Ok(self.reply(connection, PairingStatus::Rejected, true));
            }
            let Some(plaintext) = open_command(&keys, frame, MSG_FORGET) else {
                return Ok(self.reply(connection, PairingStatus::Rejected, true));
            };
            if !plaintext.is_empty() {
                return Ok(self.reply(connection, PairingStatus::Rejected, true));
            }
            self.trust.remove(&l_s)?;
            return Ok(self.reply(connection, PairingStatus::Ok, false));
        }

        if flags > 1 {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        }
        if frame[0] != MSG_STATUS_REQ {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        }
        let Some(plaintext) = open_command(&keys, frame, MSG_STATUS_REQ) else {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        };
        if plaintext.len() != 17 || plaintext[16] != 0 {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        }
        let Some(status) = self.context.status() else {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        };
        // The source device must still hold the pairing credentials, and the
        // status must name the hotspot address that it paired on. A new proxy
        // port is allowed: the target device learns it from this answer.
        let Some(credentials) = self.context.credentials() else {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        };
        if status.host != credentials.host() {
            return Ok(self.reply(connection, PairingStatus::Rejected, true));
        }
        let message = encode_status(status, &plaintext[..16])?;
        let nonce = self.identity.nonce()?;
        if nonces.contains(&nonce) || nonces.len() >= MAX_SESSION_NONCES {
            return Err(SourcePairingError::Identity);
        }
        let ciphertext = seal_message(&keys, &nonce, &message)?;
        let mut wire_payload = Vec::with_capacity(1 + 12 + ciphertext.len());
        wire_payload.push(MSG_STATUS);
        wire_payload.extend_from_slice(&nonce);
        wire_payload.extend_from_slice(&ciphertext);
        let wire = wire_frame(&wire_payload).map_err(|_| SourcePairingError::Protocol)?;
        Ok(Output::frames(connection, vec![wire], true, None))
    }

    fn expire(&mut self, session: Session, now: Duration) -> Output {
        let connection = session.connection;
        let counts = matches!(&session.stage, Stage::AwaitingDecision(..))
            && session.shown_active
            && self.app_active;
        let peer = session.peer.clone();
        self.clear_decision(connection);
        if counts {
            self.finish(connection, &peer, PairingStatus::TimedOut, now)
        } else {
            self.reply(connection, PairingStatus::TimedOut, true)
        }
    }

    fn finish(
        &mut self,
        connection: ConnectionId,
        peer: &str,
        status: PairingStatus,
        now: Duration,
    ) -> Output {
        let mut recent = self.failures.get(peer).cloned().unwrap_or_default();
        recent.retain(|at| now.saturating_sub(*at) < Duration::from_secs(FAILURE_WINDOW_SECONDS));
        recent.push(now);
        if recent.len() >= FAILURES_FOR_LOCKOUT {
            self.lockouts.retain(|_, until| now < *until);
            if self.lockouts.contains_key(peer) || self.lockouts.len() < MAX_TRACKED_PEERS {
                self.lockouts.insert(
                    peer.to_owned(),
                    now.saturating_add(Duration::from_secs(LOCKOUT_SECONDS)),
                );
            }
            // The lockout replaces the prompt-attempt budget. A later REVEAL
            // from this source address gets a fresh set of attempts.
            self.unknown_budget.remove(peer);
            recent.clear();
        }
        if recent.is_empty() {
            self.failures.remove(peer);
        } else if self.failures.contains_key(peer) || self.failures.len() < MAX_TRACKED_PEERS {
            self.failures.insert(peer.to_owned(), recent);
        }
        self.reply(connection, status, true)
    }

    fn bad(&mut self, connection: ConnectionId, peer: &str, now: Duration) -> Output {
        self.prune_invalid(now);
        if self.invalid_budget.contains_key(peer) || self.invalid_budget.len() < MAX_TRACKED_PEERS {
            let budget = self.invalid_budget.entry(peer.to_owned()).or_default();
            budget
                .failures
                .retain(|at| now.saturating_sub(*at) < Duration::from_secs(INVALID_WINDOW_SECONDS));
            budget.failures.push(now);
            if budget.failures.len() >= MAX_INVALID_FAILURES {
                let seconds = 1u64 << u32::from(budget.level.min(MAX_BACKOFF_LEVEL));
                budget.until = now.saturating_add(Duration::from_secs(seconds));
                budget.level = (budget.level + 1).min(MAX_BACKOFF_LEVEL);
                budget.failures.clear();
            }
        }
        self.reply(connection, PairingStatus::Rejected, true)
    }

    fn reply(&mut self, connection: ConnectionId, status: PairingStatus, log: bool) -> Output {
        self.clear_decision(connection);
        Output::frames(
            connection,
            vec![result_frame(status)],
            true,
            log.then_some(status),
        )
    }

    fn clear_decision(&mut self, connection: ConnectionId) {
        if self.decision == Some(connection) {
            self.decision = None;
        }
    }

    fn is_locked(&mut self, peer: &str, now: Duration) -> bool {
        self.lockouts.retain(|_, until| now < *until);
        self.lockouts.get(peer).is_some_and(|until| now < *until)
    }

    fn invalid_backoff_active(&mut self, peer: &str, now: Duration) -> bool {
        self.prune_invalid(now);
        self.invalid_budget
            .get(peer)
            .is_some_and(|budget| now < budget.until)
    }

    fn prune_unknown(&mut self, now: Duration) {
        let window = Duration::from_secs(UNKNOWN_WINDOW_SECONDS);
        self.unknown_budget.retain(|_, attempts| {
            attempts.retain(|at| now.saturating_sub(*at) < window);
            !attempts.is_empty()
        });
    }

    fn prune_challenges(&mut self, now: Duration) {
        let window = Duration::from_secs(CHALLENGE_WINDOW_SECONDS);
        self.unknown_challenges.retain(|_, challenges| {
            challenges.retain(|at| now.saturating_sub(*at) < window);
            !challenges.is_empty()
        });
    }

    /// True when the source address or the whole responder has no challenge
    /// budget left for the current window. Call `prune_challenges` first.
    fn challenge_budget_used(&self, peer: &str) -> bool {
        let peer_count = self.unknown_challenges.get(peer).map_or(0, Vec::len);
        let total: usize = self.unknown_challenges.values().map(Vec::len).sum();
        peer_count >= MAX_PEER_CHALLENGES || total >= MAX_UNKNOWN_CHALLENGES
    }

    fn charge_challenge(&mut self, peer: &str, now: Duration) {
        self.unknown_challenges
            .entry(peer.to_owned())
            .or_default()
            .push(now);
    }

    fn prune_invalid(&mut self, now: Duration) {
        let window = Duration::from_secs(INVALID_WINDOW_SECONDS);
        self.invalid_budget.retain(|_, budget| {
            budget
                .failures
                .retain(|at| now.saturating_sub(*at) < window);
            now < budget.until || !budget.failures.is_empty()
        });
    }

    fn prune_all(&mut self) {
        let now = self.last_now;
        self.prune_unknown(now);
        self.prune_challenges(now);
        self.prune_invalid(now);
        let window = Duration::from_secs(FAILURE_WINDOW_SECONDS);
        self.failures.retain(|_, recent| {
            recent.retain(|at| now.saturating_sub(*at) < window);
            !recent.is_empty()
        });
        self.lockouts.retain(|_, until| now < *until);
    }
}

/// Return the rate-limit key for one peer identifier.
///
/// The key checks reject an empty value, a value above [`MAX_PEER_LEN`], and a
/// value with a byte outside visible ASCII. An IP address is canonicalized, so
/// `2001:db8::1` and `2001:0db8:0000:0000:0000:0000:0000:0001` share one
/// budget. An IPv4-mapped IPv6 address maps to its IPv4 form. A value with a
/// port or a zone is rejected, because it would give one address more than one
/// budget.
fn canonical_peer(peer: &str) -> Result<String, SourcePairingError> {
    validate_peer(peer)?;
    if let Ok(address) = peer.parse::<IpAddr>() {
        return Ok(canonical_address(address).to_string());
    }
    if peer.contains('%') || peer.parse::<SocketAddr>().is_ok() {
        return Err(SourcePairingError::Peer);
    }
    Ok(peer.to_owned())
}

/// Map an IPv4-mapped IPv6 address to its IPv4 form.
fn canonical_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => IpAddr::V6(address),
        },
        other => other,
    }
}

/// Reject an empty peer identifier. Also reject a value above
/// [`MAX_PEER_LEN`] and a value with a byte outside visible ASCII. The host
/// passes the source address text.
fn validate_peer(peer: &str) -> Result<(), SourcePairingError> {
    if peer.is_empty() {
        return Err(SourcePairingError::Peer);
    }
    if peer.len() > MAX_PEER_LEN || !peer.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(SourcePairingError::Peer);
    }
    Ok(())
}

fn is_usable_proxy_port(port: u16) -> bool {
    port >= 1024 && port != PAIRING_PORT
}

fn is_usable_host(host: Ipv4Addr) -> bool {
    !host.is_unspecified() && !host.is_multicast()
}

fn encode_status(status: &ProxyStatus, challenge: &[u8]) -> Result<Vec<u8>, SourcePairingError> {
    if challenge.len() != 16 || !is_usable_proxy_port(status.port) || !is_usable_host(status.host) {
        return Err(SourcePairingError::Configuration);
    }
    let host = status.host.to_string();
    if host.is_empty() || host.len() > 21 {
        return Err(SourcePairingError::Configuration);
    }
    let mut out = Vec::with_capacity(27 + host.len());
    out.extend_from_slice(challenge);
    out.extend_from_slice(&status.sequence.to_be_bytes());
    out.push(u8::from(status.proxy_running));
    out.push(u8::from(status.foreground));
    out.extend_from_slice(&status.connections.to_be_bytes());
    out.extend_from_slice(&status.port.to_be_bytes());
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    Ok(out)
}

fn open_command(keys: &SessionKeys, frame: &[u8], message_type: u8) -> Option<Vec<u8>> {
    if frame.len() < 29 || frame[0] != message_type {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
    cipher
        .decrypt(
            Nonce::from_slice(&frame[1..13]),
            Payload {
                msg: &frame[13..],
                aad: &keys.h,
            },
        )
        .ok()
}

fn seal_message(
    keys: &SessionKeys,
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, SourcePairingError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &keys.h,
            },
        )
        .map_err(|_| SourcePairingError::Protocol)
}

fn result_frame(status: PairingStatus) -> Vec<u8> {
    let payload = encode_result_status(status);
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn wipe_array<const N: usize>(bytes: &mut [u8; N]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::{
        encode_hello, encode_reveal, laptop_proof, ChallengeOrResult, ResultMessage,
    };
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    // Fixed public test vectors. rust/src/pairing.rs and
    // ios/tests/PairingTests.swift hold the same values. Change all three
    // files together.
    const L_S_PRIV: [u8; 32] = [0x11; 32];
    const L_E_PRIV: [u8; 32] = [0x22; 32];
    const P_E_PRIV: [u8; 32] = [0x33; 32];
    const NONCE: [u8; 12] = [0x44; 12];
    const TOKEN: &str = "test-token-0123456789abcdef";
    const HOST: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 1);
    const PORT: u16 = 1080;
    const V_L_S: &str = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13";
    const V_L_E: &str = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20";
    const V_P_E: &str = "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14";
    const V_C: &str = "c7bf4d2e3388ea312b7750dbcfc430402b2c6b1e457fe2ee1ffeae09a4fd3aeb";
    const V_EE: &str = "1fdc192faa0212a9aae7bb4f41b580227fd5ad3e5d777faae230dfe973f3e805";
    const V_ES: &str = "5bf22caf31c0316785b0b9bc60e56d48582ce59435ce5b3c028052be42631e0f";
    const V_H: &str = "51e50f017883e3dde1ea99a473a142dfd758835adfdc933f706b3d2e9752b1b7";
    const V_K_ENC: &str = "d15b719f5c092e967be6a0a355bb972014e6245ff4d7ea9a53434878b8358b78";
    const V_K_PROOF: &str = "09089c6978faac4cc8f0ae44767a3fd8789346826ef99366d2f8c13e09ece263";
    const V_SAS: &str = "e961ca48";
    const V_CODE: &str = "500104";
    const V_PROOF: &str = "7554e349e225b68c5c2310ce69bf08c44f6aac2c73ac5a11e75a8142c1f7f97a";
    const V_CT: &str = "132a89d1add706e92d7844032a37f2486c9f386e21255687facf153edc23e7dced55371101721d50afaa326d1fb62e2c270f1501bb51d043e9c8";

    fn public(secret: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
    }

    fn payload(frame_bytes: &[u8]) -> Vec<u8> {
        assert!(frame_bytes.len() >= 3);
        let length = u16::from_be_bytes([frame_bytes[0], frame_bytes[1]]) as usize;
        assert_eq!(frame_bytes.len(), 2 + length);
        frame_bytes[2..].to_vec()
    }

    fn only_payload(output: &Output) -> Vec<u8> {
        assert_eq!(output.frames.len(), 1);
        payload(&output.frames[0])
    }

    fn result_status(output: &Output) -> Option<PairingStatus> {
        let message = only_payload(output);
        // A forget answer is RESULT OK with no ciphertext. The target side
        // accepts this exact two-byte form.
        if message == [crate::pairing::MSG_RESULT, PairingStatus::Ok as u8] {
            return Some(PairingStatus::Ok);
        }
        match crate::pairing::decode_result(&message).expect("result") {
            ResultMessage::Status(status) => Some(status),
            ResultMessage::Ok { .. } => None,
        }
    }

    /// Apply a decision to the prompt that the host shows now.
    fn decide_pending(
        responder: &mut PairingResponder,
        allow: bool,
    ) -> Result<Option<Output>, SourcePairingError> {
        let prompt = responder.pending_prompt().expect("pending prompt");
        responder.decide(prompt.connection, prompt.id, &prompt.code, allow)
    }

    #[derive(Default)]
    struct TrustState {
        keys: BTreeSet<[u8; 32]>,
        fail_add: bool,
        fail_remove: bool,
    }

    #[derive(Clone, Default)]
    struct TrustHandle(Rc<RefCell<TrustState>>);

    impl TrustHandle {
        fn add_ok(&self, key: &[u8; 32]) {
            self.0.borrow_mut().keys.insert(*key);
        }

        fn remove_ok(&self, key: &[u8; 32]) {
            self.0.borrow_mut().keys.remove(key);
        }

        fn len(&self) -> usize {
            self.0.borrow().keys.len()
        }

        fn set_fail_add(&self, value: bool) {
            self.0.borrow_mut().fail_add = value;
        }

        fn set_fail_remove(&self, value: bool) {
            self.0.borrow_mut().fail_remove = value;
        }
    }

    impl PairingTrustStore for TrustHandle {
        fn contains(&self, public_key: &[u8; 32]) -> bool {
            self.0.borrow().keys.contains(public_key)
        }

        fn add(&mut self, public_key: &[u8; 32]) -> Result<(), SourcePairingError> {
            let mut state = self.0.borrow_mut();
            if state.fail_add {
                return Err(SourcePairingError::TrustStore);
            }
            state.keys.insert(*public_key);
            Ok(())
        }

        fn remove(&mut self, public_key: &[u8; 32]) -> Result<(), SourcePairingError> {
            let mut state = self.0.borrow_mut();
            if state.fail_remove {
                return Err(SourcePairingError::TrustStore);
            }
            state.keys.remove(public_key);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestClock(Rc<Cell<Duration>>);

    impl TestClock {
        fn new(seconds: u64) -> Self {
            Self(Rc::new(Cell::new(Duration::from_secs(seconds))))
        }

        fn advance(&self, seconds: u64) {
            self.0.set(self.0.get() + Duration::from_secs(seconds));
        }

        fn set(&self, seconds: u64) {
            self.0.set(Duration::from_secs(seconds));
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Duration {
            self.0.get()
        }
    }

    struct IdentityState {
        ephemeral: [u8; 32],
        ephemeral_calls: usize,
        nonces: VecDeque<[u8; 12]>,
        fail_ephemeral: bool,
        fail_nonce: bool,
    }

    #[derive(Clone)]
    struct TestIdentity(Rc<RefCell<IdentityState>>);

    impl TestIdentity {
        fn new() -> Self {
            let mut nonces = VecDeque::new();
            for index in 0..32u8 {
                let mut nonce = [0x44; 12];
                if index != 0 {
                    nonce[1] = index;
                }
                nonces.push_back(nonce);
            }
            Self(Rc::new(RefCell::new(IdentityState {
                ephemeral: P_E_PRIV,
                ephemeral_calls: 0,
                nonces,
                fail_ephemeral: false,
                fail_nonce: false,
            })))
        }

        fn failing_ephemeral() -> Self {
            let identity = Self::new();
            identity.0.borrow_mut().fail_ephemeral = true;
            identity
        }

        fn ephemeral_calls(&self) -> usize {
            self.0.borrow().ephemeral_calls
        }
    }

    impl PairingIdentity for TestIdentity {
        fn ephemeral_secret(&mut self) -> Result<[u8; 32], SourcePairingError> {
            let mut state = self.0.borrow_mut();
            state.ephemeral_calls += 1;
            if state.fail_ephemeral {
                return Err(SourcePairingError::Identity);
            }
            Ok(state.ephemeral)
        }

        fn nonce(&mut self) -> Result<[u8; 12], SourcePairingError> {
            let mut state = self.0.borrow_mut();
            if state.fail_nonce {
                return Err(SourcePairingError::Identity);
            }
            state.nonces.pop_front().ok_or(SourcePairingError::Identity)
        }
    }

    struct ProviderState {
        credentials: Option<PairingCredentials>,
        status: Option<ProxyStatus>,
    }

    #[derive(Clone)]
    struct ProviderHandle(Rc<ProviderState>);

    impl PairingContext for ProviderHandle {
        fn credentials(&self) -> Option<&PairingCredentials> {
            self.0.credentials.as_ref()
        }

        fn status(&self) -> Option<&ProxyStatus> {
            self.0.status.as_ref()
        }
    }

    fn valid_provider() -> Rc<ProviderState> {
        Rc::new(ProviderState {
            credentials: Some(PairingCredentials::new(HOST, PORT, TOKEN).unwrap()),
            status: Some(ProxyStatus {
                proxy_running: true,
                foreground: true,
                connections: 2,
                port: PORT,
                host: HOST,
                sequence: 1,
            }),
        })
    }

    fn empty_provider() -> Rc<ProviderState> {
        Rc::new(ProviderState {
            credentials: None,
            status: None,
        })
    }

    fn make_responder(
        trust: &TrustHandle,
        clock: &TestClock,
        identity: &TestIdentity,
        provider: &Rc<ProviderState>,
    ) -> PairingResponder {
        PairingResponder::new(PairingResponderDependencies {
            identity: Box::new(identity.clone()),
            trust: Box::new(trust.clone()),
            context: Box::new(ProviderHandle(provider.clone())),
            clock: Box::new(clock.clone()),
        })
    }

    struct Target {
        l_s_priv: [u8; 32],
        l_e_priv: [u8; 32],
        p_e: Option<[u8; 32]>,
        keys: Option<SessionKeys>,
    }

    impl Target {
        fn new() -> Self {
            Self::with_ephemeral(L_E_PRIV)
        }

        fn with_ephemeral(l_e_priv: [u8; 32]) -> Self {
            Self {
                l_s_priv: L_S_PRIV,
                l_e_priv,
                p_e: None,
                keys: None,
            }
        }

        fn l_s(&self) -> [u8; 32] {
            public(&self.l_s_priv)
        }

        fn l_e(&self) -> [u8; 32] {
            public(&self.l_e_priv)
        }

        fn hello(&self, flags: Option<u8>) -> Vec<u8> {
            let l_s = self.l_s();
            let l_e = self.l_e();
            let mut message = encode_hello(&l_s, &commitment(&l_e, &l_s));
            if let Some(flags) = flags {
                message.push(flags);
            }
            message
        }

        fn accept_challenge(&mut self, output: &Output) -> (bool, [u8; 32]) {
            let message = only_payload(output);
            match crate::pairing::decode_challenge(&message).expect("challenge") {
                ChallengeOrResult::Challenge { p_e, known } => {
                    self.p_e = Some(p_e);
                    (known, p_e)
                }
                other => panic!("unexpected answer: {other:?}"),
            }
        }

        fn reveal(&mut self) -> Vec<u8> {
            let p_e = self.p_e.expect("challenge");
            let l_e = self.l_e();
            let ee = agree(&StaticSecret::from(self.l_e_priv), &p_e).unwrap();
            let es = agree(&StaticSecret::from(self.l_s_priv), &p_e).unwrap();
            let keys = derive_keys(&ee, &es, transcript_hash(&self.l_s(), &l_e, &p_e));
            let proof = laptop_proof(&keys);
            let message = encode_reveal(&l_e, &proof);
            self.keys = Some(keys);
            message
        }

        fn keys(&self) -> &SessionKeys {
            self.keys.as_ref().expect("keys")
        }

        fn seal(&self, message_type: u8, nonce: [u8; 12], plaintext: &[u8]) -> Vec<u8> {
            let keys = self.keys();
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &keys.h,
                    },
                )
                .unwrap();
            let mut out = Vec::with_capacity(1 + 12 + ciphertext.len());
            out.push(message_type);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            out
        }

        fn status_request(&self, challenge: &[u8; 16], nonce: [u8; 12], flags: u8) -> Vec<u8> {
            let mut plaintext = challenge.to_vec();
            plaintext.push(flags);
            self.seal(MSG_STATUS_REQ, nonce, &plaintext)
        }

        fn forget_request(&self, nonce: [u8; 12], plaintext: &[u8]) -> Vec<u8> {
            self.seal(MSG_FORGET, nonce, plaintext)
        }

        fn open_status(&self, output: &Output) -> Vec<u8> {
            let message = only_payload(output);
            assert_eq!(message.first(), Some(&MSG_STATUS));
            let keys = self.keys();
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
            cipher
                .decrypt(
                    Nonce::from_slice(&message[1..13]),
                    Payload {
                        msg: &message[13..],
                        aad: &keys.h,
                    },
                )
                .expect("status")
        }

        fn open_result(&self, output: &Output) -> PhoneCredentials {
            let message = only_payload(output);
            match crate::pairing::decode_result(&message).expect("result") {
                ResultMessage::Ok { nonce, ciphertext } => {
                    crate::pairing::open_credentials(self.keys(), &nonce, &ciphertext).unwrap()
                }
                ResultMessage::Status(status) => panic!("unexpected status: {status:?}"),
            }
        }
    }

    #[test]
    fn parity_vectors_match_the_target_and_swift_suites() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();

        assert_eq!(hex_v(&public(&L_S_PRIV)), V_L_S);
        assert_eq!(hex_v(&public(&L_E_PRIV)), V_L_E);

        let output = responder
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        let (known, p_e) = target.accept_challenge(&output);
        assert!(!known);
        assert_eq!(hex_v(&p_e), V_P_E);
        let challenge = only_payload(&output);
        assert_eq!(
            challenge,
            [vec![crate::pairing::MSG_CHALLENGE], p_e.to_vec(), vec![0]].concat()
        );

        let reveal = target.reveal();
        assert_eq!(
            hex_v(&commitment(&public(&L_E_PRIV), &public(&L_S_PRIV))),
            V_C
        );
        let ee = agree(&StaticSecret::from(L_E_PRIV), &p_e).unwrap();
        let es = agree(&StaticSecret::from(L_S_PRIV), &p_e).unwrap();
        assert_eq!(hex_v(&ee), V_EE);
        assert_eq!(hex_v(&es), V_ES);
        assert_eq!(hex_v(&target.keys().h), V_H);
        assert_eq!(hex_v(&target.keys().k_enc), V_K_ENC);
        assert_eq!(hex_v(&target.keys().k_proof), V_K_PROOF);
        assert_eq!(hex_v(&target.keys().sas), V_SAS);
        assert_eq!(sas_code(&target.keys().sas), V_CODE);
        assert_eq!(hex_v(&laptop_proof(target.keys())), V_PROOF);

        let output = responder.receive(1, &reveal, "peer", true).unwrap();
        assert!(output.frames.is_empty());
        assert!(!output.close);
        assert_eq!(output.status, None);
        assert_eq!(
            responder.pending_prompt().map(|p| p.code).as_deref(),
            Some("500 104")
        );
        assert_eq!(responder.pending_prompt().map(|p| p.connection), Some(1));
        assert_eq!(trust.len(), 0);

        let prompt = responder.pending_prompt().unwrap();
        let output = responder
            .decide(prompt.connection, prompt.id, &prompt.code, true)
            .unwrap()
            .unwrap();
        assert_eq!(output.status, Some(PairingStatus::Ok));
        assert!(!output.close);
        assert_eq!(trust.len(), 1);
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        let message = only_payload(&output);
        assert_eq!(message[0], crate::pairing::MSG_RESULT);
        assert_eq!(message[1], PairingStatus::Ok as u8);
        assert_eq!(&message[2..14], &NONCE);
        assert_eq!(hex_v(&message[14..]), V_CT);
        let credentials = target.open_result(&output);
        assert_eq!(credentials.host, HOST);
        assert_eq!(credentials.port, PORT);
        assert_eq!(credentials.token, TOKEN);
    }

    #[test]
    fn unknown_challenges_have_a_global_rate_limit() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        for id in 0..MAX_UNKNOWN_CHALLENGES as u64 {
            let mut target = Target::new();
            let output = responder
                .receive(id, &target.hello(None), &format!("peer-{id}"), true)
                .unwrap();
            assert!(!target.accept_challenge(&output).0);
            responder.connection_closed(id);
        }
        let mut target = Target::new();
        let output = responder
            .receive(100, &target.hello(None), "other", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Busy));
        trust.add_ok(&public(&L_S_PRIV));
        let output = responder
            .receive(101, &target.hello(None), "known", true)
            .unwrap();
        assert!(target.accept_challenge(&output).0);
        responder.connection_closed(101);
        trust.remove_ok(&public(&L_S_PRIV));
        clock.advance(CHALLENGE_WINDOW_SECONDS);
        let output = responder
            .receive(102, &target.hello(None), "other", true)
            .unwrap();
        assert!(!target.accept_challenge(&output).0);
        assert_eq!(
            responder.receive(103, &target.hello(None), "", true),
            Err(SourcePairingError::Peer)
        );
    }

    #[test]
    fn unknown_challenges_have_a_per_peer_limit_and_charge_the_secret_budget() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();

        for id in 0..MAX_PEER_CHALLENGES as u64 {
            let mut peer = Target::new();
            let output = responder
                .receive(id, &peer.hello(None), "peer-a", true)
                .unwrap();
            assert!(!peer.accept_challenge(&output).0);
            responder.connection_closed(id);
        }
        let calls = identity.ephemeral_calls();
        let output = responder
            .receive(10, &target.hello(None), "peer-a", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Busy));
        // A refused challenge must not create an ephemeral secret.
        assert_eq!(identity.ephemeral_calls(), calls);
        assert_eq!(responder.active_sessions(), 0);

        // Another source address has its own budget until the global limit.
        let output = responder
            .receive(11, &target.hello(None), "peer-b", true)
            .unwrap();
        assert!(!target.accept_challenge(&output).0);
        responder.connection_closed(11);

        // Peer-a holds four challenges and peer-b holds one. Three more
        // source addresses fill the global budget of eight.
        for index in 0..(MAX_UNKNOWN_CHALLENGES - MAX_PEER_CHALLENGES - 1) {
            let connection = 20 + index as u64;
            let mut peer = Target::new();
            let output = responder
                .receive(
                    connection,
                    &peer.hello(None),
                    &format!("peer-c{index}"),
                    true,
                )
                .unwrap();
            assert!(!peer.accept_challenge(&output).0);
            responder.connection_closed(connection);
        }
        let calls = identity.ephemeral_calls();
        let output = responder
            .receive(30, &target.hello(None), "peer-d", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Busy));
        assert_eq!(identity.ephemeral_calls(), calls);

        // The window clears both budgets.
        clock.advance(CHALLENGE_WINDOW_SECONDS);
        let output = responder
            .receive(31, &target.hello(None), "peer-a", true)
            .unwrap();
        assert!(!target.accept_challenge(&output).0);
    }

    #[test]
    fn alternate_ipv6_spellings_share_one_challenge_budget() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        for connection in 0..MAX_PEER_CHALLENGES as u64 {
            let mut target = Target::new();
            let output = responder
                .receive(connection, &target.hello(None), "2001:db8::1", true)
                .unwrap();
            assert!(!target.accept_challenge(&output).0);
            responder.connection_closed(connection);
        }

        // The same address in the full, uncompressed form shares the budget.
        let target = Target::new();
        let output = responder
            .receive(
                MAX_PEER_CHALLENGES as u64,
                &target.hello(None),
                "2001:0db8:0000:0000:0000:0000:0000:0001",
                true,
            )
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Busy));
        assert_eq!(responder.active_sessions(), 0);
    }

    #[test]
    fn ipv4_mapped_ipv6_peers_share_the_ipv4_budget() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        for connection in 0..MAX_PEER_CHALLENGES as u64 {
            let mut target = Target::new();
            let output = responder
                .receive(connection, &target.hello(None), "192.0.2.1", true)
                .unwrap();
            assert!(!target.accept_challenge(&output).0);
            responder.connection_closed(connection);
        }

        for (index, peer) in ["::ffff:192.0.2.1", "::ffff:c000:201"].iter().enumerate() {
            let target = Target::new();
            let output = responder
                .receive(10 + index as u64, &target.hello(None), peer, true)
                .unwrap();
            assert_eq!(result_status(&output), Some(PairingStatus::Busy));
            assert_eq!(responder.active_sessions(), 0);
        }
    }

    #[test]
    fn empty_and_unusable_peers_are_rejected() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let target = Target::new();

        assert_eq!(
            responder.receive(1, &target.hello(None), "", true),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(
            responder.receive(1, &target.hello(None), " ", true),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(
            responder.receive(1, &target.hello(None), "peer\n", true),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(
            responder.receive(1, &target.hello(None), &"a".repeat(MAX_PEER_LEN + 1), true),
            Err(SourcePairingError::Peer)
        );
        // A port or a zone would give one address more than one budget.
        assert_eq!(
            responder.receive(1, &target.hello(None), "192.0.2.1:443", true),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(
            responder.receive(1, &target.hello(None), "fe80::1%en0", true),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(
            responder.receive_invalid(1, ""),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(identity.ephemeral_calls(), 0);
        assert_eq!(responder.active_sessions(), 0);
    }

    #[test]
    fn receive_invalid_releases_the_session_before_a_peer_error() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(1, &target.reveal(), "peer", true)
            .unwrap();
        let prompt = responder.pending_prompt().unwrap();
        assert_eq!(responder.active_sessions(), 1);

        // The peer text is unusable. The session and the decision must still
        // be removed before the error returns.
        assert_eq!(
            responder.receive_invalid(1, ""),
            Err(SourcePairingError::Peer)
        );
        assert_eq!(responder.active_sessions(), 0);
        assert!(responder.pending_prompt().is_none());
        assert_eq!(responder.next_deadline(), None);
        assert!(responder
            .decide(prompt.connection, prompt.id, &prompt.code, true)
            .unwrap()
            .is_none());

        // The released decision lets a new target get a prompt.
        let mut next = Target::with_ephemeral([0x23; 32]);
        let output = responder
            .receive(2, &next.hello(None), "peer", true)
            .unwrap();
        next.accept_challenge(&output);
        responder.receive(2, &next.reveal(), "peer", true).unwrap();
        assert!(responder.pending_prompt().is_some());
    }

    #[test]
    fn stale_decision_does_not_approve_a_replacement_prompt() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut first = Target::new();
        let output = responder
            .receive(1, &first.hello(None), "peer", true)
            .unwrap();
        first.accept_challenge(&output);
        responder.receive(1, &first.reveal(), "peer", true).unwrap();
        let old = responder.pending_prompt().unwrap();
        responder.connection_closed(1);
        let mut second = Target::new();
        let output = responder
            .receive(1, &second.hello(None), "peer", true)
            .unwrap();
        second.accept_challenge(&output);
        responder
            .receive(1, &second.reveal(), "peer", true)
            .unwrap();
        let current = responder.pending_prompt().unwrap();
        assert_eq!(old.code, current.code);
        assert_ne!(old.id, current.id);
        assert!(responder
            .decide(old.connection, old.id, &old.code, true)
            .unwrap()
            .is_none());
        assert_eq!(responder.pending_prompt(), Some(current.clone()));
        assert_eq!(trust.len(), 0);
        assert!(responder
            .decide(2, current.id, &current.code, false)
            .unwrap()
            .is_none());
        assert!(responder
            .decide(current.connection, current.id, "000 000", true)
            .unwrap()
            .is_none());
        assert_eq!(responder.pending_prompt(), Some(current.clone()));
        assert_eq!(trust.len(), 0);
        assert_eq!(
            responder
                .decide(current.connection, current.id, &current.code, true)
                .unwrap()
                .unwrap()
                .status,
            Some(PairingStatus::Ok)
        );
        assert_eq!(trust.len(), 1);
        drop(responder);
        let new_trust = TrustHandle::default();
        let mut replacement = make_responder(&new_trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = replacement
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        replacement
            .receive(1, &target.reveal(), "peer", true)
            .unwrap();
        let next = replacement.pending_prompt().unwrap();
        assert_ne!(current.id, next.id);
        assert!(replacement
            .decide(current.connection, current.id, &current.code, true)
            .unwrap()
            .is_none());
        assert_eq!(new_trust.len(), 0);
    }

    #[test]
    fn expired_prompt_cannot_be_approved_or_extended() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(1, &target.reveal(), "peer", true)
            .unwrap();
        let prompt = responder.pending_prompt().unwrap();
        clock.advance(DECISION_SECONDS);
        assert!(responder.pending_prompt().is_none());
        let expired = responder
            .decide(prompt.connection, prompt.id, &prompt.code, true)
            .unwrap()
            .unwrap();
        assert_eq!(result_status(&expired), Some(PairingStatus::TimedOut));
        assert_eq!(trust.len(), 0);
        assert_eq!(responder.active_sessions(), 0);

        let mut next = Target::new();
        let output = responder
            .receive(2, &next.hello(None), "peer2", true)
            .unwrap();
        next.accept_challenge(&output);
        responder.receive(2, &next.reveal(), "peer2", true).unwrap();
        clock.advance(DECISION_SECONDS);
        assert_eq!(
            result_status(&responder.deactivate().unwrap().unwrap()),
            Some(PairingStatus::TimedOut)
        );
        assert!(responder.pending_prompt().is_none());
        assert_eq!(responder.next_deadline(), None);
    }

    #[test]
    fn known_target_uses_no_prompt_and_status_is_authenticated() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        trust.add_ok(&target.l_s());

        let output = responder
            .receive(10, &target.hello(Some(1)), "peer", true)
            .unwrap();
        let (known, _) = target.accept_challenge(&output);
        assert!(known);
        let reveal = target.reveal();
        let output = responder.receive(10, &reveal, "peer", true).unwrap();
        assert!(output.frames.is_empty());
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(responder.active_sessions(), 1);

        let challenge = [0x55u8; 16];
        let request = target.status_request(&challenge, [0x77u8; 12], 0);
        let output = responder.receive(10, &request, "peer", true).unwrap();
        assert!(output.close);
        assert_eq!(output.status, None);
        assert_eq!(responder.active_sessions(), 0);
        let plaintext = target.open_status(&output);
        assert_eq!(plaintext.len(), 27 + HOST.to_string().len());
        assert_eq!(&plaintext[..16], &challenge);
        assert_eq!(&plaintext[16..20], &1u32.to_be_bytes());
        assert_eq!(plaintext[20], 1);
        assert_eq!(plaintext[21], 1);
        assert_eq!(&plaintext[22..24], &2u16.to_be_bytes());
        assert_eq!(&plaintext[24..26], &PORT.to_be_bytes());
        assert_eq!(plaintext[26] as usize, HOST.to_string().len());
        assert_eq!(&plaintext[27..], HOST.to_string().as_bytes());
        assert!(!plaintext
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes()));

        let mut target = Target::new();
        let output = responder
            .receive(11, &target.hello(None), "peer", true)
            .unwrap();
        let (known, _) = target.accept_challenge(&output);
        assert!(known);
        let reveal = target.reveal();
        let output = responder.receive(11, &reveal, "peer", true).unwrap();
        assert_eq!(output.status, Some(PairingStatus::Ok));
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        let credentials = target.open_result(&output);
        assert_eq!(credentials.token, TOKEN);
        assert_eq!(trust.len(), 1);
    }

    #[test]
    fn forget_requires_trust_and_removes_the_key() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        trust.add_ok(&target.l_s());

        let output = responder
            .receive(20, &target.hello(Some(2)), "peer", true)
            .unwrap();
        let (known, _) = target.accept_challenge(&output);
        assert!(known);
        let reveal = target.reveal();
        let output = responder.receive(20, &reveal, "peer", true).unwrap();
        assert!(output.frames.is_empty());
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);

        let request = target.forget_request([0x66u8; 12], &[]);
        let output = responder.receive(20, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Ok));
        assert!(output.close);
        assert_eq!(output.status, None);
        assert_eq!(trust.len(), 0);
        assert_eq!(responder.active_sessions(), 0);

        for (connection, flags) in [(21, 1), (22, 2), (23, 3)] {
            let target = Target::new();
            let output = responder
                .receive(connection, &target.hello(Some(flags)), "peer", true)
                .unwrap();
            assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
            assert_eq!(responder.pending_prompt().map(|p| p.code), None);
            assert_eq!(trust.len(), 0);
        }
    }

    #[test]
    fn one_prompt_at_a_time_and_busy_does_not_use_an_attempt() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        let mut first = Target::new();
        let output = responder
            .receive(30, &first.hello(None), "peer", true)
            .unwrap();
        first.accept_challenge(&output);
        let reveal = first.reveal();
        responder.receive(30, &reveal, "peer", true).unwrap();
        assert_eq!(
            responder.pending_prompt().map(|p| p.code).as_deref(),
            Some("500 104")
        );

        let mut second = Target::with_ephemeral([0x23; 32]);
        let output = responder
            .receive(31, &second.hello(None), "peer", true)
            .unwrap();
        second.accept_challenge(&output);
        let reveal = second.reveal();
        let output = responder.receive(31, &reveal, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Busy));
        assert_eq!(responder.pending_prompt().map(|p| p.connection), Some(30));

        let output = decide_pending(&mut responder, false).unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Denied));

        let mut third = Target::with_ephemeral([0x24; 32]);
        let output = responder
            .receive(32, &third.hello(None), "peer", true)
            .unwrap();
        third.accept_challenge(&output);
        let reveal = third.reveal();
        responder.receive(32, &reveal, "peer", true).unwrap();
        assert!(responder.pending_prompt().map(|p| p.code).is_some());
        let output = decide_pending(&mut responder, false).unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Denied));

        // The busy handshake did not use an attempt. A third verified unknown
        // handshake still gets a prompt.
        let mut fourth = Target::with_ephemeral([0x25; 32]);
        let output = responder
            .receive(33, &fourth.hello(None), "peer", true)
            .unwrap();
        fourth.accept_challenge(&output);
        let reveal = fourth.reveal();
        responder.receive(33, &reveal, "peer", true).unwrap();
        assert!(responder.pending_prompt().map(|p| p.code).is_some());
        let output = decide_pending(&mut responder, true).unwrap().unwrap();
        assert_eq!(output.status, Some(PairingStatus::Ok));
        let credentials = fourth.open_result(&output);
        assert_eq!(credentials.token, TOKEN);
        assert_eq!(trust.len(), 1);
    }

    #[test]
    fn three_denials_lock_the_source_address_and_other_peers_continue() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        for _ in 0..3 {
            let mut target = Target::new();
            let output = responder
                .receive(40, &target.hello(None), "peer", true)
                .unwrap();
            target.accept_challenge(&output);
            let reveal = target.reveal();
            responder.receive(40, &reveal, "peer", true).unwrap();
            let output = decide_pending(&mut responder, false).unwrap().unwrap();
            assert_eq!(result_status(&output), Some(PairingStatus::Denied));
        }

        let mut other = Target::new();
        let output = responder
            .receive(41, &other.hello(None), "other", true)
            .unwrap();
        let (known, _) = other.accept_challenge(&output);
        assert!(!known);
        responder.connection_closed(41);

        let locked = Target::new();
        let output = responder
            .receive(42, &locked.hello(None), "peer", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::LockedOut));

        clock.advance(LOCKOUT_SECONDS);
        let mut recovered = Target::new();
        let output = responder
            .receive(43, &recovered.hello(None), "peer", true)
            .unwrap();
        let (known, _) = recovered.accept_challenge(&output);
        assert!(!known);
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
    }

    #[test]
    fn a_visible_prompt_timeout_sends_timed_out_and_allows_a_new_handshake() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        let mut target = Target::new();
        let output = responder
            .receive(50, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(50, &reveal, "peer", true).unwrap();
        clock.advance(DECISION_SECONDS);
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));
        assert!(output.close);
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(responder.active_sessions(), 0);

        // The timeout is recorded as a prompt failure. Three timeout failures
        // still cannot reach the lockout. The failure window is 60 seconds.
        // A visible prompt has a 60 second deadline, so each new timeout
        // replaces the old one in the record. A timeout alone cannot lock the
        // source address. A new unknown target device still gets a challenge.
        let mut fresh = Target::new();
        let output = responder
            .receive(51, &fresh.hello(None), "peer", true)
            .unwrap();
        let (known, _) = fresh.accept_challenge(&output);
        assert!(!known);
        responder.connection_closed(51);

        let clock = TestClock::new(0);
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(52, &target.hello(None), "peer", false)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(52, &reveal, "peer", false).unwrap();
        assert_eq!(responder.next_deadline(), Some(Duration::from_secs(120)));
        clock.advance(60);
        assert!(responder.tick().unwrap().is_none());
        clock.advance(60);
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));

        let mut fresh = Target::new();
        let output = responder
            .receive(53, &fresh.hello(None), "peer", true)
            .unwrap();
        let (known, _) = fresh.accept_challenge(&output);
        assert!(!known);
    }

    #[test]
    fn deactivate_extends_a_pending_prompt_without_counting_a_failure() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(60, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(60, &reveal, "peer", true).unwrap();

        clock.advance(30);
        responder.deactivate().unwrap();
        assert_eq!(responder.next_deadline(), Some(Duration::from_secs(150)));
        clock.advance(60);
        assert!(responder.tick().unwrap().is_none());
        clock.advance(60);
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));

        let mut fresh = Target::new();
        let output = responder
            .receive(61, &fresh.hello(None), "peer", true)
            .unwrap();
        let (known, _) = fresh.accept_challenge(&output);
        assert!(!known);
    }

    #[test]
    fn an_expired_prompt_is_not_marked_visible_by_receive() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", false)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(1, &target.reveal(), "peer", false)
            .unwrap();
        assert!(responder.pending_prompt().is_some());

        clock.advance(INACTIVE_DECISION_SECONDS);
        assert!(responder.pending_prompt().is_none());

        // A frame at the deadline must not mark the expired prompt visible.
        let mut other = Target::new();
        let output = responder
            .receive(2, &other.hello(None), "other", true)
            .unwrap();
        assert!(!other.accept_challenge(&output).0);
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));
        assert!(!responder.failures.contains_key("peer"));
    }

    #[test]
    fn an_expired_prompt_is_not_marked_visible_by_activate() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", false)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(1, &target.reveal(), "peer", false)
            .unwrap();
        assert!(responder.pending_prompt().is_some());

        clock.advance(INACTIVE_DECISION_SECONDS);
        assert!(responder.pending_prompt().is_none());
        responder.activate();
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));
        assert!(!responder.failures.contains_key("peer"));

        // A live prompt still becomes visible when the app returns.
        let clock = TestClock::new(0);
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(2, &target.hello(None), "peer-2", false)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(2, &target.reveal(), "peer-2", false)
            .unwrap();
        clock.advance(30);
        responder.activate();
        clock.advance(INACTIVE_DECISION_SECONDS - 30);
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));
        assert!(responder.failures.contains_key("peer-2"));
    }

    #[test]
    fn repeated_deactivate_calls_cannot_extend_the_prompt_past_the_limit() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(1, &target.reveal(), "peer", true)
            .unwrap();

        clock.advance(30);
        responder.deactivate().unwrap();
        assert_eq!(responder.next_deadline(), Some(Duration::from_secs(150)));
        clock.advance(1);
        responder.deactivate().unwrap();
        assert_eq!(responder.next_deadline(), Some(Duration::from_secs(150)));
        clock.advance(60);
        responder.deactivate().unwrap();
        assert_eq!(responder.next_deadline(), Some(Duration::from_secs(150)));

        clock.advance(59);
        let output = responder.tick().unwrap().unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::TimedOut));
    }

    #[test]
    fn invalid_messages_use_a_bounded_backoff_and_not_the_prompt_lockout() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        for connection in 0..10 {
            let output = responder.receive(connection, &[0x01], "bad", true).unwrap();
            assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        }
        let mut target = Target::new();
        let output = responder
            .receive(100, &target.hello(None), "bad", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));

        clock.advance(1);
        let output = responder
            .receive(101, &target.hello(None), "bad", true)
            .unwrap();
        let (known, _) = target.accept_challenge(&output);
        assert!(!known);
        let reveal = target.reveal();
        responder.receive(101, &reveal, "bad", true).unwrap();
        assert_eq!(
            responder.pending_prompt().map(|p| p.code).as_deref(),
            Some("500 104")
        );
        assert_eq!(trust.len(), 0);
    }

    #[test]
    fn frame_reader_is_bounded_and_state_machine_rejects_bad_shapes() {
        let framed = wire_frame(&[1, 2, 3]).unwrap();
        let mut reader = FrameReader::default();
        reader.push(&framed[..3]).unwrap();
        assert_eq!(reader.next_frame().unwrap(), None);
        reader.push(&framed[3..]).unwrap();
        assert_eq!(reader.next_frame().unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(reader.buffered_len(), 0);

        let mut empty = FrameReader::default();
        empty.push(&[0, 0]).unwrap();
        assert_eq!(empty.next_frame(), Err(SourcePairingError::Protocol));

        let mut large = FrameReader::default();
        large.push(&((MAX_FRAME + 1) as u16).to_be_bytes()).unwrap();
        assert_eq!(large.next_frame(), Err(SourcePairingError::Protocol));

        let mut over = FrameReader::default();
        assert_eq!(
            over.push(&vec![0u8; MAX_BUFFERED + 1]),
            Err(SourcePairingError::FrameTooLarge)
        );

        let mut two = FrameReader::default();
        let first = wire_frame(&[1]).unwrap();
        let second = wire_frame(&[2]).unwrap();
        two.push(&first).unwrap();
        two.push(&second).unwrap();
        assert_eq!(two.next_frame().unwrap(), Some(vec![1]));
        assert_eq!(two.next_frame().unwrap(), Some(vec![2]));

        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let output = responder.receive(1, &[], "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        let output = responder
            .receive(2, &vec![0u8; MAX_FRAME + 1], "peer", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        let output = responder.receive_invalid(3, "peer").unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        assert_eq!(responder.active_sessions(), 0);
    }

    #[test]
    fn a_failed_dependency_fails_closed() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::failing_ephemeral();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        assert_eq!(
            responder.receive(1, &target.hello(None), "peer", true),
            Err(SourcePairingError::Identity)
        );
        assert_eq!(responder.active_sessions(), 0);
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(trust.len(), 0);

        let identity = TestIdentity::new();
        identity.0.borrow_mut().fail_nonce = true;
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let output = responder
            .receive(2, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(2, &reveal, "peer", true).unwrap();
        assert_eq!(
            decide_pending(&mut responder, true),
            Err(SourcePairingError::Identity)
        );
        assert_eq!(trust.len(), 0);
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(responder.active_sessions(), 0);

        let trust = TrustHandle::default();
        trust.set_fail_add(true);
        let identity = TestIdentity::new();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(3, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(3, &reveal, "peer", true).unwrap();
        assert_eq!(
            decide_pending(&mut responder, true),
            Err(SourcePairingError::TrustStore)
        );
        assert_eq!(trust.len(), 0);
        assert_eq!(responder.active_sessions(), 0);

        let trust = TrustHandle::default();
        let identity = TestIdentity::new();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        trust.add_ok(&target.l_s());
        let output = responder
            .receive(4, &target.hello(Some(2)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(4, &reveal, "peer", true).unwrap();
        trust.set_fail_remove(true);
        let request = target.forget_request([0x66u8; 12], &[]);
        assert_eq!(
            responder.receive(4, &request, "peer", true),
            Err(SourcePairingError::TrustStore)
        );
        assert_eq!(trust.len(), 1);
        assert_eq!(responder.active_sessions(), 0);

        let trust = TrustHandle::default();
        let clock = TestClock::new(10);
        let identity = TestIdentity::new();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let target = Target::new();
        responder
            .receive(5, &target.hello(None), "peer", true)
            .unwrap();
        clock.set(5);
        assert_eq!(
            responder.receive(5, &target.hello(None), "peer", true),
            Err(SourcePairingError::Clock)
        );
        assert_eq!(
            responder.receive(6, &target.hello(None), &"a".repeat(MAX_PEER_LEN + 1), true),
            Err(SourcePairingError::Peer)
        );

        let provider = Rc::new(ProviderState {
            credentials: Some(PairingCredentials::new(HOST, PORT, TOKEN).unwrap()),
            status: Some(ProxyStatus {
                proxy_running: true,
                foreground: true,
                connections: 1,
                port: 0,
                host: HOST,
                sequence: 0,
            }),
        });
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        trust.add_ok(&target.l_s());
        let output = responder
            .receive(7, &target.hello(Some(1)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(7, &reveal, "peer", true).unwrap();
        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 0);
        assert_eq!(
            responder.receive(7, &request, "peer", true),
            Err(SourcePairingError::Configuration)
        );
    }

    #[test]
    fn credentials_reject_unusable_values_and_redact_the_token() {
        assert!(PairingCredentials::new(HOST, 0, TOKEN).is_err());
        assert!(PairingCredentials::new(HOST, 1023, TOKEN).is_err());
        assert!(PairingCredentials::new(HOST, PAIRING_PORT, TOKEN).is_err());
        assert!(PairingCredentials::new(HOST, 1024, TOKEN).is_ok());
        assert!(PairingCredentials::new(HOST, 65535, TOKEN).is_ok());
        assert!(PairingCredentials::new(HOST, PORT, "").is_err());
        assert!(PairingCredentials::new(HOST, PORT, "bad token").is_err());
        assert!(PairingCredentials::new(HOST, PORT, "a".repeat(256)).is_err());
        assert!(PairingCredentials::new(Ipv4Addr::UNSPECIFIED, PORT, TOKEN).is_err());
        assert!(PairingCredentials::new(Ipv4Addr::new(239, 1, 1, 1), PORT, TOKEN).is_err());

        let credentials = PairingCredentials::new(HOST, PORT, TOKEN).unwrap();
        let text = format!("{credentials:?}");
        assert!(!text.contains(TOKEN));
        assert!(text.contains("[redacted]"));
        assert!(!SourcePairingError::TrustStore.to_string().contains(TOKEN));
    }

    #[test]
    fn pairing_prompt_debug_redacts_the_code() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        responder
            .receive(1, &target.reveal(), "peer", true)
            .unwrap();

        let prompt = responder.pending_prompt().unwrap();
        let text = format!("{prompt:?}");
        assert!(!text.contains(&prompt.code));
        assert!(text.contains("[redacted]"));
        assert!(text.contains("connection"));
        assert!(text.contains("id"));
    }

    #[test]
    fn status_requires_the_trusted_key_and_defined_flags() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        trust.add_ok(&target.l_s());
        let output = responder
            .receive(70, &target.hello(Some(1)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(70, &reveal, "peer", true).unwrap();
        trust.remove_ok(&target.l_s());
        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 0);
        let output = responder.receive(70, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));

        trust.add_ok(&target.l_s());
        let mut target = Target::new();
        let output = responder
            .receive(71, &target.hello(Some(1)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(71, &reveal, "peer", true).unwrap();
        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 1);
        let output = responder.receive(71, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));

        let mut target = Target::new();
        let output = responder
            .receive(72, &target.hello(Some(2)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(72, &reveal, "peer", true).unwrap();
        let request = target.forget_request([0x66u8; 12], b"not empty");
        let output = responder.receive(72, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        assert_eq!(trust.len(), 1);

        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 0);
        let output = responder.receive(72, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
    }

    /// A provider that has credentials for the first call, then loses them.
    struct ExpiringProvider {
        credentials: PairingCredentials,
        status: ProxyStatus,
        calls: Cell<usize>,
    }

    impl PairingContext for Rc<ExpiringProvider> {
        fn credentials(&self) -> Option<&PairingCredentials> {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            if calls == 0 {
                Some(&self.credentials)
            } else {
                None
            }
        }

        fn status(&self) -> Option<&ProxyStatus> {
            Some(&self.status)
        }
    }

    #[test]
    fn a_missing_context_does_not_prompt_or_leak_credentials() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = empty_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        // Pairing is off. An unknown target gets NotActive at the first frame.
        // It creates no challenge, no session, and no budget entry. More tries
        // than both limits must still get NotActive, not Busy or LockedOut.
        for connection in 0..(MAX_UNKNOWN_ATTEMPTS + MAX_PEER_CHALLENGES + 1) as u64 {
            let target = Target::new();
            let output = responder
                .receive(connection, &target.hello(None), "peer", true)
                .unwrap();
            assert_eq!(result_status(&output), Some(PairingStatus::NotActive));
            assert_eq!(responder.pending_prompt().map(|p| p.code), None);
            assert_eq!(responder.active_sessions(), 0);
            assert_eq!(trust.len(), 0);
        }
        assert!(responder.unknown_budget.is_empty());
        assert!(responder.unknown_challenges.is_empty());
        assert_eq!(identity.ephemeral_calls(), 0);
    }

    #[test]
    fn pairing_off_does_not_charge_the_reveal_attempt_budget() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = Rc::new(ExpiringProvider {
            credentials: PairingCredentials::new(HOST, PORT, TOKEN).unwrap(),
            status: ProxyStatus {
                proxy_running: true,
                foreground: true,
                connections: 1,
                port: PORT,
                host: HOST,
                sequence: 0,
            },
            calls: Cell::new(0),
        });
        let mut responder = PairingResponder::new(PairingResponderDependencies {
            identity: Box::new(identity.clone()),
            trust: Box::new(trust.clone()),
            context: Box::new(provider),
            clock: Box::new(clock.clone()),
        });

        // Pairing stops after the challenge. The REVEAL gets NotActive and
        // must not use one of the three prompt attempts.
        let mut target = Target::new();
        let output = responder
            .receive(1, &target.hello(None), "peer", true)
            .unwrap();
        assert!(!target.accept_challenge(&output).0);
        let reveal = target.reveal();
        let output = responder.receive(1, &reveal, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::NotActive));
        assert!(responder.unknown_budget.is_empty());
        assert!(responder.pending_prompt().is_none());
        assert_eq!(responder.active_sessions(), 0);
    }

    #[test]
    fn sessions_are_bounded_and_close_releases_a_slot() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        for connection in 0..MAX_SESSIONS as u64 {
            let mut target = Target::new();
            let output = responder
                .receive(connection, &target.hello(None), "peer", true)
                .unwrap();
            let (known, _) = target.accept_challenge(&output);
            assert!(!known);
        }
        assert_eq!(responder.active_sessions(), MAX_SESSIONS);

        let mut extra = Target::new();
        let output = responder
            .receive(90, &extra.hello(None), "peer-extra", true)
            .unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Busy));
        assert_eq!(responder.active_sessions(), MAX_SESSIONS);

        responder.connection_closed(0);
        assert_eq!(responder.active_sessions(), MAX_SESSIONS - 1);
        let output = responder
            .receive(91, &extra.hello(None), "peer-extra", true)
            .unwrap();
        let (known, _) = extra.accept_challenge(&output);
        assert!(!known);
        assert_eq!(responder.active_sessions(), MAX_SESSIONS);
    }

    #[test]
    fn bad_commitment_proof_and_low_order_key_are_rejected_without_a_prompt() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);

        let mut target = Target::new();
        let l_s = target.l_s();
        let wrong_commit = encode_hello(&l_s, &commitment(&[9u8; 32], &l_s));
        let output = responder.receive(98, &wrong_commit, "peer", true).unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        let output = responder.receive(98, &reveal, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(trust.len(), 0);

        let mut target = Target::new();
        let output = responder
            .receive(99, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let mut reveal = target.reveal();
        *reveal.last_mut().unwrap() ^= 1;
        let output = responder.receive(99, &reveal, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(trust.len(), 0);

        let mut target = Target::new();
        let l_s = target.l_s();
        let zero_commit = encode_hello(&l_s, &commitment(&[0u8; 32], &l_s));
        let output = responder.receive(100, &zero_commit, "peer", true).unwrap();
        target.accept_challenge(&output);
        let reveal = encode_reveal(&[0u8; 32], &[0u8; 32]);
        let output = responder.receive(100, &reveal, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
        assert_eq!(responder.pending_prompt().map(|p| p.code), None);
        assert_eq!(trust.len(), 0);
    }

    #[test]
    fn a_reused_aead_nonce_is_refused() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        identity.0.borrow_mut().nonces = VecDeque::from(vec![[0x44u8; 12]; MAX_SESSION_NONCES]);
        let provider = valid_provider();
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        trust.add_ok(&target.l_s());

        let output = responder
            .receive(95, &target.hello(None), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        let output = responder.receive(95, &reveal, "peer", true).unwrap();
        assert_eq!(output.status, Some(PairingStatus::Ok));
        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 0);
        assert_eq!(
            responder.receive(95, &request, "peer", true),
            Err(SourcePairingError::Identity)
        );
    }

    #[test]
    fn status_refuses_a_missing_or_mismatched_credential_host() {
        let trust = TrustHandle::default();
        let clock = TestClock::new(0);
        let identity = TestIdentity::new();
        let target = Target::new();
        trust.add_ok(&target.l_s());

        let provider = Rc::new(ProviderState {
            credentials: Some(PairingCredentials::new(HOST, PORT, TOKEN).unwrap()),
            status: Some(ProxyStatus {
                proxy_running: true,
                foreground: true,
                connections: 1,
                port: PORT,
                host: Ipv4Addr::LOCALHOST,
                sequence: 0,
            }),
        });
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(96, &target.hello(Some(1)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(96, &reveal, "peer", true).unwrap();
        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 0);
        let output = responder.receive(96, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));

        let provider = Rc::new(ProviderState {
            credentials: None,
            status: Some(ProxyStatus {
                proxy_running: true,
                foreground: true,
                connections: 1,
                port: PORT,
                host: HOST,
                sequence: 0,
            }),
        });
        let mut responder = make_responder(&trust, &clock, &identity, &provider);
        let mut target = Target::new();
        let output = responder
            .receive(97, &target.hello(Some(1)), "peer", true)
            .unwrap();
        target.accept_challenge(&output);
        let reveal = target.reveal();
        responder.receive(97, &reveal, "peer", true).unwrap();
        let request = target.status_request(&[0x55u8; 16], [0x77u8; 12], 0);
        let output = responder.receive(97, &request, "peer", true).unwrap();
        assert_eq!(result_status(&output), Some(PairingStatus::Rejected));
    }

    fn hex_v(bytes: &[u8]) -> String {
        crate::pairing::hex(bytes)
    }

    struct RealClock {
        origin: std::time::Instant,
    }

    impl RealClock {
        fn new() -> Self {
            Self {
                origin: std::time::Instant::now(),
            }
        }
    }

    impl Clock for RealClock {
        fn now(&self) -> Duration {
            self.origin.elapsed()
        }
    }

    fn serve_one_loopback(
        listener: std::net::TcpListener,
        responder: &mut PairingResponder,
        approve: bool,
    ) {
        use std::io::{Read, Write};

        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the test client did not connect"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut reader = FrameReader::default();
        let mut buffer = [0u8; 1024];
        loop {
            if let Some(payload) = reader.next_frame().unwrap() {
                let mut output = responder.receive(1, &payload, "127.0.0.1", true).unwrap();
                if let Some(prompt) = responder.pending_prompt().filter(|_| approve) {
                    if let Some(decision) = responder
                        .decide(prompt.connection, prompt.id, &prompt.code, true)
                        .unwrap()
                    {
                        output = decision;
                    }
                }
                for frame in &output.frames {
                    stream.write_all(frame).unwrap();
                }
                if output.close {
                    return;
                }
                continue;
            }
            match stream.read(&mut buffer) {
                Ok(0) => {
                    responder.connection_closed(1);
                    return;
                }
                Ok(count) => reader.push(&buffer[..count]).unwrap(),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("the test client stopped writing");
                }
                Err(error) => panic!("read failed: {error}"),
            }
        }
    }

    #[test]
    fn target_client_pair_and_status_interoperate_over_loopback() {
        use std::sync::atomic::AtomicBool;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let trust = TrustHandle::default();
        let identity = TestIdentity::new();
        let provider = Rc::new(ProviderState {
            credentials: Some(PairingCredentials::new(Ipv4Addr::LOCALHOST, PORT, TOKEN).unwrap()),
            status: Some(ProxyStatus {
                proxy_running: true,
                foreground: true,
                connections: 2,
                port: PORT,
                host: Ipv4Addr::LOCALHOST,
                sequence: 1,
            }),
        });
        let mut responder = PairingResponder::new(PairingResponderDependencies {
            identity: Box::new(identity.clone()),
            trust: Box::new(trust.clone()),
            context: Box::new(ProviderHandle(provider.clone())),
            clock: Box::new(RealClock::new()),
        });

        let client_identity = crate::pairing::Identity::from_bytes(L_S_PRIV);
        let audit = crate::normalization::Audit::default();
        let client = std::thread::spawn(move || {
            let cancel = AtomicBool::new(false);
            let mut codes = Vec::new();
            let result = crate::pairing::pair_at(
                address,
                &client_identity,
                None,
                &audit,
                &cancel,
                crate::pairing::PairTimeouts {
                    connect: Duration::from_secs(2),
                    challenge: Duration::from_secs(2),
                    result: Duration::from_secs(2),
                },
                |code| codes.push(code.to_owned()),
            );
            (result, codes, audit.snapshot())
        });

        serve_one_loopback(listener, &mut responder, true);
        let (result, codes, audit) = client.join().unwrap();
        let credentials = result.unwrap();
        assert_eq!(credentials.host, Ipv4Addr::LOCALHOST);
        assert_eq!(credentials.port, PORT);
        assert_eq!(credentials.token, TOKEN);
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].len(), 7);
        assert_eq!(audit, (1, 0));
        assert_eq!(trust.len(), 1);
        assert_eq!(responder.active_sessions(), 0);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut responder = PairingResponder::new(PairingResponderDependencies {
            identity: Box::new(identity),
            trust: Box::new(trust),
            context: Box::new(ProviderHandle(provider)),
            clock: Box::new(RealClock::new()),
        });
        let client_identity = crate::pairing::Identity::from_bytes(L_S_PRIV);
        let audit = crate::normalization::Audit::default();
        let client = std::thread::spawn(move || {
            let cancel = AtomicBool::new(false);
            let result =
                crate::pairing::status_at(address, &client_identity, None, &audit, &cancel);
            (result, audit.snapshot())
        });

        serve_one_loopback(listener, &mut responder, false);
        let (info, audit) = client.join().unwrap();
        let info = info.unwrap();
        assert!(info.proxy_running);
        assert!(info.foreground);
        assert_eq!(info.connections, 2);
        assert_eq!(info.port, PORT);
        assert_eq!(info.host, Ipv4Addr::LOCALHOST.to_string());
        assert_eq!(audit, (1, 0));
    }
}
