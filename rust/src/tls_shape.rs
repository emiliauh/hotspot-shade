//! TLS ClientHello record reframing for an established byte relay.
//!
//! The relay carries opaque bytes. This module changes only the TLS record
//! framing of the first `ClientHello` handshake message. It does not change
//! one handshake byte, so the transcript hash is unchanged. A TLS peer
//! reassembles handshake messages across records (RFC 8446 section 5.1), so a
//! smaller record size is legal.
//!
//! What this does:
//!
//! - buffer the first handshake record or records of a flow,
//! - check that they carry one `ClientHello` message,
//! - write that message again as records whose payloads are 1 to 8 bytes,
//! - pass every byte after the `ClientHello` through unchanged.
//!
//! A stream that cannot be a `ClientHello` is passed through at the first
//! byte that rules it out. That byte is the record content type, the TLS
//! major version, the record length, or the first handshake byte. A short
//! request/response protocol therefore never waits for a full record header
//! or a complete handshake message.
//!
//! What this does not do:
//!
//! - it does not hide SNI, JA3/JA4, the destination address, DNS names, or
//!   flow shape and timing. Those stay visible,
//! - it does not change the TLS version. A byte relay cannot force the
//!   client's TLS version, and this module does not attempt it,
//! - it does not control TCP segmentation. The writes are small, but the
//!   local TCP stack and the network can coalesce them,
//! - it does not reshape a second `ClientHello`, a retry, or any later
//!   handshake record. Those bytes pass through unchanged,
//! - it does not claim to protect a non-TLS protocol whose first bytes happen
//!   to parse as a TLS `ClientHello`. Such a stream is reframed, so its
//!   receiver must read TLS records to recover the same bytes.
//!
//! Shaping is off by default. A caller turns it on by passing [`ShapeLimits`]
//! to a relay that supports it. This module is platform neutral. macOS,
//! Windows, and Linux use this Rust code. The iOS and Android source device
//! apps hold a port of this state machine. Keep the early rejection points in
//! the ports in step with this module, so a short protocol never stalls there.
//!
//! Memory and output are bounded. A flow holds at most
//! [`ShapeLimits::max_buffered`] raw bytes between calls while it waits for a
//! complete `ClientHello`; one feed may briefly append its input before the
//! cap check. The input is parsed before the cap is applied, so a feed that
//! carries the rest of a complete `ClientHello` and a large tail in one read
//! is still reframed; the same bytes split at the end of the `ClientHello`
//! take the same path if the buffered prefix stays within the cap. With small
//! custom limits, other splits may hit the cap first and pass through. The cap
//! only forces a pass-through when parsing still
//! needs more bytes. A `ClientHello` larger than the cap, a record count above
//! the cap, a record that is not a handshake record, or any malformed input
//! turns the flow into a plain pass-through, byte for byte. The caller emits
//! each record through a sink, so a slow socket applies backpressure.
//!
//! A record boundary can split the handshake header. The header is then
//! checked from the bytes already held across records, as soon as all four
//! header bytes are present. The shaper does not wait for the rest of the
//! record, and a partial length is never accepted as a complete one.
//!
//! A client that ends the stream before the `ClientHello` is complete must
//! call [`ClientHelloShaper::finish`] before the half-close. `finish` releases
//! the held bytes unchanged, in order, exactly once. It is the only correct
//! end of a buffering flow: dropping the shaper discards those bytes.
//!
//! A sink error is terminal. The shaper drops its buffers and refuses later
//! input, so a caller that retries cannot panic on a stale offset. The caller
//! closes the flow.
//!
//! The shaper holds no timer. While it waits, the raw buffer is bounded by
//! `max_buffered` and the reassembled payload by `max_client_hello`. The bytes
//! held are the first bytes of the flow. The
//! relay's own bounds apply: the SOCKS relay closes a flow after 300 seconds
//! without traffic, and a source device proxy session has its own handshake
//! and idle budgets. This module adds no shaping deadline and claims none; a
//! deadline needs a clock and a wake-up the relay does not have, and a wrong
//! one would cut a slow but valid handshake.
//!
//! The module holds no address, host name, or SNI value. It must not log one.

use std::io;

/// A TLS handshake record content type.
const CONTENT_HANDSHAKE: u8 = 22;
/// The TLS major version. A record that does not start with 3 is not TLS.
const TLS_MAJOR: u8 = 3;
/// The handshake type of a ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// A record payload cannot exceed this value in TLS 1.2 and 1.3.
pub const MAX_TLS_RECORD_PAYLOAD: usize = 16_384;
/// The fixed part of a ClientHello: handshake header, version, random, and
/// session id length. Anything shorter is not a ClientHello.
pub const MIN_CLIENT_HELLO_MESSAGE: usize = 4 + 2 + 32 + 1;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The bounds for one shaped flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShapeLimits {
    /// The largest payload of one written record. Values of 1 to 8 are
    /// accepted. The default is 8.
    pub max_chunk: usize,
    /// The largest ClientHello message that is reshaped. A larger message
    /// passes through unchanged. The default is 16 KiB.
    pub max_client_hello: usize,
    /// The most handshake records read from the client, and the most records
    /// written back, while the ClientHello is shaped. The written count
    /// includes records that carry handshake bytes after the ClientHello. A
    /// flow above either cap passes through unchanged. The default is 4096.
    pub max_records: usize,
    /// The most raw bytes buffered while the flow waits for a complete
    /// ClientHello. The default is 64 KiB. The cap is applied only when
    /// parsing still needs more bytes, so a complete ClientHello in the same
    /// feed is reframed even when that feed pushes the buffer above the cap.
    pub max_buffered: usize,
}

impl Default for ShapeLimits {
    fn default() -> Self {
        Self {
            max_chunk: 8,
            max_client_hello: 16 * 1024,
            max_records: 4096,
            max_buffered: 64 * 1024,
        }
    }
}

impl ShapeLimits {
    /// Check the bounds. A rejected set is never used.
    pub fn validate(self) -> io::Result<Self> {
        if !(1..=8).contains(&self.max_chunk) {
            return Err(invalid("max_chunk must be between 1 and 8"));
        }
        if self.max_client_hello < MIN_CLIENT_HELLO_MESSAGE {
            return Err(invalid("max_client_hello is too small"));
        }
        if self.max_records == 0 {
            return Err(invalid("max_records must be positive"));
        }
        if self.max_buffered < self.max_client_hello {
            return Err(invalid("max_buffered must cover max_client_hello"));
        }
        Ok(self)
    }
}

/// What the shaper did with the flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeState {
    /// The flow is still waiting for a record or a complete ClientHello.
    Buffering,
    /// The first ClientHello was reframed. Every later byte passes through.
    Reframed,
    /// The flow is not a shapeable TLS ClientHello. Every byte passes through.
    PassThrough,
    /// The sink failed and the flow ended. The shaper emits nothing more.
    Failed,
}

enum RecordStep {
    /// The next record header or payload is not in the buffer yet.
    NeedMore,
    /// The buffered bytes cannot be a shapeable ClientHello.
    PassThrough,
    /// One more record joined the payload buffer.
    Progress,
}

/// A per-flow TLS record reframer. Create one for each direction that shapes
/// the client to destination bytes. Never share one between flows.
pub struct ClientHelloShaper {
    limits: ShapeLimits,
    state: ShapeState,
    /// Raw bytes received but not yet emitted.
    raw: Vec<u8>,
    /// The payload bytes of the handshake records read so far.
    payload: Vec<u8>,
    /// The number of `raw` bytes that belong to the records in `payload`.
    consumed: usize,
    /// The number of handshake records read so far.
    records: usize,
    /// The legacy record version of the first record.
    version: [u8; 2],
    /// A reused record frame, so one record needs one sink call.
    record: Vec<u8>,
}

impl Default for ClientHelloShaper {
    fn default() -> Self {
        Self::with_default_limits()
    }
}

impl ClientHelloShaper {
    /// Build a shaper with validated bounds.
    pub fn new(limits: ShapeLimits) -> io::Result<Self> {
        let limits = limits.validate()?;
        Ok(Self {
            limits,
            state: ShapeState::Buffering,
            raw: Vec::new(),
            payload: Vec::new(),
            consumed: 0,
            records: 0,
            version: [TLS_MAJOR, 1],
            record: Vec::with_capacity(5 + limits.max_chunk),
        })
    }

    /// Build a shaper with the default bounds.
    pub fn with_default_limits() -> Self {
        // The default bounds pass validation.
        Self::new(ShapeLimits::default()).expect("the default shape limits are valid")
    }

    /// The bounds in use.
    pub fn limits(&self) -> ShapeLimits {
        self.limits
    }

    /// The current state. `Buffering` is the only state that holds bytes.
    pub fn state(&self) -> ShapeState {
        self.state
    }

    /// The number of bytes held while the flow waits for a ClientHello.
    pub fn buffered(&self) -> usize {
        self.raw.len()
    }

    /// Feed the next bytes from the client. Each output slice is one complete
    /// TLS record while the ClientHello is shaped, or a plain pass-through
    /// chunk. Call the sink in order. A sink error ends the flow in every
    /// state and is returned unchanged. After that error every later call
    /// returns a broken-pipe error and emits nothing: the flow is terminal.
    ///
    /// A byte that rules out a ClientHello is emitted unchanged as soon as it
    /// arrives. A prefix that still looks like TLS stays buffered until the
    /// message completes, or until it still needs more bytes and
    /// `max_buffered` is exceeded, or `finish` is called. Everything that
    /// arrived is parsed first, so a complete ClientHello is never passed
    /// through just because its feed also carried a large tail.
    pub fn feed(
        &mut self,
        input: &[u8],
        emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        match self.state {
            ShapeState::Reframed | ShapeState::PassThrough => {
                if let Err(error) = emit(input) {
                    self.fail();
                    return Err(error);
                }
                return Ok(());
            }
            ShapeState::Failed => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the TLS shape sink already failed",
                ))
            }
            ShapeState::Buffering => {}
        }
        if input.is_empty() {
            return Ok(());
        }
        self.raw.extend_from_slice(input);
        loop {
            if self.payload.is_empty() {
                match self.take_record()? {
                    RecordStep::NeedMore => return self.wait_within_cap(emit),
                    RecordStep::PassThrough => return self.pass_through(emit),
                    RecordStep::Progress => continue,
                }
            }
            // The first payload byte is the handshake type. `take_record`
            // checks it before the first record is complete. Keep the check
            // here as the single place that decides the message type.
            if self.payload[0] != HANDSHAKE_CLIENT_HELLO {
                return self.pass_through(emit);
            }
            if self.payload.len() < 4 {
                match self.take_record()? {
                    RecordStep::NeedMore => return self.wait_within_cap(emit),
                    RecordStep::PassThrough => return self.pass_through(emit),
                    RecordStep::Progress => continue,
                }
            }
            let declared = (usize::from(self.payload[1]) << 16)
                | (usize::from(self.payload[2]) << 8)
                | usize::from(self.payload[3]);
            let message_len = declared + 4;
            if !(MIN_CLIENT_HELLO_MESSAGE..=self.limits.max_client_hello).contains(&message_len) {
                return self.pass_through(emit);
            }
            if self.payload.len() < message_len {
                match self.take_record()? {
                    RecordStep::NeedMore => return self.wait_within_cap(emit),
                    RecordStep::PassThrough => return self.pass_through(emit),
                    RecordStep::Progress => continue,
                }
            }
            return self.reframe(message_len, emit);
        }
    }

    /// Keep waiting for more bytes when the held raw buffer is within the cap.
    /// Above the cap the flow gives up shaping and releases every buffered byte
    /// unchanged. This runs only when parsing still needs more input, so a
    /// complete ClientHello is always parsed first.
    fn wait_within_cap(&mut self, emit: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        if self.raw.len() > self.limits.max_buffered {
            return self.pass_through(emit);
        }
        Ok(())
    }

    /// Release the bytes still held, unchanged and in order, when the client
    /// ends the stream. Call it exactly once, before the half-close.
    ///
    /// It emits at most one slice, which is the raw input in the order it
    /// arrived. A second call and any later call emit nothing, and no later
    /// byte is shaped. A sink error here ends the flow like any other.
    pub fn finish(&mut self, emit: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        if self.state == ShapeState::Failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the TLS shape sink already failed",
            ));
        }
        if self.state != ShapeState::Buffering {
            return Ok(());
        }
        let raw = std::mem::take(&mut self.raw);
        self.payload.clear();
        self.consumed = 0;
        self.records = 0;
        self.state = ShapeState::PassThrough;
        if raw.is_empty() {
            return Ok(());
        }
        if let Err(error) = emit(&raw) {
            self.fail();
            return Err(error);
        }
        Ok(())
    }

    /// Read one handshake record from the raw buffer.
    ///
    /// Each header byte is checked as soon as it is available. A record that
    /// cannot be a handshake record is rejected without waiting for the rest
    /// of the header or payload.
    fn take_record(&mut self) -> io::Result<RecordStep> {
        let available = self.raw.len() - self.consumed;
        if available == 0 {
            return Ok(RecordStep::NeedMore);
        }
        let header = &self.raw[self.consumed..];
        if header[0] != CONTENT_HANDSHAKE {
            return Ok(RecordStep::PassThrough);
        }
        if available < 2 {
            return Ok(RecordStep::NeedMore);
        }
        if header[1] != TLS_MAJOR {
            return Ok(RecordStep::PassThrough);
        }
        if available < 5 {
            return Ok(RecordStep::NeedMore);
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len == 0 || len > MAX_TLS_RECORD_PAYLOAD {
            return Ok(RecordStep::PassThrough);
        }
        if self.payload.len() < 4 {
            // The handshake header can span records. Check the bytes held
            // across the reassembled payload and the available part of this
            // record. As soon as all four header bytes are present, reject an
            // impossible message without waiting for the whole record. Only
            // bytes inside this record are handshake bytes: a byte after its
            // payload is the next record header, not part of this message.
            let start = self.consumed + 5;
            let in_record = (available - 5).min(len);
            let have = self.payload.len();
            let take = (4 - have).min(in_record);
            let mut prefix = [0u8; 4];
            prefix[..have].copy_from_slice(&self.payload[..have]);
            prefix[have..have + take].copy_from_slice(&self.raw[start..start + take]);
            let present = have + take;
            if present >= 1 && prefix[0] != HANDSHAKE_CLIENT_HELLO {
                return Ok(RecordStep::PassThrough);
            }
            if present == 4 {
                let declared = (usize::from(prefix[1]) << 16)
                    | (usize::from(prefix[2]) << 8)
                    | usize::from(prefix[3]);
                let message_len = declared + 4;
                if !(MIN_CLIENT_HELLO_MESSAGE..=self.limits.max_client_hello).contains(&message_len)
                {
                    return Ok(RecordStep::PassThrough);
                }
            }
        }
        if available - 5 < len {
            return Ok(RecordStep::NeedMore);
        }
        if self.records == 0 {
            self.version = [header[1], header[2]];
        }
        let start = self.consumed + 5;
        self.payload
            .extend_from_slice(&self.raw[start..start + len]);
        self.consumed = start + len;
        self.records += 1;
        if self.records > self.limits.max_records {
            return Ok(RecordStep::PassThrough);
        }
        Ok(RecordStep::Progress)
    }

    /// Emit the ClientHello as small records, then the bytes after it.
    fn reframe(
        &mut self,
        message_len: usize,
        emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let written = records_for(message_len, self.limits.max_chunk);
        let leftover = self.payload[message_len..]
            .len()
            .div_ceil(MAX_TLS_RECORD_PAYLOAD);
        if written.saturating_add(leftover) > self.limits.max_records {
            return self.pass_through(emit);
        }
        let payload = std::mem::take(&mut self.payload);
        let raw = std::mem::take(&mut self.raw);
        let version = self.version;
        let mut offset = 0;
        let mut index = 0;
        while offset < message_len {
            let size = 1 + (index % self.limits.max_chunk);
            let end = (offset + size).min(message_len);
            self.write_record(version, &payload[offset..end]);
            if let Err(error) = emit(&self.record) {
                self.fail();
                return Err(error);
            }
            offset = end;
            index += 1;
        }
        // Handshake bytes that followed the ClientHello in the same records
        // stay in order and unchanged. Only their record framing is new.
        let mut rest = &payload[message_len..];
        while !rest.is_empty() {
            let size = rest.len().min(MAX_TLS_RECORD_PAYLOAD);
            self.write_record(version, &rest[..size]);
            if let Err(error) = emit(&self.record) {
                self.fail();
                return Err(error);
            }
            rest = &rest[size..];
        }
        // Bytes after the records that carried the ClientHello were never
        // touched. They go out exactly as they arrived.
        let tail = &raw[self.consumed..];
        self.state = ShapeState::Reframed;
        self.consumed = 0;
        self.records = 0;
        if !tail.is_empty() {
            if let Err(error) = emit(tail) {
                self.fail();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Build one handshake record in the reused frame.
    fn write_record(&mut self, version: [u8; 2], payload: &[u8]) {
        let len = payload.len() as u16;
        self.record.clear();
        self.record.push(CONTENT_HANDSHAKE);
        self.record.push(version[0]);
        self.record.push(version[1]);
        self.record.extend_from_slice(&len.to_be_bytes());
        self.record.extend_from_slice(payload);
    }

    /// Give up shaping and emit every buffered byte unchanged.
    fn pass_through(&mut self, emit: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        let raw = std::mem::take(&mut self.raw);
        self.state = ShapeState::PassThrough;
        self.payload.clear();
        self.consumed = 0;
        self.records = 0;
        if raw.is_empty() {
            return Ok(());
        }
        if let Err(error) = emit(&raw) {
            self.fail();
            return Err(error);
        }
        Ok(())
    }

    /// Drop every buffer and refuse later input. A sink failure is terminal:
    /// a half-written record or a stale offset can never be read again.
    fn fail(&mut self) {
        self.raw = Vec::new();
        self.payload = Vec::new();
        self.consumed = 0;
        self.records = 0;
        self.state = ShapeState::Failed;
    }
}

/// The number of records that a split of `len` bytes needs.
fn records_for(len: usize, max_chunk: usize) -> usize {
    let mut count = 0;
    let mut offset = 0;
    while offset < len {
        offset += 1 + (count % max_chunk);
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic ClientHello shape. The body is not a real handshake,
    /// but the message header and length are real.
    fn client_hello(body_len: usize) -> Vec<u8> {
        let mut message = Vec::with_capacity(4 + body_len);
        message.push(HANDSHAKE_CLIENT_HELLO);
        message.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        for i in 0..body_len {
            message.push((i % 251) as u8);
        }
        message
    }

    fn handshake_record(version: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut out = vec![CONTENT_HANDSHAKE, version[0], version[1]];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Parse the emitted chunks as TLS records and return the payload bytes,
    /// the number of records, and the largest payload.
    fn parse(chunks: &[Vec<u8>]) -> (Vec<u8>, usize, usize) {
        let mut payload = Vec::new();
        let mut largest = 0;
        for chunk in chunks {
            assert!(chunk.len() >= 5, "each emitted chunk is a record");
            assert_eq!(chunk[0], CONTENT_HANDSHAKE);
            assert_eq!(chunk[1], TLS_MAJOR);
            let len = usize::from(u16::from_be_bytes([chunk[3], chunk[4]]));
            assert_eq!(chunk.len(), 5 + len, "a record length matches its bytes");
            assert!(len <= MAX_TLS_RECORD_PAYLOAD);
            largest = largest.max(len);
            payload.extend_from_slice(&chunk[5..]);
        }
        (payload, chunks.len(), largest)
    }

    fn run(input: &[u8]) -> (Vec<Vec<u8>>, ShapeState) {
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        (chunks, shaper.state())
    }

    fn feed_parts(parts: &[&[u8]]) -> (Vec<Vec<u8>>, ShapeState) {
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        for part in parts {
            shaper
                .feed(part, &mut |chunk| {
                    chunks.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap();
        }
        (chunks, shaper.state())
    }

    fn feed_parts_with_limits(limits: ShapeLimits, parts: &[&[u8]]) -> (Vec<Vec<u8>>, ShapeState) {
        let mut shaper = ClientHelloShaper::new(limits).unwrap();
        let mut chunks = Vec::new();
        for part in parts {
            shaper
                .feed(part, &mut |chunk| {
                    chunks.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap();
        }
        (chunks, shaper.state())
    }

    /// Split `payload` into handshake records of at most `size` bytes.
    fn records_of(version: [u8; 2], payload: &[u8], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in payload.chunks(size) {
            out.extend_from_slice(&handshake_record(version, part));
        }
        out
    }

    /// Feed every part, then finish, and return the emitted bytes and the
    /// final state. Finishing releases a held prefix unchanged, so a flow that
    /// ends still conserves every byte.
    fn run_finished(parts: &[&[u8]]) -> (Vec<u8>, ShapeState) {
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        for part in parts {
            shaper
                .feed(part, &mut |chunk| {
                    chunks.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap();
        }
        shaper
            .finish(&mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        (chunks.concat(), shaper.state())
    }

    /// The bytes a stream carries: the payload of every complete handshake
    /// record, followed by every byte after the last complete record. Record
    /// framing is removed and nothing else, so the result is unchanged when
    /// only the framing changes.
    fn logical_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while rest.len() >= 5 && rest[0] == CONTENT_HANDSHAKE && rest[1] == TLS_MAJOR {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            if len == 0 || len > MAX_TLS_RECORD_PAYLOAD || rest.len() < 5 + len {
                break;
            }
            out.extend_from_slice(&rest[5..5 + len]);
            rest = &rest[5 + len..];
        }
        out.extend_from_slice(rest);
        out
    }

    /// The inputs used by the split invariance tests. Each one covers a
    /// different early decision point or record boundary.
    fn split_corpus() -> Vec<(String, Vec<u8>)> {
        let message = client_hello(300);
        let mut corpus: Vec<(String, Vec<u8>)> = Vec::new();
        corpus.push(("one record".into(), handshake_record([3, 3], &message)));
        for first in 1..=4 {
            let mut input = handshake_record([3, 3], &message[..first]);
            input.extend_from_slice(&handshake_record([3, 3], &message[first..]));
            corpus.push((format!("first record carries {first} bytes"), input));
        }
        let one_byte_records: Vec<u8> = message
            .iter()
            .flat_map(|byte| handshake_record([3, 1], &[*byte]))
            .collect();
        corpus.push(("one byte records".into(), one_byte_records));
        let mut with_tail = handshake_record([3, 3], &message);
        with_tail.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        corpus.push(("hello and an application tail".into(), with_tail));
        let mut with_later_record = handshake_record([3, 3], &message);
        with_later_record.extend_from_slice(&handshake_record([3, 3], &client_hello(24)));
        corpus.push((
            "hello and a later handshake record".into(),
            with_later_record,
        ));
        corpus.push(("short protocol".into(), b"PING".to_vec()));
        corpus.push((
            "http request".into(),
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        ));
        corpus.push(("partial header".into(), vec![CONTENT_HANDSHAKE, TLS_MAJOR]));
        corpus.push((
            "one byte handshake record".into(),
            vec![
                CONTENT_HANDSHAKE,
                TLS_MAJOR,
                1,
                0,
                1,
                HANDSHAKE_CLIENT_HELLO,
            ],
        ));
        corpus.push((
            "one byte record and a partial next header".into(),
            vec![CONTENT_HANDSHAKE, 3, 3, 0, 1, 1, CONTENT_HANDSHAKE, 3],
        ));
        corpus.push((
            "one byte record and a complete next header".into(),
            vec![
                CONTENT_HANDSHAKE,
                3,
                3,
                0,
                1,
                1,
                CONTENT_HANDSHAKE,
                3,
                3,
                0,
                1,
            ],
        ));
        corpus.push((
            "application data record".into(),
            vec![23, 3, 3, 0, 4, b'd', b'a', b't', b'a'],
        ));
        corpus.push((
            "server hello".into(),
            handshake_record([3, 3], &[2, 0, 0, 4, 0, 0, 0, 0]),
        ));
        corpus.push((
            "zero length record".into(),
            vec![CONTENT_HANDSHAKE, 3, 3, 0, 0],
        ));
        corpus
    }

    #[test]
    fn a_tiny_first_record_is_shaped_the_same_when_it_is_split_after_it() {
        // Regression: the first record carries only one handshake byte, so
        // the rest of the message arrives in the next record. The bytes after
        // the first record's payload are the next record header, not length
        // bytes of this message. Delivered whole, the flow used to pass
        // through; split after the first record, it used to reframe.
        for first in 1..=3 {
            let message = client_hello(300);
            let mut input = handshake_record([3, 3], &message[..first]);
            input.extend_from_slice(&handshake_record([3, 3], &message[first..]));
            let split = 5 + first;
            let (whole, state) = run(&input);
            let (split_chunks, split_state) = feed_parts(&[&input[..split], &input[split..]]);
            assert_eq!(state, ShapeState::Reframed, "first record of {first} bytes");
            assert_eq!(split_state, state, "first record of {first} bytes");
            assert_eq!(split_chunks, whole, "first record of {first} bytes");
            let (payload, _, _) = parse(&whole);
            assert_eq!(payload, message, "first record of {first} bytes");
        }
    }

    #[test]
    fn every_two_way_split_emits_the_same_bytes_as_one_feed() {
        for (name, input) in split_corpus() {
            let (whole, whole_state) = run_finished(&[&input]);
            assert!(
                matches!(whole_state, ShapeState::Reframed | ShapeState::PassThrough),
                "{name}: a finished flow is not buffering"
            );
            assert_eq!(
                logical_bytes(&whole),
                logical_bytes(&input),
                "{name}: every carried byte is conserved"
            );
            if whole_state == ShapeState::PassThrough {
                assert_eq!(whole, input, "{name}: a pass-through is byte for byte");
            }
            for split in 0..=input.len() {
                let (out, state) = run_finished(&[&input[..split], &input[split..]]);
                assert_eq!(
                    state, whole_state,
                    "{name}: split {split} takes the same path"
                );
                assert_eq!(out, whole, "{name}: split {split} emits the same bytes");
            }
        }
    }

    #[test]
    fn every_one_byte_feeding_emits_the_same_bytes_as_one_feed() {
        for (name, input) in split_corpus() {
            let (whole, whole_state) = run_finished(&[&input]);
            let bytes: Vec<[u8; 1]> = input.iter().map(|byte| [*byte]).collect();
            let parts: Vec<&[u8]> = bytes.iter().map(|part| part.as_slice()).collect();
            let (out, state) = run_finished(&parts);
            assert_eq!(
                state, whole_state,
                "{name}: one byte feeds take the same path"
            );
            assert_eq!(out, whole, "{name}: one byte feeds emit the same bytes");
        }
    }

    #[test]
    fn one_record_client_hello_is_reframed_and_reassembles() {
        let message = client_hello(300);
        let input = handshake_record([3, 1], &message);
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::Reframed);
        assert!(chunks.len() > 1, "the ClientHello spans many records");
        let (payload, records, largest) = parse(&chunks);
        assert_eq!(payload, message, "handshake bytes are identical");
        assert!(records >= message.len() / 8);
        assert!(largest <= 8, "no written record payload exceeds 8 bytes");
        assert!(largest >= 1);
        for chunk in &chunks {
            assert_eq!(
                &chunk[1..3],
                &[3, 1],
                "the record version is the client version"
            );
        }
    }

    #[test]
    fn a_client_hello_whose_first_record_carries_one_byte_is_reframed() {
        // A client may put one handshake byte in the first record and the
        // rest in the next one. The bytes after the first record's payload
        // are the next record header, not the rest of this message.
        let message = client_hello(300);
        let mut input = handshake_record([3, 3], &message[..1]);
        input.extend_from_slice(&handshake_record([3, 3], &message[1..]));
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::Reframed);
        let (payload, _, largest) = parse(&chunks);
        assert_eq!(payload, message);
        assert!(largest <= 8);
    }

    #[test]
    fn client_hello_split_across_records_is_reassembled() {
        let message = client_hello(500);
        let mut input = Vec::new();
        input.extend_from_slice(&handshake_record([3, 3], &message[..2]));
        input.extend_from_slice(&handshake_record([3, 3], &message[2..17]));
        input.extend_from_slice(&handshake_record([3, 3], &message[17..]));
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::Reframed);
        let (payload, _, _) = parse(&chunks);
        assert_eq!(payload, message);
    }

    #[test]
    fn one_byte_feeds_match_one_big_feed() {
        let message = client_hello(120);
        let input = handshake_record([3, 1], &message);
        let (whole, _) = run(&input);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut split = Vec::new();
        for byte in &input {
            shaper
                .feed(&[*byte], &mut |chunk| {
                    split.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(whole, split);
    }

    #[test]
    fn partial_records_wait_without_output() {
        let message = client_hello(60);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(&input[..3], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty(), "a partial header emits nothing");
        assert_eq!(shaper.buffered(), 3);
        shaper
            .feed(&input[3..], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        let (payload, _, _) = parse(&chunks);
        assert_eq!(payload, message);
    }

    #[test]
    fn bytes_after_the_client_hello_pass_through_unchanged() {
        let message = client_hello(80);
        let mut input = handshake_record([3, 3], &message);
        let tail = b"later application bytes";
        input.extend_from_slice(tail);
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::Reframed);
        let (payload, records, _) = parse(&chunks[..chunks.len() - 1]);
        assert_eq!(payload, message);
        assert!(records > 1);
        assert_eq!(chunks.last().unwrap(), tail);
    }

    #[test]
    fn data_after_the_first_flow_is_never_reshaped() {
        let message = client_hello(64);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(&input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::Reframed);
        chunks.clear();
        let later: &[u8] = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        shaper
            .feed(later, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks, vec![later.to_vec()]);
        // A second ClientHello on the same flow is not reshaped either.
        chunks.clear();
        let second = handshake_record([3, 3], &client_hello(100));
        shaper
            .feed(&second, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks, vec![second]);
    }

    #[test]
    fn non_tls_input_passes_through() {
        let input = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let (chunks, state) = run(input);
        assert_eq!(state, ShapeState::PassThrough);
        assert_eq!(chunks, vec![input.to_vec()]);
    }

    #[test]
    fn a_first_write_that_cannot_be_tls_passes_through_at_once() {
        // A short request/response protocol sends one to four bytes and then
        // waits. Each of these is impossible as a TLS record at byte 0 or
        // byte 1, so the shaper must emit it in the same call.
        let cases: [&[u8]; 8] = [
            b"P",
            b"PI",
            b"PIN",
            b"PING",
            b"ls\n",
            b"GET ",
            &[5, 1, 0],
            &[22, 4],
        ];
        for input in cases {
            let (chunks, state) = run(input);
            assert_eq!(state, ShapeState::PassThrough, "input {input:?}");
            assert_eq!(
                chunks.len(),
                1,
                "input {input:?} must not wait for more bytes"
            );
            assert_eq!(chunks.concat(), input, "every byte is preserved");
        }
    }

    #[test]
    fn every_split_of_a_short_protocol_is_forwarded_without_a_stall() {
        for len in 1..=4 {
            let input = &b"PING"[..len];
            for split in 0..=len {
                let (chunks, state) = feed_parts(&[&input[..split], &input[split..]]);
                assert_eq!(state, ShapeState::PassThrough, "len {len} split {split}");
                assert_eq!(
                    chunks.concat(),
                    input,
                    "len {len} split {split} preserves every byte"
                );
            }
        }
    }

    #[test]
    fn a_tls_major_version_other_than_three_decides_at_byte_one() {
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(&[CONTENT_HANDSHAKE], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty(), "one ambiguous byte is held");
        assert_eq!(shaper.state(), ShapeState::Buffering);
        shaper
            .feed(&[4], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        assert_eq!(chunks.concat(), vec![CONTENT_HANDSHAKE, 4]);
        chunks.clear();
        shaper
            .feed(b"rest", &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks, vec![b"rest".to_vec()]);
    }

    #[test]
    fn a_handshake_type_other_than_client_hello_decides_before_the_record_ends() {
        // A valid handshake header that declares 16 KiB of payload, then the
        // first payload byte. That byte is the message type. It is not 1, so
        // the record can never become a ClientHello.
        let header = [CONTENT_HANDSHAKE, 3, 3, 0x40, 0x00];
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(&header, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty(), "the record payload has not arrived");
        assert_eq!(shaper.state(), ShapeState::Buffering);
        shaper
            .feed(&[2], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        let mut expected = header.to_vec();
        expected.push(2);
        assert_eq!(chunks.concat(), expected);
    }

    #[test]
    fn a_declared_client_hello_length_is_checked_before_the_record_ends() {
        // A handshake record that declares 16 KiB but starts a type 1 message
        // with length 0. That message is below the minimum, so it passes
        // through without waiting for the rest of the record.
        let prefix = [
            CONTENT_HANDSHAKE,
            3,
            3,
            0x40,
            0x00,
            HANDSHAKE_CLIENT_HELLO,
            0,
            0,
            0,
        ];
        let (chunks, state) = run(&prefix);
        assert_eq!(state, ShapeState::PassThrough);
        assert_eq!(chunks.concat(), prefix);
    }

    #[test]
    fn a_header_split_into_every_field_still_reassembles() {
        let message = client_hello(90);
        let input = handshake_record([3, 3], &message);
        let parts: [&[u8]; 6] = [
            &input[..1],
            &input[1..2],
            &input[2..3],
            &input[3..5],
            &input[5..6],
            &input[6..],
        ];
        let (chunks, state) = feed_parts(&parts);
        assert_eq!(state, ShapeState::Reframed);
        let (payload, _, _) = parse(&chunks);
        assert_eq!(payload, message);
    }

    #[test]
    fn leftover_records_count_toward_the_write_cap() {
        // Ten small records carry a 39 byte ClientHello at the default chunk
        // size. One more record carries the bytes after it in the same TLS
        // record, so the written count is 11. A cap of 10 must pass the whole
        // flow through before any record is written.
        let message = client_hello(35);
        let mut payload = message.clone();
        payload.resize(MAX_TLS_RECORD_PAYLOAD, 0);
        let input = handshake_record([3, 3], &payload);
        let limits = ShapeLimits {
            max_records: 10,
            ..ShapeLimits::default()
        };
        let mut shaper = ClientHelloShaper::new(limits).unwrap();
        let mut chunks = Vec::new();
        shaper
            .feed(&input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn a_tls_record_that_is_not_a_client_hello_passes_through() {
        // Content type 23 is application data.
        let mut input = vec![23, 3, 3, 0, 4];
        input.extend_from_slice(b"data");
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn a_handshake_record_that_is_not_a_client_hello_passes_through() {
        let mut message = vec![2u8, 0, 0, 40];
        message.extend_from_slice(&[7; 40]);
        let input = handshake_record([3, 3], &message);
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn a_zero_length_or_oversize_record_passes_through() {
        for input in [
            vec![CONTENT_HANDSHAKE, 3, 3, 0, 0],
            vec![CONTENT_HANDSHAKE, 3, 3, 0x40, 0x01],
        ] {
            let (chunks, state) = run(&input);
            assert_eq!(state, ShapeState::PassThrough);
            assert_eq!(chunks, vec![input]);
        }
    }

    #[test]
    fn a_record_with_another_major_version_passes_through() {
        let input = vec![CONTENT_HANDSHAKE, 2, 3, 0, 0x04, 1, 0, 0, 0];
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn a_client_hello_above_the_cap_passes_through() {
        let message = client_hello(20 * 1024);
        let input = handshake_record([3, 1], &message);
        let (chunks, state) = run(&input);
        assert_eq!(state, ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn a_record_count_above_the_limit_passes_through() {
        let limits = ShapeLimits {
            max_chunk: 1,
            max_records: 8,
            ..ShapeLimits::default()
        };
        let message = client_hello(100);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::new(limits).unwrap();
        let mut chunks = Vec::new();
        shaper
            .feed(&input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn an_incomplete_client_hello_emits_nothing_and_stays_bounded() {
        let message = client_hello(2000);
        let mut input = handshake_record([3, 1], &message[..100]);
        // Declare the full length but send only a fragment.
        input[6..9].copy_from_slice(&(message.len() as u32).to_be_bytes()[1..]);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(&input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty());
        assert_eq!(shaper.state(), ShapeState::Buffering);
        assert!(shaper.buffered() <= ShapeLimits::default().max_buffered);
    }

    #[test]
    fn a_buffer_above_the_cap_passes_through_unchanged() {
        let limits = ShapeLimits {
            max_buffered: MIN_CLIENT_HELLO_MESSAGE + 16,
            max_client_hello: MIN_CLIENT_HELLO_MESSAGE + 16,
            ..ShapeLimits::default()
        };
        let mut shaper = ClientHelloShaper::new(limits).unwrap();
        let mut input = vec![CONTENT_HANDSHAKE, 3, 3, 0x40, 0x00];
        input.extend_from_slice(&[0u8; 64 * 1024]);
        let mut chunks = Vec::new();
        shaper
            .feed(&input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        assert_eq!(chunks, vec![input]);
    }

    #[test]
    fn invalid_limits_are_rejected() {
        for limits in [
            ShapeLimits {
                max_chunk: 0,
                ..ShapeLimits::default()
            },
            ShapeLimits {
                max_chunk: 9,
                ..ShapeLimits::default()
            },
            ShapeLimits {
                max_client_hello: 8,
                ..ShapeLimits::default()
            },
            ShapeLimits {
                max_records: 0,
                ..ShapeLimits::default()
            },
            ShapeLimits {
                max_buffered: 16,
                ..ShapeLimits::default()
            },
        ] {
            assert!(ClientHelloShaper::new(limits).is_err());
        }
    }

    #[test]
    fn records_for_counts_the_cycle() {
        assert_eq!(records_for(0, 8), 0);
        assert_eq!(records_for(1, 8), 1);
        assert_eq!(records_for(3, 8), 2); // 1 + 2
        assert_eq!(records_for(6, 8), 3); // 1 + 2 + 3
        assert_eq!(records_for(37, 8), 9); // 1 + 2 + ... + 8 = 36, then 1
        assert_eq!(records_for(5, 1), 5);
    }

    #[test]
    fn a_sink_error_is_returned() {
        let message = client_hello(100);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let error = shaper
            .feed(&input, &mut |_| {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "no reader"))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn a_sink_error_makes_the_shaper_terminal() {
        let message = client_hello(200);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let error = shaper
            .feed(&input, &mut |_| {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "no reader"))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(shaper.state(), ShapeState::Failed);
        assert_eq!(shaper.buffered(), 0, "a failed shaper holds no bytes");
        // Before this was terminal, the stale record offset made the next
        // feed subtract more than the buffer held and panic.
        let mut chunks = Vec::new();
        let again = shaper.feed(b"more bytes", &mut |chunk| {
            chunks.push(chunk.to_vec());
            Ok(())
        });
        assert_eq!(again.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(chunks.is_empty(), "a failed shaper emits nothing more");
        // finish reports the terminal failure and cannot release bytes again.
        let finish_error = shaper
            .finish(&mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap_err();
        assert_eq!(finish_error.kind(), io::ErrorKind::BrokenPipe);
        assert!(chunks.is_empty());
        assert_eq!(shaper.state(), ShapeState::Failed);
    }

    #[test]
    fn a_sink_error_after_reframing_is_terminal() {
        let message = client_hello(64);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::with_default_limits();
        shaper.feed(&input, &mut |_| Ok(())).unwrap();
        assert_eq!(shaper.state(), ShapeState::Reframed);
        let error = shaper
            .feed(b"later", &mut |_| {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "no reader"))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(shaper.state(), ShapeState::Failed);
        assert_eq!(shaper.buffered(), 0, "a failed shaper holds no bytes");
        let mut chunks = Vec::new();
        let again = shaper.feed(b"more", &mut |chunk| {
            chunks.push(chunk.to_vec());
            Ok(())
        });
        assert_eq!(again.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(chunks.is_empty());
    }

    #[test]
    fn a_sink_error_during_pass_through_is_terminal() {
        let input = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut shaper = ClientHelloShaper::with_default_limits();
        assert!(shaper
            .feed(input, &mut |_| Err(io::Error::from(
                io::ErrorKind::BrokenPipe
            )))
            .is_err());
        assert_eq!(shaper.state(), ShapeState::Failed);
        assert_eq!(shaper.buffered(), 0);
        assert!(shaper.feed(b"x", &mut |_| Ok(())).is_err());
    }

    #[test]
    fn finish_releases_an_incomplete_client_hello_unchanged_once() {
        let message = client_hello(200);
        let input = handshake_record([3, 1], &message);
        let partial = &input[..40];
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(partial, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty(), "an incomplete record emits nothing");
        assert_eq!(shaper.buffered(), partial.len());
        shaper
            .finish(&mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            chunks,
            vec![partial.to_vec()],
            "every held byte is released"
        );
        assert_eq!(shaper.buffered(), 0);
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        // Exactly once. A repeat emits nothing, and later bytes pass through.
        chunks.clear();
        shaper
            .finish(&mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty(), "finish never releases a second copy");
        shaper
            .feed(b"later", &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks, vec![b"later".to_vec()]);
    }

    #[test]
    fn finish_after_a_reframed_hello_emits_nothing() {
        let message = client_hello(64);
        let input = handshake_record([3, 1], &message);
        let mut shaper = ClientHelloShaper::with_default_limits();
        let mut chunks = Vec::new();
        shaper
            .feed(&input, &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        chunks.clear();
        shaper
            .finish(&mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty());
        assert_eq!(shaper.state(), ShapeState::Reframed);
    }

    #[test]
    fn finish_with_nothing_buffered_emits_nothing() {
        let mut shaper = ClientHelloShaper::with_default_limits();
        shaper
            .finish(&mut |_| panic!("nothing to release"))
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        // A repeat is still a no-op.
        shaper
            .finish(&mut |_| panic!("nothing to release"))
            .unwrap();
    }

    #[test]
    fn a_complete_client_hello_with_a_large_tail_is_reframed_in_one_feed() {
        // Regression: the raw cap used to be checked before parsing. A
        // 64-byte ClientHello plus a 200-byte tail in one read exceeded the
        // 100-byte cap and passed through unchanged. Split at the end of the
        // ClientHello, the same bytes were reframed.
        let limits = ShapeLimits {
            max_client_hello: 100,
            max_buffered: 100,
            ..ShapeLimits::default()
        };
        let message = client_hello(60);
        assert_eq!(message.len(), 64);
        let mut input = handshake_record([3, 3], &message);
        let boundary = input.len();
        let tail: Vec<u8> = (0..200).map(|index| (index % 251) as u8).collect();
        input.extend_from_slice(&tail);
        assert!(input.len() > limits.max_buffered);

        let (whole, whole_state) = feed_parts_with_limits(limits, &[&input]);
        assert_eq!(whole_state, ShapeState::Reframed);
        let (split, split_state) =
            feed_parts_with_limits(limits, &[&input[..boundary], &input[boundary..]]);
        assert_eq!(split_state, whole_state);
        assert_eq!(split, whole);
        // No split may change the path or the carried bytes.
        for split in 0..=input.len() {
            let (chunks, state) =
                feed_parts_with_limits(limits, &[&input[..split], &input[split..]]);
            assert_eq!(state, whole_state, "split {split}");
            assert_eq!(chunks.concat(), whole.concat(), "split {split}");
        }

        // Feeding one byte at a time takes the same path and emits the same
        // bytes, even though no single feed crosses the cap.
        let bytes: Vec<[u8; 1]> = input.iter().map(|byte| [*byte]).collect();
        let parts: Vec<&[u8]> = bytes.iter().map(|part| part.as_slice()).collect();
        let (dripped, dripped_state) = feed_parts_with_limits(limits, &parts);
        assert_eq!(dripped_state, whole_state);
        // A one-byte feed emits the tail one byte per call, so compare the
        // carried bytes, not the chunk boundaries.
        assert_eq!(dripped.concat(), whole.concat());

        let (payload, records, largest) = parse(&whole[..whole.len() - 1]);
        assert_eq!(payload, message, "the ClientHello bytes are unchanged");
        assert!(records > 1);
        assert!(largest <= 8);
        assert_eq!(whole.last().unwrap(), &tail, "the tail is unchanged");
        assert_eq!(logical_bytes(&whole.concat()), logical_bytes(&input));
    }

    #[test]
    fn a_full_size_client_hello_in_small_records_is_reframed_with_a_large_tail() {
        // The default limits. A 16 KiB ClientHello split into 4096 records of
        // four payload bytes is 36,864 raw bytes. A 31,006-byte tail pushes
        // one feed past the 64 KiB raw cap. Parsing first must still reframe
        // when the whole message arrives in that feed.
        let message = client_hello(16 * 1024 - 4);
        assert_eq!(message.len(), 16 * 1024);
        let mut input = records_of([3, 3], &message, 4);
        assert_eq!(input.len(), 4096 * 9);
        let boundary = input.len();
        let tail: Vec<u8> = (0..31_006).map(|index| (index % 251) as u8).collect();
        input.extend_from_slice(&tail);
        let limits = ShapeLimits::default();
        assert!(input.len() > limits.max_buffered);

        let (whole, whole_state) = feed_parts_with_limits(limits, &[&input]);
        assert_eq!(whole_state, ShapeState::Reframed);

        // Split exactly at the end of the ClientHello.
        let (at_boundary, at_boundary_state) =
            feed_parts_with_limits(limits, &[&input[..boundary], &input[boundary..]]);
        assert_eq!(at_boundary_state, whole_state);
        assert_eq!(at_boundary, whole);

        // The last ClientHello byte and the whole tail in one read.
        let last_hello = boundary - 1;
        let (joined, joined_state) =
            feed_parts_with_limits(limits, &[&input[..last_hello], &input[last_hello..]]);
        assert_eq!(joined_state, whole_state);
        assert_eq!(joined, whole);

        let (payload, records, largest) = parse(&whole[..whole.len() - 1]);
        assert_eq!(payload, message, "the ClientHello bytes are unchanged");
        assert!(records > 1);
        assert!(largest <= 8);
        assert_eq!(whole.last().unwrap(), &tail, "the tail is unchanged");
        assert_eq!(logical_bytes(&whole.concat()), logical_bytes(&input));
    }

    #[test]
    fn a_flow_that_still_needs_more_passes_through_when_the_cap_is_exceeded() {
        let limits = ShapeLimits {
            max_client_hello: 100,
            max_buffered: 100,
            ..ShapeLimits::default()
        };
        let message = client_hello(80);
        let input = records_of([3, 3], &message, 1);
        let mut shaper = ClientHelloShaper::new(limits).unwrap();
        let mut chunks = Vec::new();
        // Sixteen complete one-byte records are 96 bytes. Four header bytes
        // reach the cap exactly and still wait for more.
        shaper
            .feed(&input[..100], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert!(chunks.is_empty());
        assert_eq!(shaper.state(), ShapeState::Buffering);
        assert_eq!(shaper.buffered(), 100);
        // One more byte crosses the cap while the message still needs bytes.
        shaper
            .feed(&input[100..101], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(shaper.state(), ShapeState::PassThrough);
        assert_eq!(chunks, vec![input[..101].to_vec()]);
        shaper
            .feed(&input[101..], &mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        shaper
            .finish(&mut |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks.concat(), input, "the cap path conserves every byte");
    }

    #[test]
    fn a_sink_error_on_the_tail_of_a_reframed_hello_is_terminal() {
        let limits = ShapeLimits {
            max_client_hello: 100,
            max_buffered: 100,
            ..ShapeLimits::default()
        };
        let message = client_hello(60);
        let mut input = handshake_record([3, 3], &message);
        let tail = vec![7u8; 200];
        input.extend_from_slice(&tail);
        let mut shaper = ClientHelloShaper::new(limits).unwrap();
        let error = shaper
            .feed(&input, &mut |chunk| {
                if chunk == tail.as_slice() {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "no reader"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(shaper.state(), ShapeState::Failed);
        assert_eq!(shaper.buffered(), 0, "a failed shaper holds no bytes");
        let mut chunks = Vec::new();
        let again = shaper.feed(b"later", &mut |chunk| {
            chunks.push(chunk.to_vec());
            Ok(())
        });
        assert_eq!(again.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(chunks.is_empty());
    }

    #[test]
    fn an_invalid_length_split_across_records_is_rejected_without_the_whole_record() {
        let limits = ShapeLimits {
            max_client_hello: 100,
            max_buffered: 100,
            ..ShapeLimits::default()
        };
        // The first record carries only the message type. The second record
        // declares a large payload, but only its three handshake length bytes
        // arrive. The declared length is invalid in both directions.
        for length in [[0x01, 0x00, 0x00], [0x00, 0x00, 0x00]] {
            let mut input = handshake_record([3, 3], &[HANDSHAKE_CLIENT_HELLO]);
            input.extend_from_slice(&[CONTENT_HANDSHAKE, 3, 3, 0x03, 0xE8]);
            input.extend_from_slice(&length);
            let mut shaper = ClientHelloShaper::new(limits).unwrap();
            let mut chunks = Vec::new();
            shaper
                .feed(&input, &mut |chunk| {
                    chunks.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap();
            assert_eq!(shaper.state(), ShapeState::PassThrough, "length {length:?}");
            assert_eq!(chunks.concat(), input, "length {length:?}");
            // The pass-through is already decided, so the rest is not needed.
            shaper
                .feed(b"rest", &mut |chunk| {
                    chunks.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                chunks.concat(),
                [input.as_slice(), b"rest".as_slice()].concat(),
                "length {length:?}"
            );
        }
    }

    #[test]
    fn a_handshake_header_split_across_records_is_checked_at_every_split() {
        let message = client_hello(60);
        let mut input = handshake_record([3, 3], &message[..1]);
        let boundary = input.len();
        input.extend_from_slice(&handshake_record([3, 3], &message[1..]));
        let header_end = boundary + 5 + 3;
        let (whole, whole_state) = run(&input);
        assert_eq!(whole_state, ShapeState::Reframed);
        for split in [
            1,
            5,
            boundary,
            boundary + 1,
            boundary + 4,
            header_end,
            header_end + 1,
            input.len(),
        ] {
            let (chunks, state) = feed_parts(&[&input[..split], &input[split..]]);
            assert_eq!(state, whole_state, "split {split}");
            // An empty part emits an empty chunk, so compare carried bytes.
            assert_eq!(chunks.concat(), whole.concat(), "split {split}");
        }
        let (payload, _, largest) = parse(&whole);
        assert_eq!(payload, message);
        assert!(largest <= 8);
    }
}
