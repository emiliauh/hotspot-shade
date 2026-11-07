//! One pairing handoff from the user-owned engine to the protected engine.
//!
//! The macOS app runs its engine as the signed-in user. That engine holds the
//! long-term pairing identity and the source device proxy credentials in
//! process memory. When a person turns the tunnel on, a root-owned engine must
//! change the routes. Starting a new engine without the pairing would lose the
//! source device trust that the person already granted.
//!
//! The user engine writes the identity and the credentials into a private
//! descriptor. The app holds the read end and passes it to the protected helper
//! over XPC. The helper passes it to the root engine as an inherited descriptor.
//! The root engine reads the newest complete frame before it binds its listener.
//! The token never enters the app process, a browser, a status answer, a log
//! line, or a command line. A cancelled start can leave an older frame queued;
//! the root engine uses the newest frame and ignores the older copy.
//!
//! The frame carries no key schedule change. The X25519 identity is the same
//! key, and the source device sees the same public key after the handoff.

use std::io;
#[cfg(test)]
use std::io::Read;
use std::os::fd::RawFd;

use zeroize::Zeroizing;

use crate::pairing::{Identity, PhoneCredentials};

/// The frame marker. A wrong value is not a handoff from this build.
const MAGIC: [u8; 4] = *b"HSC1";
/// The fixed part: magic, identity secret, identity public, IPv4 host, port,
/// and the token length.
const HEADER_BYTES: usize = 4 + 32 + 32 + 4 + 2 + 2;
/// A source device token is 1 to 255 printable ASCII bytes, the same bound as
/// the pairing result. The bound also keeps a malformed frame from making the
/// root engine allocate an arbitrary buffer. The frame keeps its two-byte
/// length field.
pub const MAX_TOKEN_BYTES: usize = 255;

/// True when the port and token match the limits that pairing accepts: the
/// port is 1024 to 65535 and is not the pairing port, and the token is 1 to
/// [`MAX_TOKEN_BYTES`] printable ASCII bytes.
fn usable_credentials(port: u16, token: &[u8]) -> bool {
    port >= 1024
        && port != crate::pairing::PAIRING_PORT
        && !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.iter().all(u8::is_ascii_graphic)
}

/// Why a handoff frame could not be used. The messages are fixed and carry no
/// token, key, address, or descriptor number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    /// The descriptor could not be read or written.
    Io,
    /// The frame marker, length, or public key is wrong.
    Malformed,
}

impl HandoffError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Io => "The pairing handoff failed.",
            Self::Malformed => "The pairing handoff is not valid.",
        }
    }
}

/// Write one handoff frame. The caller passes the write end of a private pipe
/// and closes it after this call. The token and the identity bytes live in
/// zeroizing buffers and are cleared before the function returns.
pub fn write_handoff(
    descriptor: RawFd,
    identity: &Identity,
    credentials: &PhoneCredentials,
) -> Result<(), HandoffError> {
    if descriptor < 0 {
        return Err(HandoffError::Io);
    }
    // A root engine that exits before this write must produce EPIPE, not end
    // the user engine that serves the dashboard.
    #[cfg(target_os = "macos")]
    unsafe {
        libc::fcntl(descriptor, libc::F_SETNOSIGPIPE, 1);
    }
    let token = credentials.token.as_bytes();
    // Refuse a frame that the root engine would refuse. The check uses the
    // same limits as the read side.
    if !usable_credentials(credentials.port, token) {
        return Err(HandoffError::Malformed);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + token.len()));
    frame.extend_from_slice(&MAGIC);
    let mut secret = Zeroizing::new(identity.secret_bytes());
    frame.extend_from_slice(&secret[..]);
    frame.extend_from_slice(&identity.public());
    frame.extend_from_slice(&credentials.host.octets());
    frame.extend_from_slice(&credentials.port.to_be_bytes());
    frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
    frame.extend_from_slice(token);
    secret.fill(0);
    write_all(descriptor, &frame)
}

/// Read one handoff frame. The descriptor can stay open for a later handoff
/// from the same user engine, so this reads exactly one frame and does not wait
/// for end of file. The caller owns the descriptor and closes its copy.
pub fn read_handoff(descriptor: RawFd) -> Result<(Identity, PhoneCredentials), HandoffError> {
    if descriptor < 0 {
        return Err(HandoffError::Io);
    }
    let mut header = Zeroizing::new([0u8; HEADER_BYTES]);
    read_exact(descriptor, &mut header[..])?;
    if header[0..4] != MAGIC {
        return Err(HandoffError::Malformed);
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&header[4..36]);
    let mut public = [0u8; 32];
    public.copy_from_slice(&header[36..68]);
    let host = [header[68], header[69], header[70], header[71]];
    let port = u16::from_be_bytes([header[72], header[73]]);
    let token_len = u16::from_be_bytes([header[74], header[75]]) as usize;
    if token_len == 0 || token_len > MAX_TOKEN_BYTES {
        return Err(HandoffError::Malformed);
    }
    // Read the whole token before any value check, so a refused frame does
    // not leave its token bytes queued for the next read.
    let mut token = Zeroizing::new(vec![0u8; token_len]);
    read_exact(descriptor, &mut token[..])?;
    // The identity takes its own copy, and that copy is cleared when the
    // identity drops. The local copy in `secret` is cleared on return.
    let identity = Identity::from_bytes(*secret);
    secret.fill(0);
    if identity.public() != public {
        return Err(HandoffError::Malformed);
    }
    if !usable_credentials(port, &token) {
        return Err(HandoffError::Malformed);
    }
    let text = std::str::from_utf8(&token).map_err(|_| HandoffError::Malformed)?;
    // `PhoneCredentials` clears its token when it drops. The zeroizing buffer
    // clears the frame copy here.
    let credentials = PhoneCredentials {
        host: std::net::Ipv4Addr::from(host),
        port,
        token: text.to_owned(),
    };
    Ok((identity, credentials))
}

/// Read the newest handoff frame that is already queued, and discard older
/// frames from an earlier cancelled or failed start. The app writes one frame
/// before it asks the helper for an engine, so the frames are complete when
/// this runs. The descriptor must not block: an empty channel is a failed
/// launch, not a wait for a future pairing.
pub fn read_latest_handoff(
    descriptor: RawFd,
) -> Result<(Identity, PhoneCredentials), HandoffError> {
    if descriptor < 0 {
        return Err(HandoffError::Io);
    }
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(HandoffError::Io);
    }
    let mut latest = None;
    loop {
        let mut available: libc::c_int = 0;
        if unsafe { libc::ioctl(descriptor, libc::FIONREAD, &mut available) } < 0 || available <= 0
        {
            break;
        }
        match read_handoff(descriptor) {
            Ok(value) => latest = Some(value),
            Err(HandoffError::Io)
                if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock =>
            {
                break
            }
            Err(error) => return Err(error),
        }
    }
    latest.ok_or(HandoffError::Malformed)
}

fn read_exact(descriptor: RawFd, mut buffer: &mut [u8]) -> Result<(), HandoffError> {
    while !buffer.is_empty() {
        match read_once(descriptor, buffer) {
            Ok(0) => return Err(HandoffError::Malformed),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(HandoffError::Io),
        }
    }
    Ok(())
}

fn read_once(descriptor: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let count = unsafe {
        libc::read(
            descriptor,
            buffer.as_mut_ptr().cast(),
            buffer.len() as libc::size_t,
        )
    };
    if count >= 0 {
        Ok(count as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn write_all(descriptor: RawFd, mut buffer: &[u8]) -> Result<(), HandoffError> {
    while !buffer.is_empty() {
        let count = unsafe {
            libc::write(
                descriptor,
                buffer.as_ptr().cast(),
                buffer.len() as libc::size_t,
            )
        };
        if count > 0 {
            buffer = &buffer[count as usize..];
            continue;
        }
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(HandoffError::Io);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    fn identity() -> Identity {
        Identity::from_bytes([0x42; 32])
    }

    fn credentials() -> PhoneCredentials {
        PhoneCredentials {
            host: std::net::Ipv4Addr::new(172, 20, 10, 1),
            port: 18080,
            token: "public-test-token".into(),
        }
    }

    fn raw_pair() -> (RawFd, RawFd) {
        let (writer, reader) = UnixStream::pair().unwrap();
        (writer.into_raw_fd(), reader.into_raw_fd())
    }

    fn read_all(descriptor: RawFd) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut file =
            unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(descriptor) };
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn feed(bytes: &[u8]) -> RawFd {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let read_fd = reader.into_raw_fd();
        writer.write_all(bytes).unwrap();
        drop(writer);
        read_fd
    }

    fn close(descriptor: RawFd) {
        unsafe {
            libc::close(descriptor);
        }
    }

    #[test]
    fn round_trips_one_identity_and_credential_set() {
        let (write_fd, read_fd) = raw_pair();
        write_handoff(write_fd, &identity(), &credentials()).unwrap();
        close(write_fd);
        let (imported, imported_credentials) = read_handoff(read_fd).unwrap();
        close(read_fd);
        assert_eq!(imported.public(), identity().public());
        assert_eq!(imported_credentials.host, credentials().host);
        assert_eq!(imported_credentials.port, 18080);
        assert_eq!(imported_credentials.token, "public-test-token");
        assert!(!format!("{imported_credentials:?}").contains("public-test-token"));
    }

    #[test]
    fn rejects_a_frame_with_a_wrong_marker() {
        let (write_fd, read_fd) = raw_pair();
        write_handoff(write_fd, &identity(), &credentials()).unwrap();
        close(write_fd);
        let mut bytes = read_all(read_fd);
        bytes[0] = b'X';
        let read_fd = feed(&bytes);
        assert!(matches!(
            read_handoff(read_fd),
            Err(HandoffError::Malformed)
        ));
        close(read_fd);
    }

    #[test]
    fn rejects_a_truncated_or_oversized_token() {
        let (write_fd, read_fd) = raw_pair();
        write_handoff(write_fd, &identity(), &credentials()).unwrap();
        close(write_fd);
        let mut bytes = read_all(read_fd);
        // A token length that no frame can satisfy.
        bytes[74] = 0x7f;
        bytes[75] = 0xff;
        let read_fd = feed(&bytes);
        assert!(matches!(
            read_handoff(read_fd),
            Err(HandoffError::Malformed)
        ));
        close(read_fd);
    }

    #[test]
    fn rejects_a_public_key_that_does_not_match_the_secret() {
        let (write_fd, read_fd) = raw_pair();
        write_handoff(write_fd, &identity(), &credentials()).unwrap();
        close(write_fd);
        let mut bytes = read_all(read_fd);
        bytes[36] ^= 0x01;
        let read_fd = feed(&bytes);
        assert!(matches!(
            read_handoff(read_fd),
            Err(HandoffError::Malformed)
        ));
        close(read_fd);
    }

    /// Build a frame by hand, so a test can send values that the write side
    /// refuses.
    fn forged_frame(port: u16, token: &[u8]) -> Vec<u8> {
        let identity = identity();
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&identity.secret_bytes());
        frame.extend_from_slice(&identity.public());
        frame.extend_from_slice(&[172, 20, 10, 1]);
        frame.extend_from_slice(&port.to_be_bytes());
        frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
        frame.extend_from_slice(token);
        frame
    }

    fn read_forged(port: u16, token: &[u8]) -> Result<(Identity, PhoneCredentials), HandoffError> {
        let read_fd = feed(&forged_frame(port, token));
        let result = read_handoff(read_fd);
        close(read_fd);
        result
    }

    #[test]
    fn the_frame_uses_the_pairing_port_and_token_limits() {
        let longest = "t".repeat(MAX_TOKEN_BYTES);
        for (port, token) in [
            (1024, "public-test-token"),
            (65535, "public-test-token"),
            (18080, longest.as_str()),
            (18080, "!~"),
        ] {
            let (imported, credentials) =
                read_forged(port, token.as_bytes()).expect("a frame inside the pairing limits");
            assert_eq!(imported.public(), identity().public());
            assert_eq!(credentials.port, port);
            assert_eq!(credentials.token, token);
        }
        let too_long = "t".repeat(MAX_TOKEN_BYTES + 1);
        for (port, token) in [
            (0, b"public-test-token".as_slice()),
            (80, b"public-test-token".as_slice()),
            (1023, b"public-test-token".as_slice()),
            (
                crate::pairing::PAIRING_PORT,
                b"public-test-token".as_slice(),
            ),
            (18080, b"".as_slice()),
            (18080, b"has space".as_slice()),
            (18080, b"tab\there".as_slice()),
            (18080, b"line\nbreak".as_slice()),
            (18080, b"nul\0byte".as_slice()),
            (18080, "caf\u{e9}".as_bytes()),
            (18080, b"\xff\xfe".as_slice()),
            (18080, too_long.as_bytes()),
        ] {
            assert!(
                matches!(read_forged(port, token), Err(HandoffError::Malformed)),
                "port {port} token length {}",
                token.len()
            );
            // The write side refuses the same values, so the user engine never
            // queues a frame that the root engine would refuse.
            if let Ok(text) = std::str::from_utf8(token) {
                let (write_fd, read_fd) = raw_pair();
                let refused = PhoneCredentials {
                    host: std::net::Ipv4Addr::new(172, 20, 10, 1),
                    port,
                    token: text.into(),
                };
                assert!(matches!(
                    write_handoff(write_fd, &identity(), &refused),
                    Err(HandoffError::Malformed)
                ));
                close(write_fd);
                assert!(
                    read_all(read_fd).is_empty(),
                    "a refused frame writes nothing"
                );
            }
        }
    }

    #[test]
    fn a_refused_token_does_not_stay_queued_for_the_next_read() {
        // The bad frame is read in full before the check, so the next frame
        // starts at its own marker.
        let mut bytes = forged_frame(18080, b"has space");
        bytes.extend_from_slice(&forged_frame(18080, b"public-test-token"));
        let read_fd = feed(&bytes);
        assert!(matches!(
            read_handoff(read_fd),
            Err(HandoffError::Malformed)
        ));
        let (_, next) = read_handoff(read_fd).expect("the next frame is intact");
        assert_eq!(next.token, "public-test-token");
        close(read_fd);
    }

    #[test]
    fn rejects_a_missing_descriptor() {
        assert!(matches!(read_handoff(-1), Err(HandoffError::Io)));
    }

    #[test]
    fn the_latest_frame_wins_after_a_cancelled_start() {
        let (write_fd, read_fd) = raw_pair();
        let mut old = credentials();
        old.token = "old-test-token".into();
        write_handoff(write_fd, &identity(), &old).unwrap();
        write_handoff(write_fd, &identity(), &credentials()).unwrap();
        let (_, latest) = read_latest_handoff(read_fd).unwrap();
        assert_eq!(latest.token, "public-test-token");
        // The channel is empty after the drain. A later launch must not reuse
        // the old frame.
        assert!(matches!(
            read_latest_handoff(read_fd),
            Err(HandoffError::Malformed)
        ));
        close(write_fd);
        close(read_fd);
    }

    #[test]
    fn an_empty_channel_is_a_failed_launch() {
        let (write_fd, read_fd) = raw_pair();
        assert!(matches!(
            read_latest_handoff(read_fd),
            Err(HandoffError::Malformed)
        ));
        close(write_fd);
        close(read_fd);
    }

    #[test]
    fn a_closed_writer_still_delivers_the_queued_frame() {
        let (write_fd, read_fd) = raw_pair();
        write_handoff(write_fd, &identity(), &credentials()).unwrap();
        close(write_fd);
        let (_, latest) = read_latest_handoff(read_fd).unwrap();
        assert_eq!(latest.token, "public-test-token");
        close(read_fd);
    }
}
