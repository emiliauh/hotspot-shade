//! One pairing handoff from the standard-user Windows engine to the elevated
//! Windows engine.
//!
//! A person pairs in the engine that runs as the signed-in user, so pairing
//! needs no administrator prompt. A tunnel start needs an elevated engine.
//! Starting that engine without the pairing would lose the source device trust
//! that the person already granted. The launcher therefore gives the user
//! engine the write end of a private anonymous pipe with `--handoff-fd N`, and
//! gives the elevated engine the read end with `--credentials-fd N`. The user
//! engine writes one frame on `POST /api/pairing/handoff`. The elevated engine
//! reads the newest complete frame before it binds its listener.
//!
//! The frame is the `HSC1` frame of `credential_handoff.rs` on macOS and
//! Linux: magic, identity secret, identity public key, IPv4 host, port, token
//! length, and token. The limits are the pairing limits: port 1024 to 65535
//! and not 18090, and a token of 1 to 255 printable ASCII bytes. The token and
//! the identity bytes live in zeroizing buffers. No status answer, log line,
//! error text, or Debug output holds them.
//!
//! The handle numbers are not secrets. Each handle must be a pipe, must not
//! name the same kernel object as the token or parent handle, and has its
//! inherit flag cleared before any child process starts. The check proves that
//! the handle names a pipe object rather than a socket, file, or console, and
//! that the credentials end can read. It does not prove that the pipe is
//! anonymous, private, or the end that the launcher meant to pass, so the
//! launcher still owns that part. A pipe write blocks when the pipe buffer is
//! full, so the launcher must read the frame or close its end. The default pipe
//! buffer holds several frames.

use crate::pairing::{Identity, PhoneCredentials, PAIRING_PORT};
use zeroize::Zeroizing;

/// The frame marker. A wrong value is not a handoff from this build.
const MAGIC: [u8; 4] = *b"HSC1";
/// Magic, identity secret, identity public key, IPv4 host, port, token length.
const HEADER_BYTES: usize = 4 + 32 + 32 + 4 + 2 + 2;
/// The largest token that pairing accepts.
pub const MAX_TOKEN_BYTES: usize = 255;
/// The largest number of queued bytes that the elevated engine reads. A
/// launcher that retries a start can queue a few frames; more than this is a
/// malformed channel.
#[cfg(any(windows, test))]
const MAX_QUEUED_BYTES: usize = 64 * (HEADER_BYTES + MAX_TOKEN_BYTES);

/// Why a handoff frame could not be used. The messages are fixed and carry no
/// token, key, address, or handle number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    /// The handle could not be read or written.
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

fn usable_credentials(port: u16, token: &[u8]) -> bool {
    port >= 1024
        && port != PAIRING_PORT
        && !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.iter().all(u8::is_ascii_graphic)
}

/// Build one frame. The caller writes it and drops it, which clears it.
pub fn encode_frame(
    identity: &Identity,
    credentials: &PhoneCredentials,
) -> Result<Zeroizing<Vec<u8>>, HandoffError> {
    let token = credentials.token.as_bytes();
    if !usable_credentials(credentials.port, token) {
        return Err(HandoffError::Malformed);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + token.len()));
    frame.extend_from_slice(&MAGIC);
    let secret = Zeroizing::new(identity.secret_bytes());
    frame.extend_from_slice(&secret[..]);
    frame.extend_from_slice(&identity.public());
    frame.extend_from_slice(&credentials.host.octets());
    frame.extend_from_slice(&credentials.port.to_be_bytes());
    frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
    frame.extend_from_slice(token);
    Ok(frame)
}

/// Decode the frame at the start of `bytes` and return it with its length.
fn decode_one(bytes: &[u8]) -> Result<((Identity, PhoneCredentials), usize), HandoffError> {
    if bytes.len() < HEADER_BYTES || bytes[0..4] != MAGIC {
        return Err(HandoffError::Malformed);
    }
    let token_len = u16::from_be_bytes([bytes[74], bytes[75]]) as usize;
    if token_len == 0 || token_len > MAX_TOKEN_BYTES || bytes.len() < HEADER_BYTES + token_len {
        return Err(HandoffError::Malformed);
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&bytes[4..36]);
    let identity = Identity::from_bytes(*secret);
    if identity.public()[..] != bytes[36..68] {
        return Err(HandoffError::Malformed);
    }
    let host = std::net::Ipv4Addr::new(bytes[68], bytes[69], bytes[70], bytes[71]);
    let port = u16::from_be_bytes([bytes[72], bytes[73]]);
    let token = &bytes[HEADER_BYTES..HEADER_BYTES + token_len];
    if !usable_credentials(port, token) {
        return Err(HandoffError::Malformed);
    }
    let token = std::str::from_utf8(token).map_err(|_| HandoffError::Malformed)?;
    Ok((
        (
            identity,
            PhoneCredentials {
                host,
                port,
                token: token.to_owned(),
            },
        ),
        HEADER_BYTES + token_len,
    ))
}

/// Decode every queued frame and return the newest one. A cancelled start can
/// leave an older frame queued; the newest frame wins. An empty buffer, a
/// partial frame, or a malformed frame is an error.
pub fn decode_latest(bytes: &[u8]) -> Result<(Identity, PhoneCredentials), HandoffError> {
    let mut rest = bytes;
    let mut latest = None;
    while !rest.is_empty() {
        let (value, used) = decode_one(rest)?;
        latest = Some(value);
        rest = &rest[used..];
    }
    latest.ok_or(HandoffError::Malformed)
}

#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;

    pub type Handle = *mut c_void;
    pub const FILE_TYPE_PIPE: u32 = 3;
    pub const HANDLE_FLAG_INHERIT: u32 = 1;
    pub const ERROR_NOT_SAME_OBJECT: u32 = 1656;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetFileType(handle: Handle) -> u32;
        pub fn GetNamedPipeInfo(
            handle: Handle,
            flags: *mut u32,
            out_size: *mut u32,
            in_size: *mut u32,
            instances: *mut u32,
        ) -> i32;
        pub fn PeekNamedPipe(
            handle: Handle,
            buffer: *mut c_void,
            length: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
        pub fn ReadFile(
            handle: Handle,
            buffer: *mut u8,
            length: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        pub fn WriteFile(
            handle: Handle,
            buffer: *const u8,
            length: u32,
            written: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        pub fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
        pub fn SetLastError(error: u32);
        pub fn GetLastError() -> u32;
        pub fn CloseHandle(handle: Handle) -> i32;
        pub fn GetStdHandle(which: u32) -> Handle;
    }

    // KernelBase.dll exports CompareObjectHandles. The kernel32 import
    // library on Windows 11 24H2 and Server 2025 has no entry for it, so link
    // it with raw-dylib. On x86 the export name is undecorated, unlike the
    // default stdcall import name.
    #[cfg_attr(
        target_arch = "x86",
        link(
            name = "kernelbase",
            kind = "raw-dylib",
            import_name_type = "undecorated"
        )
    )]
    #[cfg_attr(
        not(target_arch = "x86"),
        link(name = "kernelbase", kind = "raw-dylib")
    )]
    extern "system" {
        pub fn CompareObjectHandles(first: Handle, second: Handle) -> i32;
    }

    pub const STD_INPUT_HANDLE: u32 = 0xffff_fff6;
    pub const STD_OUTPUT_HANDLE: u32 = 0xffff_fff5;
    pub const STD_ERROR_HANDLE: u32 = 0xffff_fff4;
}

/// One inherited handoff pipe handle that this process owns.
///
/// The value is the handle number. It closes the handle when it drops.
#[cfg(windows)]
#[derive(Debug)]
pub struct HandoffHandle(usize);

#[cfg(windows)]
impl Drop for HandoffHandle {
    fn drop(&mut self) {
        // SAFETY: The handle was validated as a pipe that this process owns.
        unsafe {
            win32::CloseHandle(self.0 as win32::Handle);
        }
    }
}

#[cfg(windows)]
impl HandoffHandle {
    /// Validate and seal one inherited handoff handle.
    ///
    /// The value must be a nonzero, four-byte aligned handle number of a pipe.
    /// It must not name the same kernel object as any handle
    /// in `others` (the GUI token and parent pipes). Its inherit flag is
    /// cleared, so no `netsh` child inherits it. `readable` selects the read
    /// end check for the credentials handle; the write end cannot be peeked.
    pub fn claim(value: u64, readable: bool, others: &[Option<u64>]) -> Result<Self, String> {
        if value == 0 || value >= usize::MAX as u64 || value & 3 != 0 {
            return Err("invalid pairing handoff handle".into());
        }
        let handle = value as usize as win32::Handle;
        // `GetNamedPipeInfo` must succeed, and it is what tells a pipe from a
        // socket: `GetFileType` reports `FILE_TYPE_PIPE` for both. The query
        // needs FILE_READ_ATTRIBUTES access, which a `CreatePipe` write end
        // carries, so the write end is accepted even though `readable` is
        // false. The GetNamedPipeInfo documentation states that a write-only
        // pipe handle needs GENERIC_WRITE and FILE_READ_ATTRIBUTES; a write end
        // opened with CreateFileW(GENERIC_WRITE) alone would lack
        // FILE_READ_ATTRIBUTES and would be refused here rather than accepted.
        let named = unsafe {
            win32::GetNamedPipeInfo(
                handle,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if unsafe { win32::GetFileType(handle) } != win32::FILE_TYPE_PIPE || named == 0 {
            return Err("the pairing handoff handle must be a pipe".into());
        }
        if readable {
            let mut available = 0u32;
            let ok = unsafe {
                win32::PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err("the pairing credentials handle must be readable".into());
            }
        }
        // A standard handle is not a private channel. A launcher bug that
        // passes one must not have it claimed and closed here.
        let standard = [
            win32::STD_INPUT_HANDLE,
            win32::STD_OUTPUT_HANDLE,
            win32::STD_ERROR_HANDLE,
        ]
        .map(|which| Some(unsafe { win32::GetStdHandle(which) } as usize as u64));
        for other in others.iter().chain(standard.iter()).flatten() {
            if *other == value {
                return Err("a pairing handle must be a separate handle".into());
            }
            if *other == 0 || *other >= usize::MAX as u64 || *other & 3 != 0 {
                continue;
            }
            unsafe { win32::SetLastError(0) };
            let same =
                unsafe { win32::CompareObjectHandles(handle, *other as usize as win32::Handle) };
            if same != 0 {
                return Err("a pairing handle must refer to a separate pipe".into());
            }
            let error = unsafe { win32::GetLastError() };
            if error != 0 && error != win32::ERROR_NOT_SAME_OBJECT {
                return Err("could not compare the pairing handle".into());
            }
        }
        if unsafe { win32::SetHandleInformation(handle, win32::HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err("could not clear the pairing handle inheritance".into());
        }
        Ok(Self(value as usize))
    }

    /// Write one frame. The frame buffer clears itself when it drops.
    pub fn write(
        &self,
        identity: &Identity,
        credentials: &PhoneCredentials,
    ) -> Result<(), HandoffError> {
        let frame = encode_frame(identity, credentials)?;
        let mut rest: &[u8] = &frame;
        while !rest.is_empty() {
            let mut written = 0u32;
            let length = u32::try_from(rest.len()).map_err(|_| HandoffError::Io)?;
            // SAFETY: The buffer is valid for `length` bytes. The handle is a
            // synchronous pipe, so no overlapped structure is needed.
            let ok = unsafe {
                win32::WriteFile(
                    self.0 as win32::Handle,
                    rest.as_ptr(),
                    length,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || written == 0 {
                return Err(HandoffError::Io);
            }
            rest = &rest[written as usize..];
        }
        Ok(())
    }

    /// Read every frame that is already queued and return the newest one. The
    /// read never blocks: it asks only for the bytes that `PeekNamedPipe`
    /// reports. An empty channel is a failed launch, not a wait.
    pub fn read_latest(&self) -> Result<(Identity, PhoneCredentials), HandoffError> {
        let handle = self.0 as win32::Handle;
        let mut buffer = Zeroizing::new(Vec::new());
        loop {
            let mut available = 0u32;
            let ok = unsafe {
                win32::PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // Every writer closed the pipe. Use what was read.
                break;
            }
            if available == 0 {
                break;
            }
            // The check after each read keeps the buffer at or below the
            // bound here, so at least one byte of room remains. Reading one
            // byte past the bound detects an oversized channel.
            let room = MAX_QUEUED_BYTES + 1 - buffer.len();
            let want = (available as usize).min(room);
            let start = buffer.len();
            buffer.resize(start + want, 0);
            let mut read = 0u32;
            // SAFETY: The buffer has `want` writable bytes at `start`. The
            // peek reported at least that many bytes, so the read returns at
            // once on this synchronous pipe.
            let ok = unsafe {
                win32::ReadFile(
                    handle,
                    buffer[start..].as_mut_ptr(),
                    want as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                return Err(HandoffError::Io);
            }
            buffer.truncate(start + read as usize);
            if buffer.len() > MAX_QUEUED_BYTES {
                return Err(HandoffError::Malformed);
            }
        }
        decode_latest(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn identity() -> Identity {
        Identity::from_bytes([0x31; 32])
    }

    fn credentials(port: u16, token: &str) -> PhoneCredentials {
        PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port,
            token: token.into(),
        }
    }

    #[test]
    fn a_frame_round_trips_and_matches_the_unix_layout() {
        let frame = encode_frame(&identity(), &credentials(31000, "public-test-token")).unwrap();
        assert_eq!(&frame[0..4], b"HSC1");
        assert_eq!(frame.len(), HEADER_BYTES + "public-test-token".len());
        assert_eq!(&frame[68..72], &[172, 20, 10, 1]);
        assert_eq!(&frame[72..74], &31000u16.to_be_bytes());
        let (decoded_identity, decoded) = decode_latest(&frame).unwrap();
        assert_eq!(decoded_identity.public(), identity().public());
        assert_eq!(decoded, credentials(31000, "public-test-token"));
    }

    #[test]
    fn the_newest_queued_frame_wins() {
        let mut queued = encode_frame(&identity(), &credentials(31000, "old-token"))
            .unwrap()
            .to_vec();
        queued.extend_from_slice(
            &encode_frame(&identity(), &credentials(32000, "new-token")).unwrap(),
        );
        let (_, latest) = decode_latest(&queued).unwrap();
        assert_eq!(latest, credentials(32000, "new-token"));
    }

    #[test]
    fn a_bad_frame_is_refused() {
        assert_eq!(decode_latest(&[]).unwrap_err(), HandoffError::Malformed);
        let frame = encode_frame(&identity(), &credentials(31000, "token")).unwrap();
        // Truncated.
        assert!(decode_latest(&frame[..frame.len() - 1]).is_err());
        // Wrong marker.
        let mut bad = frame.to_vec();
        bad[0] = b'X';
        assert!(decode_latest(&bad).is_err());
        // A public key that does not match the secret.
        let mut bad = frame.to_vec();
        bad[40] ^= 1;
        assert!(decode_latest(&bad).is_err());
        // A trailing partial frame after a good one.
        let mut bad = frame.to_vec();
        bad.extend_from_slice(b"HSC1");
        assert!(decode_latest(&bad).is_err());
    }

    /// A `CreatePipe` channel is the shape the launcher passes: a write end to
    /// the user engine and a read end to the elevated engine. A socket must be
    /// refused even though `GetFileType` calls it a pipe.
    #[cfg(windows)]
    #[test]
    // `RawSocket` is `u64` on 64-bit Windows and `u32` on 32-bit Windows, so
    // the widening conversion is needed on one target and is a no-op on the
    // other, where clippy reports it as useless.
    #[allow(clippy::useless_conversion)]
    fn a_pipe_write_end_is_claimed_and_a_socket_is_refused() {
        use std::ffi::c_void;
        use std::os::windows::io::AsRawSocket;

        #[link(name = "kernel32")]
        extern "system" {
            fn CreatePipe(
                read_pipe: *mut *mut c_void,
                write_pipe: *mut *mut c_void,
                attributes: *mut c_void,
                size: u32,
            ) -> i32;
        }

        // The claimed handles close themselves, so the guard owns the raw ends
        // and the successful claims are forgotten to avoid a second close.
        struct PipeEnds(*mut c_void, *mut c_void);
        impl Drop for PipeEnds {
            fn drop(&mut self) {
                // SAFETY: The test owns both ends and closes each one once.
                unsafe {
                    win32::CloseHandle(self.0);
                    win32::CloseHandle(self.1);
                }
            }
        }

        let mut read_end: *mut c_void = std::ptr::null_mut();
        let mut write_end: *mut c_void = std::ptr::null_mut();
        // SAFETY: Both out pointers are valid, and a null security attribute
        // asks for a non-inheritable anonymous pipe.
        let created = unsafe { CreatePipe(&mut read_end, &mut write_end, std::ptr::null_mut(), 0) };
        assert_ne!(created, 0, "CreatePipe failed: {}", unsafe {
            win32::GetLastError()
        });
        let ends = PipeEnds(read_end, write_end);

        let write_handle = HandoffHandle::claim(ends.1 as usize as u64, false, &[])
            .expect("a CreatePipe write end is a handoff channel");
        std::mem::forget(write_handle);
        let read_handle = HandoffHandle::claim(ends.0 as usize as u64, true, &[])
            .expect("a CreatePipe read end is a credentials channel");
        std::mem::forget(read_handle);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback socket");
        let socket = u64::from(listener.as_raw_socket());
        assert!(
            HandoffHandle::claim(socket, false, &[]).is_err(),
            "a socket handle is not a pipe"
        );
    }

    #[test]
    fn the_frame_uses_the_pairing_port_and_token_limits() {
        for (port, token) in [
            (1023u16, "token"),
            (PAIRING_PORT, "token"),
            (31000, ""),
            (31000, "has space"),
            (31000, "tab\t"),
        ] {
            assert_eq!(
                encode_frame(&identity(), &credentials(port, token)).unwrap_err(),
                HandoffError::Malformed,
                "{port} {token:?}"
            );
        }
        let long = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert!(encode_frame(&identity(), &credentials(31000, &long)).is_err());
        let max = "a".repeat(MAX_TOKEN_BYTES);
        assert!(encode_frame(&identity(), &credentials(31000, &max)).is_ok());
    }

    #[test]
    fn the_error_text_holds_no_secret() {
        for error in [HandoffError::Io, HandoffError::Malformed] {
            assert!(!error.message().contains("token-"));
            assert!(!format!("{error:?}").contains("31"));
        }
        const { assert!(MAX_QUEUED_BYTES >= 4 * (HEADER_BYTES + MAX_TOKEN_BYTES)) };
    }
}
