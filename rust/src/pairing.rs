//! Pairing between the target device GUI and the source device app, protocol v1.
//!
//! The target device opens one TCP connection to the source device hotspot
//! address on [`PAIRING_PORT`]. The two sides run an X25519 exchange. The
//! source device shows a six-digit code and asks its user to allow an unknown
//! target device. The source device then sends the proxy port, the proxy token,
//! and the hotspot address, encrypted with ChaCha20-Poly1305. The source device
//! remembers the target device static public key. A later pairing from the same
//! target device needs no tap.
//!
//! The Swift file `ios/HotspotProxy/Pairing.swift` implements the source device
//! side. Both test suites hold the same fixed vectors. Change both sides
//! together.
//!
//! Secrets: this module never logs, formats, or returns the identity key or
//! the token in error text or Debug output.
use crate::normalization;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// The phone listens for pairings on this port, on the hotspot address only.
pub const PAIRING_PORT: u16 = 18090;
/// The maximum payload of one frame.
pub const MAX_FRAME: usize = 512;
pub const VERSION: u8 = 1;
pub const MSG_HELLO: u8 = 0x01;
pub const MSG_CHALLENGE: u8 = 0x02;
pub const MSG_REVEAL: u8 = 0x03;
pub const MSG_RESULT: u8 = 0x04;
const COMMIT_LABEL: &[u8] = b"hotspotshade-commit-v1";
const PAIR_LABEL: &[u8] = b"hotspotshade-pair-v1";
const HELLO_LEN: usize = 2 + 32 + 32;
const CHALLENGE_LEN: usize = 1 + 32 + 1;
const REVEAL_LEN: usize = 1 + 32 + 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The status byte in RESULT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhoneStatus {
    Ok = 0,
    Denied = 1,
    Busy = 2,
    Rejected = 3,
    TimedOut = 4,
    NotActive = 5,
    LockedOut = 6,
}
impl PhoneStatus {
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Ok,
            1 => Self::Denied,
            2 => Self::Busy,
            3 => Self::Rejected,
            4 => Self::TimedOut,
            5 => Self::NotActive,
            6 => Self::LockedOut,
            _ => return None,
        })
    }
}

/// A pairing failure. The text of each variant is fixed and holds no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairError {
    /// The phone answered with a non-zero status.
    Phone(PhoneStatus),
    /// The phone did not accept the TCP connection.
    Unreachable,
    /// The phone did not answer in time.
    TimedOut,
    /// The caller set the cancel flag.
    Cancelled,
    /// A frame or a message had a bad length, type, or value.
    Protocol,
    /// A key agreement gave a low-order (all-zero) result.
    LowOrder,
    /// The RESULT ciphertext did not authenticate.
    Decrypt,
    /// The identity key file cannot be read or created safely.
    Identity,
    /// The random source failed.
    Random,
    /// No hotspot gateway was found.
    NoPhone,
    /// Another socket error.
    Io,
    /// A peer answered a FORGET, but protocol v1 cannot prove that the source
    /// device removed this target device key. See [`ForgetReply`].
    Unconfirmed,
}
impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for PairError {}
impl PairError {
    /// A fixed message that is safe to show in the GUI.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Phone(PhoneStatus::Ok) => "The pairing failed.",
            Self::Phone(PhoneStatus::Denied) => "The source device denied the pairing.",
            Self::Phone(PhoneStatus::Busy) => {
                "The source device is busy with another pairing. Try again in a minute."
            }
            Self::Phone(PhoneStatus::Rejected) => "The source device rejected the pairing message.",
            Self::Phone(PhoneStatus::TimedOut) => {
                "Nobody answered the prompt on the source device in time. Try again."
            }
            Self::Phone(PhoneStatus::NotActive) => {
                "Open HotspotShade on your source device."
            }
            Self::Phone(PhoneStatus::LockedOut) => {
                "The source device refuses pairings for 30 seconds after repeated failures. Wait and try again."
            }
            Self::Unreachable => "Open HotspotShade on your source device.",
            Self::TimedOut => "Open HotspotShade on your source device.",
            Self::Cancelled => "The pairing was cancelled.",
            Self::Protocol | Self::LowOrder | Self::Decrypt => {
                "The source device sent an invalid pairing message."
            }
            Self::Identity => "The target device identity key cannot be used. Check its file permissions.",
            Self::Random => "The target device random source failed.",
            Self::NoPhone => "Connect this device to the source device hotspot.",
            Self::Io => "The pairing connection failed.",
            Self::Unconfirmed => {
                "The source device answered, but this target device cannot verify that it removed the pairing."
            }
        }
    }
}

/// The proxy credentials from the phone. Debug output hides the token.
#[derive(Clone, PartialEq, Eq)]
pub struct PhoneCredentials {
    pub host: Ipv4Addr,
    pub port: u16,
    pub token: String,
}
impl Drop for PhoneCredentials {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
impl fmt::Debug for PhoneCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhoneCredentials")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("token", &"[redacted]")
            .finish()
    }
}

#[cfg(windows)]
#[link(name = "bcrypt")]
extern "system" {
    /// Fill a buffer with cryptographically strong random bytes.
    fn BCryptGenRandom(
        algorithm: *mut std::ffi::c_void,
        buffer: *mut u8,
        length: u32,
        flags: u32,
    ) -> i32;
}

/// The documented flag that selects the system-preferred random generator.
#[cfg(windows)]
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

/// Fill a buffer from the operating system random source.
///
/// On Android, bionic exports `getentropy` only from API 28. The minimum
/// Android API level for this project is 26. This function reads
/// `/dev/urandom` on Android instead. The Linux kernel CSPRNG backs that
/// device. Bionic uses the same fallback when `getrandom` is not available.
/// An open or read error returns [`PairError::Random`]. The function never
/// falls back to a weaker source and never exits the process.
pub fn random_bytes(buffer: &mut [u8]) -> Result<(), PairError> {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        // getentropy accepts at most 256 bytes per call. Use 32-byte calls.
        for chunk in buffer.chunks_mut(32) {
            let rc = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
            if rc != 0 {
                return Err(PairError::Random);
            }
        }
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        android_random_bytes(buffer)
    }
    #[cfg(windows)]
    {
        // BCryptGenRandom is the documented Windows cryptographic random
        // source. A null algorithm handle with this flag selects the system
        // preferred generator. A negative NTSTATUS is a failure.
        for chunk in buffer.chunks_mut(32) {
            let status = unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status < 0 {
                return Err(PairError::Random);
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = buffer;
        Err(PairError::Random)
    }
}

/// Fill a buffer from `/dev/urandom` on Android.
///
/// Do not call the `getrandom` system call here. The Android 8 app seccomp
/// filter traps a blocked system call with SIGSYS, and the process cannot
/// recover from that trap. The `open` and `read` calls are in the Android 8
/// app seccomp allow list. The `domain` SELinux rule allows every app domain
/// to read `random_device`.
#[cfg(target_os = "android")]
fn android_random_bytes(buffer: &mut [u8]) -> Result<(), PairError> {
    use std::io::Read;
    if buffer.is_empty() {
        return Ok(());
    }
    let mut file = std::fs::File::open("/dev/urandom").map_err(|_| PairError::Random)?;
    file.read_exact(buffer).map_err(|_| PairError::Random)
}

fn new_secret() -> Result<StaticSecret, PairError> {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes)?;
    let secret = StaticSecret::from(bytes);
    // The static secret holds its own copy. Erase this transient stack copy.
    for byte in &mut bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    Ok(secret)
}

/// The target device long-term X25519 identity. Debug output hides the key.
pub struct Identity {
    secret: StaticSecret,
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &hex(&self.public()))
            .finish()
    }
}
impl Identity {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }
    /// The secret bytes for the one private handoff to an elevated engine.
    /// The caller must keep the copy in a zeroizing buffer. Do not log it,
    /// write it to a status answer, or pass it on a command line.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
    /// `$HOME/Library/Application Support/hotspotshade/identity.key`.
    #[cfg(unix)]
    pub fn default_path() -> Result<PathBuf, PairError> {
        let home = std::env::var_os("HOME").ok_or(PairError::Identity)?;
        if home.is_empty() {
            return Err(PairError::Identity);
        }
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("hotspotshade")
            .join("identity.key"))
    }
    /// `%LOCALAPPDATA%\hotspotshade\identity.key`.
    #[cfg(windows)]
    pub fn default_path() -> Result<PathBuf, PairError> {
        windows_identity::default_path()
    }
    #[cfg(not(any(unix, windows)))]
    pub fn default_path() -> Result<PathBuf, PairError> {
        Err(PairError::Identity)
    }
    /// Read the identity key, or create it on first use. The directory gets
    /// mode 0700. The file gets mode 0600. Reject a file with the wrong
    /// length, another owner, or permissions for group or others.
    #[cfg(unix)]
    pub fn load_or_create(path: &Path) -> Result<Self, PairError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
        let dir = path.parent().ok_or(PairError::Identity)?;
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|_| PairError::Identity)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| PairError::Identity)?;
        }
        let uid = unsafe { libc::getuid() };
        let meta = std::fs::symlink_metadata(dir).map_err(|_| PairError::Identity)?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(PairError::Identity);
        }
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(mut file) => {
                let meta = file.metadata().map_err(|_| PairError::Identity)?;
                if !meta.is_file()
                    || meta.uid() != uid
                    || meta.mode() & 0o077 != 0
                    || meta.len() != 32
                {
                    return Err(PairError::Identity);
                }
                let mut bytes = [0u8; 32];
                file.read_exact(&mut bytes)
                    .map_err(|_| PairError::Identity)?;
                let mut extra = [0u8; 1];
                if file.read(&mut extra).map_err(|_| PairError::Identity)? != 0 {
                    return Err(PairError::Identity);
                }
                Ok(Self::from_bytes(bytes))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut bytes = [0u8; 32];
                random_bytes(&mut bytes)?;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)
                    .map_err(|_| PairError::Identity)?;
                let written = file
                    .write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|_| PairError::Identity);
                if written.is_err() {
                    drop(file);
                    let _ = std::fs::remove_file(path);
                    return Err(PairError::Identity);
                }
                Ok(Self::from_bytes(bytes))
            }
            Err(_) => Err(PairError::Identity),
        }
    }
    #[cfg(windows)]
    pub fn load_or_create(path: &Path) -> Result<Self, PairError> {
        windows_identity::load_or_create(path)
    }
    #[cfg(not(any(unix, windows)))]
    pub fn load_or_create(path: &Path) -> Result<Self, PairError> {
        let _ = path;
        Err(PairError::Identity)
    }
}

/// The identity that a root engine imports from the user engine. The root
/// engine runs with a different HOME, so it cannot read the user's key file.
/// The value is set once, before the engine serves any request. Keeping it in
/// memory avoids a second copy of the key on disk.
static IMPORTED_IDENTITY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Install the handoff identity. A second install of the same key is a no-op,
/// so two engines that import one handoff in the same process agree. A second
/// install with a different key is refused, so no request can replace the
/// identity of a running engine.
pub fn set_imported_identity(secret: [u8; 32]) -> Result<(), PairError> {
    match IMPORTED_IDENTITY.set(secret) {
        Ok(()) => Ok(()),
        Err(_) if IMPORTED_IDENTITY.get() == Some(&secret) => Ok(()),
        Err(_) => Err(PairError::Identity),
    }
}

/// The identity for this process: the imported handoff key when one is set,
/// otherwise the user key file. All pairing, presence, and forget paths use
/// this function so a root engine never creates a different identity.
pub fn local_identity() -> Result<Identity, PairError> {
    if let Some(secret) = IMPORTED_IDENTITY.get() {
        return Ok(Identity::from_bytes(*secret));
    }
    Identity::load_or_create(&Identity::default_path()?)
}

/// The packed identity-store failure diagnostic.
///
/// The Windows loader records only a fixed step word, a component index, and a
/// Win32 error number. It never records a path, a SID, or key material. The
/// step words, the packing, and the formatting are host-independent, so the
/// unit tests below run on every platform. The Windows loader is the only
/// writer; other platforms always read `None`.
#[cfg(any(windows, test))]
mod identity_failure {
    /// One step of the identity-store loader.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Step {
        ValidatePath = 1,
        RejectImpersonation = 2,
        Parent = 3,
        CurrentUserSid = 4,
        DirectoryChain = 5,
        AncestorOpen = 6,
        DirectoryCreate = 7,
        DirectoryObject = 8,
        VolumeAcls = 9,
        AncestorValidate = 10,
        DirectoryValidate = 11,
        OpenFile = 12,
        FileValidate = 13,
        ReadFile = 14,
        Unprotect = 15,
        SecurityDescriptor = 16,
        Protect = 17,
        CreateTemp = 18,
        TempValidate = 19,
        WriteFile = 20,
        Flush = 21,
        Rename = 22,
        WidePath = 23,
        Sid = 24,
        RemovalAce = 25,
        RemovalAces = 26,
        AncestorSecurity = 27,
        OwnerDacl = 28,
        FileInformation = 29,
        DpapiBlob = 30,
        DefaultPath = 31,
        DeleteFile = 32,
    }

    impl Step {
        /// The fixed word for this step. It never becomes free text.
        pub(super) fn word(self) -> &'static str {
            match self {
                Self::ValidatePath => "validate_path",
                Self::RejectImpersonation => "reject_impersonation",
                Self::Parent => "parent",
                Self::CurrentUserSid => "current_user_sid",
                Self::DirectoryChain => "directory_chain",
                Self::AncestorOpen => "ancestor_open",
                Self::DirectoryCreate => "directory_create",
                Self::DirectoryObject => "directory_object",
                Self::VolumeAcls => "volume_acls",
                Self::AncestorValidate => "ancestor_validate",
                Self::DirectoryValidate => "directory_validate",
                Self::OpenFile => "open_file",
                Self::FileValidate => "file_validate",
                Self::ReadFile => "read_file",
                Self::Unprotect => "unprotect",
                Self::SecurityDescriptor => "security_descriptor",
                Self::Protect => "protect",
                Self::CreateTemp => "create_temp",
                Self::TempValidate => "temp_validate",
                Self::WriteFile => "write_file",
                Self::Flush => "flush",
                Self::Rename => "rename",
                Self::WidePath => "wide_path",
                Self::Sid => "sid",
                Self::RemovalAce => "removal_ace",
                Self::RemovalAces => "removal_aces",
                Self::AncestorSecurity => "ancestor_security",
                Self::OwnerDacl => "owner_dacl",
                Self::FileInformation => "file_information",
                Self::DpapiBlob => "dpapi_blob",
                Self::DefaultPath => "default_path",
                Self::DeleteFile => "delete_file",
            }
        }

        /// Recover a step from its packed id.
        pub(super) fn from_id(id: u16) -> Option<Self> {
            Some(match id {
                1 => Self::ValidatePath,
                2 => Self::RejectImpersonation,
                3 => Self::Parent,
                4 => Self::CurrentUserSid,
                5 => Self::DirectoryChain,
                6 => Self::AncestorOpen,
                7 => Self::DirectoryCreate,
                8 => Self::DirectoryObject,
                9 => Self::VolumeAcls,
                10 => Self::AncestorValidate,
                11 => Self::DirectoryValidate,
                12 => Self::OpenFile,
                13 => Self::FileValidate,
                14 => Self::ReadFile,
                15 => Self::Unprotect,
                16 => Self::SecurityDescriptor,
                17 => Self::Protect,
                18 => Self::CreateTemp,
                19 => Self::TempValidate,
                20 => Self::WriteFile,
                21 => Self::Flush,
                22 => Self::Rename,
                23 => Self::WidePath,
                24 => Self::Sid,
                25 => Self::RemovalAce,
                26 => Self::RemovalAces,
                27 => Self::AncestorSecurity,
                28 => Self::OwnerDacl,
                29 => Self::FileInformation,
                30 => Self::DpapiBlob,
                31 => Self::DefaultPath,
                32 => Self::DeleteFile,
                _ => return None,
            })
        }
    }

    /// Bits 0..32 hold the Win32 error, 32..48 the component index, 48..64 the
    /// step id. Step ids start at 1, so a packed value of 0 is the "no failure"
    /// sentinel.
    pub(super) fn pack(step: Step, index: u64, win32: u32) -> u64 {
        (u64::from(step as u16) << 48) | (index.min(u16::MAX as u64) << 32) | u64::from(win32)
    }

    /// Why the loader refused one access entry of an ancestor directory.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum AceReason {
        /// The entry is truncated or misaligned.
        Malformed = 1,
        /// A policy, trust-label, or access-filter entry.
        PolicyAce = 2,
        /// An allow entry gives a removal right to an untrusted principal.
        Untrusted = 3,
        /// A compound or unknown entry type.
        UnknownType = 4,
    }

    impl AceReason {
        fn from_id(id: u8) -> Option<Self> {
            Some(match id {
                1 => Self::Malformed,
                2 => Self::PolicyAce,
                3 => Self::Untrusted,
                4 => Self::UnknownType,
                _ => return None,
            })
        }

        fn word(self) -> &'static str {
            match self {
                Self::Malformed => "malformed",
                Self::PolicyAce => "policy_ace",
                Self::Untrusted => "untrusted",
                Self::UnknownType => "unknown_type",
            }
        }
    }

    /// Fixed class words for the principal of a refused entry. The SID itself
    /// is never recorded, because an account SID identifies the user.
    const SID_CLASS_WORDS: [&str; 15] = [
        "none",
        "world",
        "authenticated_users",
        "users",
        "all_app_packages",
        "all_restricted_app_packages",
        "creator_owner",
        "owner_rights",
        "interactive",
        "package",
        "capability",
        "service",
        "account",
        "builtin",
        "other",
    ];

    /// The class of a SID in string form, as an index into the class words.
    pub(super) fn sid_class(sid: &str) -> u8 {
        match sid {
            "S-1-1-0" => 1,
            "S-1-5-11" => 2,
            "S-1-5-32-545" => 3,
            "S-1-15-2-1" => 4,
            "S-1-15-2-2" => 5,
            "S-1-3-0" => 6,
            "S-1-3-4" => 7,
            "S-1-5-4" => 8,
            _ if sid.starts_with("S-1-15-2-") => 9,
            _ if sid.starts_with("S-1-15-3-") => 10,
            _ if sid.starts_with("S-1-5-80-") => 11,
            _ if sid.starts_with("S-1-5-21-") => 12,
            _ if sid.starts_with("S-1-5-32-") => 13,
            _ => 14,
        }
    }

    /// The high bit marks a refused-entry detail in the Win32 field. A
    /// refused entry is a policy result, so no Win32 error applies.
    const ACE_DETAIL_FLAG: u32 = 0x8000_0000;

    /// Pack a refused-entry detail into the Win32 field of a removal_ace step.
    pub(super) fn ace_detail(reason: AceReason, ace_type: u8, sid_class: u8) -> u32 {
        ACE_DETAIL_FLAG
            | ((reason as u32) << 16)
            | (u32::from(ace_type) << 8)
            | u32::from(sid_class)
    }

    /// The formatted diagnostic, or `None` for the no-failure sentinel.
    pub(super) fn format(packed: u64) -> Option<String> {
        if packed == 0 {
            return None;
        }
        let step = Step::from_id(((packed >> 48) & 0xffff) as u16)?;
        let index = (packed >> 32) & 0xffff;
        let win32 = (packed & 0xffff_ffff) as u32;
        if step == Step::RemovalAce && win32 & ACE_DETAIL_FLAG != 0 {
            if let Some(reason) = AceReason::from_id(((win32 >> 16) & 0xff) as u8) {
                let ace_type = (win32 >> 8) & 0xff;
                let class = SID_CLASS_WORDS
                    .get((win32 & 0xff) as usize)
                    .copied()
                    .unwrap_or("other");
                return Some(format!(
                    "step={} component={} reason={} ace_type={} sid={}",
                    step.word(),
                    index,
                    reason.word(),
                    ace_type,
                    class
                ));
            }
        }
        Some(format!(
            "step={} component={} win32={}",
            step.word(),
            index,
            win32
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashSet;

        #[test]
        fn packing_round_trips_step_index_and_error() {
            for (step, index, win32) in [
                (Step::AncestorOpen, 3, 32u32),
                (Step::ValidatePath, 0, 0),
                (Step::DirectoryCreate, 4, 183),
                (Step::OpenFile, 0, 2),
                (Step::Rename, 0, 80),
            ] {
                let packed = pack(step, index, win32);
                let expected = format!("step={} component={} win32={}", step.word(), index, win32);
                assert_eq!(format(packed), Some(expected));
            }
        }

        #[test]
        fn every_step_has_a_unique_id_and_word() {
            let steps = [
                Step::ValidatePath,
                Step::RejectImpersonation,
                Step::Parent,
                Step::CurrentUserSid,
                Step::DirectoryChain,
                Step::AncestorOpen,
                Step::DirectoryCreate,
                Step::DirectoryObject,
                Step::VolumeAcls,
                Step::AncestorValidate,
                Step::DirectoryValidate,
                Step::OpenFile,
                Step::FileValidate,
                Step::ReadFile,
                Step::Unprotect,
                Step::SecurityDescriptor,
                Step::Protect,
                Step::CreateTemp,
                Step::TempValidate,
                Step::WriteFile,
                Step::Flush,
                Step::Rename,
                Step::WidePath,
                Step::Sid,
                Step::RemovalAce,
                Step::RemovalAces,
                Step::AncestorSecurity,
                Step::OwnerDacl,
                Step::FileInformation,
                Step::DpapiBlob,
                Step::DefaultPath,
                Step::DeleteFile,
            ];
            let mut ids = HashSet::new();
            let mut words = HashSet::new();
            for step in steps {
                let id = step as u16;
                assert!(id != 0, "{step:?} must not use the zero sentinel");
                assert!(ids.insert(id), "duplicate id {id}");
                assert_eq!(Step::from_id(id), Some(step), "{step:?}");
                assert!(
                    words.insert(step.word()),
                    "duplicate word {:?}",
                    step.word()
                );
                assert!(!step.word().is_empty());
                assert!(!step.word().contains(' '));
            }
        }

        #[test]
        fn a_refused_entry_names_the_reason_type_and_principal_class() {
            let detail = ace_detail(AceReason::Untrusted, 0, sid_class("S-1-15-2-123-456"));
            assert_eq!(
                format(pack(Step::RemovalAce, 3, detail)).as_deref(),
                Some("step=removal_ace component=3 reason=untrusted ace_type=0 sid=package")
            );
            let detail = ace_detail(AceReason::PolicyAce, 0x13, 0);
            assert_eq!(
                format(pack(Step::RemovalAce, 1, detail)).as_deref(),
                Some("step=removal_ace component=1 reason=policy_ace ace_type=19 sid=none")
            );
        }

        #[test]
        fn sid_classes_never_echo_the_sid() {
            for (sid, word) in [
                ("S-1-1-0", "world"),
                ("S-1-5-11", "authenticated_users"),
                ("S-1-5-32-545", "users"),
                ("S-1-5-32-544", "builtin"),
                ("S-1-15-2-1", "all_app_packages"),
                ("S-1-15-2-2", "all_restricted_app_packages"),
                ("S-1-15-2-1-2-3", "package"),
                ("S-1-15-3-1024-1", "capability"),
                ("S-1-5-80-1-2", "service"),
                ("S-1-5-21-1-2-3-1001", "account"),
                ("S-1-3-0", "creator_owner"),
                ("S-1-3-4", "owner_rights"),
                ("S-1-5-4", "interactive"),
                ("S-1-16-8192", "other"),
            ] {
                let detail = ace_detail(AceReason::Untrusted, 0, sid_class(sid));
                let text = format(pack(Step::RemovalAce, 2, detail)).unwrap();
                assert!(text.ends_with(&format!(" sid={word}")), "{sid}: {text}");
                assert!(!text.contains("S-1-"), "{text}");
            }
        }

        #[test]
        fn zero_is_the_no_failure_sentinel() {
            assert_eq!(format(0), None);
        }

        #[test]
        fn a_component_index_is_capped_at_u16_max() {
            let packed = pack(Step::AncestorOpen, u64::MAX, 32);
            assert_eq!(
                format(packed).as_deref(),
                Some(format!("step=ancestor_open component={} win32=32", u16::MAX).as_str())
            );
        }
    }
}

/// The first failing step of the most recent identity load, for diagnostics.
///
/// The string holds only a fixed step word, a component index, and a Win32
/// error number, for example `"step=ancestor_open component=3 win32=32"`. It
/// never holds a path, a SID, or key material. On non-Windows platforms this
/// always returns `None`.
#[cfg(windows)]
pub fn last_identity_failure() -> Option<String> {
    windows_identity::last_identity_failure()
}

#[cfg(not(windows))]
pub fn last_identity_failure() -> Option<String> {
    None
}

/// The Windows identity store.
///
/// The secret key is protected with per-user DPAPI. The file holds a DPAPI
/// blob, not the raw key. The directory and the file have a protected DACL
/// that grants full control to the current user only. A new file is written
/// to a random temporary name, flushed, and then renamed without replacement.
/// A failed file or security step returns [`PairError::Identity`]. A failed
/// random source returns [`PairError::Random`]. The loader never falls back to
/// plaintext.
///
/// The loader validates the private directory on every load. The path must be
/// absolute, name one file on a fixed local drive, and hold no parent,
/// current, or stream component. The volume must support persistent ACLs.
/// Every directory from the volume root to the private directory is opened
/// with `FILE_FLAG_OPEN_REPARSE_POINT`, checked for a reparse point, and held
/// until the load or create finishes. The volume root is opened with delete
/// sharing because it cannot be renamed or removed. Every lower component is
/// held without `FILE_SHARE_DELETE`. A reparse point in the file, its
/// directory, or an intermediate component is rejected.
///
/// A protected DACL on the private directory does not stop another user from
/// removing the directory through a parent. The loader therefore checks every
/// directory on the path. Every ancestor owner must be the current user,
/// LocalSystem, Builtin Administrators, or TrustedInstaller. The private
/// directory and the file must be owned by the current user and hold the
/// private descriptor. No other principal may hold a `DELETE`,
/// `FILE_DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`,
/// `MAXIMUM_ALLOWED`, `FILE_ADD_FILE`, `FILE_WRITE_ATTRIBUTES`, or
/// `GENERIC_WRITE` allow entry. The last three let a principal set a reparse
/// point on an empty ancestor, and the others let it remove, rename, or change
/// the permissions of the directory. The scan includes inherited entries that
/// apply to the object and skips inherit-only entries. A null DACL, an
/// unknown ACE type, a compound ACE, a central access policy entry, or a
/// malformed entry fails closed. The check does not assume that an inherited
/// entry is safe.
///
/// Other principals fail closed even when they look administrative, because
/// the loader cannot prove their group membership. The trust set is the
/// current user, LocalSystem, Builtin Administrators, and TrustedInstaller.
/// An owner or a hazardous allow entry for a domain administrator group must
/// be replaced with Builtin Administrators, or the store is not used.
///
/// The check is a point-in-time proof. A principal that can change an
/// ancestor DACL, take ownership, or remove an ancestor is trusted by
/// definition. The current user, an administrator, LocalSystem, and
/// TrustedInstaller can still remove the store. A principal with
/// `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`, `SeBackupPrivilege`, or
/// an equivalent backup or restore right can also change it. Treat such a
/// principal as an administrator. This boundary is inherent to per-user
/// storage and to the local operating system. The loader also fails closed
/// when the thread carries an impersonation token, because file access then
/// uses an identity other than the process user. The store never repairs an
/// existing ACL. A wrong owner, a wrong SID, an extra ACE, or an
/// unprotected private DACL fails.
///
/// A process that runs as the same user can decrypt the blob. That is a limit
/// of per-user DPAPI. A copy of the file to another user account cannot be
/// decrypted. A process that runs as the current user can change the store
/// and can decrypt it. Do not treat the identity file as protection against
/// that user.
#[cfg(windows)]
mod windows_identity {
    use super::identity_failure::{self, AceReason, Step as IdentityStep};
    use super::{hex, random_bytes, Identity, PairError};
    use std::ffi::{c_void, OsStr, OsString};
    use std::mem;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::ptr;
    use std::slice;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    type Handle = *mut c_void;
    type Psid = *mut c_void;
    type Pacl = *mut c_void;
    type Psd = *mut c_void;

    const INVALID_HANDLE_VALUE: isize = -1;

    const TOKEN_QUERY: u32 = 0x0008;
    #[cfg(test)]
    const TOKEN_IMPERSONATE: u32 = 0x0004;
    #[cfg(test)]
    const TOKEN_DUPLICATE: u32 = 0x0002;
    const TOKEN_USER: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_DACL_PROTECTED: u16 = 0x1000;
    const SDDL_REVISION_1: u32 = 1;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
    const SYSTEM_ALARM_ACE_TYPE: u8 = 3;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
    const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
    const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 7;
    const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 8;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
    const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;
    const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 12;
    const SYSTEM_AUDIT_CALLBACK_ACE_TYPE: u8 = 13;
    const SYSTEM_ALARM_CALLBACK_ACE_TYPE: u8 = 14;
    const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: u8 = 15;
    const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: u8 = 16;
    const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 17;
    const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 18;
    const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 19;
    const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 20;
    const SYSTEM_ACCESS_FILTER_ACE_TYPE: u8 = 21;
    /// The ACE applies to children only.
    const INHERIT_ONLY_ACE: u8 = 0x08;
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    /// Rights on an ancestor that can remove, replace, or redirect the private
    /// directory. `FILE_ADD_FILE` is `FILE_WRITE_DATA` for a directory, and
    /// `FILE_WRITE_ATTRIBUTES` is enough to set a reparse point on an empty
    /// directory. `GENERIC_WRITE` maps to both.
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const FILE_ADD_FILE: u32 = 0x0000_0002;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const ANCESTOR_HAZARD_RIGHTS: u32 = FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_ALL
        | MAXIMUM_ALLOWED
        | FILE_ADD_FILE
        | FILE_WRITE_ATTRIBUTES
        | GENERIC_WRITE;
    /// Rights that matter on the volume root. The root cannot be renamed,
    /// removed, or turned into a reparse point, and it is never empty. Only a
    /// right that removes a child or changes the permissions can hurt.
    const ROOT_HAZARD_RIGHTS: u32 =
        FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | MAXIMUM_ALLOWED;
    const ACL_SIZE_INFORMATION_CLASS: u32 = 2;
    const SID_REVISION: u8 = 1;
    const MAX_SID_SUB_AUTHORITIES: u32 = 15;
    const ACL_HEADER_BYTES: usize = 8;
    const MIN_SID_BYTES: u32 = 8;
    const MAX_SID_BYTES: u32 = 68;
    const MAX_ACL_BYTES: u32 = 64 * 1024;
    const MAX_ACL_ACES: u32 = 1024;
    const MAX_TOKEN_USER_BYTES: u32 = 4096;
    const MAX_PATH_COMPONENTS: usize = 64;
    const MAX_DPAPI_OUTPUT: usize = 64 * 1024;
    const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    const TRUSTED_INSTALLER_SID: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const CREATE_NEW: u32 = 1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const DRIVE_FIXED: u32 = 3;
    const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;

    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_SHARING_VIOLATION: u32 = 32;
    const ERROR_FILE_EXISTS: u32 = 80;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_NO_TOKEN: u32 = 1008;

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x0000_0001;
    const MAX_FILE_SIZE: u64 = 4096;
    pub(super) const MAGIC: &[u8; 4] = b"HSW1";
    const ENTROPY: &[u8] = b"hotspotshade-identity-v1";
    const MAX_TEMP_ATTEMPTS: usize = 16;
    /// A concurrent creator holds the final file open for a short time while
    /// it renames the temporary file into place. The open then fails with a
    /// sharing violation. Retry for at most 2 seconds, then fail closed.
    const MAX_SHARING_ATTEMPTS: u32 = 100;
    const SHARING_RETRY_DELAY: Duration = Duration::from_millis(20);

    // FOLDERID_LocalAppData.
    const FOLDERID_LOCAL_APPDATA: Guid = Guid {
        data1: 0xF1B3_2785,
        data2: 0x6FBA,
        data3: 0x4FCF,
        data4: [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91],
    };

    #[repr(C)]
    #[allow(dead_code)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: Psd,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct SidAndAttributes {
        sid: Psid,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct AclSizeInformation {
        ace_count: u32,
        acl_bytes_in_use: u32,
        acl_bytes_free: u32,
    }

    // Check the layouts that the Windows API reads through these pointers.
    const _: () = {
        assert!(mem::size_of::<Guid>() == 16);
        assert!(mem::size_of::<DataBlob>() == 2 * mem::size_of::<usize>());
        assert!(mem::size_of::<SidAndAttributes>() == 2 * mem::size_of::<usize>());
        assert!(mem::size_of::<TokenUser>() == 2 * mem::size_of::<usize>());
        assert!(mem::size_of::<AceHeader>() == 4);
        assert!(mem::size_of::<AclSizeInformation>() == 12);
        assert!(mem::size_of::<FileTime>() == 8);
        assert!(mem::size_of::<ByHandleFileInformation>() == 52);
    };
    #[cfg(target_pointer_width = "64")]
    const _: () = {
        assert!(mem::size_of::<SecurityAttributes>() == 24);
    };
    #[cfg(target_pointer_width = "32")]
    const _: () = {
        assert!(mem::size_of::<SecurityAttributes>() == 12);
    };

    #[link(name = "kernel32")]
    extern "system" {
        fn CloseHandle(handle: Handle) -> i32;
        fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            attributes: *const SecurityAttributes,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn DeleteFileW(path: *const u16) -> i32;
        fn FlushFileBuffers(handle: Handle) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetCurrentThread() -> Handle;
        fn GetFileInformationByHandle(handle: Handle, info: *mut ByHandleFileInformation) -> i32;
        fn GetDriveTypeW(root_path_name: *const u16) -> u32;
        fn GetLastError() -> u32;
        fn GetVolumeInformationByHandleW(
            file: Handle,
            volume_name: *mut u16,
            volume_name_size: u32,
            volume_serial: *mut u32,
            max_component_length: *mut u32,
            file_system_flags: *mut u32,
            file_system_name: *mut u16,
            file_system_name_size: u32,
        ) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn MoveFileExW(old: *const u16, new: *const u16, flags: u32) -> i32;
        fn ReadFile(
            handle: Handle,
            buffer: *mut u8,
            length: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn WriteFile(
            handle: Handle,
            buffer: *const u8,
            length: u32,
            written: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertSidToStringSidW(sid: Psid, string: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut Psd,
            size: *mut u32,
        ) -> i32;
        fn GetAclInformation(acl: Pacl, information: *mut c_void, length: u32, class: u32) -> i32;
        fn GetAce(acl: Pacl, index: u32, ace: *mut *mut c_void) -> i32;
        fn GetLengthSid(sid: Psid) -> u32;
        fn GetSecurityDescriptorControl(
            descriptor: Psd,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: Handle,
            object_type: u32,
            information: u32,
            owner: *mut Psid,
            group: *mut Psid,
            dacl: *mut Pacl,
            sacl: *mut Pacl,
            descriptor: *mut Psd,
        ) -> u32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            information: *mut c_void,
            length: u32,
            needed: *mut u32,
        ) -> i32;
        fn IsValidSid(sid: Psid) -> i32;
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn OpenThreadToken(
            thread: Handle,
            access: u32,
            open_as_self: i32,
            token: *mut Handle,
        ) -> i32;
        #[cfg(test)]
        fn DuplicateToken(existing: Handle, level: i32, duplicate: *mut Handle) -> i32;
        #[cfg(test)]
        fn RevertToSelf() -> i32;
        #[cfg(test)]
        fn SetThreadToken(thread: *mut Handle, token: Handle) -> i32;
        #[cfg(test)]
        fn GetSecurityDescriptorDacl(
            descriptor: Psd,
            present: *mut i32,
            dacl: *mut Pacl,
            defaulted: *mut i32,
        ) -> i32;
        #[cfg(test)]
        fn GetSecurityDescriptorOwner(
            descriptor: Psd,
            owner: *mut Psid,
            defaulted: *mut i32,
        ) -> i32;
        #[cfg(test)]
        fn SetFileSecurityW(path: *const u16, information: u32, descriptor: Psd) -> i32;
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            description: *const u16,
            entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            description: *mut *mut u16,
            entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(
            folder: *const Guid,
            flags: u32,
            token: Handle,
            path: *mut *mut u16,
        ) -> i32;
    }

    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(memory: *mut c_void);
    }

    struct HandleGuard(Handle);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 as isize != INVALID_HANDLE_VALUE {
                // Close each handle exactly once.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct SecurityDescriptor(Psd);

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // The conversion function allocates with LocalAlloc.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    /// A DPAPI output buffer. The guard erases the buffer and frees it on
    /// every path, including a failed DPAPI call that still allocated data.
    struct LocalBlob(DataBlob);

    impl LocalBlob {
        fn new() -> Self {
            Self(DataBlob {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            })
        }

        fn as_mut(&mut self) -> *mut DataBlob {
            &mut self.0
        }

        fn bytes(&self) -> Result<&[u8], PairError> {
            if self.0.pb_data.is_null() || self.0.cb_data == 0 {
                return Err(fail(IdentityStep::DpapiBlob, 0));
            }
            let length = self.0.cb_data as usize;
            if length > MAX_DPAPI_OUTPUT {
                return Err(fail(IdentityStep::DpapiBlob, 0));
            }
            Ok(unsafe { slice::from_raw_parts(self.0.pb_data, length) })
        }
    }

    impl Drop for LocalBlob {
        fn drop(&mut self) {
            if self.0.pb_data.is_null() {
                return;
            }
            let length = self.0.cb_data as usize;
            // The bounds stop a corrupt length from causing a huge erase loop.
            if length > 0 && length <= MAX_DPAPI_OUTPUT {
                unsafe {
                    wipe_raw(self.0.pb_data, length);
                }
            }
            // CryptProtectData and CryptUnprotectData allocate with LocalAlloc.
            unsafe {
                LocalFree(self.0.pb_data.cast());
            }
        }
    }

    struct TempFile {
        path: PathBuf,
        keep: bool,
    }

    impl TempFile {
        fn new(path: PathBuf) -> Self {
            Self { path, keep: false }
        }

        fn disarm(&mut self) {
            self.keep = true;
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            if !self.keep {
                let _ = delete_file(&self.path);
            }
        }
    }

    fn last_error() -> u32 {
        unsafe { GetLastError() }
    }

    /// The first failing step of the most recent load, packed. Zero is the
    /// no-failure sentinel.
    static LAST_IDENTITY_FAILURE: AtomicU64 = AtomicU64::new(0);

    /// Clear the record at the start of one load. The load then records only
    /// its own first failure.
    fn reset_identity_failure() {
        LAST_IDENTITY_FAILURE.store(0, Ordering::Release);
    }

    /// Record the first failure of the current load and return
    /// [`PairError::Identity`]. The value packs a fixed step word, a component
    /// index, and the current Win32 error. A later failure in the same load
    /// cannot overwrite the first one.
    fn fail(step: IdentityStep, index: u64) -> PairError {
        let packed = identity_failure::pack(step, index, last_error());
        let _ =
            LAST_IDENTITY_FAILURE.compare_exchange(0, packed, Ordering::Relaxed, Ordering::Relaxed);
        PairError::Identity
    }

    /// Record a refused ancestor access entry. The detail holds the reason, the
    /// entry type, and a fixed principal class word, never the SID.
    fn fail_ace(
        reason: identity_failure::AceReason,
        ace_type: u8,
        sid_class: u8,
        index: u64,
    ) -> PairError {
        let detail = identity_failure::ace_detail(reason, ace_type, sid_class);
        let packed = identity_failure::pack(IdentityStep::RemovalAce, index, detail);
        let _ =
            LAST_IDENTITY_FAILURE.compare_exchange(0, packed, Ordering::Relaxed, Ordering::Relaxed);
        PairError::Identity
    }

    /// The formatted first failure of the most recent load, or `None`.
    pub(super) fn last_identity_failure() -> Option<String> {
        identity_failure::format(LAST_IDENTITY_FAILURE.load(Ordering::Acquire))
    }

    fn wide_string(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Add the `\\?\` prefix so the Win32 calls accept long paths.
    fn wide_path(path: &Path) -> Result<Vec<u16>, PairError> {
        if !path.is_absolute() {
            return Err(fail(IdentityStep::WidePath, 0));
        }
        let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
        if raw.is_empty() || raw.contains(&0) {
            return Err(fail(IdentityStep::WidePath, 0));
        }
        const BACKSLASH: u16 = 0x5C;
        const DOT: u16 = 0x2E;
        const QUESTION: u16 = 0x3F;
        const U: u16 = 0x55;
        const N: u16 = 0x4E;
        const C: u16 = 0x43;
        let verbatim = [BACKSLASH, BACKSLASH, QUESTION, BACKSLASH];
        let device = [BACKSLASH, BACKSLASH, DOT, BACKSLASH];
        let unc = [BACKSLASH, BACKSLASH];
        let mut out = Vec::with_capacity(raw.len() + 8);
        if raw.starts_with(&verbatim) || raw.starts_with(&device) {
            out.extend_from_slice(&raw);
        } else if raw.starts_with(&unc) {
            out.extend_from_slice(&verbatim);
            out.extend_from_slice(&[U, N, C, BACKSLASH]);
            out.extend_from_slice(&raw[2..]);
        } else {
            // A drive-absolute path has the form `C:\`.
            if raw.len() < 3 || raw[1] != 0x3A || raw[2] != BACKSLASH {
                return Err(fail(IdentityStep::WidePath, 0));
            }
            out.extend_from_slice(&verbatim);
            out.extend_from_slice(&raw);
        }
        if out.len() >= 32767 {
            return Err(fail(IdentityStep::WidePath, 0));
        }
        out.push(0);
        Ok(out)
    }

    fn wide_ptr_to_string(pointer: *const u16) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0;
        // The Win32 strings end with one zero unit.
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        String::from_utf16_lossy(unsafe { slice::from_raw_parts(pointer, length) })
    }

    fn wide_ptr_to_path(pointer: *const u16) -> PathBuf {
        if pointer.is_null() {
            return PathBuf::new();
        }
        let mut length = 0;
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        let text = OsString::from_wide(unsafe { slice::from_raw_parts(pointer, length) });
        PathBuf::from(text)
    }

    fn valid_sid_text(text: &str) -> bool {
        if text.len() < 5 || text.len() > 184 {
            return false;
        }
        let mut parts = text.split('-');
        if parts.next() != Some("S") || parts.next() != Some("1") {
            return false;
        }
        let mut count = 0u32;
        for part in parts {
            if part.is_empty() || part.len() > 10 || !part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return false;
            }
            count += 1;
        }
        count > 0 && count <= MAX_SID_SUB_AUTHORITIES
    }

    /// Read the SID length from its header and reject an invalid or oversized
    /// value before any other Win32 call reads the SID.
    fn sid_length_bounded(sid: Psid, max_bytes: u32) -> Result<u32, PairError> {
        if sid.is_null() || max_bytes < MIN_SID_BYTES {
            return Err(fail(IdentityStep::Sid, 0));
        }
        let header = unsafe { slice::from_raw_parts(sid as *const u8, MIN_SID_BYTES as usize) };
        if header[0] != SID_REVISION {
            return Err(fail(IdentityStep::Sid, 0));
        }
        let count = u32::from(header[1]);
        if count == 0 || count > MAX_SID_SUB_AUTHORITIES {
            return Err(fail(IdentityStep::Sid, 0));
        }
        let length = MIN_SID_BYTES + count * 4;
        if length > MAX_SID_BYTES || length > max_bytes {
            return Err(fail(IdentityStep::Sid, 0));
        }
        if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } != length {
            return Err(fail(IdentityStep::Sid, 0));
        }
        Ok(length)
    }

    fn sid_to_string(sid: Psid, max_bytes: u32) -> Result<String, PairError> {
        sid_length_bounded(sid, max_bytes)?;
        let mut pointer: *mut u16 = ptr::null_mut();
        let result = unsafe { ConvertSidToStringSidW(sid, &mut pointer) };
        if result == 0 || pointer.is_null() {
            if !pointer.is_null() {
                unsafe {
                    LocalFree(pointer.cast());
                }
            }
            return Err(fail(IdentityStep::Sid, 0));
        }
        let text = wide_ptr_to_string(pointer);
        unsafe {
            LocalFree(pointer.cast());
        }
        if !valid_sid_text(&text) {
            return Err(fail(IdentityStep::Sid, 0));
        }
        Ok(text)
    }

    fn current_user_sid() -> Result<String, PairError> {
        let mut token: Handle = ptr::null_mut();
        // Open the token of this process. The token holds the current user SID.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
            || token.is_null()
        {
            return Err(fail(IdentityStep::CurrentUserSid, 0));
        }
        let token = HandleGuard(token);
        let mut needed = 0u32;
        // The first call reports the buffer size. It returns no data.
        unsafe {
            GetTokenInformation(token.0, TOKEN_USER, ptr::null_mut(), 0, &mut needed);
        }
        if needed < mem::size_of::<TokenUser>() as u32 || needed > MAX_TOKEN_USER_BYTES {
            return Err(fail(IdentityStep::CurrentUserSid, 0));
        }
        // A u64 buffer is aligned for the pointer and DWORD fields.
        let words = (needed as usize).div_ceil(8);
        let mut buffer = vec![0u64; words];
        if unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
            || needed > (words * 8) as u32
        {
            return Err(fail(IdentityStep::CurrentUserSid, 0));
        }
        let user = unsafe { &*(buffer.as_ptr() as *const TokenUser) };
        sid_to_string(user.user.sid, MAX_SID_BYTES)
    }

    /// Refuse to use the store while the thread carries an impersonation token.
    /// The file access check then uses an identity other than the process
    /// user, so an owner check against the process token proves nothing.
    fn reject_impersonation() -> Result<(), PairError> {
        let mut token: Handle = ptr::null_mut();
        // OpenAsSelf is TRUE so the process token can open the thread token.
        let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        let error = last_error();
        if result != 0 {
            if !token.is_null() {
                drop(HandleGuard(token));
            }
            return Err(fail(IdentityStep::RejectImpersonation, 0));
        }
        if !token.is_null() {
            drop(HandleGuard(token));
        }
        if error == ERROR_NO_TOKEN {
            Ok(())
        } else {
            Err(fail(IdentityStep::RejectImpersonation, 0))
        }
    }

    /// The principals that may remove or replace the identity store. Other
    /// principals fail closed, even when they look administrative, because
    /// the loader cannot prove their group membership.
    fn trusted_principal(sid: &str, user: &str) -> bool {
        sid == user
            || sid == LOCAL_SYSTEM_SID
            || sid == ADMINISTRATORS_SID
            || sid == TRUSTED_INSTALLER_SID
    }

    /// Return the offset of the SID in an allow ACE. The caller checked that
    /// the ACE holds a mask.
    fn allowed_ace_sid_offset(
        ace_type: u8,
        ace: *const c_void,
        length: usize,
        index: u64,
    ) -> Result<usize, PairError> {
        const OBJECT_TYPE_PRESENT: u32 = 0x1;
        const INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
        let mask_end = mem::size_of::<AceHeader>() + 4;
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => Ok(mask_end),
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                if length < mask_end + 4 {
                    return Err(fail_ace(AceReason::Malformed, ace_type, 0, index));
                }
                let flags =
                    unsafe { ptr::read_unaligned((ace as *const u8).add(mask_end) as *const u32) };
                if flags & !(OBJECT_TYPE_PRESENT | INHERITED_OBJECT_TYPE_PRESENT) != 0 {
                    return Err(fail_ace(AceReason::Malformed, ace_type, 0, index));
                }
                let mut offset = mask_end + 4;
                if flags & OBJECT_TYPE_PRESENT != 0 {
                    offset += 16;
                }
                if flags & INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    offset += 16;
                }
                if offset >= length {
                    return Err(fail_ace(AceReason::Malformed, ace_type, 0, index));
                }
                Ok(offset)
            }
            _ => Err(fail_ace(AceReason::UnknownType, ace_type, 0, index)),
        }
    }

    /// Check one ACE of an ancestor DACL. An allow entry for an untrusted
    /// principal must not hold a right that can remove, replace, or redirect
    /// the private directory. Inherit-only entries do not apply to this
    /// object; each child is checked with its own effective DACL.
    fn check_removal_ace(
        dacl: Pacl,
        ace: *mut c_void,
        acl_bytes: usize,
        user: &str,
        hazard: u32,
        index: u64,
    ) -> Result<(), PairError> {
        let offset = (ace as usize)
            .checked_sub(dacl as usize)
            .ok_or_else(|| fail_ace(AceReason::Malformed, 0, 0, index))?;
        if offset < ACL_HEADER_BYTES {
            return Err(fail_ace(AceReason::Malformed, 0, 0, index));
        }
        let bytes = ace as *const u8;
        let header = unsafe { ptr::read_unaligned(bytes as *const AceHeader) };
        let length = usize::from(header.ace_size);
        let end = offset
            .checked_add(length)
            .ok_or_else(|| fail_ace(AceReason::Malformed, header.ace_type, 0, index))?;
        if length < mem::size_of::<AceHeader>()
            || length % 4 != 0
            || offset % 4 != 0
            || end > acl_bytes
        {
            return Err(fail_ace(AceReason::Malformed, header.ace_type, 0, index));
        }
        if header.ace_flags & INHERIT_ONLY_ACE != 0 {
            return Ok(());
        }
        match header.ace_type {
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => Ok(()),
            SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE => Ok(()),
            // A central access policy, a trust label, or an access filter can
            // change the effective access outside this DACL. The loader
            // cannot prove the result, so it fails closed.
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            | SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            | SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
            | SYSTEM_ACCESS_FILTER_ACE_TYPE => {
                Err(fail_ace(AceReason::PolicyAce, header.ace_type, 0, index))
            }
            ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                if length < mem::size_of::<AceHeader>() + 4 {
                    return Err(fail_ace(AceReason::Malformed, header.ace_type, 0, index));
                }
                let mask = unsafe {
                    ptr::read_unaligned(bytes.add(mem::size_of::<AceHeader>()) as *const u32)
                };
                if mask & hazard == 0 {
                    return Ok(());
                }
                let sid_offset = allowed_ace_sid_offset(header.ace_type, ace, length, index)?;
                let sid = unsafe { bytes.add(sid_offset) as Psid };
                let sid_bytes = (length - sid_offset) as u32;
                let text = sid_to_string(sid, sid_bytes)?;
                if trusted_principal(&text, user) {
                    Ok(())
                } else {
                    Err(fail_ace(
                        AceReason::Untrusted,
                        header.ace_type,
                        identity_failure::sid_class(&text),
                        index,
                    ))
                }
            }
            // A compound ACE is obsolete and an unknown type is unprovable.
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                Err(fail_ace(AceReason::UnknownType, header.ace_type, 0, index))
            }
            _ => Err(fail_ace(AceReason::UnknownType, header.ace_type, 0, index)),
        }
    }

    fn check_removal_aces(
        dacl: Pacl,
        user: &str,
        hazard: u32,
        index: u64,
    ) -> Result<(), PairError> {
        let mut size: AclSizeInformation = unsafe { mem::zeroed() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut AclSizeInformation).cast(),
                mem::size_of::<AclSizeInformation>() as u32,
                ACL_SIZE_INFORMATION_CLASS,
            )
        } == 0
        {
            return Err(fail(IdentityStep::RemovalAces, index));
        }
        if size.ace_count > MAX_ACL_ACES
            || size.acl_bytes_in_use < ACL_HEADER_BYTES as u32
            || size.acl_bytes_in_use > MAX_ACL_BYTES
        {
            return Err(fail(IdentityStep::RemovalAces, index));
        }
        let acl_bytes = size.acl_bytes_in_use as usize;
        for ace_index in 0..size.ace_count {
            let mut ace: *mut c_void = ptr::null_mut();
            if unsafe { GetAce(dacl, ace_index, &mut ace) } == 0 || ace.is_null() {
                return Err(fail(IdentityStep::RemovalAces, index));
            }
            check_removal_ace(dacl, ace, acl_bytes, user, hazard, index)?;
        }
        Ok(())
    }

    /// Check the owner and the hazard rights of one ancestor directory. The
    /// owner can always rewrite the DACL, so an untrusted owner fails even
    /// when the current DACL looks safe.
    fn validate_ancestor_security(
        owner: Psid,
        dacl: Pacl,
        user: &str,
        root: bool,
        index: u64,
    ) -> Result<(), PairError> {
        if owner.is_null() || dacl.is_null() {
            return Err(fail(IdentityStep::AncestorSecurity, index));
        }
        let owner = sid_to_string(owner, MAX_SID_BYTES)?;
        if !trusted_principal(&owner, user) {
            return Err(fail(IdentityStep::AncestorSecurity, index));
        }
        let hazard = if root {
            ROOT_HAZARD_RIGHTS
        } else {
            ANCESTOR_HAZARD_RIGHTS
        };
        check_removal_aces(dacl, user, hazard, index)
    }

    fn security_owner_and_dacl(
        handle: Handle,
        index: u64,
    ) -> Result<(Psid, Pacl, SecurityDescriptor), PairError> {
        let mut owner: Psid = ptr::null_mut();
        let mut group: Psid = ptr::null_mut();
        let mut dacl: Pacl = ptr::null_mut();
        let mut sacl: Pacl = ptr::null_mut();
        let mut descriptor: Psd = ptr::null_mut();
        // GetSecurityInfo allocates the descriptor with LocalAlloc.
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                &mut sacl,
                &mut descriptor,
            )
        };
        let descriptor = SecurityDescriptor(descriptor);
        if result != 0 || descriptor.0.is_null() || owner.is_null() || dacl.is_null() {
            return Err(fail(IdentityStep::OwnerDacl, index));
        }
        Ok((owner, dacl, descriptor))
    }

    fn validate_ancestor_handle(
        handle: Handle,
        user: &str,
        root: bool,
        index: u64,
    ) -> Result<(), PairError> {
        let (owner, dacl, _descriptor) = security_owner_and_dacl(handle, index)?;
        validate_ancestor_security(owner, dacl, user, root, index)
    }

    /// Require a volume that stores and enforces ACLs. A FAT or exFAT volume
    /// keeps no DACL, so a private ACL on that volume proves nothing.
    fn validate_volume_acls(handle: Handle, index: u64) -> Result<(), PairError> {
        let mut flags = 0u32;
        if unsafe {
            GetVolumeInformationByHandleW(
                handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(fail(IdentityStep::VolumeAcls, index));
        }
        if flags & FILE_PERSISTENT_ACLS == 0 {
            return Err(fail(IdentityStep::VolumeAcls, index));
        }
        Ok(())
    }

    fn is_fixed_drive(letter: u8) -> bool {
        if !letter.is_ascii_alphabetic() {
            return false;
        }
        let root = [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0];
        unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_FIXED }
    }

    /// Reject a path that can redirect the identity store. The path must be
    /// absolute, name one file on a fixed local drive, and hold no parent,
    /// current, or stream component.
    fn validate_identity_path(path: &Path) -> Result<(), PairError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(fail(IdentityStep::ValidatePath, 0));
        }
        const BACKSLASH: u16 = 0x5C;
        const COLON: u16 = 0x3A;
        const DOT: u16 = 0x2E;
        const FORWARD_SLASH: u16 = 0x2F;
        const SPACE: u16 = 0x20;
        let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
        if raw.is_empty()
            || raw.contains(&0)
            || raw.contains(&FORWARD_SLASH)
            || raw.last() == Some(&BACKSLASH)
        {
            return Err(fail(IdentityStep::ValidatePath, 0));
        }
        // `Path::components` normalizes some dot and empty components. The
        // verbatim Windows path used below does not apply the same rules.
        if raw
            .split(|unit| *unit == BACKSLASH)
            .skip(1)
            .any(|part| part.is_empty() || part == [DOT] || part == [DOT, DOT])
        {
            return Err(fail(IdentityStep::ValidatePath, 0));
        }
        let mut disk: Option<u8> = None;
        let mut root_seen = false;
        let mut components = 0usize;
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => {
                    if disk.is_some() {
                        return Err(fail(IdentityStep::ValidatePath, 0));
                    }
                    match prefix.kind() {
                        Prefix::Disk(letter) => disk = Some(letter),
                        Prefix::UNC(..) | Prefix::Verbatim(..) | Prefix::DeviceNS(..) => {
                            return Err(fail(IdentityStep::ValidatePath, 0))
                        }
                        Prefix::VerbatimUNC(..) | Prefix::VerbatimDisk(..) => {
                            return Err(fail(IdentityStep::ValidatePath, 0))
                        }
                    }
                }
                Component::RootDir => {
                    if disk.is_none() || root_seen {
                        return Err(fail(IdentityStep::ValidatePath, 0));
                    }
                    root_seen = true;
                }
                Component::Normal(part) => {
                    let units: Vec<u16> = part.encode_wide().collect();
                    if units.is_empty()
                        || units.contains(&0)
                        || units.contains(&COLON)
                        || units.last() == Some(&DOT)
                        || units.last() == Some(&SPACE)
                    {
                        return Err(fail(IdentityStep::ValidatePath, 0));
                    }
                    components += 1;
                }
                Component::CurDir | Component::ParentDir => {
                    return Err(fail(IdentityStep::ValidatePath, 0))
                }
            }
        }
        if !root_seen || components == 0 || components > MAX_PATH_COMPONENTS {
            return Err(fail(IdentityStep::ValidatePath, 0));
        }
        let Some(letter) = disk else {
            return Err(fail(IdentityStep::ValidatePath, 0));
        };
        if !is_fixed_drive(letter) {
            return Err(fail(IdentityStep::ValidatePath, 0));
        }
        Ok(())
    }

    fn directory_chain(dir: &Path) -> Result<Vec<PathBuf>, PairError> {
        if !dir.is_absolute() || dir.parent().is_none() {
            return Err(fail(IdentityStep::DirectoryChain, 0));
        }
        let mut chain: Vec<PathBuf> = dir.ancestors().map(Path::to_path_buf).collect();
        chain.reverse();
        if chain.len() < 2 || chain.len() > MAX_PATH_COMPONENTS {
            return Err(fail(IdentityStep::DirectoryChain, 0));
        }
        Ok(chain)
    }

    fn private_sddl(user: &str) -> String {
        // The owner is the current user. The DACL is protected from
        // inheritance and holds one full-control entry for the current user.
        format!("O:{user}D:P(A;;FA;;;{user})")
    }

    fn security_descriptor(sddl: &str) -> Result<SecurityDescriptor, PairError> {
        let text = wide_string(sddl);
        let mut descriptor: Psd = ptr::null_mut();
        let mut size = 0u32;
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut size,
            )
        };
        let descriptor = SecurityDescriptor(descriptor);
        if result == 0 || descriptor.0.is_null() {
            return Err(fail(IdentityStep::SecurityDescriptor, 0));
        }
        Ok(descriptor)
    }

    fn private_security_descriptor(user: &str) -> Result<SecurityDescriptor, PairError> {
        security_descriptor(&private_sddl(user))
    }

    fn security_attributes(descriptor: &SecurityDescriptor) -> SecurityAttributes {
        SecurityAttributes {
            n_length: mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: descriptor.0,
            b_inherit_handle: 0,
        }
    }

    fn file_information(handle: Handle, index: u64) -> Result<ByHandleFileInformation, PairError> {
        let mut information: ByHandleFileInformation = unsafe { mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
            return Err(fail(IdentityStep::FileInformation, index));
        }
        Ok(information)
    }

    fn validate_directory_object(handle: Handle, index: u64) -> Result<(), PairError> {
        let information = file_information(handle, index)?;
        if information.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || information.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(fail(IdentityStep::DirectoryObject, index));
        }
        Ok(())
    }

    /// Check the owner, the protected DACL, and the one access entry.
    fn validate_handle(
        handle: Handle,
        directory: bool,
        user: &str,
        step: IdentityStep,
        index: u64,
    ) -> Result<ByHandleFileInformation, PairError> {
        let information = file_information(handle, index)?;
        if information.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(fail(step, index));
        }
        if (information.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
            return Err(fail(step, index));
        }
        let (owner, dacl, descriptor) = security_owner_and_dacl(handle, index)?;
        if sid_to_string(owner, MAX_SID_BYTES)? != user {
            return Err(fail(step, index));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(fail(step, index));
        }
        if revision != SDDL_REVISION_1 {
            return Err(fail(step, index));
        }
        if control & (SE_DACL_PRESENT | SE_DACL_PROTECTED) != (SE_DACL_PRESENT | SE_DACL_PROTECTED)
        {
            return Err(fail(step, index));
        }
        let mut size: AclSizeInformation = unsafe { mem::zeroed() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut AclSizeInformation).cast(),
                mem::size_of::<AclSizeInformation>() as u32,
                ACL_SIZE_INFORMATION_CLASS,
            )
        } == 0
        {
            return Err(fail(step, index));
        }
        if size.ace_count != 1
            || size.acl_bytes_in_use < ACL_HEADER_BYTES as u32
            || size.acl_bytes_in_use > MAX_ACL_BYTES
        {
            return Err(fail(step, index));
        }
        let mut ace: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(fail(step, index));
        }
        let ace_bytes = ace as *const u8;
        let ace_offset = (ace as usize)
            .checked_sub(dacl as usize)
            .ok_or_else(|| fail(step, index))?;
        let header_end = ace_offset
            .checked_add(mem::size_of::<AceHeader>())
            .ok_or_else(|| fail(step, index))?;
        if ace_offset < ACL_HEADER_BYTES || header_end > size.acl_bytes_in_use as usize {
            return Err(fail(step, index));
        }
        let header = unsafe { ptr::read_unaligned(ace_bytes as *const AceHeader) };
        if header.ace_type != ACCESS_ALLOWED_ACE_TYPE || header.ace_flags != 0 {
            return Err(fail(step, index));
        }
        let ace_size = usize::from(header.ace_size);
        let ace_prefix = mem::size_of::<AceHeader>() + 4;
        if ace_size < ace_prefix + MIN_SID_BYTES as usize
            || ace_size > size.acl_bytes_in_use as usize
        {
            return Err(fail(step, index));
        }
        let ace_end = ace_offset
            .checked_add(ace_size)
            .ok_or_else(|| fail(step, index))?;
        if ace_end > size.acl_bytes_in_use as usize {
            return Err(fail(step, index));
        }
        let mask = unsafe {
            ptr::read_unaligned(ace_bytes.add(mem::size_of::<AceHeader>()) as *const u32)
        };
        if mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS {
            return Err(fail(step, index));
        }
        let ace_sid = unsafe { ace_bytes.add(ace_prefix) as Psid };
        let ace_sid_limit = (ace_size - ace_prefix) as u32;
        if sid_to_string(ace_sid, ace_sid_limit)? != user {
            return Err(fail(step, index));
        }
        Ok(information)
    }

    fn open_directory(
        path: &Path,
        share_delete: bool,
        index: u64,
    ) -> Result<Option<Handle>, PairError> {
        let text = wide_path(path)?;
        let share =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        // Every directory needs READ_CONTROL for the owner and DACL check.
        // The volume root accepts delete sharing because it cannot be renamed
        // or removed. A lower component does not share delete, so a held handle
        // stops another process from renaming or removing that path component
        // while the store uses it. The component is opened itself, so a
        // reparse point is visible.
        let handle = unsafe {
            CreateFileW(
                text.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                share,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle as isize == INVALID_HANDLE_VALUE {
            return match last_error() {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
                _ => Err(fail(IdentityStep::AncestorOpen, index)),
            };
        }
        if handle.is_null() {
            return Err(fail(IdentityStep::AncestorOpen, index));
        }
        Ok(Some(handle))
    }

    fn create_directory(path: &Path, user: &str, index: u64) -> Result<(), PairError> {
        let descriptor = private_security_descriptor(user)?;
        let attributes = security_attributes(&descriptor);
        let text = wide_path(path)?;
        // The parent is pinned and the new directory gets the private
        // descriptor. This never repairs the ACL of an existing directory.
        if unsafe { CreateDirectoryW(text.as_ptr(), &attributes) } == 0
            && last_error() != ERROR_ALREADY_EXISTS
        {
            return Err(fail(IdentityStep::DirectoryCreate, index));
        }
        Ok(())
    }

    /// Handles for every directory between the volume root and the identity
    /// directory. The root is validated and held with delete sharing, because
    /// it cannot be renamed or removed. Each lower component is held without
    /// delete sharing, checked for a reparse point, and kept open until the
    /// load or create finishes. Every component is checked for an untrusted
    /// owner or an untrusted removal right.
    struct PinnedPath {
        _directories: Vec<HandleGuard>,
    }

    impl PinnedPath {
        fn open_or_create(dir: &Path, user: &str) -> Result<Self, PairError> {
            let chain = directory_chain(dir)?;
            let mut directories = Vec::with_capacity(chain.len());
            let mut volume_checked = false;
            for (index, path) in chain.iter().enumerate() {
                let index = index as u64;
                let root = index == 0;
                let target = index + 1 == chain.len() as u64;
                let handle = match open_directory(path, root, index)? {
                    Some(handle) => handle,
                    None => {
                        if root {
                            return Err(fail(IdentityStep::AncestorOpen, index));
                        }
                        create_directory(path, user, index)?;
                        open_directory(path, false, index)?
                            .ok_or_else(|| fail(IdentityStep::AncestorOpen, index))?
                    }
                };
                let handle = HandleGuard(handle);
                validate_directory_object(handle.0, index)?;
                if !volume_checked {
                    validate_volume_acls(handle.0, index)?;
                    volume_checked = true;
                }
                if target {
                    validate_handle(handle.0, true, user, IdentityStep::DirectoryValidate, index)?;
                } else {
                    validate_ancestor_handle(handle.0, user, root, index)?;
                }
                directories.push(handle);
            }
            Ok(Self {
                _directories: directories,
            })
        }
    }

    fn open_existing_file(path: &Path) -> Result<Option<Handle>, PairError> {
        let text = wide_path(path)?;
        let mut attempt = 1;
        loop {
            let handle = unsafe {
                CreateFileW(
                    text.as_ptr(),
                    GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            if handle as isize == INVALID_HANDLE_VALUE {
                match last_error() {
                    ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => return Ok(None),
                    // A concurrent creator can hold the new file during its
                    // rename. Wait for that handle to close. Do not widen the
                    // share mode.
                    ERROR_SHARING_VIOLATION if attempt < MAX_SHARING_ATTEMPTS => {
                        attempt += 1;
                        thread::sleep(SHARING_RETRY_DELAY);
                        continue;
                    }
                    _ => return Err(fail(IdentityStep::OpenFile, 0)),
                }
            }
            if handle.is_null() {
                return Err(fail(IdentityStep::OpenFile, 0));
            }
            return Ok(Some(handle));
        }
    }

    unsafe fn wipe_raw(pointer: *mut u8, length: usize) {
        for index in 0..length {
            // The volatile write keeps the erase operation.
            ptr::write_volatile(pointer.add(index), 0);
        }
    }

    fn wipe(bytes: &mut [u8]) {
        unsafe {
            wipe_raw(bytes.as_mut_ptr(), bytes.len());
        }
    }

    fn entropy_blob() -> DataBlob {
        DataBlob {
            cb_data: ENTROPY.len() as u32,
            pb_data: ENTROPY.as_ptr().cast_mut(),
        }
    }

    pub(super) fn protect_identity(plain: &[u8]) -> Result<Vec<u8>, PairError> {
        let entropy = entropy_blob();
        let input = DataBlob {
            cb_data: plain.len() as u32,
            pb_data: plain.as_ptr().cast_mut(),
        };
        let mut output = LocalBlob::new();
        // The default scope is the current user. Do not set
        // CRYPTPROTECT_LOCAL_MACHINE.
        if unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                output.as_mut(),
            )
        } == 0
        {
            return Err(fail(IdentityStep::Protect, 0));
        }
        let blob = output.bytes()?;
        if blob.len() > MAX_FILE_SIZE as usize - MAGIC.len() {
            return Err(fail(IdentityStep::Protect, 0));
        }
        Ok(blob.to_vec())
    }

    pub(super) fn unprotect_identity(blob: &[u8]) -> Result<[u8; 32], PairError> {
        let entropy = entropy_blob();
        let input = DataBlob {
            cb_data: blob.len() as u32,
            pb_data: blob.as_ptr().cast_mut(),
        };
        let mut output = LocalBlob::new();
        let result = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                output.as_mut(),
            )
        };
        if result == 0 {
            return Err(fail(IdentityStep::Unprotect, 0));
        }
        let plain = output.bytes()?;
        if plain.len() != 32 {
            return Err(fail(IdentityStep::Unprotect, 0));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(plain);
        Ok(key)
    }

    fn read_file(handle: Handle, length: usize) -> Result<Vec<u8>, PairError> {
        let mut bytes = vec![0u8; length];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let mut read = 0u32;
            let remaining = (bytes.len() - offset).min(u32::MAX as usize) as u32;
            if unsafe {
                ReadFile(
                    handle,
                    bytes[offset..].as_mut_ptr(),
                    remaining,
                    &mut read,
                    ptr::null_mut(),
                )
            } == 0
                || read == 0
            {
                return Err(fail(IdentityStep::ReadFile, 0));
            }
            offset += read as usize;
        }
        Ok(bytes)
    }

    fn read_identity_file(
        path: &Path,
        user: &str,
        _directories: &PinnedPath,
    ) -> Result<Option<Identity>, PairError> {
        let Some(handle) = open_existing_file(path)? else {
            return Ok(None);
        };
        let handle = HandleGuard(handle);
        let information = validate_handle(handle.0, false, user, IdentityStep::FileValidate, 0)?;
        let length = ((information.file_size_high as u64) << 32) | information.file_size_low as u64;
        if length <= MAGIC.len() as u64 || length > MAX_FILE_SIZE {
            return Err(fail(IdentityStep::FileValidate, 0));
        }
        let bytes = read_file(handle.0, length as usize)?;
        if !bytes.starts_with(MAGIC) {
            return Err(fail(IdentityStep::FileValidate, 0));
        }
        let mut key = unprotect_identity(&bytes[MAGIC.len()..])?;
        let identity = Identity::from_bytes(key);
        // The identity object owns a copied key. Erase this stack copy.
        wipe(&mut key);
        Ok(Some(identity))
    }

    fn write_file(handle: Handle, bytes: &[u8]) -> Result<(), PairError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let mut written = 0u32;
            let remaining = (bytes.len() - offset).min(u32::MAX as usize) as u32;
            if unsafe {
                WriteFile(
                    handle,
                    bytes[offset..].as_ptr(),
                    remaining,
                    &mut written,
                    ptr::null_mut(),
                )
            } == 0
                || written == 0
            {
                return Err(fail(IdentityStep::WriteFile, 0));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn delete_file(path: &Path) -> Result<(), PairError> {
        let text = wide_path(path)?;
        if unsafe { DeleteFileW(text.as_ptr()) } == 0 {
            return Err(fail(IdentityStep::DeleteFile, 0));
        }
        Ok(())
    }

    fn create_temp_file(
        dir: &Path,
        attributes: &SecurityAttributes,
    ) -> Result<(PathBuf, Handle), PairError> {
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let mut random = [0u8; 16];
            random_bytes(&mut random)?;
            let path = dir.join(format!("identity.key.tmp-{}", hex(&random)));
            let text = wide_path(&path)?;
            let handle = unsafe {
                CreateFileW(
                    text.as_ptr(),
                    GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                    0,
                    attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            if handle as isize != INVALID_HANDLE_VALUE && !handle.is_null() {
                return Ok((path, handle));
            }
            match last_error() {
                ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => continue,
                _ => return Err(fail(IdentityStep::CreateTemp, 0)),
            }
        }
        Err(fail(IdentityStep::CreateTemp, 0))
    }

    fn create_identity_file(
        path: &Path,
        user: &str,
        _directories: &PinnedPath,
    ) -> Result<Identity, PairError> {
        let dir = path.parent().ok_or_else(|| fail(IdentityStep::Parent, 0))?;
        let descriptor = private_security_descriptor(user)?;
        let attributes = security_attributes(&descriptor);

        let mut secret = [0u8; 32];
        random_bytes(&mut secret)?;
        let protected = protect_identity(&secret);
        wipe(&mut secret);
        let protected = protected?;
        let mut blob = Vec::with_capacity(MAGIC.len() + protected.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&protected);

        let (temp_path, handle) = create_temp_file(dir, &attributes)?;
        let mut temp = TempFile::new(temp_path.clone());
        let handle = HandleGuard(handle);
        // Check the private ACL before the protected key reaches the file.
        validate_handle(handle.0, false, user, IdentityStep::TempValidate, 0)?;
        let written = write_file(handle.0, &blob)
            .and_then(|_| {
                if unsafe { FlushFileBuffers(handle.0) } == 0 {
                    Err(fail(IdentityStep::Flush, 0))
                } else {
                    Ok(())
                }
            })
            .and_then(|_| {
                let information =
                    validate_handle(handle.0, false, user, IdentityStep::TempValidate, 0)?;
                let size =
                    ((information.file_size_high as u64) << 32) | information.file_size_low as u64;
                if size == blob.len() as u64 {
                    Ok(())
                } else {
                    Err(fail(IdentityStep::TempValidate, 0))
                }
            });
        drop(handle);
        written?;

        let temp_text = wide_path(&temp_path)?;
        let final_text = wide_path(path)?;
        // A rename without MOVEFILE_REPLACE_EXISTING fails when the final
        // file exists. The final path never holds a partial key. Every
        // directory component is held without delete sharing, so a rename
        // cannot redirect this call through a swapped parent.
        if unsafe {
            MoveFileExW(
                temp_text.as_ptr(),
                final_text.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let error = last_error();
            if error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS {
                // Another process created the file first. Load that file.
                drop(temp);
                return read_identity_file(path, user, _directories)?
                    .ok_or_else(|| fail(IdentityStep::Rename, 0));
            }
            return Err(fail(IdentityStep::Rename, 0));
        }
        temp.disarm();
        read_identity_file(path, user, _directories)?.ok_or_else(|| fail(IdentityStep::Rename, 0))
    }

    pub(super) fn default_path() -> Result<PathBuf, PairError> {
        reset_identity_failure();
        let mut pointer: *mut u16 = ptr::null_mut();
        // The known folder is independent of the environment. A forged
        // LOCALAPPDATA value cannot redirect the key file.
        let result = unsafe {
            SHGetKnownFolderPath(&FOLDERID_LOCAL_APPDATA, 0, ptr::null_mut(), &mut pointer)
        };
        if result < 0 || pointer.is_null() {
            if !pointer.is_null() {
                // SHGetKnownFolderPath allocates with CoTaskMemAlloc.
                unsafe {
                    CoTaskMemFree(pointer.cast());
                }
            }
            return Err(fail(IdentityStep::DefaultPath, 0));
        }
        let folder = wide_ptr_to_path(pointer);
        // The known folder API allocates with CoTaskMemAlloc.
        unsafe {
            CoTaskMemFree(pointer.cast());
        }
        if folder.as_os_str().is_empty() || !folder.is_absolute() {
            return Err(fail(IdentityStep::DefaultPath, 0));
        }
        Ok(folder.join("hotspotshade").join("identity.key"))
    }

    pub(super) fn load_or_create(path: &Path) -> Result<Identity, PairError> {
        reset_identity_failure();
        validate_identity_path(path)?;
        reject_impersonation()?;
        let dir = path.parent().ok_or_else(|| fail(IdentityStep::Parent, 0))?;
        let user = current_user_sid()?;
        // Validate every directory on the path on every load. The handles pin
        // the path and reject a directory or intermediate reparse point. The
        // ancestor check rejects every untrusted removal or ownership right
        // that could outlive the handles.
        let directories = PinnedPath::open_or_create(dir, &user)?;
        if let Some(identity) = read_identity_file(path, &user, &directories)? {
            return Ok(identity);
        }
        create_identity_file(path, &user, &directories)
    }

    #[cfg(test)]
    pub(super) fn test_current_user_sid() -> Result<String, PairError> {
        current_user_sid()
    }

    #[cfg(test)]
    pub(super) fn test_reject_impersonation() -> Result<(), PairError> {
        reject_impersonation()
    }

    /// Run `body` on this thread with an impersonation token that names the
    /// same user. The loader must refuse the store anyway, because it cannot
    /// tie the file access check to the process token.
    #[cfg(test)]
    pub(super) fn test_with_impersonation<T>(body: impl FnOnce() -> T) -> T {
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe {
                    RevertToSelf();
                }
            }
        }
        let mut process_token: Handle = ptr::null_mut();
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                &mut process_token,
            )
        };
        assert_ne!(opened, 0, "open the process token");
        let process_token = HandleGuard(process_token);
        let mut thread_token: Handle = ptr::null_mut();
        // 2 is SecurityImpersonation.
        assert_ne!(
            unsafe { DuplicateToken(process_token.0, 2, &mut thread_token) },
            0,
            "duplicate the process token"
        );
        assert!(!thread_token.is_null());
        let thread_token = HandleGuard(thread_token);
        assert_ne!(
            unsafe { SetThreadToken(ptr::null_mut(), thread_token.0) },
            0,
            "set the thread token"
        );
        let _revert = Revert;
        body()
    }

    /// Check an ancestor security descriptor from SDDL. The test helper uses
    /// the same scan as a live directory handle.
    #[cfg(test)]
    pub(super) fn test_ancestor_acl(sddl: &str) -> Result<(), PairError> {
        test_ancestor_acl_for(sddl, false)
    }

    #[cfg(test)]
    pub(super) fn test_root_acl(sddl: &str) -> Result<(), PairError> {
        test_ancestor_acl_for(sddl, true)
    }

    #[cfg(test)]
    fn test_ancestor_acl_for(sddl: &str, root: bool) -> Result<(), PairError> {
        let user = current_user_sid()?;
        let descriptor = security_descriptor(sddl)?;
        let mut owner: Psid = ptr::null_mut();
        let mut owner_defaulted = 0i32;
        if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut owner_defaulted) }
            == 0
        {
            return Err(PairError::Identity);
        }
        let mut dacl: Pacl = ptr::null_mut();
        let mut present = 0i32;
        let mut dacl_defaulted = 0i32;
        if unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut dacl_defaulted)
        } == 0
            || present == 0
        {
            return Err(PairError::Identity);
        }
        validate_ancestor_security(owner, dacl, &user, root, 0)
    }

    #[cfg(test)]
    pub(super) fn test_set_acl(path: &Path, sddl: &str) -> Result<(), PairError> {
        let descriptor = security_descriptor(sddl)?;
        let text = wide_path(path)?;
        if unsafe { SetFileSecurityW(text.as_ptr(), DACL_SECURITY_INFORMATION, descriptor.0) } == 0
        {
            return Err(PairError::Identity);
        }
        Ok(())
    }
}

/// Lower-case hex. Use it for public values only.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// C = SHA256("hotspotshade-commit-v1" || L_e || L_s).
pub fn commitment(l_e: &[u8; 32], l_s: &[u8; 32]) -> [u8; 32] {
    sha256(&[COMMIT_LABEL, l_e, l_s])
}

/// h = SHA256("hotspotshade-pair-v1" || L_s || L_e || P_e).
pub fn transcript_hash(l_s: &[u8; 32], l_e: &[u8; 32], p_e: &[u8; 32]) -> [u8; 32] {
    sha256(&[PAIR_LABEL, l_s, l_e, p_e])
}

/// One X25519 agreement. Reject a low-order (non-contributory) result.
pub fn agree(secret: &StaticSecret, public: &[u8; 32]) -> Result<[u8; 32], PairError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(PairError::LowOrder);
    }
    Ok(shared.to_bytes())
}

/// The session keys from the key schedule.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub h: [u8; 32],
    pub k_enc: [u8; 32],
    pub k_proof: [u8; 32],
    pub sas: [u8; 4],
}
impl Drop for SessionKeys {
    fn drop(&mut self) {
        for byte in self
            .h
            .iter_mut()
            .chain(self.k_enc.iter_mut())
            .chain(self.k_proof.iter_mut())
            .chain(self.sas.iter_mut())
        {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}
impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeys([redacted])")
    }
}

/// prk = HKDF-Extract(h, ee || es). Expand "enc", "proof", and "sas".
pub fn derive_keys(ee: &[u8; 32], es: &[u8; 32], h: [u8; 32]) -> SessionKeys {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ee);
    ikm[32..].copy_from_slice(es);
    let hk = Hkdf::<Sha256>::new(Some(&h), &ikm[..]);
    let mut keys = SessionKeys {
        h,
        k_enc: [0; 32],
        k_proof: [0; 32],
        sas: [0; 4],
    };
    // These lengths are far below the HKDF limit. Expand cannot fail.
    hk.expand(b"enc", &mut keys.k_enc).expect("hkdf length");
    hk.expand(b"proof", &mut keys.k_proof).expect("hkdf length");
    hk.expand(b"sas", &mut keys.sas).expect("hkdf length");
    keys
}

/// Six decimal digits: u32 big-endian of the SAS bytes, modulo 1000000.
pub fn sas_code(sas: &[u8; 4]) -> String {
    format!("{:06}", u32::from_be_bytes(*sas) % 1_000_000)
}

/// Show the code as two groups of three digits, for example "482 193".
pub fn format_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_owned()
    }
}

type HmacSha256 = Hmac<Sha256>;

/// proof = HMAC-SHA256(k_proof, b"laptop" || h). The `"laptop"` label is a
/// wire constant. Change it only with the source device app and both vectors.
pub fn laptop_proof(keys: &SessionKeys) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.k_proof).expect("hmac key");
    mac.update(b"laptop");
    mac.update(&keys.h);
    mac.finalize().into_bytes().into()
}

/// Check a proof in constant time.
pub fn verify_proof(keys: &SessionKeys, proof: &[u8]) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.k_proof).expect("hmac key");
    mac.update(b"laptop");
    mac.update(&keys.h);
    mac.verify_slice(proof).is_ok()
}

/// RESULT plaintext: [port:u16][token_len:u8][token][host_len:u8][host].
pub fn encode_credentials(credentials: &PhoneCredentials) -> Result<Vec<u8>, PairError> {
    let token = credentials.token.as_bytes();
    let host = credentials.host.to_string();
    if token.is_empty() || token.len() > 255 || credentials.port == 0 {
        return Err(PairError::Protocol);
    }
    let mut out = Vec::with_capacity(4 + token.len() + host.len());
    out.extend_from_slice(&credentials.port.to_be_bytes());
    out.push(token.len() as u8);
    out.extend_from_slice(token);
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    Ok(out)
}

/// Parse the RESULT plaintext. Every length must match exactly.
pub fn decode_credentials(bytes: &[u8]) -> Result<PhoneCredentials, PairError> {
    if bytes.len() < 3 {
        return Err(PairError::Protocol);
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let token_len = bytes[2] as usize;
    if port == 0 || token_len == 0 || bytes.len() < 3 + token_len + 1 {
        return Err(PairError::Protocol);
    }
    let token = &bytes[3..3 + token_len];
    let host_len = bytes[3 + token_len] as usize;
    let host_start = 4 + token_len;
    if host_len == 0 || bytes.len() != host_start + host_len {
        return Err(PairError::Protocol);
    }
    // The token is printable ASCII. It goes into a SOCKS5 password field.
    if !token.iter().all(|b| b.is_ascii_graphic()) {
        return Err(PairError::Protocol);
    }
    let token = std::str::from_utf8(token).map_err(|_| PairError::Protocol)?;
    let host = std::str::from_utf8(&bytes[host_start..])
        .map_err(|_| PairError::Protocol)?
        .parse::<Ipv4Addr>()
        .map_err(|_| PairError::Protocol)?;
    Ok(PhoneCredentials {
        host,
        port,
        token: token.to_owned(),
    })
}

/// Encrypt the credentials with key k_enc, the given nonce, and aad h.
pub fn seal_credentials(
    keys: &SessionKeys,
    nonce: &[u8; 12],
    credentials: &PhoneCredentials,
) -> Result<Vec<u8>, PairError> {
    let plaintext = Zeroizing::new(encode_credentials(credentials)?);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &plaintext,
                aad: &keys.h,
            },
        )
        .map_err(|_| PairError::Protocol)
}

/// Decrypt and parse the credentials.
pub fn open_credentials(
    keys: &SessionKeys,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<PhoneCredentials, PairError> {
    if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
        return Err(PairError::Protocol);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &keys.h,
                },
            )
            .map_err(|_| PairError::Decrypt)?,
    );
    decode_credentials(&plaintext)
}

pub fn encode_hello(l_s: &[u8; 32], commit: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_LEN);
    out.extend_from_slice(&[MSG_HELLO, VERSION]);
    out.extend_from_slice(l_s);
    out.extend_from_slice(commit);
    out
}

/// Parse HELLO. Return (L_s, C).
pub fn decode_hello(message: &[u8]) -> Result<([u8; 32], [u8; 32]), PairError> {
    if !(message.len() == HELLO_LEN || (message.len() == HELLO_LEN + 1 && message[66] & !3 == 0))
        || message[0] != MSG_HELLO
        || message[1] != VERSION
    {
        return Err(PairError::Protocol);
    }
    Ok((array32(&message[2..34]), array32(&message[34..66])))
}

pub fn encode_challenge(p_e: &[u8; 32], known: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHALLENGE_LEN);
    out.push(MSG_CHALLENGE);
    out.extend_from_slice(p_e);
    out.push(u8::from(known));
    out
}

/// What the phone sent after HELLO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeOrResult {
    Challenge { p_e: [u8; 32], known: bool },
    Result(ResultMessage),
}

/// Parse CHALLENGE. The phone can also send RESULT with a non-zero status
/// in its place, for example when it is busy.
pub fn decode_challenge(message: &[u8]) -> Result<ChallengeOrResult, PairError> {
    if message.first() == Some(&MSG_RESULT) {
        let result = decode_result(message)?;
        if matches!(result, ResultMessage::Ok { .. }) {
            return Err(PairError::Protocol);
        }
        return Ok(ChallengeOrResult::Result(result));
    }
    if message.len() != CHALLENGE_LEN || message[0] != MSG_CHALLENGE || message[33] > 1 {
        return Err(PairError::Protocol);
    }
    Ok(ChallengeOrResult::Challenge {
        p_e: array32(&message[1..33]),
        known: message[33] == 1,
    })
}

pub fn encode_reveal(l_e: &[u8; 32], proof: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(REVEAL_LEN);
    out.push(MSG_REVEAL);
    out.extend_from_slice(l_e);
    out.extend_from_slice(proof);
    out
}

/// Parse REVEAL. Return (L_e, proof).
pub fn decode_reveal(message: &[u8]) -> Result<([u8; 32], [u8; 32]), PairError> {
    if message.len() != REVEAL_LEN || message[0] != MSG_REVEAL {
        return Err(PairError::Protocol);
    }
    Ok((array32(&message[1..33]), array32(&message[33..65])))
}

/// A parsed RESULT message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultMessage {
    Ok {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
    Status(PhoneStatus),
}

pub fn encode_result_ok(nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&[MSG_RESULT, PhoneStatus::Ok as u8]);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

pub fn encode_result_status(status: PhoneStatus) -> Vec<u8> {
    vec![MSG_RESULT, status as u8]
}

pub fn decode_result(message: &[u8]) -> Result<ResultMessage, PairError> {
    if message.len() < 2 || message[0] != MSG_RESULT {
        return Err(PairError::Protocol);
    }
    let status = PhoneStatus::from_byte(message[1]).ok_or(PairError::Protocol)?;
    if status != PhoneStatus::Ok {
        if message.len() != 2 {
            return Err(PairError::Protocol);
        }
        return Ok(ResultMessage::Status(status));
    }
    // The smallest plaintext is 2 + 1 + 1 + 1 + 7 bytes ("1.1.1.1").
    if message.len() < 2 + NONCE_LEN + TAG_LEN + 12 {
        return Err(PairError::Protocol);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&message[2..14]);
    Ok(ResultMessage::Ok {
        nonce,
        ciphertext: message[14..].to_vec(),
    })
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

/// Prefix the payload with its u16 big-endian length.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, PairError> {
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(PairError::Protocol);
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Collect frames from a byte stream. Reject an empty or oversize frame.
#[derive(Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
}
impl FrameReader {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }
    /// Return the next complete frame, None if more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, PairError> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(PairError::Protocol);
        }
        if self.buffer.len() < 2 + length {
            return Ok(None);
        }
        let payload = self.buffer[2..2 + length].to_vec();
        self.buffer.drain(..2 + length);
        Ok(Some(payload))
    }
}

/// The source device prompt window after REVEAL while its app is active, in
/// seconds. Keep it equal to `DECISION_SECONDS` in `source_pairing.rs`,
/// `decisionSeconds` in `ios/HotspotProxy/Pairing.swift`, and
/// `DECISION_MILLIS` in the Android `PairingResponder.kt`.
pub const SOURCE_DECISION_SECONDS: u64 = 60;
/// The source device prompt window while its app is inactive, in seconds. A
/// prompt that starts while the app is inactive gets this window. The first
/// inactive notice for a live prompt extends it to at most this long after
/// that notice. Keep it equal to `INACTIVE_DECISION_SECONDS` in
/// `source_pairing.rs`, `inactiveDecisionSeconds` in the iOS app, and
/// `INACTIVE_DECISION_MILLIS` in the Android app.
pub const SOURCE_INACTIVE_DECISION_SECONDS: u64 = 120;
/// The longest time that a source device can keep one prompt open after
/// REVEAL. A prompt can start while the app is inactive (120 seconds), and the
/// first inactive notice can arrive just before that deadline and add up to
/// 120 seconds after the notice. An active start with a late inactive notice
/// gives at most 60 + 120 seconds, which is shorter.
pub const SOURCE_MAX_DECISION_SECONDS: u64 =
    SOURCE_INACTIVE_DECISION_SECONDS + SOURCE_INACTIVE_DECISION_SECONDS;
/// Extra time after the longest source window for the RESULT frame to cross
/// the hotspot link.
const RESULT_MARGIN_SECONDS: u64 = 2;

/// Timeouts for one pairing. Every phase is bounded, and the cancel flag stops
/// a wait within about 100 ms.
///
/// The RESULT wait covers the longest source device prompt window. If the
/// target device stopped waiting earlier, a person could approve the prompt
/// after the target device closed the connection. A source device that misses
/// the close could then add trust for a pairing that the target device already
/// reported as failed. A silent source device can hold the GUI for at most
/// about 246 seconds, or 247 seconds on Windows; the person can cancel at any
/// time.
#[derive(Clone, Copy, Debug)]
pub struct PairTimeouts {
    pub connect: Duration,
    /// From HELLO to CHALLENGE.
    pub challenge: Duration,
    /// From REVEAL to RESULT. It covers [`SOURCE_MAX_DECISION_SECONDS`].
    pub result: Duration,
}
/// The connect bound for one pairing listener connection.
///
/// Windows reports a refused connect only after it retries the SYN that the
/// peer reset. That took about 2 seconds on loopback on Windows Server 2025
/// build 26100. A 2-second bound there reports a closed listener as a timeout
/// (`not_responding`) instead of a refusal (`not_running`). Windows therefore
/// gets 3 seconds. macOS and Linux report the reset at once and keep 2
/// seconds.
#[cfg(windows)]
pub(crate) const LISTENER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(not(windows))]
pub(crate) const LISTENER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

impl Default for PairTimeouts {
    fn default() -> Self {
        Self {
            connect: LISTENER_CONNECT_TIMEOUT,
            challenge: Duration::from_secs(2),
            result: Duration::from_secs(SOURCE_MAX_DECISION_SECONDS + RESULT_MARGIN_SECONDS),
        }
    }
}

fn read_frame(
    stream: &mut TcpStream,
    reader: &mut FrameReader,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, PairError> {
    let mut buffer = [0u8; 600];
    loop {
        if let Some(frame) = reader.next_frame()? {
            return Ok(frame);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(PairError::Cancelled);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(PairError::TimedOut);
        }
        // Wake up often to check the cancel flag.
        stream
            .set_read_timeout(Some(left.min(Duration::from_millis(100))))
            .map_err(|_| PairError::Io)?;
        match stream.read(&mut buffer) {
            // The phone closed the connection before it answered.
            Ok(0) => return Err(PairError::Io),
            Ok(n) => reader.push(&buffer[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(PairError::Io),
        }
    }
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), PairError> {
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| PairError::Io)?;
    stream
        .write_all(&frame(payload)?)
        .map_err(|_| PairError::Io)
}

/// Pair with the phone at `host` on [`PAIRING_PORT`]. The socket comes from
/// the normalized helpers (TTL 65, pinned to `iface`). Call `on_code` with
/// the formatted code ("482 193") when it is known, before the phone user
/// decides. Return the phone proxy credentials.
pub fn pair(
    host: Ipv4Addr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
    on_code: impl FnMut(&str),
) -> Result<PhoneCredentials, PairError> {
    pair_at(
        SocketAddr::V4(SocketAddrV4::new(host, PAIRING_PORT)),
        identity,
        iface,
        audit,
        cancel,
        PairTimeouts::default(),
        on_code,
    )
}

/// Pair with the phone at `address`. Tests use a loopback address.
pub fn pair_at(
    address: SocketAddr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
    timeouts: PairTimeouts,
    mut on_code: impl FnMut(&str),
) -> Result<PhoneCredentials, PairError> {
    let mut stream = normalization::tcp_connect_cancellable(
        address,
        iface,
        audit,
        timeouts.connect,
        Some(cancel),
    )
    .map_err(|e| match e.kind() {
        io::ErrorKind::Interrupted => PairError::Cancelled,
        io::ErrorKind::TimedOut => PairError::TimedOut,
        _ => PairError::Unreachable,
    })?;
    let _ = stream.set_nodelay(true);
    let result = run_client(
        &mut stream,
        address,
        identity,
        cancel,
        timeouts,
        &mut on_code,
    );
    let _ = stream.shutdown(std::net::Shutdown::Both);
    result
}

fn run_client(
    stream: &mut TcpStream,
    address: SocketAddr,
    identity: &Identity,
    cancel: &AtomicBool,
    timeouts: PairTimeouts,
    on_code: &mut dyn FnMut(&str),
) -> Result<PhoneCredentials, PairError> {
    let l_s = identity.public();
    let ephemeral = new_secret()?;
    let l_e = PublicKey::from(&ephemeral).to_bytes();
    let mut reader = FrameReader::default();
    write_frame(stream, &encode_hello(&l_s, &commitment(&l_e, &l_s)))?;
    let message = read_frame(
        stream,
        &mut reader,
        Instant::now() + timeouts.challenge,
        cancel,
    )?;
    let p_e = match decode_challenge(&message)? {
        ChallengeOrResult::Challenge { p_e, .. } => p_e,
        ChallengeOrResult::Result(ResultMessage::Status(status)) => {
            return Err(PairError::Phone(status))
        }
        ChallengeOrResult::Result(ResultMessage::Ok { .. }) => return Err(PairError::Protocol),
    };
    let ee = Zeroizing::new(agree(&ephemeral, &p_e)?);
    let es = Zeroizing::new(agree(&identity.secret, &p_e)?);
    let keys = derive_keys(&ee, &es, transcript_hash(&l_s, &l_e, &p_e));
    write_frame(stream, &encode_reveal(&l_e, &laptop_proof(&keys)))?;
    on_code(&format_code(&sas_code(&keys.sas)));
    let message = read_frame(
        stream,
        &mut reader,
        Instant::now() + timeouts.result,
        cancel,
    )?;
    match decode_result(&message)? {
        ResultMessage::Status(status) => Err(PairError::Phone(status)),
        ResultMessage::Ok { nonce, ciphertext } => {
            let credentials = open_credentials(&keys, &nonce, &ciphertext)?;
            // The source device must name the address that the target device
            // paired with.
            if address.ip() != std::net::IpAddr::V4(credentials.host) {
                return Err(PairError::Protocol);
            }
            Ok(credentials)
        }
    }
}

/// A verified status from the phone. It contains no proxy token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhoneInfo {
    pub proxy_running: bool,
    pub foreground: bool,
    pub connections: u16,
    pub port: u16,
    pub host: String,
}

/// What one authenticated status answer did to the stored port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortUpdate {
    /// The stored port is still the phone port.
    Unchanged,
    /// The phone has a new port. The stored port now holds it.
    PortChanged { old: u16, new: u16 },
    /// The status did not name the gateway or a usable port.
    Rejected,
}

/// The fixed target-device text when the source device changes its port while
/// the tunnel runs. A running tunnel keeps its start port.
pub const PORT_CHANGED_MESSAGE: &str =
    "The source device changed its port. Turn the tunnel off and on.";

/// Update the stored proxy port from an authenticated phone status.
///
/// The caller must pass a status that came from the pairing channel. The
/// function changes the port only when the status names the gateway and a
/// usable port. It never changes the token or the host. Port 18090 is reserved
/// for pairing and is rejected.
pub fn learn_phone_info(
    credentials: &mut PhoneCredentials,
    gateway: Ipv4Addr,
    info: &PhoneInfo,
) -> PortUpdate {
    let Ok(host) = info.host.parse::<Ipv4Addr>() else {
        return PortUpdate::Rejected;
    };
    if host != gateway {
        return PortUpdate::Rejected;
    }
    if info.port < 1024 || info.port == PAIRING_PORT {
        return PortUpdate::Rejected;
    }
    if info.port == credentials.port {
        return PortUpdate::Unchanged;
    }
    let old = credentials.port;
    credentials.port = info.port;
    PortUpdate::PortChanged {
        old,
        new: info.port,
    }
}

/// Ask a trusted source device for status over a normalized outer socket.
pub fn status(
    host: Ipv4Addr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<PhoneInfo, PairError> {
    status_at(
        SocketAddr::V4(SocketAddrV4::new(host, PAIRING_PORT)),
        identity,
        iface,
        audit,
        cancel,
    )
}

pub(crate) fn status_at(
    address: SocketAddr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<PhoneInfo, PairError> {
    match authenticated_command(address, identity, iface, audit, cancel, false)? {
        CommandAnswer::Status(info) => Ok(info),
        CommandAnswer::Forget(_) => Err(PairError::Protocol),
    }
}

/// Ask the source device app whether it trusts this target device when the
/// target device holds no credentials. Send one status-only HELLO. The source
/// device app answers an unknown target device with RESULT status Rejected.
///
/// `Ok(Some(known))` means that the app answered with CHALLENGE and reported
/// whether it still trusts this target key. `Ok(None)` means that the app
/// answered Rejected, so this key is not trusted. A silent, refused, or
/// invalid answer is an error. The caller keeps its existing `not_responding`
/// and `not_running` states for those errors.
pub fn probe_unpaired(
    host: Ipv4Addr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<Option<bool>, PairError> {
    probe_unpaired_at(
        SocketAddr::V4(SocketAddrV4::new(host, PAIRING_PORT)),
        identity,
        iface,
        audit,
        cancel,
    )
}

/// The test address form of [`probe_unpaired`].
pub(crate) fn probe_unpaired_at(
    address: SocketAddr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<Option<bool>, PairError> {
    let mut stream = normalization::tcp_connect_cancellable(
        address,
        iface,
        audit,
        LISTENER_CONNECT_TIMEOUT,
        Some(cancel),
    )
    .map_err(|e| match e.kind() {
        io::ErrorKind::Interrupted => PairError::Cancelled,
        io::ErrorKind::TimedOut => PairError::TimedOut,
        _ => PairError::Unreachable,
    })?;
    // The connect has its own bound, `LISTENER_CONNECT_TIMEOUT`. The
    // exchange gets a full 2 seconds after the connect, so a slow hotspot
    // link does not leave the handshake with no time.
    let deadline = Instant::now() + Duration::from_secs(2);
    let l_s = identity.public();
    let ephemeral = new_secret()?;
    let l_e = PublicKey::from(&ephemeral).to_bytes();
    let mut hello = encode_hello(&l_s, &commitment(&l_e, &l_s));
    // Bit 0 asks for status only. This is the same flag that a status request
    // for a paired target device uses.
    hello.push(1);
    write_frame(&mut stream, &hello)?;
    let message = read_frame(&mut stream, &mut FrameReader::default(), deadline, cancel)?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    match decode_challenge(&message)? {
        // The app answered with a challenge. The `known` byte says whether the
        // app still trusts this target key. It is not a pairing request.
        ChallengeOrResult::Challenge { known, .. } => Ok(Some(known)),
        // The app does not know this target device. It holds no trust for it.
        ChallengeOrResult::Result(ResultMessage::Status(PhoneStatus::Rejected)) => Ok(None),
        ChallengeOrResult::Result(ResultMessage::Status(status)) => Err(PairError::Phone(status)),
        ChallengeOrResult::Result(ResultMessage::Ok { .. }) => Err(PairError::Protocol),
    }
}

/// The answer that a peer gave to one FORGET attempt.
///
/// Protocol v1 gives the source device no static key, and the source device
/// sends its FORGET answer as a plaintext RESULT. A host that answers on the
/// pairing port, or a host on the path, can send each of these answers while
/// the real source device still trusts this target device key. No variant
/// proves that the source device removed the key. A caller must not report
/// remote deletion from any of them. It can report that the peer answered and
/// that the removal is not verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgetReply {
    /// The peer sent CHALLENGE with known = 1, the target device sent the
    /// sealed FORGET, and the peer answered with the exact plaintext RESULT
    /// Ok. A real source device sends this after it removes the key.
    Acknowledged,
    /// The peer said before the handshake that it does not trust this key:
    /// CHALLENGE with known = 0, or RESULT Rejected. The target device sent no
    /// FORGET command.
    ReportedUnknown,
    /// The peer answered the sealed FORGET with the exact plaintext RESULT
    /// Rejected. A real source device also sends this when it cannot open the
    /// command, so this answer does not show that the key is gone.
    Rejected,
}

/// Send one FORGET to the source device and report what the peer answered.
///
/// `Ok` means only that a peer answered in a valid v1 form. See
/// [`ForgetReply`]: no answer proves remote deletion.
pub fn forget_attempt(
    host: Ipv4Addr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<ForgetReply, PairError> {
    forget_attempt_at(
        SocketAddr::V4(SocketAddrV4::new(host, PAIRING_PORT)),
        identity,
        iface,
        audit,
        cancel,
    )
}

/// Send one FORGET and return `Ok` only for a proof of remote deletion.
///
/// Protocol v1 cannot prove remote deletion (see [`ForgetReply`]), so this
/// function never returns `Ok`. A valid answer from a peer gives
/// [`PairError::Unconfirmed`]. A transport or protocol failure gives its own
/// error. A caller that wants to tell an unverified answer from no answer uses
/// [`forget_attempt`].
pub fn forget(
    host: Ipv4Addr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<(), PairError> {
    forget_at(
        SocketAddr::V4(SocketAddrV4::new(host, PAIRING_PORT)),
        identity,
        iface,
        audit,
        cancel,
    )
}

fn forget_at(
    address: SocketAddr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<(), PairError> {
    forget_attempt_at(address, identity, iface, audit, cancel)?;
    Err(PairError::Unconfirmed)
}

fn forget_attempt_at(
    address: SocketAddr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
) -> Result<ForgetReply, PairError> {
    match authenticated_command(address, identity, iface, audit, cancel, true)? {
        CommandAnswer::Forget(reply) => Ok(reply),
        CommandAnswer::Status(_) => Err(PairError::Protocol),
    }
}

/// The answer to one authenticated status or forget command.
enum CommandAnswer {
    Status(PhoneInfo),
    Forget(ForgetReply),
}

fn authenticated_command(
    address: SocketAddr,
    identity: &Identity,
    iface: Option<u32>,
    audit: &normalization::Audit,
    cancel: &AtomicBool,
    forget: bool,
) -> Result<CommandAnswer, PairError> {
    let mut stream = normalization::tcp_connect_cancellable(
        address,
        iface,
        audit,
        LISTENER_CONNECT_TIMEOUT,
        Some(cancel),
    )
    .map_err(|e| match e.kind() {
        io::ErrorKind::Interrupted => PairError::Cancelled,
        io::ErrorKind::TimedOut => PairError::TimedOut,
        _ => PairError::Unreachable,
    })?;
    // The connect has its own bound, `LISTENER_CONNECT_TIMEOUT`. The
    // exchange gets a full 2 seconds after the connect, so a slow hotspot
    // link does not leave the handshake with no time.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut reader = FrameReader::default();
    let l_s = identity.public();
    let ephemeral = new_secret()?;
    let l_e = PublicKey::from(&ephemeral).to_bytes();
    let mut hello = encode_hello(&l_s, &commitment(&l_e, &l_s));
    hello.push(if forget { 2 } else { 1 });
    write_frame(&mut stream, &hello)?;
    let message = read_frame(&mut stream, &mut reader, deadline, cancel)?;
    let p_e = match decode_challenge(&message)? {
        ChallengeOrResult::Challenge { p_e, known: true } => p_e,
        // The peer says that it does not trust this key. The answer is
        // plaintext and unauthenticated, so it is not proof that the source
        // device removed the key. Report the claim and send no command.
        ChallengeOrResult::Challenge { known: false, .. } if forget => {
            return Ok(CommandAnswer::Forget(ForgetReply::ReportedUnknown))
        }
        ChallengeOrResult::Challenge { known: false, .. } => {
            return Err(PairError::Phone(PhoneStatus::Rejected))
        }
        ChallengeOrResult::Result(ResultMessage::Status(PhoneStatus::Rejected)) if forget => {
            return Ok(CommandAnswer::Forget(ForgetReply::ReportedUnknown))
        }
        ChallengeOrResult::Result(ResultMessage::Status(s)) => return Err(PairError::Phone(s)),
        _ => return Err(PairError::Protocol),
    };
    let ee = Zeroizing::new(agree(&ephemeral, &p_e)?);
    let es = Zeroizing::new(agree(&identity.secret, &p_e)?);
    let keys = derive_keys(&ee, &es, transcript_hash(&l_s, &l_e, &p_e));
    write_frame(&mut stream, &encode_reveal(&l_e, &laptop_proof(&keys)))?;
    let mut challenge = [0u8; 16];
    let mut nonce = [0u8; 12];
    random_bytes(&mut challenge)?;
    random_bytes(&mut nonce)?;
    let mut plain = if forget {
        Vec::new()
    } else {
        challenge.to_vec()
    };
    if !forget {
        plain.push(0);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &keys.h,
            },
        )
        .map_err(|_| PairError::Protocol)?;
    let mut request = vec![if forget { 0x07 } else { 0x05 }];
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&ciphertext);
    write_frame(&mut stream, &request)?;
    let answer = read_frame(&mut stream, &mut reader, deadline, cancel)?;
    if forget {
        // Protocol v1 answers FORGET with a plaintext RESULT and no sealed
        // part. Any peer can send it, so the answer is an unauthenticated claim
        // and never proof of remote deletion. Accept only the two exact forms
        // that a source device sends.
        if answer == [MSG_RESULT, PhoneStatus::Ok as u8] {
            return Ok(CommandAnswer::Forget(ForgetReply::Acknowledged));
        }
        if answer == [MSG_RESULT, PhoneStatus::Rejected as u8] {
            return Ok(CommandAnswer::Forget(ForgetReply::Rejected));
        }
        return Err(PairError::Protocol);
    }
    // The source device can reject the status request after the handshake, for
    // example when it removed this target device from its trust list. RESULT
    // status Rejected is a valid answer. Report it as a phone status and not as
    // a protocol error.
    if answer.first() == Some(&MSG_RESULT) {
        return match decode_result(&answer)? {
            ResultMessage::Status(status) => Err(PairError::Phone(status)),
            ResultMessage::Ok { .. } => Err(PairError::Protocol),
        };
    }
    if answer.len() < 56 || answer[0] != 0x06 {
        return Err(PairError::Protocol);
    }
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&answer[1..13]),
            Payload {
                msg: &answer[13..],
                aad: &keys.h,
            },
        )
        .map_err(|_| PairError::Decrypt)?;
    if plain.len() < 27
        || plain.len() > 48
        || plain[..16] != challenge
        || plain[20] > 1
        || plain[21] > 1
        || plain.len() != 27 + usize::from(plain[26])
    {
        return Err(PairError::Protocol);
    }
    let host = std::str::from_utf8(&plain[27..])
        .map_err(|_| PairError::Protocol)?
        .parse::<Ipv4Addr>()
        .map_err(|_| PairError::Protocol)?;
    // The answer must name the address that this client connected to. A
    // status for another host is not trusted.
    if std::net::IpAddr::V4(host) != address.ip() {
        return Err(PairError::Protocol);
    }
    Ok(CommandAnswer::Status(PhoneInfo {
        proxy_running: plain[20] == 1,
        foreground: plain[21] == 1,
        connections: u16::from_be_bytes([plain[22], plain[23]]),
        port: u16::from_be_bytes([plain[24], plain[25]]),
        host: host.to_string(),
    }))
}

/// The pairing state that the GUI shows. It never holds the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairPhase {
    Idle,
    Connecting,
    Confirm,
    Paired,
    Failed,
}
impl PairPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Confirm => "confirm",
            Self::Paired => "paired",
            Self::Failed => "failed",
        }
    }
}

/// One snapshot for `GET /api/phone/pair`. All text is fixed or numeric.
#[derive(Clone, PartialEq, Eq)]
pub struct PairView {
    pub phase: PairPhase,
    pub code: Option<String>,
    pub host: Option<Ipv4Addr>,
    pub port: Option<u16>,
    pub error: Option<&'static str>,
}
/// The SAS code is a pairing secret, so Debug never prints it.
impl std::fmt::Debug for PairView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairView")
            .field("phase", &self.phase)
            .field("code", &self.code.as_ref().map(|_| "[redacted]"))
            .field("host", &self.host)
            .field("port", &self.port)
            .field("error", &self.error)
            .finish()
    }
}
impl Default for PairView {
    fn default() -> Self {
        Self {
            phase: PairPhase::Idle,
            code: None,
            host: None,
            port: None,
            error: None,
        }
    }
}
impl PairView {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.phase.as_str(),
            "code": self.code,
            "host": self.host.map(|h| h.to_string()),
            "port": self.port,
            "error": self.error,
        })
    }
}

/// Fixed GUI text for a pairing request error code.
pub fn request_error_message(code: &str) -> &'static str {
    match code {
        "pair_busy" => "A pairing is already running.",
        _ => "The pairing could not start.",
    }
}

/// The HTTP status and fixed GUI text for a forget request error code.
pub fn forget_error(code: &str) -> (u16, &'static str) {
    match code {
        "tunnel_running" => (409, "Turn off the tunnel first."),
        _ => (400, "The pairing could not be forgotten."),
    }
}

// The pairing tests open loopback TCP sockets through the normalized helpers.
// The helpers exist on Unix and Windows. Only the identity file tests need a
// platform gate. The Windows tests use per-user DPAPI and private file
// permissions.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    // Fixed public test vectors. ios/tests/PairingTests.swift holds the same
    // values. Change both files together.
    const L_S_PRIV: [u8; 32] = [0x11; 32];
    const L_E_PRIV: [u8; 32] = [0x22; 32];
    const P_E_PRIV: [u8; 32] = [0x33; 32];
    const NONCE: [u8; 12] = [0x44; 12];
    const TOKEN: &str = "test-token-0123456789abcdef";
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

    #[test]
    fn parity_vectors_match_the_swift_suite() {
        let (l_s, l_e, p_e) = (public(&L_S_PRIV), public(&L_E_PRIV), public(&P_E_PRIV));
        assert_eq!(hex(&l_s), V_L_S);
        assert_eq!(hex(&l_e), V_L_E);
        assert_eq!(hex(&p_e), V_P_E);
        assert_eq!(hex(&commitment(&l_e, &l_s)), V_C);
        let ee = agree(&StaticSecret::from(L_E_PRIV), &p_e).unwrap();
        let es = agree(&StaticSecret::from(L_S_PRIV), &p_e).unwrap();
        // The phone side gets the same shared values.
        assert_eq!(ee, agree(&StaticSecret::from(P_E_PRIV), &l_e).unwrap());
        assert_eq!(es, agree(&StaticSecret::from(P_E_PRIV), &l_s).unwrap());
        assert_eq!(hex(&ee), V_EE);
        assert_eq!(hex(&es), V_ES);
        let h = transcript_hash(&l_s, &l_e, &p_e);
        assert_eq!(hex(&h), V_H);
        let keys = derive_keys(&ee, &es, h);
        assert_eq!(hex(&keys.k_enc), V_K_ENC);
        assert_eq!(hex(&keys.k_proof), V_K_PROOF);
        assert_eq!(hex(&keys.sas), V_SAS);
        assert_eq!(sas_code(&keys.sas), V_CODE);
        assert_eq!(format_code(V_CODE), "500 104");
        let proof = laptop_proof(&keys);
        assert_eq!(hex(&proof), V_PROOF);
        assert!(verify_proof(&keys, &proof));
        let credentials = PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 1080,
            token: TOKEN.into(),
        };
        let ciphertext = seal_credentials(&keys, &NONCE, &credentials).unwrap();
        assert_eq!(hex(&ciphertext), V_CT);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
        let mut hello = encode_hello(&l_s, &commitment(&l_e, &l_s));
        hello.push(1);
        assert_eq!(
            hex(&hello),
            format!("0101{}{}01", hex(&l_s), hex(&commitment(&l_e, &l_s)))
        );
        let mut req = vec![0x55; 16];
        req.push(0);
        let mut response = vec![0x55; 16];
        response.extend_from_slice(&[0, 0, 0, 1, 1, 1, 0, 2, 4, 56, 11]);
        response.extend_from_slice(b"172.20.10.1");
        let encrypt = |nonce: &[u8; 12], plain: &[u8]| {
            cipher
                .encrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: plain,
                        aad: &keys.h,
                    },
                )
                .unwrap()
        };
        assert_eq!(
            hex(&encrypt(&NONCE, &[])),
            "db466ed9c760a7484fa50848950711f7"
        );
        assert_eq!(
            hex(&encrypt(&[0x44; 12], &req)),
            "4247c7f09df127910c427a33114f972c5e2ad0449eded52ee1f8b60f3162ba126f"
        );
        assert_eq!(hex(&encrypt(&[0x66; 12], &response)), "85c1d284f91bc6a6749ad370bf6c6abe5f8d0a580845185b4292fe2e89545d589039f667f42eadf73ae2df6c3949ce678dffda5da446");

        assert_eq!(
            open_credentials(&keys, &NONCE, &ciphertext).unwrap(),
            credentials
        );
    }

    #[test]
    fn sas_code_pads_and_wraps() {
        assert_eq!(sas_code(&[0, 0, 0, 7]), "000007");
        assert_eq!(sas_code(&[0xff, 0xff, 0xff, 0xff]), "967295");
        assert_eq!(format_code("000007"), "000 007");
    }

    #[test]
    fn low_order_points_are_rejected() {
        let secret = StaticSecret::from(L_E_PRIV);
        assert_eq!(agree(&secret, &[0u8; 32]), Err(PairError::LowOrder));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(agree(&secret, &one), Err(PairError::LowOrder));
    }

    #[test]
    fn messages_and_plaintext_have_strict_lengths() {
        let key = [7u8; 32];
        let hello = encode_hello(&key, &key);
        assert_eq!(decode_hello(&hello).unwrap(), (key, key));
        assert!(decode_hello(&hello[..65]).is_err());
        let mut wrong_version = hello.clone();
        wrong_version[1] = 2;
        assert!(decode_hello(&wrong_version).is_err());
        let challenge = encode_challenge(&key, true);
        assert_eq!(
            decode_challenge(&challenge).unwrap(),
            ChallengeOrResult::Challenge {
                p_e: key,
                known: true
            }
        );
        let mut bad_known = challenge.clone();
        bad_known[33] = 2;
        assert!(decode_challenge(&bad_known).is_err());
        assert!(decode_challenge(&challenge[..33]).is_err());
        assert_eq!(
            decode_challenge(&encode_result_status(PhoneStatus::Busy)).unwrap(),
            ChallengeOrResult::Result(ResultMessage::Status(PhoneStatus::Busy))
        );
        assert!(decode_reveal(&encode_reveal(&key, &key)[..64]).is_err());
        assert!(decode_result(&[MSG_RESULT, 9]).is_err());
        assert!(decode_result(&[MSG_RESULT, 1, 0]).is_err());
        assert!(decode_result(&[MSG_RESULT, 0, 1, 2]).is_err());

        let good = PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 1080,
            token: "abc".into(),
        };
        let plain = encode_credentials(&good).unwrap();
        assert_eq!(decode_credentials(&plain).unwrap(), good);
        let mut longer = plain.clone();
        longer.push(b'1');
        assert!(decode_credentials(&longer).is_err());
        assert!(decode_credentials(&plain[..plain.len() - 1]).is_err());
        let mut zero_port = plain.clone();
        zero_port[0] = 0;
        zero_port[1] = 0;
        assert!(decode_credentials(&zero_port).is_err());
        let mut bad_token = plain.clone();
        bad_token[3] = b' ';
        assert!(decode_credentials(&bad_token).is_err());
        assert!(decode_credentials(&[4, 56, 0, 1, b'x']).is_err());
    }

    #[test]
    fn frames_reject_empty_and_oversize_payloads() {
        assert!(frame(&[]).is_err());
        assert!(frame(&[0; MAX_FRAME + 1]).is_err());
        let mut reader = FrameReader::default();
        let framed = frame(&[1, 2, 3]).unwrap();
        reader.push(&framed[..3]);
        assert_eq!(reader.next_frame().unwrap(), None);
        reader.push(&framed[3..]);
        assert_eq!(reader.next_frame().unwrap(), Some(vec![1, 2, 3]));
        let mut big = FrameReader::default();
        big.push(&((MAX_FRAME + 1) as u16).to_be_bytes());
        assert_eq!(big.next_frame(), Err(PairError::Protocol));
        let mut empty = FrameReader::default();
        empty.push(&[0, 0]);
        assert_eq!(empty.next_frame(), Err(PairError::Protocol));
    }

    #[test]
    fn random_bytes_fills_whole_buffers() {
        // The buffer is longer than one 32-byte operating system call.
        let mut first = [0u8; 96];
        random_bytes(&mut first).unwrap();
        assert_ne!(first, [0u8; 96]);
        let mut second = [0u8; 96];
        random_bytes(&mut second).unwrap();
        assert_ne!(first, second);
        let mut empty: [u8; 0] = [];
        assert!(random_bytes(&mut empty).is_ok());
    }

    #[test]
    fn debug_output_hides_the_token_and_the_key() {
        let credentials = PhoneCredentials {
            host: Ipv4Addr::new(172, 20, 10, 1),
            port: 1080,
            token: "secret-test-token".into(),
        };
        let text = format!("{credentials:?}");
        assert!(!text.contains("secret-test-token"));
        assert!(text.contains("[redacted]"));
        let identity = Identity::from_bytes(L_S_PRIV);
        let text = format!("{identity:?}");
        assert!(!text.contains(&hex(&L_S_PRIV)));
        assert!(text.contains(V_L_S));
        assert!(!format!("{:?}", derive_keys(&[1; 32], &[2; 32], [3; 32])).contains("01"));
        for error in [
            PairError::Phone(PhoneStatus::Denied),
            PairError::Decrypt,
            PairError::Identity,
        ] {
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_private_and_stable() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "hs-identity-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let path = root.join("hotspotshade").join("identity.key");
        let first = Identity::load_or_create(&path).unwrap();
        let second = Identity::load_or_create(&path).unwrap();
        assert_eq!(first.public(), second.public());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [1u8; 31]).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        std::fs::write(&path, [1u8; 33]).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(&path, [1u8; 32]).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(windows)]
    fn unique_test_name(label: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!(
            "{label}-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        )
    }

    #[cfg(windows)]
    struct TempRoot(PathBuf);

    #[cfg(windows)]
    impl TempRoot {
        fn new(label: &str) -> Self {
            // Use the real LocalAppData parent, not the system temp directory.
            // The runtime test must exercise the same profile ACL chain as the
            // default store, and a CI temp directory can live on a loose
            // volume. The unique name never touches the real hotspotshade
            // directory or the real identity file.
            let default = Identity::default_path().expect("a LocalAppData path");
            let base = default
                .parent()
                .and_then(Path::parent)
                .expect("LocalAppData holds the hotspotshade directory")
                .to_path_buf();
            let path = base.join(unique_test_name(label));
            // Create the root with the profile default ACL, then replace it
            // with a known safe inheritable ACL. The real profile ancestors
            // above this root are still checked by the loader. This keeps the
            // runtime tests independent of an unusual LocalAppData policy and
            // lets std::fs test children inherit the user access.
            std::fs::create_dir(&path).expect("create the test root");
            let user = windows_identity::test_current_user_sid().expect("the current user SID");
            let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})");
            windows_identity::test_set_acl(&path, &sddl).expect("set the test root ACL");
            Self(path)
        }

        fn key_path(&self) -> PathBuf {
            self.0.join("hotspotshade").join("identity.key")
        }
    }

    #[cfg(windows)]
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A positive control for the negative tests. The same loader must create
    /// a valid private identity and read it back before a test breaks one
    /// condition.
    #[cfg(windows)]
    fn private_identity(path: &Path) -> [u8; 32] {
        let first = Identity::load_or_create(path).unwrap();
        let second = Identity::load_or_create(path).unwrap();
        assert_eq!(first.public(), second.public());
        first.public()
    }

    /// Create a test symlink, or report an explicit skip when the host denies
    /// the symlink privilege. Other errors fail the test.
    #[cfg(windows)]
    fn create_symlink_or_skip(
        target: &Path,
        link: &Path,
        directory: bool,
        test_name: &str,
    ) -> bool {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        let result = if directory {
            symlink_dir(target, link)
        } else {
            symlink_file(target, link)
        };
        match result {
            Ok(()) => true,
            Err(error) => {
                let permission_denied =
                    matches!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(
                    permission_denied,
                    "{test_name}: symlink creation failed: {error}"
                );
                eprintln!(
                    "SKIP {test_name}: the host denied symlink creation ({error}). The reparse check is not exercised on this host."
                );
                false
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn identity_file_is_dpapi_protected_and_stable() {
        let root = TempRoot::new("hs-identity-stable");
        let path = root.key_path();
        let first = Identity::load_or_create(&path).unwrap();
        let second = Identity::load_or_create(&path).unwrap();
        assert_eq!(first.public(), second.public());

        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(windows_identity::MAGIC));
        assert!(bytes.len() > windows_identity::MAGIC.len());
        // The file holds the DPAPI blob with a header. It is not a raw key.
        assert_ne!(bytes.len(), 32);
        for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(!name.to_string_lossy().starts_with("identity.key.tmp-"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_blob_hides_the_plaintext_and_rejects_tampering() {
        let secret = [0x5Au8; 32];
        let blob = windows_identity::protect_identity(&secret).unwrap();
        assert!(blob.len() > secret.len());
        assert!(!blob.windows(secret.len()).any(|window| window == secret));
        assert_eq!(windows_identity::unprotect_identity(&blob).unwrap(), secret);

        let mut tampered = blob;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            windows_identity::unprotect_identity(&tampered).unwrap_err(),
            PairError::Identity
        );
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_acl_accepts_trusted_removal_rights() {
        let user = windows_identity::test_current_user_sid().unwrap();
        // A normal profile parent: the current user, SYSTEM, and
        // Administrators hold full control. Builtin Users holds read access
        // only. Read access cannot remove or replace the private directory.
        let sddl = format!("O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;FR;;;BU)");
        assert_eq!(windows_identity::test_ancestor_acl(&sddl), Ok(()));

        // The system drive root grants Builtin Users append data and create
        // subdirectory. That right cannot remove, replace, or retarget an
        // existing directory.
        let sddl = format!("O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;0x4;;;BU)");
        assert_eq!(windows_identity::test_ancestor_acl(&sddl), Ok(()));

        // TrustedInstaller owns the system drive root on a default install.
        let sddl = format!(
            "O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"
        );
        assert_eq!(windows_identity::test_ancestor_acl(&sddl), Ok(()));
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_acl_rejects_untrusted_write_and_removal_rights() {
        let user = windows_identity::test_current_user_sid().unwrap();
        // The parent must not let another principal remove or replace a
        // child, change the DACL or owner, gain all access, or set a reparse
        // point on an empty directory. The test uses Builtin Users, which
        // contains more users than the test user.
        for rights in [
            "0x2",        // FILE_ADD_FILE, also FILE_WRITE_DATA for a directory
            "0x40",       // FILE_DELETE_CHILD
            "0x100",      // FILE_WRITE_ATTRIBUTES
            "0x10000",    // DELETE
            "0x40000",    // WRITE_DAC
            "0x80000",    // WRITE_OWNER
            "0x40000000", // GENERIC_WRITE
            "0x10000000", // GENERIC_ALL
            "FA",         // FILE_ALL_ACCESS
        ] {
            let sddl =
                format!("O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;{rights};;;BU)");
            assert_eq!(
                windows_identity::test_ancestor_acl(&sddl),
                Err(PairError::Identity),
                "Builtin Users must not receive {rights}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn volume_root_accepts_default_modify_but_rejects_removal_rights() {
        let user = windows_identity::test_current_user_sid().unwrap();
        // A default system drive root lets Authenticated Users create files
        // and set attributes (Modify, 0x1301bf). The root cannot be renamed,
        // removed, or redirected, so those rights are safe here.
        let sddl = "O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;AU)".to_string();
        assert_eq!(windows_identity::test_root_acl(&sddl), Ok(()));
        // The same entry on a lower ancestor stays refused.
        assert_eq!(
            windows_identity::test_ancestor_acl(&sddl),
            Err(PairError::Identity)
        );
        // Removing a child, or changing the permissions, stays refused.
        for rights in ["0x40", "0x40000", "0x80000", "0x10000000"] {
            let sddl =
                format!("O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;{rights};;;AU)");
            assert_eq!(
                windows_identity::test_root_acl(&sddl),
                Err(PairError::Identity),
                "the root must refuse {rights}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_acl_rejects_an_untrusted_owner() {
        // The owner can always rewrite the DACL, so a safe-looking DACL does
        // not make an untrusted owner safe.
        assert_eq!(
            windows_identity::test_ancestor_acl("O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)"),
            Err(PairError::Identity)
        );
        // LocalSystem is trusted.
        assert_eq!(
            windows_identity::test_ancestor_acl("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"),
            Ok(())
        );
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_acl_checks_inherited_aces_and_skips_inherit_only() {
        let user = windows_identity::test_current_user_sid().unwrap();
        // An inherited entry applies to this object. Its source does not make
        // an untrusted removal right safe.
        let inherited =
            format!("O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;ID;0x40;;;BU)");
        assert_eq!(
            windows_identity::test_ancestor_acl(&inherited),
            Err(PairError::Identity)
        );
        // An inherit-only entry does not apply to this object. The child
        // check reads the effective entry after inheritance.
        let inherit_only =
            format!("O:{user}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;OICIIO;0x40;;;BU)");
        assert_eq!(windows_identity::test_ancestor_acl(&inherit_only), Ok(()));
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_acl_rejects_null_and_accepts_empty_dacl() {
        // A null DACL grants full access to every principal.
        assert_eq!(
            windows_identity::test_ancestor_acl("O:SYD:NO_ACCESS_CONTROL"),
            Err(PairError::Identity)
        );
        // An empty DACL grants no access. The trusted owner keeps the
        // implicit WRITE_DAC right.
        assert_eq!(windows_identity::test_ancestor_acl("O:SYD:"), Ok(()));
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_acl_ignores_deny_entries() {
        // A deny entry removes access. It cannot grant a removal right.
        assert_eq!(
            windows_identity::test_ancestor_acl("O:SYD:(D;;0x40;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)"),
            Ok(())
        );
    }

    #[cfg(windows)]
    #[test]
    fn identity_refuses_a_thread_impersonation_token() {
        windows_identity::test_with_impersonation(|| {
            assert_eq!(
                windows_identity::test_reject_impersonation(),
                Err(PairError::Identity)
            );
        });
        // The helper reverted the thread token. The normal path works after.
        assert_eq!(windows_identity::test_reject_impersonation(), Ok(()));
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_a_tampered_file_without_overwriting_it() {
        let root = TempRoot::new("hs-identity-tamper");
        let path = root.key_path();
        let _ = private_identity(&path);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_permissive_file_permissions() {
        let root = TempRoot::new("hs-identity-file-acl");
        let path = root.key_path();
        let _ = private_identity(&path);
        let bytes = std::fs::read(&path).unwrap();
        // A protected DACL with one full-control entry for Everyone. The
        // loader must refuse the file.
        windows_identity::test_set_acl(&path, "D:P(A;;FA;;;WD)").unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_a_protected_acl_for_another_sid() {
        let root = TempRoot::new("hs-identity-wrong-sid");
        let path = root.key_path();
        let _ = private_identity(&path);
        // The owner stays the current user because only the DACL changes.
        // BUILTIN\Users keeps the test user able to open the file. The one
        // ACE names another SID, so only the ACE SID check can reject it.
        windows_identity::test_set_acl(&path, "D:P(A;;FA;;;BU)").unwrap();
        let bytes = std::fs::read(&path).expect("the test user must keep read access");
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn identity_load_rejects_a_permissive_directory() {
        let root = TempRoot::new("hs-identity-dir-load-acl");
        let path = root.key_path();
        let _ = private_identity(&path);
        let bytes = std::fs::read(&path).unwrap();
        let dir = path.parent().unwrap();
        // A protected DACL with one full-control entry for Everyone. The file
        // keeps its private ACL. The loader must reject the directory on load.
        windows_identity::test_set_acl(dir, "D:P(A;;FA;;;WD)").unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn identity_load_rejects_parent_removal_rights() {
        let user = windows_identity::test_current_user_sid().unwrap();
        // The private directory keeps its own protected DACL. A right on its
        // parent still lets another user remove or rename the directory after
        // the pinned handles close. The loader must reject that parent.
        for (label, rights) in [
            ("add-file", "0x2"),
            ("delete-child", "0x40"),
            ("write-attributes", "0x100"),
            ("delete", "0x10000"),
            ("write-dac", "0x40000"),
            ("write-owner", "0x80000"),
            ("full-access", "FA"),
        ] {
            let root = TempRoot::new("hs-identity-parent-removal");
            let path = root.key_path();
            let _ = private_identity(&path);
            let bytes = std::fs::read(&path).unwrap();
            let parent = path
                .parent()
                .and_then(Path::parent)
                .expect("the test root is the parent of the private directory");
            let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;{rights};;;WD)");
            windows_identity::test_set_acl(parent, &sddl).unwrap();
            assert_eq!(
                Identity::load_or_create(&path).unwrap_err(),
                PairError::Identity,
                "{label}: an untrusted removal right on the parent must fail closed"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[cfg(windows)]
    #[test]
    fn identity_load_accepts_read_only_parent_access() {
        let user = windows_identity::test_current_user_sid().unwrap();
        let root = TempRoot::new("hs-identity-parent-read");
        let path = root.key_path();
        let public = private_identity(&path);
        let parent = path
            .parent()
            .and_then(Path::parent)
            .expect("the test root is the parent of the private directory");
        // Builtin Users keeps read access. Read access cannot remove or
        // replace the private directory, so the loader must accept it.
        let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;FR;;;BU)");
        windows_identity::test_set_acl(parent, &sddl).unwrap();
        assert_eq!(Identity::load_or_create(&path).unwrap().public(), public);
    }

    #[cfg(windows)]
    #[test]
    fn identity_create_rejects_a_permissive_directory_and_creates_no_file() {
        let root = TempRoot::new("hs-identity-dir-acl");
        let good = root
            .0
            .join("good")
            .join("hotspotshade")
            .join("identity.key");
        let _ = private_identity(&good);
        let dir = root.0.join("hotspotshade");
        std::fs::create_dir(&dir).unwrap();
        // Everyone gets full control on the directory.
        windows_identity::test_set_acl(&dir, "D:P(A;;FA;;;WD)").unwrap();
        let path = dir.join("identity.key");
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_bad_lengths_without_overwriting() {
        let root = TempRoot::new("hs-identity-length");
        let path = root.key_path();
        let _ = private_identity(&path);

        std::fs::write(&path, windows_identity::MAGIC).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert_eq!(std::fs::read(&path).unwrap(), windows_identity::MAGIC);

        std::fs::write(&path, vec![0u8; 8192]).unwrap();
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert_eq!(std::fs::read(&path).unwrap().len(), 8192);
    }

    #[cfg(windows)]
    #[test]
    fn identity_creates_one_key_under_concurrent_loads() {
        let root = TempRoot::new("hs-identity-race");
        let path = root.key_path();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            workers.push(thread::spawn(move || {
                Identity::load_or_create(&path).map(|identity| identity.public())
            }));
        }
        let mut publics = Vec::new();
        for worker in workers {
            publics.push(worker.join().unwrap().unwrap());
        }
        assert!(publics.windows(2).all(|pair| pair[0] == pair[1]));
        for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(!name.to_string_lossy().starts_with("identity.key.tmp-"));
        }
    }

    /// Hold the key file with DELETE access, as a concurrent rename does. The
    /// reader opens without delete sharing, so its open gets a sharing
    /// violation while the handle is open.
    #[cfg(windows)]
    fn hold_key_for_rename(path: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        const DELETE: u32 = 0x0001_0000;
        std::fs::OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(0x7)
            .open(path)
            .unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn identity_waits_for_a_transient_sharing_violation() {
        let root = TempRoot::new("hs-identity-sharing");
        let path = root.key_path();
        let public = private_identity(&path);
        let holder = hold_key_for_rename(&path);
        let release = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(200));
            drop(holder);
        });
        assert_eq!(Identity::load_or_create(&path).unwrap().public(), public);
        release.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn identity_fails_closed_on_a_held_sharing_violation() {
        let root = TempRoot::new("hs-identity-sharing-held");
        let path = root.key_path();
        let public = private_identity(&path);
        let holder = hold_key_for_rename(&path);
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        drop(holder);
        assert_eq!(Identity::load_or_create(&path).unwrap().public(), public);
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_relative_paths_and_non_directories() {
        let root = TempRoot::new("hs-identity-unsafe-path");
        let key_path = root.key_path();
        let _ = private_identity(&key_path);
        let bytes = std::fs::read(&key_path).unwrap();

        let relative = PathBuf::from(unique_test_name("hs-identity-relative"));
        assert_eq!(
            Identity::load_or_create(&relative).unwrap_err(),
            PairError::Identity
        );
        assert!(!relative.exists());

        let unc = PathBuf::from(r"\\server\share\hotspotshade\identity.key");
        assert_eq!(
            Identity::load_or_create(&unc).unwrap_err(),
            PairError::Identity
        );
        let verbatim = PathBuf::from(r"\\?\C:\hotspotshade\identity.key");
        assert_eq!(
            Identity::load_or_create(&verbatim).unwrap_err(),
            PairError::Identity
        );

        use std::os::windows::ffi::OsStringExt;
        let nul_name = std::ffi::OsString::from_wide(&[0x41, 0, 0x42]);
        let nul_path = std::env::temp_dir().join(nul_name);
        assert_eq!(
            Identity::load_or_create(&nul_path).unwrap_err(),
            PairError::Identity
        );

        let parent_path = root
            .0
            .join("hotspotshade")
            .join("..")
            .join("hotspotshade")
            .join("identity.key");
        assert_eq!(
            Identity::load_or_create(&parent_path).unwrap_err(),
            PairError::Identity
        );

        let private_dir = root.0.join("hotspotshade");
        for path in [
            format!(r"{}\.\identity.key", private_dir.display()),
            format!(r"{}\identity.key\.", private_dir.display()),
            format!(r"{}\\identity.key", private_dir.display()),
        ] {
            assert_eq!(
                Identity::load_or_create(Path::new(&path)).unwrap_err(),
                PairError::Identity
            );
        }

        let stream_path = root.0.join("hotspotshade").join("identity.key:stream");
        assert_eq!(
            Identity::load_or_create(&stream_path).unwrap_err(),
            PairError::Identity
        );
        // The valid identity is unchanged by the rejected paths.
        assert_eq!(std::fs::read(&key_path).unwrap(), bytes);

        let not_a_root = root.0.join("not-a-dir");
        std::fs::create_dir_all(&not_a_root).unwrap();
        let dir = not_a_root.join("hotspotshade");
        std::fs::write(&dir, b"not a directory").unwrap();
        let path = dir.join("identity.key");
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn identity_default_path_is_in_local_app_data() {
        let path = Identity::default_path().unwrap();
        assert!(path.is_absolute());
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("identity.key")
        );
        assert_eq!(
            path.parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str()),
            Some("hotspotshade")
        );
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_a_reparse_point() {
        let root = TempRoot::new("hs-identity-reparse");
        let path = root.key_path();
        let _ = private_identity(&path);
        std::fs::remove_file(&path).unwrap();
        // The link target is a valid private identity. If the loader followed
        // the link, it would succeed. It must reject the reparse point.
        let target = root
            .0
            .join("target")
            .join("hotspotshade")
            .join("identity.key");
        let _ = private_identity(&target);
        if !create_symlink_or_skip(&target, &path, false, "identity_rejects_a_reparse_point") {
            return;
        }
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_a_directory_reparse_point() {
        let root = TempRoot::new("hs-identity-dir-reparse");
        let real = root.0.join("real");
        let real_path = real.join("identity.key");
        let _ = private_identity(&real_path);
        let link = root.0.join("hotspotshade");
        if !create_symlink_or_skip(
            &real,
            &link,
            true,
            "identity_rejects_a_directory_reparse_point",
        ) {
            return;
        }
        // The private directory is itself a reparse point. The valid identity
        // behind it must not be accepted.
        let path = link.join("identity.key");
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_an_intermediate_reparse_point() {
        let root = TempRoot::new("hs-identity-intermediate-reparse");
        let outside = root.0.join("outside");
        let real_path = outside
            .join("sub")
            .join("hotspotshade")
            .join("identity.key");
        let _ = private_identity(&real_path);
        let link = root.0.join("link");
        if !create_symlink_or_skip(
            &outside,
            &link,
            true,
            "identity_rejects_an_intermediate_reparse_point",
        ) {
            return;
        }
        // An intermediate component is a reparse point. The valid private
        // identity behind it must not be accepted.
        let path = link.join("sub").join("hotspotshade").join("identity.key");
        assert_eq!(
            Identity::load_or_create(&path).unwrap_err(),
            PairError::Identity
        );
    }

    // A test-only phone. It runs the phone rules from PHONE_PROXY.md with a
    // logical clock. It is not the Swift implementation.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Decide {
        Allow,
        Deny,
    }
    #[derive(Clone, Copy, Default)]
    struct Faults {
        silent: bool,
        tamper: bool,
        oversize_challenge: bool,
        short_challenge: bool,
        wrong_host: bool,
        status_mode: bool,
        wrong_echo: bool,
        wrong_status_host: bool,
        short_status: bool,
        reject_status: bool,
    }
    pub(crate) struct MockPhone {
        trust: HashSet<[u8; 32]>,
        failures: HashMap<std::net::IpAddr, Vec<u64>>,
        locked_until: HashMap<std::net::IpAddr, u64>,
        attempts: HashMap<std::net::IpAddr, Vec<u64>>,
        now: u64,
        decide: Decide,
        faults: Faults,
        prompts: usize,
        proxy_running: bool,
        connections: u16,
        status_port: u16,
    }
    impl MockPhone {
        pub(crate) fn new(decide: Decide) -> Self {
            Self {
                trust: HashSet::new(),
                failures: HashMap::new(),
                locked_until: HashMap::new(),
                attempts: HashMap::new(),
                now: 1000,
                decide,
                faults: Faults::default(),
                prompts: 0,
                proxy_running: true,
                connections: 2,
                status_port: 1080,
            }
        }
        /// Trust one target device identity.
        pub(crate) fn trust(&mut self, key: [u8; 32]) {
            self.trust.insert(key);
        }
        /// Answer an authenticated status request with these values.
        pub(crate) fn answer_status(&mut self, proxy_running: bool, connections: u16, port: u16) {
            self.faults.status_mode = true;
            self.proxy_running = proxy_running;
            self.connections = connections;
            self.status_port = port;
        }
        fn fail(&mut self, peer: std::net::IpAddr) {
            let failures = self.failures.entry(peer).or_default();
            failures.retain(|t| self.now - *t < 60);
            failures.push(self.now);
            if failures.len() >= 3 {
                self.locked_until.insert(peer, self.now + 30);
                failures.clear();
            }
        }
        fn send(stream: &mut TcpStream, payload: &[u8]) {
            let _ = stream.write_all(&frame(payload).unwrap());
        }
        fn read(stream: &mut TcpStream, reader: &mut FrameReader) -> Result<Vec<u8>, PairError> {
            let mut buffer = [0u8; 1024];
            loop {
                if let Some(frame) = reader.next_frame()? {
                    return Ok(frame);
                }
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => return Err(PairError::Io),
                    Ok(n) => reader.push(&buffer[..n]),
                }
            }
        }
        fn serve(&mut self, mut stream: TcpStream) {
            let peer = stream.peer_addr().unwrap().ip();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut reader = FrameReader::default();
            let reject = |_phone: &mut Self, stream: &mut TcpStream| {
                Self::send(stream, &encode_result_status(PhoneStatus::Rejected));
            };
            let hello = match Self::read(&mut stream, &mut reader) {
                Ok(hello) => hello,
                Err(PairError::Protocol) => return reject(self, &mut stream),
                Err(_) => return,
            };
            let Ok((l_s, commit)) = decode_hello(&hello) else {
                return reject(self, &mut stream);
            };
            let known = self.trust.contains(&l_s);
            let flags = hello.get(66).copied().unwrap_or(0);
            if !known && flags != 0 {
                return reject(self, &mut stream);
            }
            if !known && self.locked_until.get(&peer).is_some_and(|t| self.now < *t) {
                return Self::send(&mut stream, &encode_result_status(PhoneStatus::LockedOut));
            }
            if self.faults.silent {
                let mut sink = [0u8; 64];
                while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
                return;
            }
            if self.faults.oversize_challenge {
                let _ = stream.write_all(&((MAX_FRAME + 1) as u16).to_be_bytes());
                let _ = stream.write_all(&[0u8; MAX_FRAME + 1]);
                return;
            }
            let secret = StaticSecret::from(P_E_PRIV);
            let p_e = PublicKey::from(&secret).to_bytes();
            let known = self.trust.contains(&l_s);
            let mut challenge = encode_challenge(&p_e, known);
            if self.faults.short_challenge {
                challenge.pop();
            }
            Self::send(&mut stream, &challenge);
            let reveal = match Self::read(&mut stream, &mut reader) {
                Ok(reveal) => reveal,
                Err(PairError::Protocol) => return reject(self, &mut stream),
                Err(_) => return,
            };
            let Ok((l_e, proof)) = decode_reveal(&reveal) else {
                return reject(self, &mut stream);
            };
            if commitment(&l_e, &l_s) != commit {
                return reject(self, &mut stream);
            }
            let (Ok(ee), Ok(es)) = (agree(&secret, &l_e), agree(&secret, &l_s)) else {
                return reject(self, &mut stream);
            };
            let keys = derive_keys(&ee, &es, transcript_hash(&l_s, &l_e, &p_e));
            if !verify_proof(&keys, &proof) {
                return reject(self, &mut stream);
            }
            if !known {
                self.attempts.retain(|_, times| {
                    times.retain(|t| self.now - *t < 600);
                    !times.is_empty()
                });
                if !self.attempts.contains_key(&peer) && self.attempts.len() >= 256 {
                    return Self::send(&mut stream, &encode_result_status(PhoneStatus::LockedOut));
                }
                let attempts = self.attempts.entry(peer).or_default();
                if attempts.len() >= 3 {
                    return Self::send(&mut stream, &encode_result_status(PhoneStatus::LockedOut));
                }
                attempts.push(self.now);
                self.prompts += 1;
                if self.decide == Decide::Deny {
                    self.fail(peer);
                    return Self::send(&mut stream, &encode_result_status(PhoneStatus::Denied));
                }
                self.trust.insert(l_s);
            }
            if flags == 2 {
                // Status-only HELLO. No RESULT OK and no token. Wait for the
                // authenticated FORGET command.
                let Ok(request) = Self::read(&mut stream, &mut reader) else {
                    return;
                };
                if request.len() < 29 || request[0] != 0x07 {
                    return;
                }
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
                let Ok(plain) = cipher.decrypt(
                    Nonce::from_slice(&request[1..13]),
                    Payload {
                        msg: &request[13..],
                        aad: &keys.h,
                    },
                ) else {
                    return;
                };
                if !plain.is_empty() {
                    return;
                }
                self.trust.remove(&l_s);
                Self::send(&mut stream, &[MSG_RESULT, 0]);
                return;
            }
            let host = if self.faults.wrong_host {
                Ipv4Addr::new(172, 20, 10, 1)
            } else {
                Ipv4Addr::LOCALHOST
            };
            let credentials = PhoneCredentials {
                host,
                port: 1080,
                token: TOKEN.into(),
            };
            let mut ciphertext = seal_credentials(&keys, &NONCE, &credentials).unwrap();
            if self.faults.tamper {
                ciphertext[0] ^= 1;
            }
            if flags == 0 {
                Self::send(&mut stream, &encode_result_ok(&NONCE, &ciphertext));
            }
            if self.faults.status_mode {
                let Ok(request) = Self::read(&mut stream, &mut reader) else {
                    return;
                };
                if request.len() < 29 || request[0] != 5 {
                    return;
                }
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.k_enc));
                let Ok(plain) = cipher.decrypt(
                    Nonce::from_slice(&request[1..13]),
                    Payload {
                        msg: &request[13..],
                        aad: &keys.h,
                    },
                ) else {
                    return;
                };
                if plain.len() != 17 {
                    return;
                }
                if self.faults.reject_status {
                    return Self::send(&mut stream, &encode_result_status(PhoneStatus::Rejected));
                }
                let mut response = plain[..16].to_vec();
                if self.faults.wrong_echo {
                    response[0] ^= 1;
                }
                let status_host: &[u8] = if self.faults.wrong_status_host {
                    b"127.0.0.2"
                } else {
                    b"127.0.0.1"
                };
                response.extend_from_slice(&[0, 0, 0, 1]);
                response.push(u8::from(self.proxy_running));
                response.push(1);
                response.extend_from_slice(&self.connections.to_be_bytes());
                response.extend_from_slice(&self.status_port.to_be_bytes());
                response.push(status_host.len() as u8);
                response.extend_from_slice(status_host);
                let nonce = [0x66; 12];
                let ciphertext = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: &response,
                            aad: &keys.h,
                        },
                    )
                    .unwrap();
                let mut message = vec![6];
                message.extend_from_slice(&nonce);
                message.extend_from_slice(&ciphertext);
                if self.faults.short_status {
                    message.truncate(55);
                }
                Self::send(&mut stream, &message);
            }
        }
    }

    // Serve `connections` connections on a loopback listener.
    pub(crate) fn spawn_phone(
        phone: Arc<Mutex<MockPhone>>,
        connections: usize,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..connections {
                let (stream, _) = listener.accept().unwrap();
                phone.lock().unwrap().serve(stream);
            }
        });
        (address, handle)
    }

    fn quick() -> PairTimeouts {
        PairTimeouts {
            connect: Duration::from_secs(2),
            challenge: Duration::from_secs(2),
            result: Duration::from_secs(2),
        }
    }

    fn run_pair(
        address: SocketAddr,
        identity: &Identity,
        timeouts: PairTimeouts,
    ) -> (Result<PhoneCredentials, PairError>, Vec<String>, (u64, u64)) {
        let audit = normalization::Audit::default();
        let cancel = AtomicBool::new(false);
        let mut codes = Vec::new();
        let result = pair_at(address, identity, None, &audit, &cancel, timeouts, |code| {
            codes.push(code.to_owned())
        });
        (result, codes, audit.snapshot())
    }

    #[test]
    fn status_requires_trust_and_checks_the_echo() {
        let identity = Identity::from_bytes(L_S_PRIV);
        for wrong_echo in [false, true] {
            let mut mock = MockPhone::new(Decide::Allow);
            mock.trust.insert(identity.public());
            mock.faults.status_mode = true;
            mock.faults.wrong_echo = wrong_echo;
            let (address, handle) = spawn_phone(Arc::new(Mutex::new(mock)), 1);
            let audit = normalization::Audit::default();
            let result = status_at(address, &identity, None, &audit, &AtomicBool::new(false));
            if wrong_echo {
                assert_eq!(result, Err(PairError::Protocol));
            } else {
                let info = result.unwrap();
                assert!(info.proxy_running && info.foreground);
                assert_eq!(
                    (info.connections, info.port, info.host.as_str()),
                    (2, 1080, "127.0.0.1")
                );
            }
            assert_eq!(audit.snapshot(), (1, 0));
            handle.join().unwrap();
        }
    }

    #[test]
    fn status_rejects_another_host_and_a_short_answer() {
        let identity = Identity::from_bytes(L_S_PRIV);
        for (wrong_status_host, short_status) in [(true, false), (false, true)] {
            let mut mock = MockPhone::new(Decide::Allow);
            mock.trust.insert(identity.public());
            mock.faults.status_mode = true;
            mock.faults.wrong_status_host = wrong_status_host;
            mock.faults.short_status = short_status;
            let (address, handle) = spawn_phone(Arc::new(Mutex::new(mock)), 1);
            let audit = normalization::Audit::default();
            let result = status_at(address, &identity, None, &audit, &AtomicBool::new(false));
            assert_eq!(result, Err(PairError::Protocol));
            assert_eq!(audit.snapshot(), (1, 0));
            handle.join().unwrap();
        }
    }

    #[test]
    fn status_rejected_after_the_handshake_is_a_phone_status() {
        let identity = Identity::from_bytes(L_S_PRIV);
        let mut mock = MockPhone::new(Decide::Allow);
        mock.trust(identity.public());
        mock.answer_status(true, 2, 1080);
        mock.faults.reject_status = true;
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(mock)), 1);
        let audit = normalization::Audit::default();
        let result = status_at(address, &identity, None, &audit, &AtomicBool::new(false));
        assert_eq!(result, Err(PairError::Phone(PhoneStatus::Rejected)));
        assert_eq!(audit.snapshot(), (1, 0));
        handle.join().unwrap();
    }

    #[test]
    fn unpaired_probe_uses_one_status_only_hello_and_never_prompts() {
        let identity = Identity::from_bytes(L_S_PRIV);
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 1);
        let audit = normalization::Audit::default();
        let result = probe_unpaired_at(address, &identity, None, &audit, &AtomicBool::new(false));
        assert_eq!(result, Ok(None));
        assert_eq!(audit.snapshot(), (1, 0));
        handle.join().unwrap();
        let state = phone.lock().unwrap();
        assert_eq!(state.prompts, 0);
        assert!(state.trust.is_empty());
        // The same unknown target device gets Rejected from an authenticated
        // status request. The caller maps that answer to `not_trusted`.
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(MockPhone::new(Decide::Allow))), 1);
        let result = status_at(address, &identity, None, &audit, &AtomicBool::new(false));
        assert_eq!(result, Err(PairError::Phone(PhoneStatus::Rejected)));
        handle.join().unwrap();
    }

    // Read one length-prefixed frame from a test socket.
    fn read_test_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).unwrap();
        let mut payload = vec![0u8; u16::from_be_bytes(header) as usize];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    // A rogue peer that runs the v1 handshake with its own ephemeral key. It
    // does not know any trust list. It sends `challenge_known` in CHALLENGE.
    // When it says it knows the key, it reads REVEAL and the sealed FORGET and
    // then sends `answer` as the FORGET answer.
    fn spawn_rogue(challenge_known: bool, answer: Vec<u8>) -> (SocketAddr, thread::JoinHandle<()>) {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let hello = read_test_frame(&mut stream);
            // The target device asks for a forget with flags 2.
            assert_eq!(hello.get(66), Some(&2));
            let challenge = encode_challenge(&public(&P_E_PRIV), challenge_known);
            stream.write_all(&frame(&challenge).unwrap()).unwrap();
            if challenge_known {
                let reveal = read_test_frame(&mut stream);
                assert_eq!(reveal[0], MSG_REVEAL);
                let request = read_test_frame(&mut stream);
                assert_eq!(request[0], 0x07);
                stream.write_all(&frame(&answer).unwrap()).unwrap();
            }
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
        });
        (address, worker)
    }

    // A rogue peer on the path. It relays HELLO, CHALLENGE, and REVEAL between
    // the target device and the real source device, drops the sealed FORGET,
    // and sends a plaintext RESULT Ok itself. The real source device never
    // receives the command and keeps its trust.
    fn spawn_relay_that_drops_forget(source: SocketAddr) -> (SocketAddr, thread::JoinHandle<()>) {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut target, _) = server.accept().unwrap();
            target
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut phone = TcpStream::connect(source).unwrap();
            phone
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let hello = read_test_frame(&mut target);
            phone.write_all(&frame(&hello).unwrap()).unwrap();
            let challenge = read_test_frame(&mut phone);
            target.write_all(&frame(&challenge).unwrap()).unwrap();
            let reveal = read_test_frame(&mut target);
            phone.write_all(&frame(&reveal).unwrap()).unwrap();
            let request = read_test_frame(&mut target);
            assert_eq!(request[0], 0x07);
            // Drop the command. Close the source device connection so it
            // stops waiting.
            let _ = phone.shutdown(std::net::Shutdown::Both);
            drop(phone);
            target
                .write_all(&frame(&[MSG_RESULT, PhoneStatus::Ok as u8]).unwrap())
                .unwrap();
            let mut byte = [0u8; 1];
            let _ = target.read(&mut byte);
        });
        (address, worker)
    }

    #[test]
    fn forget_reaches_a_real_source_but_is_never_confirmed() {
        let identity = Identity::from_bytes(L_S_PRIV);
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().trust.insert(identity.public());
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        let audit = normalization::Audit::default();
        let cancel = AtomicBool::new(false);
        // A legitimate source device removes the key and acknowledges.
        let reply = forget_attempt_at(address, &identity, None, &audit, &cancel);
        assert_eq!(reply, Ok(ForgetReply::Acknowledged));
        assert!(phone.lock().unwrap().trust.is_empty());
        // The confirmation API still cannot call the answer proof.
        phone.lock().unwrap().trust.insert(identity.public());
        let result = forget_at(address, &identity, None, &audit, &cancel);
        assert_eq!(result, Err(PairError::Unconfirmed));
        assert!(phone.lock().unwrap().trust.is_empty());
        assert_eq!(audit.snapshot(), (2, 0));
        handle.join().unwrap();
    }

    #[test]
    fn forget_of_a_key_the_source_reports_unknown_is_not_confirmed() {
        let identity = Identity::from_bytes(L_S_PRIV);
        // An unknown key gets RESULT Rejected from a forget HELLO.
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(MockPhone::new(Decide::Allow))), 2);
        let audit = normalization::Audit::default();
        let cancel = AtomicBool::new(false);
        let reply = forget_attempt_at(address, &identity, None, &audit, &cancel);
        assert_eq!(reply, Ok(ForgetReply::ReportedUnknown));
        let result = forget_at(address, &identity, None, &audit, &cancel);
        assert_eq!(result, Err(PairError::Unconfirmed));
        assert_eq!(audit.snapshot(), (2, 0));
        handle.join().unwrap();
    }

    #[test]
    fn rogue_forget_answers_are_never_confirmed_while_the_source_still_trusts() {
        let identity = Identity::from_bytes(L_S_PRIV);
        let audit = normalization::Audit::default();
        let cancel = AtomicBool::new(false);
        // The real source device trusts this target device the whole time. No
        // rogue below reaches it, so its trust must stay.
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        phone.lock().unwrap().trust.insert(identity.public());

        // A plaintext RESULT Rejected before the handshake.
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let rejected_first = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = server.accept().unwrap();
                let _ = read_test_frame(&mut stream);
                stream
                    .write_all(&frame(&encode_result_status(PhoneStatus::Rejected)).unwrap())
                    .unwrap();
            }
        });
        assert_eq!(
            forget_attempt_at(address, &identity, None, &audit, &cancel),
            Ok(ForgetReply::ReportedUnknown)
        );
        assert_eq!(
            forget_at(address, &identity, None, &audit, &cancel),
            Err(PairError::Unconfirmed)
        );
        rejected_first.join().unwrap();

        // CHALLENGE with known = 0.
        for confirm in [false, true] {
            let (address, worker) = spawn_rogue(false, Vec::new());
            if confirm {
                assert_eq!(
                    forget_at(address, &identity, None, &audit, &cancel),
                    Err(PairError::Unconfirmed)
                );
            } else {
                assert_eq!(
                    forget_attempt_at(address, &identity, None, &audit, &cancel),
                    Ok(ForgetReply::ReportedUnknown)
                );
            }
            worker.join().unwrap();
        }

        // A full handshake with the rogue's own key, then a plaintext RESULT
        // Ok or Rejected. The rogue needs no trust list and no secret.
        for (answer, expected) in [
            (
                vec![MSG_RESULT, PhoneStatus::Ok as u8],
                ForgetReply::Acknowledged,
            ),
            (
                vec![MSG_RESULT, PhoneStatus::Rejected as u8],
                ForgetReply::Rejected,
            ),
        ] {
            let (address, worker) = spawn_rogue(true, answer.clone());
            assert_eq!(
                forget_attempt_at(address, &identity, None, &audit, &cancel),
                Ok(expected)
            );
            worker.join().unwrap();
            let (address, worker) = spawn_rogue(true, answer);
            assert_eq!(
                forget_at(address, &identity, None, &audit, &cancel),
                Err(PairError::Unconfirmed)
            );
            worker.join().unwrap();
        }

        // Any other answer form is a protocol error, not an acknowledgement.
        for answer in [
            vec![MSG_RESULT, PhoneStatus::Ok as u8, 0],
            vec![MSG_RESULT, PhoneStatus::Busy as u8],
            vec![MSG_RESULT, 9],
            vec![0x06, 0],
        ] {
            let (address, worker) = spawn_rogue(true, answer);
            assert_eq!(
                forget_attempt_at(address, &identity, None, &audit, &cancel),
                Err(PairError::Protocol)
            );
            worker.join().unwrap();
        }

        // A relay that drops the sealed FORGET and answers RESULT Ok itself.
        let (source, source_handle) = spawn_phone(Arc::clone(&phone), 1);
        let (address, relay) = spawn_relay_that_drops_forget(source);
        assert_eq!(
            forget_attempt_at(address, &identity, None, &audit, &cancel),
            Ok(ForgetReply::Acknowledged)
        );
        relay.join().unwrap();
        source_handle.join().unwrap();
        let (source, source_handle) = spawn_phone(Arc::clone(&phone), 1);
        let (address, relay) = spawn_relay_that_drops_forget(source);
        assert_eq!(
            forget_at(address, &identity, None, &audit, &cancel),
            Err(PairError::Unconfirmed)
        );
        relay.join().unwrap();
        source_handle.join().unwrap();

        // The real source device still trusts the key after every rogue
        // answer, and the confirmation API never reported success.
        assert!(phone.lock().unwrap().trust.contains(&identity.public()));
        assert_eq!(audit.snapshot().1, 0);
    }

    #[test]
    fn forget_transport_failures_keep_their_own_errors() {
        let identity = Identity::from_bytes(L_S_PRIV);
        let audit = normalization::Audit::default();
        let cancel = AtomicBool::new(false);
        // A closed port is unreachable, not an unverified answer.
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        drop(server);
        assert_eq!(
            forget_at(address, &identity, None, &audit, &cancel),
            Err(PairError::Unreachable)
        );
        // A peer that closes after HELLO gives no answer.
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let _ = read_test_frame(&mut stream);
        });
        let result = forget_attempt_at(address, &identity, None, &audit, &cancel);
        assert!(
            matches!(result, Err(PairError::Io) | Err(PairError::Protocol)),
            "{result:?}"
        );
        assert_ne!(result, Err(PairError::Unconfirmed));
        worker.join().unwrap();
        // A cancelled attempt reports the cancel.
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(MockPhone::new(Decide::Allow))), 0);
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            forget_at(address, &identity, None, &audit, &cancelled),
            Err(PairError::Cancelled)
        );
        handle.join().unwrap();
    }

    #[test]
    fn unconfirmed_forget_message_is_fixed_text() {
        let message = PairError::Unconfirmed.message();
        assert!(message.contains("cannot verify"));
        assert_eq!(PairError::Unconfirmed.to_string(), message);
    }

    #[test]
    fn learned_phone_port_requires_the_gateway_and_a_usable_port() {
        let gateway = Ipv4Addr::new(172, 20, 10, 1);
        let status = |host: &str, port: u16| PhoneInfo {
            proxy_running: true,
            foreground: true,
            connections: 1,
            port,
            host: host.into(),
        };
        let mut credentials = PhoneCredentials {
            host: gateway,
            port: 1080,
            token: TOKEN.into(),
        };
        // A new port from the gateway is accepted.
        assert_eq!(
            learn_phone_info(&mut credentials, gateway, &status("172.20.10.1", 20001)),
            PortUpdate::PortChanged {
                old: 1080,
                new: 20001
            }
        );
        assert_eq!(
            (
                credentials.port,
                credentials.host,
                credentials.token.as_str()
            ),
            (20001, gateway, TOKEN)
        );
        // The same port changes nothing.
        assert_eq!(
            learn_phone_info(&mut credentials, gateway, &status("172.20.10.1", 20001)),
            PortUpdate::Unchanged
        );
        assert_eq!(credentials.token, TOKEN);
        // Port 65535 is the largest u16 and is accepted.
        assert_eq!(
            learn_phone_info(&mut credentials, gateway, &status("172.20.10.1", 65535)),
            PortUpdate::PortChanged {
                old: 20001,
                new: 65535
            }
        );
        assert_eq!(credentials.port, 65535);
        // Port 1024 is the lowest allowed port and is accepted.
        assert_eq!(
            learn_phone_info(&mut credentials, gateway, &status("172.20.10.1", 1024)),
            PortUpdate::PortChanged {
                old: 65535,
                new: 1024
            }
        );
        assert_eq!(credentials.port, 1024);
        // Reserved and lower ports are rejected. The stored port stays.
        for port in [0, 1023, PAIRING_PORT] {
            assert_eq!(
                learn_phone_info(&mut credentials, gateway, &status("172.20.10.1", port)),
                PortUpdate::Rejected
            );
            assert_eq!(credentials.port, 1024);
        }
        // Another host is rejected, including an unparsable host.
        for host in ["172.20.10.2", "not-an-address", "::1"] {
            assert_eq!(
                learn_phone_info(&mut credentials, gateway, &status(host, 20002)),
                PortUpdate::Rejected
            );
            assert_eq!(credentials.port, 1024);
            assert_eq!(credentials.host, gateway);
            assert_eq!(credentials.token, TOKEN);
        }
    }

    #[test]
    fn unknown_target_device_with_allow_then_known_target_device_without_prompt() {
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 2);
        let identity = Identity::from_bytes(L_S_PRIV);
        let (result, codes, audit) = run_pair(address, &identity, quick());
        let credentials = result.unwrap();
        assert_eq!(credentials.port, 1080);
        assert_eq!(credentials.token, TOKEN);
        assert_eq!(credentials.host, Ipv4Addr::LOCALHOST);
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].len(), 7);
        // The pairing socket comes from the normalized helpers.
        assert_eq!(audit, (1, 0));
        assert_eq!(phone.lock().unwrap().prompts, 1);
        let (result, _, _) = run_pair(address, &identity, quick());
        assert_eq!(result.unwrap().token, TOKEN);
        assert_eq!(phone.lock().unwrap().prompts, 1);
        handle.join().unwrap();
    }

    #[test]
    fn unknown_target_device_with_deny_and_lockout_after_three_denials() {
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Deny)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 4);
        let identity = Identity::from_bytes(L_S_PRIV);
        for _ in 0..3 {
            let (result, codes, _) = run_pair(address, &identity, quick());
            assert_eq!(result, Err(PairError::Phone(PhoneStatus::Denied)));
            assert_eq!(codes.len(), 1);
        }
        let (result, codes, _) = run_pair(address, &identity, quick());
        assert_eq!(result, Err(PairError::Phone(PhoneStatus::LockedOut)));
        assert!(codes.is_empty());
        handle.join().unwrap();
        // The lockout ends after 30 seconds of logical time.
        let mut state = phone.lock().unwrap();
        state.now += 30;
        assert!(state.locked_until.values().all(|t| state.now >= *t));
    }

    fn raw_exchange(address: SocketAddr, frames: &[Vec<u8>]) -> Vec<u8> {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = FrameReader::default();
        let mut last = Vec::new();
        for bytes in frames {
            stream.write_all(bytes).unwrap();
            last = match MockPhone::read(&mut stream, &mut reader) {
                Ok(frame) => frame,
                Err(_) => return last,
            };
            if last[0] == MSG_RESULT {
                return last;
            }
        }
        last
    }

    #[test]
    fn phone_rejects_bad_commitment_bad_proof_bad_length_and_oversize() {
        let phone = Arc::new(Mutex::new(MockPhone::new(Decide::Allow)));
        let (address, handle) = spawn_phone(Arc::clone(&phone), 4);
        let l_s = public(&L_S_PRIV);
        let l_e = public(&L_E_PRIV);
        let p_e = public(&P_E_PRIV);
        let rejected = encode_result_status(PhoneStatus::Rejected);

        // Bad commitment: REVEAL carries another L_e than HELLO committed to.
        let hello = frame(&encode_hello(&l_s, &commitment(&[9; 32], &l_s))).unwrap();
        let reveal = frame(&encode_reveal(&l_e, &[0; 32])).unwrap();
        assert_eq!(raw_exchange(address, &[hello, reveal]), rejected);

        // Bad proof: the commitment matches, the proof is wrong.
        let ee = agree(&StaticSecret::from(L_E_PRIV), &p_e).unwrap();
        let es = agree(&StaticSecret::from(L_S_PRIV), &p_e).unwrap();
        let keys = derive_keys(&ee, &es, transcript_hash(&l_s, &l_e, &p_e));
        let mut proof = laptop_proof(&keys);
        proof[31] ^= 1;
        let hello = frame(&encode_hello(&l_s, &commitment(&l_e, &l_s))).unwrap();
        let reveal = frame(&encode_reveal(&l_e, &proof)).unwrap();
        assert_eq!(raw_exchange(address, &[hello, reveal]), rejected);

        // Wrong-length HELLO.
        let short = frame(&encode_hello(&l_s, &l_s)[..60]).unwrap();
        assert_eq!(raw_exchange(address, &[short]), rejected);

        // Oversize frame.
        let mut big = ((MAX_FRAME + 1) as u16).to_be_bytes().to_vec();
        big.extend_from_slice(&[0; MAX_FRAME + 1]);
        assert_eq!(raw_exchange(address, &[big]), rejected);
        handle.join().unwrap();
        assert!(phone.lock().unwrap().trust.is_empty());
        // Invalid messages do not count toward the decision lockout.
        assert!(phone.lock().unwrap().locked_until.is_empty());
    }

    #[test]
    fn client_rejects_bad_phone_messages() {
        let identity = Identity::from_bytes(L_S_PRIV);
        for (faults, expected) in [
            (
                Faults {
                    tamper: true,
                    ..Faults::default()
                },
                PairError::Decrypt,
            ),
            (
                Faults {
                    oversize_challenge: true,
                    ..Faults::default()
                },
                PairError::Protocol,
            ),
            (
                Faults {
                    short_challenge: true,
                    ..Faults::default()
                },
                PairError::Protocol,
            ),
            (
                Faults {
                    wrong_host: true,
                    ..Faults::default()
                },
                PairError::Protocol,
            ),
        ] {
            let mut mock = MockPhone::new(Decide::Allow);
            mock.faults = faults;
            let (address, handle) = spawn_phone(Arc::new(Mutex::new(mock)), 1);
            let (result, _, _) = run_pair(address, &identity, quick());
            assert_eq!(result, Err(expected));
            handle.join().unwrap();
        }
    }

    #[test]
    fn silent_phone_times_out_and_cancel_stops_the_client() {
        let identity = Identity::from_bytes(L_S_PRIV);
        let mut mock = MockPhone::new(Decide::Allow);
        mock.faults.silent = true;
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(mock)), 1);
        let timeouts = PairTimeouts {
            challenge: Duration::from_millis(300),
            ..quick()
        };
        let started = Instant::now();
        let (result, _, _) = run_pair(address, &identity, timeouts);
        assert_eq!(result, Err(PairError::TimedOut));
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(started.elapsed() < Duration::from_secs(2));
        handle.join().unwrap();

        let mut mock = MockPhone::new(Decide::Allow);
        mock.faults.silent = true;
        let (address, handle) = spawn_phone(Arc::new(Mutex::new(mock)), 1);
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            flag.store(true, Ordering::Release);
        });
        let long = PairTimeouts {
            challenge: Duration::from_secs(30),
            ..quick()
        };
        let started = Instant::now();
        let result = pair_at(
            address,
            &identity,
            None,
            &normalization::Audit::default(),
            &cancel,
            long,
            |_| {},
        );
        assert_eq!(result, Err(PairError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(5));
        canceller.join().unwrap();
        handle.join().unwrap();

        // A set cancel flag stops the client before it connects.
        let cancel = AtomicBool::new(true);
        let result = pair_at(
            address,
            &identity,
            None,
            &normalization::Audit::default(),
            &cancel,
            quick(),
            |_| {},
        );
        assert_eq!(result, Err(PairError::Cancelled));
    }

    #[test]
    fn closed_port_maps_to_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let identity = Identity::from_bytes(L_S_PRIV);
        // Windows can need more than two seconds to report a refused loopback
        // connect. The result must still be Unreachable and not a timeout.
        let timeouts = PairTimeouts {
            connect: Duration::from_secs(10),
            ..quick()
        };
        let (result, _, _) = run_pair(address, &identity, timeouts);
        assert_eq!(result, Err(PairError::Unreachable));
        assert_eq!(
            PairError::Unreachable.message(),
            "Open HotspotShade on your source device."
        );
    }
}

#[cfg(test)]
mod pair_view_debug_tests {
    use super::*;

    #[test]
    fn pair_view_debug_does_not_print_the_code() {
        let view = PairView {
            phase: PairPhase::Idle,
            code: Some("918273".to_string()),
            host: Some(Ipv4Addr::new(172, 20, 10, 1)),
            port: Some(8080),
            error: None,
        };
        let text = format!("{view:?}");
        assert!(!text.contains("918273"), "{text}");
        assert!(text.contains("[redacted]"));
        assert!(text.contains("172.20.10.1"));
    }
}
