//! One-time administrator grant for a macOS tunnel start.
//!
//! The protected helper starts the engine without an administrator prompt. The
//! engine creates no route and no tunnel device until a person turns the tunnel
//! on. At that point the app asks Authorization Services for one administrator
//! authorization and sends the external form to the helper. The helper verifies
//! the fixed right and writes this grant into the engine's root-only runtime
//! directory. The engine consumes the grant before it changes a route.
//!
//! The grant is not a token. It is a fresh file in a root-owned 0700 directory.
//! A root process could forge it; root is outside this boundary. A non-root
//! process cannot write the directory. The file holds a random value and a
//! timestamp so a partial, stale, or substituted write is refused. The engine
//! removes the file before the start, so one authorization covers one start
//! attempt.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The helper writes one line: 64 hex characters, one space, and a Unix time.
const MAX_BYTES: u64 = 128;
/// An authorization older than this is not evidence of a fresh prompt.
const MAX_AGE_SECONDS: u64 = 60;
/// A small forward skew tolerates a clock step between the app and the engine.
const FUTURE_SKEW_SECONDS: u64 = 5;

/// One grant file for the helper-owned engine.
pub struct TunnelGrant {
    path: PathBuf,
    expected_owner: u32,
}

impl TunnelGrant {
    /// The production grant is root-owned and lives in the helper's root-only
    /// runtime directory.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            expected_owner: 0,
        }
    }

    /// A test seam. The hermetic tests run as the test user and cannot create
    /// a root-owned file. The GUI backend tests use the same seam to prove
    /// that an imported credential still needs a fresh grant.
    #[cfg(test)]
    pub(crate) fn with_expected_owner(path: PathBuf, expected_owner: u32) -> Self {
        Self {
            path,
            expected_owner,
        }
    }

    /// Validate and remove the grant. A missing, stale, malformed, symlinked,
    /// or wrongly owned grant is an error, and the caller must not start the
    /// tunnel. The removal is part of the check: one authorization covers one
    /// start attempt.
    pub fn consume(&self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("grant path has no parent"))?;
        validate_directory(parent, self.expected_owner)?;

        let named = fs::symlink_metadata(&self.path)?;
        validate_file(&named, self.expected_owner)?;

        // O_NOFOLLOW stops a name swap to a symlink between the metadata read
        // and the open. The opened inode must match the one that was checked.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        let opened = file.metadata()?;
        validate_file(&opened, self.expected_owner)?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(invalid("grant file changed during the check"));
        }

        let mut bytes = Vec::new();
        file.by_ref().take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("grant file has an invalid size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("grant is not text"))?;
        let line = text.strip_suffix('\n').unwrap_or(text);
        let mut fields = line.split(' ');
        let token = fields.next().unwrap_or("");
        let timestamp = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| invalid("grant has no timestamp"))?;
        if fields.next().is_some()
            || token.len() != 64
            || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("grant has an invalid value"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("system clock is before the epoch"))?
            .as_secs();
        if timestamp > now.saturating_add(FUTURE_SKEW_SECONDS)
            || now.saturating_sub(timestamp) > MAX_AGE_SECONDS
        {
            return Err(invalid("grant is stale"));
        }

        // A removal failure means the grant may still authorize another start.
        // Fail closed instead of leaving it in place.
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_directory(path: &Path, expected_owner: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || mode != 0o700
    {
        return Err(invalid("grant directory is not protected"));
    }
    Ok(())
}

fn validate_file(metadata: &fs::Metadata, expected_owner: u32) -> io::Result<()> {
    let mode = metadata.mode() & 0o777;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        // Owner-readable, and no group or other permission. A restrictive
        // umask may clear owner-write after the helper wrote the file.
        || mode & 0o077 != 0
        || mode & 0o400 == 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_BYTES
    {
        return Err(invalid("grant file is not protected"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (PathBuf, PathBuf, u32) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "hotspotshade-grant-{}-{}-{}",
            std::process::id(),
            nanos,
            unique
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("tunnel-grant");
        let owner = unsafe { libc::geteuid() } as u32;
        (directory, path, owner)
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn write_grant(path: &Path, timestamp: u64) {
        let token = "a".repeat(64);
        fs::write(path, format!("{token} {timestamp}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn consumes_one_fresh_grant_and_removes_it() {
        let (directory, path, owner) = fixture();
        write_grant(&path, now());
        let grant = TunnelGrant::with_expected_owner(path.clone(), owner);
        assert!(grant.consume().is_ok());
        assert!(!path.exists());
        assert!(grant.consume().is_err(), "a grant is single use");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn accepts_an_owner_read_only_grant() {
        // A restrictive umask can clear owner-write after the helper wrote the
        // file. The engine only needs owner-read and no group or other access.
        let (directory, path, owner) = fixture();
        write_grant(&path, now());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let grant = TunnelGrant::with_expected_owner(path.clone(), owner);
        assert!(grant.consume().is_ok());
        assert!(!path.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_a_missing_grant() {
        let (directory, path, owner) = fixture();
        let grant = TunnelGrant::with_expected_owner(path, owner);
        assert!(grant.consume().is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_a_stale_or_future_grant() {
        let (directory, path, owner) = fixture();
        write_grant(&path, now().saturating_sub(MAX_AGE_SECONDS + 1));
        let grant = TunnelGrant::with_expected_owner(path.clone(), owner);
        assert!(grant.consume().is_err());
        write_grant(&path, now().saturating_add(FUTURE_SKEW_SECONDS + 1));
        assert!(grant.consume().is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_a_malformed_grant() {
        let (directory, path, owner) = fixture();
        let grant = TunnelGrant::with_expected_owner(path.clone(), owner);
        for value in [
            String::new(),
            "short 123\n".into(),
            format!("{} 123\n", "z".repeat(64)),
            format!("{} 123 extra\n", "a".repeat(64)),
            format!("{}\n", "a".repeat(64)),
        ] {
            fs::write(&path, value).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(grant.consume().is_err());
        }
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_a_symlinked_or_wrongly_permissioned_grant() {
        let (directory, path, owner) = fixture();
        write_grant(&path, now());
        let target = directory.join("target");
        fs::write(&target, "target").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        let grant = TunnelGrant::with_expected_owner(path.clone(), owner);
        assert!(grant.consume().is_err());

        fs::remove_file(&path).unwrap();
        write_grant(&path, now());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(grant.consume().is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_a_grant_in_an_unprotected_directory() {
        let (directory, path, owner) = fixture();
        write_grant(&path, now());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let grant = TunnelGrant::with_expected_owner(path, owner);
        assert!(grant.consume().is_err());
        let _ = fs::remove_dir_all(directory);
    }
}
