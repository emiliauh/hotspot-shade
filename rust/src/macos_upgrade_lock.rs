//! The permanent macOS lock for install and upgrade exclusion.
//!
//! The lock is one root-owned regular file at
//! `/var/db/hotspotshade/start-exclusion`. A participating tunnel start takes
//! a nonblocking shared `flock` on that file before it opens a utun or changes
//! a route. The macOS helper takes the same lock before it spawns an engine and
//! passes the locked descriptor to the child. The unapproved installer
//! coordinator foundation takes an exclusive `flock` across its transition set,
//! which includes this file, for the whole replacement transaction. The kernel
//! releases the lock when the owning process exits, including after a crash,
//! so a free lock is liveness evidence and not a stale marker.
//!
//! The file is permanent. This module never unlinks, renames, or truncates it.
//! The first participant creates it with `O_EXCL` and mode `0600`, and every
//! later participant opens the same inode. An install coordinator must keep the
//! same rule. If the path names another file, a start fails closed instead of
//! adopting the replacement.
//!
//! The helper handoff is checked when the helper provides it. The helper sets
//! `HOTSPOTSHADE_START_EXCLUSION_FD` and the matching version, device, and
//! inode. The engine validates that descriptor against the lock that it opened
//! itself. A partial or mismatched handoff is a start failure. Direct mode has
//! no handoff and takes an independent shared lock, then writes its own launch
//! intent under that lock.
//!
//! The validation is deliberately strict:
//!
//! - The state directory must be a real directory, not a symlink, owned by
//!   root, with no group or other permission bit, no set-user-ID, set-group-ID,
//!   or sticky bit, and no extended access control list.
//! - The lock file is opened with `O_NOFOLLOW` and `O_CLOEXEC`, and its type,
//!   owner, link count, mode, and extended access control list are checked
//!   through the descriptor. A direct `engine-session` create and removal also
//!   refuse an extended access control list through the held descriptor, after
//!   the metadata checks and before the write or the unlink.
//! - The helper handoff descriptor must name the same inode and carry no
//!   extended access control list either.
//! - After the lock is taken, the descriptor is compared with the path again.
//!   A path that was replaced between the open and the lock fails closed.
//! - A held exclusive lock, an unreadable path, a failed access control list
//!   read, or any failed check is a start failure. There is no warning-only
//!   path. macOS reports an object without an extended access control list as
//!   `ENOENT`; every other read failure is treated as an unknown ACL state and
//!   refused.
//!
//! # Coverage
//!
//! This is an engine-side foundation, not complete install protection. The
//! helper and the engine use `start-exclusion`. The install coordinator
//! foundation holds a transition set that includes `start-exclusion`. Both
//! direct and helper starts refuse the installer journals, the legacy helper
//! start journal, and the cleanup marker. Direct starts also refuse an engine
//! launch intent; a helper handoff owns that intent. A build that predates this
//! lock does not participate. A root process that replaces the lock inode or
//! ignores the protocol defeats an advisory lock by design. The installer
//! package remains build-only and unapproved.
//!
//! A direct start writes the helper's existing `engine-session` launch intent
//! before it opens a utun and removes it only after route and device cleanup
//! finished. The file name and text match the helper's launch intent, so a
//! direct engine and a helper cannot both create it: the `O_EXCL` create is one
//! cooperative single-start slot. This is an engine-side use of the helper's
//! record, not a new protocol name. A helper whose session controller started
//! before the direct engine may still show an authorization prompt before its
//! own `engine-session` create refuses the start. No engine is started in that
//! case.
//!
//! A direct start that cannot remove the record after route and device cleanup
//! retains the shared lock for the rest of the process and reports a failed
//! cleanup. The intent guard also sets a per-service leftover flag when it drops
//! without a verified removal. That flag is sticky: the service treats it as
//! cleanup uncertainty at every later start gate, not only on the exit path.
//!
//! The create call removes only the inode that it created when a later step
//! fails. If that removal also fails, including the case where the unlink
//! succeeded but the directory sync failed, the record may remain and the
//! leftover flag is set. This module borrows the lock, so it cannot retain the
//! lock on that early creation-failure path; the service retains the lock when
//! it observes the flag. A start panic or an early failure therefore cannot
//! turn into a clean engine exit while the shared record still blocks later
//! starts.
//!
//! The guard must outlive route and device cleanup. The macOS service wraps the
//! guard and a direct start record in one lease. It gives the lease to the
//! tunnel worker, which releases it only after the routes and the device are
//! gone. A panic in the start body, in the channel handoff, or in the worker
//! retains the guard until process exit and leaves the record in place,
//! because the panic path cannot prove that route and device cleanup finished.
//! The guard also owns a descriptor with `O_CLOEXEC`, so a child process that
//! the engine spawns does not inherit this descriptor.
//!
//! The helper handoff descriptor is a separate inherited descriptor. The engine
//! keeps it open for the life of the process, because the helper contract says
//! the engine holds it until route and device cleanup finishes. At process
//! entry, when any handoff variable is present, the engine sets `FD_CLOEXEC` on
//! the fixed descriptor before it can start any child process. That early step
//! is hardening only: it uses the fixed number rather than an
//! environment-provided one and it does not treat the environment values as
//! proof. The binary entry point in `rust/src/main.rs` performs that seal and
//! mirrors the fixed descriptor and variable names from this module. The start
//! path still validates the descriptor, its inode, and its access control list,
//! and it seals the descriptor again. After validation the engine keeps
//! `FD_CLOEXEC` set, so a child that the engine spawns cannot inherit the
//! helper's locked open file description. The engine never calls
//! `flock(LOCK_UN)` on the handoff.
//!
//! # Limits of this pass
//!
//! These are prototype limits, not claims of complete exclusion:
//!
//! - The installer coordinator foundation is sandbox-only and unapproved. Its
//!   transition set includes `start-exclusion`, so a direct start and a
//!   coordinator transaction contend on this inode today. The set still holds
//!   three names, older binaries do not participate, and no cross-binary
//!   contention test has run. The `install-journal.json` check remains a
//!   point-in-time refusal, not a lock.
//! - A direct start writes the helper's `engine-session` name without a live
//!   cross-binary test. The Rust tests simulate the helper's `O_EXCL` create and
//!   prove that one participant wins. They do not run the signed helper.
//! - The helper session controller reads the intent when it starts and after a
//!   failed create. If a direct engine creates the intent after the controller
//!   started, the app may still show one authorization prompt before the
//!   helper's own create refuses the start. No engine is started in that case.
//! - The helper recovery procedure requires a person to look for direct CLI and
//!   GUI engines as well, and it states that a direct engine also owns an
//!   `engine-session` record. It does not give a separate reviewed recovery for
//!   a direct engine and does not approve removing the record by hand.
//!   `macos/Helper/README.md` does not approve removing `engine-session` by
//!   hand.
//! - A panic in the service start body or in the tunnel worker retains the
//!   shared lock and leaves the direct start record in place. The service wraps
//!   both in one lease, so the channel handoff and the worker's monitor setup
//!   are covered as well. A panic inside the retention path itself (for
//!   example an allocation failure in the retained-lock list), a process
//!   abort, and a panic after cleanup was explicitly proved are outside this
//!   guarantee. No route or device exists on the covered setup path when the
//!   lease is still armed.
//! - No live utun, route, helper, or installer run is part of this module's
//!   tests. The injected cleanup faults prove the reporting contract, not that
//!   the operating system removed a real route.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The root-owned state directory that the helper and the installer share.
pub(crate) const LOCK_DIRECTORY: &str = "/var/db/hotspotshade";

/// The permanent lock file inside [`LOCK_DIRECTORY`].
///
/// The name matches `HelperStartExclusionProtocol.lockFileName` in the macOS
/// helper. The installer coordinator foundation also locks this name as part of
/// its transition set.
pub(crate) const LOCK_FILE_NAME: &str = "start-exclusion";

/// The helper's older write-ahead journal. A direct start refuses when it is
/// present.
const START_JOURNAL_NAME: &str = "start-journal";

/// The helper's engine launch intent. A direct start refuses when it is present.
const ENGINE_SESSION_NAME: &str = "engine-session";

/// The helper's durable cleanup block. A direct start refuses when it is
/// present.
const CLEANUP_BLOCK_NAME: &str = "cleanup-blocked";

/// The installer coordinator's file transaction journal. A direct start
/// refuses when it is present. The helper already reads this name. The engine
/// only inspects it here and never writes, replaces, or removes it.
const INSTALL_JOURNAL_NAME: &str = "install-journal.json";
const SERVICE_JOURNAL_NAME: &str = "service-journal.json";

/// The exact text of the helper's `engine-session` launch intent. A direct
/// start writes the same bytes, so the file has one meaning for both
/// participants. The helper checks presence, not the text.
const DIRECT_INTENT_CONTENTS: &[u8] = b"hotspotshade engine launch intent\n";

/// The helper's fixed handoff descriptor, environment, and protocol version.
const HANDOFF_DESCRIPTOR: libc::c_int = 5;
const HANDOFF_VERSION: u64 = 1;
const HANDOFF_FD_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_FD";
const HANDOFF_VERSION_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_VERSION";
const HANDOFF_DEVICE_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_DEVICE";
const HANDOFF_INODE_ENV: &str = "HOTSPOTSHADE_START_EXCLUSION_INODE";

/// The owner of the production lock. Only root can create or replace the
/// directory entry on a normal macOS host.
const LOCK_OWNER: u32 = 0;

/// The fixed text for a start that cannot take the lock. It holds no path,
/// token, or key.
pub(crate) const START_REFUSED_MESSAGE: &str =
    "The tunnel cannot start because the start-exclusion state is not clean. Another start or install may be active, a cleanup block or an install journal may be present, or the lock path may be unsafe.";

/// The type of lock that one participant takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockKind {
    /// A tunnel or engine start.
    Shared,
    /// The unapproved installer coordinator foundation. Tests use it to prove
    /// exclusion.
    #[cfg(test)]
    Exclusive,
}

impl LockKind {
    fn flock_flag(self) -> libc::c_int {
        match self {
            Self::Shared => libc::LOCK_SH,
            #[cfg(test)]
            Self::Exclusive => libc::LOCK_EX,
        }
    }
}

/// One validated state directory and the owner that it must have.
#[derive(Clone, Debug)]
struct LockLocation {
    directory: PathBuf,
    expected_owner: u32,
}

impl LockLocation {
    fn production() -> Self {
        Self {
            directory: PathBuf::from(LOCK_DIRECTORY),
            expected_owner: LOCK_OWNER,
        }
    }
}

/// A held shared lock on the permanent install exclusion inode.
///
/// The kernel releases the `flock` when the file descriptor closes. The file
/// itself stays in place. Drop this guard only after the tunnel worker has
/// removed every route and device that the run created.
#[derive(Debug)]
pub(crate) struct UpgradeLock {
    _file: File,
    _directory: File,
    expected_owner: u32,
    helper_handoff: bool,
}

/// Take the shared lock that a macOS tunnel start needs.
///
/// The caller must already have verified that it runs as root and must call
/// this before it opens a utun or changes a route. A held exclusive lock, an
/// unsafe file, or a failed check returns an error. The caller must treat that
/// error as a start failure.
pub(crate) fn acquire_for_tunnel_start() -> io::Result<UpgradeLock> {
    let location = LockLocation::production();
    let mut lock = acquire(&location, LockKind::Shared)?;
    let handoff = validate_helper_handoff(&lock, location.expected_owner)?;
    lock.helper_handoff = handoff;
    refuse_start_files(&lock, handoff)?;
    Ok(lock)
}

/// Take a shared lock on a disposable test directory.
///
/// The caller owns the directory. This runs the same open, validate, lock, and
/// locked-path checks as a start, but it uses no root path and no helper
/// handoff. It is a test seam for the service's panic-safe start lease.
#[cfg(test)]
pub(crate) fn acquire_shared_for_test(directory: &Path) -> io::Result<UpgradeLock> {
    acquire(&test_location(directory), LockKind::Shared)
}

/// Try to take the installer's exclusive lock on a disposable test directory.
///
/// A retained shared lock makes this return `WouldBlock`, which is the
/// exclusion evidence that the start-lease tests need.
#[cfg(test)]
pub(crate) fn acquire_exclusive_for_test(directory: &Path) -> io::Result<UpgradeLock> {
    acquire(&test_location(directory), LockKind::Exclusive)
}

#[cfg(test)]
fn test_location(directory: &Path) -> LockLocation {
    LockLocation {
        directory: directory.to_path_buf(),
        expected_owner: unsafe { libc::geteuid() },
    }
}

/// The path of the direct start record inside a test state directory.
#[cfg(test)]
pub(crate) fn direct_intent_path_for_test(directory: &Path) -> PathBuf {
    directory.join(ENGINE_SESSION_NAME)
}

impl UpgradeLock {
    /// True when the helper started this engine and owns the launch intent.
    ///
    /// A direct start writes and clears its own `engine-session` record. A
    /// helper session already has one that the helper owns, so the engine must
    /// not create or remove it.
    pub(crate) fn helper_handoff(&self) -> bool {
        self.helper_handoff
    }
}

/// The non-secret values that the helper passes to its engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HelperHandoff {
    descriptor: libc::c_int,
    version: u64,
    device: u64,
    inode: u64,
}

/// Check the helper handoff when the helper started this engine.
///
/// Direct mode has no handoff variables and needs no extra check. A partial
/// handoff is a start failure, not a reason to guess. The return value is true
/// when a helper handoff was present and validated.
fn validate_helper_handoff(lock: &UpgradeLock, expected_owner: u32) -> io::Result<bool> {
    let values = [
        read_handoff_environment(HANDOFF_FD_ENV)?,
        read_handoff_environment(HANDOFF_VERSION_ENV)?,
        read_handoff_environment(HANDOFF_DEVICE_ENV)?,
        read_handoff_environment(HANDOFF_INODE_ENV)?,
    ];
    let Some(handoff) = parse_helper_handoff(values)? else {
        return Ok(false);
    };
    validate_handoff_descriptor(
        lock,
        handoff.descriptor,
        handoff.version,
        handoff.device,
        handoff.inode,
        expected_owner,
    )?;
    Ok(true)
}

fn read_handoff_environment(name: &str) -> io::Result<Option<String>> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(value) => value.into_string().map(Some).map_err(|_| {
            io::Error::other(format!(
                "the helper start-exclusion variable {name} is not valid UTF-8"
            ))
        }),
    }
}

fn parse_helper_handoff(values: [Option<String>; 4]) -> io::Result<Option<HelperHandoff>> {
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [fd, version, device, inode] = values;
    let (Some(fd), Some(version), Some(device), Some(inode)) = (fd, version, device, inode) else {
        return Err(io::Error::other(
            "the helper start-exclusion handoff is incomplete",
        ));
    };
    let descriptor = fd
        .parse::<libc::c_int>()
        .map_err(|_| io::Error::other("the helper handoff descriptor is not a number"))?;
    let parse = |value: &str, label: &str| {
        value
            .parse::<u64>()
            .map_err(|_| io::Error::other(format!("the helper handoff {label} is not a number")))
    };
    let version = parse(&version, "version")?;
    let device = parse(&device, "device")?;
    let inode = parse(&inode, "inode")?;
    if descriptor != HANDOFF_DESCRIPTOR {
        return Err(io::Error::other(
            "the helper start-exclusion handoff uses an unexpected descriptor",
        ));
    }
    if version != HANDOFF_VERSION {
        return Err(io::Error::other(
            "the helper start-exclusion handoff uses an unsupported version",
        ));
    }
    Ok(Some(HelperHandoff {
        descriptor: HANDOFF_DESCRIPTOR,
        version,
        device,
        inode,
    }))
}

/// Prove that the inherited descriptor is the same permanent inode that this
/// engine locked independently.
///
/// The helper already checks its lock next to the spawn. This second check
/// catches a partial environment, a replaced lock path, or a descriptor that
/// was closed before the engine reached the start path.
fn validate_handoff_descriptor(
    lock: &UpgradeLock,
    descriptor: libc::c_int,
    version: u64,
    device: u64,
    inode: u64,
    expected_owner: u32,
) -> io::Result<()> {
    if descriptor != HANDOFF_DESCRIPTOR {
        return Err(io::Error::other(
            "the helper start-exclusion handoff uses an unexpected descriptor",
        ));
    }
    if version != HANDOFF_VERSION {
        return Err(io::Error::other(
            "the helper start-exclusion handoff uses an unsupported version",
        ));
    }
    if lock._file.as_raw_fd() == descriptor {
        return Err(io::Error::other(
            "the helper start-exclusion handoff names the engine's own descriptor",
        ));
    }
    validate_handoff_file(lock, descriptor, device, inode, expected_owner)
}

/// Check the inherited descriptor and its device and inode.
fn validate_handoff_file(
    lock: &UpgradeLock,
    descriptor: libc::c_int,
    device: u64,
    inode: u64,
    expected_owner: u32,
) -> io::Result<()> {
    let held = lock._file.metadata().map_err(|error| {
        lock_io_error("cannot inspect the engine's start-exclusion lock", error)
    })?;
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
        return Err(lock_io_error(
            "cannot inspect the helper start-exclusion handoff",
            io::Error::last_os_error(),
        ));
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_nlink != 1
        || status.st_uid != expected_owner
        || !safe_file_mode(u64::from(status.st_mode))
        || status.st_dev as u64 != device
        || status.st_ino != inode
        || status.st_dev as u64 != held.dev()
        || status.st_ino != held.ino()
    {
        return Err(io::Error::other(
            "the helper start-exclusion handoff does not name the locked single-link file; the start was refused",
        ));
    }
    // The handoff is a second descriptor for the same inode. Read its ACL
    // directly as well, so a handoff read failure is a start failure and not
    // an assumed clean file.
    refuse_extended_acl(descriptor, "helper start-exclusion handoff")?;
    // The process-entry seal normally sets close-on-exec already. Set it again
    // through the descriptor that this start validated, so a start path that
    // did not run the early seal still cannot pass the handoff to a child.
    // Keep the descriptor open: the helper contract says the engine holds it
    // until route and device cleanup finishes. The engine's own lock is a
    // separate descriptor with its own shared `flock`.
    seal_handoff_descriptor(descriptor)
}

/// Set `FD_CLOEXEC` on the validated helper handoff descriptor.
fn seal_handoff_descriptor(descriptor: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(lock_io_error(
            "cannot inspect the helper start-exclusion handoff flags",
            io::Error::last_os_error(),
        ));
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(lock_io_error(
            "cannot set close-on-exec on the helper start-exclusion handoff",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Refuse a direct start while a refusal file is present.
///
/// The helper creates `start-journal` before it spawns an engine in the older
/// contract, and `engine-session` before every launch. It creates
/// `cleanup-blocked` after an unclean stop and never removes it. The installer
/// coordinator owns `install-journal.json` and the service transaction owns
/// `service-journal.json`; each is removed only after its own recovery
/// procedure. The helper owns its engine-session intent, but does not own the
/// installer journals. An unreadable directory is also a refusal.
fn refuse_start_files(lock: &UpgradeLock, helper_handoff: bool) -> io::Result<()> {
    refuse_if_refusal_file_present(
        lock,
        START_JOURNAL_NAME,
        "a helper start journal is present; complete recovery before starting",
    )?;
    if !helper_handoff {
        refuse_if_refusal_file_present(
            lock,
            ENGINE_SESSION_NAME,
            "an engine launch intent is present; complete recovery before starting",
        )?;
    }
    refuse_if_refusal_file_present(
        lock,
        CLEANUP_BLOCK_NAME,
        "a cleanup block is present; complete recovery before starting",
    )?;
    refuse_if_refusal_file_present(
        lock,
        INSTALL_JOURNAL_NAME,
        "an install journal is present; complete installer recovery before starting",
    )?;
    refuse_if_refusal_file_present(
        lock,
        SERVICE_JOURNAL_NAME,
        "a service journal is present; complete installer recovery before starting",
    )
}

#[cfg(test)]
fn refuse_direct_start_files(lock: &UpgradeLock) -> io::Result<()> {
    refuse_start_files(lock, false)
}

fn refuse_if_refusal_file_present(
    lock: &UpgradeLock,
    file_name: &str,
    message: &str,
) -> io::Result<()> {
    let name = CString::new(file_name)
        .map_err(|_| io::Error::other("the helper refusal file name contains a NUL byte"))?;
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            lock._directory.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(io::Error::other(message.to_owned()));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(lock_io_error("cannot inspect a helper refusal file", error))
    }
}

/// One durable `engine-session` record that a direct start created.
///
/// The file is the helper's existing launch intent. A direct start uses the
/// same name and text so one `O_EXCL` create is a single cooperative start
/// slot for both the helper and the direct engine. The record stays after a
/// crash or an unclean cleanup, and a later start refuses until a reviewed
/// recovery clears it. No reviewed recovery for a direct engine is approved
/// yet.
///
/// Dropping this value closes its descriptors and leaves the file in place.
/// Only [`DirectStartIntent::remove_after_clean_cleanup`] removes it.
#[derive(Debug)]
pub(crate) struct DirectStartIntent {
    directory: File,
    file: File,
    expected_owner: u32,
    removed: bool,
    leftover: Arc<AtomicBool>,
}

impl DirectStartIntent {
    /// Remove the direct start record after route and device cleanup finished.
    ///
    /// The path must still name the inode that this start created, and the held
    /// descriptor must carry no extended access control list. A replaced,
    /// unsafe, or access-control-list-bearing record detected by the check is
    /// left in place and reported as an error. The check and unlink are separate
    /// calls, so a cooperative writer must not replace the name between them.
    /// A missing file is already clean. The containing
    /// directory is synced before the caller treats the removal as durable. An
    /// unlink that succeeds before a failed directory sync returns an error and
    /// still sets the leftover flag on drop, because the removal could be lost
    /// on a crash.
    pub(crate) fn remove_after_clean_cleanup(&mut self) -> io::Result<()> {
        remove_direct_start_file(&self.directory, &self.file, self.expected_owner)?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for DirectStartIntent {
    fn drop(&mut self) {
        if !self.removed {
            self.leftover.store(true, Ordering::Release);
        }
    }
}

/// Create the durable write-ahead record that a direct macOS start needs.
///
/// The caller already holds the shared `start-exclusion` lock and has verified
/// that no refusal file is present. The create is `O_EXCL`, so a helper or a
/// second direct start that wins the race makes this call fail instead of
/// overwriting its record. The file is mode `0600`, one link, written with the
/// helper's fixed text, and synced with its directory before this function
/// returns. The opened descriptor must carry no extended access control list;
/// that check runs after the metadata check and before the write, and a
/// refused record is not removed from under an ACL that a person must inspect.
pub(crate) fn create_direct_start_intent(
    lock: &UpgradeLock,
    leftover: Arc<AtomicBool>,
) -> io::Result<DirectStartIntent> {
    if lock.helper_handoff {
        return Err(io::Error::other(
            "a helper start owns the launch intent for this session",
        ));
    }
    let directory = lock._directory.try_clone().map_err(|error| {
        lock_io_error("cannot duplicate the direct start state directory", error)
    })?;
    let name = CString::new(ENGINE_SESSION_NAME).expect("the launch intent name has no NUL");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a direct or helper launch intent is present; complete recovery before starting",
            ));
        }
        return Err(lock_io_error(
            "cannot create the direct start record",
            error,
        ));
    }
    // The descriptor is owned by this File from here on.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let created = (|| -> io::Result<()> {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600 as libc::mode_t) } != 0 {
            return Err(lock_io_error(
                "cannot set the mode of the new direct start record",
                io::Error::last_os_error(),
            ));
        }
        let metadata = file
            .metadata()
            .map_err(|error| lock_io_error("cannot inspect the new direct start record", error))?;
        if !safe_intent_file(&metadata, lock.expected_owner) {
            return Err(io::Error::other(
                "the new direct start record must be a single-link owner-only regular file",
            ));
        }
        run_direct_intent_hook(file.as_raw_fd());
        // A mode bit is not the whole permission story. Refuse an extended ACL
        // through the held descriptor after the metadata check and before any
        // byte is written, as the helper does for its state files.
        refuse_extended_acl(file.as_raw_fd(), "direct start record")?;
        use std::io::Write;
        file.write_all(DIRECT_INTENT_CONTENTS)
            .map_err(|error| lock_io_error("cannot write the direct start record", error))?;
        file.sync_all()
            .map_err(|error| lock_io_error("cannot sync the direct start record", error))?;
        directory
            .sync_all()
            .map_err(|error| lock_io_error("cannot sync the direct start record directory", error))
    })();
    if let Err(error) = created {
        // Remove only the inode that this call created. A replaced path is left
        // in place for recovery. A failed removal is an uncertain record and
        // makes the exit path report a cleanup failure.
        if remove_direct_start_file(&directory, &file, lock.expected_owner).is_err() {
            leftover.store(true, Ordering::Release);
        }
        return Err(error);
    }
    Ok(DirectStartIntent {
        directory,
        file,
        expected_owner: lock.expected_owner,
        removed: false,
        leftover,
    })
}

/// Remove the record only when the path still names the created inode and the
/// held descriptor carries no extended access control list.
fn remove_direct_start_file(directory: &File, file: &File, expected_owner: u32) -> io::Result<()> {
    let held = file
        .metadata()
        .map_err(|error| lock_io_error("cannot inspect the direct start record", error))?;
    let name = CString::new(ENGINE_SESSION_NAME).expect("the launch intent name has no NUL");
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(lock_io_error(
            "cannot inspect the direct start record path",
            error,
        ));
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_nlink != 1
        || status.st_uid != expected_owner
        || !safe_file_mode(u64::from(status.st_mode))
        || status.st_dev as u64 != held.dev()
        || status.st_ino != held.ino()
    {
        return Err(io::Error::other(
            "the direct start record path no longer names the created single-link file; it was not removed",
        ));
    }
    // The path names the held inode, so the held descriptor is the same object.
    // Refuse an extended ACL through that descriptor before the unlink. A
    // replaced path or an ACL failure leaves the record in place for recovery.
    refuse_extended_acl(file.as_raw_fd(), "direct start record")?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(lock_io_error(
            "cannot remove the direct start record",
            error,
        ));
    }
    run_direct_remove_sync_hook()?;
    directory
        .sync_all()
        .map_err(|error| lock_io_error("cannot sync the removed direct start record", error))
}

/// A launch intent file is safe when it is one owner-only regular file with one
/// link. The helper uses the same rule for its files.
fn safe_intent_file(metadata: &std::fs::Metadata, expected_owner: u32) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == expected_owner
        && safe_file_mode(u64::from(metadata.mode()))
}

/// Keep a shared lock for the rest of this process when cleanup did not finish.
///
/// The kernel releases the lock only when the process exits. A later install
/// coordinator therefore cannot take the exclusive lock while routes or a
/// device from this run may remain. The vector is bounded by the service's
/// sticky cleanup gate: one process refuses further starts after the first
/// failed cleanup, including a direct start record that could not be removed.
pub(crate) fn retain_until_exit(lock: UpgradeLock) {
    retained_locks()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(lock);
}

fn retained_locks() -> &'static std::sync::Mutex<Vec<UpgradeLock>> {
    static RETAINED: std::sync::OnceLock<std::sync::Mutex<Vec<UpgradeLock>>> =
        std::sync::OnceLock::new();
    RETAINED.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Drop every retained lock in a test. Production processes keep their
/// retained locks until the kernel closes the descriptors at exit.
///
/// The caller serializes with [`retained_lock_serial_for_test`], so a test that
/// asserts exclusion is not cleared by another test's release.
#[cfg(test)]
fn release_retained_locks_for_test() {
    let _serial = retained_lock_serial_for_test();
    retained_locks()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

/// Serialize tests that observe the process-wide retained-lock list.
///
/// Retained locks are global by design, so a release in one test would
/// otherwise drop the lock that another test is asserting on.
#[cfg(test)]
pub(crate) fn retained_lock_serial_for_test() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    SERIAL
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

/// Create the state directory when it is absent, then open and validate it.
///
/// The directory is created with mode `0700`. An existing path is opened with
/// `O_NOFOLLOW` and `O_DIRECTORY`, so a symlink or a regular file is refused.
fn open_state_directory(location: &LockLocation) -> io::Result<File> {
    let mut created = false;
    match std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&location.directory)
    {
        Ok(()) => {
            created = true;
            sync_parent_directory(&location.directory)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(lock_io_error(
                &format!(
                    "cannot create the tunnel upgrade lock directory {}",
                    location.directory.display()
                ),
                error,
            ));
        }
    }
    let descriptor = unsafe {
        libc::open(
            path_pointer(&location.directory)?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(lock_io_error(
            &format!(
                "cannot open the tunnel upgrade lock directory {}",
                location.directory.display()
            ),
            io::Error::last_os_error(),
        ));
    }
    // The descriptor is owned by the returned File from here on.
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let metadata = directory.metadata().map_err(|error| {
        lock_io_error(
            &format!(
                "cannot inspect the tunnel upgrade lock directory {}",
                location.directory.display()
            ),
            error,
        )
    })?;
    if !safe_directory(&metadata, location.expected_owner) {
        return Err(io::Error::other(format!(
            "the tunnel upgrade lock directory {} must be a root-owned directory with no group or other permission and no set-user-ID, set-group-ID, or sticky bit",
            location.directory.display()
        )));
    }
    refuse_extended_acl(directory.as_raw_fd(), "tunnel upgrade lock directory")?;
    if created {
        directory.sync_all().map_err(|error| {
            lock_io_error(
                &format!(
                    "cannot sync the new tunnel upgrade lock directory {}",
                    location.directory.display()
                ),
                error,
            )
        })?;
    }
    Ok(directory)
}

/// Open the permanent lock file, or create it with `O_EXCL` when it is absent.
///
/// A new file is empty and has no meaning except as a lock target. The existing
/// file is opened read-only because `flock` does not need write access. This
/// lets a coordinator install a read-only lock inode without breaking starts.
fn open_lock_file(directory: &File) -> io::Result<File> {
    let name = CString::new(LOCK_FILE_NAME).expect("the lock file name has no NUL");
    let created = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if created >= 0 {
        // The descriptor is owned by this File from here on.
        let file = unsafe { File::from_raw_fd(created) };
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600 as libc::mode_t) } != 0 {
            return Err(lock_io_error(
                "cannot set the mode of the new tunnel upgrade lock file",
                io::Error::last_os_error(),
            ));
        }
        file.sync_all().map_err(|error| {
            lock_io_error("cannot sync the new tunnel upgrade lock file", error)
        })?;
        directory.sync_all().map_err(|error| {
            lock_io_error(
                "cannot sync the new tunnel upgrade lock directory entry",
                error,
            )
        })?;
        return Ok(file);
    }
    let create_error = io::Error::last_os_error();
    if create_error.kind() != io::ErrorKind::AlreadyExists {
        return Err(lock_io_error(
            "cannot create the tunnel upgrade lock file",
            create_error,
        ));
    }
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(lock_io_error(
            "cannot open the tunnel upgrade lock file",
            io::Error::last_os_error(),
        ));
    }
    // The descriptor is owned by the returned File from here on.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// Take the lock and return the guard.
fn acquire(location: &LockLocation, kind: LockKind) -> io::Result<UpgradeLock> {
    let directory = open_state_directory(location)?;
    let file = open_lock_file(&directory)?;
    validate_lock_file(&file, location.expected_owner)?;
    run_open_hook(&location.directory.join(LOCK_FILE_NAME));
    lock_file(&file, kind)?;
    run_post_lock_hook(&location.directory.join(LOCK_FILE_NAME));
    validate_locked_path(&directory, &file, location.expected_owner)?;
    Ok(UpgradeLock {
        _file: file,
        _directory: directory,
        expected_owner: location.expected_owner,
        helper_handoff: false,
    })
}

/// Take one nonblocking `flock`.
///
/// A held lock is a live participant, not a stale state. The caller fails the
/// start and does not wait or retry.
fn lock_file(file: &File, kind: LockKind) -> io::Result<()> {
    loop {
        let result = unsafe { libc::flock(file.as_raw_fd(), kind.flock_flag() | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another process holds the tunnel upgrade lock; an install or tunnel may be running",
            ));
        }
        return Err(lock_io_error("cannot take the tunnel upgrade lock", error));
    }
}

/// Check the file through the locked descriptor.
fn validate_lock_file(file: &File, expected_owner: u32) -> io::Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| lock_io_error("cannot inspect the tunnel upgrade lock file", error))?;
    if !safe_lock_file(&metadata, expected_owner) {
        return Err(io::Error::other(
            "the tunnel upgrade lock must be a single-link root-owned regular file with no group or other permission and no set-user-ID, set-group-ID, or sticky bit",
        ));
    }
    refuse_extended_acl(file.as_raw_fd(), "tunnel upgrade lock file")
}

/// Check that the locked descriptor is still the file at the permanent path.
///
/// The open and the lock are separate calls. Another process can replace the
/// path between them. A lock on an unlinked inode protects nothing, so this
/// check fails closed and does not adopt the replacement.
fn validate_locked_path(directory: &File, file: &File, expected_owner: u32) -> io::Result<()> {
    let held = file
        .metadata()
        .map_err(|error| lock_io_error("cannot re-inspect the tunnel upgrade lock file", error))?;
    let name = CString::new(LOCK_FILE_NAME).expect("the lock file name has no NUL");
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(lock_io_error(
            "cannot inspect the tunnel upgrade lock path after locking",
            io::Error::last_os_error(),
        ));
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_nlink != 1
        || status.st_uid != expected_owner
        || !safe_file_mode(u64::from(status.st_mode))
        || status.st_dev as u64 != held.dev()
        || status.st_ino != held.ino()
    {
        return Err(io::Error::other(
            "the tunnel upgrade lock path no longer names the locked single-link file; the start was refused",
        ));
    }
    // The descriptor and the path now name the same inode. Re-read the ACL
    // through that descriptor so an ACL added between the open and the lock is
    // refused. This is a point-in-time read, not a race-free guarantee.
    refuse_extended_acl(file.as_raw_fd(), "tunnel upgrade lock file")
}

/// A directory is safe when it is real, owned by the expected account, and has
/// no group or other permission and no set-user-ID, set-group-ID, or sticky
/// bit.
///
/// The helper and the coordinator both require mode `0700` for the state
/// directory, so a wider directory is a state that they will refuse.
fn safe_directory(metadata: &std::fs::Metadata, expected_owner: u32) -> bool {
    metadata.is_dir()
        && metadata.uid() == expected_owner
        && metadata.mode() & 0o077 == 0
        && metadata.mode() & 0o7000 == 0
}

/// A lock file is safe when it is one regular file with one link, owned by the
/// expected account, and has no group or other permission and no set-user-ID,
/// set-group-ID, or sticky bit.
///
/// The file may be read-only. `flock` does not require write access, and the
/// file holds no data. Any group or other permission is refused because the
/// helper uses the same rule for the same inode.
fn safe_lock_file(metadata: &std::fs::Metadata, expected_owner: u32) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == expected_owner
        && safe_file_mode(u64::from(metadata.mode()))
}

/// The mode has no group or other permission and none of the set-user-ID,
/// set-group-ID, or sticky bits. `0o7000` covers all three special bits, so a
/// sticky state directory is refused with the same rule.
fn safe_file_mode(mode: u64) -> bool {
    mode & 0o077 == 0 && mode & 0o7000 == 0
}

/// Sync the parent directory after a new state directory is created, so the
/// directory entry itself survives a crash.
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("the tunnel upgrade lock directory has no parent"))?;
    let descriptor = unsafe {
        libc::open(
            path_pointer(parent)?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(lock_io_error(
            "cannot open the parent of the tunnel upgrade lock directory",
            io::Error::last_os_error(),
        ));
    }
    // The descriptor is owned by this File from here on.
    let parent = unsafe { File::from_raw_fd(descriptor) };
    parent
        .sync_all()
        .map_err(|error| lock_io_error("cannot sync the tunnel upgrade lock parent", error))
}

/// Convert a path to a C string without accepting an embedded NUL.
fn path_pointer(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("the tunnel upgrade lock path contains a NUL byte"))
}

/// Keep the OS error text but always report an ordinary start failure. The
/// service maps an ordinary failure to its generic start message. A lock
/// permission problem is not an administrator prompt.
fn lock_io_error(context: &str, error: io::Error) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}

/// The small macOS access control list surface that this module needs.
///
/// The `libc` crate has no ACL bindings, so the two calls that production uses
/// are declared here. The test-only calls build one entry for a disposable
/// temporary object. This module is compiled only for macOS, where the lock
/// exists.
#[cfg(target_os = "macos")]
mod acl {
    use std::io;
    use std::os::fd::RawFd;

    /// `ACL_TYPE_EXTENDED` from `<sys/acl.h>`.
    const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
    /// `ACL_EXTENDED_ALLOW` from `<sys/acl.h>`.
    #[cfg(test)]
    const ACL_EXTENDED_ALLOW: u32 = 1;
    /// `ACL_READ_DATA` from `<sys/acl.h>`.
    #[cfg(test)]
    const ACL_READ_DATA: u32 = 1 << 1;

    #[link(name = "System")]
    extern "C" {
        fn acl_get_fd_np(descriptor: RawFd, acl_type: u32) -> *mut libc::c_void;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        #[cfg(test)]
        fn acl_init(count: libc::c_int) -> *mut libc::c_void;
        #[cfg(test)]
        fn acl_create_entry(
            acl: *mut *mut libc::c_void,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        #[cfg(test)]
        fn acl_set_tag_type(entry: *mut libc::c_void, tag: u32) -> libc::c_int;
        #[cfg(test)]
        fn acl_get_permset(
            entry: *mut libc::c_void,
            permset: *mut *mut libc::c_void,
        ) -> libc::c_int;
        #[cfg(test)]
        fn acl_add_perm(permset: *mut libc::c_void, perm: u32) -> libc::c_int;
        #[cfg(test)]
        fn acl_set_permset(entry: *mut libc::c_void, permset: *mut libc::c_void) -> libc::c_int;
        #[cfg(test)]
        fn acl_set_fd_np(descriptor: RawFd, acl: *mut libc::c_void, acl_type: u32) -> libc::c_int;
    }

    /// True when the opened object carries any extended access control list.
    ///
    /// The check is by descriptor, so a path swap cannot substitute another
    /// object between the open and the check. macOS reports an object without
    /// an extended access control list as `ENOENT`. Every other failure means
    /// the ACL state is unknown, so the caller must fail the start.
    pub(super) fn has_extended_acl(descriptor: RawFd) -> io::Result<bool> {
        // `acl_get_fd_np` reports "no ACL" through errno, so clear stale text
        // before the call. A descriptor that cannot be inspected returns
        // `EBADF`, not `ENOENT`.
        unsafe { *libc::__error() = 0 };
        let acl = unsafe { acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(error);
        }
        // The ACL object is owned by the caller. The lock only asks whether one
        // exists, so it releases the object at once. A failed free leaks the
        // object but cannot change the answer.
        unsafe { acl_free(acl) };
        Ok(true)
    }

    /// Add one allow entry to an opened object. Tests only.
    #[cfg(test)]
    pub(super) fn add_extended_acl(descriptor: RawFd) -> io::Result<()> {
        struct OwnedAcl(*mut libc::c_void);

        impl Drop for OwnedAcl {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { acl_free(self.0) };
                }
            }
        }

        let mut acl = OwnedAcl(unsafe { acl_init(1) });
        if acl.0.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut entry: *mut libc::c_void = std::ptr::null_mut();
        if unsafe { acl_create_entry(&mut acl.0, &mut entry) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut permset: *mut libc::c_void = std::ptr::null_mut();
        if unsafe { acl_get_permset(entry, &mut permset) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { acl_add_perm(permset, ACL_READ_DATA) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { acl_set_permset(entry, permset) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { acl_set_fd_np(descriptor, acl.0, ACL_TYPE_EXTENDED) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Refuse an opened object that carries any extended access control list.
///
/// The macOS helper and the installer apply the same rule to the shared state
/// directory and lock file. A direct start must not accept an object that they
/// would refuse. A failed read is a refusal, not an absent ACL. The check is a
/// point-in-time read of the held descriptor; it does not prove that no ACL is
/// added later.
#[cfg(target_os = "macos")]
fn refuse_extended_acl(descriptor: std::os::fd::RawFd, what: &str) -> io::Result<()> {
    let present = acl::has_extended_acl(descriptor).map_err(|error| {
        lock_io_error(
            &format!("cannot read the {what} extended access control list"),
            error,
        )
    })?;
    if present {
        return Err(io::Error::other(format!(
            "the {what} must not carry an extended access control list"
        )));
    }
    Ok(())
}

#[cfg(not(test))]
fn run_open_hook(_path: &Path) {}

/// A test seam that runs after the file is opened but before the lock is
/// taken. A test uses it to replace the path at that exact point. Production
/// builds have no seam.
#[cfg(test)]
fn run_open_hook(path: &Path) {
    let hook = OPEN_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(test)]
type OpenHook = std::cell::RefCell<Option<Box<dyn Fn(&Path)>>>;

#[cfg(test)]
thread_local! {
    static OPEN_HOOK: OpenHook = const { std::cell::RefCell::new(None) };
}

#[cfg(not(test))]
fn run_post_lock_hook(_path: &Path) {}

/// A test seam that runs after the lock is taken but before the locked path is
/// checked again. A test uses it to add an access control list at that exact
/// point. Production builds have no seam.
#[cfg(test)]
fn run_post_lock_hook(path: &Path) {
    let hook = POST_LOCK_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(test)]
type PostLockHook = std::cell::RefCell<Option<Box<dyn Fn(&Path)>>>;

#[cfg(test)]
thread_local! {
    static POST_LOCK_HOOK: PostLockHook = const { std::cell::RefCell::new(None) };
}

#[cfg(not(test))]
fn run_direct_intent_hook(_descriptor: std::os::fd::RawFd) {}

/// A test seam that runs after a new direct start record passes its metadata
/// check but before its access control list is read. A test uses it to add an
/// entry at that exact point. Production builds have no seam.
#[cfg(test)]
fn run_direct_intent_hook(descriptor: std::os::fd::RawFd) {
    let hook = DIRECT_INTENT_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(descriptor);
    }
}

#[cfg(test)]
type DirectIntentHook = std::cell::RefCell<Option<Box<dyn Fn(std::os::fd::RawFd)>>>;

#[cfg(test)]
thread_local! {
    static DIRECT_INTENT_HOOK: DirectIntentHook = const { std::cell::RefCell::new(None) };
}

#[cfg(not(test))]
fn run_direct_remove_sync_hook() -> io::Result<()> {
    Ok(())
}

/// A test seam that runs after the direct start record is unlinked but before
/// its directory is synced. A test uses it to inject a sync failure at that
/// exact point. Production builds have no seam.
#[cfg(test)]
fn run_direct_remove_sync_hook() -> io::Result<()> {
    let hook = DIRECT_REMOVE_SYNC_HOOK.with(|slot| slot.borrow_mut().take());
    match hook {
        Some(hook) => hook(),
        None => Ok(()),
    }
}

#[cfg(test)]
type DirectRemoveSyncHook = std::cell::RefCell<Option<Box<dyn Fn() -> io::Result<()>>>>;

#[cfg(test)]
thread_local! {
    static DIRECT_REMOVE_SYNC_HOOK: DirectRemoveSyncHook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    /// Serialize the tests that fork or that assert on exclusive-lock release.
    /// A forked child inherits the whole descriptor table, so a child from one
    /// test must not be alive while another test drops an exclusive lock.
    static FORK_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fork_serial() -> std::sync::MutexGuard<'static, ()> {
        FORK_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let unique = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "hotspotshade-upgrade-lock-{}-{}",
                std::process::id(),
                unique
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn location(&self) -> LockLocation {
            LockLocation {
                directory: self.root.join("state"),
                expected_owner: unsafe { libc::geteuid() },
            }
        }

        fn lock_path(&self) -> PathBuf {
            self.root.join("state").join(LOCK_FILE_NAME)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn test_owner() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn create_state_directory(directory: &Path) {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .unwrap();
    }

    /// Add one extended ACL entry to a disposable test object. The helper and
    /// the installer refuse any entry, so the entry needs no qualifier.
    fn add_extended_acl(path: &Path) {
        let file = std::fs::File::open(path).unwrap();
        acl::add_extended_acl(file.as_raw_fd()).unwrap();
    }

    /// Clear every test seam even when an assertion panics.
    struct ClearTestHooks;

    impl Drop for ClearTestHooks {
        fn drop(&mut self) {
            OPEN_HOOK.with(|slot| *slot.borrow_mut() = None);
            POST_LOCK_HOOK.with(|slot| *slot.borrow_mut() = None);
            DIRECT_INTENT_HOOK.with(|slot| *slot.borrow_mut() = None);
            DIRECT_REMOVE_SYNC_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn acquire_shared(location: &LockLocation) -> io::Result<UpgradeLock> {
        acquire(location, LockKind::Shared)
    }

    fn acquire_exclusive(location: &LockLocation) -> io::Result<UpgradeLock> {
        acquire(location, LockKind::Exclusive)
    }

    #[test]
    fn production_location_is_the_root_owned_state_directory() {
        let location = LockLocation::production();
        assert_eq!(location.directory, PathBuf::from("/var/db/hotspotshade"));
        assert_eq!(location.expected_owner, 0);
        assert_eq!(LOCK_FILE_NAME, "start-exclusion");
    }

    #[test]
    fn the_helper_handoff_parser_requires_all_four_values() {
        assert_eq!(
            parse_helper_handoff([None, None, None, None]).unwrap(),
            None
        );
        let values = || {
            [
                Some("5".to_owned()),
                Some("1".to_owned()),
                Some("10".to_owned()),
                Some("20".to_owned()),
            ]
        };
        let parsed = parse_helper_handoff(values()).unwrap().unwrap();
        assert_eq!(
            parsed,
            HelperHandoff {
                descriptor: 5,
                version: 1,
                device: 10,
                inode: 20,
            }
        );
        let mut incomplete = values();
        incomplete[2] = None;
        assert!(parse_helper_handoff(incomplete).is_err());
        let mut wrong_descriptor = values();
        wrong_descriptor[0] = Some("6".to_owned());
        assert!(parse_helper_handoff(wrong_descriptor).is_err());
        let mut wrong_version = values();
        wrong_version[1] = Some("2".to_owned());
        assert!(parse_helper_handoff(wrong_version).is_err());
        let mut not_a_number = values();
        not_a_number[3] = Some("twenty".to_owned());
        assert!(parse_helper_handoff(not_a_number).is_err());
    }

    #[test]
    fn a_helper_handoff_must_name_the_locked_inode() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let metadata = guard._file.metadata().unwrap();
        let duplicated = unsafe { libc::dup(guard._file.as_raw_fd()) };
        assert!(duplicated >= 0);
        // The descriptor is owned by this File from here on.
        let duplicated = unsafe { File::from_raw_fd(duplicated) };
        // `dup` clears close-on-exec. A valid handoff sets it again.
        let before = unsafe { libc::fcntl(duplicated.as_raw_fd(), libc::F_GETFD) };
        assert!(before >= 0);
        assert_eq!(before & libc::FD_CLOEXEC, 0);
        validate_handoff_file(
            &guard,
            duplicated.as_raw_fd(),
            metadata.dev(),
            metadata.ino(),
            test_owner(),
        )
        .unwrap();
        let after = unsafe { libc::fcntl(duplicated.as_raw_fd(), libc::F_GETFD) };
        assert!(after >= 0);
        assert_ne!(
            after & libc::FD_CLOEXEC,
            0,
            "a validated handoff must not be inherited by a child"
        );
        assert!(validate_handoff_file(
            &guard,
            duplicated.as_raw_fd(),
            metadata.dev(),
            metadata.ino().wrapping_add(1),
            test_owner(),
        )
        .is_err());
        assert!(seal_handoff_descriptor(-1).is_err());
    }

    #[test]
    fn a_helper_handoff_with_an_extended_acl_is_refused() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let metadata = guard._file.metadata().unwrap();
        // Add the ACL after the engine's own check, so only the independent
        // handoff check can see it.
        add_extended_acl(&test.lock_path());
        let duplicated = unsafe { libc::dup(guard._file.as_raw_fd()) };
        assert!(duplicated >= 0);
        // The descriptor is owned by this File from here on.
        let duplicated = unsafe { File::from_raw_fd(duplicated) };
        let error = validate_handoff_file(
            &guard,
            duplicated.as_raw_fd(),
            metadata.dev(),
            metadata.ino(),
            test_owner(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("extended access control list"),
            "{error}"
        );
        assert_eq!(
            unsafe { libc::fcntl(duplicated.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "a refused handoff must not be sealed"
        );
    }

    #[test]
    fn a_direct_start_refuses_a_present_helper_refusal_file() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        for (name, message) in [
            (
                START_JOURNAL_NAME,
                "a helper start journal is present; complete recovery before starting",
            ),
            (
                ENGINE_SESSION_NAME,
                "an engine launch intent is present; complete recovery before starting",
            ),
            (
                CLEANUP_BLOCK_NAME,
                "a cleanup block is present; complete recovery before starting",
            ),
            (
                INSTALL_JOURNAL_NAME,
                "an install journal is present; complete installer recovery before starting",
            ),
            (
                SERVICE_JOURNAL_NAME,
                "a service journal is present; complete installer recovery before starting",
            ),
        ] {
            let path = test.root.join("state").join(name);
            std::fs::write(&path, b"").unwrap();
            let error = refuse_direct_start_files(&guard).unwrap_err();
            assert!(error.to_string().contains(message), "{name}: {error}");
            std::fs::remove_file(&path).unwrap();
            refuse_direct_start_files(&guard).unwrap();
        }
    }

    #[test]
    fn a_helper_handoff_refuses_installer_journals_but_accepts_its_own_intent() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let state = test.root.join("state");
        std::fs::write(state.join(ENGINE_SESSION_NAME), b"").unwrap();
        refuse_start_files(&guard, true).unwrap();
        for name in [
            START_JOURNAL_NAME,
            CLEANUP_BLOCK_NAME,
            INSTALL_JOURNAL_NAME,
            SERVICE_JOURNAL_NAME,
        ] {
            let path = state.join(name);
            std::os::unix::fs::symlink("missing", &path).unwrap();
            assert!(refuse_start_files(&guard, true).is_err(), "{name}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn a_direct_start_creates_one_durable_launch_intent() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), test_owner());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), DIRECT_INTENT_CONTENTS);
        assert!(!leftover.load(Ordering::Acquire));
        // A second direct start cannot create the same record. A simulated
        // helper create with O_EXCL fails for the same reason.
        let second_lock = acquire_shared(&test.location()).unwrap();
        let second_leftover = Arc::new(AtomicBool::new(false));
        let error =
            create_direct_start_intent(&second_lock, Arc::clone(&second_leftover)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!second_leftover.load(Ordering::Acquire));
        let helper = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_err();
        assert_eq!(helper.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), DIRECT_INTENT_CONTENTS);
        // Dropping the value does not remove the durable record, and the
        // service receives the leftover signal for its exit path.
        drop(intent);
        assert!(path.is_file());
        assert!(leftover.load(Ordering::Acquire));
        // A later direct start still refuses while the record is present.
        let error = refuse_direct_start_files(&guard).unwrap_err();
        assert!(error.to_string().contains("launch intent"));
    }

    #[test]
    fn a_clean_direct_stop_removes_only_its_own_record() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        intent.remove_after_clean_cleanup().unwrap();
        assert!(!path.exists());
        // Removal is idempotent.
        intent.remove_after_clean_cleanup().unwrap();
        refuse_direct_start_files(&guard).unwrap();
        drop(intent);
        assert!(!leftover.load(Ordering::Acquire));
        // A new start can create the record again.
        let second_leftover = Arc::new(AtomicBool::new(false));
        let second = create_direct_start_intent(&guard, Arc::clone(&second_leftover)).unwrap();
        assert!(path.is_file());
        drop(second);
        assert!(second_leftover.load(Ordering::Acquire));
    }

    #[test]
    fn an_unlinked_record_with_a_failed_directory_sync_stays_uncertain() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        let _clear = ClearTestHooks;
        DIRECT_REMOVE_SYNC_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(|| {
                Err(io::Error::other(
                    "injected direct record directory sync failure",
                ))
            }));
        });
        let error = intent.remove_after_clean_cleanup().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected direct record directory sync failure"),
            "{error}"
        );
        // The unlink removed the name, but the removal is not durable. The
        // guard sets the leftover flag when it drops, so the service still
        // treats the cleanup as uncertain.
        assert!(!path.exists());
        drop(intent);
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_replaced_direct_start_record_is_not_removed() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        let replacement = test.root.join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let error = intent.remove_after_clean_cleanup().unwrap_err();
        assert!(error.to_string().contains("no longer names"));
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        drop(intent);
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_replaced_direct_start_record_with_a_safe_mode_is_still_not_removed() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        let replacement = test.root.join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let error = intent.remove_after_clean_cleanup().unwrap_err();
        assert!(error.to_string().contains("no longer names"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        drop(intent);
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_hard_linked_direct_start_record_is_not_removed() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        // The path still names the created inode, but another name now holds a
        // second link. The safe-file rule refuses two links before the unlink.
        std::fs::hard_link(&path, test.root.join("second-link")).unwrap();
        let error = intent.remove_after_clean_cleanup().unwrap_err();
        assert!(error.to_string().contains("no longer names"), "{error}");
        assert!(path.is_file());
        assert_eq!(std::fs::read(&path).unwrap(), DIRECT_INTENT_CONTENTS);
        drop(intent);
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_symlinked_direct_start_record_path_is_not_removed() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        let target = test.root.join("target");
        std::fs::write(&target, b"target").unwrap();
        let link = test.root.join("link");
        symlink(&target, &link).unwrap();
        std::fs::rename(&link, &path).unwrap();
        let error = intent.remove_after_clean_cleanup().unwrap_err();
        assert!(error.to_string().contains("no longer names"), "{error}");
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
        drop(intent);
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_direct_start_record_with_a_post_lock_acl_is_not_removed() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let mut intent = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap();
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        add_extended_acl(&path);
        let error = intent.remove_after_clean_cleanup().unwrap_err();
        assert!(
            error.to_string().contains("extended access control list"),
            "{error}"
        );
        assert!(path.is_file(), "the refused record stays for recovery");
        assert_eq!(std::fs::read(&path).unwrap(), DIRECT_INTENT_CONTENTS);
        drop(intent);
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_direct_start_record_with_an_acl_is_refused_before_any_write() {
        let test = TestDirectory::new();
        let guard = acquire_shared(&test.location()).unwrap();
        let leftover = Arc::new(AtomicBool::new(false));
        let _clear = ClearTestHooks;
        DIRECT_INTENT_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(|descriptor| {
                acl::add_extended_acl(descriptor).unwrap();
            }));
        });
        let error = create_direct_start_intent(&guard, Arc::clone(&leftover)).unwrap_err();
        assert!(
            error.to_string().contains("extended access control list"),
            "{error}"
        );
        let path = test.root.join("state").join(ENGINE_SESSION_NAME);
        assert!(path.is_file(), "the refused record stays for recovery");
        assert!(
            std::fs::read(&path).unwrap().is_empty(),
            "the refusal must run before the intent text is written"
        );
        // The cleanup path refuses to unlink a record with an ACL, so the
        // service receives the leftover signal for its exit path.
        assert!(leftover.load(Ordering::Acquire));
    }

    #[test]
    fn a_helper_handoff_does_not_create_a_direct_record() {
        let test = TestDirectory::new();
        let mut guard = acquire_shared(&test.location()).unwrap();
        guard.helper_handoff = true;
        assert!(guard.helper_handoff());
        let leftover = Arc::new(AtomicBool::new(false));
        let error = create_direct_start_intent(&guard, leftover).unwrap_err();
        assert!(error.to_string().contains("helper start owns"));
        assert!(!test.root.join("state").join(ENGINE_SESSION_NAME).exists());
    }

    #[test]
    fn a_panicking_worker_that_retains_its_lock_blocks_an_install() {
        let _serial = fork_serial();
        let test = TestDirectory::new();
        let location = test.location();
        let guard = acquire_shared(&location).unwrap();
        let worker = std::thread::spawn(move || {
            // `resume_unwind` exercises the same caught-unwind path as the
            // tunnel worker without a panic hook or a noisy test log.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::panic::resume_unwind(Box::new("injected worker panic"));
            }));
            assert!(outcome.is_err());
            retain_until_exit(guard);
        });
        worker.join().unwrap();
        struct ReleaseRetained;
        impl Drop for ReleaseRetained {
            fn drop(&mut self) {
                release_retained_locks_for_test();
            }
        }
        let _release = ReleaseRetained;
        let error = acquire_exclusive(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn the_first_start_creates_a_permanent_private_lock_file() {
        let test = TestDirectory::new();
        let location = test.location();
        let guard = acquire_shared(&location).unwrap();
        let metadata = std::fs::symlink_metadata(test.lock_path()).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), test_owner());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o077, 0);
        drop(guard);
        assert!(test.lock_path().is_file());
    }

    #[test]
    fn later_starts_keep_the_same_inode_and_do_not_truncate_the_file() {
        let test = TestDirectory::new();
        let location = test.location();
        let first = acquire_shared(&location).unwrap();
        let first_metadata = std::fs::symlink_metadata(test.lock_path()).unwrap();
        drop(first);
        std::fs::write(test.lock_path(), b"marker").unwrap();
        let second = acquire_shared(&location).unwrap();
        let second_metadata = std::fs::symlink_metadata(test.lock_path()).unwrap();
        assert_eq!(first_metadata.dev(), second_metadata.dev());
        assert_eq!(first_metadata.ino(), second_metadata.ino());
        assert_eq!(std::fs::read(test.lock_path()).unwrap(), b"marker");
        drop(second);
        assert_eq!(std::fs::read(test.lock_path()).unwrap(), b"marker");
    }

    #[test]
    fn a_shared_lock_allows_another_shared_start() {
        let test = TestDirectory::new();
        let location = test.location();
        let first = acquire_shared(&location).unwrap();
        let second = acquire_shared(&location).unwrap();
        drop(second);
        drop(first);
    }

    #[test]
    fn an_exclusive_holder_refuses_a_start_and_a_start_refuses_the_exclusive_lock() {
        let _serial = fork_serial();
        let test = TestDirectory::new();
        let location = test.location();
        let exclusive = acquire_exclusive(&location).unwrap();
        let error = acquire_shared(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(exclusive);
        let shared = acquire_shared(&location).unwrap();
        let error = acquire_exclusive(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(shared);
        acquire_exclusive(&location).unwrap();
    }

    #[test]
    fn another_process_cannot_take_the_exclusive_lock_while_a_start_holds_it() {
        let _serial = fork_serial();
        let test = TestDirectory::new();
        let location = test.location();
        let guard = acquire_shared(&location).unwrap();
        let path = CString::new(test.lock_path().as_os_str().as_bytes()).unwrap();
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Only async-signal-safe calls run in the child. Close every
            // inherited descriptor except the pipe write end: a fork in a
            // parallel test must not keep another test's lock descriptor
            // alive after that test drops it.
            unsafe {
                libc::close(pipe[0]);
                for descriptor in 3..4096 {
                    if descriptor != pipe[1] {
                        libc::close(descriptor);
                    }
                }
                let descriptor = libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                );
                let answer = if descriptor < 0 {
                    2
                } else if libc::flock(descriptor, libc::LOCK_EX | libc::LOCK_NB) == 0 {
                    1
                } else {
                    0
                };
                let byte = [answer];
                libc::write(pipe[1], byte.as_ptr().cast(), byte.len());
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe[1]);
        }
        let mut answer = [1u8];
        let read = unsafe { libc::read(pipe[0], answer.as_mut_ptr().cast(), answer.len()) };
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        unsafe {
            libc::close(pipe[0]);
        }
        assert_eq!(read, 1);
        assert_eq!(waited, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(answer[0], 0, "the child must not get the exclusive lock");
        drop(guard);
    }

    #[test]
    fn a_retained_lock_blocks_the_exclusive_lock_until_the_test_releases_it() {
        let _serial = fork_serial();
        let test = TestDirectory::new();
        let location = test.location();
        let guard = acquire_shared(&location).unwrap();
        retain_until_exit(guard);
        struct ReleaseRetained;
        impl Drop for ReleaseRetained {
            fn drop(&mut self) {
                release_retained_locks_for_test();
            }
        }
        let _release = ReleaseRetained;
        let error = acquire_exclusive(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        release_retained_locks_for_test();
        acquire_exclusive(&location).unwrap();
    }

    #[test]
    fn a_symlinked_state_directory_is_refused() {
        let test = TestDirectory::new();
        let real = test.root.join("real-state");
        create_state_directory(&real);
        symlink(&real, test.root.join("state")).unwrap();
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_symlinked_lock_file_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        let target = test.root.join("target");
        std::fs::write(&target, b"").unwrap();
        symlink(&target, state.join(LOCK_FILE_NAME)).unwrap();
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_directory_at_the_lock_path_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        std::fs::create_dir(state.join(LOCK_FILE_NAME)).unwrap();
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_fifo_at_the_lock_path_is_refused_without_blocking() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        let path = CString::new(state.join(LOCK_FILE_NAME).as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_hard_linked_lock_file_is_refused() {
        let test = TestDirectory::new();
        let location = test.location();
        drop(acquire_shared(&location).unwrap());
        std::fs::hard_link(test.lock_path(), test.root.join("second-link")).unwrap();
        let error = acquire_shared(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_group_writable_lock_file_is_refused() {
        let test = TestDirectory::new();
        let location = test.location();
        drop(acquire_shared(&location).unwrap());
        std::fs::set_permissions(test.lock_path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = acquire_shared(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_group_readable_lock_file_is_refused() {
        let test = TestDirectory::new();
        let location = test.location();
        drop(acquire_shared(&location).unwrap());
        std::fs::set_permissions(test.lock_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = acquire_shared(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_read_only_lock_file_is_accepted() {
        let test = TestDirectory::new();
        let location = test.location();
        drop(acquire_shared(&location).unwrap());
        std::fs::set_permissions(test.lock_path(), std::fs::Permissions::from_mode(0o400)).unwrap();
        acquire_shared(&location).unwrap();
    }

    #[test]
    fn a_writable_state_directory_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_state_directory_with_an_extended_acl_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        add_extended_acl(&state);
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(
            error.to_string().contains("extended access control list"),
            "{error}"
        );
        // The directory is refused before the lock file is opened, so the
        // start creates nothing inside it.
        assert!(!test.lock_path().exists());
    }

    #[test]
    fn a_lock_file_with_an_extended_acl_is_refused() {
        let test = TestDirectory::new();
        let location = test.location();
        drop(acquire_shared(&location).unwrap());
        add_extended_acl(&test.lock_path());
        let error = acquire_shared(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(
            error.to_string().contains("extended access control list"),
            "{error}"
        );
    }

    #[test]
    fn an_acl_read_on_an_invalid_descriptor_fails_closed() {
        // A descriptor that cannot be inspected is not an object without an
        // ACL. The lock reports the read failure and the start is refused.
        let error = acl::has_extended_acl(-1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let error = refuse_extended_acl(-1, "test object").unwrap_err();
        assert!(error.to_string().contains("cannot read"), "{error}");
    }

    #[test]
    fn a_state_directory_with_another_owner_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        let mut location = test.location();
        location.expected_owner = test_owner().wrapping_add(1);
        let error = acquire_shared(&location).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_lock_file_with_another_owner_is_refused() {
        let test = TestDirectory::new();
        let location = test.location();
        drop(acquire_shared(&location).unwrap());
        let mut wrong = location.clone();
        wrong.expected_owner = test_owner().wrapping_add(1);
        let error = acquire_shared(&wrong).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_path_replaced_between_the_open_and_the_lock_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        let replacement = test.root.join("replacement");
        std::fs::write(&replacement, b"").unwrap();
        OPEN_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |path: &Path| {
                std::fs::rename(&replacement, path).unwrap();
            }));
        });
        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                OPEN_HOOK.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _clear = ClearHook;
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("no longer names"));
    }

    #[test]
    fn an_acl_added_after_the_lock_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        let lock_path = state.join(LOCK_FILE_NAME);
        // The first acquire creates the permanent file. The test then locks
        // the same path again and adds the entry after the lock is taken.
        drop(acquire_shared(&test.location()).unwrap());
        let _clear = ClearTestHooks;
        POST_LOCK_HOOK.with(|slot| {
            let path = lock_path.clone();
            *slot.borrow_mut() = Some(Box::new(move |_: &Path| {
                add_extended_acl(&path);
            }));
        });
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(
            error.to_string().contains("extended access control list"),
            "{error}"
        );
    }

    #[test]
    fn a_sticky_state_directory_is_refused() {
        let test = TestDirectory::new();
        let state = test.root.join("state");
        create_state_directory(&state);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o1700)).unwrap();
        let error = acquire_shared(&test.location()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("sticky bit"), "{error}");
    }
}
