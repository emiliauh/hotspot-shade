// HotspotShade root helper.
//
// pkexec starts this program as root. It accepts no arguments. It reads one
// short request from stdin, starts the packaged engine with the per-launch
// secret on descriptor 3, and holds descriptor 4 open until stdin closes.
//
// An HS2 request also carries the user engine's pairing handoff socket on
// descriptor 2. The helper moves it to the engine's descriptor 5 and passes
// `--credentials-fd 5`. It never reads that socket. Direct mode uses HS1 and
// passes no handoff.
//
// The helper never prints the secret. It does not accept a path, a command, or
// an argument from the app or the page. The engine path is fixed at build time.
//
// The helper holds a root-owned lock and records the running engine's process
// identity. It writes a version 2 write-ahead record before the spawn, then
// records the engine identity before any post-spawn abandonment check. A second
// helper refuses to start while the first helper or its engine is still alive,
// and an unverifiable record fails closed. It never sends SIGKILL: a forced kill
// skips the engine's route and rule cleanup.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_ENGINE: &str = "/opt/hotspotshade/resources/engine/hotspotshade";
const ENGINE_HOME: &str = "/var/lib/hotspotshade";
const LOCK_PATH: &str = "/var/lib/hotspotshade/helper.lock";
const STATE_PATH: &str = "/var/lib/hotspotshade/engine.state";
const START_TIMEOUT: Duration = Duration::from_secs(10);
const EOF_GRACE: Duration = Duration::from_secs(8);
/* The engine may wait for an in-flight start request and its route cleanup.
 * Give it longer than its own bounded shutdown, and never escalate to SIGKILL:
 * a forced kill skips route and rule removal. */
const TERM_GRACE: Duration = Duration::from_secs(45);
/* A slow engine may need more than one signal. Retry the graceful signal,
 * never a forced kill. */
const TERM_RETRY: Duration = Duration::from_secs(30);

/* The app treats every non-zero helper exit as a failed stop. These values are
 * stable so the Node client can give the person one plain reason. Code 9 is
 * separate from code 5 on purpose: an engine that exited cleanly can still
 * leave a state file or a private directory behind, and the person needs the
 * route-cleanup warning rather than an engine error. */
const EXIT_REQUEST_INVALID: i32 = 1;
const EXIT_ENGINE_SIGNALED: i32 = 4;
const EXIT_ENGINE_FAILED: i32 = 5;
const EXIT_ALREADY_RUNNING: i32 = 6;
const EXIT_ABANDONED: i32 = 7;
const EXIT_STATE_UNCERTAIN: i32 = 8;
const EXIT_CLEANUP_FAILED: i32 = 9;

/* The state file is a write-ahead record. Version 2 names the boot and the PID
 * namespace, so a record from another boot or namespace is never mistaken for
 * this helper's engine. Version 1 is not upgraded or deleted; it is kept and
 * treated as uncertain. */
const STATE_HEADER: &str = "HS_ENGINE 2";
const STATE_MAX_BYTES: usize = 4096;
const MAX_GROUP_TASKS: usize = 4096;
const GROUP_SCAN_PASSES: usize = 3;
const GROUP_SCAN_PAUSE: Duration = Duration::from_millis(10);

static STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

/* Exit 1 covers several distinct preparation failures. The helper prints one
 * fixed machine-readable line on stderr before the human text so the app can
 * give the person a plain reason. The line is `HS_REASON <slug>`. The slug is
 * one of the constants below: lowercase ASCII, no secret, no path. The human
 * text on the next line stays for the system log. The client reads a bounded
 * amount of stderr and ignores a slug it does not know. */
const REASON_BAD_ARGUMENTS: &str = "bad_arguments";
const REASON_NOT_ROOT: &str = "not_root";
const REASON_NOT_PKEXEC: &str = "not_pkexec";
const REASON_ENGINE_UNSAFE_PERMISSIONS: &str = "engine_unsafe_permissions";
const REASON_ENGINE_MISSING: &str = "engine_missing";
const REASON_REQUEST_INVALID: &str = "request_invalid";
const REASON_HOME_UNAVAILABLE: &str = "home_unavailable";
const REASON_HOME_UNSAFE: &str = "home_unsafe";
const REASON_LOCK_UNAVAILABLE: &str = "lock_unavailable";
const REASON_IDENTITY_UNAVAILABLE: &str = "identity_unavailable";
const REASON_PIPES_FAILED: &str = "pipes_failed";
const REASON_TEMP_DIRECTORY_FAILED: &str = "temp_directory_failed";
const REASON_STATE_WRITE_FAILED: &str = "state_write_failed";

#[cfg(test)]
const ALL_REASONS: [&str; 13] = [
    REASON_BAD_ARGUMENTS,
    REASON_NOT_ROOT,
    REASON_NOT_PKEXEC,
    REASON_ENGINE_UNSAFE_PERMISSIONS,
    REASON_ENGINE_MISSING,
    REASON_REQUEST_INVALID,
    REASON_HOME_UNAVAILABLE,
    REASON_HOME_UNSAFE,
    REASON_LOCK_UNAVAILABLE,
    REASON_IDENTITY_UNAVAILABLE,
    REASON_PIPES_FAILED,
    REASON_TEMP_DIRECTORY_FAILED,
    REASON_STATE_WRITE_FAILED,
];

fn reason_line(reason: &str) -> String {
    format!("HS_REASON {reason}")
}

/* A closed stderr must not turn a reported failure into a panic. */
fn fail_reason(reason: &str, message: &str) -> ! {
    let mut error = io::stderr();
    let _ = writeln!(error, "{}", reason_line(reason));
    let _ = writeln!(error, "hotspotshade-helper: {message}");
    std::process::exit(EXIT_REQUEST_INVALID);
}

/* One protocol line on a stream. A reader that went away makes the write fail
 * with EPIPE; `println!` would panic on that. The caller decides what a failed
 * announcement means for the stage it is in. */
fn write_line<W: Write>(writer: &mut W, line: &str) -> io::Result<()> {
    writeln!(writer, "{line}")?;
    writer.flush()
}

fn announce(line: &str) -> io::Result<()> {
    let mut output = io::stdout().lock();
    write_line(&mut output, line)
}

fn engine_error_reason(error: &io::Error) -> &'static str {
    if error.kind() == io::ErrorKind::PermissionDenied {
        REASON_ENGINE_UNSAFE_PERMISSIONS
    } else {
        REASON_ENGINE_MISSING
    }
}

fn engine_path() -> &'static str {
    DEFAULT_ENGINE
}

fn read_line(reader: &mut fs::File, limit: usize) -> io::Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let count = reader.read(&mut byte)?;
        if count == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if buffer.len() >= limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        buffer.push(byte[0]);
    }
    String::from_utf8(buffer)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not text"))
}

/* Resolve the engine once. The canonical path is the one that is checked and
 * the one that is executed, so a symlink cannot point the check and the exec at
 * different files. */
fn resolve_engine(path: &str) -> io::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the packaged engine path is not a file",
        ));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the packaged engine is not executable",
        ));
    }
    Ok(canonical)
}

fn check_engine_owner(canonical: &Path, expected_uid: u32) -> io::Result<()> {
    let metadata = fs::metadata(canonical)?;
    if metadata.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the packaged engine is not owned by root",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the packaged engine is writable by another user",
        ));
    }
    /* A writable parent lets another user replace the engine file between this
     * check and exec. Check every directory above the canonical file. */
    let mut current = canonical.parent();
    while let Some(directory) = current {
        let dir_metadata = fs::symlink_metadata(directory)?;
        if !dir_metadata.is_dir() || dir_metadata.uid() != expected_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the packaged engine directory is not owned by root",
            ));
        }
        if dir_metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the packaged engine directory is writable by another user",
            ));
        }
        if directory == Path::new("/") {
            break;
        }
        current = directory.parent();
    }
    Ok(())
}

fn validate_engine(path: &str, expected_uid: u32) -> io::Result<PathBuf> {
    let canonical = resolve_engine(path)?;
    check_engine_owner(&canonical, expected_uid)?;
    Ok(canonical)
}

fn make_temp_directory() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    for attempt in 0..100u128 {
        let path = PathBuf::from("/tmp").join(format!(
            "hotspotshade-helper-{}-{}",
            std::process::id(),
            nanos + attempt
        ));
        /* The mode goes to mkdir, so the directory is never readable by
         * another user. A create followed by chmod leaves a window in which
         * another user can plant the port file. */
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                let metadata = fs::symlink_metadata(&path).unwrap_or_else(|_| {
                    fail_reason(
                        REASON_TEMP_DIRECTORY_FAILED,
                        "The helper temporary directory is not available.",
                    )
                });
                if !metadata.is_dir()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o777 != 0o700
                {
                    let _ = fs::remove_dir(&path);
                    fail_reason(
                        REASON_TEMP_DIRECTORY_FAILED,
                        "The helper temporary directory is not private.",
                    );
                }
                return path;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => fail_reason(
                REASON_TEMP_DIRECTORY_FAILED,
                "The helper temporary directory could not be created.",
            ),
        }
    }
    fail_reason(
        REASON_TEMP_DIRECTORY_FAILED,
        "The helper temporary directory could not be created.",
    )
}

fn remove_directory(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_directory_or_report(path: &Path) {
    if let Err(error) = remove_directory(path) {
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the private engine directory could not be removed: {error}; inspect it."
        );
    }
}

fn prepare_engine_home() {
    if let Err(error) = fs::create_dir_all(ENGINE_HOME) {
        if error.kind() != io::ErrorKind::AlreadyExists {
            fail_reason(
                REASON_HOME_UNAVAILABLE,
                "The engine home directory could not be created.",
            );
        }
    }
    let metadata = fs::symlink_metadata(ENGINE_HOME).unwrap_or_else(|_| {
        fail_reason(
            REASON_HOME_UNAVAILABLE,
            "The engine home directory is not available.",
        )
    });
    if !metadata.is_dir() || metadata.uid() != 0 {
        fail_reason(
            REASON_HOME_UNSAFE,
            "The engine home directory is not owned by root.",
        );
    }
    if metadata.mode() & 0o077 != 0 {
        let _ = fs::set_permissions(ENGINE_HOME, fs::Permissions::from_mode(0o700));
    }
    let checked = fs::symlink_metadata(ENGINE_HOME).unwrap_or_else(|_| {
        fail_reason(
            REASON_HOME_UNAVAILABLE,
            "The engine home directory is not available.",
        )
    });
    if !checked.is_dir() || checked.uid() != 0 || checked.mode() & 0o077 != 0 {
        fail_reason(
            REASON_HOME_UNSAFE,
            "The engine home directory is not private.",
        );
    }
}

fn lift_fd(fd: i32) -> io::Result<i32> {
    if fd >= 10 {
        return Ok(fd);
    }
    let lifted = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if lifted < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        libc::close(fd);
    }
    Ok(lifted)
}

fn move_fd(fd: i32, target: i32) -> io::Result<()> {
    if unsafe { libc::dup2(fd, target) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/* The request version line. HS1 starts an engine with no pairing handoff, for
 * direct mode. HS2 also passes the user engine's pairing handoff socket. */
const REQUEST_DIRECT: &str = "HS1";
const REQUEST_HANDOFF: &str = "HS2";
/* The engine reads the handoff frame from this descriptor. */
const ENGINE_CREDENTIALS_FD: i32 = 5;

/* HS2: the app passes the user engine's pairing handoff socket as descriptor
 * 2, because pkexec marks every inherited descriptor above 2 close-on-exec.
 * Move it to a private close-on-exec descriptor and point descriptor 2 at
 * stdout, so later reason lines and messages still reach the app. The helper
 * checks only that the descriptor is a socket. It never reads, writes, or
 * parses the frame; the root engine reads it on descriptor 5. */
fn take_handoff_descriptor() -> io::Result<RawFd> {
    let lifted = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 10) };
    if lifted < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::dup2(1, 2) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(lifted);
        }
        return Err(error);
    }
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(lifted, &mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
    {
        unsafe {
            libc::close(lifted);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the pairing handoff is not a socket",
        ));
    }
    Ok(lifted)
}

/* The engine has its own copy on descriptor 5 after the spawn. Closing the
 * helper copy keeps the root helper from holding the user engine's socket for
 * the whole session. */
fn close_handoff(handoff_fd: Option<RawFd>) {
    if let Some(fd) = handoff_fd {
        unsafe {
            libc::close(fd);
        }
    }
}

fn valid_secret(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_stop_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_stop_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            handle_stop_signal as *const () as libc::sighandler_t,
        );
    }
}

extern "C" fn handle_stop_signal(signal: libc::c_int) {
    STOP_SIGNAL.store(signal, Ordering::SeqCst);
}

fn stop_requested() -> bool {
    STOP_SIGNAL.load(Ordering::SeqCst) != 0 || input_hung_up(0)
}

/* This is the late-authorization guard: a helper that starts after the app gave
 * up must see that the request channel is closed and exit before it starts an
 * engine.
 *
 * A pipe reports POLLHUP when its write end closes. The Electron client uses a
 * child stdio socketpair, and there `end()` sends a half-close: the parent's
 * descriptor stays open, so the helper sees POLLRDHUP and a readable EOF, not
 * POLLHUP. Ask for POLLRDHUP explicitly, then peek one byte on a socket. A
 * zero-length peek is EOF. A byte of request data is not. A true pipe is not a
 * socket, so the peek fails and the poll flags decide. */
/* POLLRDHUP is Linux-specific. On other systems the readable-EOF peek below
 * still detects a socket write half-close. */
#[cfg(any(target_os = "linux", target_os = "android"))]
const POLL_HALF_CLOSE: libc::c_short = libc::POLLRDHUP;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const POLL_HALF_CLOSE: libc::c_short = 0;

fn input_hung_up(fd: RawFd) -> bool {
    let mut descriptor = libc::pollfd {
        fd,
        events: POLL_HALF_CLOSE | libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result <= 0 {
        return false;
    }
    let flags = descriptor.revents;
    if flags & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return true;
    }
    if flags & POLL_HALF_CLOSE != 0 {
        return true;
    }
    if flags & libc::POLLIN != 0 {
        let mut byte = [0u8; 1];
        let count = unsafe {
            libc::recv(
                fd,
                byte.as_mut_ptr().cast(),
                byte.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        /* A socket that has seen a write half-close reads as EOF. Keep a
         * channel with pending request bytes open; the request reader owns
         * those bytes. */
        return count == 0;
    }
    false
}

#[derive(Debug)]
struct HelperLock {
    _file: File,
}

fn acquire_lock_at(path: &Path, expected_uid: u32) -> io::Result<HelperLock> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != expected_uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the helper lock is not root-owned and private",
        ));
    }
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "another privileged helper is running",
            ));
        }
        return Err(error);
    }
    Ok(HelperLock { _file: file })
}

/* The kernel boot id and the PID namespace inode identify the context in which
 * a process id and a start time are meaningful. A start time is only unique
 * within one boot, and a pid is only unique within one PID namespace.
 *
 * Namespace inode numbers can be reused after a namespace is destroyed. The
 * boot id, namespace inode, pid, and start time together are a practical
 * identity, not a kernel-issued permanent one. */
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostIdentity {
    boot_id: String,
    pid_ns_dev: u64,
    pid_ns_ino: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    start_time: u64,
}

/* PENDING is the write-ahead record written before the spawn. It names the
 * helper, not the engine, because the engine process id does not exist yet.
 * ENGINE is the record written after the spawn and before any abandonment
 * check. A helper killed between the spawn and that write leaves PENDING. */
#[derive(Clone, Debug, PartialEq, Eq)]
enum StateRecord {
    Pending {
        host: HostIdentity,
        writer: ProcessIdentity,
    },
    Engine {
        host: HostIdentity,
        engine: ProcessIdentity,
    },
}

impl StateRecord {
    fn host(&self) -> &HostIdentity {
        match self {
            StateRecord::Pending { host, .. } | StateRecord::Engine { host, .. } => host,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateError {
    OlderVersion,
    UnknownVersion,
    Invalid,
}

impl StateError {
    fn message(self) -> &'static str {
        match self {
            StateError::OlderVersion => {
                "the engine state record is from an older helper and is kept for inspection"
            }
            StateError::UnknownVersion => {
                "the engine state record has an unknown version and is kept for inspection"
            }
            StateError::Invalid => {
                "the engine state record is not valid and is kept for inspection"
            }
        }
    }
}

/* The kernel prints the boot id as a lowercase UUID. Requiring that exact shape
 * keeps a foreign or damaged record out of the comparison, where an uppercase
 * variant would otherwise look like a different boot and be deleted. */
fn valid_boot_id(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        }
    })
}

/* The state file has exactly four lines. A fifth line, including a blank one,
 * is trailing data from a damaged or foreign writer and must not be accepted
 * as a shorter valid record. */
fn parse_state(text: &str) -> Result<StateRecord, StateError> {
    let mut lines = text.lines();
    let header = lines.next().ok_or(StateError::Invalid)?;
    if header == "HS_ENGINE 1" {
        return Err(StateError::OlderVersion);
    }
    if header != STATE_HEADER {
        if header.starts_with("HS_ENGINE ") {
            return Err(StateError::UnknownVersion);
        }
        return Err(StateError::Invalid);
    }
    let boot_line = lines.next().ok_or(StateError::Invalid)?;
    let boot_id = boot_line.strip_prefix("BOOT ").ok_or(StateError::Invalid)?;
    if !valid_boot_id(boot_id) {
        return Err(StateError::Invalid);
    }
    let ns_line = lines.next().ok_or(StateError::Invalid)?;
    let mut ns_parts = ns_line.split_whitespace();
    if ns_parts.next() != Some("NS") {
        return Err(StateError::Invalid);
    }
    let pid_ns_dev = ns_parts
        .next()
        .ok_or(StateError::Invalid)?
        .parse::<u64>()
        .map_err(|_| StateError::Invalid)?;
    let pid_ns_ino = ns_parts
        .next()
        .ok_or(StateError::Invalid)?
        .parse::<u64>()
        .map_err(|_| StateError::Invalid)?;
    if ns_parts.next().is_some() {
        return Err(StateError::Invalid);
    }
    let process_line = lines.next().ok_or(StateError::Invalid)?;
    let mut parts = process_line.split_whitespace();
    let kind = parts.next().ok_or(StateError::Invalid)?;
    let pid = parts
        .next()
        .ok_or(StateError::Invalid)?
        .parse::<u32>()
        .map_err(|_| StateError::Invalid)?;
    let start_time = parts
        .next()
        .ok_or(StateError::Invalid)?
        .parse::<u64>()
        .map_err(|_| StateError::Invalid)?;
    if pid == 0 || parts.next().is_some() || lines.next().is_some() {
        return Err(StateError::Invalid);
    }
    let host = HostIdentity {
        boot_id: boot_id.to_owned(),
        pid_ns_dev,
        pid_ns_ino,
    };
    let process = ProcessIdentity { pid, start_time };
    match kind {
        "PENDING" => Ok(StateRecord::Pending {
            host,
            writer: process,
        }),
        "ENGINE" => Ok(StateRecord::Engine {
            host,
            engine: process,
        }),
        _ => Err(StateError::Invalid),
    }
}

fn state_text(record: &StateRecord) -> String {
    let host = record.host();
    let (kind, process) = match record {
        StateRecord::Pending { writer, .. } => ("PENDING", writer),
        StateRecord::Engine { engine, .. } => ("ENGINE", engine),
    };
    format!(
        "{STATE_HEADER}\nBOOT {}\nNS {} {}\n{kind} {} {}\n",
        host.boot_id, host.pid_ns_dev, host.pid_ns_ino, process.pid, process.start_time
    )
}

/* Open the parent directory after a rename or an unlink so the directory entry
 * is durable too. A power loss after a state write must not leave an engine
 * that no later helper can see. A failed sync is a cleanup failure. */
fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "the state path has no parent")
    })?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    directory.sync_all()
}

fn read_state_at(path: &Path, expected_uid: u32) -> io::Result<Option<StateRecord>> {
    let file = match OpenOptions::new()
        .read(true)
        /* O_NONBLOCK keeps a foreign FIFO from blocking the root helper before
         * the file-type check below. It has no effect on a regular file. */
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    /* Check the descriptor, not the path, so a replacement between the check
     * and the read cannot redirect the parse to another file. */
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the engine state file is not root-owned and private",
        ));
    }
    let mut text = String::new();
    file.take(STATE_MAX_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    if text.len() > STATE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the engine state is not valid",
        ));
    }
    let state = parse_state(&text)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.message().to_owned()))?;
    Ok(Some(state))
}

fn write_state_at(path: &Path, record: &StateRecord, expected_uid: u32) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
    {
        Ok(value) => value,
        /* A helper killed before it renamed the state file can leave one
         * private temporary file behind. The lock is held, so removing it is
         * safe and does not hide another helper's state. */
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?
        }
        Err(error) => return Err(error),
    };
    let result = (|| -> io::Result<()> {
        write!(file, "{}", state_text(record))?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the engine state file is not private",
            ));
        }
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_state_at(path: &Path, expected_uid: u32) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the engine state file is not safe to remove",
        ));
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

fn read_boot_id_at(proc_root: &Path) -> io::Result<String> {
    let path = proc_root.join("sys/kernel/random/boot_id");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the boot identity is not a file",
        ));
    }
    let mut text = String::new();
    file.take(65).read_to_string(&mut text)?;
    if text.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the boot identity is too long",
        ));
    }
    let value = text.trim_end_matches('\n');
    if !valid_boot_id(value) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the boot identity is not a UUID",
        ));
    }
    Ok(value.to_owned())
}

fn read_pid_namespace_at(proc_root: &Path, pid: u32) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(proc_root.join(pid.to_string()).join("ns/pid"))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn current_host_identity_at(proc_root: &Path) -> io::Result<HostIdentity> {
    let boot_id = read_boot_id_at(proc_root)?;
    let (pid_ns_dev, pid_ns_ino) = read_pid_namespace_at(proc_root, std::process::id())?;
    Ok(HostIdentity {
        boot_id,
        pid_ns_dev,
        pid_ns_ino,
    })
}

fn same_pid_namespace(left: &HostIdentity, right: &HostIdentity) -> bool {
    left.pid_ns_dev == right.pid_ns_dev && left.pid_ns_ino == right.pid_ns_ino
}

fn parse_proc_state(text: &[u8]) -> io::Result<(u64, bool)> {
    let close = text.iter().rposition(|byte| *byte == b')').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "the process state is not valid")
    })?;
    let fields: Vec<&[u8]> = text[close + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    let state = fields
        .first()
        .filter(|value| value.len() == 1 && value[0].is_ascii_alphabetic())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "the process state is not valid")
        })?;
    /* Field 22 is the start time. The first field after the command name is
     * field 3, so the start time is index 19. */
    let value = fields.get(19).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "the process state is not valid")
    })?;
    let value = std::str::from_utf8(value).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "the process state is not valid")
    })?;
    let start_time = value.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "the process state is not valid")
    })?;
    Ok((start_time, matches!(state[0], b'Z' | b'X' | b'x')))
}

fn read_proc_state_at(proc_root: &Path, pid: u32) -> io::Result<(u64, bool)> {
    parse_proc_state(&fs::read(proc_root.join(pid.to_string()).join("stat"))?)
}

fn read_task_state_at(proc_root: &Path, pid: u32, tid: u32) -> io::Result<(u64, bool)> {
    parse_proc_state(&fs::read(
        proc_root
            .join(pid.to_string())
            .join("task")
            .join(tid.to_string())
            .join("stat"),
    )?)
}

fn read_proc_state(pid: u32) -> io::Result<(u64, bool)> {
    read_proc_state_at(Path::new("/proc"), pid)
}

fn read_proc_starttime(pid: u32) -> io::Result<u64> {
    read_proc_state(pid).map(|(start_time, _)| start_time)
}

/* An ENOENT from /proc can mean the process is gone or that this process
 * cannot see a process table at all. Only clear a state record after proving
 * that /proc itself is readable. */
fn process_table_available_at(proc_root: &Path) -> bool {
    parse_proc_state(&match fs::read(proc_root.join("self/stat")) {
        Ok(value) => value,
        Err(_) => return false,
    })
    .is_ok()
}

fn process_absent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn uncertain(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

enum TaskObservation {
    Live,
    Dead,
    Missing,
}

/* The thread-group leader can be a zombie while another thread in the same
 * group still runs. Scan every task in the group before treating the process
 * as gone.
 *
 * This is a bounded observation, not an atomic proof. A task created after the
 * last pass, or one that a concurrent directory change hides from the scan, is
 * not seen. It is sufficient for this engine, which does not call exit() from
 * its leader thread and then create threads. Do not reuse this as a general
 * process-liveness proof. An unreadable, empty, or oversized task list is
 * uncertain, not proof of exit. */
fn observe_group_tasks(proc_root: &Path, pid: u32) -> io::Result<TaskObservation> {
    let task_directory = proc_root.join(pid.to_string()).join("task");
    for pass in 0..GROUP_SCAN_PASSES {
        let entries = match fs::read_dir(&task_directory) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(TaskObservation::Missing);
            }
            Err(error) => return Err(error),
        };
        let mut count = 0usize;
        let mut live = false;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let tid = name
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| uncertain("the engine task list is not valid"))?;
            count += 1;
            if count > MAX_GROUP_TASKS {
                return Err(uncertain("the engine task list is too large"));
            }
            match read_task_state_at(proc_root, pid, tid) {
                Ok((_, false)) => live = true,
                Ok((_, true)) => {}
                /* A task that vanished after the listing has exited. A later
                 * pass catches a task that appeared during the scan. */
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if live {
            return Ok(TaskObservation::Live);
        }
        if count == 0 {
            return Err(uncertain("the engine task list is empty"));
        }
        if pass + 1 < GROUP_SCAN_PASSES {
            thread::sleep(GROUP_SCAN_PAUSE);
        }
    }
    Ok(TaskObservation::Dead)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EnginePresence {
    Running(&'static str),
    Absent,
    Uncertain(String),
}

/* A stale record is removed only after the process table is proven readable.
 * An ENOENT from /proc can mean the process is gone or that this process cannot
 * see a process table at all. */
fn remove_stale_state(
    path: &Path,
    expected_uid: u32,
    proc_root: &Path,
    reason: &str,
) -> EnginePresence {
    if !process_table_available_at(proc_root) {
        return EnginePresence::Uncertain(format!(
            "{reason}; the process table is not available, so the state is kept"
        ));
    }
    match remove_state_at(path, expected_uid) {
        Ok(()) => EnginePresence::Absent,
        Err(error) => EnginePresence::Uncertain(format!(
            "{reason}; the stale state could not be removed: {error}"
        )),
    }
}

/* A pending record has no engine process id. If the writer is gone, the helper
 * cannot prove whether it spawned an engine before it died. Keep the record and
 * fail closed. This is the cost of the write-ahead record: the crash window is
 * visible instead of silently unrecorded. */
const PENDING_UNCERTAIN: &str =
    "a helper wrote a pending engine start and is gone; the engine identity is unknown, so the record is kept";

fn pending_presence(proc_root: &Path, writer: ProcessIdentity) -> EnginePresence {
    match read_proc_state_at(proc_root, writer.pid) {
        Ok((start_time, dead)) => {
            if start_time != writer.start_time {
                return EnginePresence::Uncertain(
                    "the pending start writer process id was reused; the engine identity is unknown"
                        .to_owned(),
                );
            }
            if !dead {
                return EnginePresence::Running(
                    "a helper that wrote a pending engine start is still running",
                );
            }
            EnginePresence::Uncertain(PENDING_UNCERTAIN.to_owned())
        }
        Err(error) if process_absent(&error) => {
            if !process_table_available_at(proc_root) {
                return EnginePresence::Uncertain(
                    "the process table is not available; the pending engine start is kept"
                        .to_owned(),
                );
            }
            EnginePresence::Uncertain(PENDING_UNCERTAIN.to_owned())
        }
        Err(error) => EnginePresence::Uncertain(format!(
            "the pending start writer could not be inspected: {error}"
        )),
    }
}

fn engine_presence(
    path: &Path,
    expected_uid: u32,
    proc_root: &Path,
    host: &HostIdentity,
    engine: ProcessIdentity,
) -> EnginePresence {
    let (start_time, leader_dead) = match read_proc_state_at(proc_root, engine.pid) {
        Ok(value) => value,
        Err(error) if process_absent(&error) => {
            return remove_stale_state(
                path,
                expected_uid,
                proc_root,
                "the recorded engine process is gone",
            );
        }
        Err(error) => {
            return EnginePresence::Uncertain(format!(
                "the recorded engine process could not be inspected: {error}"
            ));
        }
    };
    if start_time != engine.start_time {
        /* The process id belongs to a different process. The kernel start time
         * is the identity check, so this record cannot name the old engine. */
        return remove_stale_state(
            path,
            expected_uid,
            proc_root,
            "the recorded process id belongs to a different process",
        );
    }
    match read_pid_namespace_at(proc_root, engine.pid) {
        Ok((dev, ino)) if dev == host.pid_ns_dev && ino == host.pid_ns_ino => {}
        Ok(_) => {
            return EnginePresence::Uncertain(
                "the recorded engine process id names a process in another PID namespace; the state is kept"
                    .to_owned(),
            );
        }
        Err(error) if process_absent(&error) => {
            /* The process vanished between the state read and the namespace
             * read. Re-read the process state so a vanished process is stale
             * while an unreadable namespace is uncertain. */
            return match read_proc_state_at(proc_root, engine.pid) {
                Err(error) if process_absent(&error) => remove_stale_state(
                    path,
                    expected_uid,
                    proc_root,
                    "the recorded engine process is gone",
                ),
                Ok((start_time, _)) if start_time != engine.start_time => remove_stale_state(
                    path,
                    expected_uid,
                    proc_root,
                    "the recorded process id belongs to a different process",
                ),
                Ok(_) => EnginePresence::Uncertain(
                    "the engine namespace could not be read; the state is kept".to_owned(),
                ),
                Err(error) => EnginePresence::Uncertain(format!(
                    "the engine namespace could not be read: {error}; the state is kept"
                )),
            };
        }
        Err(error) => {
            return EnginePresence::Uncertain(format!(
                "the engine namespace could not be read: {error}; the state is kept"
            ));
        }
    }
    if !leader_dead {
        return EnginePresence::Running("a previous privileged engine is still running");
    }
    match observe_group_tasks(proc_root, engine.pid) {
        Ok(TaskObservation::Live) => {
            EnginePresence::Running("a previous privileged engine still has a live task")
        }
        Ok(TaskObservation::Dead) => remove_stale_state(
            path,
            expected_uid,
            proc_root,
            "every observed engine task has exited",
        ),
        Ok(TaskObservation::Missing) => {
            /* The task directory vanished between the group read and the scan.
             * Re-read the group so a vanished group is stale while a group
             * that still exists but has no readable task list is uncertain. */
            match read_proc_state_at(proc_root, engine.pid) {
                Err(error) if process_absent(&error) => remove_stale_state(
                    path,
                    expected_uid,
                    proc_root,
                    "the recorded engine process is gone",
                ),
                Ok((start_time, false)) if start_time == engine.start_time => {
                    EnginePresence::Running("a previous privileged engine is still running")
                }
                Ok((start_time, _)) if start_time != engine.start_time => remove_stale_state(
                    path,
                    expected_uid,
                    proc_root,
                    "the recorded process id belongs to a different process",
                ),
                Ok(_) => EnginePresence::Uncertain(
                    "the engine task list is not available; the state is kept".to_owned(),
                ),
                Err(error) => EnginePresence::Uncertain(format!(
                    "the engine task list could not be read: {error}; the state is kept"
                )),
            }
        }
        Err(error) => EnginePresence::Uncertain(format!(
            "the engine task list could not be read: {error}; the state is kept"
        )),
    }
}

/* The lock only lives as long as the helper. The state file survives a helper
 * crash, so a later helper can prove that the old engine is still alive.
 *
 * Assumptions and limits:
 * - The state record names the kernel boot and the PID namespace in which its
 *   pid and start time were read.
 * - The helper and the engine share one PID namespace because the helper
 *   spawned the engine. A record from another namespace is kept as uncertain,
 *   because an engine in that namespace could still share the host routing
 *   table.
 * - /proc is mounted in this mount namespace, and a readable /proc/self/stat
 *   means the process table is available. hidepid cannot hide a matching
 *   process from root, but a namespace or mount change can.
 * - The zombie/live-task scan is a bounded observation, not an atomic proof.
 *   See observe_group_tasks. The record names the engine thread group, not a
 *   child process that the engine could create. The packaged engine does not
 *   fork a route-owning child.
 * - The state file check and the unlink are not one atomic operation. A
 *   same-uid writer that replaces the file between them is not excluded. Only
 *   root can write the private state directory.
 * - This function never signals a process id from the state file. A process id
 *   recorded by an old helper is not owned by this helper, so a signal could
 *   hit a reused process id. The engine is stopped only through the Child
 *   handle of the engine this helper spawned. */
fn previous_engine_running(
    path: &Path,
    expected_uid: u32,
    current: &HostIdentity,
) -> io::Result<EnginePresence> {
    previous_engine_running_at(path, expected_uid, Path::new("/proc"), current)
}

fn previous_engine_running_at(
    path: &Path,
    expected_uid: u32,
    proc_root: &Path,
    current: &HostIdentity,
) -> io::Result<EnginePresence> {
    let state = match read_state_at(path, expected_uid) {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(EnginePresence::Absent),
        Err(error) => {
            return Ok(EnginePresence::Uncertain(format!(
                "the engine state could not be read: {error}"
            )));
        }
    };
    if state.host().boot_id != current.boot_id {
        /* No process survives a reboot. The boot id proves that this record
         * cannot name a live process, so it is stale. The routes were cleared
         * by the reboot as well. Keep the removal explicit and reported. */
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the engine state record is from a previous boot; no process can survive a reboot, so it is stale."
        );
        return Ok(match remove_state_at(path, expected_uid) {
            Ok(()) => EnginePresence::Absent,
            Err(error) => EnginePresence::Uncertain(format!(
                "the state record is from a previous boot but could not be removed: {error}; it is kept"
            )),
        });
    }
    if !same_pid_namespace(state.host(), current) {
        return Ok(EnginePresence::Uncertain(
            "the engine state record was written in another PID namespace; the helper cannot prove that no engine uses the host routing table, so the record is kept"
                .to_owned(),
        ));
    }
    Ok(match &state {
        StateRecord::Pending { writer, .. } => pending_presence(proc_root, *writer),
        StateRecord::Engine { engine, .. } => {
            engine_presence(path, expected_uid, proc_root, state.host(), *engine)
        }
    })
}

enum PortWait {
    Ready(u16),
    Exited(ExitStatus),
    TimedOut,
    Canceled,
}

fn wait_for_port(child: &mut Child, port_path: &Path) -> PortWait {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if stop_requested() {
            return PortWait::Canceled;
        }
        if let Ok(value) = fs::read_to_string(port_path) {
            if let Ok(port) = value.trim().parse::<u16>() {
                if port > 0 {
                    return PortWait::Ready(port);
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => return PortWait::Exited(status),
            Ok(None) => {}
            Err(_) => return PortWait::TimedOut,
        }
        if Instant::now() >= deadline {
            return PortWait::TimedOut;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Termination {
    Exited(ExitStatus),
    TimedOut,
}

fn terminate(child: &mut Child) -> Termination {
    /* A child that `try_wait` already reaped has no live process id. Never
     * signal that number: the system may have given it to another process. */
    match child.try_wait() {
        Ok(Some(status)) => return Termination::Exited(status),
        Ok(None) => {}
        /* A wait error does not prove that this child still owns the process
         * id. Do not signal a number that the helper cannot verify. */
        Err(_) => return Termination::TimedOut,
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Termination::Exited(status),
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    /* Do not send SIGKILL. The engine removes its routes and rules on its
     * SIGTERM path; a forced kill would leave them behind. */
    Termination::TimedOut
}

fn classify_status(status: ExitStatus) -> i32 {
    if let Some(signal) = status.signal() {
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the engine exited on signal {signal}; inspect the routes."
        );
        return EXIT_ENGINE_SIGNALED;
    }
    match status.code() {
        Some(0) => 0,
        Some(code) => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: the engine exited with code {code}; inspect the routes."
            );
            EXIT_ENGINE_FAILED
        }
        None => EXIT_ENGINE_FAILED,
    }
}

fn final_code(signal: i32, status: ExitStatus) -> i32 {
    if signal != 0 {
        128 + signal
    } else {
        classify_status(status)
    }
}

/* Engine stop is not clean unless the state record and the private port
 * directory are gone. Report a cleanup failure with its own stable code instead
 * of returning 0 or hiding it behind an engine error. The engine status stays
 * in the stderr text; the person needs the route-cleanup warning first. */
fn complete_engine_exit(
    state_path: &Path,
    directory: &Path,
    expected_uid: u32,
    signal: i32,
    status: ExitStatus,
) -> i32 {
    let mut clean = true;
    if let Err(error) = remove_state_at(state_path, expected_uid) {
        clean = false;
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the engine state file could not be removed: {error}; inspect it before starting again."
        );
    }
    if let Err(error) = remove_directory(directory) {
        clean = false;
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the private engine directory could not be removed: {error}; inspect it."
        );
    }
    if !clean {
        return EXIT_CLEANUP_FAILED;
    }
    final_code(signal, status)
}

struct ChildContext {
    request: fs::File,
    directory: PathBuf,
    state_path: PathBuf,
    expected_uid: u32,
    parent_writer: Option<UnixStream>,
    start_closed: bool,
    grace: Duration,
}

fn child_context(
    request: fs::File,
    directory: &Path,
    parent_writer: Option<UnixStream>,
    start_closed: bool,
    grace: Duration,
) -> ChildContext {
    ChildContext {
        request,
        directory: directory.to_path_buf(),
        state_path: PathBuf::from(STATE_PATH),
        expected_uid: 0,
        parent_writer,
        start_closed,
        grace,
    }
}

/* Supervise a spawned engine until it exits. If the engine ignores SIGTERM,
 * stay alive and keep the lock instead of releasing a second helper onto the
 * routing table. The app reports the timeout; a person resolves the engine. */
fn supervise_child(mut child: Child, context: ChildContext) -> i32 {
    let ChildContext {
        request,
        directory,
        state_path,
        expected_uid,
        mut parent_writer,
        start_closed,
        grace,
    } = context;
    let directory = directory.as_path();
    let state_path = state_path.as_path();
    let (closed_tx, closed_rx) = mpsc::channel();
    let _reader = thread::spawn(move || {
        let mut request = request;
        let mut buffer = [0u8; 64];
        loop {
            match request.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let _ = closed_tx.send(());
    });

    let mut closed_at: Option<Instant> = if start_closed {
        Some(Instant::now())
    } else {
        None
    };
    if closed_at.is_some() {
        drop(parent_writer.take());
    }
    let mut last_term: Option<Instant> = None;
    let mut reported_timeout = false;

    loop {
        let signal = STOP_SIGNAL.load(Ordering::SeqCst);
        if closed_at.is_none() && (closed_rx.try_recv().is_ok() || signal != 0) {
            closed_at = Some(Instant::now());
            drop(parent_writer.take());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return complete_engine_exit(state_path, directory, expected_uid, signal, status);
            }
            Ok(None) => {}
            Err(_) => {
                /* Do not exit while the engine may still be alive. Keep the lock
                 * and retry the wait. */
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        }
        if let Some(started) = closed_at {
            if started.elapsed() >= grace
                && last_term.is_none_or(|value| value.elapsed() >= TERM_RETRY)
            {
                match terminate(&mut child) {
                    Termination::Exited(status) => {
                        return complete_engine_exit(
                            state_path,
                            directory,
                            expected_uid,
                            signal,
                            status,
                        );
                    }
                    Termination::TimedOut => {
                        last_term = Some(Instant::now());
                        if !reported_timeout {
                            reported_timeout = true;
                            let _ = writeln!(io::stderr(),
                                "hotspotshade-helper: the engine did not stop after SIGTERM; inspect the routes. The helper keeps the lock and sends no SIGKILL."
                            );
                            let _ = writeln!(io::stdout(), "HS_STOP_TIMEOUT");
                            let _ = io::stdout().flush();
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/* Debug-only test seam. The integration test pauses the helper in the window
 * between the spawn and the engine-record write, then kills it with SIGKILL.
 * The release build compiles no call to this function. */
#[cfg(debug_assertions)]
fn test_delay_after_spawn() {
    let value = match env::var("HS_HELPER_TEST_DELAY_AFTER_SPAWN_MS") {
        Ok(value) => value,
        Err(_) => return,
    };
    let milliseconds = match value.parse::<u64>() {
        Ok(value) => value.min(10_000),
        Err(_) => return,
    };
    let _ = writeln!(
        io::stderr(),
        "hotspotshade-helper: debug test delay after spawn {milliseconds} ms"
    );
    thread::sleep(Duration::from_millis(milliseconds));
}

/* Stop an engine that cannot be reported as started: it was spawned but not
 * recorded, or its port could not be announced. The state record (PENDING, or
 * ENGINE once it was written) stays in place until the child is reaped, so a
 * helper killed during this stop still leaves a record that blocks a second
 * start. */
fn abort_unrecorded_child(child: Child, context: ChildContext) -> i32 {
    let code = supervise_child(child, context);
    if code == 0 {
        /* The engine stopped, but this start failed before its identity could
         * be recorded. Do not let the app report a clean stop. */
        EXIT_ENGINE_FAILED
    } else {
        code
    }
}

fn write_pending_record(host: &HostIdentity) -> io::Result<()> {
    let pid = std::process::id();
    let start_time = read_proc_starttime(pid)?;
    write_state_at(
        Path::new(STATE_PATH),
        &StateRecord::Pending {
            host: host.clone(),
            writer: ProcessIdentity { pid, start_time },
        },
        0,
    )
}

fn run() -> i32 {
    if env::args_os().len() != 1 {
        fail_reason(REASON_BAD_ARGUMENTS, "The helper takes no arguments.");
    }
    /* Every object this root process creates stays private unless a later call
     * asks for another mode. */
    unsafe {
        libc::umask(0o077);
    }
    if unsafe { libc::geteuid() } != 0 {
        fail_reason(REASON_NOT_ROOT, "The helper must run as root.");
    }
    let _invoking_uid = env::var("PKEXEC_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value != 0)
        .unwrap_or_else(|| fail_reason(REASON_NOT_PKEXEC, "The helper must run through pkexec."));

    install_signal_handlers();

    /* Read the request version first. An HS2 request moves descriptor 2
     * before the engine check can print a reason line on it. */
    let stdin = unsafe { File::from_raw_fd(0) };
    let mut request = stdin;
    let version = read_line(&mut request, 16).unwrap_or_else(|_| {
        fail_reason(REASON_REQUEST_INVALID, "The helper request is not valid.")
    });
    let handoff_fd = match version.as_str() {
        REQUEST_DIRECT => None,
        REQUEST_HANDOFF => Some(take_handoff_descriptor().unwrap_or_else(|_| {
            fail_reason(REASON_REQUEST_INVALID, "The helper request is not valid.")
        })),
        _ => fail_reason(REASON_REQUEST_INVALID, "The helper request is not valid."),
    };

    let engine = match validate_engine(engine_path(), 0) {
        Ok(path) => path,
        Err(error) => fail_reason(
            engine_error_reason(&error),
            &format!("The packaged engine is not safe to run: {error}"),
        ),
    };

    let secret = read_line(&mut request, 128).unwrap_or_else(|_| {
        fail_reason(REASON_REQUEST_INVALID, "The helper request is not valid.")
    });
    if !valid_secret(&secret) {
        fail_reason(REASON_REQUEST_INVALID, "The helper request is not valid.");
    }

    /* pkexec may have waited a long time for the password. If the app already
     * gave up, the request pipe is closed. Do not start an engine that nobody
     * is waiting for. */
    if input_hung_up(0) || STOP_SIGNAL.load(Ordering::SeqCst) != 0 {
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the app closed the request pipe before the engine started; no engine was started."
        );
        return EXIT_ABANDONED;
    }

    prepare_engine_home();
    let _lock = match acquire_lock_at(Path::new(LOCK_PATH), 0) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: another privileged helper is already running. Wait for it to stop."
            );
            return EXIT_ALREADY_RUNNING;
        }
        Err(_) => fail_reason(REASON_LOCK_UNAVAILABLE, "The helper lock is not available."),
    };
    /* The boot and PID namespace identity are read before the state check.
     * They are part of every record this helper writes, and they are required
     * to interpret an existing record. If they are unavailable, keep any
     * existing record and fail closed. */
    let current_identity = match current_host_identity_at(Path::new("/proc")) {
        Ok(value) => value,
        Err(error) => {
            let message = format!("the boot and PID namespace identity are not available: {error}");
            match fs::symlink_metadata(Path::new(STATE_PATH)) {
                Ok(_) => {
                    let _ = writeln!(
                        io::stderr(),
                        "hotspotshade-helper: {message}; the engine state is kept."
                    );
                    return EXIT_STATE_UNCERTAIN;
                }
                Err(state_error) if state_error.kind() == io::ErrorKind::NotFound => {
                    fail_reason(REASON_IDENTITY_UNAVAILABLE, &message);
                }
                Err(_) => {
                    let _ = writeln!(
                        io::stderr(),
                        "hotspotshade-helper: {message}; the engine state cannot be inspected, so it is kept."
                    );
                    return EXIT_STATE_UNCERTAIN;
                }
            }
        }
    };
    match previous_engine_running(Path::new(STATE_PATH), 0, &current_identity) {
        Ok(EnginePresence::Absent) => {}
        Ok(EnginePresence::Running(reason)) => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: {reason}. Inspect the routes before starting again."
            );
            return EXIT_ALREADY_RUNNING;
        }
        Ok(EnginePresence::Uncertain(reason)) => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: {reason}. Inspect the routes before starting again."
            );
            return EXIT_STATE_UNCERTAIN;
        }
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: the previous engine state could not be checked: {error}. The state is kept."
            );
            return EXIT_STATE_UNCERTAIN;
        }
    }

    let (token_reader, mut token_writer) = UnixStream::pair().unwrap_or_else(|_| {
        fail_reason(
            REASON_PIPES_FAILED,
            "The helper pipes could not be created.",
        )
    });
    let (parent_reader, parent_writer) = UnixStream::pair().unwrap_or_else(|_| {
        fail_reason(
            REASON_PIPES_FAILED,
            "The helper pipes could not be created.",
        )
    });
    let mut parent_writer = Some(parent_writer);
    token_writer
        .write_all(secret.as_bytes())
        .and_then(|_| token_writer.write_all(b"\n"))
        .unwrap_or_else(|_| {
            fail_reason(
                REASON_PIPES_FAILED,
                "The helper token pipe could not be written.",
            )
        });
    token_writer.flush().unwrap_or_else(|_| {
        fail_reason(
            REASON_PIPES_FAILED,
            "The helper token pipe could not be written.",
        )
    });

    let token_fd = lift_fd(token_reader.into_raw_fd()).unwrap_or_else(|_| {
        fail_reason(
            REASON_PIPES_FAILED,
            "The helper pipes could not be prepared.",
        )
    });
    let parent_fd = lift_fd(parent_reader.into_raw_fd()).unwrap_or_else(|_| {
        fail_reason(
            REASON_PIPES_FAILED,
            "The helper pipes could not be prepared.",
        )
    });

    let directory = make_temp_directory();
    let port_path = directory.join("port");

    /* The client starts its post-authorization startup deadline at this line.
     * The password prompt has already ended. */
    /* A reader that already left makes this write fail. No engine exists yet,
     * so that is the abandoned path, not a panic. */
    let ready_announced = announce("HS_READY");
    if ready_announced.is_err() || input_hung_up(0) || STOP_SIGNAL.load(Ordering::SeqCst) != 0 {
        remove_directory_or_report(&directory);
        drop(parent_writer.take());
        drop(token_writer);
        unsafe {
            libc::close(token_fd);
            libc::close(parent_fd);
        }
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the app closed the request pipe before the engine started; no engine was started."
        );
        return EXIT_ABANDONED;
    }

    /* Write-ahead record. The helper is recorded before the engine exists. A
     * helper killed from this point until the ENGINE record is written leaves a
     * PENDING record. A later helper treats it as uncertain instead of starting
     * a second engine over a process it cannot identify. */
    if let Err(error) = write_pending_record(&current_identity) {
        remove_directory_or_report(&directory);
        drop(parent_writer.take());
        drop(token_writer);
        unsafe {
            libc::close(token_fd);
            libc::close(parent_fd);
        }
        fail_reason(
            REASON_STATE_WRITE_FAILED,
            &format!(
                "the engine start record could not be written: {error}; no engine was started."
            ),
        );
    }

    let mut command = Command::new(&engine);
    command
        .env_clear()
        .env("HOME", ENGINE_HOME)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .env("TMPDIR", "/tmp")
        .arg("gui")
        .arg("--no-open")
        .arg("--port")
        .arg("0")
        .arg("--port-file")
        .arg(&port_path)
        .arg("--token-fd")
        .arg("3")
        .arg("--parent-fd")
        .arg("4")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if handoff_fd.is_some() {
        command
            .arg("--credentials-fd")
            .arg(ENGINE_CREDENTIALS_FD.to_string());
    }
    let helper_pid = std::process::id() as libc::pid_t;
    unsafe {
        command.pre_exec(move || {
            /* A helper killed with SIGKILL cannot run its stop path. The
             * engine then receives SIGTERM and removes its routes instead of
             * staying behind as an orphan root process. */
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != helper_pid {
                return Err(io::Error::other("the helper parent exited"));
            }
            move_fd(token_fd, 3)?;
            move_fd(parent_fd, 4)?;
            if let Some(fd) = handoff_fd {
                move_fd(fd, ENGINE_CREDENTIALS_FD)?;
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(value) => value,
        Err(_) => {
            let cleanup = remove_state_at(Path::new(STATE_PATH), 0);
            remove_directory_or_report(&directory);
            drop(parent_writer.take());
            drop(token_writer);
            unsafe {
                libc::close(token_fd);
                libc::close(parent_fd);
                close_handoff(handoff_fd);
            }
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: the packaged engine did not start."
            );
            return match cleanup {
                Ok(()) => EXIT_ENGINE_FAILED,
                Err(error) => {
                    let _ = writeln!(
                        io::stderr(),
                        "hotspotshade-helper: the pending start record could not be removed: {error}; inspect it."
                    );
                    EXIT_CLEANUP_FAILED
                }
            };
        }
    };
    drop(token_writer);
    unsafe {
        libc::close(token_fd);
        libc::close(parent_fd);
        close_handoff(handoff_fd);
    }

    #[cfg(debug_assertions)]
    test_delay_after_spawn();

    /* Record the engine before any post-spawn abandonment check. A closed
     * channel or a signal after this point must leave an engine identity that
     * a later helper can verify. Do not reap the child before the read: an
     * unreaped pid cannot be reused. */
    let start_time = match read_proc_starttime(child.id()) {
        Ok(value) => value,
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: the engine process identity could not be read: {error}; stopping the engine."
            );
            return abort_unrecorded_child(
                child,
                child_context(request, &directory, parent_writer, true, Duration::ZERO),
            );
        }
    };
    let engine_namespace = match read_pid_namespace_at(Path::new("/proc"), child.id()) {
        Ok(value) => value,
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "hotspotshade-helper: the engine PID namespace could not be read: {error}; stopping the engine."
            );
            return abort_unrecorded_child(
                child,
                child_context(request, &directory, parent_writer, true, Duration::ZERO),
            );
        }
    };
    if engine_namespace != (current_identity.pid_ns_dev, current_identity.pid_ns_ino) {
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the engine is in another PID namespace than the helper; stopping it."
        );
        return abort_unrecorded_child(
            child,
            child_context(request, &directory, parent_writer, true, Duration::ZERO),
        );
    }
    if let Err(error) = write_state_at(
        Path::new(STATE_PATH),
        &StateRecord::Engine {
            host: current_identity.clone(),
            engine: ProcessIdentity {
                pid: child.id(),
                start_time,
            },
        },
        0,
    ) {
        /* Do not leave an engine behind without the state record that blocks a
         * second start. The PENDING record stays until the child is reaped. */
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the engine identity could not be recorded: {error}; stopping the engine."
        );
        return abort_unrecorded_child(
            child,
            child_context(request, &directory, parent_writer, true, Duration::ZERO),
        );
    }

    if input_hung_up(0) || STOP_SIGNAL.load(Ordering::SeqCst) != 0 {
        /* The channel can close between the pre-launch check and this point.
         * The engine record is already written, so stop the engine instead of
         * claiming that none started. */
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the app stopped waiting after the engine launch; stopping the new engine."
        );
        return supervise_child(
            child,
            child_context(request, &directory, parent_writer, true, Duration::ZERO),
        );
    }

    let port = match wait_for_port(&mut child, &port_path) {
        PortWait::Ready(port) => port,
        PortWait::Exited(status) => {
            /* wait_for_port reaped this child. Do not signal its old process
             * id: the system may already have reused it. */
            return complete_engine_exit(Path::new(STATE_PATH), &directory, 0, 0, status);
        }
        PortWait::TimedOut | PortWait::Canceled => {
            return supervise_child(
                child,
                child_context(request, &directory, parent_writer, true, Duration::ZERO),
            );
        }
    };
    remove_directory_or_report(&directory);
    if let Err(error) = announce(&format!("HS_PORT {port}")) {
        /* The engine runs, but nobody can learn its port. Stop it through the
         * normal SIGTERM path and report a failed stop, never a clean one. */
        let _ = writeln!(
            io::stderr(),
            "hotspotshade-helper: the port could not be announced: {error}; stopping the engine."
        );
        return abort_unrecorded_child(
            child,
            child_context(request, &directory, parent_writer, true, Duration::ZERO),
        );
    }

    supervise_child(
        child,
        child_context(request, &directory, parent_writer, false, EOF_GRACE),
    )
}

fn main() {
    std::process::exit(run());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_stderr_does_not_panic_when_reporting_engine_failure() {
        const MARKER: &str = "HS_HELPER_CLOSED_STDERR_TEST";
        if env::var_os(MARKER).is_some() {
            let mut ready = [0u8; 1];
            io::stdin().read_exact(&mut ready).unwrap();
            let status = ExitStatus::from_raw(1 << 8);
            assert_eq!(classify_status(status), EXIT_ENGINE_FAILED);
            return;
        }
        let mut child = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::a_closed_stderr_does_not_panic_when_reporting_engine_failure",
            ])
            .env(MARKER, "1")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stderr.take());
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert!(child.wait().unwrap().success());
    }

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn a_protocol_line_is_written_with_one_newline() {
        let mut buffer = Vec::new();
        write_line(&mut buffer, "HS_READY").expect("write the line");
        write_line(&mut buffer, "HS_PORT 4242").expect("write the line");
        assert_eq!(buffer, b"HS_READY\nHS_PORT 4242\n");
    }

    #[test]
    fn a_closed_reader_is_a_write_error_not_a_panic() {
        let mut writer = BrokenPipeWriter;
        let error = write_line(&mut writer, "HS_READY").expect_err("a broken pipe is an error");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    /* The real stdout path. The child test process swaps descriptor 1 for a
     * pipe with no reader, announces, then restores descriptor 1 so the test
     * harness can still report. A `println!` here would panic on EPIPE. */
    #[test]
    fn announce_reports_a_broken_stdout_instead_of_panicking() {
        const MARKER: &str = "HS_HELPER_BROKEN_STDOUT_TEST";
        if env::var_os(MARKER).is_some() {
            let saved = unsafe { libc::dup(1) };
            assert!(saved >= 0, "save descriptor 1");
            let mut fds = [0 as libc::c_int; 2];
            assert_eq!(
                unsafe { libc::pipe(fds.as_mut_ptr()) },
                0,
                "create the pipe"
            );
            unsafe {
                libc::close(fds[0]);
                assert!(libc::dup2(fds[1], 1) >= 0, "replace descriptor 1");
                libc::close(fds[1]);
            }
            let result = announce("HS_PORT 4242");
            unsafe {
                libc::dup2(saved, 1);
                libc::close(saved);
            }
            assert!(result.is_err(), "a pipe with no reader must fail the write");
            return;
        }
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::announce_reports_a_broken_stdout_instead_of_panicking",
            ])
            .env(MARKER, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn every_failure_reason_is_a_short_fixed_slug() {
        let mut seen = Vec::new();
        for reason in ALL_REASONS {
            assert!(
                !reason.is_empty()
                    && reason.len() <= 32
                    && reason
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{reason} is not a lowercase slug"
            );
            assert!(!seen.contains(&reason), "{reason} is repeated");
            seen.push(reason);
            assert_eq!(reason_line(reason), format!("HS_REASON {reason}"));
        }
    }

    #[test]
    fn an_unsafe_engine_install_and_a_missing_engine_have_different_reasons() {
        let denied = io::Error::new(io::ErrorKind::PermissionDenied, "x");
        let absent = io::Error::new(io::ErrorKind::NotFound, "x");
        assert_eq!(
            engine_error_reason(&denied),
            REASON_ENGINE_UNSAFE_PERMISSIONS
        );
        assert_eq!(engine_error_reason(&absent), REASON_ENGINE_MISSING);
        assert_ne!(engine_error_reason(&denied), engine_error_reason(&absent));
    }

    /* The reason line comes first, uses exit code 1, and carries nothing but
     * the fixed slug. fail_reason exits the process, so a child runs it. */
    #[test]
    fn a_preparation_failure_prints_the_reason_line_and_exits_one() {
        const MARKER: &str = "HS_HELPER_REASON_LINE_TEST";
        if env::var_os(MARKER).is_some() {
            fail_reason(
                REASON_ENGINE_UNSAFE_PERMISSIONS,
                "The packaged engine directory is writable by another user.",
            );
        }
        let output = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::a_preparation_failure_prints_the_reason_line_and_exits_one",
            ])
            .env(MARKER, "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(EXIT_REQUEST_INVALID));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines = stderr.lines();
        assert_eq!(lines.next(), Some("HS_REASON engine_unsafe_permissions"));
        assert_eq!(
            lines.next(),
            Some("hotspotshade-helper: The packaged engine directory is writable by another user.")
        );
    }

    fn temporary_directory() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let path = PathBuf::from("/tmp").join(format!(
            "hotspotshade-helper-test-{}-{}",
            std::process::id(),
            nanos
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).expect("create the test directory");
        path
    }

    fn test_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn test_host() -> HostIdentity {
        current_host_identity_at(Path::new("/proc")).expect("read the current host identity")
    }

    fn pending_record(host: &HostIdentity, pid: u32, start_time: u64) -> StateRecord {
        StateRecord::Pending {
            host: host.clone(),
            writer: ProcessIdentity { pid, start_time },
        }
    }

    fn engine_record(host: &HostIdentity, pid: u32, start_time: u64) -> StateRecord {
        StateRecord::Engine {
            host: host.clone(),
            engine: ProcessIdentity { pid, start_time },
        }
    }

    fn write_test_state(directory: &Path, record: &StateRecord) -> (PathBuf, u32) {
        let path = directory.join("engine.state");
        let uid = test_uid();
        write_state_at(&path, record, uid).expect("write the test state");
        (path, uid)
    }

    fn expect_presence(result: io::Result<EnginePresence>) -> EnginePresence {
        result.expect("inspect the engine presence")
    }

    /* A synthetic /proc tree exercises observations that a live test cannot
     * stage reliably: a zombie leader beside a live task, a vanished process
     * with and without a usable process table, and unreadable task lists. */
    fn proc_stat(pid: u32, state: char, start_time: u64) -> String {
        let mut fields = vec!["0".to_owned(); 18];
        fields.push(start_time.to_string());
        format!("{pid} (engine) {state} {}\n", fields.join(" "))
    }

    fn write_proc_file(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create the fake proc directory");
        }
        fs::write(path, contents).expect("write the fake proc file");
    }

    fn make_proc_table_available(root: &Path) {
        write_proc_file(root, "self/stat", &proc_stat(1, 'S', 1));
    }

    fn write_proc_group(root: &Path, pid: u32, state: char, start_time: u64) {
        write_proc_file(
            root,
            &format!("{pid}/stat"),
            &proc_stat(pid, state, start_time),
        );
    }

    fn write_proc_task(root: &Path, pid: u32, tid: u32, state: char, start_time: u64) {
        write_proc_file(
            root,
            &format!("{pid}/task/{tid}/stat"),
            &proc_stat(tid, state, start_time),
        );
    }

    /* The fake namespace is a regular file. The helper compares the device and
     * inode values, not the nsfs type, so the test can stage any identity. */
    fn fake_namespace(root: &Path, pid: u32) -> (u64, u64) {
        let path = root.join(pid.to_string()).join("ns/pid");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create the fake namespace directory");
        }
        fs::write(&path, b"pid namespace\n").expect("write the fake namespace");
        let metadata = fs::metadata(&path).expect("read the fake namespace");
        (metadata.dev(), metadata.ino())
    }

    fn fake_host(root: &Path, pid: u32, boot_id: &str) -> HostIdentity {
        let (pid_ns_dev, pid_ns_ino) = fake_namespace(root, pid);
        HostIdentity {
            boot_id: boot_id.to_owned(),
            pid_ns_dev,
            pid_ns_ino,
        }
    }

    #[test]
    fn a_temporary_directory_is_created_private() {
        let path = make_temp_directory();
        let metadata = fs::symlink_metadata(&path).expect("the temporary directory exists");
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), test_uid());
        assert!(!path.join("port").exists());
        remove_directory(&path).expect("remove the temporary directory");
        assert!(!path.exists());
    }

    #[test]
    fn a_reaped_child_is_not_signaled() {
        let mut child = Command::new("/bin/true").spawn().expect("start /bin/true");
        let status = child.wait().expect("reap /bin/true");
        assert!(status.success());
        /* The process id is free for reuse after the wait. terminate must
         * recognize that it has no child to signal. */
        assert_eq!(terminate(&mut child), Termination::Exited(status));
    }

    #[test]
    fn a_running_child_stops_on_sigterm_without_sigkill() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("start /bin/sleep");
        let started = Instant::now();
        match terminate(&mut child) {
            Termination::Exited(status) => {
                assert_eq!(status.signal(), Some(libc::SIGTERM));
            }
            Termination::TimedOut => panic!("the child did not stop"),
        }
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_secret_is_exactly_64_hex_characters() {
        assert!(valid_secret(&"a".repeat(64)));
        assert!(valid_secret(&"0123456789abcdef".repeat(4)));
        assert!(!valid_secret(&"a".repeat(63)));
        assert!(!valid_secret(&"a".repeat(65)));
        assert!(!valid_secret(&"g".repeat(64)));
        assert!(!valid_secret(""));
    }

    #[test]
    fn a_closed_request_pipe_is_detected_before_start() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert!(!input_hung_up(fds[0]));
        unsafe {
            libc::write(fds[1], b"x".as_ptr().cast(), 1);
            libc::close(fds[1]);
        }
        assert!(input_hung_up(fds[0]));
        unsafe {
            libc::close(fds[0]);
        }
    }

    #[test]
    fn an_open_request_socket_pair_is_not_hung_up() {
        let (reader, mut writer) = UnixStream::pair().expect("create the socket pair");
        assert!(!input_hung_up(reader.as_raw_fd()));
        writer
            .write_all(b"HS1\n")
            .expect("write pending request data");
        writer.flush().expect("flush pending request data");
        /* Pending request bytes are readable, not EOF. */
        assert!(!input_hung_up(reader.as_raw_fd()));
    }

    #[test]
    fn a_half_closed_request_socket_pair_is_detected() {
        let (reader, mut writer) = UnixStream::pair().expect("create the socket pair");
        writer
            .write_all(b"HS1\n")
            .expect("write pending request data");
        writer.flush().expect("flush pending request data");
        /* Node `end()` on child stdin sends this half-close. The parent's
         * descriptor stays open, so a POLLHUP-only guard misses it. */
        writer
            .shutdown(std::net::Shutdown::Write)
            .expect("shut down the write half");
        assert!(input_hung_up(reader.as_raw_fd()));
        drop(writer);
    }

    #[test]
    fn a_closed_request_socket_pair_is_detected() {
        let (reader, writer) = UnixStream::pair().expect("create the socket pair");
        drop(writer);
        assert!(input_hung_up(reader.as_raw_fd()));
    }

    #[test]
    fn the_checked_engine_path_is_the_canonical_path() {
        let directory = temporary_directory();
        let real = directory.join("hotspotshade");
        fs::write(&real, b"#!/bin/sh\nexit 0\n").expect("write the engine");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("make it executable");
        let link = directory.join("engine-link");
        std::os::unix::fs::symlink(&real, &link).expect("create the engine symlink");
        let resolved = resolve_engine(link.to_str().expect("the link path")).expect("resolve it");
        assert_eq!(
            resolved,
            fs::canonicalize(&real).expect("canonicalize the engine")
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_missing_or_non_executable_engine_is_refused() {
        let directory = temporary_directory();
        let missing = directory.join("missing");
        assert!(resolve_engine(missing.to_str().expect("the path")).is_err());
        let plain = directory.join("plain");
        fs::write(&plain, b"not executable\n").expect("write the plain file");
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).expect("make it plain");
        assert!(resolve_engine(plain.to_str().expect("the path")).is_err());
        assert!(resolve_engine(directory.to_str().expect("the path")).is_err());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_foreign_owner_or_writable_engine_is_refused() {
        let directory = temporary_directory();
        let engine = directory.join("hotspotshade");
        fs::write(&engine, b"#!/bin/sh\nexit 0\n").expect("write the engine");
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755))
            .expect("make it executable");
        let uid = test_uid();
        assert_eq!(
            check_engine_owner(&engine, uid.wrapping_add(1))
                .expect_err("a foreign owner must fail")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o775)).expect("widen the engine");
        assert!(check_engine_owner(&engine, uid).is_err());
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755))
            .expect("restore the engine");
        /* The temporary directory sits under a world-writable parent, so the
         * parent chain check fails closed even with the right owner. */
        assert!(check_engine_owner(&engine, uid).is_err());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn an_engine_signal_exit_is_not_a_clean_stop() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("kill -TERM $$")
            .spawn()
            .expect("start the signal child");
        let status = child.wait().expect("reap the signal child");
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert_eq!(classify_status(status), EXIT_ENGINE_SIGNALED);
    }

    #[test]
    fn an_engine_nonzero_exit_is_not_a_clean_stop() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 9")
            .spawn()
            .expect("start the failing child");
        let status = child.wait().expect("reap the failing child");
        assert_eq!(status.code(), Some(9));
        assert_eq!(classify_status(status), EXIT_ENGINE_FAILED);
    }

    #[test]
    fn a_helper_signal_exit_is_not_a_clean_stop() {
        let mut child = Command::new("/bin/true").spawn().expect("start /bin/true");
        let status = child.wait().expect("reap /bin/true");
        assert!(status.success());
        assert_eq!(final_code(libc::SIGTERM, status), 128 + libc::SIGTERM);
        assert_eq!(final_code(0, status), 0);
    }

    #[test]
    fn a_lock_file_is_created_private() {
        let directory = temporary_directory();
        let path = directory.join("helper.lock");
        let uid = test_uid();
        let lock = acquire_lock_at(&path, uid).expect("the lock");
        let metadata = fs::symlink_metadata(&path).expect("the lock file exists");
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        drop(lock);
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn only_one_helper_holds_the_lock() {
        let directory = temporary_directory();
        let path = directory.join("helper.lock");
        let uid = test_uid();
        let first = acquire_lock_at(&path, uid).expect("the first lock");
        let second = acquire_lock_at(&path, uid);
        assert_eq!(
            second.expect_err("the second lock must fail").kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(first);
        let third = acquire_lock_at(&path, uid).expect("the lock is free after a drop");
        drop(third);
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_loose_lock_file_is_refused() {
        let directory = temporary_directory();
        let path = directory.join("helper.lock");
        fs::write(&path, b"").expect("write the lock file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("widen the mode");
        let uid = test_uid();
        assert_eq!(
            acquire_lock_at(&path, uid)
                .expect_err("a loose lock must fail")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn the_boot_identity_accepts_only_a_lowercase_uuid() {
        assert!(valid_boot_id("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(!valid_boot_id("01234567-89AB-cdef-0123-456789abcdef"));
        assert!(!valid_boot_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_boot_id("01234567-89ab-cdef-0123-456789abcde"));
        assert!(!valid_boot_id("01234567-89ab-cdef-0123-456789abcdeg"));
        assert!(!valid_boot_id(""));
    }

    #[test]
    fn the_state_record_round_trips_and_detects_a_live_process() {
        let directory = temporary_directory();
        let host = test_host();
        let pid = std::process::id();
        let start_time = read_proc_starttime(pid).expect("read this process state");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, pid, start_time));
        assert_eq!(
            read_state_at(&path, uid).expect("read the state"),
            Some(engine_record(&host, pid, start_time))
        );
        assert_eq!(
            expect_presence(previous_engine_running(&path, uid, &host)),
            EnginePresence::Running("a previous privileged engine is still running")
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_reused_process_id_with_a_different_start_time_is_stale() {
        let directory = temporary_directory();
        let host = test_host();
        let pid = std::process::id();
        let start_time = read_proc_starttime(pid).expect("read this process state");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, pid, start_time + 1));
        assert_eq!(
            expect_presence(previous_engine_running(&path, uid, &host)),
            EnginePresence::Absent
        );
        assert!(!path.exists(), "the stale state is removed");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_recorded_zombie_does_not_block_a_new_engine() {
        let directory = temporary_directory();
        let host = test_host();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.1"])
            .spawn()
            .expect("start a short-lived child");
        let pid = child.id();
        let start_time = read_proc_starttime(pid).expect("read child state");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, pid, start_time));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if read_proc_state(pid).expect("observe child").1 {
                break;
            }
            assert!(Instant::now() < deadline, "child did not become a zombie");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            expect_presence(previous_engine_running(&path, uid, &host)),
            EnginePresence::Absent
        );
        assert!(!path.exists());
        child.wait().expect("reap child");
        fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn a_state_record_from_a_previous_boot_is_stale() {
        let directory = temporary_directory();
        let current = test_host();
        let previous = HostIdentity {
            boot_id: "00000000-0000-0000-0000-000000000000".to_owned(),
            pid_ns_dev: current.pid_ns_dev,
            pid_ns_ino: current.pid_ns_ino,
        };
        let (path, uid) = write_test_state(&directory, &engine_record(&previous, 4242, 100));
        assert_eq!(
            expect_presence(previous_engine_running_at(
                &path,
                uid,
                Path::new("/proc"),
                &current
            )),
            EnginePresence::Absent
        );
        assert!(!path.exists(), "the previous-boot record is removed");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_previous_boot_pending_record_is_stale() {
        let directory = temporary_directory();
        let current = test_host();
        let previous = HostIdentity {
            boot_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            pid_ns_dev: current.pid_ns_dev,
            pid_ns_ino: current.pid_ns_ino,
        };
        let (path, uid) = write_test_state(&directory, &pending_record(&previous, 4242, 100));
        assert_eq!(
            expect_presence(previous_engine_running_at(
                &path,
                uid,
                Path::new("/proc"),
                &current
            )),
            EnginePresence::Absent
        );
        assert!(
            !path.exists(),
            "the previous-boot pending record is removed"
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_state_record_from_another_pid_namespace_is_uncertain() {
        let directory = temporary_directory();
        let current = test_host();
        let foreign = HostIdentity {
            boot_id: current.boot_id.clone(),
            pid_ns_dev: current.pid_ns_dev,
            pid_ns_ino: current.pid_ns_ino.wrapping_add(1),
        };
        let (path, uid) = write_test_state(&directory, &engine_record(&foreign, 4242, 100));
        match expect_presence(previous_engine_running_at(
            &path,
            uid,
            Path::new("/proc"),
            &current,
        )) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("another PID namespace"), "{reason}");
            }
            other => panic!("a foreign namespace must stay uncertain: {other:?}"),
        }
        assert!(path.exists(), "the foreign record is kept");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_pending_record_from_a_dead_writer_is_uncertain() {
        let directory = temporary_directory();
        let host = test_host();
        let (path, uid) = write_test_state(&directory, &pending_record(&host, u32::MAX, 100));
        match expect_presence(previous_engine_running(&path, uid, &host)) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("engine identity is unknown"), "{reason}");
            }
            other => panic!("an abandoned pending record must stay uncertain: {other:?}"),
        }
        assert!(path.exists(), "the pending record is kept");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_pending_record_from_a_live_writer_blocks_a_new_engine() {
        let directory = temporary_directory();
        let host = test_host();
        let pid = std::process::id();
        let start_time = read_proc_starttime(pid).expect("read this process state");
        let (path, uid) = write_test_state(&directory, &pending_record(&host, pid, start_time));
        match expect_presence(previous_engine_running(&path, uid, &host)) {
            EnginePresence::Running(reason) => {
                assert!(reason.contains("pending engine start"), "{reason}");
            }
            other => panic!("a live pending writer must block: {other:?}"),
        }
        assert!(path.exists(), "the pending record is kept");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_pending_record_from_a_reused_writer_id_is_uncertain() {
        let directory = temporary_directory();
        let host = test_host();
        let pid = std::process::id();
        let start_time = read_proc_starttime(pid).expect("read this process state");
        let (path, uid) = write_test_state(&directory, &pending_record(&host, pid, start_time + 1));
        match expect_presence(previous_engine_running(&path, uid, &host)) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("reused"), "{reason}");
            }
            other => panic!("a reused writer id must stay uncertain: {other:?}"),
        }
        assert!(path.exists(), "the pending record is kept");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_zombie_leader_with_a_live_thread_blocks_a_new_engine() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        write_proc_group(&proc_root, 4242, 'Z', 100);
        write_proc_task(&proc_root, 4242, 4242, 'Z', 100);
        write_proc_task(&proc_root, 4242, 4243, 'S', 101);
        let host = fake_host(&proc_root, 4242, "01234567-89ab-cdef-0123-456789abcdef");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        assert_eq!(
            expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)),
            EnginePresence::Running("a previous privileged engine still has a live task")
        );
        assert_eq!(
            read_state_at(&path, uid).unwrap(),
            Some(engine_record(&host, 4242, 100))
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_zombie_leader_with_only_dead_tasks_is_stale() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        write_proc_group(&proc_root, 4242, 'Z', 100);
        write_proc_task(&proc_root, 4242, 4242, 'Z', 100);
        write_proc_task(&proc_root, 4242, 4243, 'X', 101);
        let host = fake_host(&proc_root, 4242, "01234567-89ab-cdef-0123-456789abcdef");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        assert_eq!(
            expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)),
            EnginePresence::Absent
        );
        assert!(!path.exists(), "the stale state is removed");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_live_process_in_another_namespace_is_uncertain() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        write_proc_group(&proc_root, 4242, 'S', 100);
        let (pid_ns_dev, pid_ns_ino) = fake_namespace(&proc_root, 4242);
        let host = HostIdentity {
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            pid_ns_dev,
            pid_ns_ino: pid_ns_ino.wrapping_add(1),
        };
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        match expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("another PID namespace"), "{reason}");
            }
            other => panic!("a namespace mismatch must stay uncertain: {other:?}"),
        }
        assert!(path.exists(), "the state is kept");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_missing_process_with_a_readable_proc_table_is_stale() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        let host = test_host();
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        assert_eq!(
            expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)),
            EnginePresence::Absent
        );
        assert!(!path.exists(), "the stale state is removed");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_missing_process_without_a_readable_proc_table_is_uncertain() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        fs::create_dir(&proc_root).expect("create the fake proc root");
        let host = test_host();
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        match expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("process table"), "{reason}");
            }
            other => panic!("a missing process table must not prove exit: {other:?}"),
        }
        assert!(path.exists(), "the state is kept");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn an_unreadable_task_list_preserves_the_state() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        write_proc_group(&proc_root, 4242, 'Z', 100);
        let host = fake_host(&proc_root, 4242, "01234567-89ab-cdef-0123-456789abcdef");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        let task_path = proc_root.join("4242").join("task");
        fs::write(&task_path, b"not a directory").expect("write the bad task path");
        match previous_engine_running_at(&path, uid, &proc_root, &host) {
            Ok(EnginePresence::Uncertain(_)) | Err(_) => {}
            other => panic!("an unreadable task list must stay uncertain: {other:?}"),
        }
        assert_eq!(
            read_state_at(&path, uid).unwrap(),
            Some(engine_record(&host, 4242, 100))
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_missing_task_list_while_the_group_still_exists_is_uncertain() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        write_proc_group(&proc_root, 4242, 'Z', 100);
        let host = fake_host(&proc_root, 4242, "01234567-89ab-cdef-0123-456789abcdef");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        match expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("task list"), "{reason}");
            }
            other => panic!("a group without a task list must stay uncertain: {other:?}"),
        }
        assert_eq!(
            read_state_at(&path, uid).unwrap(),
            Some(engine_record(&host, 4242, 100))
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_malformed_task_state_preserves_the_state() {
        let directory = temporary_directory();
        let proc_root = directory.join("proc");
        make_proc_table_available(&proc_root);
        write_proc_group(&proc_root, 4242, 'Z', 100);
        let host = fake_host(&proc_root, 4242, "01234567-89ab-cdef-0123-456789abcdef");
        let (path, uid) = write_test_state(&directory, &engine_record(&host, 4242, 100));
        write_proc_file(&proc_root, "4242/task/4243/stat", "not a process stat\n");
        match expect_presence(previous_engine_running_at(&path, uid, &proc_root, &host)) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("task list"), "{reason}");
            }
            other => panic!("a malformed task stat must stay uncertain: {other:?}"),
        }
        assert_eq!(
            read_state_at(&path, uid).unwrap(),
            Some(engine_record(&host, 4242, 100))
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn an_old_version_record_is_preserved_and_uncertain() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        let contents = b"HS_ENGINE 1\n4242 100\n";
        fs::write(&path, contents).expect("write the old state");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make the state private");
        let current = test_host();
        match expect_presence(previous_engine_running_at(
            &path,
            uid,
            Path::new("/proc"),
            &current,
        )) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("older helper"), "{reason}");
            }
            other => panic!("an old record must stay uncertain: {other:?}"),
        }
        assert_eq!(fs::read(&path).unwrap(), contents, "the state is preserved");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn an_unknown_version_record_is_preserved_and_uncertain() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        let contents = b"HS_ENGINE 3\nBOOT 01234567-89ab-cdef-0123-456789abcdef\n";
        fs::write(&path, contents).expect("write the unknown state");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make the state private");
        let current = test_host();
        match expect_presence(previous_engine_running_at(
            &path,
            uid,
            Path::new("/proc"),
            &current,
        )) {
            EnginePresence::Uncertain(reason) => {
                assert!(reason.contains("unknown version"), "{reason}");
            }
            other => panic!("an unknown record must stay uncertain: {other:?}"),
        }
        assert_eq!(fs::read(&path).unwrap(), contents, "the state is preserved");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn trailing_engine_state_is_rejected() {
        let host = test_host();
        let text = state_text(&engine_record(&host, 4242, 100));
        assert_eq!(parse_state(&text), Ok(engine_record(&host, 4242, 100)));
        assert!(parse_state(&format!("{text}extra\n")).is_err());
        assert!(parse_state(&format!("{text}\n")).is_err());
        assert!(parse_state(&text.replace("ENGINE 4242 100", "ENGINE 0 100")).is_err());
        assert!(parse_state(&text.replace("ENGINE 4242 100", "ENGINE 4242 100 7")).is_err());
        assert!(parse_state(&text.replace("BOOT ", "BOOT  ")).is_err());
        assert!(parse_state(&text.replace("NS ", "NS x ")).is_err());
    }

    #[test]
    fn a_pending_record_names_the_helper() {
        let host = test_host();
        let text = state_text(&pending_record(&host, 4242, 100));
        assert!(text.contains("PENDING 4242 100"));
        assert_eq!(parse_state(&text), Ok(pending_record(&host, 4242, 100)));
    }

    #[test]
    fn the_state_record_rejects_a_missing_or_extra_line() {
        let host = test_host();
        let text = state_text(&engine_record(&host, 4242, 100));
        let without_last = text
            .rmatch_indices('\n')
            .nth(1)
            .map(|(index, _)| &text[..index + 1]);
        assert!(parse_state(without_last.unwrap_or("")).is_err());
        assert!(parse_state(&text.replace("BOOT ", "BOOT X")).is_err());
    }

    #[test]
    fn an_oversized_state_is_rejected_and_kept() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        let contents = vec![b'x'; STATE_MAX_BYTES + 1];
        fs::write(&path, &contents).expect("write the oversized state");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make the state private");
        assert!(read_state_at(&path, uid).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            contents,
            "the oversized state is preserved"
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_state_write_with_a_directory_at_the_path_fails() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        fs::create_dir(&path).expect("create a directory at the state path");
        assert!(write_state_at(&path, &engine_record(&test_host(), 4242, 100), uid).is_err());
        let metadata = fs::symlink_metadata(&path).expect("the directory is kept");
        assert!(metadata.is_dir(), "the directory is not replaced");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_clean_engine_exit_with_a_clean_state_is_clean() {
        let directory = temporary_directory();
        let port_directory = directory.join("port");
        fs::create_dir(&port_directory).expect("create the port directory");
        let uid = test_uid();
        let (path, _) = write_test_state(&directory, &engine_record(&test_host(), 4242, 100));
        let status = ExitStatus::from_raw(0);
        assert_eq!(
            complete_engine_exit(&path, &port_directory, uid, 0, status),
            0
        );
        assert!(!path.exists());
        assert!(!port_directory.exists());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_clean_engine_exit_with_unremovable_state_reports_cleanup_failure() {
        let directory = temporary_directory();
        let port_directory = directory.join("port");
        fs::create_dir(&port_directory).expect("create the port directory");
        let uid = test_uid();
        let path = directory.join("engine.state");
        fs::write(&path, b"HS_ENGINE 2\n").expect("write the state");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make the state public");
        let status = ExitStatus::from_raw(0);
        assert_eq!(
            complete_engine_exit(&path, &port_directory, uid, 0, status),
            EXIT_CLEANUP_FAILED,
            "cleanup failure must not look like an engine error or a clean stop"
        );
        assert!(path.exists(), "the unremovable state is kept");
        assert!(!port_directory.exists());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_clean_engine_exit_with_a_clean_pending_state_is_clean() {
        let directory = temporary_directory();
        let port_directory = directory.join("port");
        fs::create_dir(&port_directory).expect("create the port directory");
        let uid = test_uid();
        let (path, _) = write_test_state(&directory, &pending_record(&test_host(), 4242, 100));
        let status = ExitStatus::from_raw(0);
        assert_eq!(
            complete_engine_exit(&path, &port_directory, uid, 0, status),
            0
        );
        assert!(!path.exists());
        assert!(!port_directory.exists());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_stale_engine_state_is_removed() {
        let directory = temporary_directory();
        let host = test_host();
        let (path, uid) = write_test_state(&directory, &engine_record(&host, u32::MAX, 1));
        assert_eq!(
            expect_presence(previous_engine_running(&path, uid, &host)),
            EnginePresence::Absent
        );
        assert!(!path.exists());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_stale_state_temporary_file_is_replaced() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temporary, b"left over").expect("write the stale temporary file");
        let pid = std::process::id();
        let start_time = read_proc_starttime(pid).expect("read this process state");
        write_state_at(&path, &engine_record(&test_host(), pid, start_time), uid)
            .expect("replace the stale temporary file");
        assert!(path.exists());
        assert!(!temporary.exists());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_private_malformed_engine_state_fails_closed_and_is_kept() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        let contents = b"not a state\n";
        fs::write(&path, contents).expect("write the state");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make the state private");
        assert!(read_state_at(&path, uid).is_err());
        let current = test_host();
        match expect_presence(previous_engine_running_at(
            &path,
            uid,
            Path::new("/proc"),
            &current,
        )) {
            EnginePresence::Uncertain(_) => {}
            other => panic!("a malformed state must stay uncertain: {other:?}"),
        }
        assert_eq!(fs::read(&path).unwrap(), contents, "the state is preserved");
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_private_trailing_engine_state_fails_closed_and_is_kept() {
        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let uid = test_uid();
        let host = test_host();
        let contents = format!("{}trailing\n", state_text(&engine_record(&host, 4242, 100)));
        fs::write(&path, contents.as_bytes()).expect("write the state");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make the state private");
        assert!(read_state_at(&path, uid).is_err());
        match expect_presence(previous_engine_running_at(
            &path,
            uid,
            Path::new("/proc"),
            &host,
        )) {
            EnginePresence::Uncertain(_) => {}
            other => panic!("a trailing state must stay uncertain: {other:?}"),
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            contents.as_bytes(),
            "the state is preserved"
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn a_state_fifo_is_refused_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let directory = temporary_directory();
        let path = directory.join("engine.state");
        let name = CString::new(path.as_os_str().as_bytes()).expect("make the fifo path");
        assert_eq!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
            0,
            "create the fifo: {}",
            io::Error::last_os_error()
        );
        let uid = test_uid();
        assert_eq!(
            read_state_at(&path, uid)
                .expect_err("a fifo is not a state file")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[test]
    fn an_engine_state_symlink_fails_closed() {
        let directory = temporary_directory();
        let target = directory.join("target");
        let path = directory.join("engine.state");
        fs::write(&target, b"HS_ENGINE 1\n1 1\n").expect("write the target");
        std::os::unix::fs::symlink(&target, &path).expect("create the symlink");
        let uid = test_uid();
        assert!(read_state_at(&path, uid).is_err());
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }

    #[cfg(target_os = "linux")]
    struct LiveThreadGroup {
        pid: libc::pid_t,
    }

    #[cfg(target_os = "linux")]
    impl Drop for LiveThreadGroup {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.pid, libc::SIGTERM);
            }
            let mut status = 0;
            loop {
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid {
                    break;
                }
                if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_thread_after_the_group_leader_exits_keeps_the_engine_state() {
        extern "C" fn parked_task(_: *mut libc::c_void) -> libc::c_int {
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }

        /* The test creates one short-lived child process with one parked
         * thread. It starts no route, TUN device, or privileged action. */
        let stack = vec![0u8; 1 << 20];
        let stack_top = (stack.as_ptr() as usize + stack.len()) & !0xf;
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed: {}", io::Error::last_os_error());
        if child == 0 {
            let flags = (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD
                | libc::CLONE_SYSVSEM) as libc::c_int;
            let cloned = unsafe {
                libc::clone(
                    parked_task,
                    stack_top as *mut libc::c_void,
                    flags,
                    std::ptr::null_mut(),
                )
            };
            if cloned < 0 {
                unsafe {
                    libc::syscall(libc::SYS_exit_group, 2);
                }
            }
            /* Exit only the thread-group leader. The cloned task keeps the
             * process alive and the leader becomes a zombie. */
            unsafe {
                libc::syscall(libc::SYS_exit, 0);
            }
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        let pid = child as u32;
        let _group = LiveThreadGroup { pid: child };
        let deadline = Instant::now() + Duration::from_secs(10);
        let start_time = loop {
            if let Ok((start_time, true)) = read_proc_state(pid) {
                if matches!(
                    observe_group_tasks(Path::new("/proc"), pid),
                    Ok(TaskObservation::Live)
                ) {
                    break start_time;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the child did not leave a live task behind a zombie leader"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let directory = temporary_directory();
        let host = test_host();
        let (path, uid) = write_test_state(&directory, &engine_record(&host, pid, start_time));
        assert_eq!(
            expect_presence(previous_engine_running(&path, uid, &host)),
            EnginePresence::Running("a previous privileged engine still has a live task")
        );
        assert_eq!(
            read_state_at(&path, uid).unwrap(),
            Some(engine_record(&host, pid, start_time))
        );
        fs::remove_dir_all(&directory).expect("remove the test directory");
    }
}
